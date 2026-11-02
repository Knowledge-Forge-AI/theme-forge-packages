"""Concrete protected execution for the current signing adapter.

The default runner uses only fixed absolute system tools and a clean
environment. All results are non-admitting, including actual native execution.
Private-key imports use stdin; GPG signing passphrases use private input pipes.
RPM uses a separate inherited passphrase descriptor because its fd 0 carries
the signed package data. Secret values never enter argv or the environment.
GnuPG imports the key into the fresh owned home; it is not memory-only. Clearing
our mutable buffers does not erase immutable Python copies or tool memory.
The fixed owned-agent lifetime surrounds every consumer, including failure
validation. Unconfirmed cleanup retains private directories and reachable
ownership state. This source prototype and its owned-agent dependency remain
unadopted; no result admits publication or proves escaped-descendant absence.

RPM verification parses a deliberately closed subset of RPM 6.0.2 human output
under LC_ALL=C, not a machine-status protocol. Source proves the full resolved
key fingerprint is rendered; it does not prove that a native build reports the
CI signing subkey rather than its primary. Primary-only, abbreviated, extra or
non-OK signature proof refuses. Exact native grammar, stream routing, effective
policy, signature format/count and issuer relationship remain unqualified.

Post-import GnuPG secret-key topology and detached Pacman verification status
are gated through the inactive pure signing_status_proof adapter using
trusted execution clock int(time.time()). These checks remain non-admitting and
make no native GnuPG 2.4.9 grammar, real-key topology or cryptographic
qualification claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
import math
import threading
from typing import Any, Mapping, Sequence

from protected_passphrase_fd import _PassphrasePipe, _passphrase_pipe
from owned_gpg_agent import OwnedGpgAgent
from signing_status_proof import (
    PRIMARY as _STATUS_PRIMARY,
    SUBKEY as _STATUS_SUBKEY,
    ProofError,
    inspect_ci_secret_metadata,
    inspect_detached_verification,
)

from current_protected_signing import (
    MAX_OBJECT_BYTES,
    PRIMARY_FINGERPRINT,
    SIGNING_SUBKEY_FINGERPRINT,
    ProtectedSigningError,
    SignerBinding,
    UnsignedObject,
    CURRENT_VERSIONS,
    CHANNEL_ARCHITECTURES,
    _read_stable,
    _sha256,
    validate_signer_binding,
    validate_unsigned_objects,
    verify_committed_public_key,
)


NATIVE_GPG = "/usr/bin/gpg"
NATIVE_RPM = "/usr/bin/rpm"
NATIVE_RPMSIGN = "/usr/bin/rpmsign"
NATIVE_REPO_ADD = "/usr/bin/repo-add"
MAX_PROCESS_OUTPUT = 256 * 1024
MAX_PROCESS_STDIN = 2 * 1024 * 1024
PROCESS_TIMEOUT_SECONDS = 60.0
DESCRIPTOR_MAX_BYTES = 16 * 1024 * 1024
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_RPM_DIGEST_ITEM = re.compile(rb"    (Header|Payload|Legacy) ([A-Z][A-Z0-9-]{0,31})( ALT)? digest: OK")
_RPM_SIGNATURE_ITEM = re.compile(
    rb"    Header OpenPGP V4 [A-Z][A-Z0-9/-]{0,63} [Ss]ignature, key fingerprint: ([0-9a-fA-F]{40}): OK"
)
_RPM_VERIFY_MAX_LINES = 64
_SECRET_TOPOLOGY_OPTIONS = (
    "--with-colons", "--fixed-list-mode", "--with-secret",
    "--with-fingerprint", "--with-fingerprint", "--list-secret-keys",
)
READ_DESCRIPTOR_CLEANUP = "READ_DESCRIPTOR_CLEANUP"
# Private, process-local ownership only. Never serialize these records or their
# errors. Retained invocations have no automatic retry or force-cleanup API.
_RETAINED_RUNTIME_CUSTODIES: list[dict[str, object]] = []
# A failed read-descriptor close is an unresolved ownership event even when no
# ProtectedSigningRuntime instance exists to receive it. Keep the descriptor
# ledger and its private error references strongly reachable; this registry has
# no retry or numeric-close API.
_RETAINED_READ_DESCRIPTORS: list[dict[str, object]] = []


def _rpm_verification_status(result: ProcessResult, stage: Path) -> dict[str, object]:
    """Close exact-version human status around RPM's own crypto verification.

    A verbose run has one package header and per-item lines; RPM6 suppresses
    the normal summary in this mode. Exactly one stream may carry this proof;
    the other must be empty. This records which stream supplied the candidate
    grammar without treating source inspection as native stream qualification.
    No item description, path, UID or diagnostic enters returned evidence.
    """
    if (not isinstance(result, ProcessResult) or result.returncode != 0
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes):
        raise ProtectedSigningError("RPM_VERIFY_STATUS", "RPM verification status is unavailable")
    if len(result.stdout) > MAX_PROCESS_OUTPUT or len(result.stderr) > MAX_PROCESS_OUTPUT:
        raise ProtectedSigningError("RPM_VERIFY_BOUND", "RPM verification status exceeded its bound")
    streams = [(name, value) for name, value in (("stdout", result.stdout), ("stderr", result.stderr)) if value]
    if len(streams) != 1:
        raise ProtectedSigningError("RPM_VERIFY_STREAM", "RPM verification proof requires one unambiguous stream")
    stream, body = streams[0]
    if not body.endswith(b"\n") or b"\r" in body or b"\x00" in body:
        raise ProtectedSigningError("RPM_VERIFY_FORMAT", "RPM verification framing is unsupported")
    lines = body[:-1].split(b"\n")
    if (not 2 <= len(lines) <= _RPM_VERIFY_MAX_LINES or len(lines[0]) > 8192
            or any(not line or len(line) > 1024 for line in lines[1:])
            or lines[0] != os.fsencode(str(stage)) + b":"):
        raise ProtectedSigningError("RPM_VERIFY_FORMAT", "RPM verification package binding or line bounds failed")
    signatures = 0
    digests: set[tuple[bytes, bytes, bytes | None]] = set()
    counts = {b"Header": 0, b"Payload": 0, b"Legacy": 0}
    for line in lines[1:]:
        signature = _RPM_SIGNATURE_ITEM.fullmatch(line)
        if signature:
            signatures += 1
            if signature[1].decode("ascii").upper() != SIGNING_SUBKEY_FINGERPRINT:
                raise ProtectedSigningError("RPM_SIGNATURE_ISSUER", "RPM verification did not prove the exact CI signing subkey")
            continue
        digest = _RPM_DIGEST_ITEM.fullmatch(line)
        if digest:
            item = digest.groups()
            if item in digests:
                raise ProtectedSigningError("RPM_VERIFY_AMBIGUOUS", "RPM verification repeated a digest status")
            digests.add(item)
            counts[digest[1]] += 1
            continue
        # Includes NOTTRUSTED/UNKNOWN despite a possible zero native exit, all
        # non-OK items, missing/short/key-ID-only fingerprints and diagnostics.
        raise ProtectedSigningError("RPM_VERIFY_STATUS", "RPM verification contained unsupported or unsuccessful proof")
    if signatures != 1:
        raise ProtectedSigningError("RPM_SIGNATURE_COUNT", "RPM verification must prove exactly one CI signature")
    if not digests or not (counts[b"Header"] or counts[b"Legacy"]) or not (counts[b"Payload"] or counts[b"Legacy"]):
        raise ProtectedSigningError("RPM_DIGEST_COVERAGE", "RPM verification did not prove complete digest coverage")
    return {
        "schema": "tf.rpm602-verification-status.v1",
        "status": "source-contract-match",
        "verification_level": "all", "verification_flags": 0,
        "signature_status": "OK", "signature_count": signatures,
        "signing_subkey_fingerprint": SIGNING_SUBKEY_FINGERPRINT,
        "expected_primary_fingerprint": PRIMARY_FINGERPRINT,
        "signature_range": "Header", "signature_format": "OpenPGP-V4",
        "digest_count": len(digests), "header_digest_count": counts[b"Header"],
        "payload_digest_count": counts[b"Payload"], "legacy_digest_count": counts[b"Legacy"],
        "status_stream": stream,
        "native_output_contract_qualified": False,
        "native_effective_policy_qualified": False,
        "native_issuer_relationship_qualified": False,
        "production_authority": False,
    }


def _proof_epoch() -> int:
    return int(time.time())


def _require_status_proof_binding(binding: SignerBinding) -> None:
    if (
        type(binding) is not SignerBinding
        or (binding.primary_fingerprint, binding.signing_subkey_fingerprint)
        != (_STATUS_PRIMARY, _STATUS_SUBKEY)
    ):
        raise ProtectedSigningError("STATUS_PROOF_BINDING", "Signer status proof requires the fixed CI binding")


def _status_proof(
    inspect: Any, code: str, message: str, data: bytes, binding: SignerBinding, **kwargs: object
) -> dict[str, object]:
    _require_status_proof_binding(binding)
    failed = False
    proof = None
    try:
        proof = inspect(data, now=_proof_epoch(), **kwargs)
    except ProofError:
        failed = True
    if failed:
        raise ProtectedSigningError(code, message)
    if (
        not isinstance(proof, dict)
        or proof.get("primaryFingerprint") != _STATUS_PRIMARY
        or proof.get("signingSubkeyFingerprint") != _STATUS_SUBKEY
    ):
        raise ProtectedSigningError(code, message)
    return proof


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass(frozen=True)
class ExecutionResult:
    schema: str
    status: str
    production_authority: bool
    native_execution: bool
    output_root: str
    objects: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class AuthenticatedUnsignedBundle:
    descriptor_sha256: str
    source_commit: str
    source_tree: str
    origin: str
    objects: tuple[UnsignedObject, ...]


@dataclass(frozen=True)
class _OwnedDirectory:
    path: Path
    dev: int
    ino: int


def _raw_absolute(path: str | Path, label: str) -> Path:
    raw = os.fspath(path)
    if not raw or not os.path.isabs(raw) or "\x00" in raw:
        raise ProtectedSigningError("PATH_FORMAT", f"{label} must be absolute")
    if any(part in {".", ".."} for part in raw.split(os.sep)):
        raise ProtectedSigningError("PATH_TRAVERSAL", f"{label} contains traversal")
    return Path(raw)


def _check_ancestors(path: Path, label: str) -> None:
    for ancestor in reversed(path.parents):
        try:
            info = os.lstat(ancestor)
        except OSError:
            raise ProtectedSigningError("PATH_MISSING", f"{label} parent is missing") from None
        if stat.S_ISLNK(info.st_mode):
            raise ProtectedSigningError("SYMLINK_REJECTED", f"{label} has a symlinked ancestor")


def _new_owned_directory(path: str | Path, label: str) -> _OwnedDirectory:
    candidate = _raw_absolute(path, label)
    _check_ancestors(candidate, label)
    try:
        os.mkdir(candidate, 0o700)
    except FileExistsError:
        raise ProtectedSigningError("OUTPUT_EXISTS", f"Fresh {label} already exists") from None
    except OSError:
        raise ProtectedSigningError("OUTPUT_IO", f"Unable to create {label}") from None
    try:
        info = os.lstat(candidate)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ProtectedSigningError("OUTPUT_CUSTODY", f"Fresh {label} custody is invalid")
    except BaseException as error:
        # mkdir succeeded, but no confirmed identity was returned to the caller.
        # Retain the enrollment gap instead of treating it as no created output.
        raise _LifecycleFailure("OUTPUT_CREATION", error, (), resources=(
            {"path": candidate, "created": True, "identity": None},
        )) from None
    return _OwnedDirectory(candidate, info.st_dev, info.st_ino)


def _remove_owned_directory(directory: _OwnedDirectory) -> None:
    try:
        info = os.lstat(directory.path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise ProtectedSigningError("CLEANUP_IO", "Unable to inspect owned output") from error
    if (info.st_dev, info.st_ino) != (directory.dev, directory.ino) or stat.S_ISLNK(info.st_mode):
        raise ProtectedSigningError("CLEANUP_CUSTODY", "Owned output was replaced")
    shutil.rmtree(directory.path)


def _exclusive_write(path: Path, data: bytes, label: str, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise ProtectedSigningError("OUTPUT_EXISTS", f"{label} already exists")
    fd = None
    original = None
    cleanup_errors = []
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("regular output write made no progress")
            offset += written
        os.fsync(fd)
        os.fchmod(fd, mode)
    except BaseException as error:
        original = error
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as error:
                cleanup_errors.append(error)
    if cleanup_errors:
        raise _LifecycleFailure("OUTPUT_DESCRIPTOR_CLEANUP", original, cleanup_errors,
                                resources=({"path": path, "uncertain_fd": fd},)) from None
    if original is not None:
        if isinstance(original, OSError):
            raise ProtectedSigningError("OUTPUT_IO", f"Unable to write {label}") from original
        raise original


def _ensure_child_directory(parent: Path, name: str, label: str) -> Path:
    if not _NAME.fullmatch(name):
        raise ProtectedSigningError("PATH_FORMAT", f"Unsafe {label} directory name")
    target = parent / name
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        try:
            os.mkdir(target, 0o700)
        except OSError as error:
            raise ProtectedSigningError("OUTPUT_IO", f"Unable to create {label} directory") from error
        info = os.lstat(target)
    except OSError as error:
        raise ProtectedSigningError("OUTPUT_IO", f"Unable to inspect {label} directory") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ProtectedSigningError("OUTPUT_CUSTODY", f"{label} directory custody is invalid")
    return target


def _read_regular_unpinned(path: Path, label: str) -> bytes:
    candidate = _raw_absolute(path, label)
    _check_ancestors(candidate, label)
    try:
        info = os.lstat(candidate)
    except OSError as error:
        raise ProtectedSigningError("PATH_IO", f"Unable to inspect {label}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProtectedSigningError("REGULAR_FILE_REQUIRED", f"{label} must be a regular file")
    if info.st_size < 0 or info.st_size > MAX_OBJECT_BYTES:
        raise ProtectedSigningError("SIZE_LIMIT", f"{label} exceeds its bound")
    try:
        fd = os.open(str(candidate), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProtectedSigningError("PATH_IO", f"Unable to open {label}") from error
    descriptor = {
        "fd": fd,
        "status": "open",
        "path": candidate,
        "original_error": None,
        "cleanup_error": None,
        "close_attempted": False,
        "close_confirmed": False,
    }
    body_error = None
    cleanup_error = None
    data = None
    try:
        try:
            before = os.fstat(fd)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size != info.st_size:
                raise ProtectedSigningError("FILE_CHANGED", f"{label} changed before read")
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_OBJECT_BYTES:
                block = os.read(fd, min(1024 * 1024, MAX_OBJECT_BYTES + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > MAX_OBJECT_BYTES:
                    break
            after = os.fstat(fd)
            data = b"".join(chunks)
            if total > MAX_OBJECT_BYTES or before.st_size != len(data) or (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
            ) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise ProtectedSigningError("FILE_CHANGED", f"{label} changed during read")
        except BaseException as error:
            body_error = error
            descriptor["original_error"] = error
    finally:
        descriptor["close_attempted"] = True
        try:
            os.close(fd)
        except BaseException as error:
            cleanup_error = error
            descriptor["status"] = "close-uncertain"
            descriptor["cleanup_error"] = error
            _RETAINED_READ_DESCRIPTORS.append(descriptor)
        else:
            descriptor["status"] = "closed"
            descriptor["close_confirmed"] = True
    if cleanup_error is not None:
        raise _LifecycleFailure(
            READ_DESCRIPTOR_CLEANUP,
            body_error,
            (cleanup_error,),
            resources=(descriptor,),
        ) from None
    if body_error is not None:
        raise body_error
    return data


def _regular_size(path: Path, label: str) -> int:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise ProtectedSigningError("PATH_IO", f"Unable to inspect {label}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProtectedSigningError("REGULAR_FILE_REQUIRED", f"{label} must be regular")
    return info.st_size


def _child_exited_unreaped(process: subprocess.Popen) -> bool:
    """Observe our direct child while retaining its PID/process-group reservation.

    The dedicated signer must use default SIGCHLD and no external child reaper.
    This is not a proof that a detached descendant cannot exist.
    """
    try:
        result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        raise ProtectedSigningError("COMMAND_CLEANUP", "Direct-child reservation was lost") from None
    return result is not None and result.si_pid == process.pid


def _owned_streams_at_eof(process: subprocess.Popen) -> bool:
    """Boundedly discard failed-command output while checking owned pipe EOF.

    EOF does not prove the absence of detached descendants that closed stdio.
    That remains part of the qualified fixed-tool execution contract.
    """
    complete = True
    for stream in (process.stdout, process.stderr):
        if stream is None or stream.closed:
            continue
        os.set_blocking(stream.fileno(), False)
        remaining = MAX_PROCESS_OUTPUT
        while remaining:
            try:
                block = os.read(stream.fileno(), min(16384, remaining))
            except BlockingIOError:
                complete = False
                break
            if not block:
                break
            remaining -= len(block)
        else:
            complete = False
    return complete


class _LifecycleFailure(ProtectedSigningError):
    """Sanitized surface with reachable original failures and owned resources.

    Exception attributes are custody, not serializable receipt fields. Their
    diagnostics must not be copied into reports or publication metadata.
    """

    def __init__(self, code, original_error, cleanup_errors, *, process=None, resources=()):
        super().__init__(code, "Protected lifecycle could not be confirmed")
        self.original_error = original_error
        self.cleanup_errors = tuple(cleanup_errors)
        self.process = process
        self.resources = tuple(resources)


class _ConsumerCleanupUnconfirmed(_LifecycleFailure):
    pass


@contextmanager
def _consumer_enrollment_mask():
    # Dedicated serial signer only. Restore the caller's mask, never handlers.
    blocked = set(signal.valid_signals()) - {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _stop_consumer(process):
    # Never use a numeric group after losing/reaping the direct-child reserve.
    if process.returncode is not None:
        raise ProtectedSigningError("COMMAND_CLEANUP", "Direct-child reservation was lost")
    quiescent = _child_exited_unreaped(process) and _owned_streams_at_eof(process)
    for value, grace in ((signal.SIGTERM, 1), (signal.SIGKILL, 3)):
        if quiescent:
            break
        _child_exited_unreaped(process)
        try:
            os.killpg(process.pid, value)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if _child_exited_unreaped(process) and _owned_streams_at_eof(process):
                quiescent = True
                break
            time.sleep(0.01)
    if not quiescent:
        raise ProtectedSigningError("COMMAND_CLEANUP", "Protected process cleanup could not be confirmed")
    process.wait(timeout=1)


class NativeProtectedProcessRunner:
    """Fixed-tool subprocess boundary; no shell and no inherited environment."""

    allowed = frozenset({NATIVE_GPG, NATIVE_RPM, NATIVE_RPMSIGN, NATIVE_REPO_ADD})

    def run(
        self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str], stdin: bytes,
        phase: str, timeout: float = PROCESS_TIMEOUT_SECONDS,
        passphrase_input: _PassphrasePipe | None = None,
    ) -> ProcessResult:
        values = tuple(str(value) for value in argv)
        if not values or values[0] not in self.allowed or any("\x00" in value for value in values):
            raise ProtectedSigningError("COMMAND_POLICY", f"Unsupported protected command in {phase}")
        if (not isinstance(stdin, bytes) or len(stdin) > MAX_PROCESS_STDIN
                or type(timeout) not in (int, float)
                or not 0 < timeout <= PROCESS_TIMEOUT_SECONDS or not math.isfinite(timeout)):
            raise ProtectedSigningError("COMMAND_POLICY", "Invalid protected process bounds")
        if (threading.current_thread() is not threading.main_thread() or threading.active_count() != 1
                or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
            raise ProtectedSigningError("COMMAND_POLICY", "Dedicated serial main thread and default SIGCHLD are required")
        if passphrase_input is not None and (
            not isinstance(passphrase_input, _PassphrasePipe) or values[0] != NATIVE_RPMSIGN
        ):
            raise ProtectedSigningError("COMMAND_POLICY", "Inherited passphrase input is restricted to rpmsign")
        inherited = () if passphrase_input is None else passphrase_input.pass_fds
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        pending = memoryview(stdin)
        deadline = time.monotonic() + timeout
        selector = selectors.DefaultSelector()
        process = None
        original = None
        cleanup_errors = []
        result = None
        reaped = False
        try:
            with _consumer_enrollment_mask():
                process = subprocess.Popen(
                    values, cwd=str(cwd), env=dict(env), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                    close_fds=True, start_new_session=True,
                    pass_fds=inherited,
                )
                if passphrase_input is not None:
                    passphrase_input.child_started()
                    selector.register(passphrase_input.writer_fileno(), selectors.EVENT_WRITE, "passphrase")
                for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                if pending:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    process.stdin.close()
            while selector.get_map() or not _child_exited_unreaped(process):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProtectedSigningError("COMMAND_TIMEOUT", f"Protected command timed out in {phase}")
                for key, _ in selector.select(min(remaining, 0.1)):
                    stream, name = key.fileobj, key.data
                    if name == "passphrase":
                        if passphrase_input.write_ready():
                            selector.unregister(stream)
                    elif name == "stdin":
                        try:
                            written = os.write(stream.fileno(), pending[:65536])
                            pending = pending[written:]
                        except BrokenPipeError:
                            pending = pending[len(pending):]
                        except BlockingIOError:
                            continue
                        if not pending:
                            selector.unregister(stream)
                            stream.close()
                    else:
                        try:
                            block = os.read(stream.fileno(), 16384)
                        except BlockingIOError:
                            continue
                        if not block:
                            selector.unregister(stream)
                            stream.close()
                        elif len(buffers[name]) + len(block) > MAX_PROCESS_OUTPUT:
                            raise ProtectedSigningError("COMMAND_OUTPUT_LIMIT", f"Protected command output exceeded its bound in {phase}")
                        else:
                            buffers[name].extend(block)
            status = process.wait(timeout=1)
            reaped = True
            result = ProcessResult(status, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
        except BaseException as error:
            original = error
            if process is not None and not reaped:
                try:
                    _stop_consumer(process)
                    reaped = True
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
        finally:
            # Each resource is attempted even if another closer fails. Keep all
            # references in the explicit custody error; never signal from here.
            closers = [pending.release, selector.close]
            if passphrase_input is not None:
                closers.append(passphrase_input.close)
            if process is not None:
                closers.extend(stream.close for stream in (process.stdin, process.stdout, process.stderr)
                               if stream is not None)
            for close in closers:
                try:
                    close()
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            raise _ConsumerCleanupUnconfirmed(
                "COMMAND_CLEANUP", original, cleanup_errors, process=process,
                resources=(selector, passphrase_input),
            ) from None
        if original is not None:
            raise original
        return result


def inspect_rpm_preservation(unsigned_bytes: bytes, signed_bytes: bytes) -> dict[str, object]:
    """Compare physical RPM sections using the retained maintained parser."""
    from rpm_byte_preservation import PreservationError, preservation
    try:
        return preservation(unsigned_bytes, signed_bytes)
    except PreservationError as error:
        raise ProtectedSigningError(str(error), "RPM byte preservation refused") from None


def _descriptor_value(data: Mapping[str, object], key: str, kind: type) -> object:
    value = data.get(key)
    if not isinstance(value, kind):
        raise ProtectedSigningError("DESCRIPTOR_SCHEMA", f"Descriptor field {key!r} has the wrong type")
    return value


def load_authenticated_unsigned_bundle(
    descriptor_path: str | Path,
    input_root: str | Path,
    *,
    expected_descriptor_sha256: str,
    expected_source_commit: str,
    expected_source_tree: str,
    expected_origin: str,
) -> AuthenticatedUnsignedBundle:
    """Read digest-pinned bytes; this does not prove fresh qualified import.

    Expected coordinates and digests are caller parameters. A protected workflow
    must separately retain custody from its live prepare_unsigned invocation;
    this serialized descriptor cannot create that authority.
    """
    descriptor = _raw_absolute(descriptor_path, "input descriptor")
    descriptor_data = _read_stable(descriptor, expected_descriptor_sha256, _regular_size(descriptor, "input descriptor"), "input descriptor")
    try:
        body = json.loads(descriptor_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtectedSigningError("DESCRIPTOR_SCHEMA", "Input descriptor is not JSON") from error
    if not isinstance(body, dict) or body.get("schema") != "tf.protected-unsigned-inputs.v1" or set(body) != {"schema", "source", "origin", "objects"}:
        raise ProtectedSigningError("DESCRIPTOR_SCHEMA", "Input descriptor schema mismatch")
    source = _descriptor_value(body, "source", dict)
    if set(source) != {"commit", "tree", "manifest_path", "manifest_sha256"}:
        raise ProtectedSigningError("SOURCE_MANIFEST", "Source binding fields are not closed")
    commit = _descriptor_value(source, "commit", str)
    tree = _descriptor_value(source, "tree", str)
    if not _COMMIT.fullmatch(commit) or not _COMMIT.fullmatch(tree):
        raise ProtectedSigningError("SOURCE_IDENTITY", "Source commit/tree must be full Git identities")
    if (commit, tree) != (expected_source_commit, expected_source_tree):
        raise ProtectedSigningError("SOURCE_IDENTITY", "Descriptor source identity mismatch")
    origin = _descriptor_value(body, "origin", str)
    if origin != expected_origin or not origin or "\n" in origin or "\r" in origin:
        raise ProtectedSigningError("ORIGIN", "Descriptor origin mismatch")
    manifest_path = _descriptor_value(source, "manifest_path", str)
    if not manifest_path or os.path.isabs(manifest_path) or any(part in {"", ".", ".."} for part in manifest_path.split("/")):
        raise ProtectedSigningError("DESCRIPTOR_PATH", "Manifest path must be a safe relative path")
    manifest_sha = _descriptor_value(source, "manifest_sha256", str)
    manifest = descriptor.parent / manifest_path
    manifest_bytes = _read_stable(manifest, manifest_sha, _regular_size(manifest, "source manifest"), "source manifest")
    try:
        manifest_body = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtectedSigningError("SOURCE_MANIFEST", "Source manifest is not JSON") from error
    if (
        not isinstance(manifest_body, dict)
        or set(manifest_body) != {"schema", "commit", "tree"}
        or manifest_body.get("schema") != "source-manifest.v1"
        or manifest_body.get("commit") != commit
        or manifest_body.get("tree") != tree
    ):
        raise ProtectedSigningError("SOURCE_MANIFEST", "Source manifest identity mismatch")
    root = _raw_absolute(input_root, "unsigned input root")
    _check_ancestors(root, "unsigned input root")
    try:
        root_info = os.lstat(root)
    except OSError as error:
        raise ProtectedSigningError("INPUT_ROOT", "Unsigned input root is unavailable") from error
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ProtectedSigningError("INPUT_ROOT", "Unsigned input root must be a real directory")
    objects_data = _descriptor_value(body, "objects", list)
    objects: list[UnsignedObject] = []
    for entry in objects_data:
        if not isinstance(entry, dict):
            raise ProtectedSigningError("DESCRIPTOR_SCHEMA", "Object entry must be an object")
        if set(entry) != {"channel", "product", "version", "architecture", "relative_path", "sha256", "size"}:
            raise ProtectedSigningError("DESCRIPTOR_SCHEMA", "Object fields are not closed")
        relative = _descriptor_value(entry, "relative_path", str)
        if not relative or os.path.isabs(relative) or any(part in {"", ".", ".."} for part in relative.split("/")):
            raise ProtectedSigningError("DESCRIPTOR_PATH", "Object path must be safe and relative")
        path = root / Path(relative)
        objects.append(UnsignedObject(
            channel=_descriptor_value(entry, "channel", str),
            product=_descriptor_value(entry, "product", str),
            version=_descriptor_value(entry, "version", str),
            architecture=_descriptor_value(entry, "architecture", str),
            origin=origin,
            path=path,
            sha256=_descriptor_value(entry, "sha256", str),
            size=_descriptor_value(entry, "size", int),
        ))
    checked = validate_unsigned_objects(objects, origin)
    return AuthenticatedUnsignedBundle(expected_descriptor_sha256, commit, tree, origin, checked)


def _live_object_shapes(objects: tuple[UnsignedObject, ...], origin: str) -> tuple[UnsignedObject, ...]:
    """Fixed metadata checks only; the sealed lease owns every byte read.

    This is an internal live-entry helper, never a caller-selected alternative
    to legacy pathname validation. Pure architectures retain their identity.
    """
    if type(objects) is not tuple or not objects or type(origin) is not str or not origin:
        raise ProtectedSigningError("LIVE_OBJECTS", "Closed live object metadata is required")
    seen_identity = set()
    seen_paths = set()
    pure = {"theme-forge-stellar-loom", "theme-forge-solar-sail"}
    for obj in objects:
        if type(obj) is not UnsignedObject:
            raise ProtectedSigningError("OBJECT_TYPE", "Exact live unsigned object metadata is required")
        if any(type(value) is not str for value in
               (obj.channel, obj.product, obj.version, obj.architecture, obj.origin)):
            raise ProtectedSigningError("LIVE_OBJECTS", "Live identity fields must be strings")
        if obj.channel not in CHANNEL_ARCHITECTURES:
            raise ProtectedSigningError("CHANNEL", "Unsupported live channel")
        if obj.product not in CURRENT_VERSIONS or obj.version != CURRENT_VERSIONS[obj.product]:
            raise ProtectedSigningError("VERSION", "Unsupported live product/version")
        allowed = CHANNEL_ARCHITECTURES[obj.channel]
        special = {"apt": "all", "pacman": "any"}.get(obj.channel)
        if obj.architecture not in allowed and not (obj.product in pure and obj.architecture == special):
            raise ProtectedSigningError("ARCHITECTURE", "Unsupported live package architecture")
        if obj.architecture in {"all", "any", "noarch"} and obj.product not in pure:
            raise ProtectedSigningError("ARCHITECTURE", "Native products cannot use a pure package architecture")
        if obj.origin != origin:
            raise ProtectedSigningError("ORIGIN", "Live unsigned object origin differs")
        if (type(obj.size) is not int or not 0 < obj.size <= MAX_OBJECT_BYTES
                or type(obj.sha256) is not str or re.fullmatch(r"[a-f0-9]{64}", obj.sha256) is None):
            raise ProtectedSigningError("LIVE_OBJECTS", "Live size or digest is invalid")
        path = _raw_absolute(obj.path, "live unsigned object")
        identity = (obj.channel, obj.product, obj.architecture)
        if identity in seen_identity or str(path) in seen_paths:
            raise ProtectedSigningError("DUPLICATE_OBJECT", "Duplicate live object identity or path")
        seen_identity.add(identity)
        seen_paths.add(str(path))
    return objects


def _clear_secret(secret: bytearray) -> None:
    # Does not erase immutable Python copies or memory owned by native tools.
    for index in range(len(secret)):
        secret[index] = 0


class ProtectedSigningRuntime:
    """Execute only fixed signer commands against a fresh owned output root."""

    def __init__(
        self,
        *,
        binding: SignerBinding = SignerBinding(),
        runner: Any | None = None,
    ):
        validate_signer_binding(binding)
        self.binding = binding
        self.runner = runner or NativeProtectedProcessRunner()
        self._agent = None
        self._consumer_failures = []
        self._retained_custody = None
        self._active_live_lease = None
        self._output_files = {}
        self._resource_failures = []
        self._output_root = None

    @property
    def retained_custody(self):
        """Unserializable ownership state; no automatic retry/signaling API."""
        return self._retained_custody

    def _env(self, home: Path) -> dict[str, str]:
        return {"HOME": str(home), "GNUPGHOME": str(home), "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}

    def _run(self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str], stdin: bytes, phase: str,
             passphrase_input: _PassphrasePipe | None = None) -> ProcessResult:
        if self._agent is None:
            raise ProtectedSigningError("AGENT_REQUIRED", "Owned agent lifetime is required")
        guard = (self._active_live_lease.native_phase(phase)
                 if self._active_live_lease is not None else nullcontext())
        with guard:
            original = None
            result = None
            try:
                self._agent.require_live()
                transport = {} if passphrase_input is None else {"passphrase_input": passphrase_input}
                if isinstance(self.runner, NativeProtectedProcessRunner):
                    result = self.runner.run(argv, cwd=cwd, env=env, stdin=stdin, phase=phase, **transport)
                else:
                    result = self.runner(argv, cwd=cwd, env=env, stdin=stdin, phase=phase, **transport)
                if not isinstance(result, ProcessResult) or result.returncode != 0:
                    raise ProtectedSigningError("COMMAND_FAILED", f"Protected command failed in {phase}")
                if len(result.stdout) > MAX_PROCESS_OUTPUT or len(result.stderr) > MAX_PROCESS_OUTPUT:
                    raise ProtectedSigningError("COMMAND_OUTPUT_LIMIT", f"Protected command output exceeded its bound in {phase}")
            except BaseException as error:
                original = error
                # Enroll the actual process before a lease post-check can wrap
                # this error. Independent agent and lease post-checks still run.
                self._remember_resource_errors(error)
            try:
                self._agent.require_live()
            except BaseException as live_error:
                self._remember_resource_errors(live_error)
                if self._active_live_lease is not None:
                    self._resource_failures.append(live_error)
                if original is not None:
                    raise _LifecycleFailure("AGENT_CONSUMER_LIFECYCLE", original, (live_error,)) from None
                raise
            if original is not None:
                raise original
            return result

    def _remember_resource_errors(self, error: BaseException) -> None:
        pending = [error]
        seen = set()
        while pending:
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            if isinstance(current, _ConsumerCleanupUnconfirmed):
                if all(current is not old for old in self._consumer_failures):
                    self._consumer_failures.append(current)
            if isinstance(current, _LifecycleFailure):
                uncertain = (self._active_live_lease is not None
                             or isinstance(current, _ConsumerCleanupUnconfirmed)
                             or current.code in {"OUTPUT_CREATION", "OUTPUT_DESCRIPTOR_CLEANUP",
                                                 READ_DESCRIPTOR_CLEANUP})
                if uncertain and all(current is not old for old in self._resource_failures):
                    self._resource_failures.append(current)
                if current.original_error is not None:
                    pending.append(current.original_error)
                pending.extend(current.cleanup_errors)

    def _gpg_base(self, home: Path) -> tuple[str, ...]:
        return (
            NATIVE_GPG, "--batch", "--yes", "--no-options", "--no-autostart", "--disable-dirmngr",
            "--homedir", str(home), "--no-default-keyring", "--keyring", str(home / "pubring.kbx"),
        )

    def _import_key(self, home: Path, cwd: Path, public_key: bytes, private_key: bytes) -> None:
        _require_status_proof_binding(self.binding)
        env = self._env(home)
        self._run((*self._gpg_base(home), "--import"), cwd=cwd, env=env, stdin=public_key, phase="public-key-import")
        self._run((*self._gpg_base(home), "--import"), cwd=cwd, env=env, stdin=private_key, phase="private-key-import")
        listing = self._run(
            (*self._gpg_base(home), *_SECRET_TOPOLOGY_OPTIONS),
            cwd=cwd, env=env, stdin=b"", phase="private-key-import",
        )
        _status_proof(
            inspect_ci_secret_metadata,
            "SECRET_KEY_TOPOLOGY",
            "Isolated GnuPG secret-key topology proof failed",
            listing.stdout,
            self.binding,
        )

    def _import_rpm_key(self, home: Path, cwd: Path, public_key: bytes) -> Path:
        rpm_db = _new_owned_directory(home / "rpmdb", "private RPM key database")
        key_path = home / "public-key.asc"
        _exclusive_write(key_path, public_key, "staged RPM public key")
        self._run(
            (NATIVE_RPM, "--dbpath", str(rpm_db.path), "--import", str(key_path)),
            cwd=cwd, env=self._env(home), stdin=b"", phase="rpm-public-key-import",
        )
        return rpm_db.path

    def _rpm_sign(self, stage: Path, home: Path, cwd: Path, passphrase: bytes) -> None:
        # RPM 6 feeds the signed header to GPG on fd 0. The passphrase has its
        # own inherited pipe; neither a macro nor argv contains its value.
        if not all(_NAME.fullmatch(part) for part in home.parts[1:]):
            raise ProtectedSigningError("COMMAND_POLICY", "RPM signing home must have closed ASCII components")
        with _passphrase_pipe(passphrase) as phrase:
            command = (
                "%__gpg_sign_cmd() %{shescape:%{__gpg}} "
                "--homedir %{shescape:%{_gpg_path}} --no-options --no-autostart "
                "--batch --pinentry-mode loopback --passphrase-fd " + str(phrase.reader_fd)
                + " --no-armor --no-verbose --no-secmem-warning "
                "-u %{shescape:%{_openpgp_sign_id}} -sbo %{shescape:%{2}} -- %{shescape:%{1}}"
            )
            argv = (
                NATIVE_RPMSIGN, "--define", "%_openpgp_sign gpg",
                "--define", f"%_openpgp_sign_id {self.binding.signing_subkey_fingerprint}!",
                "--define", f"%__gpg {NATIVE_GPG}", "--define", f"%_gpg_path {home}",
                "--define", command, "--addsign", str(stage),
            )
            self._run(argv, cwd=cwd, env=self._env(home), stdin=b"", phase="rpm-package-sign",
                      passphrase_input=phrase)

    def _rpm_verify(self, stage: Path, rpm_db: Path, home: Path, cwd: Path) -> dict[str, object]:
        result = self._run(
            (NATIVE_RPM, "--define", "%_pkgverify_level all", "--define", "%_pkgverify_flags 0",
             "--dbpath", str(rpm_db), "--checksig", "--verbose", str(stage)),
            cwd=cwd, env=self._env(home), stdin=b"", phase="rpm-package-verify",
        )
        return _rpm_verification_status(result, stage)

    def _pacman_sign(self, stage: Path, signature: Path, home: Path, cwd: Path, passphrase: bytes) -> None:
        argv = (
            *self._gpg_base(home), "--pinentry-mode", "loopback", "--passphrase-fd", "0",
            "--detach-sign", "--output", str(signature), "-u", f"{self.binding.signing_subkey_fingerprint}!", str(stage),
        )
        self._run(argv, cwd=cwd, env=self._env(home), stdin=passphrase, phase="pacman-package-sign")

    def _pacman_verify(self, stage: Path, signature: Path, home: Path, cwd: Path) -> None:
        _require_status_proof_binding(self.binding)
        result = self._run(
            (*self._gpg_base(home), "--status-fd", "1", "--verify", str(signature), str(stage)),
            cwd=cwd, env=self._env(home), stdin=b"", phase="pacman-package-verify",
        )
        _status_proof(
            inspect_detached_verification,
            "PACMAN_VERIFY_STATUS",
            "Detached Pacman signature status proof failed",
            result.stdout,
            self.binding,
            returncode=result.returncode,
        )

    def _write_output(self, phase: str, path: Path, data: bytes, label: str) -> None:
        lease = self._active_live_lease
        guard = lease.assembly_phase(phase) if lease is not None else nullcontext()
        with guard:
            root = self._output_root
            if root is None:
                raise ProtectedSigningError("OUTPUT_CUSTODY", "Owned output root is unavailable")
            relative = path.relative_to(root.path)
            current = root.path
            for part in relative.parts[:-1]:
                current = _ensure_child_directory(current, part, "package output")
            _exclusive_write(path, data, label)
            before = os.lstat(path)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o600):
                raise ProtectedSigningError("PACKAGE_MUTATED", "Output file shape differs")
            if _read_regular_unpinned(path, label) != data:
                raise ProtectedSigningError("PACKAGE_MUTATED", "Output readback changed")
            after = os.lstat(path)
            identity = self._output_identity(before)
            if identity != self._output_identity(after):
                raise ProtectedSigningError("PACKAGE_MUTATED", "Output identity changed during assembly")
            self._output_files[path] = (identity, _sha256(data), len(data))

    @staticmethod
    def _output_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _final_output_inventory(self, output: _OwnedDirectory, work: _OwnedDirectory) -> None:
        lease = self._active_live_lease
        guard = lease.assembly_phase("final-output-inventory") if lease is not None else nullcontext()
        with guard:
            _check_ancestors(output.path, "signing output")
            root = os.lstat(output.path)
            if ((root.st_dev, root.st_ino) != (output.dev, output.ino)
                    or not stat.S_ISDIR(root.st_mode) or stat.S_IMODE(root.st_mode) != 0o700):
                raise ProtectedSigningError("OUTPUT_CUSTODY", "Signing output root differs")
            expected_files = set(self._output_files)
            expected_directories = {output.path}
            for path in expected_files:
                parent = path.parent
                while parent != output.path:
                    expected_directories.add(parent)
                    parent = parent.parent
            seen_files = set()
            seen_directories = {output.path}
            for directory, names, files in os.walk(output.path, topdown=True, followlinks=False):
                parent = Path(directory)
                for name in tuple(names):
                    child = parent / name
                    info = os.lstat(child)
                    if child == work.path:
                        if ((info.st_dev, info.st_ino) != (work.dev, work.ino)
                                or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700):
                            raise ProtectedSigningError("OUTPUT_CUSTODY", "Private work directory differs")
                        names.remove(name)
                        continue
                    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                            or child not in expected_directories):
                        raise ProtectedSigningError("OUTPUT_INVENTORY", "Unexpected output directory")
                    seen_directories.add(child)
                for name in files:
                    path = parent / name
                    if path not in expected_files:
                        raise ProtectedSigningError("OUTPUT_INVENTORY", "Unexpected output member")
                    identity, digest, size = self._output_files[path]
                    if self._output_identity(os.lstat(path)) != identity:
                        raise ProtectedSigningError("PACKAGE_MUTATED", "Final output identity differs")
                    data = _read_regular_unpinned(path, "final package output")
                    if (len(data) != size or _sha256(data) != digest
                            or self._output_identity(os.lstat(path)) != identity):
                        raise ProtectedSigningError("PACKAGE_MUTATED", "Final output bytes differ")
                    seen_files.add(path)
            if seen_files != expected_files or seen_directories != expected_directories:
                raise ProtectedSigningError("OUTPUT_INVENTORY", "Output membership is incomplete")
            last = os.lstat(output.path)
            if (last.st_dev, last.st_ino) != (output.dev, output.ino):
                raise ProtectedSigningError("OUTPUT_CUSTODY", "Signing output root changed")

    def execute(
        self,
        objects: Sequence[UnsignedObject],
        *,
        origin: str,
        output_root: str | Path,
        public_key_bytes: bytes,
        private_key_bytes: bytes | bytearray,
        passphrase: bytes | bytearray,
    ) -> ExecutionResult:
        """Legacy mechanical entry; it cannot select or inject the live path."""
        self._require_idle()
        checked = validate_unsigned_objects(objects, origin)
        return self._execute_checked(
            checked, origin=origin, output_root=output_root, public_key_bytes=public_key_bytes,
            private_key_bytes=private_key_bytes, passphrase=passphrase,
        )

    def _require_idle(self) -> None:
        if (self._retained_custody is not None or self._agent is not None
                or self._active_live_lease is not None):
            raise ProtectedSigningError("LIFECYCLE_STATE", "Runtime custody is already occupied")

    def _retain_runtime(self, body_error, cleanup_errors, *, work, output, stage):
        lease = self._active_live_lease
        record = {
            "lease": lease, "lease_state": getattr(lease, "_state", None),
            "agent": self._agent, "work": work, "output": output,
            "consumers": tuple(self._consumer_failures),
            "resource_failures": tuple(self._resource_failures),
            "body_error": body_error,
            "cleanup_stage": stage,
            "work_state": self._directory_state(work),
            "output_state": self._directory_state(output),
        }
        self._retained_custody = record
        _RETAINED_RUNTIME_CUSTODIES.append(record)
        original = body_error
        earlier_cleanup = ()
        if isinstance(body_error, _LifecycleFailure) and body_error.code == "AGENT_CONSUMER_LIFECYCLE":
            # Preserve the established direct-body/cleanup interface while the
            # strong record also keeps the complete original lifecycle wrapper.
            original = body_error.original_error
            earlier_cleanup = body_error.cleanup_errors
        failure = _LifecycleFailure(
            "SIGNER_CLEANUP", original,
            (*earlier_cleanup, *cleanup_errors, *self._consumer_failures,
             *(error for error in self._resource_failures if error is not body_error)),
            resources=(record,),
        )
        if lease is not None and getattr(lease, "_state", None) != "closed":
            try:
                lease._retain(errors=(failure,))
            except BaseException as error:
                # The runtime's own strong record still retains every reference.
                failure.cleanup_errors += (error,)
            record["lease_state"] = getattr(lease, "_state", None)
        return failure

    @staticmethod
    def _directory_state(directory):
        """Metadata only; do not imply that a partially removed path survives."""
        if directory is None:
            return "not-enrolled"
        try:
            info = os.lstat(directory.path)
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "unknown"
        if ((info.st_dev, info.st_ino) == (directory.dev, directory.ino)
                and stat.S_ISDIR(info.st_mode)):
            return "owned-present"
        return "identity-differs"

    def _execute_checked(
        self, checked, *, origin, output_root, public_key_bytes,
        private_key_bytes, passphrase,
    ) -> ExecutionResult:
        """Fixed shared mechanics after distinct raw or sealed-live intake."""
        lease = self._active_live_lease
        private_secret = bytearray()
        passphrase_secret = bytearray()
        output = work = None
        native_observation = type(self.runner) is NativeProtectedProcessRunner
        results = []
        body_error = result = None
        cleanup_errors = []
        self._consumer_failures = []
        self._resource_failures = []
        self._output_files = {}
        self._output_root = None
        try:
            if lease is not None:
                checked = _live_object_shapes(lease.unsigned_objects(), lease.origin)
                origin = lease.origin
                lease._check_output_location(output_root)
            names = []
            for obj in checked:
                name = Path(obj.path).name
                suffix = {"apt": ".deb", "rpm": ".rpm", "pacman": ".pkg.tar.zst"}[obj.channel]
                if (not _NAME.fullmatch(name) or name.startswith(".")
                        or len(name.encode("utf-8")) > (251 if obj.channel == "pacman" else 255)
                        or not name.endswith(suffix) or name in names):
                    raise ProtectedSigningError("OBJECT_NAME", "Original package basename is invalid or collides")
                names.append(name)
            verify_committed_public_key(public_key_bytes, self.binding)
            if (type(private_key_bytes) not in (bytes, bytearray) or type(passphrase) not in (bytes, bytearray)
                    or len(private_key_bytes) > MAX_PROCESS_STDIN or len(passphrase) > MAX_PROCESS_STDIN):
                raise ProtectedSigningError("SECRET_FORMAT", "Bounded byte inputs are required for protected secrets")
            private_secret.extend(private_key_bytes)
            passphrase_secret.extend(passphrase)
            if not private_secret or not passphrase_secret:
                raise ProtectedSigningError("SECRET_REQUIRED", "Protected key and passphrase inputs are required")
            output = _new_owned_directory(output_root, "signing output")
            self._output_root = output
            work = _new_owned_directory(output.path / ".protected-work", "private signing work")
            home = _new_owned_directory(work.path / "gnupg", "private GnuPG home")
            staging = _new_owned_directory(work.path / "staging", "private staging")
            self._agent = OwnedGpgAgent(home.path, work.path)
            self._agent.start()
            self._import_key(home.path, work.path, public_key_bytes, bytes(private_secret))
            rpm_db = self._import_rpm_key(home.path, work.path, public_key_bytes) if any(obj.channel == "rpm" for obj in checked) else None
            for obj, name in zip(checked, names, strict=True):
                original = (_read_stable(obj.path, obj.sha256, obj.size, "unsigned object")
                            if lease is None else lease.read_unsigned(obj))
                stage = staging.path / name
                _exclusive_write(stage, original, "staged unsigned object")
                if obj.channel == "apt":
                    observed = _read_regular_unpinned(stage, "staged DEB")
                    if observed != original:
                        raise ProtectedSigningError("PACKAGE_MUTATED", "DEB package bytes changed during protected signing")
                    self._write_output("apt-output", output.path / "apt" / obj.architecture / stage.name, observed, "DEB output")
                    results.append({"channel": "apt", "product": obj.product, "architecture": obj.architecture,
                                    "name": name, "package_sha256": _sha256(observed)})
                elif obj.channel == "rpm":
                    self._rpm_sign(stage, home.path, work.path, bytes(passphrase_secret))
                    if rpm_db is None:
                        raise ProtectedSigningError("RPM_KEY_DATABASE", "RPM verification database was not initialized")
                    rpm_verification = self._rpm_verify(stage, rpm_db, home.path, work.path)
                    signed = _read_regular_unpinned(stage, "signed RPM")
                    preservation = inspect_rpm_preservation(original, signed)
                    archive = "x86_64" if obj.architecture == "noarch" else obj.architecture
                    self._write_output("rpm-output", output.path / "rpm" / archive / stage.name, signed, "signed RPM output")
                    if obj.architecture == "noarch":
                        self._write_output("noarch-output", output.path / "rpm" / "aarch64" / stage.name, signed, "reused signed noarch RPM")
                    results.append({"channel": "rpm", "product": obj.product, "architecture": obj.architecture,
                                    "name": name, "preservation": preservation, "rpm_verification": rpm_verification})
                else:
                    signature = staging.path / (stage.name + ".sig")
                    self._pacman_sign(stage, signature, home.path, work.path, bytes(passphrase_secret))
                    self._pacman_verify(stage, signature, home.path, work.path)
                    observed = _read_regular_unpinned(stage, "signed Pacman input")
                    if observed != original:
                        raise ProtectedSigningError("PACKAGE_MUTATED", "Pacman package bytes changed during signing")
                    archive = "x86_64" if obj.architecture == "any" else obj.architecture
                    self._write_output("pacman-output", output.path / "pacman" / archive / stage.name, observed, "Pacman package output")
                    signature_bytes = _read_regular_unpinned(signature, "Pacman signature")
                    self._write_output("signature-output", output.path / "pacman" / archive / signature.name, signature_bytes, "Pacman signature output")
                    results.append({"channel": "pacman", "product": obj.product, "architecture": obj.architecture,
                                    "name": name, "package_sha256": _sha256(observed)})
            self._final_output_inventory(output, work)
            result = ExecutionResult(
                schema="tf.current-protected-signing-execution.v1",
                status="observed" if native_observation else "test-only",
                production_authority=False, native_execution=native_observation,
                output_root=str(output.path), objects=tuple(results),
            )
        except BaseException as error:
            body_error = error
            self._remember_resource_errors(error)
            if lease is not None and (
                    isinstance(error, OSError)
                    or (isinstance(error, ProtectedSigningError) and error.code in {
                        "PACKAGE_MUTATED", "OUTPUT_INVENTORY", "OUTPUT_CUSTODY", "FILE_CHANGED",
                    })):
                # A live output/custody mismatch is terminal even if native
                # consumers subsequently stop successfully.
                self._resource_failures.append(error)
        finally:
            for secret in (private_secret, passphrase_secret):
                try:
                    _clear_secret(secret)
                except BaseException as error:
                    cleanup_errors.append(error)
            if self._agent is not None:
                try:
                    self._agent.close()
                    if not self._agent.cleanup_confirmed:
                        cleanup_errors.append(ProtectedSigningError("AGENT_CLEANUP", "Agent cleanup is unconfirmed"))
                except BaseException as error:
                    cleanup_errors.append(error)

        known_uncertainty = bool(cleanup_errors or self._consumer_failures or self._resource_failures)
        if lease is not None and getattr(lease, "_state", None) == "retained":
            known_uncertainty = True
            cleanup_errors.append(ProtectedSigningError("LIVE_CUSTODY_RETAINED", "Live custody has an unresolved failure"))
        # Never close input holds while any consumer/agent/resource uncertainty
        # is already known. The final source check precedes all descriptor close.
        if lease is not None and not known_uncertainty:
            try:
                lease.check()
                lease._close_confirmed()
            except BaseException as error:
                cleanup_errors.append(error)
                known_uncertainty = True
        if known_uncertainty:
            raise self._retain_runtime(body_error, cleanup_errors, work=work, output=output,
                                       stage="before-directory-deletion") from None
        self._agent = None
        try:
            if work is not None:
                _remove_owned_directory(work)
            if body_error is not None and output is not None:
                _remove_owned_directory(output)
        except BaseException as error:
            # Lease teardown is already confirmed; do not revive its authority
            # or imply that earlier completed deletion can be rolled back.
            raise self._retain_runtime(body_error, (error,), work=work, output=output,
                                       stage="partial-directory-cleanup") from None
        if body_error is not None:
            raise body_error
        return result

    def execute_live_lease(
        self, lease: Any, *, output_root: str | Path, public_key_bytes: bytes,
        private_key_bytes: bytes | bytearray, passphrase: bytes | bytearray,
    ) -> ExecutionResult:
        """Strict transfer-minted intake; raw objects cannot select this entry."""
        self._require_idle()
        try:
            from current_import_routing import _LiveSigningLease
        except ImportError as error:
            raise ProtectedSigningError("LIVE_OWNER_API", "Live routing owner is unavailable") from error
        if type(lease) is not _LiveSigningLease:
            raise ProtectedSigningError("LIVE_LEASE_REQUIRED", "Module-owned live lease required")
        # The owner checks its minted registry, PID and active state. An intake
        # refusal does not touch an already-running lease owned by another call.
        try:
            lease._begin()
        except Exception as error:
            raise ProtectedSigningError("LIVE_LEASE_REQUIRED", "Transfer-minted active lease is required") from error
        self._active_live_lease = lease
        try:
            return self._execute_checked(
                (), origin="", output_root=output_root, public_key_bytes=public_key_bytes,
                private_key_bytes=private_key_bytes, passphrase=passphrase,
            )
        finally:
            self._active_live_lease = None

    @staticmethod
    def retain_apt_signatures(
        apt_candidate: Any, signed_store: Any, *, inrelease_bytes: bytes, release_gpg_bytes: bytes,
        issuer: str, evidence: Mapping[str, object], inrelease_adapter: Any, detached_adapter: Any,
    ) -> tuple[Any, Any]:
        """Call concrete AptSignatureAdapter and existing RS9 retention APIs."""
        try:
            from apt_signature_adapter import AptSignatureAdapter
            from rs9.repo_apt import AptRepositoryCandidate
            from rs9.signed_store import SignedStore
        except ImportError as error:
            raise ProtectedSigningError("APT_OWNER_API", "APT4/RS9 production APIs are unavailable") from error
        if not isinstance(apt_candidate, AptRepositoryCandidate) or not isinstance(signed_store, SignedStore):
            raise ProtectedSigningError("APT_OWNER_API", "Existing AptRepositoryCandidate and SignedStore are required")
        if type(inrelease_adapter) is not AptSignatureAdapter or type(detached_adapter) is not AptSignatureAdapter:
            raise ProtectedSigningError("APT_ADAPTER", "Concrete APT4 AptSignatureAdapter instances are required")
        if issuer != PRIMARY_FINGERPRINT or not inrelease_bytes or not release_gpg_bytes:
            raise ProtectedSigningError("APT_INPUT", "APT signatures and committed issuer are required")
        records = []
        for inline, signature, adapter in ((True, inrelease_bytes, inrelease_adapter), (False, release_gpg_bytes, detached_adapter)):
            validator = adapter.as_signed_store_validator()
            if not callable(validator):
                raise ProtectedSigningError("APT_ADAPTER", "APT4 native validator callback is unavailable")
            try:
                records.append(apt_candidate.retain_external_signature(
                    signed_store, signature, inline=inline, issuer=issuer, evidence=dict(evidence), validator=validator,
                ))
            except Exception as error:
                raise ProtectedSigningError("APT_RETAIN_FAILED", "Existing APT/SignedStore retention failed") from error
        return records[0], records[1]


__all__ = [
    "AuthenticatedUnsignedBundle", "ExecutionResult", "NativeProtectedProcessRunner", "ProcessResult",
    "ProtectedSigningRuntime", "inspect_rpm_preservation", "load_authenticated_unsigned_bundle",
]
