"""Pinned public-key-only APT signature validation adapter.

This proposal is independent of the RS9 source tree.  It exposes the
validation result shape accepted by ``SignedStore.retain`` and owns a concrete
bounded GnuPG runner for the protected public hosted production workflow.
Controlled executors are fixture seams only and never confer retention
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime as _datetime
import hashlib
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Mapping, Protocol


GPG_BINARY = "/usr/bin/gpg"
PRIMARY_FINGERPRINT = "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF"
SIGNING_SUBKEY_FINGERPRINT = "C021E00EE3D37C459B0E1CB3199F8028126E8A8C"
PUBLIC_KEY_SHA256 = "6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95"
SCHEMA = "tf.apt-public-signature-validation.v3"

MAX_PUBLIC_KEY_BYTES = 8 * 1024 * 1024
MAX_RELEASE_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 8 * 1024 * 1024
MAX_INRELEASE_BYTES = MAX_RELEASE_BYTES + MAX_SIGNATURE_BYTES
MAX_STATUS_BYTES = 256 * 1024
MAX_STDERR_BYTES = 256 * 1024
MAX_GPG_BINARY_BYTES = 64 * 1024 * 1024
GPG_TIMEOUT_SECONDS = 30.0

# Strong process-local ownership. Uncertain public verification resources have
# no automatic retry or force-cleanup path; the containing runner must stop.
_RETAINED_PUBLIC_VERIFIERS: list[object] = []


def _retain_public_verifier(owner: object) -> None:
    if all(owner is not existing for existing in _RETAINED_PUBLIC_VERIFIERS):
        _RETAINED_PUBLIC_VERIFIERS.append(owner)

CLOCK_SKEW_SECONDS = 300

_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
_SAFE_KIND = {"inrelease", "release.gpg"}
_SAFE_STATUS = {
    "NEWSIG", "KEY_CONSIDERED", "SIG_ID", "GOODSIG", "VALIDSIG",
    "TRUST_UNDEFINED", "TRUST_FULLY", "TRUST_ULTIMATE", "PLAINTEXT",
    "PLAINTEXT_LENGTH",
}
_REJECT_STATUS = {
    "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED",
    "SIGEXPIRED", "NO_PUBKEY", "NODATA", "FAILURE", "ERROR", "BADARMOR",
    "UNEXPECTED", "UNSUPPORTED_ALGORITHM", "DECRYPTION_FAILED", "BADMDC",
    "TRUST_NEVER", "TRUST_MARGINAL",
}
_STRONG_HASH_ALGORITHMS = {"8", "9", "10", "11"}
_SIGNATURE_CLASS = {"inrelease": "01", "release.gpg": "00"}
_KEY_RECORDS = {"tru", "uid", "uat", "sig", "rvs"}


class SignatureValidationError(ValueError):
    """Stable, non-sensitive failure used by the adapter and its caller."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class CommandResult:
    """Bounded runner result; stdout is status or key-listing output."""

    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass(frozen=True)
class FileIdentity:
    """Fields sufficient to detect replacement, truncation, and mutation."""

    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass
class StagedFile:
    """Read-only descriptor and pathname held across the GPG invocation."""

    path: Path
    fd: int
    identity: FileIdentity
    data: bytes

    def assert_unchanged(self) -> None:
        try:
            path_info = _lstat_no_symlink(self.path, "staged input")
            current = _file_identity(os.fstat(self.fd))
            if path_info is None or current != self.identity or _file_identity(path_info) != self.identity:
                raise SignatureValidationError("STAGED_FILE_CHANGED", "Staged input identity changed")
            observed = os.pread(self.fd, len(self.data), 0)
            if observed != self.data:
                raise SignatureValidationError("STAGED_FILE_CHANGED", "Staged input bytes changed")
        except SignatureValidationError as error:
            if error.code == "STAGED_FILE_CHANGED":
                raise
            raise SignatureValidationError("STAGED_FILE_CHANGED", "Staged input path changed") from None
        except OSError:
            raise SignatureValidationError("STAGED_FILE_CHANGED", "Staged input could not be read") from None

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            raise SignatureValidationError("STAGED_CLOSE_UNCONFIRMED", "Staged descriptor cleanup is unconfirmed") from None


class GpgRunner(Protocol):
    def __call__(self, argv: tuple[str, ...], env: Mapping[str, str], phase: str) -> CommandResult: ...


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_fingerprint(value: str) -> str:
    if not isinstance(value, str):
        raise SignatureValidationError("FINGERPRINT_FORMAT", "Fingerprint must be text")
    normalized = value.strip().replace(" ", "").upper().removeprefix("0X")
    if not _FINGERPRINT.fullmatch(normalized):
        raise SignatureValidationError("FINGERPRINT_FORMAT", "Full 40-character fingerprint required")
    return normalized


def _absolute_path(path: str | Path, label: str) -> Path:
    raw = str(path)
    candidate = Path(path)
    if not candidate.is_absolute():
        raise SignatureValidationError("PATH_FORMAT", f"{label} must be absolute")
    if "\x00" in raw:
        raise SignatureValidationError("PATH_FORMAT", f"{label} contains NUL")
    if any(part in {".", ".."} for part in candidate.parts):
        raise SignatureValidationError("PATH_FORMAT", f"{label} contains traversal")
    return candidate


def _file_identity(info: os.stat_result) -> FileIdentity:
    return FileIdentity(
        dev=info.st_dev,
        ino=info.st_ino,
        mode=stat.S_IMODE(info.st_mode) | stat.S_IFMT(info.st_mode),
        uid=info.st_uid,
        gid=info.st_gid,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


def _lstat_no_symlink(path: Path, label: str, *, allow_missing: bool = False) -> os.stat_result | None:
    """Inspect every component without following a symlink."""
    current = Path(path.anchor or "/")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    if not parts:
        try:
            return os.lstat(current)
        except OSError:
            raise SignatureValidationError("PATH_IO", f"Unable to inspect {label}") from None
    info: os.stat_result | None = None
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if allow_missing and index == len(parts) - 1:
                return None
            raise SignatureValidationError("PATH_MISSING", f"{label} is missing") from None
        except OSError:
            raise SignatureValidationError("PATH_IO", f"Unable to inspect {label}") from None
        if stat.S_ISLNK(info.st_mode):
            raise SignatureValidationError("SYMLINK_REJECTED", f"{label} contains a symlink")
    return info


def _read_regular(
    path: str | Path,
    label: str,
    max_bytes: int,
    *,
    require_owner: bool = False,
    private_mode: bool = False,
) -> tuple[bytes, FileIdentity]:
    candidate = _absolute_path(path, label)
    path_info = _lstat_no_symlink(candidate, label)
    assert path_info is not None
    try:
        fd = os.open(str(candidate), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise SignatureValidationError("PATH_IO", f"Unable to open {label}") from None
    body_error = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SignatureValidationError("REGULAR_FILE_REQUIRED", f"{label} must be regular")
        if _file_identity(path_info) != _file_identity(before):
            raise SignatureValidationError("FILE_CHANGED", f"{label} changed before read")
        if require_owner and before.st_uid != os.getuid():
            raise SignatureValidationError("FILE_CUSTODY", f"{label} is not owned by the current user")
        if private_mode and stat.S_IMODE(before.st_mode) & 0o077:
            raise SignatureValidationError("FILE_MODE", f"{label} is not private")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise SignatureValidationError("FILE_LIMIT", f"{label} exceeds its bound")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            block = os.read(fd, min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > max_bytes:
                break
        data = b"".join(chunks)
        after = os.fstat(fd)
        if len(data) > max_bytes or _file_identity(before) != _file_identity(after) or len(data) != before.st_size:
            raise SignatureValidationError("FILE_CHANGED", f"{label} changed during read")
        return data, _file_identity(before)
    except BaseException as error:
        body_error = error
        raise
    finally:
        _close_public_descriptor(fd, candidate, body_error)


def _validate_home(home: str | Path, *, require_empty: bool) -> Path:
    candidate = _absolute_path(home, "verification home")
    info = _lstat_no_symlink(candidate, "verification home")
    if info is None or not stat.S_ISDIR(info.st_mode):
        raise SignatureValidationError("HOME_REQUIRED", "Verification home directory required")
    if info.st_uid != os.getuid():
        raise SignatureValidationError("HOME_OWNER", "Verification home is not owned by current user")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise SignatureValidationError("HOME_MODE", "Verification home must be mode 0700")
    if require_empty:
        try:
            entries = os.listdir(candidate)
        except OSError:
            raise SignatureValidationError("HOME_IO", "Unable to inspect verification home") from None
        if entries:
            raise SignatureValidationError("HOME_NOT_FRESH", "Verification home must be empty before import")
    return candidate


def _validate_scoped_path(path: str | Path, home: Path, label: str) -> Path:
    candidate = _absolute_path(path, label)
    _lstat_no_symlink(candidate.parent, f"{label} parent")
    try:
        candidate.relative_to(home)
    except ValueError:
        raise SignatureValidationError("KEYRING_SCOPE", f"{label} must be inside verification home") from None
    return candidate


def _validate_destination(path: str | Path, home: Path, label: str) -> Path:
    candidate = _validate_scoped_path(path, home, label)
    if _lstat_no_symlink(candidate, label, allow_missing=True) is not None:
        raise SignatureValidationError("DESTINATION_EXISTS", f"Fresh {label} destination already exists")
    return candidate


def _mkdir_owned(parent: Path, name: str) -> Path:
    if "/" in name or name in {".", ".."}:
        raise SignatureValidationError("PATH_FORMAT", "Invalid private staging directory name")
    target = parent / name
    try:
        os.mkdir(target, 0o700)
    except FileExistsError:
        raise SignatureValidationError("DESTINATION_EXISTS", "Staging directory already exists") from None
    except OSError:
        raise SignatureValidationError("STAGING_IO", "Unable to create staging directory") from None
    info = _lstat_no_symlink(target, "staging directory")
    if info is None or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SignatureValidationError("STAGING_CUSTODY", "Staging directory custody is invalid")
    return target


def _close_public_descriptor(fd: int, path: Path, original_error: BaseException | None) -> None:
    """Close once; retain the actual uncertain resource without retry."""
    try:
        os.close(fd)
    except OSError as error:
        record = {"fd": fd, "path": path, "status": "close-uncertain",
                  "original_error": original_error, "cleanup_error": error}
        _retain_public_verifier(record)
        failure = SignatureValidationError(
            "STAGED_CLEANUP_UNCONFIRMED", "Public descriptor cleanup is unconfirmed",
        )
        failure.original_error = original_error
        failure.cleanup_errors = (error,)
        failure.retained_descriptors = (record,)
        raise failure from None


def _stage_file(parent: Path, name: str, data: bytes, max_bytes: int) -> StagedFile:
    if not name or "/" in name or name in {".", ".."}:
        raise SignatureValidationError("PATH_FORMAT", "Invalid staged filename")
    if len(data) > max_bytes:
        raise SignatureValidationError("FILE_LIMIT", "Staged data exceeds its bound")
    target = parent / name
    try:
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise SignatureValidationError("STAGING_IO", "Unable to create staged file") from None
    body_error = None
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("Staged write made no progress")
            offset += written
        os.fsync(fd)
    except BaseException as error:
        body_error = error
    _close_public_descriptor(fd, target, body_error)
    if body_error is not None:
        if isinstance(body_error, OSError):
            raise SignatureValidationError("STAGING_IO", "Unable to write staged file") from None
        raise body_error
    read_fd = None
    try:
        read_fd = os.open(str(target), os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(read_fd)
        path_info = _lstat_no_symlink(target, "staged file")
        if (not stat.S_ISREG(info.st_mode) or info.st_size != len(data)
                or path_info is None or _file_identity(path_info) != _file_identity(info)):
            raise SignatureValidationError("STAGING_CUSTODY", "Staged file identity is invalid")
        staged = StagedFile(target, read_fd, _file_identity(info), data)
        staged.assert_unchanged()
        return staged
    except BaseException as error:
        if read_fd is not None:
            _close_public_descriptor(read_fd, target, error)
        if isinstance(error, OSError):
            raise SignatureValidationError("STAGING_IO", "Unable to reopen staged file") from None
        raise


def _create_private_output(parent: Path, name: str) -> Path:
    """Create the GnuPG output before launch so its mode cannot follow umask."""
    if not name or "/" in name or name in {".", ".."}:
        raise SignatureValidationError("PATH_FORMAT", "Invalid private output filename")
    target = parent / name
    fd = None
    body_error = None
    try:
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fsync(fd)
    except BaseException as error:
        body_error = error
    if fd is not None:
        _close_public_descriptor(fd, target, body_error)
    if isinstance(body_error, FileExistsError):
        raise SignatureValidationError("DESTINATION_EXISTS", "Plaintext output already exists") from None
    if isinstance(body_error, OSError):
        raise SignatureValidationError("STAGING_IO", "Unable to create private plaintext output") from None
    if body_error is not None:
        raise body_error
    info = _lstat_no_symlink(target, "plaintext output")
    if info is None or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise SignatureValidationError("STAGING_CUSTODY", "Plaintext output custody is invalid")
    return target


def _common_command(gpg_binary: str | Path, *, home: str | Path, keyring: str | Path) -> tuple[str, ...]:
    return (
        str(_absolute_path(gpg_binary, "GnuPG binary")), "--homedir", str(_absolute_path(home, "verification home")),
        "--batch", "--yes", "--no-tty", "--no-options", "--no-auto-check-trustdb", "--no-auto-key-retrieve",
        "--disable-dirmngr", "--no-autostart", "--no-default-keyring", "--keyring",
        str(_absolute_path(keyring, "keyring")),
    )


def build_import_command(
    gpg_binary: str | Path, *, home: str | Path, keyring: str | Path, public_key: str | Path
) -> tuple[str, ...]:
    """Build deterministic public-key import argv; never execute it here."""
    return _common_command(gpg_binary, home=home, keyring=keyring) + (
        "--import", str(_absolute_path(public_key, "public key")),
    )


def build_key_listing_command(
    gpg_binary: str | Path, *, home: str | Path, keyring: str | Path
) -> tuple[str, ...]:
    """Build the bounded post-import public-key capability listing command."""
    return _common_command(gpg_binary, home=home, keyring=keyring) + (
        "--with-colons", "--fixed-list-mode", "--list-keys", PRIMARY_FINGERPRINT,
    )


def build_verify_command(
    gpg_binary: str | Path, *, kind: str, home: str | Path, keyring: str | Path,
    signed: str | Path, release: str | Path, plaintext: str | Path,
) -> tuple[str, ...]:
    """Build isolated verify/decrypt argv using only staged paths."""
    if kind not in _SAFE_KIND:
        raise SignatureValidationError("SIGNATURE_KIND", "Only InRelease and Release.gpg are supported")
    common = _common_command(gpg_binary, home=home, keyring=keyring) + ("--status-fd", "1")
    if kind == "inrelease":
        return common + (
            "--output", str(_absolute_path(plaintext, "plaintext output")), "--decrypt",
            str(_absolute_path(signed, "InRelease")),
        )
    return common + (
        "--verify", str(_absolute_path(signed, "Release.gpg")), str(_absolute_path(release, "Release")),
    )


def _validate_clearsigned_structure(data: bytes) -> None:
    if not isinstance(data, bytes) or len(data) > MAX_INRELEASE_BYTES:
        raise SignatureValidationError("SIGNATURE_LIMIT", "InRelease exceeds its bound")
    signed_marker = b"-----BEGIN PGP SIGNED MESSAGE-----"
    signature_marker = b"-----BEGIN PGP SIGNATURE-----"
    end_marker = b"-----END PGP SIGNATURE-----"
    if data.count(signed_marker) != 1 or data.count(signature_marker) != 1 or data.count(end_marker) != 1:
        raise SignatureValidationError("SIGNATURE_FORMAT", "Exactly one clearsigned message is required")
    first_eol = data.find(b"\n")
    if first_eol < 0 or data[:first_eol].rstrip(b"\r") != signed_marker:
        raise SignatureValidationError("SIGNATURE_FORMAT", "InRelease cleartext header missing")
    header_start = first_eol + 1
    blank = re.search(br"\r?\n\r?\n", data[header_start:])
    if blank is None:
        raise SignatureValidationError("SIGNATURE_FORMAT", "InRelease header terminator missing")
    body_start = header_start + blank.end()
    signature_offset = data.find(signature_marker, body_start)
    if signature_offset <= body_start or data[signature_offset - 1:signature_offset] not in {b"\n", b"\r"}:
        raise SignatureValidationError("SIGNATURE_FORMAT", "InRelease signature block boundary invalid")
    end_offset = data.find(end_marker, signature_offset + len(signature_marker))
    if end_offset < 0 or data[end_offset - 1:end_offset] not in {b"\n", b"\r"}:
        raise SignatureValidationError("SIGNATURE_FORMAT", "InRelease signature terminator invalid")
    trailing = data[end_offset + len(end_marker):]
    if trailing not in {b"", b"\n", b"\r\n"}:
        raise SignatureValidationError("SIGNATURE_FORMAT", "Trailing clearsigned content is forbidden")


def _timestamp_value(value: str, label: str, *, allow_zero: bool) -> float:
    """Parse GnuPG DETAILS date fields without accepting invented formats."""
    if value == "0" and allow_zero:
        return 0.0
    if re.fullmatch(r"\d+", value):
        parsed = int(value)
        if parsed == 0:
            raise SignatureValidationError("STATUS_FORMAT", f"{label} must be non-zero")
        return float(parsed)
    normalized = value
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed_date = _datetime.datetime.fromisoformat(normalized)
    except ValueError:
        parsed_date = None
    if parsed_date is None:
        try:
            return _datetime.datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=_datetime.timezone.utc).timestamp()
        except ValueError:
            raise SignatureValidationError("STATUS_FORMAT", f"{label} is not a documented GnuPG timestamp") from None
    if parsed_date.tzinfo is None:
        parsed_date = parsed_date.replace(tzinfo=_datetime.timezone.utc)
    return parsed_date.timestamp()


def _parse_status(status_bytes: bytes, kind: str, *, now: float | None = None) -> dict[str, str]:
    if not isinstance(status_bytes, bytes) or len(status_bytes) > MAX_STATUS_BYTES:
        raise SignatureValidationError("STATUS_LIMIT", "GnuPG status stream exceeds its bound")
    try:
        text = status_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise SignatureValidationError("STATUS_FORMAT", "GnuPG status stream is not ASCII") from None
    now_value = time.time() if now is None else float(now)
    newsig_count = sig_id_count = plaintext_count = 0
    good: list[list[str]] = []
    valid: list[list[str]] = []
    trust: list[str] = []
    for line in text.splitlines():
        if not line.startswith("[GNUPG:] "):
            raise SignatureValidationError("STATUS_FORMAT", "Unexpected non-status GnuPG output")
        fields = line[len("[GNUPG:] "):].split()
        if not fields:
            raise SignatureValidationError("STATUS_FORMAT", "Empty GnuPG status record")
        tag, rest = fields[0], fields[1:]
        if tag in _REJECT_STATUS:
            raise SignatureValidationError("SIGNATURE_REJECTED", f"GnuPG reported {tag}")
        if tag not in _SAFE_STATUS:
            raise SignatureValidationError("STATUS_UNEXPECTED", f"Unexpected GnuPG status {tag}")
        if tag == "NEWSIG":
            newsig_count += 1
        elif tag == "SIG_ID":
            sig_id_count += 1
        elif tag == "GOODSIG":
            good.append(rest)
        elif tag == "VALIDSIG":
            valid.append(rest)
        elif tag == "PLAINTEXT":
            plaintext_count += 1
        elif tag.startswith("TRUST_"):
            trust.append(tag)
    if newsig_count != 1 or sig_id_count != 1 or len(good) != 1 or len(valid) != 1:
        raise SignatureValidationError("SIGNATURE_COUNT", "Exactly one GPG signature status sequence is required")
    if kind == "inrelease" and plaintext_count != 1:
        raise SignatureValidationError("PLAINTEXT_STATUS", "GPG did not emit exactly one plaintext status")
    if kind == "release.gpg" and plaintext_count:
        raise SignatureValidationError("PLAINTEXT_STATUS", "Detached verification emitted unexpected plaintext")
    fields = valid[0]
    if len(fields) < 10:
        raise SignatureValidationError("STATUS_FORMAT", "VALIDSIG identity fields are incomplete")
    signing = _normalize_fingerprint(fields[0])
    primary = _normalize_fingerprint(fields[9])
    if signing != SIGNING_SUBKEY_FINGERPRINT or primary != PRIMARY_FINGERPRINT:
        raise SignatureValidationError("IDENTITY_MISMATCH", "Signing subkey or primary fingerprint is not pinned")
    created_timestamp = _timestamp_value(fields[2], "Signature creation timestamp", allow_zero=False)
    created_date = _timestamp_value(fields[1], "Signature creation date", allow_zero=False)
    if _datetime.datetime.fromtimestamp(created_date, _datetime.timezone.utc).date() != _datetime.datetime.fromtimestamp(created_timestamp, _datetime.timezone.utc).date():
        raise SignatureValidationError("SIGNATURE_DATE_MISMATCH", "Signature creation date disagrees with its timestamp")
    if created_timestamp > now_value + CLOCK_SKEW_SECONDS:
        raise SignatureValidationError("SIGNATURE_TIME", "Signature creation time is in the future")
    expiry_timestamp = _timestamp_value(fields[3], "Signature expiry timestamp", allow_zero=True) if fields[3] else 0.0
    if expiry_timestamp and expiry_timestamp <= now_value:
        raise SignatureValidationError("SIGNATURE_EXPIRED", "Signature expiry date has passed")
    if fields[4] != "4" or not fields[6].isdigit() or fields[6] == "0":
        raise SignatureValidationError("SIGNATURE_FORMAT", "Unsupported OpenPGP signature version or public-key algorithm")
    if fields[7] not in _STRONG_HASH_ALGORITHMS:
        raise SignatureValidationError("WEAK_HASH", "Signature hash algorithm is not approved")
    if fields[8].upper() != _SIGNATURE_CLASS[kind]:
        raise SignatureValidationError("SIGNATURE_KIND", "Signature class does not match the signed object kind")
    good_key = good[0][0] if good[0] else ""
    if good_key.upper().removeprefix("0X") not in {signing[-16:], primary[-16:], signing, primary}:
        raise SignatureValidationError("IDENTITY_MISMATCH", "GOODSIG key identifier is not the pinned signer")
    return {
        "primary_fingerprint": primary,
        "signing_fingerprint": signing,
        "trust_status": trust[-1] if trust else "not-reported",
    }


def _parse_key_listing(listing_bytes: bytes, *, now: float | None = None) -> dict[str, str]:
    if not isinstance(listing_bytes, bytes) or len(listing_bytes) > MAX_STATUS_BYTES:
        raise SignatureValidationError("KEY_LISTING_LIMIT", "GPG key listing exceeds its bound")
    try:
        text = listing_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise SignatureValidationError("KEY_LISTING_FORMAT", "GPG key listing is not ASCII") from None
    now_value = time.time() if now is None else float(now)
    records: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    primary_for_subkey: str | None = None
    for line in text.splitlines():
        fields = line.split(":")
        record_type = fields[0] if fields else ""
        if record_type in {"pub", "sub"}:
            if len(fields) <= 11:
                raise SignatureValidationError("KEY_LISTING_FORMAT", "GPG key record is incomplete")
            try:
                created = int(fields[5] or "0")
                expires = int(fields[6] or "0")
            except ValueError:
                raise SignatureValidationError("KEY_LISTING_FORMAT", "GPG key dates are invalid") from None
            if created and created > now_value + CLOCK_SKEW_SECONDS:
                raise SignatureValidationError("KEY_LISTING_TIME", "GPG key was created in the future")
            if expires and expires <= now_value:
                raise SignatureValidationError("KEY_LISTING_EXPIRED", "Pinned GPG key is expired")
            if fields[1] in {"r", "e", "d", "i", "n"}:
                raise SignatureValidationError("KEY_LISTING_REVOKED", "Pinned GPG key is revoked or disabled")
            current = {
                "type": record_type,
                "trust": fields[1],
                "capabilities": fields[11],
                "fingerprint": None,
                "primary": primary_for_subkey if record_type == "sub" else None,
            }
            records.append(current)
        elif record_type == "fpr":
            if current is None or len(fields) <= 9:
                raise SignatureValidationError("KEY_LISTING_FORMAT", "GPG fingerprint record is misplaced")
            fingerprint = _normalize_fingerprint(fields[9])
            current["fingerprint"] = fingerprint
            if current["type"] == "pub":
                primary_for_subkey = fingerprint
                current["primary"] = fingerprint
        elif record_type in _KEY_RECORDS or not line:
            continue
        else:
            raise SignatureValidationError("KEY_LISTING_UNEXPECTED", "Unexpected GPG key-listing record")
    pubs = [entry for entry in records if entry["type"] == "pub"]
    subs = [entry for entry in records if entry["type"] == "sub"]
    if len(pubs) != 1 or len(subs) != 1 or any(entry["fingerprint"] is None for entry in records):
        raise SignatureValidationError("KEY_LISTING_COUNT", "GPG key listing is not exactly one primary and one subkey")
    primary = pubs[0]
    signing = subs[0]
    if primary["fingerprint"] != PRIMARY_FINGERPRINT or signing["fingerprint"] != SIGNING_SUBKEY_FINGERPRINT:
        raise SignatureValidationError("KEY_LISTING_IDENTITY", "GPG key listing fingerprints do not match pins")
    if signing["primary"] != PRIMARY_FINGERPRINT or "s" not in str(signing["capabilities"]):
        raise SignatureValidationError("KEY_LISTING_CAPABILITY", "Pinned signing subkey is not bound or signing-capable")
    return {
        "primary_fingerprint": PRIMARY_FINGERPRINT,
        "signing_fingerprint": SIGNING_SUBKEY_FINGERPRINT,
        "key_listing": "valid",
    }


class NativeGpgRunner:
    """Fixed GPG policy with native process ownership delegated to C6."""

    def __init__(
        self, gpg_binary: str | Path, *, timeout_seconds: float = GPG_TIMEOUT_SECONDS,
        max_stdout: int = MAX_STATUS_BYTES, max_stderr: int = MAX_STDERR_BYTES,
        executor: Callable[[tuple[str, ...], Mapping[str, str], str], CommandResult] | None = None,
    ) -> None:
        self.gpg_binary = str(_absolute_path(gpg_binary, "GnuPG binary"))
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise SignatureValidationError("RUNNER_CONFIG", "GPG timeout is outside the bound")
        if max_stdout <= 0 or max_stdout > MAX_STATUS_BYTES or max_stderr <= 0 or max_stderr > MAX_STDERR_BYTES:
            raise SignatureValidationError("RUNNER_CONFIG", "GPG output cap is outside the bound")
        self.timeout_seconds, self.max_stdout, self.max_stderr = timeout_seconds, max_stdout, max_stderr
        self._executor = executor
        self._executable_sha256: str | None = None
        self._retained_custody: object | None = None

    @property
    def trusted_native(self) -> bool:
        return self._executor is None and self.gpg_binary == GPG_BINARY

    @property
    def retained_custody(self) -> object | None:
        """Owned cleanup failure/resources; never serialize or retry."""
        return self._retained_custody

    @property
    def process_cleanup_confirmed(self) -> bool:
        return self._retained_custody is None

    @property
    def executable_sha256(self) -> str:
        return self._executable_sha256 or "fixture-not-recorded"

    def __call__(self, argv: tuple[str, ...], env: Mapping[str, str], phase: str) -> CommandResult:
        if self._retained_custody is not None:
            raise SignatureValidationError("RUNNER_CUSTODY_RETAINED", "Public verification cleanup remains unconfirmed")
        if not isinstance(argv, tuple) or not argv or argv[0] != self.gpg_binary:
            raise SignatureValidationError("RUNNER_COMMAND", "Runner received an unexpected GPG command")
        if phase not in {"import", "inspect", "verify"} or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
            raise SignatureValidationError("RUNNER_COMMAND", "GPG command shape is invalid")
        clean_env = self._clean_env(env)
        self._validate_argv(argv, clean_env, phase)
        if self._executor is not None:
            try:
                result = self._executor(argv, clean_env, phase)
            except SignatureValidationError:
                raise
            except TimeoutError:
                raise SignatureValidationError("GPG_TIMEOUT", "Controlled GPG runner timed out") from None
            except Exception:
                raise SignatureValidationError("RUNNER_IO", "Controlled GPG runner failed") from None
            return self._bounded_result(result)
        try:
            executable_sha = self._validate_native_binary()
        except SignatureValidationError as error:
            if getattr(error, "retained_descriptors", ()):
                self._retained_custody = error
                _retain_public_verifier(self)
            raise
        if self._executable_sha256 is not None and self._executable_sha256 != executable_sha:
            raise SignatureValidationError("GPG_BINARY_CHANGED", "GPG executable changed during validation")
        self._executable_sha256 = executable_sha
        return self._run_subprocess(argv, clean_env)

    def _clean_env(self, env: Mapping[str, str]) -> dict[str, str]:
        required = {"HOME", "GNUPGHOME", "LC_ALL", "LANG"}
        if set(env) != required or env.get("LC_ALL") != "C" or env.get("LANG") != "C":
            raise SignatureValidationError("RUNNER_ENV", "Runner environment is not the explicit isolated environment")
        home = str(env["HOME"])
        if home != str(env["GNUPGHOME"]) or not Path(home).is_absolute():
            raise SignatureValidationError("RUNNER_ENV", "HOME and GNUPGHOME must be the same absolute path")
        _absolute_path(home, "verification home")
        return {"HOME": home, "GNUPGHOME": home, "LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin"}

    def _validate_native_binary(self) -> str:
        if self.gpg_binary != GPG_BINARY:
            raise SignatureValidationError("GPG_BINARY_PATH", "Hosted production GPG path is not approved")
        info = _lstat_no_symlink(Path(GPG_BINARY), "GnuPG binary")
        if info is None or not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise SignatureValidationError("GPG_BINARY_CUSTODY", "GnuPG binary must be a root-owned regular file")
        mode = stat.S_IMODE(info.st_mode)
        if not mode & 0o111 or mode & 0o022:
            raise SignatureValidationError("GPG_BINARY_CUSTODY", "GnuPG binary permissions are unsafe")
        data, _ = _read_regular(GPG_BINARY, "GnuPG binary", MAX_GPG_BINARY_BYTES)
        return _sha256(data)

    @staticmethod
    def _path_argument(value: str, home: Path, label: str, *, allow_missing: bool, private_file: bool) -> Path:
        path = _validate_scoped_path(value, home, label)
        info = _lstat_no_symlink(path, label, allow_missing=allow_missing)
        if info is None:
            if not allow_missing:
                raise SignatureValidationError("RUNNER_COMMAND", f"{label} is missing")
            return path
        if private_file and (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise SignatureValidationError("RUNNER_COMMAND", f"{label} is not a private staged regular file")
        return path

    def _validate_argv(self, argv: tuple[str, ...], env: Mapping[str, str], phase: str) -> None:
        home = _absolute_path(env["GNUPGHOME"], "verification home")
        if "--keyring" not in argv:
            raise SignatureValidationError("RUNNER_COMMAND", "GPG keyring argument is required")
        keyring_index = argv.index("--keyring")
        if keyring_index + 1 >= len(argv):
            raise SignatureValidationError("RUNNER_COMMAND", "GPG keyring path is missing")
        keyring = argv[keyring_index + 1]
        common = _common_command(self.gpg_binary, home=home, keyring=keyring)
        if argv[:len(common)] != common:
            raise SignatureValidationError("RUNNER_COMMAND", "GPG command options are not the approved template")
        _validate_scoped_path(keyring, home, "keyring")
        if phase == "import":
            if len(argv) != len(common) + 2 or argv[-2] != "--import":
                raise SignatureValidationError("RUNNER_COMMAND", "GPG import command shape is invalid")
            self._path_argument(argv[-1], home, "staged public key", allow_missing=False, private_file=True)
            return
        if phase == "inspect":
            expected = common + ("--with-colons", "--fixed-list-mode", "--list-keys", PRIMARY_FINGERPRINT)
            if argv != expected:
                raise SignatureValidationError("RUNNER_COMMAND", "GPG key-listing command shape is invalid")
            return
        detached = len(argv) >= 4 and "--verify" in argv
        if detached:
            if len(argv) != len(common) + 5 or argv[len(common)] != "--status-fd" or argv[len(common) + 1] != "1" or argv[len(common) + 2] != "--verify":
                raise SignatureValidationError("RUNNER_COMMAND", "GPG detached verification shape is invalid")
            self._path_argument(argv[-2], home, "staged signature", allow_missing=False, private_file=True)
            self._path_argument(argv[-1], home, "staged Release", allow_missing=False, private_file=True)
            return
        if len(argv) != len(common) + 6 or argv[len(common):len(common) + 3] != ("--status-fd", "1", "--output"):
            raise SignatureValidationError("RUNNER_COMMAND", "GPG InRelease verification shape is invalid")
        self._path_argument(argv[len(common) + 3], home, "plaintext output", allow_missing=False, private_file=True)
        if argv[len(common) + 4] != "--decrypt":
            raise SignatureValidationError("RUNNER_COMMAND", "GPG InRelease decrypt option is missing")
        self._path_argument(argv[len(common) + 5], home, "staged InRelease", allow_missing=False, private_file=True)

    def _bounded_result(self, result: CommandResult) -> CommandResult:
        if not isinstance(result, CommandResult):
            raise SignatureValidationError("RUNNER_IO", "Runner returned an invalid result")
        if len(result.stdout) > self.max_stdout or len(result.stderr) > self.max_stderr:
            raise SignatureValidationError("GPG_OUTPUT_LIMIT", "GPG output exceeded its bound")
        return result

    def _run_subprocess(self, argv: tuple[str, ...], env: Mapping[str, str]) -> CommandResult:
        """Delegate native process ownership to the existing C6 runner."""
        try:
            from protected_signing_runtime import (
                MAX_PROCESS_OUTPUT, PROCESS_TIMEOUT_SECONDS,
                NativeProtectedProcessRunner, ProcessResult, ProtectedSigningError,
            )
        except ImportError:
            raise SignatureValidationError(
                "PROCESS_OWNER_UNAVAILABLE", "Existing bounded process owner is unavailable",
            ) from None
        # This native profile uses the existing owner's fixed 256 KiB streams.
        # Controlled executors retain their existing configurable fixture caps.
        if (self.timeout_seconds > PROCESS_TIMEOUT_SECONDS
                or self.max_stdout != MAX_PROCESS_OUTPUT
                or self.max_stderr != MAX_PROCESS_OUTPUT):
            raise SignatureValidationError(
                "RUNNER_CONFIG", "Native bounds must fit the existing process owner",
            )
        try:
            result = NativeProtectedProcessRunner().run(
                argv, cwd=Path(env["GNUPGHOME"]), env=env, stdin=b"",
                phase="apt-public-signature-verification", timeout=self.timeout_seconds,
            )
        except ProtectedSigningError as error:
            if error.code == "COMMAND_CLEANUP":
                # Keep the actual C6 error and its owned process/resources.
                # No serialization, retry, fallback, or additional signaling.
                self._retained_custody = error
                _retain_public_verifier(self)
                failure = SignatureValidationError(
                    "GPG_CLEANUP_UNCONFIRMED", "Public verification cleanup is unconfirmed",
                )
                failure.cleanup_confirmed = False
                failure.original_code = getattr(getattr(error, "original_error", None), "code", None)
                raise failure from None
            mapped = {
                "COMMAND_TIMEOUT": "GPG_TIMEOUT",
                "COMMAND_OUTPUT_LIMIT": "GPG_OUTPUT_LIMIT",
                "COMMAND_POLICY": "RUNNER_CONFIG",
            }.get(error.code, "RUNNER_IO")
            raise SignatureValidationError(mapped, "Bounded public verification failed") from None
        except OSError:
            raise SignatureValidationError("RUNNER_IO", "Unable to run public verification") from None
        if type(result) is not ProcessResult:
            raise SignatureValidationError("RUNNER_IO", "Process owner returned an invalid result")
        return self._bounded_result(CommandResult(result.returncode, result.stdout, result.stderr))


def _build_validation_result(
    *,
    kind: str,
    release_data: bytes,
    signed_data: bytes,
    key_facts: Mapping[str, str],
    identity: Mapping[str, str],
    native: bool,
    gpg_binary_sha256: str,
) -> dict[str, str]:
    """Build the one result shape shared by validation and seam tests."""
    result = {
        "schema": SCHEMA,
        "status": "valid",
        "release_sha256": _sha256(release_data),
        "signed_sha256": _sha256(signed_data),
        "public_key_sha256": PUBLIC_KEY_SHA256,
        "signature_kind": kind,
        "trust_status": identity["trust_status"],
        "key_listing": key_facts["key_listing"],
        "verification_mode": "native" if native else "fixture",
        "confers_signature_authentication": "true" if native else "false",
        "gpg_binary_sha256": gpg_binary_sha256,
    }
    if native:
        result.update({
            "verified_issuer": PRIMARY_FINGERPRINT,
            "primary_key_id": PRIMARY_FINGERPRINT,
            "primary_fingerprint": identity["primary_fingerprint"],
            "signing_subkey": identity["signing_fingerprint"],
        })
    else:
        result.update({
            "fixture_primary_fingerprint": identity["primary_fingerprint"],
            "fixture_signing_fingerprint": identity["signing_fingerprint"],
            "fixture_key_listing": key_facts["key_listing"],
        })
    return result


class AptSignatureAdapter:
    """Validate callback-held APT signature bytes through an isolated runner."""

    def __init__(
        self, *, kind: str, gpg_binary: str | Path, public_key: str | Path,
        verification_home: str | Path, keyring: str | Path, runner: GpgRunner,
    ) -> None:
        if kind not in _SAFE_KIND:
            raise SignatureValidationError("SIGNATURE_KIND", "Only InRelease and Release.gpg are supported")
        self.kind = kind
        self.gpg_binary, self.public_key = _absolute_path(gpg_binary, "GnuPG binary"), _absolute_path(public_key, "public key")
        self.home = _validate_home(verification_home, require_empty=False)
        self.keyring = _validate_scoped_path(keyring, self.home, "keyring")
        if not callable(runner):
            raise SignatureValidationError("RUNNER_REQUIRED", "Callable GPG runner required")
        self.runner = runner
        self._used = False
        self._retained_staged: tuple[StagedFile, ...] = ()
        self._retained_allocations: tuple[object, ...] = ()

    @property
    def retained_custody(self) -> object | None:
        """Read-only handoff of uncertain public verification ownership."""
        owner = self.runner.retained_custody if type(self.runner) is NativeGpgRunner else None
        if owner is not None or self._retained_staged or self._retained_allocations:
            return (owner, self._retained_staged + self._retained_allocations)
        return None

    @property
    def process_cleanup_confirmed(self) -> bool:
        return type(self.runner) is NativeGpgRunner and self.runner.process_cleanup_confirmed

    @property
    def _real_runner(self) -> bool:
        return type(self.runner) is NativeGpgRunner and self.runner.trusted_native

    def _read_inputs(self, release_bytes: bytes, signed_bytes: bytes) -> tuple[bytes, bytes, bytes]:
        if not isinstance(release_bytes, bytes) or not release_bytes or len(release_bytes) > MAX_RELEASE_BYTES:
            raise SignatureValidationError("RELEASE_LIMIT", "Release bytes are missing or oversized")
        signed_limit = MAX_INRELEASE_BYTES if self.kind == "inrelease" else MAX_SIGNATURE_BYTES
        if not isinstance(signed_bytes, bytes) or not signed_bytes or len(signed_bytes) > signed_limit:
            raise SignatureValidationError("SIGNATURE_LIMIT", "Signature bytes are missing or oversized")
        key_bytes, _ = _read_regular(self.public_key, "public key", MAX_PUBLIC_KEY_BYTES)
        if b"BEGIN PGP PRIVATE KEY BLOCK" in key_bytes:
            raise SignatureValidationError("PRIVATE_KEY_REJECTED", "Private key material is forbidden")
        if _sha256(key_bytes) != PUBLIC_KEY_SHA256:
            raise SignatureValidationError("KEY_DIGEST_MISMATCH", "Public key is not the committed key bundle")
        if self.kind == "inrelease":
            _validate_clearsigned_structure(signed_bytes)
        return key_bytes, release_bytes, signed_bytes

    def validate(self, release_bytes: bytes, signed_bytes: bytes, evidence: Mapping[str, object] | None = None) -> dict[str, str]:
        if self._used:
            raise SignatureValidationError("ADAPTER_REUSED", "A fresh verification home is single-use")
        self._used = True
        native_authority = self._real_runner
        _validate_home(self.home, require_empty=True)
        _validate_destination(self.keyring, self.home, "keyring")
        staged: list[StagedFile] = []
        body_error: BaseException | None = None
        try:
            key_bytes, release_data, signed_data = self._read_inputs(release_bytes, signed_bytes)
            stage_dir, output_dir = _mkdir_owned(self.home, "staged"), _mkdir_owned(self.home, "output")
            staged_key = _stage_file(stage_dir, "public-key.asc", key_bytes, MAX_PUBLIC_KEY_BYTES)
            staged.append(staged_key)
            staged_release = _stage_file(stage_dir, "Release", release_data, MAX_RELEASE_BYTES)
            staged.append(staged_release)
            staged_signed = _stage_file(stage_dir, self.kind, signed_data, MAX_INRELEASE_BYTES if self.kind == "inrelease" else MAX_SIGNATURE_BYTES)
            staged.append(staged_signed)
            plaintext = _create_private_output(output_dir, "plaintext")
            import_argv = build_import_command(self.gpg_binary, home=self.home, keyring=self.keyring, public_key=staged_key.path)
            listing_argv = build_key_listing_command(self.gpg_binary, home=self.home, keyring=self.keyring)
            verify_argv = build_verify_command(
                self.gpg_binary, kind=self.kind, home=self.home, keyring=self.keyring,
                signed=staged_signed.path, release=staged_release.path, plaintext=plaintext,
            )
            env = {"GNUPGHOME": str(self.home), "HOME": str(self.home), "LC_ALL": "C", "LANG": "C"}
            imported = self.runner(import_argv, env, "import")
            if not isinstance(imported, CommandResult) or imported.returncode != 0:
                raise SignatureValidationError("IMPORT_FAILED", "Public-key import failed")
            for item in staged:
                item.assert_unchanged()
            listed = self.runner(listing_argv, env, "inspect")
            if not isinstance(listed, CommandResult) or listed.returncode != 0:
                raise SignatureValidationError("KEY_LISTING_FAILED", "GPG key capability listing failed")
            key_facts = _parse_key_listing(listed.stdout)
            for item in staged:
                item.assert_unchanged()
            verified = self.runner(verify_argv, env, "verify")
            if not isinstance(verified, CommandResult) or verified.returncode != 0:
                raise SignatureValidationError("VERIFY_FAILED", "GnuPG signature verification failed")
            for item in staged:
                item.assert_unchanged()
            if self.kind == "inrelease":
                plaintext_data, _ = _read_regular(
                    plaintext, "GPG plaintext output", MAX_RELEASE_BYTES, require_owner=True, private_mode=True,
                )
                if plaintext_data != release_data:
                    raise SignatureValidationError("PLAINTEXT_MISMATCH", "GPG plaintext differs from held Release")
            identity = _parse_status(verified.stdout, self.kind)
            gpg_hash = self.runner.executable_sha256 if isinstance(self.runner, NativeGpgRunner) else "fixture-not-recorded"
            return _build_validation_result(
                kind=self.kind, release_data=release_data, signed_data=signed_data,
                key_facts=key_facts, identity=identity, native=native_authority,
                gpg_binary_sha256=gpg_hash,
            )
        except BaseException as error:
            body_error = error
            allocations = getattr(error, "retained_descriptors", ())
            if allocations:
                self._retained_allocations += tuple(allocations)
                _retain_public_verifier(self)
            raise
        finally:
            if type(self.runner) is NativeGpgRunner and not self.runner.process_cleanup_confirmed:
                self._retained_staged = tuple(staged)
                _retain_public_verifier(self)
            else:
                failures = []
                retained = []
                for item in staged:
                    try:
                        item.close()
                    except BaseException as error:
                        failures.append(error)
                        retained.append(item)
                if failures:
                    self._retained_staged = tuple(retained)
                    _retain_public_verifier(self)
                    failure = SignatureValidationError(
                        "STAGED_CLEANUP_UNCONFIRMED", "Staged verification cleanup is unconfirmed",
                    )
                    failure.original_error = body_error
                    failure.cleanup_errors = tuple(failures)
                    raise failure from None

    def as_signed_store_validator(self) -> Callable[[bytes, bytes, dict[str, object]], dict[str, str]]:
        """Return the existing SignedStore callback, refusing fixture runners."""
        def validator(unsigned: bytes, signed: bytes, evidence: dict[str, object]) -> dict[str, str]:
            if not self._real_runner:
                raise SignatureValidationError("NATIVE_REQUIRED", "Only the fixed native GPG runner may authorize retention")
            result = self.validate(unsigned, signed, evidence)
            if result.get("confers_signature_authentication") != "true":
                raise SignatureValidationError("NATIVE_REQUIRED", "Native GPG verification required")
            return result
        return validator


__all__ = [
    "AptSignatureAdapter", "CommandResult", "FileIdentity", "GPG_BINARY", "GPG_TIMEOUT_SECONDS",
    "MAX_INRELEASE_BYTES", "MAX_STATUS_BYTES", "NativeGpgRunner", "PRIMARY_FINGERPRINT",
    "PUBLIC_KEY_SHA256", "SCHEMA", "SIGNING_SUBKEY_FINGERPRINT", "SignatureValidationError",
    "build_import_command", "build_key_listing_command", "build_verify_command",
]
