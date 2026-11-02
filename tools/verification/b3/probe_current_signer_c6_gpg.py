"""Proposed non-admitting C6 + secret-key topology + throwaway GPG probe.

Review artifact only. Exercises ProtectedSigningRuntime.execute on one
synthetic throwaway Pacman-channel object inside the prepared Fedora 43 B3
container without live unsigned package transport or production authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
from typing import Mapping

_THIS_DIR = Path(__file__).resolve(strict=True).parent
_INPUTS_DIR = _THIS_DIR / "inputs"
for _entry in (str(_THIS_DIR), str(_INPUTS_DIR)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import b3_fixture_entrypoint as b3_entry  # noqa: E402
import b3_fixture_inputs as b3_inputs  # noqa: E402
from current_protected_signing import (  # noqa: E402
    PRIMARY_FINGERPRINT,
    PUBLIC_KEY_SHA256,
    SIGNING_SUBKEY_FINGERPRINT,
    ProtectedSigningError,
    SignerBinding,
    UnsignedObject,
    verify_committed_public_key,
)
from owned_gpg_agent import OwnedAgentError  # noqa: E402
from protected_signing_runtime import (  # noqa: E402
    MAX_PROCESS_STDIN,
    ProtectedSigningRuntime,
    _RETAINED_READ_DESCRIPTORS,
    _RETAINED_RUNTIME_CUSTODIES,
    _clear_secret,
)
from signing_status_proof import ProofError  # noqa: E402

STAGE1_SCHEMA = "tf.current-signer-c6-gpg-stage1.v1"
AVAILABILITY_SCHEMA = "tf.current-signer-c6-gpg-secret-availability.v1"
RECEIPT_SCHEMA = "tf.current-signer-c6-gpg-probe-receipt.v1"

PROMOTED_INPUT_SHA256: Mapping[str, str] = {
    "tools/verification/b3/inputs/owned_gpg_agent.py": (
        "305f613aa989f807d5155c082e568d8e0c79ba63aa4ab8a25252433250c5c2cf"
    ),
    "tools/verification/b3/inputs/current_protected_signing.py": (
        "c04d30b55ea9632c93512e4bb1271101cc7aff0f62dba6dfdb0222b4e7c5b041"
    ),
    "tools/verification/b3/inputs/signing_status_proof.py": (
        "1f7cef1c8c73d9979c3bb48d5b241dcf51aebc660a5a4fbc555ec7f3a463d5e9"
    ),
    "tools/verification/b3/inputs/protected_passphrase_fd.py": (
        "abec0b730be0043ade1cdc9a022234941d467854e977f3f3727b25283899b325"
    ),
    "tools/verification/b3/inputs/protected_signing_runtime.py": (
        "fbcbc1eaf3ffc0c7c35f23059c73aa830331c446c9717b05869121def46701f4"
    ),
    "keys/knowledge-forge-ai-packages.asc": PUBLIC_KEY_SHA256,
}

THROWAWAY_BASENAME = "theme-forge-solar-sail-0.3.0-1-x86_64.pkg.tar.zst"
THROWAWAY_PAYLOAD = b"THROWAWAY-C6-GPG-PROBE-NON-PACKAGE-PAYLOAD-V1\n"
FRAME_MAGIC = b"TFC6GPG1"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ProbeError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _error_code_from_exception(error: BaseException, fallback: str) -> str:
    if isinstance(error, (ProbeError, ProtectedSigningError, OwnedAgentError, b3_entry.FixtureError)):
        return str(error.code)
    code = getattr(error, "code", None)
    if isinstance(code, str) and code:
        return code
    if isinstance(error, ProofError) and error.args and isinstance(error.args[0], str):
        return error.args[0]
    return fallback


def verify_self_and_tests_digests(
    *,
    expected_probe_sha256: str,
    expected_tests_sha256: str | None = None,
    probe_path: Path | None = None,
    tests_path: Path | None = None,
) -> dict[str, str]:
    if not isinstance(expected_probe_sha256, str) or not _HEX64_RE.fullmatch(expected_probe_sha256):
        raise ProbeError("EXPECTED_PROBE_SHA256_INVALID", "Expected 64-hex SHA-256 for probe script")
    target_probe = probe_path or Path(__file__).resolve(strict=True)
    if not target_probe.is_file() or target_probe.is_symlink():
        raise ProbeError("PROBE_SOURCE_MISSING", "Probe script must be a regular file")
    actual_probe_sha = _sha256_bytes(target_probe.read_bytes())
    if actual_probe_sha != expected_probe_sha256:
        raise ProbeError("PROBE_SOURCE_DIGEST_MISMATCH", "Probe script digest mismatch")
    digests = {"probe_source_sha256": actual_probe_sha}
    if expected_tests_sha256 is not None:
        if not isinstance(expected_tests_sha256, str) or not _HEX64_RE.fullmatch(expected_tests_sha256):
            raise ProbeError("EXPECTED_TESTS_SHA256_INVALID", "Expected 64-hex SHA-256 for probe tests")
        target_tests = tests_path or target_probe.with_name("test_probe_current_signer_c6_gpg.py")
        if not target_tests.is_file() or target_tests.is_symlink():
            raise ProbeError("PROBE_TESTS_MISSING", "Probe test file must be a regular file")
        actual_tests_sha = _sha256_bytes(target_tests.read_bytes())
        if actual_tests_sha != expected_tests_sha256:
            raise ProbeError("PROBE_TESTS_DIGEST_MISMATCH", "Probe test file digest mismatch")
        digests["probe_tests_sha256"] = actual_tests_sha
    return digests


def authenticate_stage1(
    repo_root: Path,
    *,
    expected_probe_sha256: str,
    expected_tests_sha256: str,
) -> dict[str, object]:
    b3_entry._check_credential_free_env()
    self_digests = verify_self_and_tests_digests(
        expected_probe_sha256=expected_probe_sha256,
        expected_tests_sha256=expected_tests_sha256,
        probe_path=repo_root / "tools/verification/b3/probe_current_signer_c6_gpg.py",
        tests_path=repo_root / "tools/verification/b3/test_probe_current_signer_c6_gpg.py",
    )
    verified: dict[str, str] = {}
    for rel, expected in PROMOTED_INPUT_SHA256.items():
        candidate = repo_root / rel
        if not candidate.is_file() or candidate.is_symlink():
            raise ProbeError("STAGE1_INPUT_MISSING", f"Missing promoted input {rel}")
        actual = _sha256_bytes(candidate.read_bytes())
        if actual != expected:
            raise ProbeError("STAGE1_DIGEST_MISMATCH", f"Digest mismatch for {rel}")
        verified[rel] = actual
    verify_committed_public_key((repo_root / "keys/knowledge-forge-ai-packages.asc").read_bytes())
    return {
        "schema": STAGE1_SCHEMA,
        "status": "pass",
        "production_authority": False,
        "probe_source_sha256": self_digests["probe_source_sha256"],
        "probe_tests_sha256": self_digests["probe_tests_sha256"],
        "verified_files": verified,
        "primary_fingerprint": PRIMARY_FINGERPRINT,
        "signing_subkey_fingerprint": SIGNING_SUBKEY_FINGERPRINT,
    }


def emit_stdin_frame(
    availability_out: Path,
    *,
    expected_probe_sha256: str,
) -> None:
    self_digests = verify_self_and_tests_digests(expected_probe_sha256=expected_probe_sha256)
    key_raw = os.environ.get("PACKAGE_SIGNING_KEY", "").encode("utf-8")
    phrase_raw = os.environ.get("PACKAGE_SIGNING_PASSPHRASE", "").encode("utf-8")
    key_ok = bool(key_raw.strip()) and b"\x00" not in key_raw and len(key_raw) <= MAX_PROCESS_STDIN
    phrase_ok = (
        bool(phrase_raw.strip()) and b"\x00" not in phrase_raw and len(phrase_raw) <= MAX_PROCESS_STDIN
    )
    _write_json(
        availability_out,
        {
            "schema": AVAILABILITY_SCHEMA,
            "status": "pass" if (key_ok and phrase_ok) else "fail",
            "production_authority": False,
            "probe_source_sha256": self_digests["probe_source_sha256"],
            "package_signing_key_non_empty": key_ok,
            "package_signing_passphrase_non_empty": phrase_ok,
        },
    )
    if not (key_ok and phrase_ok):
        raise ProbeError("SECRET_INPUT_INVALID", "Required signing secrets are empty or out of bounds")
    header = FRAME_MAGIC + struct.pack(">II", len(key_raw), len(phrase_raw))
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(key_raw)
    sys.stdout.buffer.write(phrase_raw)
    sys.stdout.buffer.flush()


def _read_stdin_frame(stream: object) -> tuple[bytearray, bytearray]:
    read = getattr(stream, "read")
    prefix = read(16)
    if len(prefix) != 16 or prefix[:8] != FRAME_MAGIC:
        raise ProbeError("STDIN_FRAME_FORMAT", "Invalid secret frame header")
    key_len, phrase_len = struct.unpack(">II", prefix[8:16])
    if not (0 < key_len <= MAX_PROCESS_STDIN and 0 < phrase_len <= MAX_PROCESS_STDIN):
        raise ProbeError("STDIN_FRAME_BOUNDS", "Secret frame lengths out of bounds")
    key_buf = bytearray(read(key_len))
    phrase_buf = bytearray(read(phrase_len))
    extra = read(1)
    if len(key_buf) != key_len or len(phrase_buf) != phrase_len or extra:
        _clear_secret(key_buf)
        _clear_secret(phrase_buf)
        raise ProbeError("STDIN_FRAME_TRUNCATED", "Secret frame payload length mismatch")
    if b"\x00" in key_buf or b"\x00" in phrase_buf:
        _clear_secret(key_buf)
        _clear_secret(phrase_buf)
        raise ProbeError("STDIN_FRAME_NUL", "Secret frame contains NUL byte")
    return key_buf, phrase_buf


def build_probe_failure_receipt(
    error: BaseException,
    *,
    probe_parent: Path | None = None,
    runtime: ProtectedSigningRuntime | None = None,
) -> dict[str, object]:
    probe_root = (probe_parent / "c6-gpg-probe") if probe_parent is not None else None
    work_dir = (probe_root / "out" / ".protected-work") if probe_root is not None else None
    retained_record = runtime.retained_custody if runtime is not None else (
        _RETAINED_RUNTIME_CUSTODIES[-1] if _RETAINED_RUNTIME_CUSTODIES else None
    )
    retained_agent = retained_record.get("agent") if isinstance(retained_record, Mapping) else None
    retained_agent_cleanup_confirmed = (
        getattr(retained_agent, "cleanup_confirmed", False) is True
        if retained_agent is not None
        else False
    )
    custody_retained = (
        (runtime is not None and runtime.retained_custody is not None)
        or bool(_RETAINED_RUNTIME_CUSTODIES)
        or bool(_RETAINED_READ_DESCRIPTORS)
    )
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "failed-closed",
        "evidence_class": "native-unqualified",
        "production_authority": False,
        "error_code": _error_code_from_exception(error, "NATIVE_PROBE_FAILED"),
        "custody_retained": custody_retained,
        "cleanup": {
            "agent_cleanup_inferred_from_execute_return": False,
            "retained_agent_cleanup_confirmed": retained_agent_cleanup_confirmed,
            "work_dir_absent": True if work_dir is None else not work_dir.exists(),
            "probe_root_absent": True if probe_root is None else not probe_root.exists(),
            "retained_custody_count": len(_RETAINED_RUNTIME_CUSTODIES),
            "retained_read_descriptor_count": len(_RETAINED_READ_DESCRIPTORS),
        },
    }


def execute_native_probe(
    *,
    repo_root: Path,
    facts_path: Path,
    probe_parent: Path,
    secret_stream: object,
    expected_probe_sha256: str,
    expected_tests_sha256: str,
    runtime: ProtectedSigningRuntime | None = None,
) -> dict[str, object]:
    b3_entry._check_credential_free_env()
    stage1_auth = authenticate_stage1(
        repo_root,
        expected_probe_sha256=expected_probe_sha256,
        expected_tests_sha256=expected_tests_sha256,
    )
    facts = json.loads(facts_path.read_text(encoding="utf-8"))
    manifest = b3_inputs.load_manifest(repo_root / "tools/verification/b3/manifest.json")
    b3_inputs.validate_measured_facts(facts, manifest)

    public_key_bytes = (repo_root / "keys/knowledge-forge-ai-packages.asc").read_bytes()
    key_secret, phrase_secret = _read_stdin_frame(secret_stream)
    probe_root = probe_parent / "c6-gpg-probe"
    input_dir = probe_root / "in"
    output_dir = probe_root / "out"
    work_dir = output_dir / ".protected-work"
    active_runtime = runtime or ProtectedSigningRuntime(binding=SignerBinding())
    try:
        os.mkdir(probe_root, 0o700)
        os.mkdir(input_dir, 0o700)
        input_path = input_dir / THROWAWAY_BASENAME
        fd = os.open(str(input_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, THROWAWAY_PAYLOAD)
            os.fsync(fd)
        finally:
            os.close(fd)
        input_sha = _sha256_bytes(THROWAWAY_PAYLOAD)
        obj = UnsignedObject(
            channel="pacman",
            product="theme-forge-solar-sail",
            version="0.3.0",
            architecture="x86_64",
            origin="probe",
            path=input_path,
            sha256=input_sha,
            size=len(THROWAWAY_PAYLOAD),
        )
        execution = active_runtime.execute(
            (obj,),
            origin="probe",
            output_root=output_dir,
            public_key_bytes=public_key_bytes,
            private_key_bytes=key_secret,
            passphrase=phrase_secret,
        )
        out_pkg = output_dir / "pacman" / "x86_64" / THROWAWAY_BASENAME
        out_sig = output_dir / "pacman" / "x86_64" / (THROWAWAY_BASENAME + ".sig")
        sig_bytes = out_sig.read_bytes()
        pkg_bytes = out_pkg.read_bytes()
        if pkg_bytes != THROWAWAY_PAYLOAD or not sig_bytes:
            raise ProbeError("PROBE_OUTPUT_MISMATCH", "Throwaway output or detached signature invalid")
        sig_sha = _sha256_bytes(sig_bytes)
        sig_size = len(sig_bytes)
    finally:
        _clear_secret(key_secret)
        _clear_secret(phrase_secret)
        custody_retained = (
            active_runtime.retained_custody is not None
            or bool(_RETAINED_RUNTIME_CUSTODIES)
            or bool(_RETAINED_READ_DESCRIPTORS)
        )
        if not custody_retained and not work_dir.exists() and probe_root.exists():
            shutil.rmtree(probe_root)

    work_absent = not work_dir.exists()
    probe_absent = not probe_root.exists()
    if not (work_absent and probe_absent):
        raise ProbeError("PROBE_CLEANUP_UNCONFIRMED", "Throwaway probe directories were not cleanly removed")

    return {
        "schema": RECEIPT_SCHEMA,
        "status": "pass",
        "evidence_class": "native-unqualified",
        "production_authority": False,
        "custody_retained": False,
        "probe_source_sha256": stage1_auth["probe_source_sha256"],
        "probe_tests_sha256": stage1_auth["probe_tests_sha256"],
        "native_execution": execution.native_execution,
        "execution_status": execution.status,
        "primary_fingerprint": PRIMARY_FINGERPRINT,
        "signing_subkey_fingerprint": SIGNING_SUBKEY_FINGERPRINT,
        "public_key_sha256": PUBLIC_KEY_SHA256,
        "exercised_phases": [
            "public-key-import",
            "private-key-import",
            "pacman-package-sign",
            "pacman-package-verify",
            "final-output-inventory",
        ],
        "object_count": len(execution.objects),
        "throwaway_input_sha256": input_sha,
        "throwaway_output_sha256": execution.objects[0]["package_sha256"],
        "detached_signature_sha256": sig_sha,
        "detached_signature_bytes": sig_size,
        "cleanup": {
            "agent_cleanup_inferred_from_execute_return": (
                active_runtime.retained_custody is None and active_runtime._agent is None
            ),
            "work_dir_absent": work_absent,
            "probe_root_absent": probe_absent,
            "retained_custody_count": len(_RETAINED_RUNTIME_CUSTODIES),
            "retained_read_descriptor_count": len(_RETAINED_READ_DESCRIPTORS),
        },
        "scope_labels": {
            "signing_key_validity": "observed-under-c6-non-admitting",
            "c6_lifecycle": "observed-with-key-import-and-sign-non-admitting",
            "native_status_grammar": "observed-for-gpg249-secret-topology-and-detached-verify",
            "per_family_tools": "gpg-observed-only-rpm-and-repo-add-unexercised",
            "unsigned_admission": "not-exercised-synthetic-throwaway-input",
            "production_publication": "not-authorized",
        },
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Non-admitting C6 + GPG native probe")
    parser.add_argument("--authenticate-stage1", action="store_true")
    parser.add_argument("--emit-stdin-frame", action="store_true")
    parser.add_argument("--execute-native", action="store_true")
    parser.add_argument("--expected-probe-sha256", default=None)
    parser.add_argument("--expected-tests-sha256", default=None)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--facts", type=Path)
    parser.add_argument("--probe-parent", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--availability-out", type=Path)
    parser.add_argument("--receipt-out", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    modes = [bool(args.authenticate_stage1), bool(args.emit_stdin_frame), bool(args.execute_native)]
    if sum(modes) == 0:
        refusal = {
            "schema": RECEIPT_SCHEMA,
            "status": "refused",
            "error_code": "EXPLICIT_MODE_REQUIRED",
            "production_authority": False,
        }
        print(json.dumps(refusal, sort_keys=True))
        return 2
    if sum(modes) > 1:
        refusal = {
            "schema": RECEIPT_SCHEMA,
            "status": "refused",
            "error_code": "MUTUALLY_EXCLUSIVE_MODE_FLAGS",
            "production_authority": False,
        }
        print(json.dumps(refusal, sort_keys=True))
        return 2
    if not args.expected_probe_sha256:
        target_schema = (
            STAGE1_SCHEMA
            if args.authenticate_stage1
            else (AVAILABILITY_SCHEMA if args.emit_stdin_frame else RECEIPT_SCHEMA)
        )
        refusal = {
            "schema": target_schema,
            "status": "refused",
            "error_code": "EXPECTED_PROBE_SHA256_REQUIRED",
            "production_authority": False,
        }
        out_stream = sys.stderr if args.emit_stdin_frame else sys.stdout
        print(json.dumps(refusal, sort_keys=True), file=out_stream)
        return 2

    if args.authenticate_stage1:
        if args.repo_root is None or args.out is None or not args.expected_tests_sha256:
            refusal = {
                "schema": STAGE1_SCHEMA,
                "status": "refused",
                "error_code": "STAGE1_INPUTS_REQUIRED",
                "production_authority": False,
            }
            print(json.dumps(refusal, sort_keys=True))
            return 2
        try:
            receipt = authenticate_stage1(
                args.repo_root.resolve(strict=True),
                expected_probe_sha256=args.expected_probe_sha256,
                expected_tests_sha256=args.expected_tests_sha256,
            )
            _write_json(args.out, receipt)
        except Exception as error:
            failure = {
                "schema": STAGE1_SCHEMA,
                "status": "failed-closed",
                "error_code": _error_code_from_exception(error, "STAGE1_AUTH_FAILED"),
                "production_authority": False,
            }
            try:
                _write_json(args.out, failure)
            except OSError:
                pass
            print(json.dumps(failure, sort_keys=True))
            return 2
        print(json.dumps(receipt, sort_keys=True))
        return 0

    if args.emit_stdin_frame:
        if args.availability_out is None:
            refusal = {
                "schema": AVAILABILITY_SCHEMA,
                "status": "refused",
                "error_code": "AVAILABILITY_OUT_REQUIRED",
                "production_authority": False,
            }
            print(json.dumps(refusal, sort_keys=True), file=sys.stderr)
            return 2
        try:
            emit_stdin_frame(
                args.availability_out,
                expected_probe_sha256=args.expected_probe_sha256,
            )
        except Exception as error:
            failure = {
                "schema": AVAILABILITY_SCHEMA,
                "status": "failed-closed",
                "error_code": _error_code_from_exception(error, "SECRET_FRAME_EMIT_FAILED"),
                "production_authority": False,
            }
            try:
                if not args.availability_out.is_file():
                    _write_json(args.availability_out, failure)
            except OSError:
                pass
            print(json.dumps(failure, sort_keys=True), file=sys.stderr)
            return 2
        return 0

    if (
        args.repo_root is None
        or args.facts is None
        or args.probe_parent is None
        or args.receipt_out is None
        or not args.expected_tests_sha256
    ):
        refusal = {
            "schema": RECEIPT_SCHEMA,
            "status": "refused",
            "error_code": "NATIVE_INPUTS_REQUIRED",
            "production_authority": False,
        }
        print(json.dumps(refusal, sort_keys=True))
        return 2
    active_runtime = ProtectedSigningRuntime(binding=SignerBinding())
    resolved_parent: Path | None = None
    try:
        resolved_parent = args.probe_parent.resolve(strict=True)
        receipt = execute_native_probe(
            repo_root=args.repo_root.resolve(strict=True),
            facts_path=args.facts.resolve(strict=True),
            probe_parent=resolved_parent,
            secret_stream=sys.stdin.buffer,
            expected_probe_sha256=args.expected_probe_sha256,
            expected_tests_sha256=args.expected_tests_sha256,
            runtime=active_runtime,
        )
        _write_json(args.receipt_out, receipt)
    except Exception as error:
        failure = build_probe_failure_receipt(
            error,
            probe_parent=resolved_parent,
            runtime=active_runtime,
        )
        try:
            _write_json(args.receipt_out, failure)
        except OSError:
            pass
        print(json.dumps(failure, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
