"""Non-admitting synthetic APT Release signing and public verification probe.

The existing C6 runtime owns private signing; the concrete APT adapter delegates
public verification processes to the same C6 process owner. No release packages,
SignedStore admission, live lease, repository metadata publication or key rotation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

_HERE = Path(__file__).resolve(strict=True).parent
for _directory in (_HERE, _HERE / "inputs"):
    if str(_directory) not in sys.path:
        sys.path.insert(0, str(_directory))

import probe_current_signer_c6_gpg as common
import b3_fixture_entrypoint as b3_entry
import b3_fixture_inputs as b3_inputs
from apt_signature_adapter import AptSignatureAdapter, NativeGpgRunner, GPG_BINARY
from current_protected_signing import (
    PRIMARY_FINGERPRINT, SIGNING_SUBKEY_FINGERPRINT, PUBLIC_KEY_SHA256, SignerBinding,
)
from protected_signing_runtime import ProtectedSigningRuntime

SCHEMA = "tf.current-signer-c6-apt-probe-receipt.v1"
STAGE1_SCHEMA = "tf.current-signer-c6-apt-stage1.v1"
COMMON_SOURCE_SHA256 = "b580a0adff2ba3eb3f5d22b76b2b40bbe0ce1f2d9da478780caa6b22722957a1"
COMMON_TESTS_SHA256 = "0dc5a41fa948c322169d5d97115f80ee9b8847ecf1f4d7c80a6cd684e62dd397"
APT_SOURCE_SHA256 = "710e2858e98f42f7a61b2629a641fe5d6738a12a6e3ee608ce047d868691e8f8"
RELEASE_BYTES = (
    b"Origin: Theme Forge synthetic C6 APT probe\n"
    b"Label: Non-publishing throwaway verification\n"
    b"Suite: synthetic-probe\n"
    b"Codename: synthetic-probe\n"
    b"Description: No release packages or repository admission\n"
)
_RETAINED_PROBE_READS: list[object] = []

SAFE_ERROR_CODES = frozenset({
    "APT_PROBE_INPUTS", "APT_PROBE_SOURCE", "APT_PROBE_TESTS",
    "APT_SOURCE_DIGEST", "APT_SIGNING_OBSERVATION", "APT_RELEASE_MISMATCH",
    "APT_SIGNATURE_OBSERVATION", "APT_NATIVE_REQUIRED", "APT_PROBE_CLEANUP",
    "APT_EXPLICIT_MODE_REQUIRED", "APT_MODE_CONFLICT",
})


class ProbeError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_file(path: Path, expected: str, code: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected or ""):
        raise ProbeError(code)
    if path.is_symlink() or not path.is_file() or _sha(path.read_bytes()) != expected:
        raise ProbeError(code)


def authenticate_stage1(repo_root: Path, probe_sha: str, tests_sha: str) -> dict[str, object]:
    _check_file(repo_root / "tools/verification/b3/probe_current_signer_c6_apt.py",
                probe_sha, "APT_PROBE_SOURCE")
    _check_file(repo_root / "tools/verification/b3/test_probe_current_signer_c6_apt.py",
                tests_sha, "APT_PROBE_TESTS")
    base = common.authenticate_stage1(
        repo_root, expected_probe_sha256=COMMON_SOURCE_SHA256,
        expected_tests_sha256=COMMON_TESTS_SHA256,
    )
    _check_file(repo_root / "tools/verification/b3/inputs/apt_signature_adapter.py",
                APT_SOURCE_SHA256, "APT_SOURCE_DIGEST")
    return {
        "schema": STAGE1_SCHEMA, "status": "pass", "production_authority": False,
        "probe_source_sha256": probe_sha, "probe_tests_sha256": tests_sha,
        "apt_adapter_sha256": APT_SOURCE_SHA256,
        "common_stage1": base,
    }


def authenticate_framing_sources(repo_root: Path, probe_sha: str, tests_sha: str) -> None:
    """Authenticate only public code here; this host process owns secret env."""
    _check_file(repo_root / "tools/verification/b3/probe_current_signer_c6_apt.py",
                probe_sha, "APT_PROBE_SOURCE")
    _check_file(repo_root / "tools/verification/b3/test_probe_current_signer_c6_apt.py",
                tests_sha, "APT_PROBE_TESTS")
    _check_file(repo_root / "tools/verification/b3/inputs/apt_signature_adapter.py",
                APT_SOURCE_SHA256, "APT_SOURCE_DIGEST")
    common.verify_self_and_tests_digests(
        expected_probe_sha256=COMMON_SOURCE_SHA256,
        expected_tests_sha256=COMMON_TESTS_SHA256,
        probe_path=repo_root / "tools/verification/b3/probe_current_signer_c6_gpg.py",
        tests_path=repo_root / "tools/verification/b3/test_probe_current_signer_c6_gpg.py",
    )


def _zero(value: bytearray | None) -> None:
    if value is not None:
        value[:] = b"\0" * len(value)


def _has_custody(runtime: object, adapters: list[object]) -> bool:
    return (bool(_RETAINED_PROBE_READS) or getattr(runtime, "retained_custody", None) is not None
            or any(getattr(a, "retained_custody", None) is not None
                   or not getattr(a, "process_cleanup_confirmed", False)
                   for a in adapters))


def check_observations(execution: object, release: bytes,
                       results: list[dict[str, str]]) -> None:
    if (getattr(execution, "native_execution", False) is not True
            or getattr(execution, "status", None) != "observed"
            or getattr(execution, "production_authority", None) is not False):
        raise ProbeError("APT_SIGNING_OBSERVATION")
    if release != RELEASE_BYTES:
        raise ProbeError("APT_RELEASE_MISMATCH")
    if len(results) != 2:
        raise ProbeError("APT_SIGNATURE_OBSERVATION")
    for kind, result in zip(("inrelease", "release.gpg"), results, strict=True):
        expected = {
            "status": "valid", "verification_mode": "native",
            "confers_signature_authentication": "true", "signature_kind": kind,
            "release_sha256": _sha(RELEASE_BYTES),
            "public_key_sha256": PUBLIC_KEY_SHA256,
            "verified_issuer": PRIMARY_FINGERPRINT,
            "primary_fingerprint": PRIMARY_FINGERPRINT,
            "signing_subkey": SIGNING_SUBKEY_FINGERPRINT,
        }
        if any(result.get(key) != value for key, value in expected.items()):
            raise ProbeError("APT_NATIVE_REQUIRED")
        if not re.fullmatch(r"[0-9a-f]{64}", result.get("gpg_binary_sha256", "")):
            raise ProbeError("APT_NATIVE_REQUIRED")


def _identity(path: Path) -> tuple[int, int, int, int]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ProbeError("APT_PROBE_CLEANUP")
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


def _read_output(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    body_error = None
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= maximum):
            raise ProbeError("APT_RELEASE_MISMATCH")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        last = path.lstat()
        signature = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                  item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(data) != before.st_size or signature(before) != signature(after) or signature(after) != signature(last):
            raise ProbeError("APT_RELEASE_MISMATCH")
        return bytes(data)
    except BaseException as error:
        body_error = error
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            # No retry: the numeric descriptor may already have been released.
            record = {"fd": descriptor, "path": path, "original_error": body_error,
                      "cleanup_error": error, "status": "close-uncertain"}
            _RETAINED_PROBE_READS.append(record)
            failure = ProbeError("APT_PROBE_CLEANUP")
            failure.original_error = body_error
            failure.retained_read = record
            raise failure from None


def execute_native_probe(*, repo_root: Path, facts_path: Path,
                         probe_parent: Path, probe_sha: str,
                         tests_sha: str, secret_stream: object) -> dict[str, object]:
    b3_entry._check_credential_free_env()
    authenticated = authenticate_stage1(repo_root, probe_sha, tests_sha)
    manifest = b3_inputs.load_manifest(repo_root / "tools/verification/b3/manifest.json")
    b3_inputs.validate_measured_facts(
        json.loads(facts_path.read_text(encoding="utf-8")), manifest,
    )
    root = probe_parent / "c6-apt-probe"
    # Existing parent/controller contract: fresh root-owned 0700 parent measured
    # by Stage2. Refuse reuse and retain originals on every uncertainty.
    if root.exists() or root.is_symlink():
        raise ProbeError("APT_PROBE_INPUTS")
    key = phrase = None
    runtime = ProtectedSigningRuntime(binding=SignerBinding())
    adapters: list[AptSignatureAdapter] = []
    body_error = None
    root_identity = None
    results: list[dict[str, str]] = []
    try:
        key, phrase = common._read_stdin_frame(secret_stream)
        root.mkdir(mode=0o700)
        root_identity = _identity(root)
        output = root / "signed"
        public_key = repo_root / "keys/knowledge-forge-ai-packages.asc"
        execution = runtime.execute_apt_release(
            RELEASE_BYTES, output_root=output,
            public_key_bytes=public_key.read_bytes(),
            private_key_bytes=key, passphrase=phrase,
        )
        if runtime.retained_custody is not None or (output / ".protected-work").exists():
            raise ProbeError("APT_PROBE_CLEANUP")
        release = _read_output(output / "Release", 64 * 1024 * 1024)
        signatures = [_read_output(output / name, maximum) for name, maximum in
                      (("InRelease", 72 * 1024 * 1024), ("Release.gpg", 8 * 1024 * 1024))]
        for number, (kind, signed) in enumerate(zip(("inrelease", "release.gpg"), signatures, strict=True)):
            home = root / ("public-verification-" + str(number))
            home.mkdir(mode=0o700)
            runner = NativeGpgRunner(GPG_BINARY)
            adapter = AptSignatureAdapter(
                kind=kind, gpg_binary=GPG_BINARY, public_key=public_key,
                verification_home=home, keyring=home / "public-keyring.gpg",
                runner=runner,
            )
            adapters.append(adapter)
            results.append(adapter.validate(release, signed))
        check_observations(execution, release, results)
    except BaseException as error:
        body_error = error
    finally:
        _zero(key)
        _zero(phrase)
        retained = _has_custody(runtime, adapters)
        work_absent = not (root / "signed/.protected-work").exists()
        if not retained and work_absent and root_identity is not None and root.exists():
            try:
                if _identity(root) != root_identity:
                    raise ProbeError("APT_PROBE_CLEANUP")
                shutil.rmtree(root)
            except BaseException:
                if body_error is None:
                    body_error = ProbeError("APT_PROBE_CLEANUP")
        cleanup_ok = not retained and work_absent and not root.exists()

    if body_error is not None:
        # Only fixed probe-owned codes are serialized. Library/native exception
        # messages and retained resource objects never enter diagnostic output.
        code = getattr(body_error, "code", "")
        if code not in SAFE_ERROR_CODES:
            code = "NATIVE_APT_PROBE_FAILED"
        return {
            "schema": SCHEMA, "status": "failed-closed",
            "evidence_class": "native-unqualified", "production_authority": False,
            "error_code": code, "custody_retained": retained,
            "cleanup": {"private_work_absent": work_absent,
                        "probe_root_absent": not root.exists(),
                        "confirmed": cleanup_ok},
        }
    if not cleanup_ok:
        raise ProbeError("APT_PROBE_CLEANUP")
    return {
        "schema": SCHEMA, "status": "pass",
        "evidence_class": "native-synthetic-apt-slice",
        "production_authority": False,
        "full_signer_qualified": False, "unsigned_admission": False,
        "repository_publication": False,
        "primary_fingerprint": PRIMARY_FINGERPRINT,
        "signing_subkey_fingerprint": SIGNING_SUBKEY_FINGERPRINT,
        "public_key_sha256": PUBLIC_KEY_SHA256,
        "probe_source_sha256": authenticated["probe_source_sha256"],
        "probe_tests_sha256": authenticated["probe_tests_sha256"],
        "apt_adapter_sha256": APT_SOURCE_SHA256,
        "release_sha256": _sha(RELEASE_BYTES),
        "verification": [
            {key: result[key] for key in (
                "signature_kind", "signed_sha256", "verification_mode",
                "confers_signature_authentication", "gpg_binary_sha256")}
            for result in results
        ],
        "custody_retained": False,
        "cleanup": {"private_work_absent": True, "probe_root_absent": True,
                    "confirmed": True},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthetic, non-publishing C6 APT native probe")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--authenticate-stage1", action="store_true")
    modes.add_argument("--emit-stdin-frame", action="store_true")
    modes.add_argument("--execute-native", action="store_true")
    for name in ("expected-probe-sha256", "expected-tests-sha256"):
        parser.add_argument("--" + name)
    for name in ("repo-root", "facts", "probe-parent", "out", "availability-out", "receipt-out"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(argv)
    if not any((args.authenticate_stage1, args.emit_stdin_frame, args.execute_native)):
        print(json.dumps({"schema": SCHEMA, "status": "refused",
                          "error_code": "APT_EXPLICIT_MODE_REQUIRED",
                          "production_authority": False}, sort_keys=True))
        return 2
    try:
        if not args.repo_root or not args.expected_probe_sha256 or not args.expected_tests_sha256:
            raise ProbeError("APT_PROBE_INPUTS")
        repo = args.repo_root.resolve(strict=True)
        if args.emit_stdin_frame:
            if args.availability_out is None:
                raise ProbeError("APT_PROBE_INPUTS")
            authenticate_framing_sources(repo, args.expected_probe_sha256, args.expected_tests_sha256)
            common.emit_stdin_frame(args.availability_out,
                                    expected_probe_sha256=COMMON_SOURCE_SHA256)
            return 0
        if args.authenticate_stage1:
            if args.out is None:
                raise ProbeError("APT_PROBE_INPUTS")
            receipt = authenticate_stage1(repo, args.expected_probe_sha256, args.expected_tests_sha256)
            target = args.out
        else:
            if args.facts is None or args.probe_parent is None or args.receipt_out is None:
                raise ProbeError("APT_PROBE_INPUTS")
            target = args.receipt_out
            receipt = execute_native_probe(
                repo_root=repo, facts_path=args.facts.resolve(strict=True),
                probe_parent=args.probe_parent.resolve(strict=True),
                probe_sha=args.expected_probe_sha256, tests_sha=args.expected_tests_sha256,
                secret_stream=sys.stdin.buffer,
            )
        common._write_json(target, receipt)
        print(json.dumps(receipt, sort_keys=True))
        return 0 if receipt["status"] == "pass" else 2
    except Exception as error:
        code = getattr(error, "code", "")
        failure = {"schema": SCHEMA, "status": "failed-closed",
                   "error_code": code if code in SAFE_ERROR_CODES else "NATIVE_APT_PROBE_FAILED",
                   "production_authority": False}
        # Framing mode stdout is exclusively binary. No private diagnostic bytes.
        print(json.dumps(failure, sort_keys=True),
              file=sys.stderr if args.emit_stdin_frame else sys.stdout)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
