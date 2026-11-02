"""Pure unit tests for the proposed C6 + GPG probe entrypoint.

Review artifact only. Exercises frame parsing, secret zeroing, credential-free
container checks, self/test digest pins, status-grammar acceptance/refusal,
and simulated ProtectedSigningRuntime execution, rejection, cleanup, and
retained-custody failure receipts without invoking GnuPG, RPM, Docker, or real
secrets.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

_THIS_DIR = Path(__file__).resolve(strict=True).parent
for _entry in (str(_THIS_DIR), str(_THIS_DIR / "inputs")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import b3_fixture_entrypoint as b3_entry
from current_protected_signing import ProtectedSigningError, SignerBinding
import probe_current_signer_c6_gpg as probe
import protected_signing_runtime as psr
from signing_status_proof import (
    PRIMARY,
    SUBKEY,
    ProofError,
    inspect_ci_secret_metadata,
    inspect_detached_verification,
)


def _valid_secret_listing() -> bytes:
    grip1 = "A" * 64
    grip2 = "B" * 64
    return (
        f"sec:u:4096:1:{PRIMARY[-16:]}:1700000000:1900000000:::::cCS:::#::23::0:\n"
        f"fpr:::::::::{PRIMARY}:\n"
        f"grp:::::::::{grip1}:\n"
        f"ssb:u:4096:1:{SUBKEY[-16:]}:1700000000:1900000000:::::s:::+::23::0:\n"
        f"fpr:::::::::{SUBKEY}:\n"
        f"grp:::::::::{grip2}:\n"
    ).encode("ascii")


def _valid_verify_status() -> bytes:
    return (
        f"[GNUPG:] NEWSIG\n"
        f"[GNUPG:] GOODSIG {SUBKEY[-16:]} Test\n"
        f"[GNUPG:] VALIDSIG {SUBKEY} 2023-11-14 1700000000 0 4 0 1 8 00 {PRIMARY}\n"
    ).encode("ascii")


def _frame_bytes(key: bytes = b"SYNTHETIC-KEY", phrase: bytes = b"SYNTHETIC-PASS") -> bytes:
    return probe.FRAME_MAGIC + struct.pack(">II", len(key), len(phrase)) + key + phrase


class _FakeOwnedAgent:
    next_cleanup_confirmed = True

    def __init__(self, home: str | os.PathLike[str], work: str | os.PathLike[str]):
        self.home = Path(home)
        self.work = Path(work)
        self.started = False
        self.cleanup_confirmed = False

    def start(self) -> None:
        self.started = True

    def require_live(self) -> None:
        if not self.started:
            raise RuntimeError("agent not started")

    def close(self) -> None:
        self.started = False
        self.cleanup_confirmed = bool(type(self).next_cleanup_confirmed)


class ProbeUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        psr._RETAINED_RUNTIME_CUSTODIES.clear()
        psr._RETAINED_READ_DESCRIPTORS.clear()
        _FakeOwnedAgent.next_cleanup_confirmed = True

    def tearDown(self) -> None:
        psr._RETAINED_RUNTIME_CUSTODIES.clear()
        psr._RETAINED_READ_DESCRIPTORS.clear()

    def test_valid_stdin_frame_parses_and_rejects_trailing_bytes(self) -> None:
        key = b"SYNTHETIC-KEY-MATERIAL"
        phrase = b"SYNTHETIC-PASSPHRASE"
        frame = _frame_bytes(key, phrase)
        k_out, p_out = probe._read_stdin_frame(io.BytesIO(frame))
        self.assertEqual(bytes(k_out), key)
        self.assertEqual(bytes(p_out), phrase)
        with self.assertRaises(probe.ProbeError) as ctx:
            probe._read_stdin_frame(io.BytesIO(frame + b"X"))
        self.assertEqual(ctx.exception.code, "STDIN_FRAME_TRUNCATED")
        with self.assertRaises(probe.ProbeError) as bad_magic:
            probe._read_stdin_frame(io.BytesIO(b"BADMAGIC" + b"\x00" * 8))
        self.assertEqual(bad_magic.exception.code, "STDIN_FRAME_FORMAT")
        with self.assertRaises(probe.ProbeError) as bad_bounds:
            probe._read_stdin_frame(io.BytesIO(probe.FRAME_MAGIC + struct.pack(">II", 0, 4)))
        self.assertEqual(bad_bounds.exception.code, "STDIN_FRAME_BOUNDS")

    def test_stdin_frame_rejects_nul_bytes_and_clears_buffers(self) -> None:
        key = b"BAD\x00KEY"
        phrase = b"OK"
        frame = _frame_bytes(key, phrase)
        with self.assertRaises(probe.ProbeError) as ctx:
            probe._read_stdin_frame(io.BytesIO(frame))
        self.assertEqual(ctx.exception.code, "STDIN_FRAME_NUL")
        buf = bytearray(b"SECRET-BYTES")
        psr._clear_secret(buf)
        self.assertEqual(bytes(buf), b"\x00" * len(buf))

    def test_credential_free_env_and_expected_sha256_pins(self) -> None:
        probe_path = Path(probe.__file__).resolve(strict=True)
        tests_path = Path(__file__).resolve(strict=True)
        probe_sha = hashlib.sha256(probe_path.read_bytes()).hexdigest()
        tests_sha = hashlib.sha256(tests_path.read_bytes()).hexdigest()
        digests = probe.verify_self_and_tests_digests(
            expected_probe_sha256=probe_sha,
            expected_tests_sha256=tests_sha,
            probe_path=probe_path,
            tests_path=tests_path,
        )
        self.assertEqual(digests["probe_source_sha256"], probe_sha)
        self.assertEqual(digests["probe_tests_sha256"], tests_sha)
        with self.assertRaises(probe.ProbeError) as bad_probe:
            probe.verify_self_and_tests_digests(
                expected_probe_sha256="0" * 64,
                probe_path=probe_path,
            )
        self.assertEqual(bad_probe.exception.code, "PROBE_SOURCE_DIGEST_MISMATCH")
        with self.assertRaises(probe.ProbeError) as bad_tests:
            probe.verify_self_and_tests_digests(
                expected_probe_sha256=probe_sha,
                expected_tests_sha256="0" * 64,
                probe_path=probe_path,
                tests_path=tests_path,
            )
        self.assertEqual(bad_tests.exception.code, "PROBE_TESTS_DIGEST_MISMATCH")
        with patch.dict(os.environ, {"PACKAGE_SIGNING_KEY": "leaked"}, clear=False):
            with self.assertRaises(b3_entry.FixtureError) as cred_err:
                probe.authenticate_stage1(
                    probe_path.parent,
                    expected_probe_sha256=probe_sha,
                    expected_tests_sha256=tests_sha,
                )
            self.assertEqual(cred_err.exception.code, "CREDENTIAL_ENV_FORBIDDEN")

    def test_status_proof_accepts_offline_primary_and_online_subkey(self) -> None:
        proof = inspect_ci_secret_metadata(_valid_secret_listing(), now=1800000000)
        self.assertEqual(proof["primaryFingerprint"], PRIMARY)
        self.assertEqual(proof["signingSubkeyFingerprint"], SUBKEY)
        self.assertFalse(proof["primarySecretAvailable"])
        self.assertTrue(proof["signingSecretAvailable"])
        verify_proof = inspect_detached_verification(
            _valid_verify_status(), returncode=0, now=1800000000
        )
        self.assertEqual(verify_proof["statusPair"], "GOODSIG+VALIDSIG")

    def test_status_proof_rejects_online_primary_wrong_caps_or_bad_verify_token(self) -> None:
        grip1 = "A" * 64
        grip2 = "B" * 64
        wrong_primary_caps = (
            f"sec:u:4096:1:{PRIMARY[-16:]}:1700000000:1900000000:::::scSC:::#::23::0:\n"
            f"fpr:::::::::{PRIMARY}:\n"
            f"grp:::::::::{grip1}:\n"
            f"ssb:u:4096:1:{SUBKEY[-16:]}:1700000000:1900000000:::::s:::+::23::0:\n"
            f"fpr:::::::::{SUBKEY}:\n"
            f"grp:::::::::{grip2}:\n"
        ).encode("ascii")
        with self.assertRaises(ProofError) as caps_err:
            inspect_ci_secret_metadata(wrong_primary_caps, now=1800000000)
        self.assertEqual(caps_err.exception.args[0], "KEY_SECRET_OR_CAPABILITY")

        online_primary = (
            f"sec:u:4096:1:{PRIMARY[-16:]}:1700000000:1900000000:::::cCS:::+::23::0:\n"
            f"fpr:::::::::{PRIMARY}:\n"
            f"grp:::::::::{grip1}:\n"
            f"ssb:u:4096:1:{SUBKEY[-16:]}:1700000000:1900000000:::::s:::+::23::0:\n"
            f"fpr:::::::::{SUBKEY}:\n"
            f"grp:::::::::{grip2}:\n"
        ).encode("ascii")
        with self.assertRaises(ProofError) as online_err:
            inspect_ci_secret_metadata(online_primary, now=1800000000)
        self.assertEqual(online_err.exception.args[0], "KEY_SECRET_OR_CAPABILITY")

        bad_verify = (
            f"[GNUPG:] NEWSIG\n"
            f"[GNUPG:] GOODSIG {SUBKEY[-16:]} Test\n"
            f"[GNUPG:] BADSIG {SUBKEY[-16:]} Test\n"
            f"[GNUPG:] VALIDSIG {SUBKEY} 2023-11-14 1700000000 0 4 0 1 8 00 {PRIMARY}\n"
        ).encode("ascii")
        with self.assertRaises(ProofError) as verify_err:
            inspect_detached_verification(bad_verify, returncode=0, now=1800000000)
        self.assertEqual(verify_err.exception.args[0], "STATUS_REJECTED")

    def _run_simulated_probe(
        self,
        *,
        verify_stdout: bytes,
        cleanup_confirmed: bool = True,
    ) -> tuple[Path, psr.ProtectedSigningRuntime, dict[str, object] | None, BaseException | None]:
        _FakeOwnedAgent.next_cleanup_confirmed = cleanup_confirmed
        raw_tmp = tempfile.mkdtemp(prefix="tf-c6-gpg-unit-")
        base = Path(raw_tmp).resolve(strict=True)
        os.chmod(base, 0o700)
        repo_root = base / "repo"
        (repo_root / "keys").mkdir(parents=True)
        pub_src = Path(__file__).resolve(strict=True).parents[3] / "keys/knowledge-forge-ai-packages.asc"
        pub_bytes = (
            pub_src.read_bytes()
            if pub_src.is_file()
            else b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        (repo_root / "keys/knowledge-forge-ai-packages.asc").write_bytes(pub_bytes)
        facts_path = base / "facts.json"
        facts_path.write_text(json.dumps({"execution_mode": "fixture"}), encoding="utf-8")
        probe_parent = base / "parent"
        os.mkdir(probe_parent, 0o700)

        def fake_runner(argv, *, cwd, env, stdin, phase, **kwargs):
            if phase == "private-key-import" and "--list-secret-keys" in argv:
                return psr.ProcessResult(returncode=0, stdout=_valid_secret_listing(), stderr=b"")
            if phase == "pacman-package-sign":
                out_idx = list(argv).index("--output") + 1
                sig_path = Path(argv[out_idx])
                psr._exclusive_write(sig_path, b"SYNTHETIC-DETACHED-SIGNATURE\n", "test sig")
                return psr.ProcessResult(returncode=0, stdout=b"", stderr=b"")
            if phase == "pacman-package-verify":
                return psr.ProcessResult(returncode=0, stdout=verify_stdout, stderr=b"")
            return psr.ProcessResult(returncode=0, stdout=b"", stderr=b"")

        runtime = psr.ProtectedSigningRuntime(binding=SignerBinding(), runner=fake_runner)
        stage1_stub = {
            "probe_source_sha256": "a" * 64,
            "probe_tests_sha256": "b" * 64,
        }
        with (
            patch.object(psr, "OwnedGpgAgent", _FakeOwnedAgent),
            patch.object(psr, "_proof_epoch", return_value=1800000000),
            patch.object(psr, "verify_committed_public_key", return_value=None),
            patch.object(probe, "authenticate_stage1", return_value=stage1_stub),
            patch.object(probe.b3_inputs, "load_manifest", return_value=object()),
            patch.object(probe.b3_inputs, "validate_measured_facts", return_value={}),
            patch.object(probe.b3_entry, "_check_credential_free_env", return_value=None),
        ):
            try:
                receipt = probe.execute_native_probe(
                    repo_root=repo_root,
                    facts_path=facts_path,
                    probe_parent=probe_parent,
                    secret_stream=io.BytesIO(_frame_bytes()),
                    expected_probe_sha256="a" * 64,
                    expected_tests_sha256="b" * 64,
                    runtime=runtime,
                )
                return probe_parent, runtime, receipt, None
            except BaseException as err:
                return probe_parent, runtime, None, err

    def test_simulated_runtime_success_and_cleanup(self) -> None:
        probe_parent, runtime, receipt, err = self._run_simulated_probe(
            verify_stdout=_valid_verify_status(),
            cleanup_confirmed=True,
        )
        self.assertIsNone(err)
        assert receipt is not None
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["evidence_class"], "native-unqualified")
        self.assertFalse(receipt["production_authority"])
        self.assertFalse(receipt["custody_retained"])
        cleanup = receipt["cleanup"]
        assert isinstance(cleanup, dict)
        self.assertTrue(cleanup["agent_cleanup_inferred_from_execute_return"])
        self.assertTrue(cleanup["work_dir_absent"])
        self.assertTrue(cleanup["probe_root_absent"])
        self.assertEqual(cleanup["retained_custody_count"], 0)
        self.assertIsNone(runtime.retained_custody)
        self.assertFalse((probe_parent / "c6-gpg-probe").exists())

    def test_simulated_runtime_body_rejection_cleans_probe_root_when_custody_clear(self) -> None:
        bad_verify = (
            f"[GNUPG:] NEWSIG\n"
            f"[GNUPG:] GOODSIG {SUBKEY[-16:]} Test\n"
            f"[GNUPG:] BADSIG {SUBKEY[-16:]} Test\n"
        ).encode("ascii")
        probe_parent, runtime, receipt, err = self._run_simulated_probe(
            verify_stdout=bad_verify,
            cleanup_confirmed=True,
        )
        self.assertIsNone(receipt)
        self.assertIsInstance(err, ProtectedSigningError)
        assert isinstance(err, ProtectedSigningError)
        self.assertEqual(err.code, "PACMAN_VERIFY_STATUS")
        self.assertIsNone(runtime.retained_custody)
        self.assertFalse((probe_parent / "c6-gpg-probe").exists())
        failure = probe.build_probe_failure_receipt(
            err, probe_parent=probe_parent, runtime=runtime
        )
        self.assertEqual(failure["status"], "failed-closed")
        self.assertEqual(failure["error_code"], "PACMAN_VERIFY_STATUS")
        self.assertFalse(failure["custody_retained"])
        self.assertTrue(failure["cleanup"]["probe_root_absent"])

    def test_simulated_runtime_unconfirmed_agent_retains_custody_and_writes_failure_receipt(self) -> None:
        probe_parent, runtime, receipt, err = self._run_simulated_probe(
            verify_stdout=_valid_verify_status(),
            cleanup_confirmed=False,
        )
        self.assertIsNone(receipt)
        self.assertIsNotNone(err)
        assert err is not None
        self.assertIsNotNone(runtime.retained_custody)
        self.assertEqual(len(psr._RETAINED_RUNTIME_CUSTODIES), 1)
        self.assertTrue((probe_parent / "c6-gpg-probe").exists())
        failure = probe.build_probe_failure_receipt(
            err, probe_parent=probe_parent, runtime=runtime
        )
        self.assertEqual(failure["status"], "failed-closed")
        self.assertEqual(failure["error_code"], "SIGNER_CLEANUP")
        self.assertTrue(failure["custody_retained"])
        self.assertEqual(failure["cleanup"]["retained_custody_count"], 1)
        self.assertFalse(failure["cleanup"]["retained_agent_cleanup_confirmed"])
        self.assertFalse(failure["cleanup"]["probe_root_absent"])


if __name__ == "__main__":
    unittest.main()
