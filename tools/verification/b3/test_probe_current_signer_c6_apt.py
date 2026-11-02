"""Pure adverse-contract checks; no test confers native signature authority."""
from __future__ import annotations
import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

_HERE = Path(__file__).resolve(strict=True).parent
sys.path.insert(0, str(_HERE))
import probe_current_signer_c6_apt as probe


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.native = patch.object(subprocess, "Popen", side_effect=AssertionError("NATIVE_DENIED"))
        self.native.start()
        self.addCleanup(self.native.stop)

    def observations(self):
        execution = SimpleNamespace(native_execution=True, status="observed", production_authority=False)
        values = []
        for kind in ("inrelease", "release.gpg"):
            values.append({
                "status": "valid", "verification_mode": "native",
                "confers_signature_authentication": "true", "signature_kind": kind,
                "release_sha256": hashlib.sha256(probe.RELEASE_BYTES).hexdigest(),
                "public_key_sha256": probe.PUBLIC_KEY_SHA256,
                "verified_issuer": probe.PRIMARY_FINGERPRINT,
                "primary_fingerprint": probe.PRIMARY_FINGERPRINT,
                "signing_subkey": probe.SIGNING_SUBKEY_FINGERPRINT,
                "gpg_binary_sha256": "a" * 64,
            })
        # Synthetic records exercise only the observation checker, never native
        # probe execution, a pass receipt, SignedStore, or signature retention.
        return execution, values

    def test_fixed_observation_schema_only(self):
        execution, results = self.observations()
        self.assertIsNone(probe.check_observations(execution, probe.RELEASE_BYTES, results))

    def test_fixture_signing_observation_refused(self):
        execution, results = self.observations()
        execution.native_execution = False
        with self.assertRaisesRegex(probe.ProbeError, "APT_SIGNING_OBSERVATION"):
            probe.check_observations(execution, probe.RELEASE_BYTES, results)

    def test_production_claim_refused(self):
        execution, results = self.observations()
        execution.production_authority = True
        with self.assertRaises(probe.ProbeError):
            probe.check_observations(execution, probe.RELEASE_BYTES, results)

    def test_modified_release_refused(self):
        execution, results = self.observations()
        with self.assertRaisesRegex(probe.ProbeError, "APT_RELEASE_MISMATCH"):
            probe.check_observations(execution, probe.RELEASE_BYTES + b"x", results)

    def test_each_required_native_identity_field_checked(self):
        execution, good = self.observations()
        for index in range(2):
            for key in list(good[index]):
                if key == "gpg_binary_sha256":
                    continue
                with self.subTest(index=index, key=key):
                    changed = [dict(item) for item in good]
                    changed[index][key] = "wrong"
                    with self.assertRaisesRegex(probe.ProbeError, "APT_NATIVE_REQUIRED"):
                        probe.check_observations(execution, probe.RELEASE_BYTES, changed)

    def test_non_digest_executable_identity_refused(self):
        execution, results = self.observations()
        results[0]["gpg_binary_sha256"] = "fixture-not-recorded"
        with self.assertRaises(probe.ProbeError):
            probe.check_observations(execution, probe.RELEASE_BYTES, results)

    def test_signature_pair_required(self):
        execution, results = self.observations()
        with self.assertRaises(probe.ProbeError):
            probe.check_observations(execution, probe.RELEASE_BYTES, results[:1])

    def test_zeroing_same_mutable_buffer(self):
        secret = bytearray(b"inert-fixture")
        identity = id(secret)
        probe._zero(secret)
        self.assertEqual(id(secret), identity)
        self.assertEqual(secret, b"\0" * 13)
        probe._zero(None)

    def test_process_or_staged_custody_blocks_cleanup(self):
        runtime = SimpleNamespace(retained_custody=None)
        clean = SimpleNamespace(retained_custody=None, process_cleanup_confirmed=True)
        self.assertFalse(probe._has_custody(runtime, [clean]))
        clean.retained_custody = object()
        self.assertTrue(probe._has_custody(runtime, [clean]))
        clean.retained_custody = None
        clean.process_cleanup_confirmed = False
        self.assertTrue(probe._has_custody(runtime, [clean]))
        runtime.retained_custody = object()
        self.assertTrue(probe._has_custody(runtime, []))

    def test_no_mode_refuses_without_native_or_secrets(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(probe.main([]), 2)
        self.assertIn("APT_EXPLICIT_MODE_REQUIRED", out.getvalue())

    def test_framing_failure_uses_stderr_only(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(probe.main(["--emit-stdin-frame"]), 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("APT_PROBE_INPUTS", err.getvalue())

    def test_unknown_failure_message_not_serialized(self):
        with tempfile.TemporaryDirectory() as temp:
            args = ["--authenticate-stage1", "--repo-root", temp,
                    "--out", str(Path(temp) / "receipt.json"),
                    "--expected-probe-sha256", "a" * 64,
                    "--expected-tests-sha256", "b" * 64]
            with patch.object(probe, "authenticate_stage1", side_effect=ValueError("PRIVATE_FIXTURE_DO_NOT_RETAIN")):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(probe.main(args), 2)
            self.assertNotIn("PRIVATE_FIXTURE", out.getvalue())
            self.assertIn("NATIVE_APT_PROBE_FAILED", out.getvalue())

    def test_stage1_rejects_source_mismatch_before_common_auth(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(probe.common, "authenticate_stage1") as authenticate:
                with self.assertRaisesRegex(probe.ProbeError, "APT_PROBE_SOURCE"):
                    probe.authenticate_stage1(Path(temp), "a" * 64, "b" * 64)
                authenticate.assert_not_called()

    def test_bounded_output_reader_preserves_original(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Release"
            path.write_bytes(b"inert")
            path.chmod(0o600)
            self.assertEqual(probe._read_output(path, 5), b"inert")
            with self.assertRaises(probe.ProbeError):
                probe._read_output(path, 4)
            self.assertEqual(path.read_bytes(), b"inert")

    def test_output_symlink_or_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); path = root / "Release"
            path.write_bytes(b"inert");path.chmod(0o600)
            (root / "link").symlink_to(path)
            with self.assertRaises(OSError):
                probe._read_output(root / "link", 10)
            os.link(path, root / "hardlink")
            with self.assertRaises(probe.ProbeError):
                probe._read_output(path, 10)

    def test_root_identity_rejects_leaf_symlink_and_public_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); child = root / "owned"; child.mkdir(mode=0o700)
            first = probe._identity(child)
            self.assertEqual(first, probe._identity(child))
            (root / "link").symlink_to(child)
            with self.assertRaises(probe.ProbeError):
                probe._identity(root / "link")
            child.chmod(0o755)
            with self.assertRaises(probe.ProbeError):
                probe._identity(child)



    def test_frame_emission_accepts_only_inert_secret_inputs_after_source_checks(self):
        repo = _HERE.parents[2]
        source_sha = hashlib.sha256((_HERE / "probe_current_signer_c6_apt.py").read_bytes()).hexdigest()
        tests_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            availability = Path(temp) / "availability.json"
            capture = SimpleNamespace(buffer=io.BytesIO())
            args = ["--emit-stdin-frame", "--repo-root", str(repo),
                    "--expected-probe-sha256", source_sha,
                    "--expected-tests-sha256", tests_sha,
                    "--availability-out", str(availability)]
            with patch.dict(os.environ, {"PACKAGE_SIGNING_KEY": "INERT-NOT-A-KEY",
                                         "PACKAGE_SIGNING_PASSPHRASE": "INERT-NOT-A-CREDENTIAL"}):
                with patch.object(sys, "stdout", capture), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(probe.main(args), 0)
            self.assertTrue(availability.is_file())
            key, phrase = probe.common._read_stdin_frame(io.BytesIO(capture.buffer.getvalue()))
            self.assertEqual(key, b"INERT-NOT-A-KEY")
            self.assertEqual(phrase, b"INERT-NOT-A-CREDENTIAL")
            probe._zero(key);probe._zero(phrase)

    def test_probe_output_close_uncertainty_retains_fd_and_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Release";path.write_bytes(b"inert");path.chmod(0o600)
            original_close = probe.os.close;opened = []
            original_open = probe.os.open
            snapshot = tuple(getattr(probe, "_RETAINED_PROBE_READS", ()))
            def capture(name, flags, *args):
                fd = original_open(name, flags, *args);opened.append(fd);return fd
            def close(fd):
                if fd in opened:raise OSError("inert-read-close")
                return original_close(fd)
            try:
                with patch.object(probe.os, "open", side_effect=capture), patch.object(probe.os, "close", side_effect=close):
                    with self.assertRaises(probe.ProbeError):
                        probe._read_output(path, 10)
                self.assertTrue(probe._has_custody(SimpleNamespace(retained_custody=None), []))
                self.assertEqual(probe._RETAINED_PROBE_READS[-1]["fd"], opened[0])
                os.fstat(opened[0])
                self.assertTrue(path.is_file())
            finally:
                for fd in opened:original_close(fd)
                if hasattr(probe, "_RETAINED_PROBE_READS"):
                    probe._RETAINED_PROBE_READS[:] = snapshot

    def test_composed_probe_refuses_fixture_observation_and_zeroes_frame_buffers(self):
        import struct
        repo = _HERE.parents[2];references = []
        class FixtureRuntime:
            retained_custody = None
            def __init__(self, **_):pass
            def execute_apt_release(self, release, *, output_root, private_key_bytes, passphrase, **_):
                references.extend((private_key_bytes, passphrase))
                output_root.mkdir(mode=0o700)
                for name, data in (("Release", release), ("InRelease", b"INERT"), ("Release.gpg", b"INERT")):
                    path=output_root/name;path.write_bytes(data);path.chmod(0o600)
                return SimpleNamespace(native_execution=False,status="test-only",production_authority=False)
        class FixtureAdapter:
            retained_custody = None
            process_cleanup_confirmed = True
            def __init__(self, **_):pass
            def validate(self, *_):return {"verification_mode":"fixture","confers_signature_authentication":"false"}
        key, phrase = b"INERT-KEY", b"INERT-PHRASE"
        frame = probe.common.FRAME_MAGIC + struct.pack(">II",len(key),len(phrase)) + key + phrase
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);facts=root/"facts.json";facts.write_text("{}")
            with patch.object(probe.b3_entry,"_check_credential_free_env"), patch.object(probe,"authenticate_stage1",return_value={}), patch.object(probe.b3_inputs,"load_manifest",return_value={}), patch.object(probe.b3_inputs,"validate_measured_facts"), patch.object(probe,"ProtectedSigningRuntime",FixtureRuntime), patch.object(probe,"AptSignatureAdapter",FixtureAdapter):
                receipt=probe.execute_native_probe(repo_root=repo,facts_path=facts,probe_parent=root,probe_sha="a"*64,tests_sha="b"*64,secret_stream=io.BytesIO(frame))
            self.assertEqual(receipt["status"],"failed-closed")
            self.assertEqual(receipt["error_code"],"APT_SIGNING_OBSERVATION")
            self.assertFalse(receipt["production_authority"])
            self.assertFalse((root/"c6-apt-probe").exists())
            self.assertTrue(references and all(not any(value) for value in references))

if __name__ == "__main__":
    unittest.main()
