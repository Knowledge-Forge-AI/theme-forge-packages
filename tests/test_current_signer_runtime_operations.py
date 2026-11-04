"""Pure runtime-to-worker-to-host diagnostic checks; no keys or native tools.

The process runner and agent are inert fixtures. These tests exercise operation
selection in the real runtime and its failure record crossing the worker/host
boundary. They do not qualify signing, the live lease or private cleanup.
"""

import ast
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_current_signer_post_frame_diagnostics as base
import protected_signing_runtime as runtime

EXPECTED = {
    "public-key-import": "RUNTIME_IMPORT_PUBLIC",
    "private-key-import": "RUNTIME_IMPORT_CI",
    "rpm-public-key-import": "RUNTIME_RPM_IMPORT_PUBLIC",
    "rpm-package-sign": "RUNTIME_RPM_PACKAGE_SIGN",
    "rpm-package-verify": "RUNTIME_RPM_PACKAGE_VERIFY",
    "pacman-package-sign": "RUNTIME_PACMAN_PACKAGE_SIGN",
    "pacman-package-verify": "RUNTIME_PACMAN_PACKAGE_VERIFY",
    "apt-release-clearsign": "RUNTIME_APT_CLEARSIGN",
    "apt-release-detach-sign": "RUNTIME_APT_DETACH_SIGN",
    "rpm-metadata-create": "RUNTIME_RPM_METADATA_CREATE",
    "rpm-metadata-sign": "RUNTIME_RPM_METADATA_SIGN",
    "rpm-metadata-verify": "RUNTIME_RPM_METADATA_VERIFY",
    "pacman-database-create": "RUNTIME_PACMAN_DATABASE_CREATE",
    "pacman-database-sign": "RUNTIME_PACMAN_DATABASE_SIGN",
    "pacman-database-verify": "RUNTIME_PACMAN_DATABASE_VERIFY",
}


class RuntimeOperationTests(unittest.TestCase):
    def make_runtime(self, runner):
        obj = runtime.ProtectedSigningRuntime(runner=runner)
        obj._agent = types.SimpleNamespace(require_live=lambda: None)
        return obj

    def invoke(self, obj, phase):
        return obj._run((), cwd=Path("."), env={}, stdin=b"", phase=phase)

    def test_every_live_native_operation_records_before_failure(self):
        def runner(*args, **kwargs):
            raise runtime.ProtectedSigningError("COMMAND_FAILED", base.TEXT_CANARY)
        obj = self.make_runtime(runner)
        for phase, label in EXPECTED.items():
            with self.subTest(phase=phase):
                with self.assertRaises(runtime.ProtectedSigningError):
                    self.invoke(obj, phase)
                self.assertEqual(obj._last_native_operation, label)

    def test_successful_commands_keep_last_requested_operation(self):
        obj = self.make_runtime(lambda *a, **k: runtime.ProcessResult(0, b"", b""))
        for phase, label in EXPECTED.items():
            self.invoke(obj, phase)
            self.assertEqual(obj._last_native_operation, label)

    def test_marker_precedes_agent_and_lease_guards(self):
        obj = runtime.ProtectedSigningRuntime(runner=lambda *a, **k: None)
        with self.assertRaises(runtime.ProtectedSigningError):
            self.invoke(obj, "rpm-package-sign")
        self.assertEqual(obj._last_native_operation, EXPECTED["rpm-package-sign"])
        class Lease:
            def native_phase(self, phase):
                raise runtime.ProtectedSigningError("LIVE_LEASE_REQUIRED", base.TEXT_CANARY)
        obj._agent = types.SimpleNamespace(require_live=lambda: None)
        obj._active_live_lease = Lease()
        with self.assertRaises(runtime.ProtectedSigningError):
            self.invoke(obj, "pacman-package-sign")
        self.assertEqual(obj._last_native_operation, EXPECTED["pacman-package-sign"])

    def test_unknown_nonexact_and_hostile_phase_is_unavailable(self):
        obj = self.make_runtime(lambda *a, **k: runtime.ProcessResult(0, b"", b""))
        class Hostile:
            def __hash__(self):
                raise AssertionError("must not hash")
        for phase in (base.PATH_CANARY, None, [], Hostile(), type("S", (str,), {})("public-key-import")):
            self.invoke(obj, phase)
            self.assertIsNone(obj._last_native_operation)

    def test_idle_intake_resets_stale_state_but_busy_runtime_is_preserved(self):
        obj = runtime.ProtectedSigningRuntime()
        self.assertIsNone(obj._last_native_operation)
        obj._last_native_operation = "RUNTIME_RPM_PACKAGE_SIGN"
        obj._require_idle()
        self.assertIsNone(obj._last_native_operation)
        obj._last_native_operation = "RUNTIME_IMPORT_CI"
        obj._agent = object()
        with self.assertRaises(runtime.ProtectedSigningError):
            obj._require_idle()
        self.assertEqual(obj._last_native_operation, "RUNTIME_IMPORT_CI")
        self.assertIsNone(runtime.ProtectedSigningRuntime()._last_native_operation)

    def test_operation_vocabularies_match_across_each_boundary(self):
        labels = set(EXPECTED.values()) | {"RUNTIME_AGENT_START"}
        self.assertEqual(labels, base.sw._RUNTIME_OPERATION_STEPS)
        self.assertTrue(labels <= base.sw._POST_FRAME_STEPS)
        self.assertEqual(base.sw._POST_FRAME_STEPS, base.hc._POST_FRAME_WORKER_STEPS)
        self.assertEqual(len(base.sw._POST_FRAME_STEPS), 25)
        self.assertNotIn("SIGNING_RUNTIME", labels)

    def test_closed_phase_set_covers_actual_live_lease(self):
        importer = Path(runtime.__file__).parents[1] / "current_import_routing.py"
        tree = ast.parse(importer.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "_NATIVE_PHASES" for t in n.targets))
        self.assertEqual(set(EXPECTED), ast.literal_eval(node.value.args[0]))
        self.assertEqual(runtime._NATIVE_OPERATION_LABELS, EXPECTED)


class WorkerRuntimeBoundaryTests(base._WorkerFixture):
    def failing_runtime(self, phase, code="COMMAND_FAILED"):
        def runner(*args, **kwargs):
            raise runtime.ProtectedSigningError(code, base.TEXT_CANARY)
        obj = runtime.ProtectedSigningRuntime(runner=runner)
        obj._agent = types.SimpleNamespace(require_live=lambda: None)
        def execute(this, *args, **kwargs):
            return this._run((), cwd=Path("."), env={}, stdin=b"", phase=phase)
        obj.execute_live_lease = types.MethodType(execute, obj)
        return obj

    def test_real_runtime_failure_crosses_worker_and_host_with_only_fixed_labels(self):
        for phase, label in EXPECTED.items():
            with self.subTest(phase=phase):
                out = self._flow(runtime=self.failing_runtime(phase),
                                 overrides={"protected_signing_runtime": runtime})
                self.assertIs(out.error.runtime, out.runtime)
                self.assertEqual(bytes(out.buffers["key"]), bytes(len(base.KEY_CANARY)))
                self.assertEqual(bytes(out.buffers["phrase"]), bytes(len(base.PHRASE_CANARY)))
                rc, text = base._run_worker_main(out.error)
                doc = json.loads(text)
                self.assertEqual(rc, 2)
                self.assertEqual(doc["error_code"], "WITHHELD_POST_FRAME")
                self.assertEqual(doc["post_frame_diagnostic"]["step"], label)
                self.assertEqual(doc["post_frame_diagnostic"]["code"], "COMMAND_FAILED")
                parsed = base.hc._parse_untrusted_post_frame_worker_stderr(text.encode("ascii"))
                self.assertEqual(parsed["step"], label)
                self.assertEqual(parsed["record"], "VALID")
                self.assertIs(parsed["untrusted_worker_claim"], True)
                self.assertEqual(out.lease.close_calls, 0)
                base._assert_no_canary(self, text)

    def test_diagnostic_interruption_retains_runtime_and_does_not_close_input_lease(self):
        lease = base.FakeLease()
        obj = self.failing_runtime("rpm-package-sign")
        interruption = KeyboardInterrupt()
        original = base.sw._mark_post_frame_step
        def mark(tracker, step):
            if step == "RUNTIME_RPM_PACKAGE_SIGN":
                raise interruption
            return original(tracker, step)
        with mock.patch.object(base, "FakeLease", return_value=lease), mock.patch.object(base.sw, "_mark_post_frame_step", side_effect=mark):
            with self.assertRaises(KeyboardInterrupt) as got:
                self._flow(runtime=obj, overrides={"protected_signing_runtime": runtime})
        self.assertIs(got.exception, interruption)
        self.assertIs(got.exception.runtime, obj)
        self.assertEqual(lease.close_calls, 0)
        self.assertIs(base.sw._RETAINED_WORKER_CUSTODIES[-1]["runtime"], obj)

    def test_only_exact_runtime_and_fixed_operation_are_accepted(self):
        for marker in (None, base.PATH_CANARY, "RECEIPT", [], type("S", (str,), {})("RUNTIME_IMPORT_CI")):
            obj = self.failing_runtime("public-key-import")
            def execute(this, *args, **kwargs):
                this._last_native_operation = marker
                raise runtime.ProtectedSigningError("COMMAND_FAILED", base.TEXT_CANARY)
            obj.execute_live_lease = types.MethodType(execute, obj)
            out = self._sign(runtime=obj, overrides={"protected_signing_runtime": runtime})
            self.assertEqual(out.tracker.step, "SIGNING_RUNTIME")
        class ForeignRuntime(base.FakeRuntime):
            @property
            def _last_native_operation(self):
                raise AssertionError("foreign properties must not be inspected")
        out = self._sign(runtime=ForeignRuntime(raise_error=RuntimeError(base.TEXT_CANARY)),
                         overrides={"protected_signing_runtime": runtime})
        self.assertEqual(out.tracker.step, "SIGNING_RUNTIME")
        self.assertIsInstance(out.error, RuntimeError)

    def test_agent_start_label_and_post_command_failure_are_explicitly_last_requested(self):
        for marker in ("RUNTIME_AGENT_START", "RUNTIME_RPM_PACKAGE_VERIFY"):
            obj = self.failing_runtime("public-key-import")
            def execute(this, *args, **kwargs):
                this._last_native_operation = marker
                raise runtime.ProtectedSigningError("SIGNER_CLEANUP", base.TEXT_CANARY)
            obj.execute_live_lease = types.MethodType(execute, obj)
            out = self._sign(runtime=obj, overrides={"protected_signing_runtime": runtime})
            self.assertEqual(out.tracker.step, marker)
            self.assertEqual(base.sw._post_frame_diagnostic(out.tracker, out.error)["code"], "UNCLASSIFIED")


    def test_nine_runtime_error_codes_cross_only_as_fixed_untrusted_labels(self):
        codes = ("COMMAND_FAILED", "COMMAND_TIMEOUT", "COMMAND_OUTPUT_LIMIT",
                 "OUTPUT_INVENTORY", "REPOSITORY_METADATA", "PACKAGE_MUTATED",
                 "AGENT_CONSUMER_LIFECYCLE", "COMMAND_CLEANUP", "AGENT_REQUIRED")
        for code in codes:
            with self.subTest(code=code):
                out = self._flow(runtime=self.failing_runtime("rpm-metadata-create", code),
                                 overrides={"protected_signing_runtime": runtime})
                rc, text = base._run_worker_main(out.error)
                self.assertEqual(rc, 2)
                doc = json.loads(text)
                self.assertEqual(doc["post_frame_diagnostic"]["code"], code)
                parsed = base.hc._parse_untrusted_post_frame_worker_stderr(text.encode("ascii"))
                self.assertEqual(parsed["code"], code)
                self.assertEqual(parsed["step"], "RUNTIME_RPM_METADATA_CREATE")
                self.assertIs(parsed["untrusted_worker_claim"], True)
                self.assertEqual(out.lease.close_calls, 0)
                self.assertEqual(bytes(out.buffers["key"]), bytes(len(base.KEY_CANARY)))
                self.assertEqual(bytes(out.buffers["phrase"]), bytes(len(base.PHRASE_CANARY)))
                base._assert_no_canary(self, text)


if __name__ == "__main__":
    unittest.main()
