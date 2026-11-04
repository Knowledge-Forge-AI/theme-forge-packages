"""Pure fixture checks for the PRIVATE, UNADOPTED post-frame closed diagnostic proposal.

No credentials, GPG, Docker, Nix, network, native processes or external state are used. All
secret-looking values are synthetic canaries. Collaborator modules are replaced by in-memory fakes
through ``sys.modules`` only for the duration of each test.
"""

from __future__ import annotations

import contextlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

_SIGNER_DIR = Path(__file__).resolve().parents[1] / "tools" / "verification" / "current_signer"
if str(_SIGNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SIGNER_DIR))

import signer_host_controller as hc  # noqa: E402
import signer_worker as sw  # noqa: E402
from source_closure import WORKER_RECEIPT_SCHEMA  # noqa: E402

KEY_CANARY = b"SYNTHETIC-KEY-CANARY-7f3a"
PHRASE_CANARY = b"SYNTHETIC-PASSPHRASE-CANARY-91c2"
PATH_CANARY = "/home/runner/SYNTHETIC-PATH-CANARY/private"
TEXT_CANARY = "SYNTHETIC-TEXT-CANARY"
CANARY_TOKENS = ("CANARY", "/home/runner", "Traceback")

WORKER_ARGV = [
    "--p-root", "/x", "--r-root", "/x", "--workspace-root", "/x", "--export-root", "/x",
    "--p-commit", "c", "--p-tree", "t", "--r-commit", "c", "--r-tree", "t",
    "--source-closure-sha256", "s", "--challenge-nonce", "n", "--expected-gpg-sha256", "g",
    "--expected-rpm-sha256", "r", "--release-date", "d", "--rs9-run", "1",
]
HOST_ARGV = [
    "--p-root", "/x", "--r-root", "/x", "--export-root", "/x",
    "--p-commit", "c", "--p-tree", "t", "--r-commit", "c", "--r-tree", "t",
    "--source-closure-sha256", "s", "--challenge-nonce", "n", "--run-id-suffix", "1",
    "--container-image", "i", "--container-python", "/py", "--expected-gpg-sha256", "g",
    "--expected-rpm-sha256", "r", "--release-date", "d", "--rs9-run", "1",
]
WORKER_FAILED_BASE_KEYS = {
    "schema", "status", "error_code", "custody_retained", "publication_authority", "native_client_qualification",
}
HOST_SUCCESS_KEYS = {
    "schema", "status", "gate_state", "worker_receipt", "host_container_and_network_teardown",
    "c6_agent_and_private_work_cleanup_confirmed", "publication_authority", "native_client_qualification",
}
WORKER_RECEIPT_KEYS = {
    "schema", "status", "evidence_class", "worker_pid", "lease_owner_pid", "same_pid_verified", "source_binding",
    "descriptor_sha256", "online_intake_token_present", "container_signing_credential_free_at_start",
    "container_totally_credential_free_at_start", "online_token_removed_from_future_child_env",
    "env_removal_erases_kernel_or_memory_copies", "custody_model", "native_signing_execution", "signing_status",
    "signed_package_rows", "c6_agent_and_private_work_cleanup_confirmed", "lease_closed_confirmed",
    "stage_snapshot_joined_to_fresh_admission", "public_verification_status", "public_native_crypto_verified",
    "signed_store_records", "exported_file_count", "exported_files", "custody_retained",
    "publication_authority", "native_client_qualification",
}


def _assert_no_canary(test: unittest.TestCase, text: str) -> None:
    for token in CANARY_TOKENS:
        test.assertNotIn(token, text)


# --------------------------------------------------------------------------------------------
# Worker fakes
# --------------------------------------------------------------------------------------------

class FakeLease:
    def __init__(self) -> None:
        self.state = "active"
        self._pid = os.getpid()
        self._record: dict[str, object] = {}
        self.close_calls = 0

    def _close_confirmed(self) -> None:
        self.close_calls += 1
        self.state = "closed"


class FakeRuntime:
    def __init__(self, *, raise_error: BaseException | None = None, retained: object | None = None) -> None:
        self.raise_error = raise_error
        self.retained_custody = retained
        self._agent = None
        self.seen_key: bytearray | None = None
        self.seen_phrase: bytearray | None = None

    def execute_live_lease(self, lease, *, output_root, public_key_bytes, private_key_bytes, passphrase):
        self.seen_key, self.seen_phrase = private_key_bytes, passphrase
        if self.raise_error is not None:
            raise self.raise_error
        lease.state = "closed"
        return types.SimpleNamespace(native_execution=False, status="test-only", objects=[object()])


class FakeStreams:
    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.close_errors: list[BaseException] = []
        self.closed_out = False

    def write_line(self, data: bytes) -> None:
        self.written.append(data)

    def read_line(self) -> bytes:
        return b"challenge\n"

    def close_out(self) -> None:
        self.closed_out = True

    def close_all(self) -> None:
        return None


class FakeSourceBinding:
    def __init__(self, *args: object) -> None:
        self.args = args

    def record(self) -> dict[str, object]:
        return {"binding": "synthetic"}


def _files_module(write_error: BaseException | None = None) -> types.ModuleType:
    mod = types.ModuleType("public_repository_files")
    members = {"dists/stable/Release": b"synthetic"}
    mod.snapshot = lambda path: types.SimpleNamespace(members=dict(members))
    mod.unchanged = lambda before: None

    def write_new(root, new_members):
        if write_error is not None:
            raise write_error

    mod.write_new = write_new
    mod.inventory = lambda m: sorted(m)
    return mod


def _worker_modules(read_frame, *, files: types.ModuleType | None = None) -> dict[str, object]:
    runtime_mod = types.ModuleType("protected_signing_runtime")

    class _Forbidden:
        def __init__(self) -> None:
            raise AssertionError("real signing runtime must not be constructed in fixtures")

    runtime_mod.ProtectedSigningRuntime = _Forbidden
    verifier_mod = types.ModuleType("public_repository_verifier")
    verifier_mod.require_all_custody_closed = lambda: None

    def _forbidden_verify(**kwargs):
        raise AssertionError("real verifier must not run in fixtures")

    verifier_mod.verify_and_assemble = _forbidden_verify
    protocol_mod = types.ModuleType("signer_protocol_io")
    protocol_mod.read_secret_frame = read_frame
    protocol_mod.ProtocolStreams = None
    isolation_mod = types.ModuleType("signing_linux_isolation")
    isolation_mod.prove_linux_isolation = lambda: None
    gate_mod = types.ModuleType("signing_network_gate")
    gate_mod.SourceBinding = FakeSourceBinding
    gate_mod.encode_message = lambda kind, binding, nonce, worker_pid: b"ready\n"

    def worker_acknowledgement(line, binding, nonce, prove, worker_pid):
        prove()
        return b"ack\n"

    gate_mod.worker_acknowledgement = worker_acknowledgement
    return {
        "protected_signing_runtime": runtime_mod,
        "public_repository_files": files or _files_module(),
        "public_repository_verifier": verifier_mod,
        "signer_protocol_io": protocol_mod,
        "signing_linux_isolation": isolation_mod,
        "signing_network_gate": gate_mod,
    }


def _passing_verifier(**kwargs):
    return {"status": "pass", "native_crypto_verified": False, "signed_store_records": 1}


class _WorkerFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="tf-post-frame-diag-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "p" / "keys").mkdir(parents=True)
        (self.tmp / "p" / "keys" / "knowledge-forge-ai-packages.asc").write_bytes(b"SYNTHETIC PUBLIC KEY\n")
        (self.tmp / "r").mkdir()
        (self.tmp / "export").mkdir()
        (self.tmp / "home").mkdir()
        self.config = sw.WorkerConfig(
            p_root=self.tmp / "p", r_root=self.tmp / "r", workspace_root=self.tmp / "ws",
            export_root=self.tmp / "export", p_commit="c" * 40, p_tree="d" * 40, r_commit="e" * 40, r_tree="f" * 40,
            source_closure_sha256="a" * 64, rs9_run=1, challenge_nonce="n" * 64,
            expected_gpg_sha256="b" * 64, expected_rpm_sha256="c" * 64, release_date="2026-10-30",
            require_native_signing=False,
        )
        self.dirs = {
            "home": self.tmp / "home", "collection": self.tmp / "collection", "stage": self.tmp / "stage",
            "lease_dest": self.tmp / "lease", "signing_output": self.tmp / "signed-output",
            "public_work": self.tmp / "public-work", "public_deploy": self.tmp / "public-deploy",
        }
        self._saved_custodies = list(sw._RETAINED_WORKER_CUSTODIES)
        self.addCleanup(self._restore_custodies)

    def _restore_custodies(self) -> None:
        sw._RETAINED_WORKER_CUSTODIES[:] = self._saved_custodies

    def _frame_reader(self, frame_error: BaseException | None = None):
        buffers = {"key": bytearray(KEY_CANARY), "phrase": bytearray(PHRASE_CANARY)}

        def read_frame(streams, error_cls):
            if frame_error is not None:
                raise frame_error
            return buffers["key"], buffers["phrase"]

        return read_frame, buffers

    def _sign(self, *, frame_error=None, runtime=None, verifier=None, files=None, overrides=None, track=True):
        read_frame, buffers = self._frame_reader(frame_error)
        lease, rt = FakeLease(), runtime or FakeRuntime()
        hooks = sw.WorkerHooks(runtime_factory=lambda: rt, public_verifier=verifier or _passing_verifier)
        modules = _worker_modules(read_frame, files=files)
        modules.update(overrides or {})
        tracker = sw._PostFramePhase() if track else None
        result = error = None
        with mock.patch.dict(sys.modules, modules), mock.patch.object(sw, "_require_serial_preconditions"):
            try:
                result = sw._sign_and_verify_public(
                    self.config, self.dirs, (lease, types.SimpleNamespace(members={})), None, hooks,
                    worker_pid=os.getpid(), phase=tracker,
                )
            except Exception as caught:  # noqa: BLE001 - fixture captures the exact raised object
                error = caught
        return types.SimpleNamespace(
            result=result, error=error, tracker=tracker, buffers=buffers, lease=lease, runtime=rt,
        )

    def _flow(self, *, frame_error=None, runtime=None, verifier=None, files=None, overrides=None,
              collect_error=None, receipt_error=None):
        read_frame, buffers = self._frame_reader(frame_error)
        lease, rt = FakeLease(), runtime or FakeRuntime()
        streams = FakeStreams()
        hooks = sw.WorkerHooks(
            streams=streams, isolation_prover=lambda: None, runtime_factory=lambda: rt,
            public_verifier=verifier or _passing_verifier,
        )
        modules = _worker_modules(read_frame, files=files)
        modules.update(overrides or {})
        collect = mock.Mock(side_effect=collect_error) if collect_error is not None else mock.Mock(
            return_value=(lease, types.SimpleNamespace(members={}), os.getpid()))
        patches = [
            mock.patch.dict(sys.modules, modules),
            mock.patch.object(sw, "_check_online_env", return_value=False),
            mock.patch.object(sw, "_authenticate_worker_sources",
                              return_value={"descriptor": {}, "descriptor_sha256": "a" * 64}),
            mock.patch.object(sw, "_prepare_workspace_dirs", return_value=self.dirs),
            mock.patch.object(sw, "_collect_and_snapshot", collect),
            mock.patch.object(sw, "_strip_online_tokens_and_require_clean"),
            mock.patch.object(sw, "_require_serial_preconditions"),
        ]
        if receipt_error is not None:
            patches.append(mock.patch.object(sw, "_write_worker_receipt", side_effect=receipt_error))
        result = error = None
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            try:
                result = sw.execute_worker_flow(self.config, hooks=hooks)
            except Exception as caught:  # noqa: BLE001
                error = caught
        return types.SimpleNamespace(
            result=result, error=error, buffers=buffers, lease=lease, runtime=rt, streams=streams,
        )


def _run_worker_main(error: BaseException) -> tuple[int, str]:
    buf = io.StringIO()
    with mock.patch.object(sw, "execute_worker_flow", side_effect=error), contextlib.redirect_stderr(buf):
        rc = sw.main(list(WORKER_ARGV))
    return rc, buf.getvalue()


# --------------------------------------------------------------------------------------------
# Worker: step tracker at the actual changed boundaries
# --------------------------------------------------------------------------------------------

class WorkerStepBoundaryTests(_WorkerFixture):
    def test_private_module_import_failure_is_generic_import_label(self):
        out = self._sign(overrides={"protected_signing_runtime": None})
        self.assertIsInstance(out.error, ImportError)
        diag = sw._post_frame_diagnostic(out.tracker, out.error)
        self.assertEqual(diag, {
            "schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "PRIVATE_MODULE_IMPORT", "code": "PYTHON_MODULE_NOT_FOUND",
        })

    def test_frame_read_refusal_code(self):
        for code in ("STDIN_FRAME_NUL", "STDIN_FRAME_BOUNDS", "STDIN_FRAME_TRUNCATED", "STDIN_FRAME_FORMAT"):
            with self.subTest(code=code):
                out = self._sign(frame_error=sw.WorkerError(code, TEXT_CANARY))
                diag = sw._post_frame_diagnostic(out.tracker, out.error)
                expected = "STDIN_FRAME_FORMAT" if code == "STDIN_FRAME_FORMAT" else "UNCLASSIFIED"
                self.assertEqual((diag["step"], diag["code"]), ("FRAME_READ", expected))
                _assert_no_canary(self, json.dumps(diag))

    def test_signing_runtime_coded_failure_preserves_zeroization_and_runtime_attr(self):
        class RuntimeRefusal(RuntimeError):
            def __init__(self) -> None:
                self.code = "GPG_TIMEOUT"
                super().__init__(f"GPG_TIMEOUT: {PATH_CANARY}")

        runtime = FakeRuntime(raise_error=RuntimeRefusal())
        out = self._sign(runtime=runtime)
        self.assertIs(out.error.runtime, runtime)
        self.assertIs(runtime.seen_key, out.buffers["key"])
        self.assertEqual(bytes(out.buffers["key"]), bytes(len(KEY_CANARY)))
        self.assertEqual(bytes(out.buffers["phrase"]), bytes(len(PHRASE_CANARY)))
        diag = sw._post_frame_diagnostic(out.tracker, out.error)
        self.assertEqual((diag["step"], diag["code"]), ("SIGNING_RUNTIME", "GPG_TIMEOUT"))
        _assert_no_canary(self, json.dumps(diag))

    def test_signing_runtime_generic_exception_fallback(self):
        out = self._sign(runtime=FakeRuntime(raise_error=ValueError(f"{PATH_CANARY} {KEY_CANARY!r}")))
        self.assertEqual(bytes(out.buffers["key"]), bytes(len(KEY_CANARY)))
        diag = sw._post_frame_diagnostic(out.tracker, out.error)
        self.assertEqual((diag["step"], diag["code"]), ("SIGNING_RUNTIME", "PYTHON_VALUE_ERROR"))
        _assert_no_canary(self, json.dumps(diag))

    def test_key_specific_refusal_code_is_not_exposed(self):
        class KeyRefusal(RuntimeError):
            code = "PRIVATE_KEY_REJECTED"

        out = self._sign(runtime=FakeRuntime(raise_error=KeyRefusal("x")))
        diag = sw._post_frame_diagnostic(out.tracker, out.error)
        self.assertEqual((diag["step"], diag["code"]), ("SIGNING_RUNTIME", "UNCLASSIFIED"))

    def test_custody_check_cleanup_unconfirmed(self):
        runtime = FakeRuntime(retained=object())
        out = self._sign(runtime=runtime)
        self.assertEqual(out.error.code, "PRIVATE_CLEANUP_UNCONFIRMED")
        self.assertIs(out.error.runtime, runtime)
        diag = sw._post_frame_diagnostic(out.tracker, out.error)
        self.assertEqual((diag["step"], diag["code"]), ("CUSTODY_CHECK", "PRIVATE_CLEANUP_UNCONFIRMED"))

    def test_public_verification_refusal(self):
        out = self._sign(verifier=lambda **kw: {"status": "fail", "native_crypto_verified": False})
        diag = sw._post_frame_diagnostic(out.tracker, out.error)
        self.assertEqual((diag["step"], diag["code"]), ("PUBLIC_VERIFICATION", "PUBLIC_VERIFICATION_FAILED"))

    def test_public_export_generic_exception(self):
        out = self._sign(files=_files_module(write_error=KeyError(PATH_CANARY)))
        diag = sw._post_frame_diagnostic(out.tracker, out.error)
        self.assertEqual((diag["step"], diag["code"]), ("PUBLIC_EXPORT", "PYTHON_KEY_ERROR"))
        _assert_no_canary(self, json.dumps(diag))

    def test_success_unchanged_with_and_without_tracker(self):
        tracked = self._sign()
        self.assertIsNone(tracked.error)
        self.assertEqual(len(tracked.result), 4)
        self.assertEqual(tracked.tracker.step, "PUBLIC_EXPORT")
        shutil.rmtree(self.tmp / "export" / "public-repository")
        untracked = self._sign(track=False)
        self.assertIsNone(untracked.error)
        self.assertEqual(len(untracked.result), 4)


class WorkerClassificationTests(unittest.TestCase):
    def test_closed_vocabulary_and_fallbacks(self):
        self.assertEqual(sw._classify_post_frame_error(sw.WorkerError("EXPORT_INVENTORY_MISMATCH", "m")),
                         "EXPORT_INVENTORY_MISMATCH")
        self.assertEqual(sw._classify_post_frame_error(sw.WorkerError("SYNTHETIC_UNLISTED_CODE", "m")), "UNCLASSIFIED")
        self.assertEqual(sw._classify_post_frame_error(ImportError(PATH_CANARY)), "PYTHON_IMPORT_ERROR")
        self.assertEqual(sw._classify_post_frame_error(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "x")),
                         "PYTHON_UNICODE_ERROR")
        self.assertEqual(sw._classify_post_frame_error(FileNotFoundError(2, "x", PATH_CANARY)), "PYTHON_FILE_NOT_FOUND")
        self.assertEqual(sw._classify_post_frame_error(RecursionError()), "PYTHON_RECURSION_ERROR")
        self.assertEqual(sw._classify_post_frame_error(TypeError("not JSON serializable")), "PYTHON_TYPE_ERROR")

        class Custom(Exception):
            pass

        self.assertEqual(sw._classify_post_frame_error(Custom(TEXT_CANARY)), "UNCLASSIFIED")

        class IntCode(OSError):
            code = 404

        self.assertEqual(sw._classify_post_frame_error(IntCode()), "PYTHON_OS_ERROR")

        class StrSubclassCode(Exception):
            code = type("S", (str,), {})("GPG_TIMEOUT")

        self.assertEqual(sw._classify_post_frame_error(StrSubclassCode()), "UNCLASSIFIED")

        class HostileCode(Exception):
            @property
            def code(self):
                raise RuntimeError(TEXT_CANARY)

        self.assertEqual(sw._classify_post_frame_error(HostileCode()), "UNCLASSIFIED")

    def test_tracker_marks_only_listed_steps(self):
        tracker = sw._PostFramePhase()
        self.assertEqual(tracker.step, "PRIVATE_PHASE_ENTERED")
        sw._mark_post_frame_step(tracker, "RECEIPT")
        self.assertEqual(tracker.step, "RECEIPT")
        sw._mark_post_frame_step(tracker, PATH_CANARY)
        self.assertEqual(tracker.step, "UNAVAILABLE")
        sw._mark_post_frame_step(None, "RECEIPT")
        with self.assertRaises(AttributeError):
            tracker.extra = TEXT_CANARY  # type: ignore[attr-defined]

    def test_no_shared_module_level_tracker(self):
        self.assertFalse(any(isinstance(value, sw._PostFramePhase) for value in vars(sw).values()))

    def test_closed_revalidation(self):
        fallback = {"schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "UNAVAILABLE", "code": "UNCLASSIFIED"}
        good = {"schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "RECEIPT", "code": "PYTHON_TYPE_ERROR"}
        self.assertEqual(sw._closed_post_frame_diagnostic(good), good)
        for bad in (
            None, "RECEIPT", [good], dict(good, extra=TEXT_CANARY), dict(good, step=PATH_CANARY),
            dict(good, code="SYNTHETIC_UNLISTED"), dict(good, schema="other"), dict(good, code=1),
            {k: v for k, v in good.items() if k != "code"},
        ):
            self.assertEqual(sw._closed_post_frame_diagnostic(bad), fallback)


# --------------------------------------------------------------------------------------------
# Worker: execute_worker_flow and main serialization
# --------------------------------------------------------------------------------------------

class WorkerFlowTests(_WorkerFixture):
    def test_success_receipt_schema_unchanged(self):
        out = self._flow()
        self.assertIsNone(out.error)
        self.assertEqual(set(out.result), WORKER_RECEIPT_KEYS)
        self.assertNotIn("post_frame_diagnostic", json.dumps(out.result))
        on_disk = json.loads((self.tmp / "export" / "outer-controller-receipt.json").read_text())
        self.assertEqual(on_disk, out.result)
        self.assertEqual(out.streams.written, [b"ready\n", b"ack\n"])

    def test_pre_frame_failure_has_no_diagnostic(self):
        out = self._flow(collect_error=sw.WorkerError("STAGE_ROUTING_MISMATCH", TEXT_CANARY))
        self.assertIs(out.error.private_phase_entered, False)
        self.assertFalse(hasattr(out.error, "post_frame_diagnostic"))
        rc, text = _run_worker_main(out.error)
        doc = json.loads(text)
        self.assertEqual(rc, 2)
        self.assertEqual(set(doc), WORKER_FAILED_BASE_KEYS)
        self.assertEqual(doc["error_code"], "STAGE_ROUTING_MISMATCH")

    def test_import_failure_attaches_diagnostic_and_preserves_lease_cleanup(self):
        out = self._flow(overrides={"protected_signing_runtime": None})
        self.assertIsInstance(out.error, ImportError)
        self.assertIs(out.error.private_phase_entered, True)
        self.assertEqual(out.lease.close_calls, 1)
        self.assertEqual(sw._RETAINED_WORKER_CUSTODIES, self._saved_custodies)
        self.assertEqual(out.error.post_frame_diagnostic, {
            "schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "PRIVATE_MODULE_IMPORT", "code": "PYTHON_MODULE_NOT_FOUND",
        })

    def test_runtime_failure_preserves_retention_and_zeroization(self):
        runtime = FakeRuntime(raise_error=RuntimeError(TEXT_CANARY))
        out = self._flow(runtime=runtime)
        self.assertEqual(bytes(out.buffers["key"]), bytes(len(KEY_CANARY)))
        self.assertEqual(bytes(out.buffers["phrase"]), bytes(len(PHRASE_CANARY)))
        self.assertEqual(len(sw._RETAINED_WORKER_CUSTODIES), len(self._saved_custodies) + 1)
        self.assertIs(sw._RETAINED_WORKER_CUSTODIES[-1]["error"], out.error)
        self.assertEqual(out.lease.close_calls, 0)
        self.assertEqual((out.error.post_frame_diagnostic["step"], out.error.post_frame_diagnostic["code"]),
                         ("SIGNING_RUNTIME", "PYTHON_RUNTIME_ERROR"))
        rc, text = _run_worker_main(out.error)
        doc = json.loads(text)
        self.assertEqual(doc["custody_retained"], True)
        self.assertEqual(doc["error_code"], "WITHHELD_POST_FRAME")
        _assert_no_canary(self, text)

    def test_receipt_serialization_failure_is_classified(self):
        out = self._flow(receipt_error=TypeError(f"Object of type {TEXT_CANARY} is not JSON serializable"))
        self.assertEqual(out.error.post_frame_diagnostic, {
            "schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "RECEIPT", "code": "PYTHON_TYPE_ERROR",
        })

    def test_independent_trackers_per_invocation(self):
        first = self._flow(frame_error=sw.WorkerError("STDIN_FRAME_NUL", "m"))
        second = self._flow(verifier=lambda **kw: {"status": "fail"})
        self.assertEqual(first.error.post_frame_diagnostic["step"], "FRAME_READ")
        self.assertEqual(second.error.post_frame_diagnostic["step"], "PUBLIC_VERIFICATION")


class WorkerMainTests(unittest.TestCase):
    def setUp(self) -> None:
        saved = list(sw._RETAINED_WORKER_CUSTODIES)
        sw._RETAINED_WORKER_CUSTODIES[:] = []
        self.addCleanup(lambda: sw._RETAINED_WORKER_CUSTODIES.__setitem__(slice(None), saved))

    def test_post_frame_record_withholds_code_detail_and_text(self):
        error = sw.WorkerError("PUBLIC_VERIFICATION_FAILED", f"{TEXT_CANARY} {PATH_CANARY}")
        error.private_phase_entered = True
        error.detail = "UDP_V4_SOCKET"
        error.post_frame_diagnostic = {
            "schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "PUBLIC_VERIFICATION", "code": "PUBLIC_VERIFICATION_FAILED",
        }
        rc, text = _run_worker_main(error)
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(text), {
            "schema": WORKER_RECEIPT_SCHEMA, "status": "failed-closed", "error_code": "WITHHELD_POST_FRAME",
            "custody_retained": False, "publication_authority": False, "native_client_qualification": False,
            "post_frame_diagnostic": {
                "schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "PUBLIC_VERIFICATION",
                "code": "PUBLIC_VERIFICATION_FAILED",
            },
        })
        self.assertEqual(text.count("\n"), 1)
        _assert_no_canary(self, text)
        view = hc._parse_untrusted_post_frame_worker_stderr(text.encode("ascii"))
        self.assertEqual(view, {
            "schema": hc.POST_FRAME_DIAGNOSTIC_SCHEMA, "record": "VALID", "step": "PUBLIC_VERIFICATION",
            "code": "PUBLIC_VERIFICATION_FAILED", "untrusted_worker_claim": True,
        })

    def test_post_frame_args_code_is_not_serialized(self):
        error = RuntimeError("SYNTHETIC_ARGS_CODE_CANARY")
        error.private_phase_entered = True
        rc, text = _run_worker_main(error)
        doc = json.loads(text)
        self.assertEqual(doc["error_code"], "WITHHELD_POST_FRAME")
        self.assertEqual(doc["post_frame_diagnostic"]["step"], "UNAVAILABLE")
        self.assertEqual(doc["post_frame_diagnostic"]["code"], "UNCLASSIFIED")
        _assert_no_canary(self, text)

    def test_post_frame_tampered_claim_becomes_unavailable(self):
        error = ValueError(TEXT_CANARY)
        error.private_phase_entered = True
        error.post_frame_diagnostic = {"schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": PATH_CANARY, "code": TEXT_CANARY}
        _rc, text = _run_worker_main(error)
        doc = json.loads(text)
        self.assertEqual(doc["post_frame_diagnostic"], {
            "schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "UNAVAILABLE", "code": "UNCLASSIFIED",
        })
        _assert_no_canary(self, text)
        self.assertEqual(hc._parse_untrusted_post_frame_worker_stderr(text.encode("ascii"))["record"], "VALID")

    def test_pre_frame_record_unchanged(self):
        error = sw.WorkerError("ISOLATION_SOCKET_PRESENT", TEXT_CANARY)
        error.private_phase_entered = False
        error.detail = "UDP_V4_SOCKET"
        error.post_frame_diagnostic = {"schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "RECEIPT", "code": "UNCLASSIFIED"}
        _rc, text = _run_worker_main(error)
        self.assertEqual(json.loads(text), {
            "schema": WORKER_RECEIPT_SCHEMA, "status": "failed-closed", "error_code": "ISOLATION_SOCKET_PRESENT",
            "custody_retained": False, "publication_authority": False, "native_client_qualification": False,
            "error_detail": "UDP_V4_SOCKET",
        })
        self.assertEqual(hc._parse_untrusted_pre_frame_worker_stderr(text.encode("ascii")),
                         ("ISOLATION_SOCKET_PRESENT", "UDP_V4_SOCKET"))

    def test_pre_frame_args_code_fallback_unchanged(self):
        _rc, text = _run_worker_main(RuntimeError("SOME_FIXED_CODE"))
        doc = json.loads(text)
        self.assertEqual(set(doc), WORKER_FAILED_BASE_KEYS)
        self.assertEqual(doc["error_code"], "SOME_FIXED_CODE")


# --------------------------------------------------------------------------------------------
# Host: untrusted record validation
# --------------------------------------------------------------------------------------------

def _worker_record(**overrides) -> dict:
    doc = {
        "schema": WORKER_RECEIPT_SCHEMA, "status": "failed-closed", "error_code": "WITHHELD_POST_FRAME",
        "custody_retained": False, "publication_authority": False, "native_client_qualification": False,
        "post_frame_diagnostic": {
            "schema": sw.POST_FRAME_DIAGNOSTIC_SCHEMA, "step": "SIGNING_RUNTIME", "code": "PYTHON_IMPORT_ERROR",
        },
    }
    doc.update(overrides)
    return doc


def _line(doc: dict) -> bytes:
    return (json.dumps(doc, sort_keys=True) + "\n").encode("ascii")


def _unavailable(record: str) -> dict:
    return {
        "schema": hc.POST_FRAME_DIAGNOSTIC_SCHEMA, "record": record, "step": "UNAVAILABLE", "code": "UNCLASSIFIED",
        "untrusted_worker_claim": True,
    }


class HostRecordParserTests(unittest.TestCase):
    parse = staticmethod(hc._parse_untrusted_post_frame_worker_stderr)

    def test_valid_record(self):
        self.assertEqual(self.parse(_line(_worker_record())), {
            "schema": hc.POST_FRAME_DIAGNOSTIC_SCHEMA, "record": "VALID", "step": "SIGNING_RUNTIME",
            "code": "PYTHON_IMPORT_ERROR", "untrusted_worker_claim": True,
        })

    def test_absent_and_framing_failures(self):
        good = _line(_worker_record())
        self.assertEqual(self.parse(b""), _unavailable("ABSENT"))
        for raw in (
            good + good,
            good + f"{TEXT_CANARY}\n".encode(),
            b" " * 5000 + good,
            good.replace(b"\n", b"\r\n"),
            good[:-1] + b"\x00\n",
            good[:-1] + "é".encode("utf-8") + b"\n",
            b"\n\n",
        ):
            self.assertEqual(self.parse(raw), _unavailable("NOT_SINGLE_RECORD"))
        self.assertEqual(self.parse(bytearray(good)), _unavailable("NOT_SINGLE_RECORD"))

    def test_invalid_records(self):
        diag = _worker_record()["post_frame_diagnostic"]
        duplicate = b'{"status": "failed-closed", ' + _line(_worker_record())[1:]
        cases = [
            duplicate,
            b"{not json}\n",
            b"CURRENT_SIGNER_MODE_REQUIRED\n",
            b"[]\n",
            _line(_worker_record(extra=f"{TEXT_CANARY} {PATH_CANARY}")),
            _line({k: v for k, v in _worker_record().items() if k != "custody_retained"}),
            _line(_worker_record(error_code="PUBLIC_VERIFICATION_FAILED")),
            _line(_worker_record(status="pass")),
            _line(_worker_record(schema="other")),
            _line(_worker_record(custody_retained=0)),
            _line(_worker_record(publication_authority=0)),
            _line(_worker_record(native_client_qualification=None)),
            _line(_worker_record(post_frame_diagnostic=None)),
            _line(_worker_record(post_frame_diagnostic=dict(diag, extra=TEXT_CANARY))),
            _line(_worker_record(post_frame_diagnostic=dict(diag, schema="other"))),
            _line(_worker_record(post_frame_diagnostic=dict(diag, step="signing_runtime"))),
            _line(_worker_record(post_frame_diagnostic=dict(diag, step=PATH_CANARY))),
            _line(_worker_record(post_frame_diagnostic=dict(diag, code="SYNTHETIC_UNLISTED_CODE"))),
            _line(_worker_record(post_frame_diagnostic=dict(diag, code="PRIVATE_KEY_REJECTED"))),
            _line(_worker_record(post_frame_diagnostic=dict(diag, code=7))),
        ]
        for raw in cases:
            view = self.parse(raw)
            self.assertEqual(view, _unavailable("INVALID_RECORD"), raw)
            _assert_no_canary(self, json.dumps(view))

    def test_sanitize(self):
        valid = self.parse(_line(_worker_record()))
        self.assertEqual(hc.sanitize_post_frame_diagnostic(valid), valid)
        self.assertEqual(hc.sanitize_post_frame_diagnostic(_unavailable("ABSENT")), _unavailable("ABSENT"))
        for bad in (
            None, [], dict(valid, untrusted_worker_claim=False), dict(valid, extra=1),
            dict(valid, record="UNKNOWN"), dict(valid, code=TEXT_CANARY), dict(valid, step=PATH_CANARY),
            dict(_unavailable("INVALID_RECORD"), step="RECEIPT"), dict(valid, schema="other"),
        ):
            self.assertIsNone(hc.sanitize_post_frame_diagnostic(bad))


# --------------------------------------------------------------------------------------------
# Host: builder and controller integration with fakes
# --------------------------------------------------------------------------------------------

class FakeGate:
    def __init__(self, binding=None, nonce=None, *, frame_emitted=False, failed_phase=None, state="waiting-ready"):
        self.frame_emitted = frame_emitted
        self.failed_phase = failed_phase
        self.state = state
        self.worker_pid = 4242


class FakeSelector:
    def __init__(self) -> None:
        self.calls = 0

    def get_map(self):
        self.calls += 1
        return {}


def _session_class(exit_code: int, stderr: bytes):
    class FakeSession:
        instances: list = []

        def __init__(self, proc, deadline, error_cls) -> None:
            self.deadline = time.monotonic() + 60.0
            self.selector = FakeSelector()
            self.stderr_buf = bytearray(stderr)
            self.cleanup_uncertain = False
            FakeSession.instances.append(self)

        def _pump_once(self, timeout: float) -> None:
            raise AssertionError("no pumping expected with an empty selector map")

        def wait_for_exit(self) -> int:
            return exit_code

        def require_stdout_clean_eof(self) -> None:
            return None

        def terminate_and_close(self) -> None:
            return None

    return FakeSession


def _good_teardown() -> dict:
    return {
        "owner_custody": "resolved", "container_absence_confirmed": True, "builtin_bridge_preserved": True,
        "owned_bridge_endpoint_absent_confirmed": True, "session_cleanup_uncertain": False,
        "spawn_outcome_uncertain": False, "unexpected_bridge_peer_observed": False,
        "container_force_remove_attempted": False, "container_force_removed": False,
    }


class HostBuilderTests(unittest.TestCase):
    def _session(self, raw: bytes):
        return _session_class(2, raw)(None, 0.0, hc.HostControllerError)

    def test_post_frame_nonzero_exit_parses_record(self):
        session = self._session(_line(_worker_record()))
        gate = FakeGate(frame_emitted=True, state="frame-closed")
        diag = hc._build_post_frame_diagnostic(gate, session, hc.HostControllerError("WORKER_NONZERO_EXIT", "x"))
        self.assertEqual(diag["record"], "VALID")
        self.assertEqual((diag["step"], diag["code"]), ("SIGNING_RUNTIME", "PYTHON_IMPORT_ERROR"))
        self.assertEqual(session.selector.calls, 1)
        self.assertIs(gate.frame_emitted, True)
        self.assertEqual(gate.state, "frame-closed")

    def test_not_applied_before_post_frame_or_for_other_errors(self):
        for gate, error in (
            (FakeGate(frame_emitted=False, state="checking-isolation"), hc.HostControllerError("WORKER_NONZERO_EXIT", "x")),
            (FakeGate(frame_emitted=True, failed_phase="emitting-frame"), hc.HostControllerError("WORKER_NONZERO_EXIT", "x")),
            (FakeGate(frame_emitted=True, state="frame-closed"), hc.HostControllerError("PROTOCOL_EXTRA_STDOUT", "x")),
            (FakeGate(frame_emitted=True, state="frame-closed"), RuntimeError("WORKER_NONZERO_EXIT")),
        ):
            session = self._session(_line(_worker_record()))
            self.assertIsNone(hc._build_post_frame_diagnostic(gate, session, error))
            self.assertEqual(session.selector.calls, 0)

    def test_existing_handshake_fields_remain_withheld(self):
        session = self._session(_line(_worker_record()))
        gate = FakeGate(frame_emitted=True, state="frame-closed")
        observation = hc._build_handshake_observation(gate, session, hc.HostControllerError("WORKER_NONZERO_EXIT", "x"))
        self.assertEqual(observation["gate_phase"], "POST_FRAME")
        self.assertEqual(observation["worker_error_code"], "WITHHELD_POST_FRAME")
        self.assertEqual(observation["worker_error_detail"], "WITHHELD_POST_FRAME")
        self.assertEqual(session.selector.calls, 0)


class HostControllerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        saved = list(hc._RETAINED_HOST_SESSIONS)
        self.addCleanup(lambda: hc._RETAINED_HOST_SESSIONS.__setitem__(slice(None), saved))
        self.saved_sessions = saved
        self.config = hc.HostControllerConfig(
            p_root=Path("/p"), r_root=Path("/r"), export_root=Path("/e"), p_commit="c", p_tree="t",
            r_commit="c", r_tree="t", source_closure_sha256="s", rs9_run=1, challenge_nonce="n",
            run_id_suffix="1", container_image="i", container_python="/py", expected_gpg_sha256="g",
            expected_rpm_sha256="r", release_date="d", pass_online_github_token=False,
        )
        self.hooks = hc.HostControllerHooks(
            docker_cmd_runner=lambda argv, timeout: (0, b"", b""),
            worker_spawner=lambda argv, env: object(), frame_emitter=lambda: bytearray(),
        )

    def _run(self, *, exit_code: int, stderr: bytes, gate_error: BaseException | None = None):
        session_cls = _session_class(exit_code, stderr)
        protocol_mod = types.ModuleType("signer_protocol_io")
        protocol_mod.ForegroundContainerSession = session_cls
        gate_mod = types.ModuleType("signing_network_gate")
        gate_mod.HostGate = FakeGate
        gate_mod.SourceBinding = FakeSourceBinding
        gate_mod.default_bridge_owner_label = lambda suffix, nonce: "0" * 64

        def fake_gate_session(gate, session, gate_cmds, runner, emitter, *, prepare_disconnect=None):
            if gate_error is not None:
                gate.failed_phase = "checking-ready"
                raise gate_error
            gate.frame_emitted, gate.state = True, "frame-closed"
            return "frame-closed"

        teardown_calls: list = []

        def fake_teardown(session, *args, **kwargs):
            teardown_calls.append(session)
            return _good_teardown(), None

        patches = [
            mock.patch.dict(sys.modules, {"signer_protocol_io": protocol_mod, "signing_network_gate": gate_mod}),
            mock.patch.object(hc, "_authenticate_host_sources", return_value=(Path("/p"), Path("/r"), Path("/e"), {})),
            mock.patch.object(hc, "build_default_bridge_run_argv", return_value=("/usr/bin/docker", "run")),
            mock.patch.object(hc, "_default_bridge_preflight", return_value="b" * 64),
            mock.patch.object(hc, "scoped_git_env", return_value={}),
            mock.patch.object(hc, "_run_gate_session", side_effect=fake_gate_session),
            mock.patch.object(hc, "_teardown_default_bridge_session", side_effect=fake_teardown),
            mock.patch.object(hc, "_frame_custody_retained", return_value=False),
            mock.patch.object(hc, "_verify_exported_artifacts",
                              return_value={"c6_agent_and_private_work_cleanup_confirmed": True}),
        ]
        result = error = None
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            try:
                result = hc.execute_host_controller(self.config, hooks=self.hooks)
            except Exception as caught:  # noqa: BLE001
                error = caught
        return types.SimpleNamespace(result=result, error=error, sessions=session_cls.instances, teardown=teardown_calls)

    @staticmethod
    def _host_main(error: BaseException) -> tuple[int, str]:
        buf = io.StringIO()
        with mock.patch.object(hc, "execute_host_controller", side_effect=error), \
                mock.patch.object(hc, "_frame_custody_retained", return_value=False), \
                contextlib.redirect_stderr(buf):
            rc = hc.main(list(HOST_ARGV))
        return rc, buf.getvalue()

    def test_post_frame_failure_exposes_only_closed_diagnostic(self):
        out = self._run(exit_code=2, stderr=_line(_worker_record()))
        self.assertIsInstance(out.error, hc.HostControllerError)
        self.assertEqual(out.error.code, "WORKER_NONZERO_EXIT")
        self.assertEqual(out.teardown, out.sessions)
        self.assertEqual(out.error.host_teardown["frame_capture_custody_retained"], False)
        self.assertEqual(hc._RETAINED_HOST_SESSIONS, self.saved_sessions)
        self.assertEqual(out.error.handshake_observation["worker_error_code"], "WITHHELD_POST_FRAME")
        self.assertEqual(out.error.post_frame_diagnostic["record"], "VALID")
        rc, text = self._host_main(out.error)
        doc = json.loads(text)
        self.assertEqual(rc, 2)
        self.assertEqual(set(doc), {
            "schema", "status", "error_code", "custody_retained", "host_container_and_network_teardown",
            "publication_authority", "native_client_qualification", "handshake_observation", "post_frame_diagnostic",
        })
        self.assertEqual(doc["error_code"], "WORKER_NONZERO_EXIT")
        self.assertEqual(doc["status"], "failed-closed")
        self.assertEqual(doc["handshake_observation"]["worker_error_detail"], "WITHHELD_POST_FRAME")
        self.assertEqual(doc["post_frame_diagnostic"], {
            "schema": hc.POST_FRAME_DIAGNOSTIC_SCHEMA, "record": "VALID", "step": "SIGNING_RUNTIME",
            "code": "PYTHON_IMPORT_ERROR", "untrusted_worker_claim": True,
        })

    def test_untrusted_garbage_cannot_alter_error_or_teardown(self):
        raw = f"Traceback {TEXT_CANARY} {PATH_CANARY}\n".encode() + _line(_worker_record())
        out = self._run(exit_code=2, stderr=raw)
        self.assertEqual(out.error.code, "WORKER_NONZERO_EXIT")
        self.assertEqual(out.teardown, out.sessions)
        self.assertEqual(hc._RETAINED_HOST_SESSIONS, self.saved_sessions)
        self.assertEqual(out.error.post_frame_diagnostic, _unavailable("NOT_SINGLE_RECORD"))
        _rc, text = self._host_main(out.error)
        self.assertEqual(json.loads(text)["post_frame_diagnostic"], _unavailable("NOT_SINGLE_RECORD"))
        _assert_no_canary(self, text)

    def test_pre_frame_failure_has_no_post_frame_output(self):
        out = self._run(exit_code=2, stderr=_line(_worker_record()),
                        gate_error=hc.HostControllerError("MESSAGE_FORMAT", "x"))
        self.assertEqual(out.error.code, "MESSAGE_FORMAT")
        self.assertIsNone(out.error.post_frame_diagnostic)
        _rc, text = self._host_main(out.error)
        doc = json.loads(text)
        self.assertNotIn("post_frame_diagnostic", doc)
        self.assertEqual(doc["handshake_observation"]["worker_error_code"], "UNRECOGNIZED_STDERR_FORMAT")

    def test_success_summary_unchanged(self):
        out = self._run(exit_code=0, stderr=_line(_worker_record()))
        self.assertIsNone(out.error)
        self.assertEqual(set(out.result), HOST_SUCCESS_KEYS)
        self.assertEqual(out.result["status"], "pass")

    def test_host_main_requires_post_frame_and_nonzero_exit(self):
        valid = hc._parse_untrusted_post_frame_worker_stderr(_line(_worker_record()))
        post_obs = {"gate_phase": "POST_FRAME", "framing_reason": "NONE",
                    "worker_error_code": "WITHHELD_POST_FRAME", "worker_error_detail": "WITHHELD_POST_FRAME"}
        pre_obs = {"gate_phase": "CHECKING_READY", "framing_reason": "NONE",
                   "worker_error_code": "NONE", "worker_error_detail": "NONE"}
        for code, obs, diag, expected in (
            ("WORKER_NONZERO_EXIT", post_obs, valid, True),
            ("WORKER_RECEIPT_INVALID", post_obs, valid, False),
            ("WORKER_NONZERO_EXIT", pre_obs, valid, False),
            ("WORKER_NONZERO_EXIT", None, valid, False),
            ("WORKER_NONZERO_EXIT", post_obs, dict(valid, code=TEXT_CANARY), False),
        ):
            error = hc.HostControllerError(code, "x")
            error.handshake_observation = obs
            error.post_frame_diagnostic = diag
            _rc, text = self._host_main(error)
            self.assertEqual("post_frame_diagnostic" in json.loads(text), expected, (code, obs))
            _assert_no_canary(self, text)


# --------------------------------------------------------------------------------------------
# Source-level vocabulary and boundary checks
# --------------------------------------------------------------------------------------------

class SourceLevelTests(unittest.TestCase):
    def test_worker_and_host_vocabularies_match_and_are_bounded(self):
        self.assertEqual(sw._POST_FRAME_STEPS, hc._POST_FRAME_WORKER_STEPS)
        self.assertEqual(sw._POST_FRAME_CODES, hc._POST_FRAME_WORKER_CODES)
        self.assertEqual(sw.POST_FRAME_DIAGNOSTIC_SCHEMA, hc._WORKER_POST_FRAME_DIAGNOSTIC_SCHEMA)
        self.assertEqual(len(sw._POST_FRAME_REFUSAL_CODES), 52)
        self.assertEqual(len(sw._POST_FRAME_CODES), 70)
        self.assertEqual(len(sw._POST_FRAME_EXCEPTION_LABELS), len({label for _c, label in sw._POST_FRAME_EXCEPTION_LABELS}))
        for label in sw._POST_FRAME_CODES | sw._POST_FRAME_STEPS | hc._POST_FRAME_RECORD_STATES:
            self.assertRegex(label, r"^[A-Z0-9_]{3,64}$")

    def test_no_key_or_passphrase_labels(self):
        for code in ("STDIN_FRAME_NUL", "STDIN_FRAME_BOUNDS", "STDIN_FRAME_TRUNCATED"):
            self.assertNotIn(code, sw._POST_FRAME_CODES)
            self.assertEqual(sw._classify_post_frame_error(sw.WorkerError(code, TEXT_CANARY)), "UNCLASSIFIED")
        for label in sw._POST_FRAME_CODES:
            self.assertFalse(label.startswith("KEY_"), label)
            for marker in ("PRIVATE_KEY", "PASSPHRASE", "PASSWORD", "SECRET", "CREDENTIAL", "TOKEN"):
                self.assertNotIn(marker, label)

    def test_refusal_codes_are_existing_source_labels(self):
        worker_text = Path(sw.__file__).read_text(encoding="utf-8")
        start = worker_text.index("_POST_FRAME_REFUSAL_CODES = frozenset({")
        worker_outside = worker_text[:start] + worker_text[worker_text.index("})", start):]
        other_text = "".join(
            (_SIGNER_DIR / name).read_text(encoding="utf-8") for name in ("signer_protocol_io.py", "source_closure.py",
                "protected_signing_runtime.py", "repository_metadata_assembly.py")
        )
        for code in sw._POST_FRAME_REFUSAL_CODES:
            self.assertTrue(
                code in hc._PRE_FRAME_WORKER_CODE_ALLOWLIST
                or f'"{code}"' in worker_outside or f'"{code}"' in other_text,
                code,
            )

    def test_exception_ordering_is_specific_first(self):
        classes = [cls for cls, _label in sw._POST_FRAME_EXCEPTION_LABELS]
        for i, earlier in enumerate(classes):
            for later in classes[i + 1:]:
                self.assertFalse(issubclass(later, earlier) and later is not earlier, (earlier, later))

    def test_classifier_never_reads_text_or_args(self):
        source = inspect.getsource(sw._classify_post_frame_error) + inspect.getsource(sw._post_frame_diagnostic)
        for forbidden in (".args", "str(", "repr(", "__name__", "__qualname__", "format(", "%"):
            self.assertNotIn(forbidden, source)
        host_source = inspect.getsource(hc._parse_untrusted_post_frame_worker_stderr)
        self.assertNotIn("re.", host_source)

    def test_marks_precede_existing_operations_without_reordering(self):
        source = inspect.getsource(sw._sign_and_verify_public)
        order = [
            '_mark_post_frame_step(phase, "PRIVATE_MODULE_IMPORT")', "import protected_signing_runtime",
            '_mark_post_frame_step(phase, "FRAME_READ")', "read_secret_frame(streams, WorkerError)",
            '_mark_post_frame_step(phase, "SIGNING_RUNTIME")', "_require_serial_preconditions(worker_pid, lease)",
            "execute_live_lease", "zero_bytes(phrase_buf)",
            '_mark_post_frame_step(phase, "CUSTODY_CHECK")', "PRIVATE_CLEANUP_UNCONFIRMED",
            '_mark_post_frame_step(phase, "PUBLIC_VERIFICATION")', "verifier_fn = ",
            '_mark_post_frame_step(phase, "PUBLIC_EXPORT")', "verified_deploy = ",
        ]
        positions = [source.index(token) for token in order]
        self.assertEqual(positions, sorted(positions))
        flow = inspect.getsource(sw.execute_worker_flow)
        self.assertLess(flow.index("private_phase_entered = True"), flow.index("phase = _PostFramePhase()"))
        self.assertLess(flow.index('_mark_post_frame_step(phase, "RECEIPT")'), flow.index("_write_worker_receipt("))
        self.assertLess(flow.index("_retain_worker_failure("), flow.index("_post_frame_diagnostic(phase, error)"))
        self.assertEqual(len(re.findall(r"_mark_post_frame_step\(", flow + source)), 8)


class ParentMalformedJSONBoundTests(unittest.TestCase):
    def test_deep_json_within_byte_bound_is_fixed_invalid_record(self):
        values = (
            b"[" * 1400 + b"0" + b"]" * 1400,
            b'{"x":' + b"[" * 1400 + b"0" + b"]" * 1400 + b"}",
        )
        for value in values:
            with self.subTest(root_object=value.startswith(b"{")):
                self.assertLessEqual(len(value), hc._MAX_POST_FRAME_RECORD_BYTES)
                self.assertEqual(hc._parse_untrusted_post_frame_worker_stderr(value),
                                 _unavailable("INVALID_RECORD"))


if __name__ == "__main__":
    unittest.main()
