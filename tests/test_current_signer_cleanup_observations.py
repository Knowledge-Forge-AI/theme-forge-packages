"""Cleanup and handshake observations: bounded output and failure preservation."""
import ast
import contextlib
import errno
import io
import json
import random
import types
import os
from pathlib import Path
import stat
import tempfile
import unittest
import sys
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/verification/current_signer"))
import runtime_workflow_bridge as bridge
import signer_host_controller as _diag_host
import signer_protocol_io as _diag_protocol

SOURCE = ROOT / "tests/fixtures/current_signer_cleanup_baseline.py"
node = next(n for n in ast.parse(SOURCE.read_text()).body
            if isinstance(n, ast.FunctionDef) and n.name == "_cleanup_owned_tree")
namespace = {"Path": Path, "os": os, "stat": stat}
exec(compile(ast.Module(body=[node], type_ignores=[]), "<original-cleanup>", "exec"), namespace)
original_cleanup = namespace["_cleanup_owned_tree"]
ALLOWED = {"transport", "quarantine", "build"}

def layout(root):
    root.mkdir()
    for name in sorted(ALLOWED):
        (root / name).mkdir()
    (root / "transport/gh-config").mkdir()
    for name in ("metadata-0001.bin", "metadata-0002.bin", "archive-0003.bin",
                 "metadata-0004.bin", "metadata-0005.bin"):
        (root / "transport" / name).write_bytes(b"public fixture")
    for index in range(30):
        (root / "quarantine" / (str(index) + ".rpm")).write_bytes(b"public rpm fixture")

def snapshot(root):
    if not root.exists():
        return None
    rows = {}
    for path in root.rglob("*"):
        info = path.lstat()
        kind = stat.S_IFMT(info.st_mode)
        rows[path.relative_to(root).as_posix()] = (
            kind, stat.S_IMODE(info.st_mode), info.st_nlink,
            path.read_bytes() if stat.S_ISREG(info.st_mode) else None,
        )
    return rows

class CleanupObservationTests(unittest.TestCase):
    def test_real_transport_shape_and_thirty_archives_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "owned"
            layout(root)
            details = []
            self.assertTrue(bridge._cleanup_owned_tree(root, ALLOWED, failure_sink=details))
            self.assertEqual(details, [])
            self.assertFalse(root.exists())

    def test_failure_decisions_and_remaining_bytes_match_original(self):
        cases = {
            "foreign_root": ("ROOT_ENTRIES", "ROOT"),
            "build_directory": ("NESTED_DIRECTORY", "BUILD"),
            "transport_directory": ("NESTED_DIRECTORY", "TRANSPORT"),
            "gh_config_directory": ("GH_CONFIG_NOT_REGULAR", "GH_CONFIG"),
            "gh_config_symlink": ("GH_CONFIG_NOT_REGULAR", "GH_CONFIG"),
            "transport_symlink": ("CHILD_SYMLINK", "TRANSPORT"),
            "hardlink": ("CHILD_LINK_COUNT", "QUARANTINE"),
            "fifo": ("CHILD_SPECIAL_FILE", "QUARANTINE"),
        }
        for case, expected in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                roots = [Path(temporary) / name for name in ("old", "new")]
                for root in roots:
                    layout(root)
                    private_name = "INPUT_NAME_MUST_NOT_BE_REPORTED"
                    if case == "foreign_root":
                        (root / private_name).write_bytes(b"keep")
                    elif case == "build_directory":
                        (root / "build" / private_name).mkdir()
                    elif case == "transport_directory":
                        (root / "transport" / private_name).mkdir()
                    elif case == "gh_config_directory":
                        (root / "transport/gh-config" / private_name).mkdir()
                    elif case == "gh_config_symlink":
                        (root / "transport/gh-config" / private_name).symlink_to("../../metadata-0001.bin")
                    elif case == "transport_symlink":
                        (root / "transport" / private_name).symlink_to("metadata-0001.bin")
                    elif case == "hardlink":
                        os.link(root / "quarantine/0.rpm", root / "quarantine" / private_name)
                    elif case == "fifo":
                        os.mkfifo(root / "quarantine" / private_name)
                details = []
                self.assertFalse(original_cleanup(roots[0], ALLOWED))
                self.assertFalse(bridge._cleanup_owned_tree(roots[1], ALLOWED, failure_sink=details))
                self.assertEqual(snapshot(roots[0]), snapshot(roots[1]))
                self.assertEqual(len(details), 1)
                self.assertEqual((details[0]["category"], details[0]["scope"]), expected)
                self.assertNotIn("INPUT_NAME", repr(details))

    def test_foreign_owner_labels_at_each_scope_preserve_original_behavior(self):
        cases = {
            ".": ("ROOT_FOREIGN_OWNER", "ROOT"),
            "build": ("SUBDIR_FOREIGN_OWNER", "BUILD"),
            "quarantine/0.rpm": ("CHILD_FOREIGN_OWNER", "QUARANTINE"),
            "transport/gh-config/config.yml": ("GH_CONFIG_FOREIGN_OWNER", "GH_CONFIG"),
        }
        real_lstat = os.lstat
        for selected, expected in cases.items():
            with self.subTest(scope=selected), tempfile.TemporaryDirectory() as temporary:
                roots = [Path(temporary) / name for name in ("old", "new")]
                outcomes, details = [], []
                for index, root in enumerate(roots):
                    layout(root)
                    (root / "transport/gh-config/config.yml").write_bytes(b"public config fixture")
                    target = root if selected == "." else root / selected
                    def foreign_owner(path, *args, **kwargs):
                        info = real_lstat(path, *args, **kwargs)
                        if Path(path) == target:
                            fields = list(info)
                            fields[4] = info.st_uid + 1
                            return os.stat_result(fields)
                        return info
                    with mock.patch.object(os, "lstat", side_effect=foreign_owner):
                        outcomes.append(
                            original_cleanup(root, ALLOWED) if index == 0 else
                            bridge._cleanup_owned_tree(root, ALLOWED, failure_sink=details)
                        )
                self.assertEqual(outcomes, [False, False])
                self.assertEqual(snapshot(roots[0]), snapshot(roots[1]))
                self.assertEqual((details[0]["category"], details[0]["scope"]), expected)

    def test_oserror_reports_operation_and_closed_errno(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "owned"
            layout(root)
            details = []
            with mock.patch.object(os, "unlink", side_effect=PermissionError(errno.EACCES, "PRIVATE ERROR TEXT")):
                self.assertFalse(bridge._cleanup_owned_tree(root, ALLOWED, failure_sink=details))
            self.assertEqual(details, [{
                "category": "FILESYSTEM", "scope": "QUARANTINE",
                "operation": "UNLINK", "errno": "EACCES",
            }])
            self.assertNotIn("PRIVATE", repr(details))

    def run_main(self, observation):
        error = bridge.RuntimeBridgeError("WORK_ROOT_CLEANUP_FAILED",
                                          custody_retained=True,
                                          cleanup_observation=observation)
        stderr = io.StringIO()
        with mock.patch.object(bridge, "execute_prepare_image", side_effect=error), contextlib.redirect_stderr(stderr):
            result = bridge.main([
                "prepare-image", "--p-root", "/fixture/p", "--r-root", "/fixture/r",
                "--binding-file", "/fixture/binding", "--work-root", "/fixture/work",
                "--image-receipt", "/fixture/receipt", "--github-output", "/fixture/output",
            ])
        return result, stderr.getvalue()

    def test_cli_retains_failure_and_reports_only_closed_labels(self):
        observation = {"category": "GH_CONFIG_NOT_REGULAR", "scope": "GH_CONFIG",
                       "operation": "LSTAT", "errno": "NONE"}
        result, output = self.run_main(observation)
        self.assertEqual(result, 2)
        self.assertEqual(output, (
            "REFUSED WORK_ROOT_CLEANUP_FAILED\n"
            "WORK_ROOT_CLEANUP CATEGORY=GH_CONFIG_NOT_REGULAR SCOPE=GH_CONFIG OPERATION=LSTAT ERRNO=NONE\n"
            "BRIDGE_CUSTODY_RETAINED\n"
        ))

    def test_invalid_or_private_observation_never_reaches_cli(self):
        for observation in [
            {"category": "/" + "private" + "/input", "scope": "GH_CONFIG", "operation": "LSTAT", "errno": "NONE"},
            {"category": "FILESYSTEM", "scope": "ROOT", "operation": "LSTAT", "errno": "secret"},
            {"category": "ROOT_ENTRIES", "scope": "ROOT", "operation": "LISTDIR", "errno": "NONE",
             "path": "/" + "private" + "/input"},
        ]:
            with self.subTest(observation=observation):
                result, output = self.run_main(observation)
                self.assertEqual(result, 2)
                self.assertEqual(output, "REFUSED WORK_ROOT_CLEANUP_FAILED\nBRIDGE_CUSTODY_RETAINED\n")


# Handshake observations preserve failure identity and disclose only closed labels.


def _handshake_record(**changes):
    doc={"schema":"tf.current-signer-worker-receipt.v1","status":"failed-closed","error_code":"WORKER_EXECUTION_FAILED","custody_retained":False,"publication_authority":False,"native_client_qualification":False}
    doc.update(changes)
    return json.dumps(doc,sort_keys=True).encode()+b"\n"


class HandshakeDiagnosticOutputTests(unittest.TestCase):
    def test_unknown_codes_and_private_like_values_never_echo(self):
        for code in ["GH_TOKEN","PRIVATE_SENTINEL_987","/fixture/sentinel","x"*100, "", "TOKEN_VALUE_ABC"]:
            observed=_diag_host._parse_untrusted_pre_frame_worker_stderr(_handshake_record(error_code=code))
            self.assertEqual(observed,("UNLISTED_WORKER_CODE","NONE"))
            if code:
                self.assertNotIn(code, json.dumps(observed))
        observed=_diag_host._parse_untrusted_pre_frame_worker_stderr(_handshake_record(error_detail="/fixture/sentinel"))
        self.assertEqual(observed,("WORKER_EXECUTION_FAILED","UNLISTED_WORKER_DETAIL"))

    def test_duplicate_nonmapping_extra_and_truncated_records_are_closed(self):
        good=_handshake_record()
        duplicate=good.replace(b'"error_code": "WORKER_EXECUTION_FAILED"',b'"error_code": "WORKER_EXECUTION_FAILED", "error_code": "PRIVATE_SENTINEL_987"')
        for data in [duplicate,b"null\n",b"[]\n",b"[{}]\n",good[:-5],b"prefix\n"+good,good+good,good+b"suffix\n",_handshake_record(extra="PRIVATE_SENTINEL_987"),_handshake_record(custody_retained=0),_handshake_record(publication_authority=0),_handshake_record(error_code=["PRIVATE_SENTINEL_987"]),b"\xff",b"a"*4097,b"\x00",good.replace(b"\n",b"\r\n")]:
            observed=_diag_host._parse_untrusted_pre_frame_worker_stderr(data)
            self.assertEqual(observed,("UNRECOGNIZED_STDERR_FORMAT","NONE"))

    def test_seeded_bytes_fuzz_returns_only_closed_labels(self):
        rnd=random.Random(9271)
        for _ in range(1200):
            data=rnd.randbytes(rnd.randrange(0,5000))
            code,detail=_diag_host._parse_untrusted_pre_frame_worker_stderr(data)
            self.assertIn(code,_diag_host._ALLOWED_HANDSHAKE_OBSERVATIONS["worker_error_code"])
            self.assertIn(detail,_diag_host._ALLOWED_HANDSHAKE_OBSERVATIONS["worker_error_detail"])

    def test_emission_started_or_completed_never_drains_worker_stderr(self):
        class NeverDrain:
            @property
            def stderr_buf(self):raise AssertionError("private stream accessed")
            @property
            def deadline(self):raise AssertionError("private stream drained")
        for phase,emitted in [("emitting-frame",False),("emitting-frame",True),("frame-closed",True),("checking-ready",True)]:
            gate=types.SimpleNamespace(failed_phase=phase,state="failed",frame_emitted=emitted)
            error=RuntimeError();error.framing_reason="PRIVATE_SENTINEL_987"
            result=_diag_host._build_handshake_observation(gate,NeverDrain(),error)
            self.assertEqual(result["worker_error_code"],"WITHHELD_POST_FRAME")
            self.assertEqual(result["worker_error_detail"],"WITHHELD_POST_FRAME")
            self.assertEqual(result["framing_reason"],"NONE")

    def test_observation_key_and_value_allowlists_are_strict(self):
        good={"gate_phase":"CHECKING_READY","framing_reason":"EMPTY_EOF","worker_error_code":"STDERR_EMPTY","worker_error_detail":"NONE"}
        self.assertEqual(_diag_host.sanitize_handshake_observation(good),good)
        for obj in [dict(good,extra="PRIVATE_SENTINEL_987"),{k:v for k,v in good.items() if k!="gate_phase"},dict(good,gate_phase="PRIVATE_SENTINEL_987"),dict(good,worker_error_detail=1),None,[]]:
            self.assertIsNone(_diag_host.sanitize_handshake_observation(obj))


    def test_detail_label_sets_agree_without_importing_guarded_leaves(self):
        expected = _diag_host._PRE_FRAME_WORKER_DETAIL_ALLOWLIST
        for filename, constant in [
            ("signer_worker.py", "_ALLOWED_PRE_FRAME_ERROR_DETAILS"),
            ("signing_linux_isolation.py", "ISOLATION_DETAIL_CODES"),
        ]:
            source = ROOT / "tools/verification/current_signer" / filename
            tree = ast.parse(source.read_text())
            assignment = next(node for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(name, ast.Name) and name.id == constant for name in node.targets))
            self.assertEqual(frozenset(ast.literal_eval(assignment.value.args[0])), expected)

    def test_original_interrupt_skips_diagnostic_streams(self):
        with mock.patch.object(_diag_host, "_classify_gate_phase", side_effect=AssertionError("diagnostics entered")) as classifier:
            self.assertIsNone(_diag_host._build_handshake_observation(object(), object(), KeyboardInterrupt()))
            self.assertIsNone(_diag_host._build_handshake_observation(object(), object(), SystemExit(1)))
            classifier.assert_not_called()



def _handshake_config():
    return _diag_host.HostControllerConfig(
        p_root=Path("/fixture/p"),r_root=Path("/fixture/r"),export_root=Path("/fixture/export"),
        p_commit="1"*40,p_tree="2"*40,r_commit="3"*40,r_tree="4"*40,source_closure_sha256="5"*64,
        rs9_run=123,challenge_nonce="6"*64,run_id_suffix="123",container_image="sha256:"+"7"*64,
        container_python="/usr/bin/python3",expected_gpg_sha256="8"*64,expected_rpm_sha256="9"*64,
        release_date="Tue, 03 Nov 2026 00:00:00 +0000")


def _handshake_teardown(*args, **kwargs):
    return {"session_cleanup_uncertain":False,"container_absence_confirmed":True,"network_removed":True,
            "container_force_remove_attempted":True,"container_force_removed":True,"teardown_interrupted":False},None


class HandshakeFailureAttributionTests(unittest.TestCase):
    def run_diagnostic_failure(self, diagnostic_error):
        original=_diag_host.HostControllerError("MESSAGE_FRAMING","synthetic primary")
        fake_session=types.SimpleNamespace()
        with mock.patch.object(_diag_host,"_authenticate_host_sources",return_value=(Path("/fixture/p"),Path("/fixture/r"),Path("/fixture/export"),{})),\
             mock.patch.object(_diag_host,"build_docker_run_argv",return_value=("/usr/bin/docker","run")),\
             mock.patch.object(_diag_host,"scoped_git_env",return_value={}),\
             mock.patch.object(_diag_protocol,"ForegroundContainerSession",return_value=fake_session),\
             mock.patch.object(_diag_host,"_run_gate_session",side_effect=original),\
             mock.patch.object(_diag_host,"_build_handshake_observation",side_effect=diagnostic_error),\
             mock.patch.object(_diag_host,"_teardown_host_session",side_effect=_handshake_teardown) as cleanup:
            hooks=_diag_host.HostControllerHooks(docker_cmd_runner=lambda *args:(0,b"",b""),worker_spawner=lambda *args:object(),frame_emitter=lambda:bytearray())
            try:_diag_host.execute_host_controller(_handshake_config(),hooks=hooks)
            except BaseException as caught:
                return original,caught,cleanup.call_count
            self.fail("failure was lost")

    def test_diagnostic_exception_preserves_primary_error_and_teardown(self):
        original,caught,calls=self.run_diagnostic_failure(ValueError("synthetic diagnostic failure"))
        self.assertIs(caught,original)
        self.assertEqual(calls,1)
        self.assertTrue(caught.host_teardown["container_absence_confirmed"])

    def test_diagnostic_interrupt_keeps_interrupt_and_teardown(self):
        interrupt=KeyboardInterrupt()
        original,caught,calls=self.run_diagnostic_failure(interrupt)
        self.assertIs(caught,interrupt)
        self.assertEqual(calls,1)
        self.assertTrue(caught.host_teardown["container_absence_confirmed"])

    def test_drain_does_not_swallow_keyboard_interrupt(self):
        class Selector:
            def get_map(self):return {1:types.SimpleNamespace(data="stderr")}
        class Session:
            deadline=1e30
            selector=Selector()
            stderr_buf=b""
            def _pump_once(self,timeout):raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            _diag_host._drain_pre_frame_stderr(Session(),grace_seconds=0.01)


if __name__ == "__main__":
    unittest.main()
