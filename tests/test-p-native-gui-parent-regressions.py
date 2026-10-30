"""Pure protocol/cleanup regressions: no process, signal, GUI or Nix launch."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).parents[1] / "tools/verification/p-native-gui-controller.py"
spec = importlib.util.spec_from_file_location("p_gui_parent_fixture", PATH)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

def identity(path, marker):
    return {"path": path, "size": 3, "sha256": marker * 64}

def make_session(scenario="C-signal", platform="linux-x64", launch_binding="8"):
    source = {"pCommit":"a"*40,"pTree":"b"*40,"nebularCommit":"c"*40,"nebularTree":"d"*40}
    app_identity = identity("/nix/store/gui/bin/gui", "e")
    monitor_identity = identity("/nix/store/bwrap/bin/bwrap", "f")
    config = {"source":source,"platform":platform,"scenario":scenario,"nonce":"1"*32,
              "application":app_identity,"monitor":{"executable":monitor_identity,"argv":["bwrap","--die-with-parent"]},
              "receiptPath":"/fixture/receipt.json","launchBindingSha256":launch_binding*64,
              "nodePid":101,"monitorPid":202,
              "predicateHelper":identity("/nix/store/helper/p-process-predicate-probe.py","7")}
    app = {"pid":303,"start":4}
    monitor = {"pid":202,"start":3}
    identities = {11:{"dev":1,"ino":202,**{k:v for k,v in monitor_identity.items() if k!="path"}},
                  12:{"dev":1,"ino":303,**{k:v for k,v in app_identity.items() if k!="path"}}}
    acknowledgements = [{"op":"ARMED","seq":1}]
    def disarm(*args):
        acknowledgements.append({"op":"DISARMED","seq":2})
        lease.write = None
    lease = types.SimpleNamespace(nonce=config["nonce"],acknowledgements=acknowledgements,
                                  write=8,pulse=lambda:None,disarm=disarm,fail=Mock())
    def snapshot(view, process):
        return {**process,"ppid":101 if process is monitor else 202,
                "state":"T" if process is monitor else "Z","exit_code":0 if process is monitor else 15}
    def wait(check, deadline, pulse=lambda:None):
        value=check()
        if not value: raise AssertionError("fixture predicate false")
        return value
    stable = types.SimpleNamespace(opened_identity=lambda fd:identities[fd],send=Mock(),
        wait_until=wait,assert_fixed=snapshot,recheck_stopped_identity=lambda *a:None,
        zombie_witness=lambda before,first,second,after,app,mon:
            {"pid":app["pid"],"ppid":mon["pid"],"start":app["start"],"state":"Z","exit_code":15},
        resumed_or_exited=lambda *a:True,cleanup_bound=Mock(return_value=[]))
    session=object.__new__(M.GuiSession)
    session.config=config;session.stable=stable;session.view=types.SimpleNamespace(close=Mock())
    session.handles=[];session.monitor=monitor;session.application=app;session.monitor_fd=21;session.application_fd=22
    session.monitor_executable_fd=11;session.application_executable_fd=12;session.credentials={}
    session.lease=None;session.fixture_lease=lease;stable.Lease=Mock(return_value=lease)
    session.finalization_deadline=None;session.bound=True;session.completed=False;session.witness=None
    session._revalidate_handles=Mock()
    context={"schema":"theme-forge.p-native-gui-context.v1","transform":"p-linux-gui-controller-v1",
             **source,"rawExecutable":app_identity,"publicWrapper":identity("/nix/store/wrapper/bin/tfnf","6"),
             "monitor":config["monitor"],"controller":{"python":"/nix/store/python/bin/python3","scriptSha256":"5"*64},
             "predicateHelper":config["predicateHelper"],"bridgeSha256":"4"*64}
    return session,context

def transcript(scenario="C-signal", platform="linux-x64", launch_digest=None):
    session,context=make_session(scenario,platform)
    if launch_digest is not None: session.config["launchBindingSha256"]=launch_digest
    bound=session._response("BOUND")
    with patch.object(M,"_receipt",return_value={}),patch.object(M.select,"select",return_value=([22],[],[])):
        terminated=session.terminate() if scenario=="C-signal" else None
        final=session.finalize({"code":143 if scenario=="C-signal" else 0,"signal":None})
    return {"context":context,"scenario":scenario,"platform":platform,"bound":bound,"terminated":terminated,"final":final}

class ParentRegression(unittest.TestCase):
    def test_real_producer_has_common_source_target_all_phases(self):
        for scenario,platform in [("C-signal","linux-x64"),("C","linux-x64"),("B","linux-arm64")]:
            item=transcript(scenario,platform)
            for response in [item["bound"],item["terminated"],item["final"]]:
                if response is None: continue
                self.assertEqual(response["source"],item["bound"]["source"])
                self.assertEqual(response["launchBindingSha256"],item["bound"]["launchBindingSha256"])
                self.assertEqual(response["target"],item["bound"]["target"])
            if scenario=="C-signal":
                self.assertEqual(item["final"]["watchdog"]["acknowledgements"][-1]["op"],"DISARMED")
            else:self.assertIsNone(item["final"]["watchdog"])

    def test_response_echoes_changed_launch_binding(self):
        session, _ = make_session(launch_binding="9")
        self.assertEqual(session._response("BOUND")["launchBindingSha256"], "9" * 64)

    def test_failed_identity_refuses_direct_cleanup_and_remains_failure(self):
        session,_=make_session();session.lease=session.fixture_lease
        session._revalidate_handles.side_effect=M.Refusal("identity changed")
        with self.assertRaises(M.Refusal):
            session.close()
        session.stable.cleanup_bound.assert_not_called()
        session.lease.fail.assert_called_once()
        session.view.close.assert_called_once()

    def test_successful_identity_allows_exact_handle_cleanup(self):
        session,_=make_session()
        session.close()
        session.stable.cleanup_bound.assert_called_once_with(21,22,session.lease,False)

    def test_completed_session_never_signals_or_rescues(self):
        session,_=make_session();session.lease=session.fixture_lease;session.completed=True;session.lease.write=None
        session.close()
        session.stable.cleanup_bound.assert_not_called()
        session.lease.fail.assert_not_called()

    def test_undisarmed_completed_session_is_failure(self):
        session,_=make_session();session.lease=session.fixture_lease;session.completed=True
        with self.assertRaises(M.Refusal):session.close()
        session.stable.cleanup_bound.assert_not_called()

    def test_live_exec_change_closes_reopened_descriptor_and_refuses(self):
        session,_=make_session()
        session.view.executable=Mock(return_value=({"dev":9,"ino":9,"size":3,"sha256":"9"*64},44))
        with patch.object(M.os,"close") as close:
            with self.assertRaisesRegex(M.Refusal,"live executable identity changed"):
                M.GuiSession._live_executable_matches(session,session.application,12,{"state":"R"})
            close.assert_called_once_with(44)

    def test_disarmed_real_watchdog_is_not_heartbeated_during_finalization(self):
        helper_path = PATH.with_name("p-process-predicate-probe.py")
        helper_spec = importlib.util.spec_from_file_location("real_predicate_fixture", helper_path)
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        stopped = object.__new__(helper.Lease)
        stopped.child = types.SimpleNamespace(poll=lambda: 0)
        stopped.write = None
        with self.assertRaises(helper.Refusal):
            stopped.pulse()
        session, _ = make_session()
        session.lease = stopped
        session.witness = {"exit_code": 15}
        session.finalization_deadline = M.time.monotonic() + 5
        session.heartbeat()
        session.finalization_deadline = M.time.monotonic() - 1
        with self.assertRaisesRegex(M.Refusal, "finalization deadline"):
            session.heartbeat()

    def test_unarmed_gui_wait_has_no_signal_watchdog_deadline(self):
        session,_=make_session("C")
        with patch.object(M.time,"monotonic",return_value=100000):
            session.heartbeat()
        self.assertIsNone(session.lease)
        session.stable.Lease.assert_not_called()

    def test_signal_finalize_enforces_deadline_inside_finalize(self):
        session,_=make_session()
        session.lease=session.fixture_lease;session.lease.write=None
        session.witness={"exit_code":15};session.finalization_deadline=M.time.monotonic()-1
        with self.assertRaisesRegex(M.Refusal,"finalization deadline"):
            session.finalize({"code":143,"signal":None})
        self.assertFalse(session.completed)

    def test_final_response_hashing_cannot_cross_completion_deadline(self):
        session,_=make_session()
        session.lease=session.fixture_lease;session.lease.write=None
        session.witness={"exit_code":15};session.finalization_deadline=5
        clock=[4.9];original=session.stable.opened_identity
        def slow_identity(fd):
            clock[0]=6
            return original(fd)
        session.stable.opened_identity=slow_identity
        with patch.object(M.time,"monotonic",side_effect=lambda:clock[0]),patch.object(M.select,"select",return_value=([22],[],[])):
            with self.assertRaisesRegex(M.Refusal,"finalization deadline"):
                session.finalize({"code":143,"signal":None})
        self.assertFalse(session.completed)

    def test_complete_signal_transaction_deadline_includes_response_hashing(self):
        for endpoint,accepted in [(34.9,True),(35,False),(36,False)]:
            with self.subTest(endpoint=endpoint):
                session,_=make_session();clock=[0]
                original_disarm=session.fixture_lease.disarm
                def disarm(*args):
                    original_disarm(*args);clock[0]=31
                session.fixture_lease.disarm=disarm
                original_identity=session.stable.opened_identity
                def slow_identity(fd):
                    clock[0]=endpoint
                    return original_identity(fd)
                session.stable.opened_identity=slow_identity
                def receipt(*args):
                    clock[0]=15
                    return {}
                with patch.object(M.time,"monotonic",side_effect=lambda:clock[0]),patch.object(M.select,"select",return_value=([22],[],[])),patch.object(M,"_receipt",side_effect=receipt):
                    if accepted:self.assertEqual(session.terminate()["op"],"TERMINATED")
                    else:
                        with self.assertRaises(M.Refusal):session.terminate()

    def test_watchdog_starts_only_at_signal_with_authenticated_helper(self):
        session,_=make_session()
        session.config["monitor"]["argv"]=["bwrap"]
        session.view.snapshot=Mock(return_value={"pid":202,"ppid":101,"start":3})
        def ready():
            session.monitor_executable_fd=11
            return True
        session._monitor_ready=ready
        session.view.status=Mock(return_value={"Uid":(os.getuid(),)*4,"Gid":(os.getgid(),)*4})
        session.view.threads=Mock(return_value=1)
        session.view.namespace=Mock(return_value="pid:fixture")
        session.view.read=Mock(return_value=b"bwrap\0")
        session._discover_application=Mock(return_value=session.application)
        session.stable.wait_until=lambda check,*args:check()
        session.stable.assert_fixed=lambda view,identity:{**identity,"ppid":101 if identity["pid"]==202 else 202,"state":"T" if identity["pid"]==202 else "Z","exit_code":0 if identity["pid"]==202 else 15}
        session.stable.pidfd_target=Mock()
        session.view.executable=Mock(return_value=({"size":3,"sha256":"e"*64},12))
        lease=session.fixture_lease;session.stable.Lease=Mock(return_value=lease)
        with patch.object(M.os,"getppid",return_value=101),patch.object(M.os,"pidfd_open",create=True,side_effect=[21,22]):
            result=session.bind()
        session.stable.Lease.assert_not_called()
        self.assertIsNone(session.lease)
        self.assertEqual(result["op"],"BOUND")
        with patch.object(M,"_receipt",return_value={}),patch.object(M.select,"select",return_value=([22],[],[])):
            session.terminate()
        self.assertEqual(session.stable.Lease.call_args.args[1],session.config["predicateHelper"]["path"])

if __name__=="__main__":
    if sys.argv[1:]==["--emit-transcripts"]:
        print(json.dumps([transcript("C-signal"),transcript("C"),transcript("B","linux-arm64")]))
    else:
        unittest.main()
