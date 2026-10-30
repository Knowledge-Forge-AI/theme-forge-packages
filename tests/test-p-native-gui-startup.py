"""Inert process-view startup transitions; no native subjects or signals."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
import os

path=Path(__file__).with_name("test-p-native-gui-parent-regressions.py")
spec=importlib.util.spec_from_file_location("gui_startup_parent_fixture",path)
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
M=P.M

class StartupTests(unittest.TestCase):
    def session(self,images):
        session,_=P.make_session("C")
        session.handles=[];session.monitor_fd=None;session.monitor_executable_fd=None
        session.application_fd=None;session.application_executable_fd=None
        session.view.snapshot=Mock(return_value={"pid":202,"ppid":101,"start":3})
        session.view.directory=Mock(return_value=14)
        session.view.executable=Mock(side_effect=images)
        session.view.read=Mock(return_value=b"bwrap\0--die-with-parent\0")
        session.view.status=Mock(return_value={"Uid":(os.getuid(),)*4,"Gid":(os.getgid(),)*4})
        session.view.threads=Mock(return_value=1);session.view.namespace=Mock(return_value="pid:fixture")
        session.stable.assert_fixed=lambda view,ident:{**ident,"ppid":101 if ident["pid"]==202 else 202}
        session.stable.pidfd_target=Mock()
        original_identity=session.stable.opened_identity
        session.stable.opened_identity=lambda fd:original_identity({33:11,34:12}.get(fd,fd))
        session._discover_application=Mock(return_value={"pid":303,"start":4})
        session.stable.Lease=Mock(return_value=session.lease)
        def wait(check,deadline,pulse=lambda:None):
            for _ in range(3):
                value=check()
                if value:return value
            raise M.Refusal("fixture readiness deadline")
        session.stable.wait_until=wait
        return session

    def test_bind_waits_for_bash_bash_bwrap_with_pidfd_and_closes_transient_exec_fds(self):
        wrong={"size":4,"sha256":"0"*64};right={"size":3,"sha256":"f"*64};app={"size":3,"sha256":"e"*64}
        session=self.session([(wrong,31),(wrong,32),(right,33),(app,34)])
        with patch.object(M.os,"getppid",return_value=101),patch.object(M.os,"pidfd_open",create=True,side_effect=[21,22]),\
             patch.object(M.os,"readlink",return_value=session.config["monitor"]["executable"]["path"]),patch.object(M.os,"close") as close:
            result=session.bind()
        self.assertEqual(result["op"],"BOUND")
        self.assertEqual(session.monitor_fd,21)
        self.assertEqual(session.monitor_executable_fd,33)
        self.assertEqual([call.args[0] for call in close.call_args_list],[31,32])
        self.assertEqual(session.stable.pidfd_target.call_args_list[0].args[1:],(21,202))
        self.assertIn(33,session.handles)

    def test_monitor_that_remains_bash_refuses_at_readiness_deadline(self):
        wrong={"size":4,"sha256":"0"*64}
        session=self.session([(wrong,31),(wrong,32),(wrong,33)])
        with patch.object(M.os,"getppid",return_value=101),patch.object(M.os,"pidfd_open",create=True,return_value=21),\
             patch.object(M.os,"close") as close:
            with self.assertRaisesRegex(M.Refusal,"readiness deadline"):session.bind()
        self.assertIsNone(session.monitor_fd)
        self.assertIsNone(session.monitor_executable_fd)
        self.assertEqual([call.args[0] for call in close.call_args_list],[31,32,33])
        session.stable.Lease.assert_not_called()

    def test_matching_app_one_thread_is_polled_until_two_threads(self):
        session,_=P.make_session()
        session.credentials={"Uid":(os.getuid(),)*4,"Gid":(os.getgid(),)*4}
        scan=Mock()
        scan.snapshot.return_value={"pid":303,"start":4,"ppid":202}
        scan.executable.side_effect=[({"size":3,"sha256":"e"*64},71),({"size":3,"sha256":"e"*64},72)]
        scan.status.return_value=session.credentials
        scan.namespace.return_value="pid:fixture";scan.threads.side_effect=[1,2]
        session.view.namespace=Mock(return_value="pid:fixture")
        session.view.root="fixture";session.stable.ProcView=Mock(return_value=scan)
        session._direct_children=Mock(return_value=[303])
        with patch.object(M.os,"close") as close:
            self.assertIsNone(session._discover_application())
            self.assertEqual(session._discover_application()["pid"],303)
        self.assertEqual([call.args[0] for call in close.call_args_list],[71,72])
        self.assertEqual(scan.close.call_count,2)

    def test_one_thread_matching_child_cannot_hide_ambiguous_second_match(self):
        session,_=P.make_session()
        session.credentials={"Uid":(os.getuid(),)*4,"Gid":(os.getgid(),)*4}
        scan=Mock()
        scan.snapshot.side_effect=lambda pid:{"pid":pid,"start":4,"ppid":202}
        scan.executable.side_effect=[({"size":3,"sha256":"e"*64},71),({"size":3,"sha256":"e"*64},72)]
        scan.status.return_value=session.credentials
        scan.namespace.return_value="pid:fixture";scan.threads.side_effect=[1,2]
        session.view.namespace=Mock(return_value="pid:fixture")
        session.view.root="fixture";session.stable.ProcView=Mock(return_value=scan)
        session._direct_children=Mock(return_value=[303,304])
        with patch.object(M.os,"close") as close:
            with self.assertRaisesRegex(M.Refusal,"ambiguous raw GUI application"):
                session._discover_application()
        self.assertEqual([call.args[0] for call in close.call_args_list],[71,72])

if __name__=="__main__":unittest.main()
