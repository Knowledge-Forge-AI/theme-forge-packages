"""Pure contract checks; never launches Docker, GnuPG or a native agent."""
import ast
import types
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "tools/verification/current_signer"
sys.path.insert(0, str(SRC))
import signing_image_build as sib
import keyfree_agent_image_check as check
import container_process_entry as entry

def accepted():
    return {
        "schema": check.SCHEMA, "status": "passed", "phase": "COMPLETE", "code": "NONE",
        "worker_uid": 1001, "worker_gid": 1001,
        "agent_source_sha256": check.AGENT_SOURCE_SHA256,
        "agent_started_and_live": True, "agent_cleanup_confirmed": True,
        "custody_retained": False, "fresh_state_disposal": "owned-container-teardown",
        "signing_credentials_used": False, "production_authority": False,
    }

class ImageContract(unittest.TestCase):
    def test_recipe_runs_existing_preparation_before_stage_removal(self):
        text=sib.render_offline_dockerfile()
        marker="/usr/bin/python3 -I -B /tmp/tf-rpm-stage/prepare_isolated_global_config.py --prepare-image"
        self.assertIn(marker, text)
        self.assertLess(text.index("/usr/bin/dnf install"), text.index(marker))
        self.assertLess(text.index(marker), text.index("/usr/bin/rm -rf /tmp/tf-rpm-stage"))
        self.assertIn("--expected-helper-sha256 c6a8cf05d3c46fd1497fd9de490366e4ad7fb3caafbb61c049a15bc669526a11",text)
        self.assertEqual(sib.validate_offline_dockerfile(text),sib.EXPECTED_DOCKERFILE_SHA256)

    def test_context_pins_bind_all_three_actual_sources(self):
        pins=sib.IMAGE_CHECK_SOURCE_PINS
        self.assertEqual(set(pins), {"prepare_isolated_global_config.py","owned_gpg_agent.py","keyfree_agent_image_check.py","container_process_entry.py"})
        payloads=sib._image_check_source_payloads()
        self.assertEqual(set(payloads),set(pins))
        for name,raw in payloads.items():
            self.assertEqual((len(raw),sib.sha256_hex(raw)),tuple(pins[name][1:]))
            self.assertIn(name,sib.ALLOWED_CONTEXT_FILENAMES)

    def test_probe_keeps_restrictions_and_adds_exact_private_tmpfs(self):
        argv=sib._make_command_plan("123").probe_argv("sha256:"+"1"*64)
        for pair in (("--network","none"),("--user","1001:1001"),("--cap-drop","ALL"),("--security-opt","no-new-privileges")):
            i=argv.index(pair[0]);self.assertEqual(argv[i+1],pair[1])
        self.assertIn("--read-only",argv)
        self.assertEqual(argv[argv.index("--tmpfs")+1],"/work/workspace:rw,noexec,nosuid,nodev,mode=0700,uid=1001,gid=1001")
        self.assertIn("keyfree_agent_check",sib._CONTAINER_PROBE_CODE)
        compile(sib._CONTAINER_PROBE_CODE,"probe","exec")

    def test_gate_requires_success(self):
        self.assertEqual(sib._verify_keyfree_agent_check(accepted()),accepted())
        for field in accepted():
            bad=accepted();del bad[field]
            with self.subTest(field=field),self.assertRaises(sib.ImageBuildError):
                sib._verify_keyfree_agent_check(bad)
        bad=accepted();bad["unexpected"]="PRIVATE"
        with self.assertRaises(sib.ImageBuildError):sib._verify_keyfree_agent_check(bad)

    def test_failed_check_reports_only_closed_code(self):
        bad=accepted();bad.update(status="failed-closed",phase="START",code="GLOBAL_CONFIG_REJECTED",agent_started_and_live=False)
        with self.assertRaises(sib.ImageBuildError) as raised:sib._verify_keyfree_agent_check(bad)
        self.assertEqual(raised.exception.code,"KEYFREE_AGENT_GLOBAL_CONFIG_REJECTED")
        bad["code"]="PRIVATE-NOT-ALLOWED"
        with self.assertRaises(sib.ImageBuildError) as raised:sib._verify_keyfree_agent_check(bad)
        self.assertNotIn("PRIVATE",str(raised.exception))
        self.assertEqual(raised.exception.code,"KEYFREE_AGENT_REPORT_INVALID")


class ReportContract(unittest.TestCase):
    def test_every_accepted_field_is_exact_and_type_sensitive(self):
        for field, value in accepted().items():
            bad=accepted()
            if type(value) is bool:bad[field]=not value
            elif type(value) is int:bad[field]=True
            else:bad[field]="UNTRUSTED"
            with self.subTest(field=field), self.assertRaises(sib.ImageBuildError):
                sib._verify_keyfree_agent_check(bad)

    def test_each_closed_refusal_survives_without_payload(self):
        for code in sib.KEYFREE_AGENT_CODES:
            bad=accepted();bad.update(status="failed-closed",phase="START",code=code,agent_started_and_live=False)
            with self.subTest(code=code),self.assertRaises(sib.ImageBuildError) as raised:
                sib._verify_keyfree_agent_check(bad)
            self.assertEqual(raised.exception.code,"KEYFREE_AGENT_"+code)

    def test_fixture_reports_cannot_omit_check(self):
        manifest=sib.AdmissionManifest("1"*64,sib.EXPECTED_DOCKERFILE_SHA256,sib.CONTAINER_PYTHON_PATH,{})
        report=sib.ImageInspectionReport("sha256:"+"1"*64,True,True,True,True,{},None,sib.UPSTREAM_NOTICE_PINS_SHA256)
        with self.assertRaises(sib.ImageBuildError) as raised:
            sib._verify_inspection_report(manifest,report.image_id,report)
        self.assertEqual(raised.exception.code,"KEYFREE_AGENT_REPORT_INVALID")

    def test_native_binding_requires_check_even_if_flags_claim_ready(self):
        result=sib.ImageBuildResult(
            status="ready-native",execution_mode="native-subprocess-engine",
            manifest_sha256=sib.ADMITTED_MANIFEST_SHA256,recipe_sha256=sib.EXPECTED_DOCKERFILE_SHA256,
            image_id="sha256:"+"1"*64,container_python=sib.CONTAINER_PYTHON_PATH,
            tool_digests={k:"1"*64 for k in sib.REQUIRED_TOOL_PATHS},
            tool_bytes={},tool_versions={},step_receipts=(),context_cleaned=True,
            custody_retained=False,retained_custody_count=0,native_execution_observed=True,
            native_ready_for_host_controller=True)
        with self.assertRaises(sib.ImageBuildError) as raised:sib.to_host_controller_image_kwargs(result)
        self.assertEqual(raised.exception.code,"KEYFREE_AGENT_REPORT_INVALID")

    def test_admission_keeps_only_recipe_delta(self):
        doc=sib.parse_strict_json((SRC/"runtime-image-admission.json").read_bytes())
        self.assertEqual(doc["recipe_sha256"],sib.EXPECTED_DOCKERFILE_SHA256)
        self.assertEqual(sib.sha256_hex((SRC/"runtime-image-admission.json").read_bytes()),sib.ADMITTED_MANIFEST_SHA256)

class SourceCustody(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get("TF_TEST_TMP"))
        self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def test_pinned_source_bytes_reject_mutation_link_alias_and_missing(self):
        real=SRC.parent
        for mode in ("changed","link","hardlink","missing"):
            with self.subTest(mode=mode):
                base=self.root/mode;target=base/"b3/prepare_isolated_global_config.py";target.parent.mkdir(parents=True)
                for name,(rel,_,_) in sib.IMAGE_CHECK_SOURCE_PINS.items():
                    if name=="prepare_isolated_global_config.py":continue
                    other_source=base/rel;other_source.parent.mkdir(parents=True,exist_ok=True)
                    other_source.write_bytes((real/rel).read_bytes())
                content=(real/"b3/prepare_isolated_global_config.py").read_bytes()
                if mode=="changed":target.write_bytes(content+b"\n")
                elif mode=="link":
                    other=base/"fixture";other.write_bytes(content);target.symlink_to(other)
                elif mode=="hardlink":
                    other=base/"fixture";other.write_bytes(content);os.link(other,target)
                with patch.object(sib,"__file__",str(base/"current_signer/signing_image_build.py")):
                    with self.assertRaises(sib.ImageBuildError):sib._image_check_source_payloads()

    def test_context_stages_exact_sources_and_disposes_only_owned_files(self):
        cert=b"public fixture"
        context,identity=sib._stage_build_context(self.root,"987",cert,{})
        self.assertEqual(stat.S_IMODE(context.stat().st_mode),0o700)
        for name,raw in sib._image_check_source_payloads().items():
            self.assertEqual((context/name).read_bytes(),raw)
            self.assertEqual(stat.S_IMODE((context/name).stat().st_mode),0o600)
        self.assertTrue(sib._release_build_context(context,identity))
        self.assertFalse(context.exists())

    def test_staged_source_tamper_is_refused_before_other_inputs(self):
        for mutation in ("bytes","mode","link","hardlink"):
            with self.subTest(mutation=mutation):
                base=self.root/mutation;base.mkdir()
                context,identity=sib._stage_build_context(base,"765",b"public fixture",{})
                # Complete the inventory with inert files; source verification runs
                # before archive/certificate parsing, so no native tool is needed.
                for name in sib.ALLOWED_CONTEXT_FILENAMES:
                    if not (context/name).exists():sib._write_context_file(context,name,b"inert")
                target=context/"keyfree_agent_image_check.py"
                if mutation=="bytes":target.write_bytes(b"changed")
                elif mutation=="mode":target.chmod(0o644)
                else:
                    target.unlink()
                    other=base/"other";other.write_bytes(b"harmless")
                    if mutation=="link":target.symlink_to(other)
                    else:os.link(other,target)
                with self.assertRaises(sib.ImageBuildError):sib._verify_staged_context(context,identity)
                # Fixture-owned correction only; never use cleanup to accept this context.
                if mutation in {"link","hardlink"}:target.unlink()
                elif mutation=="mode":target.chmod(0o600)
                self.assertTrue(sib._release_build_context(context,identity))

class FakeAgent:
    def __init__(self,home,job):
        self.home=home;self.job=job;self.cleanup_confirmed=False;self.events=[]
    def start(self):self.events.append("start")
    def require_live(self):self.events.append("live")
    def close(self):self.events.append("close");self.cleanup_confirmed=True

class CheckLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get("TF_TEST_TMP"))
        self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.home.chmod(0o700);os.chown(self.home,-1,os.getgid())
        self.stack=[]
        for item in (patch.object(check,"WORKSPACE",self.home),
                     patch.object(check,"WORKER_UID",os.getuid()),
                     patch.object(check,"WORKER_GID",os.getgid()),
                     patch.object(sys,"platform","linux"),
                     patch.dict(os.environ,{},clear=True)):
            item.start();self.addCleanup(item.stop)
        check._RETAINED_CHECKS.clear()

    def execute(self,cls=FakeAgent):
        instances=[]
        def make(home,job):
            agent=cls(home,job);instances.append(agent);return agent
        with patch.object(check,"_load_agent_class",return_value=make):
            result=check.run_keyfree_agent_check()
        return result,instances

    def test_success_requires_live_and_confirmed_agent_close(self):
        result,agents=self.execute()
        self.assertEqual(result["status"],"passed")
        self.assertEqual(result["phase"],"COMPLETE")
        self.assertEqual(agents[0].events,["start","live","close"])
        self.assertTrue(result["agent_cleanup_confirmed"])
        self.assertFalse(result["custody_retained"])
        self.assertFalse(result["signing_credentials_used"])
        self.assertFalse(result["production_authority"])

    def test_existing_workspace_entry_is_not_reused_or_deleted(self):
        job=self.home/"keyfree-agent-check";job.mkdir();(job/"marker").write_bytes(b"fixture")
        result,agents=self.execute()
        self.assertEqual(result["status"],"failed-closed");self.assertEqual(result["phase"],"WORKSPACE")
        self.assertEqual(agents,[]);self.assertEqual((job/"marker").read_bytes(),b"fixture")

    def test_start_failure_preserves_closed_code_and_close_obligation(self):
        class Refusing(FakeAgent):
            def start(self):raise check.CheckRefusal("GLOBAL_CONFIG_REJECTED")
        result,agents=self.execute(Refusing)
        self.assertEqual(result["code"],"GLOBAL_CONFIG_REJECTED")
        self.assertEqual(result["phase"],"START")
        self.assertFalse(result["agent_started_and_live"])
        self.assertEqual(agents[0].events,["close"])
        self.assertTrue(result["agent_cleanup_confirmed"])

    def test_live_failure_is_not_relabelled_as_close(self):
        class Refusing(FakeAgent):
            def require_live(self):raise check.CheckRefusal("AGENT_NOT_LIVE")
        result,agents=self.execute(Refusing)
        self.assertEqual((result["code"],result["phase"]),("AGENT_NOT_LIVE","LIVE"))
        self.assertEqual(agents[0].events,["start","close"])

    def test_close_failure_retains_object_and_never_uses_teardown_as_proof(self):
        class Refusing(FakeAgent):
            def close(self):raise RuntimeError("untrusted fixture text")
        result,agents=self.execute(Refusing)
        self.assertEqual(result["code"],"AGENT_CLEANUP_UNCONFIRMED")
        self.assertEqual(result["phase"],"CLOSE")
        self.assertFalse(result["agent_cleanup_confirmed"])
        self.assertTrue(result["custody_retained"])
        self.assertEqual(check._RETAINED_CHECKS,[agents[0]])
        self.assertNotIn("untrusted",repr(result))

    def test_close_without_confirmed_property_is_not_success(self):
        class Refusing(FakeAgent):
            def close(self):pass
        result,agents=self.execute(Refusing)
        self.assertEqual(result["status"],"failed-closed");self.assertTrue(result["custody_retained"])

    def test_hostile_exception_code_never_escapes_or_reveals_text(self):
        class Hostile(BaseException):
            @property
            def code(self):raise SystemExit("fixture-sensitive")
        class Refusing(FakeAgent):
            def start(self):raise Hostile("fixture-sensitive")
        result,agents=self.execute(Refusing)
        self.assertEqual(result["code"],"AGENT_CHECK_FAILED")
        self.assertNotIn("fixture-sensitive",repr(result));self.assertTrue(result["agent_cleanup_confirmed"])

    def test_each_forbidden_environment_presence_refuses_before_source_load(self):
        for name in check._FORBIDDEN_ENV:
            with self.subTest(name=name),patch.dict(os.environ,{name:""},clear=True),patch.object(check,"_load_agent_class") as loader:
                result=check.run_keyfree_agent_check()
                self.assertEqual(result["code"],"CHECK_CONTEXT_REFUSED");loader.assert_not_called()

    def test_source_load_refusal_is_closed_and_no_agent_is_created(self):
        with patch.object(check,"_load_agent_class",side_effect=check.CheckRefusal("AGENT_SOURCE_REFUSED")):
            result=check.run_keyfree_agent_check()
        self.assertEqual((result["code"],result["phase"]),("AGENT_SOURCE_REFUSED","SOURCE"))
        self.assertFalse(result["custody_retained"])

    def test_constructor_exception_keeps_no_unobtained_custody_claim(self):
        class Refusing(FakeAgent):
            def __init__(self,home,job):raise RuntimeError("fixture-sensitive")
        result,agents=self.execute(Refusing)
        self.assertEqual(result["code"],"AGENT_CHECK_FAILED")
        self.assertFalse(result["custody_retained"]);self.assertFalse(result["agent_cleanup_confirmed"])


class ProcessEntryContract(unittest.TestCase):
    def test_parent_drops_environment_and_streams_before_release(self):
        events=[]
        def close(fd):events.append(("close",fd))
        def write(fd,body):events.append(("release",fd,body));self.assertEqual(dict(os.environ),{});return len(body)
        def exit_(status):raise SystemExit(status)
        with patch.dict(os.environ,{"GH_TOKEN":"inert-fixture"},clear=True),patch.object(sys,"platform","linux"),\
                patch.object(os,"getpid",return_value=1),patch.object(os,"getuid",return_value=1001),\
                patch.object(os,"getgid",return_value=1001),patch.object(os,"geteuid",return_value=1001),patch.object(os,"getegid",return_value=1001),patch.object(os,"pipe2",return_value=(10,11),create=True),\
                patch.object(os,"fork",return_value=22),patch.object(os,"close",side_effect=close),\
                patch.object(os,"write",side_effect=write),patch.object(entry,"_wait_for_child",return_value=7),patch.object(entry.signal,"signal") as handler,\
                patch.object(os,"_exit",side_effect=exit_):
            with self.assertRaises(SystemExit) as raised:entry.enter_noninit(["--",entry.PYTHON,"-I","-B","-c","pass"])
        self.assertEqual(raised.exception.code,7)
        handler.assert_called_once();self.assertEqual(handler.call_args.args[0],entry.signal.SIGINT)
        release=next(i for i,event in enumerate(events) if event[0]=="release")
        self.assertTrue(all(("close",fd) in events[:release] for fd in (0,1,2,10)))

    def test_noninit_child_execs_same_fixed_worker_after_barrier(self):
        target=["--",entry.PYTHON,"-I","-B",entry.WORKER,"--current-signer-worker"]
        with patch.dict(os.environ,{},clear=True),patch.object(sys,"platform","linux"),\
                patch.object(os,"getpid",side_effect=[1,22]),patch.object(os,"getppid",return_value=1),\
                patch.object(os,"getuid",return_value=1001),patch.object(os,"getgid",return_value=1001),patch.object(os,"geteuid",return_value=1001),patch.object(os,"getegid",return_value=1001),\
                patch.object(os,"pipe2",return_value=(10,11),create=True),patch.object(os,"fork",return_value=0),\
                patch.object(os,"close") as close,patch.object(os,"read",side_effect=[b"G",b""]),\
                patch.object(os,"execve",side_effect=SystemExit(0)) as execute:
            with self.assertRaises(SystemExit):entry.enter_noninit(target)
        execute.assert_called_once_with(entry.PYTHON,tuple(target[1:]),{})
        self.assertEqual([c.args[0] for c in close.call_args_list],[11,10])

    def test_wrong_barrier_or_parent_never_executes(self):
        for body,eof,parent in ((b"",b"",1),(b"X",b"",1),(b"G",b"X",1),(b"G",b"",3)):
            with self.subTest(body=body,eof=eof,parent=parent),patch.dict(os.environ,{},clear=True),\
                    patch.object(sys,"platform","linux"),patch.object(os,"getpid",side_effect=[1,22]),\
                    patch.object(os,"getppid",return_value=parent),patch.object(os,"getuid",return_value=1001),\
                    patch.object(os,"getgid",return_value=1001),patch.object(os,"geteuid",return_value=1001),patch.object(os,"getegid",return_value=1001),patch.object(os,"pipe2",return_value=(10,11),create=True),\
                    patch.object(os,"fork",return_value=0),patch.object(os,"close"),\
                    patch.object(os,"read",side_effect=[body,eof]),patch.object(os,"execve") as execute:
                with self.assertRaises(entry.EntryRefusal):entry.enter_noninit(["--",entry.PYTHON,"-I","-B","-c","pass"])
                execute.assert_not_called()

    def test_bad_context_and_signing_environment_refuse_before_fork(self):
        for pid,extra in ((2,{}),(1,{"PACKAGE_SIGNING_KEY":""}),(1,{"PACKAGE_SIGNING_PASSPHRASE":""})):
            with self.subTest(pid=pid,extra=extra),patch.object(sys,"platform","linux"),\
                    patch.object(os,"getpid",return_value=pid),patch.object(os,"getuid",return_value=1001),\
                    patch.object(os,"getgid",return_value=1001),patch.object(os,"geteuid",return_value=1001),patch.object(os,"getegid",return_value=1001),patch.dict(os.environ,extra,clear=True),patch.object(os,"fork") as fork:
                with self.assertRaises(entry.EntryRefusal):entry.enter_noninit(["--",entry.PYTHON,"-I","-B","-c","pass"])
                fork.assert_not_called()

    def test_target_rejects_other_executables_scripts_and_flags(self):
        for target in (["--","/bin/sh","-c","pass"],["--",entry.PYTHON,"-B","-I","-c","pass"],["--",entry.PYTHON,"-I","-B","/other.py"],["--",entry.PYTHON,"-I","-B",entry.WORKER,"--other"]):
            with self.subTest(target=target),self.assertRaises(entry.EntryRefusal):entry._target(target)

    def test_wait_preserves_direct_child_status_and_reaps_only_that_child(self):
        for status,wanted in ((0,0),(7<<8,7),(9,137)):
            with self.subTest(status=status),patch.object(os,"waitpid",return_value=(22,status)) as wait:
                self.assertEqual(entry._wait_for_child(22),wanted);wait.assert_called_once_with(22,0)

    def test_no_std_stream_reads_or_other_child_creation_in_entry(self):
        tree=ast.parse(Path(entry.__file__).read_text())
        reads=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="read"]
        self.assertEqual(len(reads),2)
        self.assertTrue(all(isinstance(n.args[0],ast.Name) and n.args[0].id=="read_fd" for n in reads))
        forks=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="fork"]
        self.assertEqual(len(forks),1)

class AdditionalCustody(unittest.TestCase):
    def test_helper_and_host_have_matching_fixed_emission_vocabulary(self):
        extra={"AGENT_SOURCE_REFUSED","WORKSPACE_REFUSED","CHECK_CONTEXT_REFUSED","AGENT_CHECK_FAILED","AGENT_CLEANUP_UNCONFIRMED"}
        self.assertEqual(check._CODES|extra,sib.KEYFREE_AGENT_CODES)

    def test_pid1_refuses_before_agent_or_workspace(self):
        with patch.object(sys,"platform","linux"),patch.object(os,"getpid",return_value=1),patch.object(check,"_load_agent_class") as loader:
            result=check.run_keyfree_agent_check()
        self.assertEqual(result["code"],"CHECK_CONTEXT_REFUSED");loader.assert_not_called()

    def test_start_refusal_with_uncertain_close_keeps_both_facts(self):
        bad=accepted();bad.update(status="failed-closed",phase="START",code="PATH_SCOPE",agent_started_and_live=False,agent_cleanup_confirmed=False,custody_retained=True)
        with self.assertRaises(sib.ImageBuildError) as raised:sib._verify_keyfree_agent_check(bad)
        self.assertEqual(raised.exception.code,"KEYFREE_AGENT_PATH_SCOPE_CLOSE_UNCONFIRMED")
        self.assertTrue(raised.exception.custody_retained)

    def test_real_loader_authenticates_and_compiles_without_starting_native_agent(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TF_TEST_TMP")) as t:
            root=Path(t);agent=root/"owned_gpg_agent.py";agent.write_bytes((SRC/"owned_gpg_agent.py").read_bytes());agent.chmod(0o444)
            original_fstat=os.fstat;original_lstat=os.lstat
            def root_owned(info):
                fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
                value={k:getattr(info,k) for k in fields};value.update(st_uid=0,st_gid=0);return types.SimpleNamespace(**value)
            with patch.object(check,"__file__",str(root/"keyfree_agent_image_check.py")),\
                    patch.object(os,"fstat",side_effect=lambda fd:root_owned(original_fstat(fd))),\
                    patch.object(os,"lstat",side_effect=lambda *a,**k:root_owned(original_lstat(*a,**k))):
                cls=check._load_agent_class()
                self.assertEqual(cls.__name__,"OwnedGpgAgent")
                self.assertIsInstance(cls.cleanup_confirmed,property)
                self.assertTrue(all(callable(getattr(cls,n,None)) for n in ("start","require_live","close")))
                agent.chmod(0o644)
                with self.assertRaises(check.CheckRefusal):check._source_bytes(agent)
                agent.write_bytes(b"altered");agent.chmod(0o444)
                with self.assertRaises(check.CheckRefusal):check._source_bytes(agent)



class SharedTopology(unittest.TestCase):
    def test_actual_host_and_inspection_argv_share_fixed_noninit_entry(self):
        import signer_host_controller as host
        cfg=host.HostControllerConfig(
            p_root=Path("/fixture/p"),r_root=Path("/fixture/r"),export_root=Path("/fixture/out"),
            p_commit="1"*40,p_tree="2"*40,r_commit="3"*40,r_tree="4"*40,
            source_closure_sha256="5"*64,rs9_run=123,challenge_nonce="6"*64,run_id_suffix="123",
            container_image="sha256:"+"7"*64,container_python="/usr/bin/python3",
            expected_gpg_sha256="8"*64,expected_rpm_sha256="9"*64,
            release_date="Tue, 03 Nov 2026 00:00:00 +0000")
        with patch.object(host,"physical_dir",side_effect=lambda path,label:Path(path)):
            production=host.build_docker_run_argv(cfg,"bridge","owned")
        inspection=sib._make_command_plan("123").probe_argv(cfg.container_image)
        prefix=(entry.PYTHON,"-I","-B",sib.IMAGE_CHECK_DIR+"/container_process_entry.py","--",entry.PYTHON,"-I","-B")
        for argv in (production,inspection):
            start=argv.index(cfg.container_image)+1
            self.assertEqual(argv[start:start+len(prefix)],prefix)
            self.assertNotIn("--init",argv)
            self.assertEqual(entry._target(list(argv[start+4:])),tuple(argv[start+5:]))


class SourceGuardRefusals(unittest.TestCase):
    def test_exact_source_rejects_uid_gid_link_count_and_identity_changes(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TF_TEST_TMP")) as t:
            source=Path(t)/"owned_gpg_agent.py";source.write_bytes((SRC/"owned_gpg_agent.py").read_bytes());source.chmod(0o444)
            native_stat=os.fstat;native_lstat=os.lstat
            fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
            for mutation in ("uid","gid","nlink","identity"):
                def value(info,*,named=False):
                    row={k:getattr(info,k) for k in fields};row.update(st_uid=0,st_gid=0)
                    if mutation=="uid":row["st_uid"]=1001
                    elif mutation=="gid":row["st_gid"]=1001
                    elif mutation=="nlink":row["st_nlink"]=2
                    elif named:row["st_ino"]+=1
                    return types.SimpleNamespace(**row)
                with self.subTest(mutation=mutation),patch.object(os,"fstat",side_effect=lambda fd:value(native_stat(fd))),\
                        patch.object(os,"lstat",side_effect=lambda *a,**k:value(native_lstat(*a,**k),named=True)):
                    with self.assertRaises(check.CheckRefusal):check._source_bytes(source)
            link=source.with_name("link");link.symlink_to(source)
            with self.assertRaises(check.CheckRefusal):check._source_bytes(link)


class DynamicWorkerIdentity(unittest.TestCase):
    def test_entry_accepts_unelevated_dynamic_identity_and_refuses_root_or_elevation(self):
        for uid,gid,euid,egid,accepted_context in (
            (1001,121,1001,121,True),(1234,1234,1234,1234,True),
            (0,121,0,121,False),(1001,0,1001,0,False),
            (1001,121,0,121,False),(1001,121,1001,0,False)):
            with self.subTest(uid=uid,gid=gid,euid=euid,egid=egid),patch.dict(os.environ,{},clear=True),\
                    patch.object(sys,"platform","linux"),patch.object(os,"getpid",return_value=1),\
                    patch.object(os,"getuid",return_value=uid),patch.object(os,"getgid",return_value=gid),\
                    patch.object(os,"geteuid",return_value=euid),patch.object(os,"getegid",return_value=egid),\
                    patch.object(os,"pipe2",return_value=(10,11),create=True),\
                    patch.object(os,"fork",side_effect=RuntimeError("inert fork boundary")) as fork:
                if accepted_context:
                    with self.assertRaises(RuntimeError):entry.enter_noninit(["--",entry.PYTHON,"-I","-B","-c","pass"])
                    fork.assert_called_once()
                else:
                    with self.assertRaises(entry.EntryRefusal):entry.enter_noninit(["--",entry.PYTHON,"-I","-B","-c","pass"])
                    fork.assert_not_called()

    def test_loaded_agent_has_only_stdlib_imports_and_all_fixed_codes_are_covered(self):
        tree=ast.parse((SRC/"owned_gpg_agent.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                self.assertTrue(all(alias.name.split(".")[0] in sys.stdlib_module_names for alias in node.names))
            elif isinstance(node,ast.ImportFrom):
                self.assertEqual(node.level,0);self.assertIn(node.module.split(".")[0],sys.stdlib_module_names)
            elif isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {"_fail","OwnedAgentError"} and node.args:
                literal=node.args[0]
                if isinstance(literal,ast.Constant) and type(literal.value) is str:self.assertIn(literal.value,check._CODES)

if __name__=="__main__":unittest.main()

