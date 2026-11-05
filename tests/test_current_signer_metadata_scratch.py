"""Key-free component reproduction with actual metadata helpers and actual agent guards."""
import importlib.util,json,os,stat,sys,tempfile,types,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
PUBLIC=HERE.parent/"tools/verification/current_signer"
SOURCE=PUBLIC/"repository_metadata_assembly.py"
sys.path.insert(0,str(PUBLIC))
import protected_signing_runtime as runtime_mod
import owned_gpg_agent as agent
spec=importlib.util.spec_from_file_location("metadata_component_under_test",SOURCE)
metadata=importlib.util.module_from_spec(spec);sys.modules[spec.name]=metadata;spec.loader.exec_module(metadata)
class StopBeforeNative(Exception):pass
class BoundaryTests(unittest.TestCase):
 def invoke(self,lane,*,foreign=False,replaced=False,collision=False):
  with tempfile.TemporaryDirectory(dir=HERE) as text:
   root=Path(text);work=root/"work";work.mkdir(mode=0o700)
   home=work/"gnupg";home.mkdir(mode=0o700)
   staging=work/"staging";staging.mkdir(mode=0o700)
   fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
   custody=agent._RetainedCustody(job_fd=fd,job_entries_before=agent._job_entry_snapshot(fd),directories=[agent._Directory(work,fd,agent._ident(os.fstat(fd)))])
   phase="rpm-metadata-create" if lane!="pacman" else "pacman-database-create"
   leaf="metadata-tmp-"+("rpm-"+lane if lane!="pacman" else "pacman")
   if foreign:(work/"unowned").mkdir(mode=0o700)
   if replaced:os.chmod(staging,0o755)
   if collision:(staging/leaf).mkdir(mode=0o700)
   seen=[]
   class Runtime:
    _env=runtime_mod.ProtectedSigningRuntime._env
    def _run(self,argv,**kw):
     agent._check_directories(custody)
     seen.append((argv,kw))
     self_test.assertEqual(kw["phase"],phase)
     tmp=Path(kw["env"]["TMPDIR"])
     self_test.assertEqual(tmp,staging/leaf)
     self_test.assertEqual(stat.S_IMODE(tmp.stat().st_mode),0o700)
     self_test.assertEqual(kw["cwd"],work)
     self_test.assertEqual(set(os.listdir(fd)),set(custody.job_entries_before))
     raise StopBeforeNative()
   self_test=self;rt=Runtime()
   try:
    if collision:
     with self.assertRaises(runtime_mod.ProtectedSigningError) as got:
      metadata._metadata_tool_env(rt,home,staging,"rpm-"+lane)
     self.assertEqual(got.exception.code,"OUTPUT_EXISTS");self.assertEqual(seen,[]);return
    if foreign or replaced:
     with self.assertRaises(agent.OwnedAgentError) as got:
      metadata._rpm_repository(rt,lane,{"inert.rpm":b"PUBLIC INERT FIXTURE"},home,work,staging,root,b"unused")
     self.assertEqual(got.exception.code,"JOB_ROOT_CHANGED");self.assertEqual(seen,[]);return
    with self.assertRaises(StopBeforeNative):
     if lane=="pacman":
      metadata._pacman_repository(rt,{"inert.pkg.tar.zst":b"PUBLIC INERT FIXTURE","inert.pkg.tar.zst.sig":b"PUBLIC INERT SIGNATURE"},home,work,staging,root,b"unused",arch="x86_64")
     else:
      metadata._rpm_repository(rt,lane,{"inert.rpm":b"PUBLIC INERT FIXTURE"},home,work,staging,root,b"unused")
    self.assertEqual(len(seen),1)
   finally:os.close(fd)
 def test_rpm_x86_keeps_job_root_inventory(self):self.invoke("x86_64")
 def test_rpm_arm_keeps_job_root_inventory(self):self.invoke("aarch64")
 def test_pacman_keeps_job_root_inventory(self):self.invoke("pacman")
 def test_foreign_job_root_entry_still_refused(self):self.invoke("x86_64",foreign=True)
 def test_baseline_mode_change_still_refused(self):self.invoke("x86_64",replaced=True)
 def test_existing_metadata_scratch_still_refused(self):self.invoke("x86_64",collision=True)
if __name__=="__main__":unittest.main()
