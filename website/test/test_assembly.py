from pathlib import Path
import copy,hashlib,importlib.util,io,json,os,tarfile,tempfile,unittest
from unittest.mock import patch
root=Path(__file__).resolve().parents[1]
path=root/'tools/assemble-pages.py'
spec=importlib.util.spec_from_file_location('assembly',path);assembly=importlib.util.module_from_spec(spec);spec.loader.exec_module(assembly)
inventory=json.loads((root/'protected-inventory.json').read_text())
class AssemblyTests(unittest.TestCase):
 def test_archive_refuses_protected_mutation_after_tree_verification(self):
  with tempfile.TemporaryDirectory(prefix='site-proof-',dir=root) as temporary:
   p=Path(temporary);out=p/'public';out.mkdir();body=b'original-public-bytes'
   assembly.write_new(out,'apt/a.bin',body)
   entries={'apt/a.bin':{'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}}
   assembly.verify_protected(out,entries)
   (out/'apt/a.bin').write_bytes(b'replaced-public-bytes')
   with self.assertRaisesRegex(assembly.Refused,'ARCHIVE_PROTECTED_MEMBER_CHANGED'):
    assembly.archive_exact(out,['apt/a.bin'],p/'refused.tar',entries)
 def test_redirects_cannot_downgrade_or_send_api_authority_elsewhere(self):
  handler=assembly.SameOriginRedirect();request=assembly.urllib.request.Request('https://api.github.com/repos/Knowledge-Forge-AI/theme-forge-packages/deployments?environment=github-pages')
  for target in ['http://api.github.com/repos/Knowledge-Forge-AI/theme-forge-packages/deployments','https://other.test/','https://api.github.com/repos/other/private/deployments']:
   with self.subTest(target=target),self.assertRaises(assembly.Refused):handler.redirect_request(request,None,302,'redirect',{},target)
 def test_exact_published_inventory_is_admitted(self):
  self.assertEqual(len(assembly.validate_inventory(copy.deepcopy(inventory))),75)
 def test_collision_or_unknown_namespace_is_rejected(self):
  for bad in ('index.html','website/main.js','other/a.bin','/apt/a.bin','apt/../a.bin','apt/DB/a.bin'):
   data=copy.deepcopy(inventory);value=data.pop(next(iter(data)));data[bad]=value
   with self.subTest(path=bad),self.assertRaises(assembly.Refused):assembly.validate_inventory(data)
 def test_member_count_size_digest_and_total_are_bound(self):
  for field,value in [('bytes',-1),('bytes',True),('bytes',128*1024*1024+1),('sha256','x'*64),('bytes',123)]:
   data=copy.deepcopy(inventory);data[next(iter(data))][field]=value
   with self.subTest(field=field,value=value),self.assertRaises(assembly.Refused):assembly.validate_inventory(data)
  data=copy.deepcopy(inventory);data.pop(next(iter(data)))
  with self.assertRaises(assembly.Refused):assembly.validate_inventory(data)
 def test_protected_bytes_are_rechecked_after_website_addition(self):
  with tempfile.TemporaryDirectory(prefix='site-proof-',dir=root) as temporary:
   p=Path(temporary);body=b'original-public-bytes';assembly.write_new(p,'apt/package.bin',body)
   entries={'apt/package.bin':{'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}}
   assembly.write_new(p,'index.html',b'new website');assembly.verify_protected(p,entries)
   (p/'apt/package.bin').write_bytes(b'replaced-public-bytes')
   with self.assertRaises(assembly.Refused):assembly.verify_protected(p,entries)
 def test_archive_uses_neutral_metadata_and_exact_allowlist(self):
  with tempfile.TemporaryDirectory(prefix='site-proof-',dir=root) as temporary:
   p=Path(temporary);out=p/'public';out.mkdir();assembly.write_new(out,'index.html',b'page');assembly.write_new(out,'apt/a.bin',b'public')
   dest=p/'out.tar';assembly.archive_exact(out,['index.html','apt/a.bin'],dest)
   with tarfile.open(dest) as archive:
    self.assertEqual(archive.getnames(),['.','./apt','./apt/a.bin','./index.html'])
    for member in archive:
     self.assertEqual((member.uid,member.gid,member.mtime,member.uname,member.gname,member.mode),(0,0,0,'','',0o755 if member.isdir() else 0o644))
   assembly.write_new(out,'unknown.bin',b'unknown')
   with self.assertRaises(assembly.Refused):assembly.archive_exact(out,['index.html','apt/a.bin'],p/'refused.tar')
 def test_archive_has_ancestor_entries_and_gnu_long_paths(self):
  with tempfile.TemporaryDirectory(prefix='site-proof-',dir=root) as temporary:
   p=Path(temporary);out=p/'public';out.mkdir();name='apt/dists/resolute/main/binary-arm64/by-hash/SHA256/'+'a'*64;body=b'exact-public-index'
   assembly.write_new(out,name,body);entries={name:{'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}}
   dest=p/'out.tar';assembly.archive_exact(out,[name],dest,entries)
   raw=dest.read_bytes();offset=0;long_headers=0
   while offset+512<=len(raw) and raw[offset:offset+512]!=bytes(512):
    header=raw[offset:offset+512];size=int(header[124:136].strip(b'\0 '),8)
    self.assertEqual(header[345:500],bytes(155))
    if header[156:157]==b'L':
     self.assertEqual(header[:100].split(b'\0',1)[0],b'././@LongLink');long_headers+=1
    offset+=512+((size+511)//512)*512
   self.assertGreater(long_headers,0)
   with tarfile.open(dest) as tar:
    prior=set()
    for member in tar:
     canonical=member.name.removeprefix('./')
     if member.name=='.':canonical=''
     parent=canonical.rsplit('/',1)[0] if '/' in canonical else ''
     if canonical:self.assertIn(parent,prior)
     if member.isdir():prior.add(canonical)
     else:self.assertEqual(tar.extractfile(member).read(),body);self.assertEqual(canonical,name)
   (out/'unknown-empty').mkdir()
   with self.assertRaisesRegex(assembly.Refused,'OUTPUT_DIRECTORY_INVENTORY'):assembly.archive_exact(out,[name],p/'refused.tar',entries)
 def test_links_and_hardlinks_are_not_read_or_archived(self):
  with tempfile.TemporaryDirectory(prefix='site-proof-',dir=root) as temporary:
   p=Path(temporary);out=p/'public';out.mkdir();assembly.write_new(out,'index.html',b'page')
   (out/'foreign').symlink_to(p,target_is_directory=True)
   with self.assertRaises(assembly.Refused):assembly.archive_exact(out,['index.html'],p/'out.tar')
   os.link(out/'index.html',p/'hardlink')
   with self.assertRaises(assembly.Refused):assembly.read_regular(p/'hardlink',100)
 def test_wrong_repository_cname_stops_before_api_or_network(self):
  with patch.object(assembly,'admit_previous_deployment',side_effect=AssertionError('unexpected API')):
   with self.assertRaisesRegex(assembly.Refused,'CNAME_DOMAIN'):
    assembly.assemble('release-starport-9',root,root/'never-created-site',root/'never-created-site.tar')
 def test_unknown_and_failed_publishers_stop(self):
  for deployment,statuses in [({'id':1,'ref':'staging','sha':'a'*40},[]),({'id':1,'ref':'main','sha':'a'*40},[{'state':'failure'}]),({'id':1,'ref':'main','sha':'a'*40},[{'state':'success','log_url':'https://example.test/other'}])]:
   def api(repository,suffix):return [deployment] if suffix.startswith('deployments?') else statuses
   with self.subTest(deployment=deployment,statuses=statuses),patch.object(assembly,'api',api),self.assertRaises(assembly.Refused):assembly.admit_previous_deployment('theme-forge-packages')
 def test_initial_starport_requires_explicit_https_404(self):
  with patch.object(assembly,'api',return_value=[]):
   with patch.object(assembly,'fetch',side_effect=assembly.urllib.error.HTTPError('https://rs9.knowledge-forge.ai/',404,'Not found',{},None)):
    self.assertEqual(assembly.admit_previous_deployment('release-starport-9')['kind'],'initial-project-site')
   for code in (403,503):
    with patch.object(assembly,'fetch',side_effect=assembly.urllib.error.HTTPError('https://rs9.knowledge-forge.ai/',code,'Unknown',{},None)),self.assertRaises(assembly.Refused):assembly.admit_previous_deployment('release-starport-9')
   with patch.object(assembly,'fetch',return_value=b'already served'),self.assertRaises(assembly.Refused):assembly.admit_previous_deployment('release-starport-9')
   with self.assertRaises(assembly.Refused):assembly.admit_previous_deployment('theme-forge-packages')
 def test_known_production_and_prior_website_publishers_are_bound(self):
  dep={'id':7688464725,'ref':'main','sha':assembly.INITIAL_PACKAGE_SOURCE}
  statuses=[{'state':'success','log_url':'https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/42859410403/job/129981612851'}]
  with patch.object(assembly,'api',side_effect=lambda repo,suffix:[dep] if suffix.startswith('deployments?') else statuses):
   self.assertEqual(assembly.admit_previous_deployment('theme-forge-packages')['kind'],'qualified-package-publication')
  dep['id']=123;dep['sha']='a'*40;statuses[0]['log_url']='https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/123/job/456'
  run={'path':'.github/workflows/project-pages.yml','head_branch':'main','conclusion':'success','head_sha':'a'*40}
  def api(repository,suffix):return run if suffix.startswith('actions/') else ([dep] if suffix.startswith('deployments?') else statuses)
  with patch.object(assembly,'api',api):
   self.assertEqual(assembly.admit_previous_deployment('theme-forge-packages')['kind'],'prior-website-publication')
   run['path']='.github/workflows/publish.yml'
   with self.assertRaises(assembly.Refused):assembly.admit_previous_deployment('theme-forge-packages')
 def recovery_fixture(self):
  history=[{'id':7709348450,'sha':assembly.FAILED_WEBSITE_SOURCE,'ref':'main'},{'id':7704763715,'sha':assembly.FAILED_WEBSITE_SOURCE,'ref':'main'},{'id':assembly.INITIAL_PACKAGE_DEPLOYMENT,'sha':assembly.INITIAL_PACKAGE_SOURCE,'ref':'main'}]
  statuses={identifier:[{'state':state,'log_url':'https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/'+str(run)+'/job/'+str(job)}] for identifier,state,run,job in ((7709348450,'failure',42982720952,130505789335),(7704763715,'failure',42982720952,130396788604),(assembly.INITIAL_PACKAGE_DEPLOYMENT,'success',42859410403,129981612851))}
  run={'id':assembly.FAILED_WEBSITE_RUN,'path':'.github/workflows/project-pages.yml','head_branch':'main','head_sha':assembly.FAILED_WEBSITE_SOURCE,'status':'completed','conclusion':'failure','run_attempt':2}
  def api(repository,suffix):
   if suffix.startswith('actions/'):return run
   if suffix.startswith('deployments?'):return history if suffix.endswith('=3') else history[:1]
   return statuses[int(suffix.split('/')[1])]
  return history,statuses,run,api
 def test_only_exact_two_failed_attempts_above_the_original_publication_can_recover(self):
  history,statuses,run,api=self.recovery_fixture()
  with patch.object(assembly,'api',api):
   result=assembly.admit_previous_deployment('theme-forge-packages');self.assertEqual(result['kind'],'exact-failed-website-recovery');self.assertEqual(result['lastSuccessfulDeployment'],assembly.INITIAL_PACKAGE_DEPLOYMENT)
   with self.assertRaisesRegex(assembly.Refused,'FAILED_WEBSITE_SCOPE'):assembly.admit_previous_deployment('release-starport-9')
 def test_failed_recovery_refuses_foreign_changed_missing_or_ongoing_history(self):
  mutations=[lambda h,s,r:h.pop(),lambda h,s,r:h.reverse(),lambda h,s,r:h[1].update(sha='a'*40),lambda h,s,r:h[2].update(id=1),lambda h,s,r:s[7704763715][0].update(state='in_progress'),lambda h,s,r:s[7709348450][0].update(log_url='https://example.test/foreign'),lambda h,s,r:r.update(run_attempt=3),lambda h,s,r:r.update(conclusion='success'),lambda h,s,r:r.update(head_sha='b'*40),lambda h,s,r:r.update(path='.github/workflows/publish.yml')]
  for index,mutate in enumerate(mutations):
   history,statuses,run,api=self.recovery_fixture();latest=copy.deepcopy(history[0]);mutate(history,statuses,run)
   with self.subTest(index=index),patch.object(assembly,'api',api),self.assertRaises(assembly.Refused):assembly.admit_known_failed_website('theme-forge-packages',latest)
if __name__=='__main__':unittest.main()
