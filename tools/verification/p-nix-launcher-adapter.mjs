/** P-owned test-only adapter. The pinned upstream source is never overwritten. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, lstatSync, readlinkSync, realpathSync } from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SPAWN_ANCHOR='spawn(launchTarget, [`--nebular-release-smoke=${scenario}`]';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');

export function measurePublicWrapper(wrapper) {
  const chain=[];let current=wrapper;
  for(let depth=0;depth<40;depth++) {
    assert(current.startsWith('/nix/store/'),'Public wrapper chain must remain in the materialized Nix store');
    const info=lstatSync(current);
    assert(info.isFile()||info.isSymbolicLink(),'Regular public wrapper or declared symlink required');
    const target=info.isSymbolicLink()?readlinkSync(current):null;
    chain.push({path:current,type:info.isSymbolicLink()?'symlink':'file',mode:info.mode&0o777,target});
    if(!target)return {path:wrapper,sha256:hash(readFileSync(wrapper)),resolvedPath:realpathSync(wrapper),chain};
    current=resolve(dirname(current),target);
  }
  throw new Error('Public wrapper symlink chain exceeds bound');
}

export function adaptPinnedHarness(original, wrapper, expectedOriginalSha256) {
  const originalBytes=Buffer.from(original);
  assert.equal(hash(originalBytes),expectedOriginalSha256,'Pinned upstream smoke source changed');
  assert.equal(resolve(wrapper),wrapper,'Canonical absolute public wrapper path required');
  assert.equal(basename(wrapper),'tfnf');
  assert(!/[\u0000-\u001f\u007f]/.test(wrapper));
  const text=originalBytes.toString('utf8');
  assert.equal(text.split(SPAWN_ANCHOR).length,2,'Exactly one supported upstream process-spawn boundary required');
  const replacement='spawn('+JSON.stringify(wrapper)+', [`--nebular-release-smoke=${scenario}`]';
  const adapted=text.replace(SPAWN_ANCHOR,replacement);
  const before=text.split('\n'),after=adapted.split('\n');
  assert.equal(before.length,after.length);
  const changed=before.flatMap((line,index)=>line===after[index]?[]:[index]);
  assert.equal(changed.length,1,'Only one spawn-target line may change');
  const line=changed[0];
  assert.equal(after[line].replace(replacement,SPAWN_ANCHOR),before[line]);
  const diff='--- upstream/tools/native-rc-smoke.mjs\n+++ p-test-only/native-rc-smoke.p-nix-wrapper.mjs\n'
    +`@@ -${line+1},1 +${line+1},1 @@\n-${before[line]}\n+${after[line]}\n`;
  return {adapted,diff,originalSha256:hash(originalBytes),adaptedSha256:hash(adapted),
    adaptationDiffSha256:hash(diff),changedLine:line+1,spawnLine:after[line],
    provenance:'P-owned test-only single process-spawn target adaptation; not unchanged upstream source'};
}

export function preparePublicWrapperHarness({checkout,wrapper,evidence,contract,derivationsSha256,closureSha256,outputs,rawPayloadRoot}) {
  assert(/^\/nix\/store\/[a-z0-9]{32}-[^/]+\/bin\/tfnf$/.test(wrapper),'Exact materialized P Nix public wrapper required');
  const originalPath=join(checkout,'tools/native-rc-smoke.mjs');
  const expected=contract.nebularSource.files['tools/native-rc-smoke.mjs'].sha256;
  const original=readFileSync(originalPath);
  const adaptation=adaptPinnedHarness(original,wrapper,expected);
  const wrapperInfo=lstatSync(wrapper);assert(wrapperInfo.isFile()||wrapperInfo.isSymbolicLink());
  const wrapperBytes=readFileSync(wrapper);
  const wrapperIdentity=measurePublicWrapper(wrapper);
  const adaptedPath=join(checkout,'tools/native-rc-smoke.p-nix-wrapper.mjs');
  // Adding this disclosed derived module preserves its original relative imports.
  writeFileSync(adaptedPath,adaptation.adapted,{flag:'wx',mode:0o644});
  assert.equal(hash(readFileSync(originalPath)),expected,'Upstream input must remain byte-identical');
  const record={schema:'theme-forge.p-nix-test-launcher-adapter.v1',
    provenance:adaptation.provenance,transform:'p-single-spawn-target-v1',
    adapterCodeSha256:hash(readFileSync(fileURLToPath(import.meta.url))),
    upstreamCommit:contract.nebularSource.commit,upstreamTree:contract.nebularSource.tree,
    originalSource:'tools/native-rc-smoke.mjs',originalSourceSha256:adaptation.originalSha256,
    adaptedSource:'tools/native-rc-smoke.p-nix-wrapper.mjs',adaptedSourceSha256:adaptation.adaptedSha256,
    adaptationDiffSha256:adaptation.adaptationDiffSha256,changedLine:adaptation.changedLine,
    publicWrapperPath:wrapper,publicWrapperSha256:hash(wrapperBytes),publicWrapperType:wrapperInfo.isSymbolicLink()?'symlink':'file',
    publicWrapperLinkTarget:wrapperInfo.isSymbolicLink()?readlinkSync(wrapper):null,
    publicWrapperResolvedPath:realpathSync(wrapper),publicWrapperIdentity:wrapperIdentity,
    rawPayloadRoot,outputs,derivationsSha256,closureSha256,
    rawPayloadAndLauncherChecks:'unchanged upstream checks against installed raw root',
    pidReceiptAndSignalChecks:'unchanged upstream child.pid equality and app-only C-signal target',
    productionEnabled:false,publicationAuthority:false};
  writeFileSync(join(evidence,'p-test-adaptation.diff'),adaptation.diff);
  writeFileSync(join(evidence,'p-test-adapted-harness.mjs'),adaptation.adapted);
  writeFileSync(join(evidence,'p-test-adapter-binding.json'),JSON.stringify(record,null,2)+'\n');
  return {adaptedPath,record};
}
