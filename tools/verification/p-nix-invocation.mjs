import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, lstatSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export function nixBuildArguments(root,system,attribute,outLink) {
  return ['build',`path:${root}#packages.${system}.${attribute}`,'--no-update-lock-file','--out-link',outLink];
}

export function nixCheckArguments(root) {
  return ['flake','check','path:'+root,'--no-update-lock-file','-L'];
}

export function createOutLinkWorkDirectory(evidence,{mode,runnerTemp=process.env.RUNNER_TEMP}={}) {
  const actual=resolve(evidence),parent=dirname(actual);
  const info=lstatSync(actual);assert(info.isDirectory() && !info.isSymbolicLink(),'Physical evidence directory required');
  if(mode==='native-hosted') {
    assert(typeof runnerTemp==='string' && runnerTemp.length>0,'Hosted RUNNER_TEMP required');
    assert.equal(realpathSync(parent),realpathSync(runnerTemp),'Evidence must be a direct child of RUNNER_TEMP');
  } else assert.equal(mode,'fixture');
  const work=mkdtempSync(join(realpathSync(parent),'p-nix-work-'));
  assert.equal(dirname(work),realpathSync(parent));assert.notEqual(work,realpathSync(actual));
  return work;
}
