import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export function executionModeFor(run=spawnSync,spawnService=spawn) {
  return run===spawnSync && spawnService===spawn?'native-hosted':'fixture';
}

export function hostedFacts(mode,env=process.env) {
  assert(['native-hosted','fixture'].includes(mode));
  const facts={githubActions:env.GITHUB_ACTIONS??null,repository:env.GITHUB_REPOSITORY??null,
    sourceSha:env.GITHUB_SHA??null,runId:env.GITHUB_RUN_ID??null,runAttempt:env.GITHUB_RUN_ATTEMPT??null,
    workflow:env.GITHUB_WORKFLOW??null,workflowRef:env.GITHUB_WORKFLOW_REF??null,
    workflowSha:env.GITHUB_WORKFLOW_SHA??null,runnerOs:env.RUNNER_OS??null,runnerArch:env.RUNNER_ARCH??null,
    runnerEnvironment:env.RUNNER_ENVIRONMENT??null};
  if(mode==='native-hosted') {
    assert.equal(facts.githubActions,'true');assert.equal(facts.repository,'Knowledge-Forge-AI/theme-forge-packages');
    assert(/^[a-f0-9]{40}$/.test(facts.sourceSha??''));assert(/^[a-f0-9]{40}$/.test(facts.workflowSha??''));
    assert(/^[1-9][0-9]*$/.test(facts.runId??''));assert(/^[1-9][0-9]*$/.test(facts.runAttempt??''));
    assert(typeof facts.workflow==='string' && facts.workflow.length>0);
    assert(facts.workflowRef?.startsWith('Knowledge-Forge-AI/theme-forge-packages/.github/workflows/validate.yml@'));
    assert(['Linux','macOS'].includes(facts.runnerOs));assert(['X64','ARM64'].includes(facts.runnerArch));
    assert.equal(facts.runnerEnvironment,'github-hosted');
  }
  return {...facts,executionMode:mode,fixtureMode:mode==='fixture',admitting:mode==='native-hosted'};
}

export function admissionFields(mode) {
  assert(['native-hosted','fixture'].includes(mode));
  return {executionMode:mode,fixtureMode:mode==='fixture',accepted:mode==='native-hosted',
    qualificationStatus:mode==='native-hosted'?'native-candidate-qualified':'fixture-only-non-admitting',
    productionEnabled:false,publicationAuthority:false};
}

export function bindScenarioFiles(evidence,scenario,platform) {
  const scenarios={'darwin-arm64':['A'],'linux-arm64':['B'],'linux-x64':['C','C-signal']};
  assert(scenarios[platform]?.includes(scenario),'Invalid adapted scenario/platform');
  const label='p-nix-public-wrapper-'+scenario;
  const result={scenario,role:'P-adapted-public-wrapper'};
  for(const [kind,suffix] of [['run','run.json'],['receipt','receipt.json']]) {
    const relativePath='public-wrapper-gui/'+label+'.'+suffix;const path=join(evidence,relativePath);
    const info=lstatSync(path);assert(info.isFile() && !info.isSymbolicLink());
    const bytes=readFileSync(path),value=JSON.parse(bytes);
    assert.equal(value.scenario,scenario);assert.equal(value.status,'pass');
    if(kind==='run')assert.equal(value.platform,platform);
    result[kind]={path:relativePath,sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length};
  }
  return result;
}

export function bindRawLauncher(launchRoot,system,pins) {
  assert(['aarch64-darwin','aarch64-linux','x86_64-linux'].includes(system));
  const darwin=system==='aarch64-darwin';
  const path=darwin?'Contents/Resources/bin/tfnf':'bin/tfnf';
  const full=darwin?join(launchRoot,'Theme Forge Nebular Fusion.app',path):join(launchRoot,path);
  const info=lstatSync(full);assert(info.isFile() && !info.isSymbolicLink());
  const bytes=readFileSync(full);const sha256=createHash('sha256').update(bytes).digest('hex');
  assert.equal(sha256,pins[path],'Installed raw launcher differs from current release pin');
  return {path,sha256,bytes:bytes.length};
}
