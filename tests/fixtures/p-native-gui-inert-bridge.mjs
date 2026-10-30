/** Inert derived-body fixture only. Never used by the production bridge or workflow. */
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {PassThrough} from "node:stream";
import {readFileSync,writeFileSync} from "node:fs";
import {join} from "node:path";
const config=JSON.parse(readFileSync(new URL("./fixture-inputs.json",import.meta.url)));
const {SCENARIOS}=await import(config.upstreamSourceUrl);
export const calls={spawn:0,bind:0,finalize:0};
export async function spawnGuiBound(value) {
  calls.spawn++;
  assert.equal(value.launchTarget,config.publicWrapper);
  assert.deepEqual(value.args,["--nebular-release-smoke=A"]);
  assert.equal(value.platform,"darwin-arm64");assert.equal(value.scenario,"A");
  assert.deepEqual(value.expectedApp,config.expectedApp);
  assert.equal(value.options.cwd,value.options.env.HOME);
  assert.equal(value.options.detached,true);assert.deepEqual(value.options.stdio,["ignore","pipe","pipe"]);
  for(const key of ["HOME","TMPDIR","XDG_CONFIG_HOME","XDG_CACHE_HOME","XDG_DATA_HOME","XDG_STATE_HOME","XDG_RUNTIME_DIR"])
    assert(value.options.env[key].startsWith(config.ownerTemp));
  assert.equal(value.options.env.TFNF_RELEASE_SMOKE_DIR,value.smokeDir);
  assert.equal(value.options.env.LANG,"C.UTF-8");assert.equal(value.options.env.LC_ALL,"C.UTF-8");
  assert.equal(value.options.env.TZ,"UTC");assert.equal(value.options.env.GSETTINGS_BACKEND,"memory");
  for(const key of ["PWD","NODE_OPTIONS","NODE_PATH","LD_LIBRARY_PATH"])assert(!Object.hasOwn(value.options.env,key));
  assert.equal(value.controllerEvidenceDir,config.evidence);assert.equal(value.label,"fixture-derived-A");
  const receipt={schema:"nebular.release-smoke-receipt-v1",scenario:"A",target:"aarch64-apple-darwin",pid:303,
    status:"pass",awaitingSignal:false,executable:{sha256:value.expectedApp.sha256},
    driver:{scenario:"A",status:"pass",steps:SCENARIOS.A.steps.map(id=>({id,ok:true}))}};
  writeFileSync(join(value.smokeDir,"receipt.json"),JSON.stringify(receipt),{mode:0o600});
  const child=new EventEmitter();child.pid=303;child.exitCode=0;child.signalCode=null;
  child.stdout=new PassThrough();child.stderr=new PassThrough();
  return {child,monitorExit:Promise.resolve({code:0,signal:null}),applicationPid:()=>303,
    bindApplication:async()=>{calls.bind++;},finalize:async()=>{calls.finalize++;},
    abortFailure:async()=>{throw Error("unexpected fixture abort");},
    terminateApplication:async()=>{throw Error("unexpected signal");}};
}
