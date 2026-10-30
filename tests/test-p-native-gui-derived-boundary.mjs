/** Derived identifier/environment/receipt flow only; no subject or host process scan. */
import assert from "node:assert/strict";
import test from "node:test";
import childProcess from "node:child_process";
import fs from "node:fs";
import {syncBuiltinESMExports} from "node:module";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,cpSync,rmSync,realpathSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,dirname} from "node:path";
import {pathToFileURL} from "node:url";
import {derivePinnedGuiHarness,sha256} from "../tools/verification/p-native-gui-adapter.mjs";
import {fixtureObserver} from "./p-native-gui-fixtures.mjs";

for(const simulatedHost of ["darwin","linux"]) {
test("derived runSmoke executes real spawn-boundary scope with an inert bridge on "+simulatedHost,async()=>{
  const sourcePath=process.env.NEBULAR_SMOKE_SOURCE,coreFixture=process.env.NEBULAR_CORE_FIXTURE;
  assert(sourcePath&&coreFixture,"authenticated smoke source and core fixture must be selected");
  const original=readFileSync(sourcePath),sourceSha=sha256(original);
  assert.equal(sourceSha,"874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69");
  const temporary=realpathSync(mkdtempSync(join(tmpdir(),"p-gui-derived-boundary-")));
  const home=join(temporary,"owner-home"),temp=join(temporary,"owner-temp"),checkout=join(temporary,"fixture-checkout");
  for(const path of [home,temp,checkout])mkdirSync(path,{mode:0o700});
  const data=join(checkout,"docs/examples/v0.4/brand-system/core-minimal");
  mkdirSync(dirname(data),{recursive:true});cpSync(coreFixture,data,{recursive:true});
  const launchRoot=join(temporary,"payload"),executable=join(launchRoot,"Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion");
  mkdirSync(dirname(executable),{recursive:true});writeFileSync(executable,"owned inert executable fixture",{mode:0o755});
  const measured=readFileSync(executable),expectedApp={path:executable,sha256:sha256(measured),size:measured.length};
  const outputDir=join(temporary,"derived"),evidence=join(temporary,"evidence");
  mkdirSync(outputDir,{mode:0o700});mkdirSync(evidence,{mode:0o700});
  const python="/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-python/bin/python3.13";
  const publicWrapper="/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-product/bin/tfnf";
  const observer=fixtureObserver(publicWrapper,python);
  const binding={pCommit:"a".repeat(40),pTree:"b".repeat(40),nebularCommit:"c".repeat(40),nebularTree:"d".repeat(40),
    rawExecutable:expectedApp,publicWrapper:{path:publicWrapper,sha256:observer.expectedSha256,size:Buffer.byteLength(observer.declaredText)},
    monitor:{executable:{path:observer.context.bwrap,sha256:"8".repeat(64),size:3}},
    controller:{python,scriptSha256:"9".repeat(64)},
    predicateHelper:{path:"/fixture/predicate.py",sha256:"1".repeat(64),size:3},
    bridgeSha256:"2".repeat(64),resolverSha256:"3".repeat(64),launchObserver:observer};
  writeFileSync(join(outputDir,"stub-bridge.mjs"),readFileSync(new URL("./fixtures/p-native-gui-inert-bridge.mjs",import.meta.url)),{mode:0o600});
  writeFileSync(join(outputDir,"fixture-inputs.json"),JSON.stringify({publicWrapper,expectedApp,ownerTemp:temp,evidence,
    upstreamSourceUrl:pathToFileURL(sourcePath).href}),{mode:0o600});
  const derived=derivePinnedGuiHarness(original,sourceSha,binding,"./stub-bridge.mjs",dirname(sourcePath));
  const target=join(outputDir,"native-rc-smoke.p-native-gui.mjs");writeFileSync(target,derived.adapted,{mode:0o600});
  const priorHome=process.env.HOME,priorTmp=process.env.TMPDIR,priorSpawnSync=childProcess.spawnSync;
  const priorReaddirSync=fs.readdirSync;
  const priorPlatform=Object.getOwnPropertyDescriptor(process,"platform");
  let processScans=0,psScans=0,procScans=0;
  try{
    process.env.HOME=home;process.env.TMPDIR=temp;
    Object.defineProperty(process,"platform",{...priorPlatform,value:simulatedHost});
    childProcess.spawnSync=(command,args)=>{assert.equal(command,"ps");assert.deepEqual(args,["-axww","-o","pid=,command="]);
      processScans++;psScans++;return{status:0,signal:null,stdout:"",stderr:""};};
    fs.readdirSync=(path,...args)=>{
      if(path==="/proc"){processScans++;procScans++;return [];}
      return priorReaddirSync(path,...args);
    };
    syncBuiltinESMExports();
    const module=await import(pathToFileURL(target).href);
    assert(module.persistentStateLocations("darwin-arm64").every(path=>path.startsWith(home+"/")));
    const result=await module.runSmoke({platform:"darwin-arm64",scenario:"A",source:"raw-archive",
      launchRoot,checkout,evidenceDir:evidence,label:"fixture-derived-A"});
    assert.equal(result.status,"pass",JSON.stringify(result.problems));
    const bridge=await import(pathToFileURL(join(outputDir,"stub-bridge.mjs")).href);
    assert.deepEqual(bridge.calls,{spawn:1,bind:1,finalize:1});assert(processScans>=2);
    if(simulatedHost==="darwin"){assert(psScans>=2);assert.equal(procScans,0);}
    else{assert(procScans>=2);assert.equal(psScans,0);}
    assert.equal(sha256(readFileSync(sourcePath)),sourceSha);
    const receipt=JSON.parse(readFileSync(join(evidence,"fixture-derived-A.receipt.json")));
    assert.equal(receipt.pid,303);assert.equal(receipt.status,"pass");
  }finally{
    childProcess.spawnSync=priorSpawnSync;fs.readdirSync=priorReaddirSync;syncBuiltinESMExports();
    Object.defineProperty(process,"platform",priorPlatform);
    if(priorHome===undefined)delete process.env.HOME;else process.env.HOME=priorHome;
    if(priorTmp===undefined)delete process.env.TMPDIR;else process.env.TMPDIR=priorTmp;
    rmSync(temporary,{recursive:true,force:true});
  }
});
}
