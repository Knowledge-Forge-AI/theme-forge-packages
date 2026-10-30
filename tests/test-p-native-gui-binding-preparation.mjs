import assert from "node:assert/strict";
import test from "node:test";
import {readFileSync,mkdtempSync,writeFileSync,symlinkSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {fileURLToPath} from "node:url";
import {join,resolve} from "node:path";
import {prepareNativeGuiBinding,qualificationPlan,guiProfileFor,runNativeRoute,retainNixCheckFailure} from "../tools/verification/qualify-p-current-nix.mjs";
import {validateContext,validateFreshLaunchFacts,validateObserverInputs,controllerBindMessage,spawnGuiBound,CONTROLLER_TERMINATE_WAIT_MS} from "../tools/verification/p-native-gui-controller-bridge.mjs";
import {isFreshLaunchBinding,freezeLaunchInputs} from "../tools/verification/p-native-gui-launch-binding.mjs";
import {fixtureObserver,fixtureFacts,digest,sha} from "./p-native-gui-fixtures.mjs";
const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const wrapper="/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-product/bin/tfnf";
const python="/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-python/bin/python3.13";
const contextPath="/nix/store/cccccccccccccccccccccccccccccccc-p-predicate-context.json";
const evidence="/fixture/evidence",raw="/fixture/raw/bin/theme-forge-nebular-fusion";
const pSource={commit:"a".repeat(40),tree:"b".repeat(40)};
function fixture({contextMutation=()=>{},observerMutation=()=>{}}={}) {
  const observer=fixtureObserver(wrapper,python);observerMutation(observer);
  const context={python};contextMutation(context);
  const calls=[];
  const read=(path,encoding)=>{
    let value;
    if(path===contextPath)value=Buffer.from(JSON.stringify(context));
    else if(path===join(evidence,"p-native-gui-observer-inputs.json"))value=Buffer.from(JSON.stringify(observer));
    else if(path===wrapper)value=Buffer.from(observer.declaredText);
    else if(path===raw)value=Buffer.from("raw");
    else if(path===observer.context.bwrap)value=Buffer.from("bwrap");
    else value=readFileSync(path);
    return encoding?value.toString(encoding):value;
  };
  const checked=(command,args)=>{calls.push({command,args});return command==="nix"?contextPath+"\n":"";};
  return {observer,calls,run:()=>prepareNativeGuiBinding({root,system:"x86_64-linux",wrapper,evidence,
    rawExecutable:raw,closurePath:join(evidence,"p-runtime-closure.json"),pSource,checked,read})};
}
test("real binding constructor uses exact context and locked Python with complete source closure",()=>{
  const value=fixture(),prepared=value.run(),binding=prepared.guiBinding;
  assert.deepEqual(value.calls[0],{command:"nix",args:["build","--no-update-lock-file","--no-link","--print-out-paths",
    root+"#testTools.x86_64-linux.predicateContext"]});
  assert.deepEqual(value.calls[1],{command:python,args:["-I","-S",join(root,"tools/verification/p-native-gui-prepare-context.py"),
    root,"x86_64-linux",contextPath,wrapper,join(evidence,"p-runtime-closure.json"),join(evidence,"p-native-gui-observer-inputs.json")]});
  assert.equal(binding.pCommit,pSource.commit);assert.equal(binding.pTree,pSource.tree);
  assert.equal(binding.launchObserver.publicationAuthority,false);
  assert.equal(binding.monitor.executable.path,value.observer.context.bwrap);
  assert.equal(binding.launchObserver.wrapperPath,wrapper);
  assert.equal(binding.resolverSha256.length,64);
  assert.equal(Object.keys(prepared.controllerSources).length,5);
  assert.doesNotThrow(()=>validateContext({schema:"theme-forge.p-native-gui-context.v1",
    transform:"p-linux-gui-controller-v1",...binding}));
});
test("binding preparation refuses unpinned Python; observer validation rejects source and context drift",()=>{
  assert.throws(()=>fixture({contextMutation:value=>{value.python="/usr/bin/python3";}}).run(),/locked observer Python/);
  const binding=fixture().run().guiBinding;
  for(const corrupt of [
    value=>{value.expectedSha256="0".repeat(64);},
    value=>{value.nixpkgsRevision="0".repeat(40);},
    value=>{value.python="/usr/bin/python3";},
    value=>{value.extra=true;},
    value=>{value.declaredText+="\n";},
  ]){
    const bad=structuredClone(binding.launchObserver);corrupt(bad);
    assert.throws(()=>validateObserverInputs(bad,binding.publicWrapper,binding.controller.python));
  }
});
test("same-run record facts join exact wrapper and smoke request without minting a resolver capability",()=>{
  const binding=fixture().run().guiBinding;
  const context={schema:"theme-forge.p-native-gui-context.v1",transform:"p-linux-gui-controller-v1",...binding};
  const facts=fixtureFacts(context,"C");
  assert.equal(validateFreshLaunchFacts(facts,context,"C"),facts.bindingSha256);
  assert.equal(isFreshLaunchBinding({facts},freezeLaunchInputs({args:["--nebular-release-smoke=C"],cwd:"/fixture/home",env:{}})),false);
  for(const corrupt of [
    value=>{value.fixtureMode=true;},
    value=>{value.source.wrapperSha256="0".repeat(64);},
    value=>{value.wrapperPublicPathSha256="0".repeat(64);},
    value=>{value.stdoutEOF=false;},
    value=>{value.observerExitCode=1;},
    value=>{value.smokeArgumentsSha256="0".repeat(64);},
    value=>{value.argvCount=8193;},
  ]){
    const bad=structuredClone(facts);delete bad.bindingSha256;corrupt(bad);bad.bindingSha256=digest(bad);
    assert.throws(()=>validateFreshLaunchFacts(bad,context,"C"));
  }
});

test("bind wire constructor accepts bounded fresh vectors and refuses oversized requests before spawn",()=>{
  const {guiBinding:context}=fixture().run();
  const make=argv=>controllerBindMessage({nonce:"1".repeat(32),nodePid:101,monitorPid:Number.MAX_SAFE_INTEGER,
    monitor:{executable:context.monitor.executable,argv},expectedApp:context.rawExecutable,context,
    platform:"linux-x64",scenario:"C",smokeDir:"/fixture/smoke",launchBindingSha256:"9".repeat(64)});
  assert.equal(make(Array(129).fill("x")).monitor.argv.length,129);
  assert.equal(make(Array(8192).fill("x")).monitor.argv.length,8192);
  assert.throws(()=>make(Array(8193).fill("x")),/argv count/);
  assert.throws(()=>make(Array(100).fill("x".repeat(1000))),/wire bound/);
  assert.throws(()=>make(["x\n"]),/control bytes/);
  assert.throws(()=>make([""]),/nonempty/);
});

test("bridge permits a public symlink to reach bounded authenticated resolver readback",async()=>{
  const temporary=mkdtempSync(join(tmpdir(),"p-gui-bridge-symlink-"));
  try{
    const executable=join(temporary,"raw-executable"),realWrapper=join(temporary,"wrapper"),publicWrapper=join(temporary,"tfnf");
    const fileIdentity=path=>{const bytes=readFileSync(path);return {path,sha256:sha(bytes),size:bytes.length};};
    const binding=fixture().run().guiBinding;
    binding.launchObserver=fixtureObserver(publicWrapper,python);
    writeFileSync(executable,"owned inert nonexecutable fixture");
    writeFileSync(realWrapper,binding.launchObserver.declaredText);
    symlinkSync(realWrapper,publicWrapper);
    binding.publicWrapper=fileIdentity(publicWrapper);
    binding.rawExecutable=fileIdentity(executable);
    const sources=join(root,"tools/verification");
    binding.controller={python,scriptSha256:sha(readFileSync(join(sources,"p-native-gui-controller.py")))};
    binding.bridgeSha256=sha(readFileSync(join(sources,"p-native-gui-controller-bridge.mjs")));
    binding.resolverSha256=sha(readFileSync(join(sources,"p-native-gui-launch-binding.mjs")));
    binding.predicateHelper=fileIdentity(join(sources,"p-process-predicate-probe.py"));
    const context={schema:"theme-forge.p-native-gui-context.v1",transform:"p-linux-gui-controller-v1",...binding};
    // The synthetic expected resolved store path intentionally cannot equal this
    // owned temporary source. Rejection must come from the resolver, before any spawn.
    await assert.rejects(spawnGuiBound({launchTarget:publicWrapper,args:["--nebular-release-smoke=C"],
      options:{cwd:temporary,env:{},detached:true,stdio:["ignore","pipe","pipe"]},
      expectedApp:binding.rawExecutable,context,platform:"linux-x64",scenario:"C",
      smokeDir:temporary,controllerEvidenceDir:temporary,label:"fixture-C"}),
      error=>error.code==="SOURCE_MISMATCH");
  }finally{rmSync(temporary,{recursive:true,force:true});}
});

test("bridge termination wait covers complete controller transaction within qualified watchdog floor",()=>{
  const pythonSource=readFileSync(join(root,"tools/verification/p-native-gui-controller.py"),"utf8");
  const seconds=Number(pythonSource.match(/^SIGNAL_TRANSACTION_BUDGET_SECONDS = (\d+)$/m)[1]);
  assert(CONTROLLER_TERMINATE_WAIT_MS>seconds*1000);
  assert(CONTROLLER_TERMINATE_WAIT_MS<40000);
});

test("versioned plan declares exact native per-system GUI profile and binding member",()=>{
  const expected={
    "x86_64-linux":["p-linux-gui-controller-v1","p-native-gui-binding.json",["C","C-signal"]],
    "aarch64-linux":["p-linux-gui-controller-v1","p-native-gui-binding.json",["B"]],
    "aarch64-darwin":["p-single-spawn-target-v1","p-test-adapter-binding.json",["A"]],
  };
  for(const [system,[profile,member,scenarios]]of Object.entries(expected)){
    const declaration=guiProfileFor(system),plan=qualificationPlan(system);
    assert.equal(declaration.profile,profile);assert.equal(declaration.bindingMember,member);
    assert.equal(plan.guiProfile,profile);assert.deepEqual(plan.adaptedScenarios,scenarios);
    assert.equal(plan.runnerPolicy.event,"workflow_dispatch");assert.equal(plan.runnerPolicy.branch,"main");
    assert.equal(typeof plan.guiSeams,"string");
  }
  assert(qualificationPlan("aarch64-linux").required.some(value=>value.includes("ordinary finalization")));
  assert(!qualificationPlan("aarch64-linux").required.some(value=>value.includes("C-signal witness")));
  assert.throws(()=>guiProfileFor("unknown"));
});
test("qualified Linux route cannot silently fall back and fixture backends cannot become native",async()=>{
  let commands=0;const run=()=>{commands++;throw Error("unexpected fixture command");};
  const common={root:"/fixture/root",checkout:"/fixture/checkout",evidence:"/fixture/evidence",run,spawnService:()=>{}};
  await assert.rejects(runNativeRoute({...common,system:"x86_64-linux"}),/explicit native controller flag/);
  await assert.rejects(runNativeRoute({...common,system:"aarch64-darwin",nativeGuiController:true}),/explicit native controller flag/);
  await assert.rejects(runNativeRoute({...common,system:"x86_64-linux",nativeGuiController:true}),/actual public native host/);
  assert.equal(commands,0);
});


test("Nix failure diagnostics retain bounded public build output without changing failure authority",()=>{
  const temporary=mkdtempSync(join(tmpdir(),"p-nix-failure-"));
  try {
    const result={status:1,signal:null,stdout:"public fixture output",stderr:"tail marker\n"+"é".repeat(100000)};
    const record=retainNixCheckFailure(temporary,result);
    assert.equal(result.status,1);assert.equal(record.failed,true);
    assert.equal(record.accepted,false);assert.equal(record.publicationAuthority,false);
    assert.equal(record.exitCode,1);assert.equal(record.streams.stdout.truncated,false);
    assert.equal(record.streams.stderr.truncated,true);
    for(const stream of ["stdout","stderr"]) {
      const data=readFileSync(join(temporary,record.streams[stream].member));
      assert(data.length<=65536);assert.equal(data.length,record.streams[stream].retainedBytes);
      assert.equal(sha(data),record.streams[stream].retainedSha256);
      assert.equal(sha(Buffer.from(result[stream])),record.streams[stream].sha256);
    }
    assert.deepEqual(JSON.parse(readFileSync(join(temporary,"nix-flake-check.failure.json"))),record);
  } finally {rmSync(temporary,{recursive:true,force:true});}
});
