import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { readFileSync, mkdtempSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import test from "node:test";
import { validateResponse, stopOwnedChild, observeSpawn, sendWithin, boundedResponses, captureOwnedExit, controllerResponsePath, settleFailedOwnedChildren }
  from "../tools/verification/p-native-gui-controller-bridge.mjs";

const fixtures=JSON.parse(readFileSync(new URL("./fixtures/p-native-gui-response-transcripts.json",import.meta.url)));
test("actual Python response producers satisfy Node BOUND/TERMINATED/FINALIZED contracts",()=>{
  for(const item of fixtures){
    const state={nonce:item.bound.nonce,launchBindingSha256:item.launchBinding.bindingSha256};
    const {context,platform,scenario}=item;
    const args=[state,context,context.rawExecutable,item.bound.monitor.pid,platform,scenario];
    validateResponse(item.bound,"BOUND",...args);
    if(item.terminated) validateResponse(item.terminated,"TERMINATED",...args);
    validateResponse(item.final,"FINALIZED",...args,item.final.monitorExit);
    for(const operation of ["bound","terminated","final"]){
      const response=item[operation];if(!response)continue;
      for(const field of ["source","target"]){
        const changed=structuredClone(response);delete changed[field];
        assert.throws(()=>validateResponse(changed,response.op,...args,item.final.monitorExit));
      }
    }
  }
});

function owned({exit=null,killResult=true,neverExit=false}={}){
  const child=new EventEmitter();child.exitCode=exit;child.signalCode=null;child.pid=101;
  child.signals=[];
  child.kill=(signal)=>{
    child.signals.push(signal);
    if(killResult&&!neverExit)queueMicrotask(()=>{
      child.signalCode=signal;child.emit("exit",null,signal);
    });
    return killResult;
  };
  return child;
}
test("already exited owner has an exit proof without another signal",async()=>{
  const child=owned({exit:0});
  assert.deepEqual(await stopOwnedChild(child),{code:0,signal:null});
  assert.deepEqual(child.signals,[]);
});
test("monitor cleanup awaits the exact owned child exit",async()=>{
  const child=owned();
  assert.deepEqual(await stopOwnedChild(child,{killFirst:true,killMs:20}),{code:null,signal:"SIGKILL"});
  assert.deepEqual(child.signals,["SIGKILL"]);
});
test("controller grace timeout forces a bounded kill and awaits exit",async()=>{
  const child=owned();
  assert.deepEqual(await stopOwnedChild(child,{graceMs:2,killMs:20}),{code:null,signal:"SIGKILL"});
});
test("refused kill and unconfirmed exit stay failures",async()=>{
  await assert.rejects(stopOwnedChild(owned({killResult:false}),{killFirst:true,killMs:2}));
  await assert.rejects(stopOwnedChild(owned({neverExit:true}),{killFirst:true,killMs:2}),/exit timeout/);
});
test("asynchronous spawn error and startup timeout are bounded",async()=>{
  const child=owned();const ready=observeSpawn(child,20);
  child.emit("error",new Error("inert fixture"));
  await assert.rejects(ready,/spawn failed/);
  await assert.rejects(observeSpawn(owned(),2),/spawn timeout/);
  const success=owned();const launched=observeSpawn(success,20);success.emit("spawn");await launched;
});
test("write completion, backpressure timeout and pipe closure are bounded",async()=>{
  const stream=new Writable({write(chunk,encoding,callback){callback();}});
  await sendWithin(stream,'{"op":"bind"}\n',20);stream.end();
  const blocked=new EventEmitter();blocked.write=()=>false;
  await assert.rejects(sendWithin(blocked,"{}",2),/write timeout/);
  assert.equal(blocked.listenerCount("error"),0);
  const closed=new EventEmitter();closed.write=()=>false;
  const sending=sendWithin(closed,"{}",20);closed.emit("close");
  await assert.rejects(sending,/input closed/);
});
test("response reader refuses oversized unterminated lines without retaining them",async()=>{
  const stdout=new PassThrough();const reader=boundedResponses({stdout});
  const waiting=reader.next();
  stdout.write(Buffer.alloc(65_537,120));
  await assert.rejects(waiting,/framing bound/);
  stdout.write(Buffer.alloc(65_537,121));reader.close();stdout.end();
});
test("response EOF preserves a complete queued response but refuses truncated data",async()=>{
  const stdout=new PassThrough();const reader=boundedResponses({stdout});
  stdout.write('{"op":"BOUND"}\n');stdout.end();
  assert.deepEqual(await reader.next(),{op:"BOUND"});
  await assert.rejects(reader.next(),/EOF/);reader.close();
  const other=new PassThrough();const bad=boundedResponses({stdout:other});
  const waiting=bad.next();other.end('{"op":"BOUND"');
  await assert.rejects(waiting,/truncated/);bad.close();
});

test("monitor exit during async startup is captured before the harness waits",async()=>{
  const child=owned();const exited=captureOwnedExit(child);
  child.exitCode=143;child.emit("exit",143,null);
  await new Promise(resolve=>setTimeout(resolve,2));
  assert.deepEqual(await exited,{code:143,signal:null});
  assert.deepEqual(await captureOwnedExit(child),{code:143,signal:null});
});

test("controller evidence survives outside the disposable smoke directory",()=>{
  assert.equal(controllerResponsePath("/fresh/evidence","p-nix-public-wrapper-C"),"/fresh/evidence/p-nix-public-wrapper-C.controller.json");
  assert.throws(()=>controllerResponsePath("/fresh/evidence","../escape"));
  assert.throws(()=>controllerResponsePath("relative","valid"));
});

test("GUI binding source identities must match the executing qualification source",async()=>{
  const {assertGuiSourceBinding}=await import("../tools/verification/qualify-p-current-nix.mjs");
  const pSource={commit:"a".repeat(40),tree:"b".repeat(40)};
  const nebular={commit:"c".repeat(40),tree:"d".repeat(40)};
  const binding={pCommit:pSource.commit,pTree:pSource.tree,nebularCommit:nebular.commit,nebularTree:nebular.tree};
  assert.doesNotThrow(()=>assertGuiSourceBinding(binding,pSource,nebular));
  for(const field of Object.keys(binding)){
    assert.throws(()=>assertGuiSourceBinding({...binding,[field]:"0".repeat(40)},pSource,nebular));
  }
});

test("actual producer transcripts are consumed as bounded same-source control evidence",async()=>{
  const {bindGuiControlEvidence}=await import("../tools/verification/qualify-p-current-nix.mjs");
  const directory=mkdtempSync(join(tmpdir(),"p-gui-record-"));
  const path=join(directory,"control.json");
  const recordFor=item=>({
    schema:"theme-forge.p-native-gui-response-record.v1",status:"complete",
    nonceSha256:createHash("sha256").update(item.bound.nonce).digest("hex"),
    source:item.bound.source,launchBinding:item.launchBinding,
    responses:[{phase:"BOUND",response:item.bound},...(item.terminated?[{phase:"TERMINATED",response:item.terminated}]:[]),
      {phase:"FINALIZED",response:item.final}],
    controllerExit:{code:0,signal:null},cleanup:null,
  });
  try{
    for(const item of fixtures){
      const original=recordFor(item);
      writeFileSync(path,JSON.stringify(original,null,2)+"\n",{mode:0o600});
      const result=bindGuiControlEvidence(path,item.context,item.scenario,item.platform);
      assert.equal(result.phases.length,item.scenario==="C-signal"?3:2);
      assert.equal(result.publicationAuthority,false);
      for(const corrupt of [
        value=>{value.controllerExit.code=1;},
        value=>{value.source.pCommit="0".repeat(40);},
        value=>{value.nonceSha256="0".repeat(64);},
        value=>{value.responses.forEach(row=>{row.response.nonce="";});value.nonceSha256=createHash("sha256").update("").digest("hex");},
        value=>{value.launchBinding.bindingSha256="0".repeat(64);},
        value=>{value.responses[0].response.launchBindingSha256="0".repeat(64);},
        value=>{value.responses.pop();},
        value=>{value.responses.at(-1).response.monitorExit={code:7,signal:null};},
      ]){
        const bad=structuredClone(original);corrupt(bad);writeFileSync(path,JSON.stringify(bad),{mode:0o600});
        assert.throws(()=>bindGuiControlEvidence(path,item.context,item.scenario,item.platform));
      }
      writeFileSync(path,JSON.stringify(original).replace('"status":"complete"','"status":"complete","status":"complete"'),{mode:0o600});
      assert.throws(()=>bindGuiControlEvidence(path,item.context,item.scenario,item.platform),/duplicate/);
    }
    writeFileSync(path,Buffer.alloc(65_537,32),{mode:0o600});
    assert.throws(()=>bindGuiControlEvidence(path,fixtures[0].context,"C-signal","linux-x64"),/bounded regular/);
    const link=join(directory,"link.json");symlinkSync(path,link);
    assert.throws(()=>bindGuiControlEvidence(link,fixtures[0].context,"C-signal","linux-x64"));
  }finally{rmSync(directory,{recursive:true,force:true});}
});

test("ordinary abort preserves monitor until cooperative controller EOF cleanup exits",async()=>{
  const monitor=owned(),controller=owned(),events=[];
  const kill=monitor.kill;monitor.kill=signal=>{events.push("monitor-kill");return kill(signal);};
  controller.stdin={end(){events.push("controller-eof");queueMicrotask(()=>{
    assert.deepEqual(monitor.signals,[]);events.push("controller-cleanup");
    controller.exitCode=1;controller.emit("exit",1,null);
  });}};
  const results=await settleFailedOwnedChildren(monitor,controller,{graceMs:20,killMs:20});
  assert.deepEqual(events,["controller-eof","controller-cleanup","monitor-kill"]);
  assert(results.every(value=>value.status==="fulfilled"));
  assert.deepEqual(controller.signals,[]);assert.deepEqual(monitor.signals,["SIGKILL"]);
});
test("controller grace expiry kills its exact owner before monitor cleanup",async()=>{
  const monitor=owned(),controller=owned(),events=[];
  for(const [name,child]of[["controller",controller],["monitor",monitor]]){
    const kill=child.kill;child.kill=signal=>{events.push(name+"-kill");return kill(signal);};
  }
  controller.stdin={end(){events.push("controller-eof");}};
  const results=await settleFailedOwnedChildren(monitor,controller,{graceMs:2,killMs:20});
  assert.deepEqual(events,["controller-eof","controller-kill","monitor-kill"]);
  assert(results.every(value=>value.status==="fulfilled"));
});
test("unconfirmed controller cleanup remains failed and still closes owned monitor",async()=>{
  const monitor=owned(),controller=owned({killResult:false});
  controller.stdin={end(){}};
  const results=await settleFailedOwnedChildren(monitor,controller,{graceMs:2,killMs:2});
  assert.equal(results[1].status,"rejected");assert.equal(results[0].status,"fulfilled");
  assert.deepEqual(monitor.signals,["SIGKILL"]);
});
