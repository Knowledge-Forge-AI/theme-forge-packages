import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';

const hash=value=>createHash('sha256').update(value).digest('hex');
const exact=(value,keys)=>assert(value && typeof value==='object' && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort()),'Unexpected protocol fields');
export const INITIALIZE_METHODS=['workspaceOpen','projectOpen','sourceOpen','workspaceStatus','projectList','assetList',
  'assetGet','assetValidate','assetDiff','sourceAnalyze','previewStatus','progress','cancellation','mutationPlans','planApply'];
// Exact 1.0 capability values from the authenticated Burst 0.7.0 v1-validate.js.
export const INITIALIZE_LIMITS={maxFrameBytes:16777216,maxConcurrentReads:4,maxQueuedReads:4,
  assetPageSizeMin:1,assetPageSizeDefault:64,assetPageSizeMax:128,sourceDetailPageSizeMin:1,
  sourceDetailPageSizeDefault:64,sourceDetailPageSizeMax:128,maxActivePlans:4,maxRetainedPlanBytes:201326592,
  maxRetainedNativeSnapshotPlans:1,planTtlMs:600000,maxConcurrentApplies:1};

export function cleanNodeEnvironment(inherited=process.env) {
  const env={...inherited};delete env.NODE_OPTIONS;delete env.NODE_PATH;return env;
}

export async function probeStudioService(executable,{spawnService=spawn,version,timeoutMs=30000,env=process.env}={}) {
  const child=spawnService(executable,[],{env:cleanNodeEnvironment(env),stdio:['pipe','pipe','pipe']});
  return await new Promise((resolve,reject)=>{
    let pending='',stdout='',stderr='',stage='initialize',failure,settled=false,killTimer;
    const transcript=[];const responses={};
    const timer=setTimeout(()=>fail(new Error('Studio protocol timeout')),timeoutMs);
    function complete(error,value) {
      if(settled)return;settled=true;clearTimeout(timer);clearTimeout(killTimer);
      if(error) {
        error.probeEvidence={kind:'service-protocol',complete:false,stage,transcript,
          stdoutSha256:hash(stdout),stderrSha256:hash(stderr)};
        reject(error);
      } else resolve(value);
    }
    function fail(error) {
      if(failure||settled)return;failure=error;
      try{child.kill('SIGKILL');}catch{}
      if(!settled)killTimer=setTimeout(()=>complete(failure),2000);
    }
    function send(message) {
      const bytes=JSON.stringify(message)+'\n';
      transcript.push({direction:'request',method:message.method,id:message.id??null,sha256:hash(bytes)});
      child.stdin.write(bytes);
    }
    child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
    child.stderr.on('data',chunk=>{stderr+=chunk;if(Buffer.byteLength(stderr)>1048576)fail(new Error('Studio stderr exceeds bound'));});
    child.stdout.on('data',chunk=>{
      if(failure||settled)return;
      try {
        stdout+=chunk;pending+=chunk;assert(Buffer.byteLength(stdout)<=1048576,'Studio stdout exceeds bound');
        while(pending.includes('\n')) {
          const end=pending.indexOf('\n'),line=pending.slice(0,end);pending=pending.slice(end+1);
          const message=JSON.parse(line);exact(message,['jsonrpc','id','result']);assert.equal(message.jsonrpc,'2.0');
          transcript.push({direction:'response',id:message.id,sha256:hash(line+'\n')});
          if(stage==='initialize') {
            assert.equal(message.id,1);const value=message.result;
            exact(value,['protocol','selectedVersion','server','sessionNonce','capabilities']);
            assert.equal(value.protocol,'tfsb.studio');assert.equal(value.selectedVersion,'1.0');
            exact(value.server,['name','version']);assert.equal(value.server.name,'tfsb-studio-service');assert.equal(value.server.version,version);
            assert.equal(typeof value.sessionNonce,'string');assert(/^[A-Za-z0-9_-]{43}$/.test(value.sessionNonce));
            exact(value.capabilities,['methods','limits']);exact(value.capabilities.methods,INITIALIZE_METHODS);
            for(const name of INITIALIZE_METHODS)assert.equal(value.capabilities.methods[name],true);
            assert.deepEqual(value.capabilities.limits,INITIALIZE_LIMITS);
            responses.initialize=hash(line+'\n');stage='shutdown';
            send({jsonrpc:'2.0',method:'initialized',params:{sessionNonce:value.sessionNonce}});
            send({jsonrpc:'2.0',id:2,method:'shutdown',params:{sessionNonce:value.sessionNonce}});
          } else {
            assert.equal(stage,'shutdown','Unexpected/duplicate protocol response');assert.equal(message.id,2);assert.equal(message.result,null);
            responses.shutdown=hash(line+'\n');stage='exit-sent';
            // Keep stdin open: EOF must not substitute for processing the exit notification.
            send({jsonrpc:'2.0',method:'exit',params:{}});
          }
        }
      } catch(error){fail(error);}
    });
    child.on('error',fail);child.stdin.on('error',fail);child.stdout.on('error',fail);child.stderr.on('error',fail);
    child.on('close',(status,signal)=>{
      if(failure)return complete(failure);
      try {
        assert.equal(stage,'exit-sent','EOF/early exit is not a protocol exchange');assert.equal(pending,'');
        assert.equal(status,0);assert.equal(signal,null);assert.equal(stderr,'');
        complete(null,{kind:'service-protocol',protocol:'tfsb.studio',selectedVersion:'1.0',serverVersion:version,
          methods:['initialize','initialized','shutdown','exit'],responses,exitCode:status,
          stdoutSha256:hash(stdout),stderrSha256:hash(stderr),transcript});
      } catch(error){complete(error);}
    });
    try {
      send({jsonrpc:'2.0',id:1,method:'initialize',params:{protocol:'tfsb.studio',minVersion:'1.0',maxVersion:'1.0',
        client:{name:'p-current-nix-qualification',version:'1'},capabilities:{progress:false,cancellation:false}}});
    } catch(error){fail(error);}
  });
}

export async function dispatchProbe({command,executable,probe,checked,spawnService=spawn,version,env=process.env}) {
  switch(probe.kind) {
    case 'service-protocol':
      assert.equal(command,'tfsb-studio-service');assert.deepEqual(probe.argv,[]);
      assert.equal(probe.expect_exit,0);assert.equal(probe.input,'');
      assert.deepEqual(probe.exchange,['initialize','initialized','shutdown','exit']);
      assert.equal(probe.protocol,'tfsb.studio');assert.equal(probe.selectedVersion,'1.0');
      return await probeStudioService(executable,{spawnService,version,env});
    case 'launcher-metadata':
      assert.equal(command,'tfnf');assert([['--version'],['--path']].some(argv=>JSON.stringify(argv)===JSON.stringify(probe.argv)));
      break;
    case 'argv': case 'stdin': break;
    default: throw new Error('Unsupported command probe kind: '+String(probe.kind));
  }
  const stdout=checked(executable,probe.argv,{exit:probe.expect_exit,input:probe.input,timeout:30000,env:cleanNodeEnvironment(env)});
  for(const expected of probe.stdout_contains)assert(stdout.includes(expected),'Released command contract failed');
  return {kind:probe.kind,argv:probe.argv,exitCode:probe.expect_exit,stdoutSha256:hash(stdout),stdout};
}
