/** P's own native route proposal. No RS9 package or closure receipt can satisfy it. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync, realpathSync, openSync, closeSync, fstatSync, lstatSync, readSync, constants } from 'node:fs';
import { join, resolve, dirname, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { dispatchProbe, cleanNodeEnvironment } from './p-command-probes.mjs';
import { executionModeFor, hostedFacts, admissionFields, bindScenarioFiles, bindRawLauncher } from './p-qualification-evidence.mjs';
import { nixBuildArguments, nixCheckArguments, createOutLinkWorkDirectory } from './p-nix-invocation.mjs';
import { validateCandidateContext } from './current-candidate-context.mjs';
import { preparePublicWrapperHarness, measurePublicWrapper } from './p-nix-launcher-adapter.mjs';
import { materializeControllerClosure, materializeDerivedHarness } from './p-native-gui-adapter.mjs';
import { parseUniqueJson, validateResponse, controllerResponsePath, validateFreshLaunchFacts } from './p-native-gui-controller-bridge.mjs';

const directory=dirname(fileURLToPath(import.meta.url));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const contract=JSON.parse(readFileSync(join(directory,'p-current-nix-contract.json'),'utf8'));
const commands=JSON.parse(readFileSync(join(directory,'current-command-contracts.json'),'utf8')).commands;
const hostSystems={'linux:x64':'x86_64-linux','linux:arm64':'aarch64-linux','darwin:arm64':'aarch64-darwin'};

export function guiProfileFor(system) {
  assert.equal(contract.schema,'theme-forge.p-current-native-three-plan-v2','Versioned GUI plan required');
  const expected={'x86_64-linux':'p-linux-gui-controller-v1','aarch64-linux':'p-linux-gui-controller-v1',
    'aarch64-darwin':'p-single-spawn-target-v1'};
  assert.deepEqual(Object.keys(contract.guiAdapter.profiles).sort(),Object.keys(expected).sort(),'GUI profile system set');
  assert(Object.hasOwn(expected,system),'Unsupported native P system');
  const selected=contract.guiAdapter.profiles[system];
  assert.equal(selected.profile,expected[system],'GUI profile differs from native route');
  const scenarios={'x86_64-linux':['C','C-signal'],'aarch64-linux':['B'],'aarch64-darwin':['A']};
  assert.deepEqual(selected.scenarios,scenarios[system],'GUI profile scenarios differ');
  assert.equal(selected.bindingMember,system==='aarch64-darwin'?'p-test-adapter-binding.json':'p-native-gui-binding.json');
  return selected;
}

export function qualificationPlan(system) {
  assert(contract.systems.includes(system),'Unsupported native P system');
  const profile=guiProfileFor(system);
  const controller=profile.profile==='p-linux-gui-controller-v1';
  return {system,productionEnabled:false,publicationAuthority:false,acceptance:'requires-real-native-evidence',
    nixAttributes:['tfsb','tfsl','tfss','tfnf','theme-forge-nebular-fusion-payload'],
    commands:['tfsb','tfsb-studio-service','tfsl','tfsl-batch','tfss','tfnf'],
    required:['P flake checks','P derivations and recursive runtime closure','real public wrapper probes',
      'Burst artifact target, load, backend and ABI',controller
        ?(system==='x86_64-linux'?'P-owned wrapper monitor and controller-bound application with C-signal witness'
          :'P-owned wrapper monitor and controller-bound application with ordinary finalization')
        :'P-adapted single-spawn harness through the public wrapper'],
    adaptedScenarios:[...profile.scenarios],guiProfile:profile.profile,
    guiSeams:contract.guiSeams[system],runnerPolicy:contract.runnerPolicy};
}

export function nodeFromWrapper(text) {
  const paths=[...new Set(text.match(/\/nix\/store\/[a-z0-9]{32}-[^\s"'/]+\/bin\/node/g)||[])];
  assert.equal(paths.length,1,'One exact Nix Node interpreter must be present; host Node fallback forbidden');
  return paths[0];
}

export function assertTaggedSource(checkout) {
  for(const [path,pin] of Object.entries(contract.nebularSource.files)) {
    const bytes=readFileSync(join(checkout,path));assert.equal(bytes.length,pin.bytes);assert.equal(hash(bytes),pin.sha256);
  }
}

function fileIdentity(path) {
  const bytes = readFileSync(path);
  return { path: resolve(path), sha256: hash(bytes), size: bytes.length };
}

/**
 * Opt-in Linux GUI route.  The default Darwin/current route remains the
 * reviewed public-wrapper adapter.  A Linux caller must supply fresh,
 * independently measured identities and source paths; a saved probe receipt
 * is not accepted as a GUI authority by this function.
 */
export function prepareNativeGuiHarness({ checkout, wrapper, evidence, rawPayloadRoot, guiBinding, controllerSources }) {
  assert(guiBinding && typeof guiBinding === 'object', 'fresh Linux GUI binding is required');
  assert(controllerSources && typeof controllerSources === 'object', 'derived controller sources are required');
  const sourcePath = join(checkout, 'tools/native-rc-smoke.mjs');
  const rawExecutable = join(rawPayloadRoot, 'bin/theme-forge-nebular-fusion');
  assert.equal(resolve(guiBinding.rawExecutable.path), resolve(rawExecutable), 'GUI binding executable path');
  assert.deepEqual(fileIdentity(rawExecutable), guiBinding.rawExecutable, 'GUI executable bytes changed');
  assert.deepEqual(fileIdentity(wrapper), guiBinding.publicWrapper, 'public wrapper bytes changed');
  const outputDir = join(evidence, 'derived-native-gui');
  const closure = materializeControllerClosure({ outputDir, ...controllerSources });
  const closureByName = Object.fromEntries(closure.files.map((file) => [file.name, file]));
  assert.equal(closureByName['p-native-gui-controller-bridge.mjs'].sha256, guiBinding.bridgeSha256,
    'controller bridge binding differs from materialized bytes');
  assert.equal(closureByName['p-native-gui-controller.py'].sha256, guiBinding.controller.scriptSha256,
    'controller script binding differs from materialized bytes');
  assert.equal(closureByName['p-process-predicate-probe.py'].sha256, guiBinding.predicateHelper.sha256,
    'predicate helper binding differs from materialized bytes');
  assert.equal(closureByName['p-native-gui-launch-binding.mjs'].sha256,guiBinding.resolverSha256,
    'fresh launch resolver binding differs from materialized bytes');
  const boundBinding = {
    ...guiBinding,
    predicateHelper: { ...guiBinding.predicateHelper, path: closureByName['p-process-predicate-probe.py'].path },
  };
  const adapter = materializeDerivedHarness({
    sourcePath,
    outputDir,
    expectedOriginalSha256: hash(readFileSync(sourcePath)),
    binding: boundBinding,
  });
  const bindingPath = join(evidence, 'p-native-gui-binding.json');
  writeFileSync(bindingPath, JSON.stringify({
    schema: 'theme-forge.p-native-gui-binding.v1',
    productionEnabled: false,
    publicationAuthority: false,
    binding: boundBinding,
    closure: closure.files,
    adapter: { schema: adapter.schema, transform: adapter.transform, originalSourceSha256: adapter.originalSourceSha256,
      adaptedSourceSha256: adapter.adaptedSourceSha256, adaptationDiffSha256: adapter.adaptationDiffSha256,
      changedLines: adapter.changedLines, changes: adapter.changes, upstreamImports: adapter.upstreamImports },
    publicWrapperIdentity: measurePublicWrapper(wrapper),
  }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { adaptedPath: adapter.target, bindingPath, record: {
    ...adapter, closure: closure.files,
    publicWrapperPath: wrapper, publicWrapperSha256: guiBinding.publicWrapper.sha256,
    publicWrapperIdentity: measurePublicWrapper(wrapper),
  } };
}

export function bindGuiControlEvidence(path, context, scenario, platform) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes;
  try {
    const before = fstatSync(fd, {bigint:true});
    assert(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= 65536n,
      'bounded regular controller evidence required');
    bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length-offset, offset);
      assert(count > 0, 'short controller evidence');
      offset += count;
    }
    const after = fstatSync(fd, {bigint:true});
    const named = lstatSync(path, {bigint:true});
    const frame = value => ['dev','ino','mode','size','mtimeNs','ctimeNs','uid','gid','nlink'].map(key=>value[key]);
    assert.deepEqual(frame(after), frame(before), 'controller evidence changed');
    assert.deepEqual(frame(named), frame(before), 'controller evidence path changed');
  } finally { closeSync(fd); }
  const record = parseUniqueJson(bytes.toString('utf8'));
  assert(record && typeof record === 'object' && !Array.isArray(record), 'controller record object');
  assert.equal(Object.keys(record).sort().join(','),
    ['schema','status','nonceSha256','launchBinding','source','responses','controllerExit','cleanup'].sort().join(','),
    'controller record fields');
  assert.equal(record.schema, 'theme-forge.p-native-gui-response-record.v1');
  assert.equal(record.status, 'complete', 'controller did not complete');
  assert.deepEqual(record.controllerExit, {code:0,signal:null}, 'controller did not exit cleanly');
  assert.equal(record.cleanup, null, 'passing controller record contains failure cleanup');
  assert.deepEqual(record.source, {pCommit:context.pCommit,pTree:context.pTree,
    nebularCommit:context.nebularCommit,nebularTree:context.nebularTree}, 'controller record source');
  const phases = scenario === 'C-signal' ? ['BOUND','TERMINATED','FINALIZED'] : ['BOUND','FINALIZED'];
  assert(Array.isArray(record.responses) && record.responses.length === phases.length, 'controller response phase count');
  const first = record.responses[0].response;
  assert(first && typeof first.nonce === 'string' && /^[0-9a-f]{32}$/.test(first.nonce), 'controller nonce missing or malformed');
  assert.equal(record.nonceSha256, hash(Buffer.from(first.nonce)), 'controller nonce digest');
  const launchBindingSha256=validateFreshLaunchFacts(record.launchBinding,context,scenario);
  const state = {nonce:first.nonce,launchBindingSha256};
  const monitorPid = first.monitor?.pid;
  const monitorExit = {code:scenario==='C-signal'?143:0,signal:null};
  for (let index=0;index<phases.length;index++) {
    const entry=record.responses[index];
    assert(entry && Object.keys(entry).sort().join(',')==='phase,response', 'controller phase fields');
    assert.equal(entry.phase, phases[index], 'controller phase order');
    validateResponse(entry.response, phases[index], state, context, context.rawExecutable, monitorPid,
      platform, scenario, phases[index]==='FINALIZED'?monitorExit:null);
  }
  return {schema:'theme-forge.p-native-gui-control-evidence.v1',sha256:hash(bytes),bytes:bytes.length,
    phases,monitorExit,source:record.source,launchBindingSha256,publicationAuthority:false};
}

export function assertGuiSourceBinding(binding, pSource, nebularSource) {
  assert.equal(binding.pCommit, pSource.commit, 'GUI P commit differs from executing source');
  assert.equal(binding.pTree, pSource.tree, 'GUI P tree differs from executing source');
  assert.equal(binding.nebularCommit, nebularSource.commit, 'GUI Nebular commit differs');
  assert.equal(binding.nebularTree, nebularSource.tree, 'GUI Nebular tree differs');
}


export function prepareNativeGuiBinding({root,system,wrapper,evidence,rawExecutable,closurePath,pSource,checked,read=readFileSync}) {
  assert(['x86_64-linux','aarch64-linux'].includes(system),'native GUI binding is Linux-only');
  const measured=path=>{const bytes=read(path);return {path:resolve(path),sha256:hash(bytes),size:bytes.length};};
  const contextOutput=checked('nix',['build','--no-update-lock-file','--no-link','--print-out-paths',
    root+'#testTools.'+system+'.predicateContext']).trim();
  assert(/^\/nix\/store\/[0-9a-df-np-sv-z]{32}-[^/\s]+$/.test(contextOutput),'one exact materialized observer context required');
  const nativeContext=parseUniqueJson(read(contextOutput,'utf8'));
  assert(typeof nativeContext.python==='string' && /^\/nix\/store\/[^/\s]+\/bin\/python3(?:\.[0-9]+)?$/.test(nativeContext.python),
    'one locked observer Python required');
  const observerPath=join(evidence,'p-native-gui-observer-inputs.json');
  const preparer=join(root,'tools/verification/p-native-gui-prepare-context.py');
  checked(nativeContext.python,['-I','-S',preparer,root,system,contextOutput,wrapper,closurePath,observerPath]);
  const launchObserver=parseUniqueJson(read(observerPath,'utf8'));
  const source=name=>join(root,'tools/verification',name);
  const bridgeSource=source('p-native-gui-controller-bridge.mjs');
  const controllerSource=source('p-native-gui-controller.py');
  const stableSource=source('p-process-predicate-probe.py');
  const resolverSource=source('p-native-gui-launch-binding.mjs');
  const stableSha256='8caa44844e3d3c77911f6909f128e1ea1178ae29acc6d37eb3c430324ec28811';
  assert.equal(hash(read(stableSource)),stableSha256,'held predicate helper changed');
  const guiBinding={pCommit:pSource.commit,pTree:pSource.tree,
    nebularCommit:contract.nebularSource.commit,nebularTree:contract.nebularSource.tree,
    rawExecutable:measured(rawExecutable),publicWrapper:measured(wrapper),
    monitor:{executable:measured(launchObserver.context.bwrap)},
    controller:{python:launchObserver.python,scriptSha256:hash(read(controllerSource))},
    predicateHelper:measured(stableSource),bridgeSha256:hash(read(bridgeSource)),
    resolverSha256:hash(read(resolverSource)),launchObserver};
  assertGuiSourceBinding(guiBinding,pSource,contract.nebularSource);
  return {guiBinding,controllerSources:{bridgeSource,controllerSource,stableSource,resolverSource,stableSha256}};
}

// Only the public Nix flake-check phase may retain these bounded build diagnostics.
// Application probes keep their existing digest-only output policy.
export function retainNixCheckFailure(evidence,result) {
  const limit=64*1024;
  const streams={};
  for(const stream of ['stdout','stderr']) {
    const bytes=Buffer.from(result[stream]||'','utf8');
    const retained=bytes.subarray(Math.max(0,bytes.length-limit));
    const member='nix-flake-check.'+stream+'.log';
    writeFileSync(join(evidence,member),retained);
    streams[stream]={member,bytes:bytes.length,sha256:hash(bytes),
      retainedBytes:retained.length,retainedSha256:hash(retained),truncated:bytes.length>limit};
  }
  const record={schema:'theme-forge.p-nix-check-failure.v1',phase:'nix-flake-check',
    exitCode:result.status,signal:result.signal,failed:true,accepted:false,
    publicationAuthority:false,maxRetainedBytesPerStream:limit,streams};
  writeFileSync(join(evidence,'nix-flake-check.failure.json'),JSON.stringify(record,null,2)+'\n');
  return record;
}

export async function runNativeRoute({system,root,checkout,evidence,run=spawnSync,spawnService=spawn,
  nativeGuiController=false}) {
  const plan=qualificationPlan(system);
  const declared=guiProfileFor(system);
  const requiresController=declared.profile==='p-linux-gui-controller-v1';
  assert.equal(nativeGuiController,requiresController,'Declared GUI profile requires matching explicit native controller flag');
  const mode=executionModeFor(run,spawnService);
  if(requiresController)assert.equal(mode,'native-hosted','GUI controller qualification requires actual public native host');
  let guiBinding=null,controllerSources=null;
  const hosted=hostedFacts(mode);
  assert.equal(contract.status,'prepared-test-only-native-route');
  assert.equal(hostSystems[process.platform+':'+process.arch],system,'Native runner mismatch');
  const lockPath=join(root,'release-lock.json');
  const lock=JSON.parse(readFileSync(lockPath));
  const identity=validateCandidateContext(lock,lockPath,true);
  assertTaggedSource(checkout);
  mkdirSync(evidence,{recursive:true});
  const flakeLockSha256=hash(readFileSync(join(root,'flake.lock')));
  writeFileSync(join(evidence,'p-input-identities.json'),JSON.stringify({
    ...identity,executionMode:mode,fixtureMode:mode==='fixture',flakeLockSha256},null,2)+'\n');
  const observations=[];
  function checked(command,args,options={}) {
    const result=run(command,args,{cwd:root,encoding:'utf8',timeout:options.timeout||1800000,
      maxBuffer:16*1024*1024,input:options.input||'',env:options.env??cleanNodeEnvironment()});
    observations.push({command,args,executionMode:mode,fixtureMode:mode==='fixture',status:result.status,signal:result.signal,
      stdoutSha256:hash(result.stdout||''),stderrSha256:hash(result.stderr||'')});
    writeFileSync(join(evidence,'operations.json'),JSON.stringify(observations,null,2)+'\n');
    if(options.nixCheckDiagnostics && (result.error||result.signal!==null||result.status!==0))
      retainNixCheckFailure(evidence,result);
    assert.ifError(result.error);assert.equal(result.signal,null);assert.equal(result.status,options.exit||0);
    return result.stdout;
  }
  // Authenticate the actual current checkout, not an old release source or an edited harness.
  assert.equal(checked('git',['-C',checkout,'rev-parse','HEAD']).trim(),contract.nebularSource.commit);
  assert.equal(checked('git',['-C',checkout,'rev-parse','HEAD^{tree}']).trim(),contract.nebularSource.tree);
  assert.equal(checked('git',['-C',checkout,'diff','--exit-code','--no-ext-diff','--no-textconv','HEAD','--']).trim(),'');
  const pSource={commit:checked('git',['-C',root,'rev-parse','HEAD']).trim(),
    tree:checked('git',['-C',root,'rev-parse','HEAD^{tree}']).trim(),
    workflowFileSha256:hash(readFileSync(join(root,'.github/workflows/validate.yml')))};
  assert(/^[a-f0-9]{40}$/.test(pSource.commit) && /^[a-f0-9]{40}$/.test(pSource.tree));
  if(mode==='native-hosted')assert.equal(pSource.commit,hosted.sourceSha);
  assert.equal(checked('git',['-C',root,'diff','--exit-code','--no-ext-diff','--no-textconv','HEAD','--']).trim(),'');
  const nixVersion=checked('nix',['--version']).trim();assert(nixVersion.startsWith('nix ') && nixVersion.length<256);
  const outLinkWorkDirectory=createOutLinkWorkDirectory(evidence,{mode});
  const outputs={};
  for(const attribute of plan.nixAttributes) {
    const link=join(outLinkWorkDirectory,'result-'+attribute);
    checked('nix',nixBuildArguments(root,system,attribute,link));
    outputs[attribute]=realpathSync(link);
  }
  checked('nix',nixCheckArguments(root),{nixCheckDiagnostics:true});
  assert.equal(hash(readFileSync(join(root,'flake.lock'))),flakeLockSha256,'Nix lockfile changed');
  const closure=checked('nix',['path-info','--recursive','--json',...Object.values(outputs)]);
  assert(Object.keys(JSON.parse(closure)).length>0);
  writeFileSync(join(evidence,'p-runtime-closure.json'),closure);
  const drvPaths=checked('nix',['path-info','--derivation',...Object.values(outputs)]).trim().split('\n');
  assert(drvPaths.every(path=>/^\/nix\/store\/[^/\s]+\.drv$/.test(path)));
  const derivations=checked('nix',['derivation','show',...drvPaths]);
  writeFileSync(join(evidence,'p-derivations.json'),derivations);
  const productOutput={'theme-forge-stellar-burst':outputs.tfsb,'theme-forge-stellar-loom':outputs.tfsl,
    'theme-forge-solar-sail':outputs.tfss,'theme-forge-nebular-fusion':outputs.tfnf};
  const commandEvidence=[];
  for(const command of plan.commands) {
    const definition=commands[command];const executable=join(productOutput[definition.project],'bin',command);
    if(definition.project!=='theme-forge-nebular-fusion') {
      for(const [path,expected] of Object.entries(definition.implementation_sha256))
        assert.equal(hash(readFileSync(join(productOutput[definition.project],'lib',definition.project,path))),expected);
    }
    for(const probe of definition.probes) {
      try {
        const proof=await dispatchProbe({command,executable,probe,checked,spawnService,version:lock.products[definition.project].version});
        commandEvidence.push({command,executionMode:mode,fixtureMode:mode==='fixture',...proof});
      } catch(error) {
        if(error.probeEvidence)commandEvidence.push({command,executionMode:mode,fixtureMode:mode==='fixture',...error.probeEvidence});
        throw error;
      } finally {
        writeFileSync(join(evidence,'command-probes.json'),JSON.stringify(commandEvidence,null,2)+'\n');
      }
    }
  }
  const burstRoot=join(outputs.tfsb,'lib/theme-forge-stellar-burst');
  assert.equal(hash(readFileSync(join(burstRoot,'dist/directory-snapshot-native.js'))),contract.burstLoaderSha256);
  const pin=contract.burstNative[system];
  const artifact=join(burstRoot,'native/directory-snapshot/prebuilds',pin.artifact,'native-addon-posix-openat-v1.node');
  const artifactBytes=readFileSync(artifact);assert.equal(artifactBytes.length,pin.bytes);assert.equal(hash(artifactBytes),pin.sha256);
  const node=nodeFromWrapper(readFileSync(join(outputs.tfsb,'bin/tfsb'),'utf8'));
  const program=`import assert from 'node:assert/strict'; const m=await import(process.argv[1]);
    assert.equal(m.currentDirectorySnapshotArtifact(),process.argv[2]); const r=m.loadDirectorySnapshotNative();
    assert.equal(r.ok,true);assert.equal(r.artifact,process.argv[2]);
    assert.equal(r.addon.backend,process.argv[3]);assert.equal(r.addon.abiVersion,Number(process.argv[4]));
    console.log(JSON.stringify({target:r.artifact,loaded:true,backend:r.addon.backend,abiVersion:r.addon.abiVersion}));`;
  const native=checked(node,['--input-type=module','-e',program,
    pathToFileURL(join(burstRoot,'dist/directory-snapshot-native.js')).href,pin.artifact,pin.backend,String(pin.abiVersion)],{timeout:30000,env:cleanNodeEnvironment()});
  const nativeProof=JSON.parse(native);
  assert.equal(nativeProof.target,pin.artifact);assert.equal(nativeProof.loaded,true);
  assert.equal(nativeProof.backend,pin.backend);assert.equal(nativeProof.abiVersion,pin.abiVersion);
  writeFileSync(join(evidence,'burst-native-target-load.json'),JSON.stringify({
    ...nativeProof,executionMode:mode,fixtureMode:mode==='fixture',scope:'target/load/backend/ABI'},null,2)+'\n');
  const darwin=system==='aarch64-darwin';
  const payload=outputs['theme-forge-nebular-fusion-payload'];
  const launchRoot=darwin?join(payload,'Applications'):join(payload,'lib/theme-forge-nebular-fusion');
  const gui=darwin?join(launchRoot,'Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion'):join(launchRoot,'bin/theme-forge-nebular-fusion');
  assert.equal(hash(readFileSync(gui)),lock.products['theme-forge-nebular-fusion'].rawArchives[system].executableSha256);
  // Optional observation, including module loading, cannot replace GUI work.
  try {
    const {observeSidecarMode}=await import('./p-sidecar-mode-diagnostic.mjs');
    observeSidecarMode({launchRoot,system,evidence});
  } catch {}
  const rawLauncher=bindRawLauncher(launchRoot,system,commands.tfnf.implementation_sha256);
  const pathProbe=await dispatchProbe({command:'tfnf',executable:join(outputs.tfnf,'bin/tfnf'),
    probe:{kind:'launcher-metadata',argv:['--path'],expect_exit:0,input:'',stdout_contains:[]},checked});
  assert.equal(realpathSync(pathProbe.stdout.trim()),realpathSync(gui));
  commandEvidence.push({command:'tfnf',executionMode:mode,fixtureMode:mode==='fixture',...pathProbe});
  writeFileSync(join(evidence,'command-probes.json'),JSON.stringify(commandEvidence,null,2)+'\n');
  const wrapper=join(outputs.tfnf,'bin/tfnf');
  if(nativeGuiController) {
    assert.equal(mode,'native-hosted','GUI controller qualification requires actual public native host');
    const prepared=prepareNativeGuiBinding({root,system,wrapper,evidence,rawExecutable:gui,
      closurePath:join(evidence,'p-runtime-closure.json'),pSource,checked});
    guiBinding=prepared.guiBinding;controllerSources=prepared.controllerSources;
  }
  const guiHarness = ['x86_64-linux', 'aarch64-linux'].includes(system) && guiBinding !== null
    ? prepareNativeGuiHarness({ checkout, wrapper, evidence, rawPayloadRoot: launchRoot, guiBinding, controllerSources })
    : preparePublicWrapperHarness({checkout,wrapper,evidence,contract,
      outputs,rawPayloadRoot:launchRoot,derivationsSha256:hash(derivations),closureSha256:hash(closure)});
  const {adaptedPath,record:adapter}=guiHarness;
  assert.equal(adapter.transform,plan.guiProfile,'Materialized adapter differs from declared GUI profile');
  const adapterBindingPath=guiHarness.bindingPath??join(evidence,'p-test-adapter-binding.json');
  assert.equal(basename(adapterBindingPath),declared.bindingMember,'Adapter binding member differs from declared profile');
  if (['x86_64-linux', 'aarch64-linux'].includes(system) && guiBinding !== null) {
    assertGuiSourceBinding(guiBinding, pSource, contract.nebularSource);
  }
  const platform=system==='x86_64-linux'?'linux-x64':system==='aarch64-linux'?'linux-arm64':'darwin-arm64';
  const scenarios=[];
  for(const scenario of plan.adaptedScenarios) {
    // All original installed raw payload/launcher/runtime/protocol/cleanup checks remain in the adapter.
    checked(process.execPath,[adaptedPath,'--platform',platform,'--scenario',scenario,
      '--launch-root',launchRoot,'--checkout',checkout,'--evidence',join(evidence,'public-wrapper-gui'),
      '--source','raw-archive','--label','p-nix-public-wrapper-'+scenario],{timeout:600000});
    const scenarioFiles = bindScenarioFiles(evidence,scenario,platform);
    if (guiHarness.bindingPath) {
      const control = bindGuiControlEvidence(
        controllerResponsePath(join(evidence,'public-wrapper-gui'),'p-nix-public-wrapper-'+scenario),
        adapter.context, scenario, platform);
      scenarios.push({...scenarioFiles,nativeGuiControl:control});
    } else scenarios.push(scenarioFiles);
    assert.equal(hash(readFileSync(join(checkout,'tools/native-rc-smoke.mjs'))),adapter.originalSourceSha256);
    assert.equal(hash(readFileSync(adaptedPath)),adapter.adaptedSourceSha256);
    assert.equal(hash(readFileSync(wrapper)),adapter.publicWrapperSha256);
    assert.deepEqual(measurePublicWrapper(wrapper),adapter.publicWrapperIdentity);
    assert.equal(checked('git',['-C',checkout,'diff','--exit-code','--no-ext-diff','--no-textconv','HEAD','--']).trim(),'');
  }
  assert.equal(hash(readFileSync(join(root,'flake.lock'))),flakeLockSha256,'Nix lockfile changed after qualification');
  const result={schema:'theme-forge.p-current-native-three-candidate-qualification-v2',...identity,...plan,
    outputs,outLinkWorkDirectory,flakeLockSha256,adapterBindingSha256:hash(readFileSync(adapterBindingPath)),
    adapterTransform:adapter.transform,
    rawPayloadChecks:'unchanged upstream checks against exact installed raw root',
    guiExecution:guiHarness.bindingPath?'P-owned wrapper monitor/controller with exact application witness':'P-owned single-spawn-target test adapter uses actual public wrapper',
    scenarios,commandProbesSha256:hash(readFileSync(join(evidence,'command-probes.json'))),rawLauncher,
    nativeLoadProofSha256:hash(readFileSync(join(evidence,'burst-native-target-load.json'))),
    hosted,pSource,nixVersion,...admissionFields(mode)};
  writeFileSync(join(evidence,'p-nix-candidate-qualification.json'),JSON.stringify(result,null,2)+'\n');
  return result;
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv[2]==='--plan')console.log(JSON.stringify(qualificationPlan(process.argv[3]),null,2));
  else {
    const args=process.argv.slice(2);
    const nativeGuiController=args[0]==='--native-gui-controller';
    if(nativeGuiController)args.shift();
    assert.equal(args.length,3,'Usage: qualify-p-current-nix.mjs [--native-gui-controller] <system> <checkout> <evidence>');
    await runNativeRoute({system:args[0],root:resolve(directory,'../..'),checkout:resolve(args[1]),evidence:resolve(args[2]),nativeGuiController});
  }
}
