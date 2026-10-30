/** P's own native route proposal. No RS9 package or closure receipt can satisfy it. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync, realpathSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { dispatchProbe, cleanNodeEnvironment } from './p-command-probes.mjs';
import { executionModeFor, hostedFacts, admissionFields, bindScenarioFiles, bindRawLauncher } from './p-qualification-evidence.mjs';
import { nixBuildArguments, nixCheckArguments, createOutLinkWorkDirectory } from './p-nix-invocation.mjs';
import { validateCandidateContext } from './current-candidate-context.mjs';
import { preparePublicWrapperHarness, measurePublicWrapper } from './p-nix-launcher-adapter.mjs';

const directory=dirname(fileURLToPath(import.meta.url));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const contract=JSON.parse(readFileSync(join(directory,'p-current-nix-contract.json'),'utf8'));
const commands=JSON.parse(readFileSync(join(directory,'current-command-contracts.json'),'utf8')).commands;
const hostSystems={'linux:x64':'x86_64-linux','linux:arm64':'aarch64-linux','darwin:arm64':'aarch64-darwin'};

export function qualificationPlan(system) {
  assert(contract.systems.includes(system),'Unsupported native P system');
  return {system,productionEnabled:false,publicationAuthority:false,acceptance:'requires-real-native-evidence',
    nixAttributes:['tfsb','tfsl','tfss','tfnf','theme-forge-nebular-fusion-payload'],
    commands:['tfsb','tfsb-studio-service','tfsl','tfsl-batch','tfss','tfnf'],
    required:['P flake checks','P derivations and recursive runtime closure','real public wrapper probes',
      'Burst artifact target, load, backend and ABI','P-adapted single-spawn harness scenarios via public wrapper'],
    adaptedScenarios:system==='x86_64-linux'?['C','C-signal']:system==='aarch64-linux'?['B']:['A'],
    guiSeams:contract.guiSeams,runnerPolicy:contract.runnerPolicy};
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

export async function runNativeRoute({system,root,checkout,evidence,run=spawnSync,spawnService=spawn}) {
  const plan=qualificationPlan(system);
  const mode=executionModeFor(run,spawnService);
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
  checked('nix',nixCheckArguments(root));
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
  const rawLauncher=bindRawLauncher(launchRoot,system,commands.tfnf.implementation_sha256);
  const pathProbe=await dispatchProbe({command:'tfnf',executable:join(outputs.tfnf,'bin/tfnf'),
    probe:{kind:'launcher-metadata',argv:['--path'],expect_exit:0,input:'',stdout_contains:[]},checked});
  assert.equal(realpathSync(pathProbe.stdout.trim()),realpathSync(gui));
  commandEvidence.push({command:'tfnf',executionMode:mode,fixtureMode:mode==='fixture',...pathProbe});
  writeFileSync(join(evidence,'command-probes.json'),JSON.stringify(commandEvidence,null,2)+'\n');
  const wrapper=join(outputs.tfnf,'bin/tfnf');
  const {adaptedPath,record:adapter}=preparePublicWrapperHarness({checkout,wrapper,evidence,contract,
    outputs,rawPayloadRoot:launchRoot,derivationsSha256:hash(derivations),closureSha256:hash(closure)});
  const platform=system==='x86_64-linux'?'linux-x64':system==='aarch64-linux'?'linux-arm64':'darwin-arm64';
  const scenarios=[];
  for(const scenario of plan.adaptedScenarios) {
    // All original installed raw payload/launcher/runtime/protocol/cleanup checks remain in the adapter.
    checked(process.execPath,[adaptedPath,'--platform',platform,'--scenario',scenario,
      '--launch-root',launchRoot,'--checkout',checkout,'--evidence',join(evidence,'public-wrapper-gui'),
      '--source','raw-archive','--label','p-nix-public-wrapper-'+scenario],{timeout:600000});
    scenarios.push(bindScenarioFiles(evidence,scenario,platform));
    assert.equal(hash(readFileSync(join(checkout,'tools/native-rc-smoke.mjs'))),adapter.originalSourceSha256);
    assert.equal(hash(readFileSync(adaptedPath)),adapter.adaptedSourceSha256);
    assert.equal(hash(readFileSync(wrapper)),adapter.publicWrapperSha256);
    assert.deepEqual(measurePublicWrapper(wrapper),adapter.publicWrapperIdentity);
    assert.equal(checked('git',['-C',checkout,'diff','--exit-code','--no-ext-diff','--no-textconv','HEAD','--']).trim(),'');
  }
  assert.equal(hash(readFileSync(join(root,'flake.lock'))),flakeLockSha256,'Nix lockfile changed after qualification');
  const result={schema:'theme-forge.p-current-native-three-candidate-qualification-v1',...identity,...plan,
    outputs,outLinkWorkDirectory,flakeLockSha256,adapterBindingSha256:hash(readFileSync(join(evidence,'p-test-adapter-binding.json'))),
    rawPayloadChecks:'unchanged upstream checks against exact installed raw root',
    guiExecution:'P-owned single-spawn-target test adapter uses actual public wrapper',
    scenarios,commandProbesSha256:hash(readFileSync(join(evidence,'command-probes.json'))),rawLauncher,
    nativeLoadProofSha256:hash(readFileSync(join(evidence,'burst-native-target-load.json'))),
    hosted,pSource,nixVersion,...admissionFields(mode)};
  writeFileSync(join(evidence,'p-nix-candidate-qualification.json'),JSON.stringify(result,null,2)+'\n');
  return result;
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv[2]==='--plan')console.log(JSON.stringify(qualificationPlan(process.argv[3]),null,2));
  else {
    assert.equal(process.argv.length,5,'Usage: qualify-p-current-nix.mjs <system> <checkout> <evidence>');
    await runNativeRoute({system:process.argv[2],root:resolve(directory,'../..'),checkout:resolve(process.argv[3]),evidence:resolve(process.argv[4])});
  }
}
