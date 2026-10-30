/** Synthetic grammar samples only. These never mint a resolver capability or native authority. */
import {readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import {authenticateWrapper} from "../tools/verification/p-native-gui-launch-binding.mjs";
export const sha=bytes=>createHash("sha256").update(bytes).digest("hex");
export const canonical=value=>JSON.stringify(value,(key,entry)=>entry&&!Array.isArray(entry)&&typeof entry==="object"
  ?Object.fromEntries(Object.keys(entry).sort().map(name=>[name,entry[name]])):entry);
export const digest=value=>sha(Buffer.from(canonical(value)));
export function fixtureObserver(wrapperPath,python) {
  const declaredText=readFileSync(new URL("./fixtures/p-gui-qualified-wrapper-x64.bash",import.meta.url),"utf8");
  const pinnedBash=declaredText.split("\n")[0].slice(2);
  const bwrap=declaredText.match(/^cmd=\(\n  (\S+)\n/m)[1];
  const containerInit=declaredText.match(/^  (\S+) "\$@"$/m)[1];
  const originalInit=declaredText.match(/--symlink (\S+) \/init/)[1];
  return {schema:"theme-forge.p-native-gui-observer-inputs.v1",declaredText,expectedSha256:sha(Buffer.from(declaredText)),
    wrapperPath,expectedResolvedWrapperPath:"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tfnf-bwrap",pinnedBash,
    context:{bwrap,containerInit,originalInit},
    buildFhsEnvSourceSha256:"5c642cc3eed380324d3109a9a428be020ed529774f5c4f5877bb2bb1b93ac93f",
    containerSourceSha256:"40f92dd2ca8e5161e55b5d85c2ece3a79a43b6d96dc20d6b0b05a0fcabf4c7fd",
    declaredDerivation:"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tfnf-bwrap.drv",
    declaredDerivationSha256:"1".repeat(64),containerProducer:{syntheticFixture:true},
    productClosureSha256:"2".repeat(64),nixpkgsRevision:"b6c8664de9b6cc07fe5666a29f91884ba81197c4",
    python,publicationAuthority:false};
}
export function fixtureFacts(context,scenario) {
  const value=context.launchObserver,bytes=Buffer.from(value.declaredText);
  const auth=authenticateWrapper({wrapperBytes:bytes,declaredBytes:bytes,expectedSha256:value.expectedSha256,
    pinnedBash:value.pinnedBash,context:value.context,buildFhsEnvSourceSha256:value.buildFhsEnvSourceSha256,
    containerSourceSha256:value.containerSourceSha256});
  const facts={schema:"theme-forge.p-gui-fresh-launch-binding.v1",source:auth.facts,
    nonce:"3".repeat(64),wrapperBindingSha256:"4".repeat(64),wrapperPublicPathSha256:sha(Buffer.from(context.publicWrapper.path)),
    wrapperResolvedPathSha256:sha(Buffer.from(value.expectedResolvedWrapperPath)),cwdSha256:"5".repeat(64),
    environmentSha256:"6".repeat(64),smokeArgumentsSha256:digest(["--nebular-release-smoke="+scenario]),
    argvSha256:"7".repeat(64),argvCount:20,optionCount:8,stdoutBytes:200,stderrBytes:0,
    stderrSha256:sha(Buffer.alloc(0)),deadlineMs:10000,outputLimitBytes:1048576,processExitObserved:true,
    observerExitCode:0,observerExitSignal:null,stdoutEOF:true,stderrEOF:true,exactSourceReadbacks:true,
    fixtureMode:false,admitting:false,guiQualification:false,nativeQualification:false,productionEnabled:false,publicationAuthority:false};
  facts.bindingSha256=digest(facts);
  return facts;
}
