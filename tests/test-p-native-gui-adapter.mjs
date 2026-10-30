import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import {fixtureObserver} from "./p-native-gui-fixtures.mjs";
import {
  ANCHORS,
  derivePinnedGuiHarness,
  materializeControllerClosure,
  materializeDerivedHarness,
  sha256,
} from "../tools/verification/p-native-gui-adapter.mjs";
import { parseControllerLine, validateContext, validateResponse } from "../tools/verification/p-native-gui-controller-bridge.mjs";

const node = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-node/bin/node";
const python = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-python/bin/python3.13";
const sourcePath = process.env.NEBULAR_SMOKE_SOURCE;
assert(sourcePath, "NEBULAR_SMOKE_SOURCE must select the authenticated qualification checkout");
const source = readFileSync(sourcePath);
const identity = (path, bytes) => ({ path, sha256: sha256(bytes), size: bytes.length });
const binding = {
  pCommit: "a".repeat(40),
  pTree: "b".repeat(40),
  nebularCommit: "c".repeat(40),
  nebularTree: "d".repeat(40),
  rawExecutable: identity("/nix/store/cccccccccccccccccccccccccccccccc-nebular/bin/theme-forge-nebular-fusion", Buffer.from("raw")),
  publicWrapper: identity("/nix/store/dddddddddddddddddddddddddddddddd-nebular/bin/tfnf", Buffer.from("wrapper")),
  monitor: {
    executable: identity("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-bwrap/bin/bwrap", Buffer.from("bwrap")),
    argv: ["bwrap", "--die-with-parent"],
  },
  controller: { python, scriptSha256: "e".repeat(64) },
  predicateHelper: identity("/nix/store/ffffffffffffffffffffffffffffffff-p-helper/p-process-predicate-probe.py", Buffer.from("helper")),
  bridgeSha256: "f".repeat(64),
};

binding.launchObserver=fixtureObserver(binding.publicWrapper.path,python);
binding.publicWrapper=identity(binding.publicWrapper.path,Buffer.from(binding.launchObserver.declaredText));
binding.monitor={executable:identity(binding.launchObserver.context.bwrap,Buffer.from("bwrap"))};
binding.resolverSha256="8".repeat(64);

test("derives the Linux GUI transform without touching the pinned source", () => {
  const originalSha = sha256(source);
  const result = derivePinnedGuiHarness(source, originalSha, binding);
  assert.equal(result.originalSourceSha256, originalSha);
  assert.equal(result.productionEnabled, false);
  assert.equal(result.publicationAuthority, false);
  assert(result.adapted.startsWith("#!/usr/bin/env node\nimport { spawnGuiBound }"));
  assert.match(result.adapted, /await gui\.bindApplication\(\);/);
  assert.match(result.adapted, /await gui\.terminateApplication\(\);/);
  assert.match(result.adapted, /await gui\.finalize\(\{ monitorExit: exit \}\);/);
  assert(!result.adapted.includes("entry.pid !== child.pid"));
  assert.equal(result.changes.length, 11);
  assert.match(result.adapted, /const exited = gui\.monitorExit/);
  assert.match(result.adapted, /launchTarget: P_GUI_CONTEXT\.publicWrapper\.path/);
  assert(!result.adapted.includes('if (exit.signal !== "SIGTERM")'));
  assert(!result.adapted.includes("process.kill("));
  assert(result.diff.includes("changes-json"));
  assert.equal(sha256(source), originalSha);
  assert.throws(() => derivePinnedGuiHarness(source, "0".repeat(64), binding), /pinned upstream source changed/);
});

test("materializes only regular derived closure files in a fresh directory", () => {
  const outputDir = mkdtempSync(join(tmpdir(), "p-native-gui-"));
  try {
    const adapterDir = new URL("../tools/verification/", import.meta.url);
    const closure = materializeControllerClosure({
      outputDir,
      bridgeSource: new URL("../tools/verification/p-native-gui-controller-bridge.mjs", import.meta.url).pathname,
      controllerSource: new URL("../tools/verification/p-native-gui-controller.py", import.meta.url).pathname,
      stableSource: new URL("../tools/verification/p-process-predicate-probe.py", import.meta.url).pathname,
      resolverSource: new URL("../tools/verification/p-native-gui-launch-binding.mjs", import.meta.url).pathname,
      stableSha256: "8caa44844e3d3c77911f6909f128e1ea1178ae29acc6d37eb3c430324ec28811",
    });
    assert.equal(closure.files.length, 4);
    assert.deepEqual(closure.files.map((file) => file.name), [
      "p-native-gui-controller-bridge.mjs",
      "p-native-gui-controller.py",
      "p-process-predicate-probe.py",
      "p-native-gui-launch-binding.mjs",
    ]);
    assert(closure.files.every((file) => file.mode === 0o644 && file.bytes > 0));
    assert.equal(adapterDir.protocol, "file:");
    assert.throws(() => materializeControllerClosure({
      outputDir: new URL("../tools/verification/", import.meta.url).pathname,
      bridgeSource: new URL("../tools/verification/p-native-gui-controller-bridge.mjs", import.meta.url).pathname,
      controllerSource: new URL("../tools/verification/p-native-gui-controller.py", import.meta.url).pathname,
      stableSource: new URL("../tools/verification/p-process-predicate-probe.py", import.meta.url).pathname,
      resolverSource: new URL("../tools/verification/p-native-gui-launch-binding.mjs", import.meta.url).pathname,
    }), /outside each authenticated source directory/);
  } finally {
    rmSync(outputDir, { recursive: true, force: true });
  }
});

test("controller protocol parser rejects malformed or unbounded lines", () => {
  assert.deepEqual(parseControllerLine('{"op":"BOUND"}'), { op: "BOUND" });
  assert.throws(() => parseControllerLine("not-json"));
  assert.throws(() => parseControllerLine('{"op":"bind"}'));
  assert.throws(() => parseControllerLine('{"op":"BOUND","op":"BOUND"}'));
  assert.throws(() => parseControllerLine('{"op":"BOUND","value":NaN}'));
  assert.throws(() => parseControllerLine('{"op":"BOUND"}trailing'));
  assert.throws(() => parseControllerLine(`{"op":"BOUND","padding":"${"x".repeat(70_000)}"}`));
  assert.doesNotThrow(() => validateContext({
    schema: "theme-forge.p-native-gui-context.v1",
    transform: "p-linux-gui-controller-v1",
    pCommit: "a".repeat(40), pTree: "b".repeat(40), nebularCommit: "c".repeat(40), nebularTree: "d".repeat(40),
    rawExecutable: binding.rawExecutable, publicWrapper: binding.publicWrapper,
    monitor: binding.monitor, controller: binding.controller, predicateHelper: binding.predicateHelper, bridgeSha256: binding.bridgeSha256, resolverSha256: binding.resolverSha256, launchObserver: binding.launchObserver,
  }));
  assert.throws(() => validateContext({
    schema: "theme-forge.p-native-gui-context.v1",
    transform: "p-linux-gui-controller-v1",
    pCommit: "a".repeat(40), pTree: "b".repeat(40), nebularCommit: "c".repeat(40), nebularTree: "d".repeat(40),
    rawExecutable: binding.rawExecutable, publicWrapper: binding.publicWrapper,
    monitor: binding.monitor, controller: binding.controller, predicateHelper: binding.predicateHelper, bridgeSha256: binding.bridgeSha256, resolverSha256: binding.resolverSha256, launchObserver: binding.launchObserver, appPid: 99,
  }));
});

test("qualification route keeps Darwin mechanics and declares explicit Linux controller selection", () => {
  const qualify = readFileSync(new URL("../tools/verification/qualify-p-current-nix.mjs", import.meta.url), "utf8");
  assert.match(qualify, /\['x86_64-linux', 'aarch64-linux'\]\.includes\(system\) && guiBinding !== null/);
  assert.match(qualify, /p-process-predicate-probe\.py/);
  assert.match(qualify, /prepareNativeGuiHarness/);
  assert.match(qualify, /preparePublicWrapperHarness/);
  assert.match(qualify, /\['x86_64-linux', 'aarch64-linux'\]\.includes\(system\) && guiBinding !== null\n    \? prepareNativeGuiHarness/);
  assert.match(qualify, /: preparePublicWrapperHarness/);
  assert.match(qualify, /productionEnabled: false/);
});

test("controller cleanup is fail-closed and uses held-process boundaries", () => {
  const controller = readFileSync(new URL("../tools/verification/p-native-gui-controller.py", import.meta.url), "utf8");
  assert.match(controller, /select\.select\(\[fd\]/);
  assert.match(controller, /cleanup=\(self\.application_fd/);
  assert.match(controller, /_revalidate_handles/);
  assert.doesNotMatch(controller, /os\.kill\(/);
  assert.doesNotMatch(controller, /kill\(-/);
  assert.match(controller, /controller framing\/EOF/);
});

test("response identity and cleanup shapes are closed before control", () => {
  const context = {
    schema: "theme-forge.p-native-gui-context.v1", transform: "p-linux-gui-controller-v1",
    pCommit: "a".repeat(40), pTree: "b".repeat(40), nebularCommit: "c".repeat(40), nebularTree: "d".repeat(40),
    rawExecutable: binding.rawExecutable, publicWrapper: binding.publicWrapper, monitor: binding.monitor,
    controller: binding.controller, predicateHelper: binding.predicateHelper, bridgeSha256: binding.bridgeSha256, resolverSha256: binding.resolverSha256, launchObserver: binding.launchObserver,
  };
  const state = { nonce: "1".repeat(32), launchBindingSha256:"9".repeat(64), monitor: null, application: null };
  const process = (pid, start, executable) => ({ pid, start, executable: { dev: 1, ino: pid, size: executable.size, sha256: executable.sha256 } });
  const response = {
    accepted: true, application: process(303, 4, binding.rawExecutable), monitor: process(202, 3, binding.monitor.executable), nonce: state.nonce,
    op: "BOUND", schema: "theme-forge.p-native-gui-controller.v1",
    launchBindingSha256:state.launchBindingSha256,
    source: { pCommit: context.pCommit, pTree: context.pTree, nebularCommit: context.nebularCommit, nebularTree: context.nebularTree },
    target: "x86_64-unknown-linux-gnu",
  };
  assert.doesNotThrow(() => validateResponse(response, "BOUND", state, context, binding.rawExecutable, 202, "linux-x64", "C"));
  assert.throws(() => validateResponse({ ...response, extra: true }, "BOUND", state, context, binding.rawExecutable, 202, "linux-x64", "C"));
  assert.throws(() => validateResponse({ ...response, nonce: "2".repeat(32) }, "BOUND", state, context, binding.rawExecutable, 202, "linux-x64", "C"));
});

test("staged harness imports its authenticated upstream helpers outside checkout",async()=>{
  const outputDir=mkdtempSync(join(tmpdir(),"p-gui-imports-"));
  try{
    materializeControllerClosure({
      outputDir,
      bridgeSource:new URL("../tools/verification/p-native-gui-controller-bridge.mjs",import.meta.url).pathname,
      controllerSource:new URL("../tools/verification/p-native-gui-controller.py",import.meta.url).pathname,
      stableSource:new URL("../tools/verification/p-process-predicate-probe.py",import.meta.url).pathname,
      resolverSource:new URL("../tools/verification/p-native-gui-launch-binding.mjs",import.meta.url).pathname,
      stableSha256:"8caa44844e3d3c77911f6909f128e1ea1178ae29acc6d37eb3c430324ec28811",
    });
    const result=materializeDerivedHarness({sourcePath,outputDir,expectedOriginalSha256:sha256(source),binding});
    assert.equal(result.upstreamImports.length,4);
    assert(result.upstreamImports.every(item=>item.sourceUrl.startsWith("file:")&&item.sha256.length===64));
    const imported=await import(pathToFileURL(result.target).href);
    assert.equal(typeof imported.runSmoke,"function");
    assert.equal(sha256(readFileSync(sourcePath)),sha256(source));
  }finally{rmSync(outputDir,{recursive:true,force:true});}
});
