/**
 * P-owned, test-only derivation of the pinned Nebular smoke harness.
 *
 * This module never edits the authenticated Nebular checkout.  It emits a
 * separately named harness plus a closed binding record.  The derived source
 * is not a GUI qualification receipt and cannot grant publication authority.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, lstatSync, readlinkSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { validateObserverInputs } from "./p-native-gui-controller-bridge.mjs";

export const GUI_ADAPTER_SCHEMA = "theme-forge.p-native-gui-adapter.v1";
export const GUI_TRANSFORM = "p-linux-gui-controller-v1";
export const GUI_CONTEXT_SCHEMA = "theme-forge.p-native-gui-context.v1";

export const ANCHORS = Object.freeze({
  importPrefix: "#!/usr/bin/env node\n",
  spawn: '      const child = spawn(launchTarget, [`--nebular-release-smoke=${scenario}`], { cwd: home, env, detached: true, stdio: ["ignore", "pipe", "pipe"] });',
  launched: '      if (typeof child.pid === "number") run.launched();',
  sidecar: "entry.pid !== child.pid",
  signal: '          process.kill(child.pid, "SIGTERM");',
  timeoutKill: '        try { process.kill(-child.pid, "SIGKILL"); } catch { /* already gone */ }',
  orphanKill: '        for (const entry of orphans) { try { process.kill(entry.pid, "SIGKILL"); } catch { /* gone */ } }',
  receipt: "      const record = run.receipt(",
  exited: "      run.exited();",
  judgePid: "pid: child.pid",
  exitedPromise: '      const exited = new Promise((done) => child.on("exit", (code, signal) => done({ code, signal })));',
  signalJudge: 'if (exit.signal !== "SIGTERM")',
});

const HEX40 = /^[a-f0-9]{40}$/;
const HEX64 = /^[a-f0-9]{64}$/;

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireText(value, label) {
  assert.equal(typeof value, "string", `${label} must be text`);
  assert(!/[\u0000-\u001f\u007f]/.test(value), `${label} contains control bytes`);
  return value;
}

function requireHex(value, label, pattern = HEX64) {
  assert(pattern.test(value), `${label} must be lowercase hexadecimal`);
  return value;
}

function requirePath(value, label) {
  requireText(value, label);
  assert(value.startsWith("/"), `${label} must be absolute`);
  assert(!value.includes("/../") && !value.endsWith("/.."), `${label} may not contain parent traversal`);
  return value;
}

function requireIdentity(identity, label) {
  assert(identity && typeof identity === "object" && !Array.isArray(identity), `${label} must be an object`);
  assert.equal(Object.keys(identity).sort().join(","), "path,sha256,size", `${label} fields are closed`);
  requirePath(identity.path, `${label}.path`);
  requireHex(identity.sha256, `${label}.sha256`);
  assert(Number.isSafeInteger(identity.size) && identity.size > 0, `${label}.size must be positive`);
  return Object.freeze({ path: identity.path, sha256: identity.sha256, size: identity.size });
}

function requireMonitorIdentity(identity) {
  assert(identity && typeof identity === "object" && !Array.isArray(identity), "monitor identity required");
  assert.equal(Object.keys(identity).sort().join(","), "executable", "monitor identity fields are closed");
  const executable = requireIdentity(identity.executable, "monitor.executable");
  return Object.freeze({ executable });
}

function requireController(controller) {
  assert(controller && typeof controller === "object" && !Array.isArray(controller), "controller binding required");
  assert.equal(Object.keys(controller).sort().join(","), "python,scriptSha256", "controller fields are closed");
  requirePath(controller.python, "controller.python");
  assert(controller.python.startsWith("/nix/store/"), "controller Python must be the locked Nix output");
  requireHex(controller.scriptSha256, "controller.scriptSha256");
  return Object.freeze({ python: controller.python, scriptSha256: controller.scriptSha256 });
}

function requireBinding(binding) {
  assert(binding && typeof binding === "object" && !Array.isArray(binding), "GUI binding required");
  const required = ["pCommit", "pTree", "nebularCommit", "nebularTree", "rawExecutable", "publicWrapper", "monitor", "controller", "predicateHelper", "bridgeSha256", "resolverSha256", "launchObserver"];
  assert.equal(Object.keys(binding).sort().join(","), required.slice().sort().join(","), "GUI binding fields are closed");
  assert(HEX40.test(binding.pCommit) && HEX40.test(binding.pTree), "P source identity is invalid");
  assert(HEX40.test(binding.nebularCommit) && HEX40.test(binding.nebularTree), "Nebular source identity is invalid");
  const rawExecutable = requireIdentity(binding.rawExecutable, "rawExecutable");
  const publicWrapper = requireIdentity(binding.publicWrapper, "publicWrapper");
  const monitor = requireMonitorIdentity(binding.monitor);
  const controller = requireController(binding.controller);
  const predicateHelper = requireIdentity(binding.predicateHelper, "predicateHelper");
  requireHex(binding.bridgeSha256, "bridgeSha256");
  requireHex(binding.resolverSha256, "resolverSha256");
  validateObserverInputs(binding.launchObserver,publicWrapper,controller.python);
  assert.equal(monitor.executable.path,binding.launchObserver.context.bwrap,"monitor differs from declared bubblewrap");
  return Object.freeze({
    schema: GUI_CONTEXT_SCHEMA,
    transform: GUI_TRANSFORM,
    pCommit: binding.pCommit,
    pTree: binding.pTree,
    nebularCommit: binding.nebularCommit,
    nebularTree: binding.nebularTree,
    rawExecutable,
    publicWrapper,
    monitor,
    controller,
    predicateHelper,
    bridgeSha256: binding.bridgeSha256,
    resolverSha256: binding.resolverSha256,
    launchObserver: binding.launchObserver,
  });
}

function replaceExactly(text, anchor, replacement, label) {
  const count = text.split(anchor).length - 1;
  assert.equal(count, 1, `${label} must occur exactly once`);
  return text.replace(anchor, replacement);
}

function changedLines(before, after) {
  const oldLines = before.split("\n");
  const newLines = after.split("\n");
  const limit = Math.max(oldLines.length, newLines.length);
  const changed = [];
  for (let index = 0; index < limit; index += 1) {
    if (oldLines[index] !== newLines[index]) changed.push(index + 1);
  }
  return changed;
}

function makeContextLiteral(context) {
  return `const P_GUI_CONTEXT = Object.freeze(${JSON.stringify(context)});`;
}

export function derivePinnedGuiHarness(originalBytes, expectedOriginalSha256, binding, bridgeSpecifier = "./p-native-gui-controller-bridge.mjs", upstreamToolsDirectory = null) {
  assert(Buffer.isBuffer(originalBytes), "upstream smoke source must be bytes");
  requireHex(expectedOriginalSha256, "expected upstream source SHA");
  assert.equal(sha256(originalBytes), expectedOriginalSha256, "pinned upstream source changed");
  const context = requireBinding(binding);
  requireText(bridgeSpecifier, "bridge specifier");
  assert(bridgeSpecifier.startsWith("./") && !bridgeSpecifier.includes(".."), "bridge must be a local sibling");
  const original = originalBytes.toString("utf8");
  assert(original.startsWith(ANCHORS.importPrefix), "unexpected smoke source preamble");

  const importLine = `import { spawnGuiBound } from ${JSON.stringify(bridgeSpecifier)};\n`;
  const contextLine = `${makeContextLiteral(context)}\n`;
  let adapted = ANCHORS.importPrefix + importLine + contextLine + original.slice(ANCHORS.importPrefix.length);
  const changes = [
    { label: "local bridge import", beforeSha256: sha256(Buffer.from(ANCHORS.importPrefix)), afterSha256: sha256(Buffer.from(ANCHORS.importPrefix + importLine + contextLine)), beforeBytes: Buffer.byteLength(ANCHORS.importPrefix), afterBytes: Buffer.byteLength(ANCHORS.importPrefix + importLine + contextLine) },
  ];
  function replaceTracked(label, anchor, replacement) {
    changes.push({ label, beforeSha256: sha256(Buffer.from(anchor)), afterSha256: sha256(Buffer.from(replacement)), beforeBytes: Buffer.byteLength(anchor), afterBytes: Buffer.byteLength(replacement) });
    adapted = replaceExactly(adapted, anchor, replacement, label);
  }
  const spawn = `      const gui = await spawnGuiBound({ launchTarget: P_GUI_CONTEXT.publicWrapper.path, args: [\`--nebular-release-smoke=\${scenario}\`], options: { cwd: home, env, detached: true, stdio: ["ignore", "pipe", "pipe"] }, expectedApp: { path: executable, sha256: measured.sha256, size: measured.size }, context: P_GUI_CONTEXT, platform, scenario, smokeDir, controllerEvidenceDir: evidenceDir, label });\n      const child = gui.child;`;
  replaceTracked("spawn boundary", ANCHORS.spawn, spawn);
  replaceTracked("launch marker", ANCHORS.launched, ANCHORS.launched);
  replaceTracked("owned exit binding", ANCHORS.exitedPromise, "      const exited = gui.monitorExit;\n      await gui.bindApplication();");
  replaceTracked("monitor signal exit", ANCHORS.signalJudge, 'if (exit.code !== 143 || exit.signal !== null)');
  replaceTracked("sidecar exclusion", ANCHORS.sidecar, "entry.pid !== gui.applicationPid()");
  replaceTracked("C-signal boundary", ANCHORS.signal, "          await gui.terminateApplication();");
  replaceTracked("timeout failure cleanup", ANCHORS.timeoutKill, "        await gui.abortFailure();");
  replaceTracked("orphan failure cleanup", ANCHORS.orphanKill, "        await gui.abortFailure();");
  replaceTracked("finalization boundary", ANCHORS.receipt, `      await gui.finalize({ monitorExit: exit });\n${ANCHORS.receipt}`);
  replaceTracked("receipt PID boundary", ANCHORS.judgePid, "pid: gui.applicationPid()");

  const upstreamImports = [];
  if (upstreamToolsDirectory !== null) {
    requirePath(upstreamToolsDirectory, "authenticated upstream tools directory");
    for (const name of ["fs-snapshot.mjs", "native-launcher.mjs", "native-rc-package.mjs", "native-runtime.mjs"]) {
      const imported = join(upstreamToolsDirectory, name);
      const info = lstatSync(imported);
      assert(info.isFile() && !info.isSymbolicLink(), "upstream helper must be a regular tracked source");
      const bytes = readFileSync(imported);
      const sourceUrl = pathToFileURL(imported).href;
      replaceTracked(`authenticated import ${name}`, `from "./${name}";`, `from ${JSON.stringify(sourceUrl)};`);
      upstreamImports.push({ name, path: imported, bytes: bytes.length, sha256: sha256(bytes), sourceUrl });
    }
  }
  const changed = changedLines(original, adapted);
  assert(changed.length > 0, "GUI transform must change source");
  const diff = [
    "--- pinned/tools/native-rc-smoke.mjs",
    "+++ derived/tools/native-rc-smoke.p-native-gui.mjs",
    `@@ transform=${GUI_TRANSFORM} changed-lines=${changed.join(",")}`,
    `-source-sha256 ${sha256(originalBytes)}`,
    `+derived-sha256 ${sha256(Buffer.from(adapted))}`,
    `changes-json ${JSON.stringify(changes)}`,
  ].join("\n") + "\n";
  return Object.freeze({
    schema: GUI_ADAPTER_SCHEMA,
    transform: GUI_TRANSFORM,
    originalSource: "tools/native-rc-smoke.mjs",
    originalSourceSha256: sha256(originalBytes),
    adaptedSource: "tools/native-rc-smoke.p-native-gui.mjs",
    adaptedSourceSha256: sha256(Buffer.from(adapted)),
    adaptationDiffSha256: sha256(Buffer.from(diff)),
    changedLines: Object.freeze(changed),
    changes: Object.freeze(changes.map((change) => Object.freeze(change))),
    bridgeSpecifier,
    upstreamImports: Object.freeze(upstreamImports),
    context,
    adapted,
    diff,
    productionEnabled: false,
    publicationAuthority: false,
  });
}

export function materializeControllerClosure({ outputDir, bridgeSource, controllerSource, stableSource, resolverSource, stableSha256 = null }) {
  requirePath(outputDir, "controller closure output directory");
  const sources = [
    ["p-native-gui-controller-bridge.mjs", bridgeSource, 0o644],
    ["p-native-gui-controller.py", controllerSource, 0o644],
    ["p-process-predicate-probe.py", stableSource, 0o644],
    ["p-native-gui-launch-binding.mjs", resolverSource, 0o644],
  ];
  const outputResolved = resolve(outputDir);
  for (const [, source] of sources) {
    const sourceParent = dirname(resolve(source));
    assert(outputResolved !== sourceParent && !outputResolved.startsWith(`${sourceParent}/`),
      "derived closure must be staged outside each authenticated source directory");
  }
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  const files = [];
  for (const [name, source, mode] of sources) {
    requirePath(source, `${name} source`);
    const sourceInfo = lstatSync(source);
    assert(sourceInfo.isFile() && !sourceInfo.isSymbolicLink() && sourceInfo.nlink === 1, `${name} source must be a regular single-link file`);
    const bytes = readFileSync(source);
    const target = join(outputDir, name);
    writeFileSync(target, bytes, { flag: "wx", mode });
    const targetInfo = lstatSync(target);
    assert(targetInfo.isFile() && !targetInfo.isSymbolicLink() && targetInfo.nlink === 1, `${name} derived file must be a regular single-link file`);
    files.push(Object.freeze({ name, path: target, source, bytes: bytes.length, sha256: sha256(bytes), mode: targetInfo.mode & 0o777 }));
  }
  if (stableSha256 !== null) {
    requireHex(stableSha256, "predicate helper sha256");
    assert.equal(files.find((file) => file.name === "p-process-predicate-probe.py").sha256, stableSha256,
      "predicate helper bytes changed");
  }
  return Object.freeze({ outputDir, files: Object.freeze(files) });
}

export function materializeDerivedHarness({ sourcePath, outputDir, expectedOriginalSha256, binding, bridgeSpecifier }) {
  const originalBytes = readFileSync(sourcePath);
  const derived = derivePinnedGuiHarness(originalBytes, expectedOriginalSha256, binding, bridgeSpecifier, dirname(sourcePath));
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  const target = join(outputDir, "native-rc-smoke.p-native-gui.mjs");
  writeFileSync(target, derived.adapted, { flag: "wx", mode: 0o644 });
  const originalInfo = lstatSync(sourcePath);
  const targetInfo = lstatSync(target);
  assert(originalInfo.isFile() && targetInfo.isFile(), "derived harness must be regular files");
  return Object.freeze({ ...derived, target, targetRealpath: realpathSync(target) });
}
