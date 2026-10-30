/**
 * Node-side owner bridge for the P-derived Linux GUI harness.
 *
 * This module owns the wrapper ChildProcess and wait status.  The Python
 * sibling discovers the application and owns only the pidfd/procfs witness.
 * The bridge has no numeric-PID signal API and is intentionally not a generic
 * launcher override.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { readFileSync, lstatSync, realpathSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { authenticateWrapper, freezeLaunchInputs, stageObserver, resolveFreshLaunch, removeObserver,
  isFreshLaunchBinding } from "./p-native-gui-launch-binding.mjs";

export const CONTROLLER_SCHEMA = "theme-forge.p-native-gui-controller.v1";
export const CONTROLLER_TERMINATE_WAIT_MS = 38_000;
const MAX_LINE_BYTES = 65536;
const HEX64 = /^[a-f0-9]{64}$/;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function text(value, label) {
  assert.equal(typeof value, "string", `${label} must be text`);
  assert(!/[\u0000-\u001f\u007f]/.test(value), `${label} contains control bytes`);
  return value;
}

function hash(value, label) {
  assert(HEX64.test(value), `${label} must be a lowercase SHA-256`);
  return value;
}

function absolute(value, label) {
  text(value, label);
  assert(value.startsWith("/"), `${label} must be absolute`);
  assert(!value.includes("/../") && !value.endsWith("/.."), `${label} contains traversal`);
  return value;
}

function identity(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} identity required`);
  assert.equal(Object.keys(value).sort().join(","), "path,sha256,size", `${label} identity fields are closed`);
  absolute(value.path, `${label}.path`);
  hash(value.sha256, `${label}.sha256`);
  assert(Number.isSafeInteger(value.size) && value.size > 0, `${label}.size must be positive`);
  return value;
}

function fileIdentity(path, label) {
  const info = lstatSync(path);
  assert(info.isFile() && !info.isSymbolicLink(), `${label} must be a regular file`);
  const bytes = readFileSync(path);
  return { path, sha256: sha256(bytes), size: bytes.length };
}

function positiveInteger(value, label) {
  assert(Number.isSafeInteger(value) && value > 0, `${label} must be positive integer`);
  return value;
}

function processIdentity(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} identity required`);
  assert.equal(Object.keys(value).sort().join(","), "dev,ino,sha256,size", `${label} identity fields are closed`);
  positiveInteger(value.dev, `${label}.dev`);
  positiveInteger(value.ino, `${label}.ino`);
  positiveInteger(value.size, `${label}.size`);
  hash(value.sha256, `${label}.sha256`);
  return value;
}

function boundProcess(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} binding required`);
  assert.equal(Object.keys(value).sort().join(","), "executable,pid,start", `${label} fields are closed`);
  positiveInteger(value.pid, `${label}.pid`);
  positiveInteger(value.start, `${label}.start`);
  processIdentity(value.executable, `${label}.executable`);
  return value;
}

function sourceIdentity(context) {
  return { pCommit: context.pCommit, pTree: context.pTree, nebularCommit: context.nebularCommit, nebularTree: context.nebularTree };
}

function assertSource(value, context) {
  assert(value && typeof value === "object" && !Array.isArray(value), "response source required");
  assert.deepEqual(value, sourceIdentity(context), "response source changed");
}

function validateWitness(value, state) {
  assert(value && typeof value === "object" && !Array.isArray(value), "C-signal witness required");
  assert.equal(Object.keys(value).sort().join(","), "exit_code,pid,ppid,start,state", "witness fields are closed");
  for (const key of ["exit_code", "pid", "ppid", "start"]) {
    assert(Number.isSafeInteger(value[key]) && value[key] > 0, `witness ${key} type`);
  }
  assert.equal(value.pid, state.application.pid, "witness application PID");
  assert.equal(value.ppid, state.monitor.pid, "witness monitor parent");
  assert.equal(value.start, state.application.start, "witness application start");
  assert.equal(value.state, "Z", "witness zombie state");
  assert.equal(value.exit_code, 15, "witness is not exact SIGTERM 15");
  return value;
}

function validateWatchdog(value) {
  assert(value && typeof value === "object" && !Array.isArray(value), "watchdog proof required");
  assert.equal(Object.keys(value).sort().join(","), "acknowledgements,nonceSha256,rescue", "watchdog fields are closed");
  hash(value.nonceSha256, "watchdog nonce digest");
  assert.equal(value.rescue, false, "watchdog rescue was reported during a passing transaction");
  assert(Array.isArray(value.acknowledgements) && value.acknowledgements.length >= 1, "watchdog acknowledgements");
  let previous = 0;
  for (const item of value.acknowledgements) {
    assert(item && typeof item === "object" && !Array.isArray(item), "watchdog acknowledgement object");
    assert.equal(Object.keys(item).sort().join(","), "op,seq", "watchdog acknowledgement fields");
    assert(["ARMED", "DISARMED"].includes(item.op), "watchdog acknowledgement operation");
    positiveInteger(item.seq, "watchdog acknowledgement sequence");
    assert(item.seq > previous, "watchdog acknowledgement sequence order");
    previous = item.seq;
  }
  assert.equal(value.acknowledgements[0].op, "ARMED", "watchdog was not armed");
  assert.equal(value.acknowledgements.at(-1).op, "DISARMED", "watchdog was not disarmed");
  return value;
}

function validateMonitorExit(value, expected) {
  assert(value && typeof value === "object" && !Array.isArray(value), "monitor exit required");
  assert.equal(Object.keys(value).sort().join(","), "code,signal", "monitor exit fields are closed");
  assert(value.code === null || Number.isSafeInteger(value.code), "monitor exit code");
  assert(value.signal === null || typeof value.signal === "string", "monitor exit signal");
  assert.deepEqual(value, expected, "monitor exit changed");
  return value;
}

function validateCleanup(value) {
  assert(value && typeof value === "object" && !Array.isArray(value), "cleanup proof required");
  assert.equal(Object.keys(value).sort().join(","), "application,controller,monitor", "cleanup fields are closed");
  assert.deepEqual(value, { application: "exited", controller: "closed", monitor: "node-waited" }, "cleanup proof");
  return value;
}


const canonical = value => JSON.stringify(value, (key, entry) =>
  entry && !Array.isArray(entry) && typeof entry === "object"
    ? Object.fromEntries(Object.keys(entry).sort().map(name => [name, entry[name]])) : entry);
const digestObject = value => sha256(Buffer.from(canonical(value)));

export function validateObserverInputs(value, publicWrapper, python) {
  const fields = ["schema","declaredText","expectedSha256","wrapperPath","expectedResolvedWrapperPath",
    "pinnedBash","context","buildFhsEnvSourceSha256","containerSourceSha256","declaredDerivation",
    "declaredDerivationSha256","containerProducer","productClosureSha256","nixpkgsRevision","python","publicationAuthority"];
  assert(value && typeof value === "object" && !Array.isArray(value), "observer inputs object");
  assert.equal(Object.keys(value).sort().join(","),fields.sort().join(","),"observer input fields");
  assert.equal(value.schema,"theme-forge.p-native-gui-observer-inputs.v1");
  assert.equal(value.publicationAuthority,false);
  assert.equal(value.python,python,"observer Python differs");
  assert.equal(value.wrapperPath,publicWrapper.path,"observer public wrapper differs");
  assert.equal(value.expectedSha256,publicWrapper.sha256,"observer wrapper digest differs");
  absolute(value.expectedResolvedWrapperPath,"resolved wrapper");
  assert(value.expectedResolvedWrapperPath.startsWith("/nix/store/"),"resolved wrapper outside store");
  assert.equal(value.nixpkgsRevision,"b6c8664de9b6cc07fe5666a29f91884ba81197c4","observer Nix pin differs");
  assert.equal(value.buildFhsEnvSourceSha256,"5c642cc3eed380324d3109a9a428be020ed529774f5c4f5877bb2bb1b93ac93f");
  assert.equal(value.containerSourceSha256,"40f92dd2ca8e5161e55b5d85c2ece3a79a43b6d96dc20d6b0b05a0fcabf4c7fd");
  absolute(value.declaredDerivation,"declared derivation");
  assert(value.declaredDerivation.startsWith("/nix/store/") && value.declaredDerivation.endsWith(".drv"));
  hash(value.declaredDerivationSha256,"declared derivation digest");
  hash(value.productClosureSha256,"product closure digest");
  assert(value.containerProducer && typeof value.containerProducer === "object"
    && !Array.isArray(value.containerProducer) && Object.keys(value.containerProducer).length>0,"container producer missing");
  assert.equal(typeof value.declaredText,"string","declared wrapper text missing");
  assert(Buffer.byteLength(value.declaredText)>0 && Buffer.byteLength(value.declaredText)<=131072,"declared wrapper bound");
  assert(Buffer.byteLength(JSON.stringify(value))<=65536,"observer inputs bound");
  const bytes=Buffer.from(value.declaredText);
  return authenticateWrapper({wrapperBytes:bytes,declaredBytes:bytes,expectedSha256:value.expectedSha256,
    pinnedBash:value.pinnedBash,context:value.context,buildFhsEnvSourceSha256:value.buildFhsEnvSourceSha256,
    containerSourceSha256:value.containerSourceSha256});
}

export function validateFreshLaunchFacts(facts, context, scenario) {
  const fields=["schema","source","nonce","wrapperBindingSha256","wrapperPublicPathSha256","wrapperResolvedPathSha256",
    "cwdSha256","environmentSha256","smokeArgumentsSha256","argvSha256","argvCount","optionCount","stdoutBytes",
    "stderrBytes","stderrSha256","deadlineMs","outputLimitBytes","processExitObserved","observerExitCode",
    "observerExitSignal","stdoutEOF","stderrEOF","exactSourceReadbacks","fixtureMode","admitting","guiQualification",
    "nativeQualification","productionEnabled","publicationAuthority","bindingSha256"];
  assert(facts && typeof facts==="object" && !Array.isArray(facts),"fresh launch facts object");
  assert.equal(Object.keys(facts).sort().join(","),fields.sort().join(","),"fresh launch fact fields");
  assert.equal(facts.schema,"theme-forge.p-gui-fresh-launch-binding.v1");
  for(const key of ["nonce","wrapperBindingSha256","wrapperPublicPathSha256","wrapperResolvedPathSha256",
    "cwdSha256","environmentSha256","smokeArgumentsSha256","argvSha256","stderrSha256","bindingSha256"]) hash(facts[key],key);
  const rest={...facts};delete rest.bindingSha256;
  assert.equal(facts.bindingSha256,digestObject(rest),"fresh launch binding digest differs");
  const expected=validateObserverInputs(context.launchObserver,context.publicWrapper,context.controller.python);
  assert.deepEqual(facts.source,expected.facts,"fresh launch wrapper source differs");
  assert.equal(facts.wrapperPublicPathSha256,sha256(Buffer.from(context.publicWrapper.path)));
  assert.equal(facts.wrapperResolvedPathSha256,sha256(Buffer.from(context.launchObserver.expectedResolvedWrapperPath)));
  assert.equal(facts.smokeArgumentsSha256,digestObject(["--nebular-release-smoke="+scenario]),"fresh smoke argument differs");
  for(const key of ["processExitObserved","stdoutEOF","stderrEOF","exactSourceReadbacks"]) assert.equal(facts[key],true,key);
  for(const key of ["fixtureMode","admitting","guiQualification","nativeQualification","productionEnabled","publicationAuthority"])
    assert.equal(facts[key],false,key);
  assert.equal(facts.observerExitCode,0);assert.equal(facts.observerExitSignal,null);
  assert.equal(facts.deadlineMs,10000);assert.equal(facts.outputLimitBytes,1048576);
  assert(Number.isSafeInteger(facts.argvCount) && facts.argvCount>0 && facts.argvCount<=8192);
  assert(Number.isSafeInteger(facts.optionCount) && facts.optionCount>0 && facts.optionCount<facts.argvCount);
  for(const key of ["stdoutBytes","stderrBytes"]) assert(Number.isSafeInteger(facts[key]) && facts[key]>=0 && facts[key]<=1048576);
  assert(facts.stdoutBytes>0 && facts.stdoutBytes+facts.stderrBytes<=1048576,"observer output aggregate bound");
  return facts.bindingSha256;
}

export function validateContext(context) {
  assert(context && typeof context === "object" && !Array.isArray(context), "GUI context required");
  assert.equal(Object.keys(context).sort().join(","),
    ["bridgeSha256", "controller", "monitor", "nebularCommit", "nebularTree", "pCommit", "pTree", "predicateHelper", "publicWrapper", "rawExecutable", "schema", "transform", "launchObserver", "resolverSha256"].sort().join(","),
    "GUI context fields are closed");
  assert.equal(context.schema, "theme-forge.p-native-gui-context.v1", "wrong GUI context schema");
  assert.equal(context.transform, "p-linux-gui-controller-v1", "wrong GUI transform");
  for (const key of ["pCommit", "pTree", "nebularCommit", "nebularTree"]) {
    assert(/^[a-f0-9]{40}$/.test(context[key]), `${key} is not a Git identity`);
  }
  identity(context.rawExecutable, "raw executable");
  identity(context.publicWrapper, "public wrapper");
  assert(context.monitor && typeof context.monitor === "object", "monitor binding missing");
  assert.equal(Object.keys(context.monitor).sort().join(","), "executable", "monitor binding fields are closed");
  identity(context.monitor.executable, "monitor executable");
  assert(context.controller && typeof context.controller === "object", "controller binding missing");
  assert.equal(Object.keys(context.controller).sort().join(","), "python,scriptSha256", "controller binding fields are closed");
  absolute(context.controller.python, "controller Python");
  assert(context.controller.python.startsWith("/nix/store/"), "controller Python must be locked Nix output");
  hash(context.controller.scriptSha256, "controller script");
  identity(context.predicateHelper, "predicate helper");
  hash(context.bridgeSha256, "controller bridge");
  hash(context.resolverSha256, "launch resolver");
  validateObserverInputs(context.launchObserver,context.publicWrapper,context.controller.python);
  assert.equal(context.monitor.executable.path,context.launchObserver.context.bwrap,"monitor differs from declared bubblewrap");
}

function skipJsonString(raw, start) {
  assert(raw[start] === '"', "JSON string expected");
  let escaped = false;
  for (let index = start + 1; index < raw.length; index += 1) {
    const character = raw[index];
    if (escaped) { escaped = false; continue; }
    if (character === "\\") { escaped = true; continue; }
    if (character === '"') return index + 1;
    assert(character >= " " && character !== "\u007f", "JSON control byte");
  }
  throw new Error("unterminated JSON string");
}

function skipJsonWhitespace(raw, start) {
  let index = start;
  while (index < raw.length && /\s/.test(raw[index])) index += 1;
  return index;
}

function scanUniqueJson(raw, start = 0) {
  let index = skipJsonWhitespace(raw, start);
  const first = raw[index];
  if (first === '"') return skipJsonString(raw, index);
  if (first === "{") {
    index = skipJsonWhitespace(raw, index + 1);
    const keys = new Set();
    if (raw[index] === "}") return index + 1;
    while (true) {
      assert(raw[index] === '"', "JSON object key expected");
      const keyStart = index;
      index = skipJsonString(raw, index);
      const key = JSON.parse(raw.slice(keyStart, index));
      assert(!keys.has(key), `duplicate JSON response field ${key}`);
      keys.add(key);
      index = skipJsonWhitespace(raw, index);
      assert(raw[index] === ":", "JSON object colon expected");
      index = scanUniqueJson(raw, index + 1);
      index = skipJsonWhitespace(raw, index);
      if (raw[index] === "}") return index + 1;
      assert(raw[index] === ",", "JSON object separator expected");
      index = skipJsonWhitespace(raw, index + 1);
    }
  }
  if (first === "[") {
    index = skipJsonWhitespace(raw, index + 1);
    if (raw[index] === "]") return index + 1;
    while (true) {
      index = scanUniqueJson(raw, index);
      index = skipJsonWhitespace(raw, index);
      if (raw[index] === "]") return index + 1;
      assert(raw[index] === ",", "JSON array separator expected");
      index = skipJsonWhitespace(raw, index + 1);
    }
  }
  const primitive = raw.slice(index).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/);
  assert(primitive, "JSON value expected");
  return index + primitive[0].length;
}

export function parseUniqueJson(line) {
  assert.equal(typeof line, "string", "JSON input must be text");
  assert(Buffer.byteLength(line, "utf8") <= MAX_LINE_BYTES, "JSON input exceeds bound");
  const end = scanUniqueJson(line);
  assert(skipJsonWhitespace(line, end) === line.length, "trailing JSON response data");
  return JSON.parse(line);
}

export function parseControllerLine(line) {
  text(line, "controller line");
  const value = parseUniqueJson(line);
  assert(value && typeof value === "object" && !Array.isArray(value), "controller response must be an object");
  assert(typeof value.op === "string" && ["BOUND", "TERMINATED", "FINALIZED"].includes(value.op), "controller response operation");
  return value;
}

export function boundedResponses(child) {
  const pending = [];
  const waiters = [];
  let failure = null;
  let buffer = Buffer.alloc(0);
  const fail = (error) => {
    if (failure) return;
    failure = error;
    buffer = Buffer.alloc(0);
    while (waiters.length) waiters.shift()(failure);
  };
  const onData = (chunk) => {
    if (failure) return; // Keep draining owned stdout without retaining bytes.
    const input = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let offset = 0;
    while (offset < input.length && !failure) {
      const newline = input.indexOf(10, offset);
      const end = newline < 0 ? input.length : newline;
      const piece = input.subarray(offset, end);
      if (buffer.length + piece.length > MAX_LINE_BYTES) {
        fail(new Error("controller response framing bound"));
        break;
      }
      buffer = Buffer.concat([buffer, piece]);
      if (newline < 0) break;
      try {
        const response = parseControllerLine(buffer.toString("utf8").replace(/\r$/, ""));
        buffer = Buffer.alloc(0);
        if (waiters.length) waiters.shift()(null, response);
        else {
          pending.push(response);
          if (pending.length > 8) throw new Error("controller response queue overflow");
        }
      } catch (error) { fail(error); }
      offset = end + 1;
    }
  };
  const onEnd = () => fail(new Error(buffer.length ? "controller response truncated" : "controller response EOF"));
  child.stdout.on("data", onData);
  child.stdout.once("end", onEnd);
  child.stdout.once("error", fail);
  const next = () => {
    if (pending.length) return Promise.resolve(pending.shift());
    if (failure) return Promise.reject(failure);
    return new Promise((resolvePromise, rejectPromise) => waiters.push((error, value) => error ? rejectPromise(error) : resolvePromise(value)));
  };
  return { next, close: () => {
    fail(new Error("controller response closed"));
    child.stdout.off("data", onData);
    child.stdout.off("end", onEnd);
    child.stdout.off("error", fail);
    child.stdout.resume();
  } };
}

async function nextWithin(responses, milliseconds) {
  assert(Number.isSafeInteger(milliseconds) && milliseconds > 0, "controller response timeout bound");
  let timer;
  try {
    return await Promise.race([
      responses.next(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("controller response timeout")), milliseconds); }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export function validateResponse(response, expected, state, context, expectedApp, monitorPid, platform, scenario, monitorExit = null) {
  const fields = {
    BOUND: ["launchBindingSha256", "accepted", "application", "monitor", "nonce", "op", "schema", "source", "target"],
    TERMINATED: ["launchBindingSha256", "accepted", "application", "monitor", "nonce", "op", "schema", "source", "target", "watchdog", "witness"],
    FINALIZED: ["launchBindingSha256", "accepted", "application", "cleanup", "monitor", "monitorExit", "nonce", "op", "schema", "source", "target", "watchdog", "witness"],
  }[expected];
  assert(fields, `unsupported controller response ${expected}`);
  assert(response && typeof response === "object" && !Array.isArray(response), `controller ${expected} object`);
  assert.equal(Object.keys(response).sort().join(","), fields.slice().sort().join(","), `controller ${expected} fields are closed`);
  assert.equal(response.schema, CONTROLLER_SCHEMA, `controller ${expected} schema`);
  assert.equal(response.op, expected, `controller response ${expected} required`);
  assert.equal(response.nonce, state.nonce, "controller nonce changed");
  hash(state.launchBindingSha256,"expected launch binding");
  assert.equal(response.launchBindingSha256,state.launchBindingSha256,"controller launch binding changed");
  assert.equal(response.accepted, true, `controller ${expected} did not accept`);
  assertSource(response.source, context);
  const target = { "linux-arm64": "aarch64-unknown-linux-gnu", "linux-x64": "x86_64-unknown-linux-gnu" }[platform];
  assert.equal(response.target, target, "controller target changed");
  const monitor = boundProcess(response.monitor, "response.monitor");
  assert.equal(monitor.pid, monitorPid, "response monitor PID changed");
  assert.equal(monitor.executable.sha256, context.monitor.executable.sha256, "response monitor executable changed");
  assert.equal(monitor.executable.size, context.monitor.executable.size, "response monitor executable size changed");
  const application = boundProcess(response.application, "response.application");
  assert.notEqual(application.pid, monitor.pid, "application and monitor identities collapsed");
  assert.equal(application.executable.sha256, expectedApp.sha256, "response application executable changed");
  assert.equal(application.executable.size, expectedApp.size, "response application executable size changed");
  if (expected === "BOUND") {
    state.monitor = monitor;
    state.application = application;
    return response;
  }
  assert.deepEqual(monitor, state.monitor, "response monitor identity changed");
  assert.deepEqual(application, state.application, "response application identity changed");
  if (expected === "TERMINATED") {
    assert.equal(scenario, "C-signal", "TERMINATED is only valid for C-signal");
    validateWitness(response.witness, state);
    validateWatchdog(response.watchdog);
    state.terminated = response;
    return response;
  }
  validateMonitorExit(response.monitorExit, monitorExit);
  if (scenario === "C-signal") {
    assert(state.terminated, "C-signal finalization preceded termination witness");
    validateWitness(response.witness, state);
  } else {
    assert.equal(response.witness, null, "ordinary finalization must not contain a signal witness");
  }
  if(scenario==="C-signal")validateWatchdog(response.watchdog);
  else assert.equal(response.watchdog,null,"ordinary scenario must not claim an armed signal watchdog");
  validateCleanup(response.cleanup);
  state.final = response;
  return response;
}

function expectedSpawnOptions(options) {
  assert(options && typeof options === "object", "spawn options required");
  assert.equal(options.detached, true, "wrapper must retain detached launch semantics");
  assert.equal(options.shell ?? false, false, "shell launch is forbidden");
  assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"], "wrapper stdio changed");
  absolute(options.cwd, "wrapper cwd");
}

export function waitForExit(child, milliseconds) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  return new Promise((resolvePromise, rejectPromise) => {
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      child.off("exit", onExit);
      child.off("error", onError);
    };
    const onExit = (code, signal) => { cleanup(); resolvePromise({ code, signal }); };
    const onError = (error) => { cleanup(); rejectPromise(error); };
    timer = setTimeout(() => { cleanup(); rejectPromise(new Error("owned child exit timeout")); }, milliseconds);
    child.once("exit", onExit);
    child.once("error", onError);
  });
}

export async function stopOwnedChild(child, { killFirst = false, graceMs = 5_000, killMs = 2_000 } = {}) {
  const kill = () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    assert.equal(child.kill("SIGKILL"), true, "owned child kill was not accepted");
  };
  if (killFirst) kill();
  try {
    return await waitForExit(child, killFirst ? killMs : graceMs);
  } catch (error) {
    if (killFirst) throw error;
    kill();
    return await waitForExit(child, killMs);
  }
}

export async function settleFailedOwnedChildren(monitor, controller, { graceMs = 5_000, killMs = 2_000 } = {}) {
  try { controller.stdin.end(); } catch { /* already closed; still require an exit proof */ }
  // Preserve monitor identity while the controller performs exact-handle EOF cleanup.
  const [controllerExit] = await Promise.allSettled([stopOwnedChild(controller, { graceMs, killMs })]);
  const [monitorExit] = await Promise.allSettled([stopOwnedChild(monitor, { killFirst: true, killMs })]);
  return [monitorExit, controllerExit];
}

export function sendWithin(stream, raw, milliseconds = 2_000) {
  assert(Buffer.byteLength(raw, "utf8") <= MAX_LINE_BYTES, "controller request exceeds bound");
  return new Promise((resolvePromise, rejectPromise) => {
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      stream.off("error", onError);
      stream.off("close", onClose);
    };
    const done = (error) => { cleanup(); error ? rejectPromise(error) : resolvePromise(); };
    const onError = (error) => done(error);
    const onClose = () => done(new Error("controller input closed before write completed"));
    stream.once("error", onError);
    stream.once("close", onClose);
    timer = setTimeout(() => done(new Error("controller input write timeout")), milliseconds);
    try { stream.write(raw, (error) => done(error)); } catch (error) { done(error); }
  });
}

export function captureOwnedExit(child) {
  if (child.exitCode !== null || child.signalCode !== null)
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  return new Promise((resolvePromise) => child.once("exit", (code, signal) => resolvePromise({ code, signal })));
}

export function observeSpawn(child, milliseconds = 2_000) {
  return new Promise((resolvePromise, rejectPromise) => {
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      child.off("spawn", onSpawn);
      child.off("error", onError);
    };
    const onSpawn = () => {
      cleanup();
      if (Number.isInteger(child.pid) && child.pid > 1) resolvePromise();
      else rejectPromise(new Error("owned child did not provide PID"));
    };
    const onError = () => { cleanup(); rejectPromise(new Error("owned child spawn failed")); };
    child.once("spawn", onSpawn);
    child.once("error", onError);
    timer = setTimeout(() => { cleanup(); rejectPromise(new Error("owned child spawn timeout")); }, milliseconds);
  });
}

export function controllerResponsePath(evidenceDir, label) {
  absolute(evidenceDir, "controller evidence directory");
  assert(typeof label === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(label), "controller evidence label");
  return join(evidenceDir, label + ".controller.json");
}


export function controllerBindMessage({nonce,nodePid,monitorPid,monitor,expectedApp,context,
  platform,scenario,smokeDir,launchBindingSha256}) {
  assert(typeof nonce==="string" && /^[0-9a-f]{32}$/.test(nonce),"controller bind nonce");
  positiveInteger(nodePid,"Node PID");positiveInteger(monitorPid,"monitor PID");
  hash(launchBindingSha256,"launch binding digest");
  assert(monitor && Object.keys(monitor).sort().join(",")==="argv,executable","controller monitor fields");
  identity(monitor.executable,"monitor executable");
  assert(Array.isArray(monitor.argv) && monitor.argv.length>0 && monitor.argv.length<=8192,"monitor argv count");
  monitor.argv.forEach(value=>{
    text(value,"monitor argv item");
    assert(value.length>0,"monitor argv item must be nonempty");
  });
  absolute(smokeDir,"smoke directory");
  identity(expectedApp,"application executable");
  const targets={"linux-arm64":["B"],"linux-x64":["C","C-signal"]};
  assert(targets[platform]?.includes(scenario),"controller bind platform/scenario");
  const binding={schema:CONTROLLER_SCHEMA,op:"bind",nonce,nodePid,monitorPid,monitor,
    application:expectedApp,predicateHelper:context.predicateHelper,source:sourceIdentity(context),
    platform,scenario,receiptPath:join(smokeDir,"receipt.json"),launchBindingSha256};
  assert(Buffer.byteLength(JSON.stringify(binding)+"\n")<=MAX_LINE_BYTES,"controller bind wire bound");
  return binding;
}

export async function spawnGuiBound({ launchTarget, args, options, expectedApp, context, platform, scenario, smokeDir, controllerEvidenceDir, label }) {
  validateContext(context);
  expectedSpawnOptions(options);
  absolute(launchTarget, "public wrapper launch target");
  assert.equal(resolve(launchTarget), context.publicWrapper.path, "launch target differs from sealed public wrapper");
  assert(Array.isArray(args) && args.length === 1 && args[0] === `--nebular-release-smoke=${scenario}`, "wrapper arguments changed");
  assert(["linux-arm64", "linux-x64"].includes(platform), "GUI controller is Linux-only");
  absolute(smokeDir, "smoke directory");
  const responsePath = controllerResponsePath(controllerEvidenceDir, label);
  assert.deepEqual(fileIdentity(expectedApp.path, "raw GUI executable"), expectedApp, "raw GUI identity changed");

  const bridgePath = fileURLToPath(import.meta.url);
  assert.equal(sha256(readFileSync(bridgePath)), context.bridgeSha256, "controller bridge bytes changed");
  const controllerPath = join(dirname(bridgePath), "p-native-gui-controller.py");
  assert.equal(sha256(readFileSync(controllerPath)), context.controller.scriptSha256, "controller bytes changed");
  const predicatePath = join(dirname(controllerPath), "p-process-predicate-probe.py");
  assert.equal(resolve(context.predicateHelper.path), resolve(predicatePath), "predicate helper is not the held closure sibling");
  assert.deepEqual(fileIdentity(predicatePath, "predicate helper"), context.predicateHelper, "predicate helper bytes changed");

  const resolverPath=join(dirname(bridgePath),"p-native-gui-launch-binding.mjs");
  assert.equal(sha256(readFileSync(resolverPath)),context.resolverSha256,"launch resolver bytes changed");
  const inputs=freezeLaunchInputs({args,cwd:options.cwd,env:options.env});
  // The resolver performs bounded physical readback of the actual symlink chain.
  // Authenticate this observer transform from sealed declared bytes first.
  const authentication=authenticateWrapper({wrapperBytes:Buffer.from(context.launchObserver.declaredText),
    declaredBytes:Buffer.from(context.launchObserver.declaredText),expectedSha256:context.publicWrapper.sha256,
    pinnedBash:context.launchObserver.pinnedBash,context:context.launchObserver.context,
    buildFhsEnvSourceSha256:context.launchObserver.buildFhsEnvSourceSha256,
    containerSourceSha256:context.launchObserver.containerSourceSha256});
  const observerDir=join(smokeDir,"p-fresh-wrapper-observer");
  mkdirSync(observerDir,{mode:0o700});
  const observer=await stageObserver(authentication,{directory:observerDir,wrapperPath:launchTarget,
    expectedResolvedWrapperPath:context.launchObserver.expectedResolvedWrapperPath,
    authenticatedSourceRoot:dirname(bridgePath)});
  let launch;
  try { launch=await resolveFreshLaunch({observer,launchInputs:inputs}); }
  finally { await removeObserver(observer); }
  assert(isFreshLaunchBinding(launch,inputs),"same-process fresh launch handle missing");
  const launchBindingSha256=validateFreshLaunchFacts(launch.facts,context,scenario);
  assert(launch.resolvedArgv.length<=8192,"fresh monitor argv exceeds controller policy");
  const monitor={executable:context.monitor.executable,argv:launch.resolvedArgv};
  const launchOptions={...options,cwd:inputs.cwd,env:inputs.env};
  const state = { launchBindingSha256, applicationPid: null, bound: false, finalizing: false, finalized: false, aborted: false,
    nonce: randomBytes(16).toString("hex"), monitor: null, application: null, terminated: null, final: null,
    responses: [] };
  const bindParameters={monitor,expectedApp,context,platform,scenario,smokeDir,launchBindingSha256};
  // Refuse a too-large request before launching any subject, allowing worst-case PID width.
  controllerBindMessage({...bindParameters,nonce:"0".repeat(32),nodePid:process.pid,monitorPid:Number.MAX_SAFE_INTEGER});
  const childErrors = [];
  const controllerErrors = [];
  const child = spawn(launchTarget, inputs.args, launchOptions);
  const monitorExit = captureOwnedExit(child);
  child.on("error", () => childErrors.push("process-error"));
  let controller;
  try {
    await observeSpawn(child);
    controller = spawn(context.controller.python, ["-I", "-S", controllerPath, "controller"], {
      cwd: launchOptions.cwd,
      env: launchOptions.env,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });
    controller.on("error", () => controllerErrors.push("process-error"));
    await observeSpawn(controller);
  } catch (error) {
    const cleanup = [];
    if (Number.isInteger(child.pid)) cleanup.push(stopOwnedChild(child, { killFirst: true }));
    if (controller && Number.isInteger(controller.pid)) cleanup.push(stopOwnedChild(controller, { killFirst: true }));
    const exits = await Promise.allSettled(cleanup);
    assert(exits.every((value) => value.status === "fulfilled"), "startup owned child exit unconfirmed");
    throw error;
  }
  controller.stderr.resume();
  const responses = boundedResponses(controller);
  controller.once("exit", () => {
    if (!state.finalized && !state.finalizing && !state.aborted && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  const parentExitCleanup = () => {
    try { controller.stdin.end(); } catch { /* process is already leaving */ }
    if (child.exitCode === null) child.kill("SIGKILL");
  };
  process.once("exit", parentExitCleanup);
  const send = (message) => {
    assert(!state.finalized && !state.aborted, "controller bridge is closed");
    const raw = `${JSON.stringify(message)}\n`;
    assert.equal(controllerErrors.length, 0, "controller spawn failed");
    return sendWithin(controller.stdin, raw);
  };
  const writeResponseRecord = (status, controllerExitValue = null, cleanup = null) => {
    const recordPath = responsePath;
    writeFileSync(recordPath, `${JSON.stringify({ schema: "theme-forge.p-native-gui-response-record.v1", status,
      nonceSha256: sha256(Buffer.from(state.nonce)), launchBinding: launch.facts,
      source: sourceIdentity(context), responses: state.responses,
      controllerExit: controllerExitValue, cleanup }, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    return recordPath;
  };
  let abortPromise = null;
  const abortFailure = () => {
    if (state.finalized) return Promise.resolve();
    if (abortPromise !== null) return abortPromise;
    state.aborted = true;
    abortPromise = (async () => {
      const exits = await settleFailedOwnedChildren(child, controller);
      responses.close();
      process.off("exit", parentExitCleanup);
      const exitFact = (result) => result.status === "fulfilled"
        ? { observed: true, ...result.value }
        : { observed: false, reason: "owned-exit-unconfirmed" };
      const cleanup = { monitor: exitFact(exits[0]), controller: exitFact(exits[1]),
        childErrors: [...childErrors], controllerErrors: [...controllerErrors],
        application: "controller-or-watchdog-failure-cleanup-unqualified" };
      try { writeResponseRecord("failed", cleanup.controller, cleanup); } catch { /* original failure remains */ }
      assert(cleanup.monitor.observed && cleanup.controller.observed, "owned cleanup exit proof unavailable");
    })();
    return abortPromise;
  };
  const binding=controllerBindMessage({...bindParameters,nonce:state.nonce,nodePid:process.pid,monitorPid:child.pid});
  return Object.freeze({
    child,
    monitorExit,
    async bindApplication() {
      assert(!state.bound, "application binding already requested");
      try {
        await send(binding);
        const response = validateResponse(await nextWithin(responses, 30_000), "BOUND", state, context, expectedApp, child.pid, platform, scenario);
        state.responses.push({ phase: "BOUND", response });
        state.bound = true;
        return response;
      } catch (error) {
        await abortFailure();
        throw error;
      }
    },
    applicationPid() {
      assert(state.bound && state.application && Number.isInteger(state.application.pid), "application is not independently bound");
      return state.application.pid;
    },
    async terminateApplication() {
      assert(state.bound, "application must be bound before C-signal");
      try {
        await send({ schema: CONTROLLER_SCHEMA, op: "terminate", nonce: state.nonce, scenario });
        const response = validateResponse(await nextWithin(responses, CONTROLLER_TERMINATE_WAIT_MS), "TERMINATED", state, context, expectedApp, child.pid, platform, scenario);
        state.responses.push({ phase: "TERMINATED", response });
        return response;
      } catch (error) {
        await abortFailure();
        throw error;
      }
    },
    async abortFailure() {
      await abortFailure();
      return { status: "failed", ownedMonitorCleanup: "ChildProcess.kill(SIGKILL)" };
    },
    async finalize({ monitorExit }) {
      assert(state.bound && monitorExit && typeof monitorExit === "object", "finalization binding missing");
      try {
        state.finalizing = true;
        const normalizedExit = { code: monitorExit.code ?? null, signal: monitorExit.signal ?? null };
        await send({ schema: CONTROLLER_SCHEMA, op: "finalize", nonce: state.nonce, monitorExit: normalizedExit });
        const response = validateResponse(await nextWithin(responses, 5_000), "FINALIZED", state, context, expectedApp, child.pid, platform, scenario, normalizedExit);
        state.responses.push({ phase: "FINALIZED", response });
        controller.stdin.end();
        const exit = await waitForExit(controller, 5_000);
        assert.deepEqual(exit, { code: 0, signal: null }, "controller did not exit cleanly");
        assert.equal(controllerErrors.length, 0, "controller reported a process error");
        assert.equal(childErrors.length, 0, "monitor reported a process error");
        state.finalized = true;
        state.finalizing = false;
        process.off("exit", parentExitCleanup);
        responses.close();
        writeResponseRecord("complete", exit);
        return response;
      } catch (error) {
        state.finalizing = false;
        await abortFailure();
        throw error;
      }
    },
  });
}
