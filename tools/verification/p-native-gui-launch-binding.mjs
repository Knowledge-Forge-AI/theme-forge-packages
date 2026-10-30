/** Fresh observation of a source-bound wrapper. Supplies no GUI/admission authority. */
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { spawn as nativeSpawn } from 'node:child_process';

const SOURCE_LIMIT = 128 * 1024;
const OUTPUT_LIMIT = 1024 * 1024;
const DEADLINE_MS = 10_000;
const TERM_GRACE_MS = 500;
const CLEANUP_MS = 1_000;
const FINAL_EXEC = 'exec "${cmd[@]}"';
const PRINT = 'printf \'%s\\0\' "${cmd[@]}"';
const ARITIES = Object.freeze({ '--dev-bind': 2, '--proc': 1, '--chdir': 1,
  '--die-with-parent': 0, '--bind': 2, '--tmpfs': 1, '--symlink': 2,
  '--ro-bind': 2, '--remount-ro': 1, '--ro-bind-try': 2 });
const SMOKE = new Set(['--nebular-release-smoke=B', '--nebular-release-smoke=C', '--nebular-release-smoke=C-signal']);
const authenticated = new WeakMap();
const staged = new WeakMap();
const launches = new WeakSet();
const fresh = new WeakMap();
const utf8 = new TextDecoder('utf-8', { fatal: true });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = value => JSON.stringify(value, (key, entry) => entry && !Array.isArray(entry) && typeof entry === 'object'
  ? Object.fromEntries(Object.keys(entry).sort().map(name => [name, entry[name]])) : entry);
const digest = value => hash(canonical(value));

export class LaunchBindingError extends Error {
  constructor(code, cleanup = null) { super(code); this.name = 'LaunchBindingError'; this.code = code; this.cleanup = cleanup; }
}
function need(test, code) { if (!test) throw new LaunchBindingError(code); }
function closed(value, keys) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'), 'BINDING_SHAPE');
}
function sha(value) { need(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'SOURCE_DIGEST'); return value; }
function absolute(value) {
  need(typeof value === 'string' && value.length <= 4096 && value.startsWith('/') && !/[\0\r\n]/.test(value)
    && path.normalize(value) === value && !value.includes('//'), 'BINDING_PATH'); return value;
}
function store(value) {
  absolute(value);
  need(/^\/nix\/store\/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+(?:\/[^/\s]+)*$/.test(value), 'STORE_IDENTITY');
  return value;
}
function contextValue(value) {
  closed(value, ['bwrap', 'containerInit', 'originalInit']);
  const result = Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, store(entry)]));
  need(result.bwrap.endsWith('/bin/bwrap') && result.containerInit.endsWith('-container-init')
    && result.originalInit.endsWith('-init'), 'SOURCE_IDENTITIES');
  return Object.freeze(result);
}
function text(bytes) {
  need(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= SOURCE_LIMIT, 'SOURCE_BOUND');
  try { const value = utf8.decode(bytes); need(!/[\0\r]/.test(value), 'SOURCE_ENCODING'); return value; }
  catch (error) { if (error instanceof LaunchBindingError) throw error; throw new LaunchBindingError('SOURCE_ENCODING'); }
}

export function authenticateWrapper(input) {
  closed(input, ['wrapperBytes', 'declaredBytes', 'expectedSha256', 'pinnedBash', 'context', 'buildFhsEnvSourceSha256', 'containerSourceSha256']);
  const source = text(input.wrapperBytes);
  text(input.declaredBytes);
  need(input.wrapperBytes.equals(input.declaredBytes) && hash(input.wrapperBytes) === sha(input.expectedSha256), 'SOURCE_MISMATCH');
  const bash = store(input.pinnedBash), context = contextValue(input.context);
  need(bash.endsWith('/bin/bash') && source.split('\n')[0] === '#!' + bash, 'PINNED_BASH');
  // Conservative source guard, not a general Bash parser. Exact authenticated bytes
  // and the separately graph-bound pinned producer remain prerequisites.
  need(!/\$0|\$\{[#!]?0(?:\}|[^0-9])|\$\{[@*][^}]*\}|BASH_SOURCE|BASH_ARGV0/.test(source), 'WRAPPER_PATHNAME_USE');
  const offset = source.indexOf(FINAL_EXEC);
  need(offset >= 0 && source.indexOf(FINAL_EXEC, offset + 1) === -1
    && source.slice(offset).trimEnd() === FINAL_EXEC
    && (offset === 0 || source[offset - 1] === '\n'), 'TERMINAL_EXEC');
  need(source.includes('cmd=(\n  ' + context.bwrap + '\n')
    && source.slice(0, offset).endsWith('  ' + context.containerInit + ' "$@"\n)\n')
    && source.split('--symlink ' + context.originalInit + ' /init').length === 2
    && source.includes('"${ro_mounts[@]}"') && source.includes('"${auto_mounts[@]}"'), 'WRAPPER_LAYOUT');
  const observer = Buffer.from(source.slice(0, offset) + PRINT + source.slice(offset + FINAL_EXEC.length));
  const facts = Object.freeze({ schema: 'theme-forge.p-gui-wrapper-source.v1',
    wrapperSha256: input.expectedSha256, declaredSha256: hash(input.declaredBytes),
    observerSha256: hash(observer), prefixSha256: hash(Buffer.from(source.slice(0, offset))),
    bash, ...context, buildFhsEnvSourceSha256: sha(input.buildFhsEnvSourceSha256),
    containerSourceSha256: sha(input.containerSourceSha256), terminalOnlyTransform: true, pathnameUseAbsent: true });
  const handle = Object.freeze({ facts });
  authenticated.set(handle, { source: Buffer.from(input.wrapperBytes), observer, bash, context, facts });
  return handle;
}

export function getObserverSource(authentication) {
  need(authenticated.has(authentication), 'SOURCE_HANDLE');
  return Buffer.from(authenticated.get(authentication).observer);
}

export function freezeLaunchInputs(input) {
  closed(input, ['args', 'cwd', 'env']);
  need(Array.isArray(input.args) && input.args.length === 1 && SMOKE.has(input.args[0]), 'GUI_SMOKE_ARGUMENT');
  const cwd = absolute(input.cwd);
  need(input.env && typeof input.env === 'object' && !Array.isArray(input.env)
    && [Object.prototype, null].includes(Object.getPrototypeOf(input.env)), 'LAUNCH_ENVIRONMENT');
  const env = Object.create(null);
  let total = 0;
  for (const [key, value] of Object.entries(input.env)) {
    need(/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) && typeof value === 'string'
      && !/[\0\r\n]/.test(value) && Buffer.byteLength(value) <= 32768, 'LAUNCH_ENVIRONMENT');
    need(!/^(?:BASH_|LD_|DYLD_)/.test(key) && !new Set(['ENV', 'SHELLOPTS', 'BASHOPTS', 'IFS', 'CDPATH',
      'GLOBIGNORE', 'PROMPT_COMMAND', 'PS4', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONHOME']).has(key), 'DANGEROUS_ENVIRONMENT');
    total += Buffer.byteLength(key) + Buffer.byteLength(value);
    need(total <= 128 * 1024, 'LAUNCH_ENVIRONMENT_BOUND');
    env[key] = value;
  }
  need(!Object.hasOwn(env, 'PWD') || env.PWD === cwd, 'LAUNCH_CWD_ENVIRONMENT');
  const result = { args: Object.freeze([...input.args]), cwd, env: Object.freeze(env) };
  Object.defineProperty(result, 'toJSON', { value: () => ({ schema: 'theme-forge.p-ephemeral-launch-input-digests.v1',
    argumentsSha256: digest(result.args), cwdSha256: hash(cwd), environmentSha256: digest(env) }) });
  Object.freeze(result);
  launches.add(result);
  return result;
}

export function parseFreshArgv(raw, input) {
  closed(input, ['context', 'launchInputs']);
  let { context, launchInputs } = input;
  need(launches.has(launchInputs), 'FROZEN_LAUNCH_HANDLE');
  context = contextValue(context);
  need(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= OUTPUT_LIMIT && raw.at(-1) === 0, 'ARGV_FRAMING');
  let argv;
  try { argv = utf8.decode(raw.subarray(0, -1)).split('\0'); } catch { throw new LaunchBindingError('ARGV_ENCODING'); }
  need(argv.length <= 8192 && argv.every(arg => arg && Buffer.byteLength(arg) <= 16384 && !/[\r\n]/.test(arg)), 'ARGV_BOUND');
  need(argv[0] === context.bwrap && argv.at(-2) === context.containerInit
    && argv.at(-1) === launchInputs.args[0], 'GUI_ARGV_SUFFIX');
  const options = [];
  for (let i = 1; i < argv.length - 2;) {
    const flag = argv[i], count = ARITIES[flag];
    need(Object.hasOwn(ARITIES, flag) && i + count < argv.length - 2, 'BWRAP_OPTION');
    options.push(argv.slice(i, i + count + 1)); i += count + 1;
  }
  need(canonical(options.slice(0, 3)) === canonical([['--dev-bind', '/dev', '/dev'], ['--proc', '/proc'], ['--chdir', launchInputs.cwd]]), 'BWRAP_INITIAL_POLICY');
  for (const [flag, tuple] of [['--dev-bind', ['--dev-bind', '/dev', '/dev']], ['--proc', ['--proc', '/proc']],
    ['--chdir', ['--chdir', launchInputs.cwd]], ['--die-with-parent', ['--die-with-parent']]]) {
    need(options.filter(option => option[0] === flag).length === 1
      && options.some(option => canonical(option) === canonical(tuple)), 'BWRAP_CORE_POLICY');
  }
  need(options.filter(option => canonical(option) === canonical(['--bind', '/nix', '/nix'])).length === 1, 'BWRAP_NIX_POLICY');
  const init = options.filter(option => option.at(-1) === '/init');
  need(init.length === 1 && canonical(init[0]) === canonical(['--symlink', context.originalInit, '/init']), 'BWRAP_INIT_POLICY');
  need(options.filter(option => canonical(option) === canonical(['--tmpfs', '/tmp/.X11-unix'])).length === 1, 'BWRAP_X11_POLICY');
  const display = launchInputs.env.DISPLAY ?? '', sockets = options.filter(option => option[0] === '--ro-bind-try');
  if (display.includes(':')) {
    const number = display.slice(display.lastIndexOf(':') + 1).split('.')[0];
    need(/^[0-9]+$/.test(number), 'BWRAP_X11_POLICY');
    const socket = '/tmp/.X11-unix/X' + number;
    need(canonical(sockets) === canonical([['--ro-bind-try', socket, socket]]), 'BWRAP_X11_POLICY');
  } else need(sockets.length === 0, 'BWRAP_X11_POLICY');
  for (const option of options) {
    const destination = option.at(-1);
    if (option.length === 1) continue;
    absolute(destination);
    if (['--bind', '--dev-bind', '--ro-bind', '--ro-bind-try'].includes(option[0])) absolute(option[1]);
    if (option[0] !== '--chdir') need(destination !== '/', 'BWRAP_PROTECTED_MOUNT');
    if (option[0] === '--bind') need(!destination.startsWith('/nix/'), 'BWRAP_NIX_POLICY');
    need(!['/dev', '/proc', '/init'].some(root => destination.startsWith(root + '/')), 'BWRAP_PROTECTED_MOUNT');
    if (destination === '/nix') need(canonical(option) === canonical(['--bind', '/nix', '/nix']), 'BWRAP_NIX_POLICY');
    if (destination === '/dev') need(canonical(option) === canonical(['--dev-bind', '/dev', '/dev']), 'BWRAP_CORE_POLICY');
    if (destination === '/proc') need(canonical(option) === canonical(['--proc', '/proc']), 'BWRAP_CORE_POLICY');
  }
  return Object.freeze({ argv: Object.freeze(argv), optionCount: options.length });
}

function fileIdentity(stat, bytes) {
  return { device: String(stat.dev), inode: String(stat.ino), mode: stat.mode & 0o7777,
    uid: stat.uid, links: stat.nlink, size: bytes.length, sha256: hash(bytes) };
}
async function physicalFile(filename, max = SOURCE_LIMIT, exclusive = false) {
  absolute(filename);
  need(await fs.realpath(filename) === filename, 'SOURCE_PHYSICAL_PATH');
  need(Number.isInteger(constants.O_NONBLOCK) && constants.O_NONBLOCK > 0, 'SOURCE_OPEN_FLAGS');
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    need(before.isFile() && (!exclusive || before.nlink === 1) && before.size <= max, 'SOURCE_PHYSICAL_FILE');
    const bytes = Buffer.alloc(max + 1); let length = 0;
    while (length < bytes.length) {
      const read = await handle.read(bytes, length, bytes.length - length, null);
      if (!read.bytesRead) break; length += read.bytesRead;
    }
    const after = await handle.stat();
    need(length <= max && before.size === length && before.ino === after.ino
      && before.dev === after.dev && before.mtimeMs === after.mtimeMs && before.size === after.size, 'SOURCE_CHANGED');
    const body = bytes.subarray(0, length);
    return { bytes: body, identity: fileIdentity(after, body) };
  } finally { await handle.close(); }
}
function outside(directory, root) {
  const relative = path.relative(root, directory);
  return relative === '..' || relative.startsWith('..' + path.sep);
}

async function stagingDirectory(directory, sourceRoot) {
  need(await fs.realpath(directory) === directory && await fs.realpath(sourceRoot) === sourceRoot
    && outside(directory, sourceRoot), 'OBSERVER_STAGING_BOUNDARY');
  const root = await fs.lstat(sourceRoot, { bigint: true });
  need(root.isDirectory() && !root.isSymbolicLink(), 'OBSERVER_STAGING_BOUNDARY');
  const stat = await fs.lstat(directory, { bigint: true });
  need(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o7777n) === 0o700n
    && typeof process.getuid === 'function' && stat.uid === BigInt(process.getuid())
    && typeof stat.mtimeNs === 'bigint' && typeof stat.ctimeNs === 'bigint', 'OBSERVER_STAGING_DIRECTORY');
  return { path: directory, device: String(stat.dev), inode: String(stat.ino), mode: Number(stat.mode & 0o7777n),
    uid: String(stat.uid), gid: String(stat.gid), links: String(stat.nlink),
    mtimeNs: String(stat.mtimeNs), ctimeNs: String(stat.ctimeNs),
    sourceRoot: { path: sourceRoot, device: String(root.dev), inode: String(root.ino) } };
}

function directoryLocation(binding) {
  // Exclusive creation may change link count as well as timestamps (e.g. APFS).
  // Full post-creation values, including links/timestamps, bind later readbacks.
  const { mtimeNs, ctimeNs, links, ...location } = binding;
  return location;
}

async function wrapperFile(filename) {
  absolute(filename);
  const storeOrigin = filename.startsWith('/nix/store/');
  if (storeOrigin) store(filename);
  let current = filename;
  const links = [];
  for (;;) {
    const components = current.split('/').slice(1);
    let redirected = false;
    for (let index = 0; index < components.length; index++) {
      const component = '/' + components.slice(0, index + 1).join('/');
      const before = await fs.lstat(component);
      if (!before.isSymbolicLink()) continue;
      need(links.length < 16, 'WRAPPER_SYMLINK_BOUND');
      const target = await fs.readlink(component), after = await fs.lstat(component);
      need(target.length <= 4096 && !/[\0\r\n]/.test(target) && before.ino === after.ino
        && before.dev === after.dev && before.mtimeMs === after.mtimeMs, 'SOURCE_CHANGED');
      links.push({ path: component, target, device: String(after.dev), inode: String(after.ino),
        uid: after.uid, mode: after.mode & 0o777, links: after.nlink });
      current = path.resolve(path.dirname(component), target, ...components.slice(index + 1));
      if (storeOrigin) store(current);
      redirected = true; break;
    }
    if (!redirected) break;
  }
  const file = await physicalFile(current);
  return { bytes: file.bytes, identity: { requestedPath: filename, resolvedPath: current, links, file: file.identity } };
}

async function stageObserverImpl(authentication, input) {
  need(authenticated.has(authentication), 'SOURCE_HANDLE');
  closed(input, ['directory', 'wrapperPath', 'expectedResolvedWrapperPath', 'authenticatedSourceRoot']);
  const directory = absolute(input.directory), sourceRoot = absolute(input.authenticatedSourceRoot);
  const beforeDirectory = await stagingDirectory(directory, sourceRoot);
  const state = authenticated.get(authentication), wrapperPath = absolute(input.wrapperPath);
  const wrapper = await wrapperFile(wrapperPath);
  need(wrapper.bytes.equals(state.source) && wrapper.identity.resolvedPath === absolute(input.expectedResolvedWrapperPath), 'SOURCE_MISMATCH');
  const filename = path.join(directory, 'p-gui-observer-' + randomBytes(16).toString('hex') + '.bash');
  const handle = await fs.open(filename, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  let created, script, directoryBinding;
  try {
    try { created = await handle.stat(); await handle.writeFile(state.observer); await handle.sync(); }
    finally { await handle.close(); }
    script = await physicalFile(filename, SOURCE_LIMIT, true);
    need(script.bytes.equals(state.observer) && script.identity.mode === 0o600 && script.identity.links === 1
      && script.identity.uid === process.getuid() && String(created.ino) === script.identity.inode
      && String(created.dev) === script.identity.device, 'OBSERVER_BYTE_BINDING');
    // Capture lifetime metadata only after our exclusive creation changes it.
    directoryBinding = await stagingDirectory(directory, sourceRoot);
    need(canonical(directoryLocation(beforeDirectory)) === canonical(directoryLocation(directoryBinding)), 'OBSERVER_STAGING_DIRECTORY');
  } catch (error) {
    try { const leftover = await fs.lstat(filename);
      if (created && leftover.isFile() && leftover.ino === created.ino && leftover.dev === created.dev) await fs.unlink(filename);
    } catch { /* Never delete an unproved replacement or mask the primary refusal. */ }
    throw error;
  }
  const result = { facts: state.facts };
  Object.defineProperty(result, 'path', { value: filename });
  Object.freeze(result);
  staged.set(result, { state, wrapperPath, wrapper: wrapper.identity, script: script.identity,
    directory, sourceRoot, directoryBinding, disposed: false });
  return result;
}

export async function stageObserver(authentication, input) {
  try { return await stageObserverImpl(authentication, input); }
  catch (error) { if (error instanceof LaunchBindingError) throw error; throw new LaunchBindingError('OBSERVER_STAGING_IO'); }
}

async function readback(observer, record) {
  need(!record.disposed, 'OBSERVER_DISPOSED');
  need(canonical(await stagingDirectory(record.directory, record.sourceRoot)) === canonical(record.directoryBinding), 'OBSERVER_STAGING_DIRECTORY');
  const wrapper = await wrapperFile(record.wrapperPath), script = await physicalFile(observer.path, SOURCE_LIMIT, true);
  need(canonical(wrapper.identity) === canonical(record.wrapper) && wrapper.bytes.equals(record.state.source)
    && canonical(script.identity) === canonical(record.script) && script.bytes.equals(record.state.observer), 'SOURCE_CHANGED');
  need(canonical(await stagingDirectory(record.directory, record.sourceRoot)) === canonical(record.directoryBinding), 'OBSERVER_STAGING_DIRECTORY');
}

export async function removeObserver(observer) {
  need(staged.has(observer), 'OBSERVER_HANDLE');
  const record = staged.get(observer);
  try { await readback(observer, record); await fs.unlink(observer.path); record.disposed = true; }
  catch (error) { if (error instanceof LaunchBindingError) throw error; throw new LaunchBindingError('OBSERVER_STAGING_IO'); }
}

function observe(runtime, interpreter, filename, launchInputs) {
  return new Promise((resolve, reject) => {
    let child;
    try { child = runtime.spawn(interpreter, [filename, ...launchInputs.args], {
      cwd: launchInputs.cwd, env: launchInputs.env, shell: false, detached: false,
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { reject(new LaunchBindingError('OBSERVER_SPAWN')); return; }
    let spawned = false, exited = false, outEnd = false, errEnd = false, done = false;
    let code, signal, aggregate = 0, stdoutBytes = 0, stderrBytes = 0, failure = null;
    let term = false, kill = false, cleanupExpired = false;
    const chunks = [], stderrHash = createHash('sha256'), timers = [], listeners = [];
    const facts = () => Object.freeze({ processExitObserved: exited, stdoutEOF: outEnd, stderrEOF: errEnd,
      terminationRequested: term, killRequested: kill, boundedCleanupExpired: cleanupExpired });
    const listen = (object, event, fn) => { object.on(event, fn); listeners.push([object, event, fn]); };
    const later = (fn, ms) => { const timer = runtime.setTimeout(fn, ms); timers.push(timer); };
    const finish = () => {
      if (done) return; done = true;
      for (const timer of timers) runtime.clearTimeout(timer);
      for (const [object, event, fn] of listeners) object.off(event, fn);
      if (failure) { child.stdout?.destroy(); child.stderr?.destroy(); reject(new LaunchBindingError(failure, facts())); }
      else resolve({ raw: Buffer.concat(chunks), stdoutBytes, stderrBytes,
        stderrSha256: stderrHash.digest('hex'), cleanup: facts() });
    };
    const complete = () => { if (exited && outEnd && errEnd && (failure || spawned && code === 0 && signal === null)) finish(); };
    const fail = reason => {
      if (done || failure) return; failure = reason;
      if (!spawned && !Number.isSafeInteger(child.pid)) { finish(); return; }
      if (!exited) { term = true; try { child.kill('SIGTERM'); } catch { /* Refusal retains unproved cleanup. */ } }
      if (done) return;
      later(() => { if (!done && !exited) { kill = true; try { child.kill('SIGKILL'); } catch { /* Bounded refusal. */ } } }, TERM_GRACE_MS);
      later(() => { if (!done) { cleanupExpired = true; finish(); } }, CLEANUP_MS);
      complete();
    };
    if (!child || !child.stdout || !child.stderr || typeof child.on !== 'function'
      || typeof child.kill !== 'function') { reject(new LaunchBindingError('OBSERVER_PROCESS_BOUNDARY')); return; }
    // Install lifecycle proof before consuming any observer bytes.
    listen(child, 'spawn', () => { spawned = true; if (!Number.isSafeInteger(child.pid) || child.pid <= 0) fail('OBSERVER_PROCESS_BOUNDARY'); complete(); });
    listen(child, 'error', () => fail('OBSERVER_SPAWN'));
    listen(child, 'exit', (exitCode, exitSignal) => {
      exited = true; code = exitCode; signal = exitSignal;
      if (!spawned || code !== 0 || signal !== null) fail('OBSERVER_EXIT');
      complete();
    });
    for (const [stream, isOut] of [[child.stdout, true], [child.stderr, false]]) {
      listen(stream, 'data', chunk => {
        if (done || failure) return;
        if (!Buffer.isBuffer(chunk)) { fail('OBSERVER_STREAM_TYPE'); return; }
        aggregate += chunk.length;
        if (aggregate > OUTPUT_LIMIT) { fail('OBSERVER_OUTPUT_BOUND'); return; }
        if (isOut) { stdoutBytes += chunk.length; chunks.push(Buffer.from(chunk)); }
        else { stderrBytes += chunk.length; stderrHash.update(chunk); }
      });
      listen(stream, 'end', () => { if (isOut) outEnd = true; else errEnd = true; complete(); });
      listen(stream, 'error', () => fail('OBSERVER_STREAM'));
      listen(stream, 'close', () => { if (!(isOut ? outEnd : errEnd)) fail('OBSERVER_EOF'); });
    }
    later(() => fail('OBSERVER_DEADLINE'), DEADLINE_MS);
  });
}

async function resolveWith(runtime, input) {
  closed(input, ['observer', 'launchInputs']);
  const { observer, launchInputs } = input;
  need(staged.has(observer) && launches.has(launchInputs), 'FRESH_RESOLVER_HANDLES');
  const record = staged.get(observer);
  if (!runtime.fixtureMode) store(record.wrapperPath);
  try { await readback(observer, record); } catch { throw new LaunchBindingError('SOURCE_READBACK'); }
  let observed, failure;
  try { observed = await observe(runtime, record.state.bash, observer.path, launchInputs); }
  catch (error) { failure = error instanceof LaunchBindingError ? error : new LaunchBindingError('OBSERVER_PROCESS_BOUNDARY'); }
  try { await readback(observer, record); }
  catch { if (failure) failure.sourceReadback = 'failed'; else failure = new LaunchBindingError('SOURCE_READBACK', observed?.cleanup); }
  if (failure) throw failure;
  const parsed = parseFreshArgv(observed.raw, { context: record.state.context, launchInputs });
  const facts = { schema: 'theme-forge.p-gui-fresh-launch-binding.v1', source: record.state.facts,
    nonce: randomBytes(32).toString('hex'), wrapperBindingSha256: digest(record.wrapper),
    wrapperPublicPathSha256: hash(record.wrapperPath), wrapperResolvedPathSha256: hash(record.wrapper.resolvedPath),
    cwdSha256: hash(launchInputs.cwd), environmentSha256: digest(launchInputs.env),
    smokeArgumentsSha256: digest(launchInputs.args), argvSha256: hash(observed.raw), argvCount: parsed.argv.length,
    optionCount: parsed.optionCount, stdoutBytes: observed.stdoutBytes, stderrBytes: observed.stderrBytes,
    stderrSha256: observed.stderrSha256, deadlineMs: DEADLINE_MS, outputLimitBytes: OUTPUT_LIMIT,
    processExitObserved: true, observerExitCode: 0, observerExitSignal: null,
    stdoutEOF: true, stderrEOF: true, exactSourceReadbacks: true,
    fixtureMode: runtime.fixtureMode, admitting: false, guiQualification: false,
    nativeQualification: false, productionEnabled: false, publicationAuthority: false };
  facts.bindingSha256 = digest(facts);
  const result = { facts: Object.freeze(facts) };
  Object.defineProperties(result, { resolvedArgv: { value: parsed.argv }, launchInputs: { value: launchInputs } });
  Object.freeze(result);
  fresh.set(result, launchInputs);
  return result;
}

export function isFreshLaunchBinding(binding, launchInputs) { return fresh.has(binding) && fresh.get(binding) === launchInputs; }
export function resolveFreshLaunch(input) {
  return resolveWith({ spawn: nativeSpawn, setTimeout, clearTimeout, fixtureMode: false }, input);
}
export function createFixtureResolver(runtime) {
  closed(runtime, ['spawn', 'setTimeout', 'clearTimeout']);
  need(Object.values(runtime).every(value => typeof value === 'function'), 'FIXTURE_RUNTIME');
  return input => resolveWith({ ...runtime, fixtureMode: true }, input);
}
