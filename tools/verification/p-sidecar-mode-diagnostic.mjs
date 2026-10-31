/** Optional metadata observation. Never a qualification or launch decision. */
import { createHash } from 'node:crypto';
import { constants, lstatSync, openSync, closeSync, fstatSync, readSync,
  writeFileSync, fchmodSync } from 'node:fs';
import { isAbsolute, normalize, join } from 'node:path';

const MANIFEST_LIMIT = 2 * 1024 * 1024;
const FILE_LIMIT = 256 * 1024 * 1024;
const PAYLOAD_LIMIT = 1024 * 1024 * 1024;
const FILE_COUNT_LIMIT = 10000;
const CHUNK = 65536;
const MEMBER = 'p-sidecar-mode-diagnostic.json';
const SYSTEMS = new Set(['x86_64-linux', 'aarch64-linux', 'aarch64-darwin']);
class DiagnosticFailure extends Error {
  constructor(category) { super(category); this.category = category; }
}
function need(condition, category) { if (!condition) throw new DiagnosticFailure(category); }
function absolute(path) {
  need(typeof path === 'string' && path.length <= 4096 && isAbsolute(path)
    && normalize(path) === path && !path.includes('//') && !/[\0-\x1f\x7f]/.test(path), 'UNSAFE_PATH');
  return path;
}
function relative(path) {
  need(typeof path === 'string' && path.length > 0 && path.length <= 1024
    && !path.startsWith('/') && !path.includes('\\') && /^[\x20-\x7e]+$/.test(path)
    && path.split('/').every(part => part && part !== '.' && part !== '..'), 'INVALID_MANIFEST');
  return path;
}
function identity(info) {
  return [info.dev, info.ino, info.mode, info.size, info.uid, info.gid,
    info.nlink, info.mtimeNs, info.ctimeNs].join(':');
}
function directoryIdentity(info) {
  // Shared ancestors may gain unrelated entries while the probe runs. Bind
  // their actual directory objects and permissions, not entry timestamps.
  return [info.dev, info.ino, info.mode, info.uid, info.gid].join(':');
}
function chain(path) {
  absolute(path);
  const entries = [];
  let current = '/';
  for (const part of ['/', ...path.split('/').slice(1)]) {
    current = part === '/' ? '/' : join(current, part);
    const info = lstatSync(current, { bigint: true });
    need(!info.isSymbolicLink() && (current === path || info.isDirectory()), 'UNSAFE_PATH');
    const directory = info.isDirectory();
    entries.push([current, directory ? directoryIdentity(info) : identity(info), directory]);
  }
  return entries;
}
function recheck(entries) {
  for (const [path, expected, directory] of entries) {
    const info = lstatSync(path, { bigint: true });
    need(!info.isSymbolicLink() && (directory ? info.isDirectory()
      && directoryIdentity(info) === expected : identity(info) === expected), 'IDENTITY_CHANGED');
  }
}
function readRegular(path, limit, contents = false, budget = null) {
  const ancestry = chain(path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    need(before.isFile(), 'NOT_REGULAR');
    need(identity(before) === ancestry.at(-1)[1], 'IDENTITY_CHANGED');
    need(before.size >= 0n && before.size <= BigInt(limit), 'LIMIT_EXCEEDED');
    recheck(ancestry); // Validate opened identity and physical components before reading.
    if (budget !== null) {
      budget.bytes += Number(before.size);
      need(budget.bytes <= PAYLOAD_LIMIT, 'LIMIT_EXCEEDED');
    }
    const hash = createHash('sha256'), buffer = Buffer.alloc(CHUNK), pieces = [];
    let bytes = 0;
    for (;;) {
      const count = readSync(fd, buffer, 0, Math.min(CHUNK, limit - bytes + 1), null);
      if (!count) break;
      bytes += count;
      need(bytes <= limit, 'LIMIT_EXCEEDED');
      hash.update(buffer.subarray(0, count));
      if (contents) pieces.push(Buffer.from(buffer.subarray(0, count)));
    }
    need(BigInt(bytes) === before.size && identity(fstatSync(fd, { bigint: true })) === identity(before), 'IDENTITY_CHANGED');
    recheck(ancestry);
    const result = { mode: Number(before.mode & 0o777n), size: bytes, sha256: hash.digest('hex'),
      ...(contents ? { contents: Buffer.concat(pieces).toString('utf8') } : {}) };
    Object.defineProperty(result, 'readIdentity', { value: identity(before) });
    return result;
  } finally { closeSync(fd); }
}
function expected(value) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Number.isInteger(value.mode) && value.mode >= 0 && value.mode <= 0o777
    && Number.isSafeInteger(value.size) && value.size >= 0 && value.size <= FILE_LIMIT
    && typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.sha256), 'INVALID_MANIFEST');
  return { mode: value.mode, size: value.size, sha256: value.sha256 };
}
function observe(launchRoot, system) {
  absolute(launchRoot);
  need(SYSTEMS.has(system), 'UNSUPPORTED_SYSTEM');
  const darwin = system === 'aarch64-darwin';
  const app = join(launchRoot, 'Theme Forge Nebular Fusion.app', 'Contents');
  const runtimePath = darwin ? join(app, 'MacOS/tfsb-studio-service') : join(launchRoot, 'bin/tfsb-studio-service');
  const payloadRoot = darwin ? join(app, 'Resources/sidecar-payload')
    : join(launchRoot, 'sidecar-payload');
  const manifestFile = readRegular(join(payloadRoot, 'manifest.json'), MANIFEST_LIMIT, true);
  let manifest;
  try { manifest = JSON.parse(manifestFile.contents); }
  catch { throw new DiagnosticFailure('INVALID_MANIFEST'); }
  need(manifest && typeof manifest === 'object' && !Array.isArray(manifest)
    && Array.isArray(manifest.files) && manifest.files.length > 0
    && manifest.files.length <= FILE_COUNT_LIMIT, 'INVALID_MANIFEST');
  const runtimeExpected = expected(manifest.runtime);
  const seen = new Set();
  let totalExpected = 0;
  // Validate the complete path/size inventory before it can select any reads.
  const files = manifest.files.map(value => {
    const metadata = expected(value), path = relative(value.path);
    need(!seen.has(path) && path !== 'manifest.json', 'INVALID_MANIFEST');
    seen.add(path);
    totalExpected += metadata.size;
    need(totalExpected <= PAYLOAD_LIMIT, 'LIMIT_EXCEEDED');
    return { path, metadata };
  });
  const runtimeActual = readRegular(runtimePath, FILE_LIMIT);
  const mismatches = { mode: 0, size: 0, sha256: 0 };
  const budget = { bytes: 0 };
  for (const file of files) {
    const actual = readRegular(join(payloadRoot, file.path), FILE_LIMIT, false, budget);
    for (const field of ['mode', 'size', 'sha256']) mismatches[field] += Number(actual[field] !== file.metadata[field]);
  }
  // Reopen bounded manifest metadata after payload reads, without retaining its body.
  const manifestAfter = readRegular(join(payloadRoot, 'manifest.json'), MANIFEST_LIMIT);
  need(manifestAfter.readIdentity === manifestFile.readIdentity
    && manifestAfter.sha256 === manifestFile.sha256, 'IDENTITY_CHANGED');
  const runtimeMismatches = Object.fromEntries(['mode', 'size', 'sha256'].map(field => [field, runtimeActual[field] !== runtimeExpected[field]]));
  return { status: Object.values(runtimeMismatches).some(Boolean) || Object.values(mismatches).some(Boolean)
      ? 'incompatible' : 'compatible',
    failureCategory: null,
    runtime: { role: 'sidecar-runtime', actual: runtimeActual, expected: runtimeExpected, mismatches: runtimeMismatches },
    payload: { role: 'sidecar-payload', files: files.length, actualBytes: budget.bytes,
      expectedBytes: totalExpected, mismatches },
    manifest: { role: 'sidecar-manifest', size: manifestFile.size, sha256: manifestFile.sha256 } };
}

export function observeSidecarMode(input) {
  let record = { schema: 'theme-forge.p-sidecar-mode-diagnostic.v1',
    productionEnabled: false, publicationAuthority: false, productionAuthority: false,
    admitting: false, accepted: false, guiQualified: false,
    status: 'unavailable', failureCategory: null, runtime: null, payload: null, manifest: null,
    evidenceWriteStatus: 'unavailable', evidenceFailureCategory: null };
  try { record = { ...record, ...observe(input.launchRoot, input.system) }; }
  catch (error) { record.failureCategory = error instanceof DiagnosticFailure ? error.category : 'OBSERVATION_FAILED'; }
  // Every exception, including evidence I/O, stays inside this optional boundary.
  // Never overwrite prior evidence or let diagnostic failure replace GUI work.
  try {
    absolute(input.evidence);
    chain(input.evidence);
    const fd = openSync(join(input.evidence, MEMBER), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try {
      fchmodSync(fd, 0o600);
      record.evidenceWriteStatus = 'written';
      writeFileSync(fd, JSON.stringify(record, null, 2) + '\n');
    } finally { closeSync(fd); }
  } catch {
    record.evidenceWriteStatus = 'failed';
    record.evidenceFailureCategory = 'EVIDENCE_WRITE_FAILED';
  }
  return record;
}
