import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { observeSidecarMode } from '../tools/verification/p-sidecar-mode-diagnostic.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const member = 'p-sidecar-mode-diagnostic.json';
const marker = 'INERT-PUBLIC-CONTENT-NOT-FOR-EVIDENCE';
function fixture(darwin = false) {
  const root = fs.mkdtempSync(join(fs.realpathSync(tmpdir()), 'sidecar-mode-'));
  const launchRoot = join(root, 'installed'), evidence = join(root, 'evidence');
  const app = join(launchRoot, 'Theme Forge Nebular Fusion.app/Contents');
  const runtime = darwin ? join(app, 'MacOS/tfsb-studio-service') : join(launchRoot, 'bin/tfsb-studio-service');
  const payload = darwin ? join(app, 'Resources/sidecar-payload') : join(launchRoot, 'lib/theme-forge-nebular-fusion/sidecar-payload');
  fs.mkdirSync(dirname(runtime), { recursive: true });
  fs.mkdirSync(join(payload, 'nested'), { recursive: true });
  fs.mkdirSync(evidence, { mode: 0o700 });
  const runtimeBytes = Buffer.from(marker + '-runtime');
  const files = [['entry.js', Buffer.from(marker + '-entry')], ['nested/data.bin', Buffer.from(marker + '-data')]];
  fs.writeFileSync(runtime, runtimeBytes, { mode: 0o755 });
  fs.chmodSync(runtime, 0o755);
  const manifest = { runtime: { mode: 0o755, size: runtimeBytes.length, sha256: hash(runtimeBytes) },
    files: files.map(([path, bytes]) => {
      fs.writeFileSync(join(payload, path), bytes, { mode: 0o644 });
      fs.chmodSync(join(payload, path), 0o644);
      return { path, mode: 0o644, size: bytes.length, sha256: hash(bytes) };
    }) };
  const manifestPath = join(payload, 'manifest.json');
  const save = () => fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  save();
  return { root, launchRoot, evidence, runtime, payload, manifestPath, manifest, save,
    system: darwin ? 'aarch64-darwin' : 'x86_64-linux',
    close: () => fs.rmSync(root, { recursive: true, force: true }) };
}
function observe(f) { return observeSidecarMode({ launchRoot: f.launchRoot, system: f.system, evidence: f.evidence }); }
function sanitized(record, f) {
  const encoded = JSON.stringify(record);
  assert(!encoded.includes(f.root));
  assert(!encoded.includes(marker));
  assert(!encoded.includes('entry.js'));
  for (const key of ['productionEnabled', 'publicationAuthority', 'productionAuthority', 'admitting', 'accepted', 'guiQualified']) assert.equal(record[key], false);
}

test('archive modes and exact runtime metadata are observed for both fixed layouts', () => {
  for (const darwin of [false, true]) {
    const f = fixture(darwin);
    try {
      const record = observe(f);
      assert.equal(record.status, 'compatible');
      assert.deepEqual(record.runtime.actual, record.runtime.expected);
      assert.equal(record.runtime.actual.mode, 0o755);
      assert.deepEqual(record.payload.mismatches, { mode: 0, size: 0, sha256: 0 });
      assert.equal(record.payload.files, 2);
      assert.equal(record.evidenceWriteStatus, 'written');
      assert.equal(fs.statSync(join(f.evidence, member)).mode & 0o777, 0o600);
      assert.deepEqual(JSON.parse(fs.readFileSync(join(f.evidence, member))), record);
      sanitized(record, f);
    } finally { f.close(); }
  }
});

test('store-normalized modes report incompatibility without changing installed files', () => {
  const f = fixture();
  try {
    fs.chmodSync(f.runtime, 0o555);
    for (const value of f.manifest.files) fs.chmodSync(join(f.payload, value.path), 0o444);
    const record = observe(f);
    assert.equal(record.status, 'incompatible');
    assert.equal(record.runtime.actual.mode, 0o555);
    assert.equal(record.runtime.expected.mode, 0o755);
    assert.deepEqual(record.runtime.mismatches, { mode: true, size: false, sha256: false });
    assert.deepEqual(record.payload.mismatches, { mode: 2, size: 0, sha256: 0 });
    assert.equal(fs.statSync(f.runtime).mode & 0o777, 0o555);
    sanitized(record, f);
  } finally { f.close(); }
});

test('runtime and payload content/size drift produce only bounded counters and digests', () => {
  const f = fixture();
  try {
    fs.appendFileSync(f.runtime, 'x');
    const first = join(f.payload, f.manifest.files[0].path);
    fs.writeFileSync(first, Buffer.alloc(f.manifest.files[0].size, 65));
    fs.appendFileSync(join(f.payload, f.manifest.files[1].path), 'x');
    const record = observe(f);
    assert.equal(record.status, 'incompatible');
    assert.deepEqual(record.runtime.mismatches, { mode: false, size: true, sha256: true });
    assert.deepEqual(record.payload.mismatches, { mode: 0, size: 1, sha256: 2 });
    sanitized(record, f);
  } finally { f.close(); }
});

test('malformed and oversized manifests return closed failures without file-content retention', () => {
  for (const kind of ['syntax', 'shape', 'oversized', 'count', 'aggregate', 'empty', 'duplicate']) {
    const f = fixture();
    try {
      if (kind === 'syntax') fs.writeFileSync(f.manifestPath, marker);
      else if (kind === 'shape') fs.writeFileSync(f.manifestPath, JSON.stringify({ runtime: { sha256: marker } }));
      else if (kind === 'oversized') fs.writeFileSync(f.manifestPath, Buffer.alloc(2 * 1024 * 1024 + 1));
      else if (kind === 'count') { f.manifest.files = Array(10001).fill(f.manifest.files[0]); f.save(); }
      else if (kind === 'empty') { f.manifest.files = []; f.save(); }
      else if (kind === 'duplicate') { f.manifest.files.push(f.manifest.files[0]); f.save(); }
      else { f.manifest.files = Array.from({ length: 5 }, (_, i) => ({ ...f.manifest.files[0], path: 'item-' + i, size: 256 * 1024 * 1024 })); f.save(); }
      const record = observe(f);
      assert.equal(record.status, 'unavailable');
      assert(['INVALID_MANIFEST', 'LIMIT_EXCEEDED'].includes(record.failureCategory));
      assert.equal(record.runtime, null);
      sanitized(record, f);
    } finally { f.close(); }
  }
});

test('individual runtime/file size bounds apply before reading contents', () => {
  for (const role of ['runtime', 'payload']) {
    const f = fixture();
    const originalLstat = fs.lstatSync, originalFstat = fs.fstatSync;
    try {
      const target = role === 'runtime' ? f.runtime : join(f.payload, f.manifest.files[0].path);
      const targetInfo = fs.statSync(target);
      // Model oversized metadata while retaining a physically tiny inert tree.
      const oversized = info => {
        info.size = typeof info.size === 'bigint' ? 268435457n : 268435457;
        return info;
      };
      fs.lstatSync = (path, ...args) => {
        const info = originalLstat(path, ...args);
        return path === target ? oversized(info) : info;
      };
      fs.fstatSync = (fd, ...args) => {
        const info = originalFstat(fd, ...args);
        return String(info.dev) === String(targetInfo.dev) && String(info.ino) === String(targetInfo.ino)
          ? oversized(info) : info;
      };
      syncBuiltinESMExports();
      const record = observe(f);
      assert.equal(record.status, 'unavailable');
      assert.equal(record.failureCategory, 'LIMIT_EXCEEDED');
      sanitized(record, f);
    } finally {
      fs.lstatSync = originalLstat; fs.fstatSync = originalFstat;
      syncBuiltinESMExports(); f.close();
    }
  }
});

test('manifest path escapes and symlink components refuse without reading the target', () => {
  for (const kind of ['escape', 'absolute', 'file-link', 'directory-link', 'runtime-link', 'manifest-link']) {
    const f = fixture();
    try {
      const outside = join(f.root, 'outside');
      fs.writeFileSync(outside, marker);
      if (kind === 'escape' || kind === 'absolute') {
        f.manifest.files[0].path = kind === 'escape' ? '../outside' : outside;
        f.save();
      } else if (kind === 'manifest-link') {
        fs.unlinkSync(f.manifestPath); fs.symlinkSync(outside, f.manifestPath);
      } else if (kind === 'runtime-link') {
        fs.unlinkSync(f.runtime); fs.symlinkSync(outside, f.runtime);
      } else if (kind === 'file-link') {
        const target = join(f.payload, f.manifest.files[0].path);
        fs.unlinkSync(target); fs.symlinkSync(outside, target);
      } else {
        fs.rmSync(join(f.payload, 'nested'), { recursive: true });
        fs.symlinkSync(f.root, join(f.payload, 'nested'));
      }
      const originalRead = fs.readSync;
      const outsideInfo = fs.statSync(outside);
      let outsideRead = false;
      fs.readSync = (fd, ...args) => {
        const info = fs.fstatSync(fd);
        if (info.dev === outsideInfo.dev && info.ino === outsideInfo.ino) outsideRead = true;
        return originalRead(fd, ...args);
      };
      syncBuiltinESMExports();
      let record;
      try { record = observe(f); }
      finally { fs.readSync = originalRead; syncBuiltinESMExports(); }
      assert.equal(record.status, 'unavailable');
      assert(['INVALID_MANIFEST', 'UNSAFE_PATH'].includes(record.failureCategory));
      assert.equal(outsideRead, false);
      sanitized(record, f);
    } finally { f.close(); }
  }
});

test('mutation during an opened file read is rejected with a sanitized category', () => {
  const f = fixture();
  const originalRead = fs.readSync;
  try {
    const info = fs.statSync(f.runtime);
    let mutated = false;
    fs.readSync = (fd, ...args) => {
      const current = fs.fstatSync(fd);
      if (!mutated && current.dev === info.dev && current.ino === info.ino) {
        mutated = true;
        fs.appendFileSync(f.runtime, marker);
      }
      return originalRead(fd, ...args);
    };
    syncBuiltinESMExports();
    const record = observe(f);
    assert.equal(mutated, true);
    assert.equal(record.status, 'unavailable');
    assert.equal(record.failureCategory, 'IDENTITY_CHANGED');
    sanitized(record, f);
  } finally { fs.readSync = originalRead; syncBuiltinESMExports(); f.close(); }
});

test('unrelated ancestor entries do not invalidate stable payload objects', () => {
  const f = fixture();
  const originalRead = fs.readSync;
  try {
    const info = fs.statSync(f.runtime);
    let changed = false;
    fs.readSync = (fd, ...args) => {
      const current = fs.fstatSync(fd);
      if (!changed && current.dev === info.dev && current.ino === info.ino) {
        changed = true;
        fs.writeFileSync(join(f.root, 'unrelated-entry'), 'inert');
      }
      return originalRead(fd, ...args);
    };
    syncBuiltinESMExports();
    const record = observe(f);
    assert.equal(changed, true);
    assert.equal(record.status, 'compatible');
    sanitized(record, f);
  } finally { fs.readSync = originalRead; syncBuiltinESMExports(); f.close(); }
});

test('observation failure and exclusive evidence-write failure never throw or overwrite', () => {
  const f = fixture();
  try {
    const path = join(f.evidence, member);
    fs.writeFileSync(path, 'prior-diagnostic');
    fs.unlinkSync(f.manifestPath);
    const record = observe(f);
    assert.equal(record.status, 'unavailable');
    assert.equal(record.failureCategory, 'OBSERVATION_FAILED');
    assert.equal(record.evidenceWriteStatus, 'failed');
    assert.equal(record.evidenceFailureCategory, 'EVIDENCE_WRITE_FAILED');
    assert.equal(hash(fs.readFileSync(path)), hash('prior-diagnostic'));
    sanitized(record, f);
    assert.doesNotThrow(() => observeSidecarMode(null));
  } finally { f.close(); }
});

test('actual route fragment reaches required GUI operation and preserves its failure after diagnostic failure', async () => {
  const f = fixture(true);
  try {
    fs.unlinkSync(f.manifestPath);
    const gui = join(f.launchRoot, 'Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion');
    fs.writeFileSync(gui, 'inert-gui-bytes');
    const source = fs.readFileSync(new URL('../tools/verification/qualify-p-current-nix.mjs', import.meta.url), 'utf8');
    const start = source.indexOf("  const darwin=system==='aarch64-darwin';");
    const stop = source.indexOf("{timeout:600000});", start) + "{timeout:600000});".length;
    assert(start > 0 && stop > start);
    // Execute only the real route's installed-payload-to-GUI-call fragment.
    // All external operations are inert callbacks; no Nix, child or GUI runs.
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    const names = ['system','outputs','join','hash','readFileSync','lock','observeSidecarMode','evidence',
      'bindRawLauncher','commands','dispatchProbe','realpathSync','commandEvidence','writeFileSync',
      'nativeGuiController','guiBinding','preparePublicWrapperHarness','checkout','contract','derivations','closure',
      'assert','mode','plan','basename','declared','checked','process'];
    const run = new AsyncFunction(...names, source.slice(start, stop) + '\n}\n');
    let called = false;
    const requiredFailure = new Error('required-inert-GUI-result');
    const values = ['aarch64-darwin', { 'theme-forge-nebular-fusion-payload': f.root, tfnf: f.root }, join,
      hash, fs.readFileSync, { products: { 'theme-forge-nebular-fusion': { rawArchives: {
        'aarch64-darwin': { executableSha256: hash('inert-gui-bytes') } } } } }, observeSidecarMode, f.evidence,
      () => ({}), { tfnf: { implementation_sha256: {} } }, async () => ({ stdout: gui }), fs.realpathSync,
      [], fs.writeFileSync, false, null, () => ({ adaptedPath: 'inert-harness', record: { transform: 'inert' } }),
      f.root, {}, Buffer.alloc(0), Buffer.alloc(0), assert, 'fixture', { guiProfile: 'inert', adaptedScenarios: ['A'] },
      basename, { bindingMember: 'p-test-adapter-binding.json' }, () => { called = true; throw requiredFailure; }, process];
    // The installed Darwin route appends /Applications to its payload output.
    values[1]['theme-forge-nebular-fusion-payload'] = join(f.root, 'package');
    fs.mkdirSync(values[1]['theme-forge-nebular-fusion-payload'], { recursive: true });
    fs.renameSync(f.launchRoot, join(values[1]['theme-forge-nebular-fusion-payload'], 'Applications'));
    const boundGui = join(values[1]['theme-forge-nebular-fusion-payload'], 'Applications/Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion');
    values[names.indexOf('dispatchProbe')] = async () => ({ stdout: boundGui });
    let diagnostic;
    values[names.indexOf('observeSidecarMode')] = input => { diagnostic = observeSidecarMode(input); return diagnostic; };
    await assert.rejects(run(...values), error => error === requiredFailure);
    assert.equal(called, true);
    assert.equal(diagnostic.evidenceWriteStatus, 'written');
    called = false;
    // The second attempt also hits exclusive evidence-write refusal; the same
    // required GUI callback and its original error must still survive.
    await assert.rejects(run(...values), error => error === requiredFailure);
    assert.equal(called, true);
    assert.equal(diagnostic.evidenceWriteStatus, 'failed');
    const record = JSON.parse(fs.readFileSync(join(f.evidence, member)));
    assert.equal(record.status, 'unavailable');
    sanitized(record, f);
  } finally { f.close(); }
});
