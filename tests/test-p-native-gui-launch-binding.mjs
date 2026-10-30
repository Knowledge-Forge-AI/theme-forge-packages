import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { constants as fsConstants, fstatSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import * as binding from '../tools/verification/p-native-gui-launch-binding.mjs';

// Exact parent-retained qualified 4841-byte derivation text, not an execution fixture.
const REAL_WRAPPER = "#!/nix/store/10dxp0qxqxxsyiljrh2kp0xqhz6arhcx-bash-5.3p15/bin/bash\nignored=(/nix /dev /proc /etc )\nro_mounts=()\nsymlinks=()\netc_ignored=()\n\n\n\n# loop through all entries of root in the fhs environment, except its /etc.\nfor i in /nix/store/ycvw6afcf466gk2f3czjsd1bp9iiswak-tfnf-fhsenv-rootfs/*; do\n  path=\"/${i##*/}\"\n  if [[ $path == '/etc' ]]; then\n    :\n  elif [[ -L $i ]]; then\n    symlinks+=(--symlink \"$(/nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/bin/readlink \"$i\")\" \"$path\")\n    ignored+=(\"$path\")\n  else\n    ro_mounts+=(--ro-bind \"$i\" \"$path\")\n    ignored+=(\"$path\")\n  fi\ndone\n\n# loop through the entries of /etc in the fhs environment.\nif [[ -d /nix/store/ycvw6afcf466gk2f3czjsd1bp9iiswak-tfnf-fhsenv-rootfs/etc ]]; then\n  for i in /nix/store/ycvw6afcf466gk2f3czjsd1bp9iiswak-tfnf-fhsenv-rootfs/etc/*; do\n    path=\"/${i##*/}\"\n    # NOTE: we're binding /etc/fonts and /etc/ssl/certs from the host so we\n    # don't want to override it with a path from the FHS environment.\n    if [[ $path == '/fonts' || $path == '/ssl' ]]; then\n      continue\n    fi\n    if [[ -L $i ]]; then\n      symlinks+=(--symlink \"$i\" \"/etc$path\")\n    else\n      ro_mounts+=(--ro-bind \"$i\" \"/etc$path\")\n    fi\n    etc_ignored+=(\"/etc$path\")\n  done\nfi\n\n# propagate /etc from the actual host if nested\nif [[ -e /.host-etc ]]; then\n  ro_mounts+=(--ro-bind /.host-etc /.host-etc)\nelse\n  ro_mounts+=(--ro-bind /etc /.host-etc)\nfi\n\ndeclare -A etc_ignored_set\nfor ign in \"${etc_ignored[@]}\"; do\n  etc_ignored_set[$ign]=1\ndone\n\n# link selected etc entries from the actual root\nfor i in /etc/static /etc/nix /etc/shells /etc/bashrc /etc/zshenv /etc/zshrc /etc/zinputrc /etc/zprofile /etc/passwd /etc/group /etc/shadow /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/profiles /etc/login.defs /etc/sudoers /etc/sudoers.d /etc/localtime /etc/zoneinfo /etc/machine-id /etc/os-release /etc/pam.d /etc/fonts /etc/alsa /etc/asound.conf /etc/ssl/certs /etc/ca-certificates /etc/pki /etc/dconf; do\n  if [[ -n \"${etc_ignored_set[$i]:-}\" ]]; then\n    continue\n  fi\n  if [[ -e $i ]]; then\n    symlinks+=(--symlink \"/.host-etc/${i#/etc/}\" \"$i\")\n  fi\ndone\n\ndeclare -A ignored_set\nfor ign in \"${ignored[@]}\"; do\n  ignored_set[$ign]=1\ndone\n\ndeclare -a auto_mounts\n# loop through all directories in the root\nfor dir in /*; do\n  # if it is a directory and not already provided by the FHS env or\n  # explicitly ignored, bind-mount it into the chroot. Use exact match\n  # via associative array because regex substring matching incorrectly\n  # skips prefixes (e.g. /sb would match /sbin and never get mounted,\n  # breaking --chdir when CWD is on a custom mount like /sb/project).\n  # https://github.com/NixOS/nixpkgs/issues/241151\n  if [[ -d \"$dir\" ]] && [[ -z \"${ignored_set[$dir]:-}\" ]]; then\n    # add it to the mount list\n    auto_mounts+=(--bind \"$dir\" \"$dir\")\n  fi\ndone\n\ndeclare -a x11_args\n# Always mount a tmpfs on /tmp/.X11-unix\n# Rationale: https://github.com/flatpak/flatpak/blob/be2de97e862e5ca223da40a895e54e7bf24dbfb9/common/flatpak-run.c#L277\nx11_args+=(--tmpfs /tmp/.X11-unix)\n\n# Try to guess X socket path. This doesn't cover _everything_, but it covers some things.\nif [[ \"$DISPLAY\" == *:* ]]; then\n  # recover display number from $DISPLAY formatted [host]:num[.screen]\n  display_nr=${DISPLAY/#*:} # strip host\n  display_nr=${display_nr/%.*} # strip screen\n  local_socket=/tmp/.X11-unix/X$display_nr\n  x11_args+=(--ro-bind-try \"$local_socket\" \"$local_socket\")\nfi\n\n\n\ncmd=(\n  /nix/store/zri6pfys37ih88s5yckr47khz5zw1rzk-bubblewrap-0.12.0/bin/bwrap\n  --dev-bind /dev /dev\n  --proc /proc\n  --chdir \"$(pwd)\"\n  \n  \n  \n  \n  \n  \n  --die-with-parent\n  --bind /nix /nix\n  \n  # Our glibc will look for the cache in its own path in `/nix/store`.\n  # As such, we need a cache to exist there, because pressure-vessel\n  # depends on the existence of an ld cache. However, adding one\n  # globally proved to be a bad idea (see #100655), the solution we\n  # settled on being mounting one via bwrap.\n  # Also, the cache needs to go to both 32 and 64 bit glibcs, for games\n  # of both architectures to work.\n  --tmpfs /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc \\\n  --tmpfs /etc \\\n  --symlink /etc/ld.so.conf /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/ld.so.conf \\\n  --symlink /etc/ld.so.cache /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/ld.so.cache \\\n  --ro-bind /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/rpc /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/rpc \\\n  --remount-ro /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc \\\n  --symlink /nix/store/msxm3xjics0s0qmg4c4apnayb4xz4574-tfnf-init /init \\\n  \"${ro_mounts[@]}\"\n  \"${symlinks[@]}\"\n  \"${auto_mounts[@]}\"\n  \"${x11_args[@]}\"\n  \n  /nix/store/f58pgq0yfin4v7b3r6wzbx2g9x489ncc-container-init \"$@\"\n)\nexec \"${cmd[@]}\"\n\n";
const EXPECTED_WRAPPER_SHA256 = 'a5a75a547adb4d2b782f02993ad4a510bb4c2730786752422a60e75c5df46b17';

const hash = value => createHash('sha256').update(value).digest('hex');
const BASH = REAL_WRAPPER.split('\n')[0].slice(2);
const CONTEXT = Object.freeze({ bwrap: REAL_WRAPPER.match(/  (\/nix\/store\/[^\s]+\/bin\/bwrap)\n/)[1],
  containerInit: REAL_WRAPPER.match(/  (\/nix\/store\/[^\s]+-container-init) "\$@"/)[1],
  originalInit: REAL_WRAPPER.match(/--symlink (\/nix\/store\/[^\s]+-tfnf-init) \/init/)[1] });
const sourceInput = (source = REAL_WRAPPER) => ({ wrapperBytes: Buffer.from(source), declaredBytes: Buffer.from(source),
  expectedSha256: hash(source), pinnedBash: BASH, context: CONTEXT,
  buildFhsEnvSourceSha256: '5c642cc3eed380324d3109a9a428be020ed529774f5c4f5877bb2bb1b93ac93f',
  containerSourceSha256: '40f92dd2ca8e5161e55b5d85c2ece3a79a43b6d96dc20d6b0b05a0fcabf4c7fd' });
const launch = (cwd = '/fresh/gui/cwd', scenario = 'C') => binding.freezeLaunchInputs({
  args: ['--nebular-release-smoke=' + scenario], cwd, env: { DISPLAY: ':91', PATH: '/fixture/path', HOME: '/fixture/home' } });
function argvFor(input, extra = []) {
  return [CONTEXT.bwrap, '--dev-bind', '/dev', '/dev', '--proc', '/proc', '--chdir', input.cwd,
    '--die-with-parent', '--bind', '/nix', '/nix', '--symlink', CONTEXT.originalInit, '/init',
    ...extra, '--tmpfs', '/tmp/.X11-unix',
    ...(input.env.DISPLAY?.includes(':') ? ['--ro-bind-try', '/tmp/.X11-unix/X' + input.env.DISPLAY.split(':').at(-1).split('.')[0],
      '/tmp/.X11-unix/X' + input.env.DISPLAY.split(':').at(-1).split('.')[0]] : []), CONTEXT.containerInit, ...input.args];
}
const raw = argv => Buffer.from(argv.join('\0') + '\0');
const coded = code => error => error instanceof binding.LaunchBindingError && error.code === code;
const flush = () => new Promise(resolve => setImmediate(resolve));

class Clock {
  now = 0; next = 0; timers = new Map();
  setTimeout = (fn, ms) => { const id = ++this.next; this.timers.set(id, { at: this.now + ms, fn }); return id; };
  clearTimeout = id => this.timers.delete(id);
  advance(ms) {
    const until = this.now + ms;
    for (;;) {
      const next = [...this.timers].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      this.now = next[1].at; this.timers.delete(next[0]); next[1].fn();
    }
    this.now = until;
  }
}
class OwnedChild extends EventEmitter {
  stdout = new PassThrough(); stderr = new PassThrough(); pid = 4141; kills = [];
  kill(signal) { this.kills.push(signal); return true; }
  finish(code = 0, signal = null) { this.emit('exit', code, signal); this.stdout.end(); this.stderr.end(); }
}
function processFixture({ noSpawn = false, noPid = false, throwing = false } = {}) {
  const clock = new Clock(), child = new OwnedChild(), calls = [];
  let ready;
  const started = new Promise(resolve => { ready = resolve; });
  if (noPid) delete child.pid;
  const spawn = (...args) => {
    calls.push(args); ready();
    if (throwing) throw new Error('private spawn diagnostics');
    if (!noSpawn) queueMicrotask(() => child.emit('spawn'));
    return child;
  };
  return { clock, child, calls, started, resolve: binding.createFixtureResolver({ spawn,
    setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout }) };
}
async function files(t, { symlink = false } = {}) {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'p-gui-inert-stage-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const sourceRoot = path.join(directory, 'authenticated-checkout'), stage = path.join(directory, 'observer'), cwd = path.join(directory, 'gui-cwd');
  for (const name of [sourceRoot, stage, cwd]) await fs.mkdir(name, { mode: 0o700 });
  const actual = path.join(directory, 'realized-wrapper');
  await fs.writeFile(actual, REAL_WRAPPER, { mode: 0o644 });
  const wrapperPath = symlink ? path.join(directory, 'public-wrapper') : actual;
  if (symlink) await fs.symlink('realized-wrapper', wrapperPath);
  const authentication = binding.authenticateWrapper(sourceInput());
  const observer = await binding.stageObserver(authentication, { directory: stage, wrapperPath, expectedResolvedWrapperPath: actual, authenticatedSourceRoot: sourceRoot });
  return { directory, sourceRoot, stage, cwd, actual, wrapperPath, authentication, observer, input: launch(cwd) };
}

test('qualified fixture identity and terminal-only observer transform are exact', () => {
  assert.equal(Buffer.byteLength(REAL_WRAPPER), 4841); assert.equal(hash(REAL_WRAPPER), EXPECTED_WRAPPER_SHA256);
  const auth = binding.authenticateWrapper(sourceInput()), observer = binding.getObserverSource(auth).toString();
  const final = 'exec "${cmd[@]}"', position = REAL_WRAPPER.indexOf(final);
  assert.equal(observer, REAL_WRAPPER.slice(0, position) + 'printf \'%s\\0\' "${cmd[@]}"' + REAL_WRAPPER.slice(position + final.length));
  assert.ok(REAL_WRAPPER.slice(0, position).endsWith('  ' + CONTEXT.containerInit + ' "$@"\n)\n'));
  assert.equal(auth.facts.bash, BASH); assert.equal(auth.facts.pathnameUseAbsent, true);
  assert.throws(() => binding.getObserverSource(JSON.parse(JSON.stringify(auth))), coded('SOURCE_HANDLE'));
});

test('matching declared bytes cannot bypass pathname, terminal or pinned-interpreter guards', () => {
  for (const use of ['$0', '${0}', '${#0}', '${!0}', '${@:0}', '${0:-fallback}', '${BASH_SOURCE[0]}', '$BASH_SOURCE', '$BASH_ARGV0']) {
    const changed = REAL_WRAPPER.replace('\n', '\nprintf "' + use + '"\n');
    assert.throws(() => binding.authenticateWrapper(sourceInput(changed)), coded('WRAPPER_PATHNAME_USE'));
  }
  for (const changed of [REAL_WRAPPER + 'echo extra\n', REAL_WRAPPER.replace('cmd=(\n', 'exec "${cmd[@]}"\ncmd=(\n')])
    assert.throws(() => binding.authenticateWrapper(sourceInput(changed)), coded('TERMINAL_EXEC'));
  assert.throws(() => binding.authenticateWrapper({ ...sourceInput(), pinnedBash: '/nix/store/' + '1'.repeat(32) + '-bash/bin/bash' }), coded('PINNED_BASH'));
  assert.throws(() => binding.authenticateWrapper({ ...sourceInput(), declaredBytes: Buffer.from('other') }), coded('SOURCE_MISMATCH'));
  assert.throws(() => binding.authenticateWrapper({ ...sourceInput(), expectedSha256: '0'.repeat(64) }), coded('SOURCE_MISMATCH'));
});

test('source arrays, exact container forwarding, init and size cannot be relabeled', () => {
  for (const changed of [REAL_WRAPPER.replace('"$@"', ''), REAL_WRAPPER.replace(CONTEXT.containerInit, CONTEXT.originalInit),
    REAL_WRAPPER.replace('--symlink ' + CONTEXT.originalInit, '--symlink /other'), REAL_WRAPPER.replace('"${ro_mounts[@]}"', '')])
    assert.throws(() => binding.authenticateWrapper(sourceInput(changed)), coded('WRAPPER_LAYOUT'));
  assert.throws(() => binding.authenticateWrapper(sourceInput('x'.repeat(128 * 1024 + 1))), coded('SOURCE_BOUND'));
});

test('frozen launch inputs reject dangerous environment without observer-only filtering', () => {
  for (const key of ['BASH_ENV', 'ENV', 'BASHOPTS', 'SHELLOPTS', 'BASH_FUNC_x', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'IFS', 'NODE_OPTIONS'])
    assert.throws(() => binding.freezeLaunchInputs({ args: ['--nebular-release-smoke=B'], cwd: '/gui', env: { [key]: 'private' } }), coded('DANGEROUS_ENVIRONMENT'));
  for (const args of [[], ['--help'], ['--nebular-release-smoke=B', 'extra']])
    assert.throws(() => binding.freezeLaunchInputs({ args, cwd: '/gui', env: {} }), coded('GUI_SMOKE_ARGUMENT'));
  assert.throws(() => binding.freezeLaunchInputs({ args: ['--nebular-release-smoke=B'], cwd: '/gui', env: { PWD: '/other' } }), coded('LAUNCH_CWD_ENVIRONMENT'));
  const env = { DISPLAY: ':99', HOME: 'private-value' }, args = ['--nebular-release-smoke=C'];
  const result = binding.freezeLaunchInputs({ args, cwd: '/gui', env });
  env.DISPLAY = ':1'; args[0] = 'changed'; assert.equal(result.env.DISPLAY, ':99');
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.args) && Object.isFrozen(result.env));
  assert.ok(!JSON.stringify(result).includes('private-value'));
  assert.ok(!JSON.stringify(result).includes('/gui'));
});

test('GUI parser uses fresh cwd and exact suffix inside cmd for all three scenarios', () => {
  for (const scenario of ['B', 'C', 'C-signal']) {
    const input = launch('/fresh/gui/not-driver-cwd', scenario), argv = argvFor(input);
    const parsed = binding.parseFreshArgv(raw(argv), { context: CONTEXT, launchInputs: input });
    assert.deepEqual(parsed.argv, argv); assert.equal(parsed.optionCount, 8);
    assert.throws(() => binding.parseFreshArgv(raw([...argv, input.args[0]]), { context: CONTEXT, launchInputs: input }), coded('GUI_ARGV_SUFFIX'));
  }
});

test('realized static mounts and fresh DISPLAY policy use explicit typed fields', () => {
  const input = launch(), glibc = REAL_WRAPPER.match(/--tmpfs (\/nix\/store\/[^\s]+\/etc)/)[1];
  const rootfs = REAL_WRAPPER.match(/for i in (\/nix\/store\/[^\s]+-rootfs)\/\*/)[1];
  const extra = ['--tmpfs', glibc, '--tmpfs', '/etc', '--symlink', '/etc/ld.so.conf', glibc + '/ld.so.conf',
    '--symlink', '/etc/ld.so.cache', glibc + '/ld.so.cache', '--ro-bind', glibc + '/rpc', glibc + '/rpc',
    '--remount-ro', glibc, '--ro-bind', rootfs + '/usr', '/usr', '--ro-bind', '/etc', '/.host-etc',
    '--symlink', '/.host-etc/passwd', '/etc/passwd', '--bind', '/home', '/home'];
  assert.deepEqual(binding.parseFreshArgv(raw(argvFor(input, extra)), { context: CONTEXT, launchInputs: input }).argv, argvFor(input, extra));
  const changed = binding.freezeLaunchInputs({ args: input.args, cwd: input.cwd, env: { ...input.env, DISPLAY: ':92' } });
  assert.throws(() => binding.parseFreshArgv(raw(argvFor(input)), { context: CONTEXT, launchInputs: changed }), coded('BWRAP_X11_POLICY'));
  for (const extraMount of [['--tmpfs', '/'], ['--bind', '/other', '/nix/store'], ['--bind', '/other', '/etc/../dev']])
    assert.throws(() => binding.parseFreshArgv(raw(argvFor(input, extraMount)), { context: CONTEXT, launchInputs: input }), binding.LaunchBindingError);
});

test('parser refuses malformed framing, element bounds, arbitrary commands and saved input', () => {
  const input = launch(), argv = argvFor(input);
  for (const value of [Buffer.alloc(0), raw(argv).subarray(0, -1), Buffer.from([255, 0]),
    Buffer.alloc(1024 * 1024 + 1), raw([...argv.slice(0, -2), 'x'.repeat(16385), ...argv.slice(-2)])])
    assert.throws(() => binding.parseFreshArgv(value, { context: CONTEXT, launchInputs: input }), binding.LaunchBindingError);
  assert.throws(() => binding.parseFreshArgv(raw(argv), { context: CONTEXT, launchInputs: JSON.parse(JSON.stringify(input)) }), coded('FROZEN_LAUNCH_HANDLE'));
  assert.throws(() => binding.parseFreshArgv(raw(argv), { context: CONTEXT, launchInputs: input, savedArgv: argv }), coded('BINDING_SHAPE'));
  for (const extra of [['--unshare-all'], ['--new-session'], ['--setenv', 'HOME', '/other'], ['/bin/sh'], ['--bind']])
    assert.throws(() => binding.parseFreshArgv(raw(argvFor(input, extra)), { context: CONTEXT, launchInputs: input }), binding.LaunchBindingError);
});

test('parser retains original dev/proc/chdir/parent/nix/init policies and identities', () => {
  const input = launch(), base = argvFor(input);
  const changedCwd = [...base]; changedCwd[7] = '/other';
  const changedBwrap = [...base]; changedBwrap[0] = CONTEXT.originalInit;
  const changedContainer = [...base]; changedContainer[changedContainer.length - 2] = CONTEXT.originalInit;
  for (const argv of [changedCwd, changedBwrap, changedContainer, base.filter(value => value !== '--die-with-parent')])
    assert.throws(() => binding.parseFreshArgv(raw(argv), { context: CONTEXT, launchInputs: input }), binding.LaunchBindingError);
  for (const extra of [['--dev-bind', '/dev', '/dev'], ['--proc', '/proc'], ['--die-with-parent'],
    ['--bind', '/nix', '/nix'], ['--bind', '/other', '/nix'], ['--symlink', CONTEXT.originalInit, '/init'],
    ['--ro-bind', '/other', '/init'], ['--bind', '/other', '/dev/x']])
    assert.throws(() => binding.parseFreshArgv(raw(argvFor(input, extra)), { context: CONTEXT, launchInputs: input }), binding.LaunchBindingError);
});

test('exclusive regular0600 staging preserves unrelated files and rejects checkout/symlink staging', async t => {
  const f = await files(t);
  assert.equal((await fs.lstat(f.observer.path)).mode & 0o777, 0o600);
  assert.deepEqual(await fs.readFile(f.observer.path), binding.getObserverSource(f.authentication));
  await fs.writeFile(path.join(f.stage, 'unrelated'), 'retained');
  const second = await binding.stageObserver(f.authentication, { directory: f.stage, wrapperPath: f.wrapperPath, expectedResolvedWrapperPath: f.actual, authenticatedSourceRoot: f.sourceRoot });
  assert.notEqual(second.path, f.observer.path);
  await binding.removeObserver(second); assert.equal(await fs.readFile(path.join(f.stage, 'unrelated'), 'utf8'), 'retained');
  const nested = path.join(f.sourceRoot, 'observer'); await fs.mkdir(nested, { mode: 0o700 });
  await assert.rejects(binding.stageObserver(f.authentication, { directory: nested, wrapperPath: f.wrapperPath, expectedResolvedWrapperPath: f.actual, authenticatedSourceRoot: f.sourceRoot }), coded('OBSERVER_STAGING_BOUNDARY'));
  const alias = path.join(f.directory, 'stage-alias'); await fs.symlink(f.stage, alias);
  await assert.rejects(binding.stageObserver(f.authentication, { directory: alias, wrapperPath: f.wrapperPath, expectedResolvedWrapperPath: f.actual, authenticatedSourceRoot: f.sourceRoot }), coded('OBSERVER_STAGING_BOUNDARY'));
  await assert.rejects(binding.stageObserver(f.authentication, { directory: f.stage, wrapperPath: f.wrapperPath,
    expectedResolvedWrapperPath: path.join(f.directory, 'wrong-file'), authenticatedSourceRoot: f.sourceRoot }), coded('SOURCE_MISMATCH'));
});

test('fresh owned-process boundary receives exact frozen inputs and emits only closed durable facts', async t => {
  const f = await files(t), p = processFixture(), pending = p.resolve({ observer: f.observer, launchInputs: f.input });
  await p.started; await flush();
  const [command, args, options] = p.calls[0]; assert.equal(command, BASH);
  assert.deepEqual(args, [f.observer.path, ...f.input.args]); assert.equal(options.cwd, f.input.cwd);
  assert.equal(options.env, f.input.env); assert.equal(options.shell, false); assert.equal(options.detached, false);
  p.child.stdout.write(raw(argvFor(f.input))); p.child.stderr.write('bounded diagnostic'); p.child.finish();
  const result = await pending;
  assert.equal(result.launchInputs, f.input); assert.deepEqual(result.resolvedArgv, argvFor(f.input));
  assert.equal(result.facts.fixtureMode, true); assert.equal(result.facts.admitting, false);
  assert.equal(result.facts.guiQualification, false); assert.equal(result.facts.publicationAuthority, false);
  assert.equal(result.facts.nativeQualification, false); assert.equal(result.facts.productionEnabled, false);
  assert.equal(result.facts.observerExitCode, 0); assert.equal(result.facts.observerExitSignal, null);
  assert.equal(result.facts.deadlineMs, 10000); assert.equal(result.facts.outputLimitBytes, 1024 * 1024);
  assert.ok(binding.isFreshLaunchBinding(result, f.input));
  assert.equal(binding.isFreshLaunchBinding(JSON.parse(JSON.stringify(result)), f.input), false);
  assert.ok(!JSON.stringify(result.facts).includes(f.directory));
  assert.ok(!JSON.stringify(result.facts).includes('bounded diagnostic'));
  assert.deepEqual(Object.keys(result), ['facts']);
  assert.ok(!JSON.stringify(result).includes(f.directory));
  assert.ok(!JSON.stringify(f.observer).includes(f.directory));
  assert.equal(p.clock.timers.size, 0); assert.deepEqual(p.child.kills, []);
});

test('public wrapper symlink chains bind resolved source and detect a same-byte retarget', async t => {
  const f = await files(t, { symlink: true }), p = processFixture();
  const pending = p.resolve({ observer: f.observer, launchInputs: f.input });
  await p.started; await flush(); p.child.stdout.end(raw(argvFor(f.input))); p.child.stderr.end(); p.child.emit('exit', 0, null);
  assert.equal((await pending).facts.exactSourceReadbacks, true);
  const other = path.join(f.directory, 'same-byte-other-wrapper'); await fs.writeFile(other, REAL_WRAPPER);
  await fs.unlink(f.wrapperPath); await fs.symlink('same-byte-other-wrapper', f.wrapperPath);
  const refused = processFixture();
  await assert.rejects(refused.resolve({ observer: f.observer, launchInputs: f.input }), coded('SOURCE_READBACK'));
  assert.equal(refused.calls.length, 0);
});

test('stale sources or observer permissions/symlinks refuse before any process factory', async t => {
  for (const mutation of [async f => fs.writeFile(f.actual, REAL_WRAPPER + '#changed'),
    async f => fs.chmod(f.observer.path, 0o644), async f => fs.chmod(f.observer.path, 0o4600),
    async f => fs.link(f.observer.path, path.join(f.directory, 'observer-hardlink')),
    async f => { await fs.unlink(f.observer.path); await fs.symlink(f.actual, f.observer.path); }]) {
    const f = await files(t), p = processFixture(); await mutation(f);
    await assert.rejects(p.resolve({ observer: f.observer, launchInputs: f.input }), coded('SOURCE_READBACK'));
    assert.equal(p.calls.length, 0);
  }
});

test('source readback after zero exit detects wrapper and observer mutation', async t => {
  for (const which of ['actual', 'observer']) {
    const f = await files(t), p = processFixture(), pending = p.resolve({ observer: f.observer, launchInputs: f.input });
    const refusal = assert.rejects(pending, coded('SOURCE_READBACK'));
    await p.started; await flush();
    await fs.writeFile(which === 'actual' ? f.actual : f.observer.path, 'changed');
    p.child.stdout.write(raw(argvFor(f.input))); p.child.finish(); await refusal;
  }
  const f = await files(t), p = processFixture(), pending = p.resolve({ observer: f.observer, launchInputs: f.input });
  const refusal = assert.rejects(pending, error => coded('OBSERVER_EXIT')(error) && error.sourceReadback === 'failed');
  await p.started; await flush(); await fs.writeFile(f.actual, 'changed'); p.child.finish(1, null); await refusal;
});

test('live stdout plus stderr cap terminates only the owned child before EOF', async t => {
  const f = await files(t), p = processFixture(), pending = p.resolve({ observer: f.observer, launchInputs: f.input });
  const refusal = assert.rejects(pending, error => coded('OBSERVER_OUTPUT_BOUND')(error) && error.cleanup.processExitObserved);
  await p.started; await flush();
  p.child.stderr.write(Buffer.alloc(1024 * 1024)); p.child.stdout.write(Buffer.from('x'));
  assert.deepEqual(p.child.kills, ['SIGTERM']); p.clock.advance(500);
  assert.deepEqual(p.child.kills, ['SIGTERM', 'SIGKILL']);
  p.child.finish(null, 'SIGKILL'); await refusal; assert.equal(p.clock.timers.size, 0);
});

test('deadline and unproved child cleanup expire within fixed owned-child bounds', async t => {
  const f = await files(t), p = processFixture(), pending = p.resolve({ observer: f.observer, launchInputs: f.input });
  const refusal = assert.rejects(pending, error => coded('OBSERVER_DEADLINE')(error)
    && error.cleanup.boundedCleanupExpired && !error.cleanup.processExitObserved);
  await p.started; await flush();
  p.clock.advance(9999); assert.deepEqual(p.child.kills, []);
  p.clock.advance(1); assert.deepEqual(p.child.kills, ['SIGTERM']);
  p.clock.advance(500); assert.deepEqual(p.child.kills, ['SIGTERM', 'SIGKILL']);
  p.clock.advance(500); await refusal; assert.equal(p.clock.timers.size, 0);
});

test('EOF without exit and zero exit without EOF cannot create a result', async t => {
  for (const proof of ['exit-only', 'EOF-only']) {
    const f = await files(t), p = processFixture(), pending = p.resolve({ observer: f.observer, launchInputs: f.input });
    const refusal = assert.rejects(pending, coded('OBSERVER_DEADLINE'));
    await p.started; await flush(); p.child.stdout.write(raw(argvFor(f.input)));
    if (proof === 'exit-only') p.child.emit('exit', 0, null);
    else { p.child.stdout.end(); p.child.stderr.end(); await flush(); }
    p.clock.advance(11000); await refusal;
  }
});

test('spawn throw/error, nonzero/signal exits and stream close are coded refusals', async t => {
  for (const mode of ['throw', 'error', 'nonzero', 'signal', 'close']) {
    const f = await files(t), p = processFixture({ throwing: mode === 'throw', noSpawn: mode === 'error', noPid: mode === 'error' });
    const pending = p.resolve({ observer: f.observer, launchInputs: f.input });
    const refusal = assert.rejects(pending, error => error instanceof binding.LaunchBindingError && !error.message.includes('private'));
    await p.started; await flush();
    if (mode === 'error') p.child.emit('error', new Error('private failure detail'));
    if (mode === 'nonzero') p.child.finish(1, null);
    if (mode === 'signal') p.child.finish(null, 'SIGTERM');
    if (mode === 'close') { p.child.stdout.destroy(); await flush(); p.child.finish(null, 'SIGTERM'); }
    p.clock.advance(11000); await refusal;
  }
});

test('saved handles, stale observer disposal and production route never run fake factories as native', async t => {
  const f = await files(t), p = processFixture();
  await assert.rejects(p.resolve({ observer: JSON.parse(JSON.stringify(f.observer)), launchInputs: f.input }), coded('FRESH_RESOLVER_HANDLES'));
  await assert.rejects(binding.resolveFreshLaunch({ observer: JSON.parse(JSON.stringify(f.observer)), launchInputs: f.input }), coded('FRESH_RESOLVER_HANDLES'));
  assert.equal(p.calls.length, 0);
  assert.throws(() => binding.createFixtureResolver({ spawn() {}, setTimeout() {}, clearTimeout() {}, fixtureMode: false }), coded('BINDING_SHAPE'));
  await binding.removeObserver(f.observer);
  await assert.rejects(p.resolve({ observer: f.observer, launchInputs: f.input }), coded('SOURCE_READBACK'));
  assert.equal(p.calls.length, 0);
});

async function promptlyRefuses(pending, fifo) {
  const outcome = pending.then(() => ({ code: 'accepted' }), error => ({ code: error.code }));
  let timer;
  const observed = await Promise.race([outcome.then(value => ({ settled: true, value })),
    new Promise(resolve => { timer = setTimeout(() => resolve({ settled: false }), 1000); })]);
  clearTimeout(timer);
  // Safety release for a regressed blocking read-only FIFO open, never used by
  // the fixed component. No data, subject process or resolver clock advance.
  let writerOpened = false;
  if (!observed.settled) {
    const writer = await fs.open(fifo, fsConstants.O_WRONLY | fsConstants.O_NONBLOCK);
    writerOpened = true; await writer.close(); await outcome;
  }
  assert.equal(observed.settled, true, 'readback must settle without a FIFO writer');
  assert.equal(writerOpened, false); assert.equal(observed.value.code, 'SOURCE_READBACK');
}

test('owned FIFO wrapper/observer replacements refuse without data or subject timer/spawn', async t => {
  for (const phase of ['before', 'after']) for (const source of ['wrapper', 'observer']) {
    const f = await files(t), p = processFixture();
    assert(process.env.P_GUI_FIFO_FIXTURES && path.isAbsolute(process.env.P_GUI_FIFO_FIXTURES), 'P_GUI_FIFO_FIXTURES must select owned fresh fixtures');
    const fixture = path.join(process.env.P_GUI_FIFO_FIXTURES, 'fifo-' + phase + '-' + source);
    assert.ok((await fs.lstat(fixture)).isFIFO(), 'run the owned FIFO fixture preparer first');
    const target = source === 'wrapper' ? f.actual : f.observer.path;
    let pending;
    if (phase === 'after') {
      pending = p.resolve({ observer: f.observer, launchInputs: f.input });
      await p.started; await flush();
    }
    await fs.unlink(target); await fs.rename(fixture, target);
    if (phase === 'before') pending = p.resolve({ observer: f.observer, launchInputs: f.input });
    else { p.child.stdout.write(raw(argvFor(f.input))); p.child.finish(); }
    await promptlyRefuses(pending, target);
    assert.equal(p.calls.length, phase === 'before' ? 0 : 1);
    assert.equal(p.clock.now, 0); if (phase === 'before') assert.equal(p.clock.next, 0);
    assert.equal(p.clock.timers.size, 0); assert.deepEqual(p.child.kills, []);
  }
});

test('staged-directory chmod refuses before/after observer and remove cannot unlink', async t => {
  for (const phase of ['before', 'after']) {
    const f = await files(t), p = processFixture();
    let pending;
    if (phase === 'after') { pending = p.resolve({ observer: f.observer, launchInputs: f.input }); await p.started; await flush(); }
    await fs.chmod(f.stage, 0o777);
    if (phase === 'before') pending = p.resolve({ observer: f.observer, launchInputs: f.input });
    const refusal = assert.rejects(pending, coded('SOURCE_READBACK'));
    if (phase === 'after') { p.child.stdout.write(raw(argvFor(f.input))); p.child.finish(); }
    await refusal;
    assert.equal(p.calls.length, phase === 'before' ? 0 : 1); assert.equal(p.clock.timers.size, 0);
    await assert.rejects(binding.removeObserver(f.observer), coded('OBSERVER_STAGING_DIRECTORY'));
    assert.ok((await fs.lstat(f.observer.path)).isFile());
  }
});

test('directory replacement preserving observer inode and source-boundary retarget refuse', async t => {
  for (const phase of ['before', 'after']) for (const kind of ['replace', 'symlink', 'source-root']) {
    const f = await files(t), p = processFixture();
    let pending;
    if (phase === 'after') { pending = p.resolve({ observer: f.observer, launchInputs: f.input }); await p.started; await flush(); }
    if (kind === 'source-root') {
      await fs.rename(f.sourceRoot, f.sourceRoot + '-old'); await fs.mkdir(f.sourceRoot, { mode: 0o700 });
    } else {
      const originalInode = (await fs.lstat(f.observer.path)).ino, old = f.stage + '-old';
      await fs.rename(f.stage, old);
      if (kind === 'symlink') await fs.symlink(old, f.stage);
      else { await fs.mkdir(f.stage, { mode: 0o700 }); await fs.rename(path.join(old, path.basename(f.observer.path)), f.observer.path); }
      assert.equal((await fs.stat(f.observer.path)).ino, originalInode);
    }
    if (phase === 'before') pending = p.resolve({ observer: f.observer, launchInputs: f.input });
    const refusal = assert.rejects(pending, coded('SOURCE_READBACK'));
    if (phase === 'after') { p.child.stdout.write(raw(argvFor(f.input))); p.child.finish(); }
    await refusal; assert.equal(p.calls.length, phase === 'before' ? 0 : 1); assert.equal(p.clock.timers.size, 0);
  }
});

test('directory timestamps bind only observer subdir; external app receipts remain compatible', async t => {
  const f = await files(t), p = processFixture();
  await fs.writeFile(path.join(f.directory, 'app-receipt.json'), '{}');
  await fs.writeFile(path.join(f.cwd, 'app-observation.json'), '{}');
  const pending = p.resolve({ observer: f.observer, launchInputs: f.input });
  await p.started; await flush(); p.child.stdout.write(raw(argvFor(f.input))); p.child.finish();
  assert.ok(binding.isFreshLaunchBinding(await pending, f.input));
  await binding.removeObserver(f.observer);
  assert.equal(await fs.readFile(path.join(f.directory, 'app-receipt.json'), 'utf8'), '{}');
  const changed = await files(t), refused = processFixture();
  await fs.writeFile(path.join(changed.stage, 'unexpected-entry'), 'directory drift');
  await assert.rejects(refused.resolve({ observer: changed.observer, launchInputs: changed.input }), coded('SOURCE_READBACK'));
  assert.equal(refused.calls.length, 0); assert.equal(refused.clock.timers.size, 0);
});

test('initial staged-handle stat failure closes its fd and preserves an unproved replacement', async t => {
  const f = await files(t), probe = await fs.open(f.actual, 'r'), prototype = Object.getPrototypeOf(probe);
  await probe.close();
  const original = prototype.stat, names = new Set(await fs.readdir(f.stage));
  let injected = false, failedDescriptor, replacement;
  prototype.stat = async function (...args) {
    const info = await original.apply(this, args);
    if (!injected && info.isFile() && info.size === 0) {
      injected = true; failedDescriptor = this.fd;
      const added = (await fs.readdir(f.stage)).filter(name => !names.has(name));
      assert.equal(added.length, 1); replacement = path.join(f.stage, added[0]);
      await fs.unlink(replacement); await fs.writeFile(replacement, 'unproved replacement', { mode: 0o600 });
      throw new Error('inert initial stat failure');
    }
    return info;
  };
  try {
    await assert.rejects(binding.stageObserver(f.authentication, { directory: f.stage, wrapperPath: f.wrapperPath,
      expectedResolvedWrapperPath: f.actual, authenticatedSourceRoot: f.sourceRoot }), coded('OBSERVER_STAGING_IO'));
    assert.ok(injected); assert.throws(() => fstatSync(failedDescriptor), error => error.code === 'EBADF');
  } finally { prototype.stat = original; }
  assert.equal(await fs.readFile(replacement, 'utf8'), 'unproved replacement');
});
