# ArchARM key-free native runtime/SDK probe — PROPOSAL, NOT ADMITTED

Status: v2 correction prepared for review only. One prior v1 native diagnostic
run failed; this correction has not been run natively.
Pure callback validation is recorded separately and does not prove native acceptance. Adopting it, running it on hosted infrastructure, or relying on
it for any decision needs a separate owner decision. This source does not grant
or imply any authorization.

## Exact scope

The probe answers one question: on a native `ubuntu-24.04-arm` runner, can the
pinned ArchARM base rootfs plus exactly 139 pinned, signed packages (six roots:
`fakeroot`, `python`, `nodejs-lts-jod`, `gtk3`, `webkit2gtk-4.1`,
`xorg-server-xvfb`; 201,499,452 package bytes) be installed by pacman with
signature enforcement in an isolated container, then run a small set of SDK and
headless runtime checks as an unprivileged user?

In scope:

- Python 3.14.9 (a tool inside the container only, separate from the host
  observer Python): stdlib `json`, `hashlib`, `tarfile`, `lzma`, `tomllib`,
  `ctypes`.
- Node 22.23.4 version string plus `arm64`/`linux`.
- Running `fakeroot` natively.
- `makepkg` (nonroot) builds an inert `arch=('aarch64')` fixture with
  `PKGEXT=.pkg.tar.zst` and `SOURCE_DATE_EPOCH=1767225600`. The probe then checks
  the zstd magic, `.PKGINFO` `arch`/`builddate`, `pacman -Qip`/`-Qqp` parsing, and
  `repo-add` fixture metadata. All of this happens in container tmpfs and none of
  it is kept.
- Xvfb started and stopped by the probe's own script inside the container, with
  `DISPLAY=:99`. `ctypes` loads `libgtk-3.so.0` and calls
  `gtk_init_check(NULL, NULL)`, then loads `libwebkit2gtk-4.1.so.0` and checks
  that it reports version 2.54.2.

Out of scope, not exercised, and not implied:

- R, Q, any GUI product, or signing.
- Publication, image push, or package upload.
- Product package installation or any product runtime change.
- Full GUI application qualification. The Nebular/Burst native gates stay open:
  the result's `assertions` are all fixed to `false`.
- Optional upstream features that are missing because of signed `optdepends`
  (Python Tk, Enchant spell plugins, HEIF loader, gssdp GTK4 sniffer, `tiffgt`,
  `sensord`). The probe adds no packages to fix optional ELF tools.

## Inputs and pins (checked before any package is parsed or run)

- `PACKAGE-PINS.json` (new; content-bound by size and SHA-256) is validated as closed JSON:
  - Duplicate keys and NaN/Infinity are refused.
  - The key sets are exact. There are no command fields.
  - Per package: name, version and arch rules; `filename` equals
    `name-version-arch.pkg.tar.xz`; the URL is derived exactly from the
    `fl.us.mirror.archlinuxarm.org/aarch64/{core,extra,alarm}/` prefix with `:`
    encoded as `%3A`; size and SHA-256 of both the package and its detached
    signature.
  - Count equals 139, and the sum of package bytes equals `totalBytes`, which
    equals 201,499,452.
  - The root set and the tool versions match fixed constants.
  - The exact committed pin file is 78,585 bytes, SHA-256
    `53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987`. The controller refuses other pin bytes and
    requires the result's `packagePinsSha256` to equal this value.
  - Caps: 64 MiB per package, 4 KiB per signature, 256 MiB aggregate, 1 MiB pin
    file, 16 KiB result.
- `ROOTFS-PIN.json` and the public certificate come from the existing base probe
  and are unchanged. The rootfs is pinned at 829,367,415 bytes with SHA-256
  `42a4ee…b319`. The certificate is pinned at 3,857 bytes with SHA-256
  `4e4202…b5f9`. Signer and primary key: `68B3537F39A313B3E574D06777193F152BDBE6A6`.
- Inputs from the run context are limited to the GitHub run ID, `run_attempt == 1`,
  and the 40-hex source SHA. They are passed as argv through `env:`, never
  interpolated into a shell script.

## Download and signature policy

- Bounded HTTPS only. There is no proxy, and redirects are refused (the base
  helper's `NoRedirect`). Each download needs exactly HTTP 200 with
  `geturl() == url` and an exact `Content-Length`, and must finish within a
  per-file and an aggregate deadline. The pinned SHA-256 is then checked with the
  base helper's `check_file`.
- A mirror rotation, a mutable "latest" name changing, or any unknown failure is
  a fixed refusal. Nothing is retried and no pin is refreshed. Note that the
  rootfs URL is the mutable `ArchLinuxARM-aarch64-latest.tar.gz`; if the mirror
  has moved on, this probe fails with `INPUT_SIZE`/`INPUT_HASH` by design.
- Files go into a fresh workspace owned by this run. Package paths are numeric
  (`NNN.pkg.tar.xz` plus `NNN.pkg.tar.xz.sig`) and never use mirror file names.
- Host `gpgv` uses only the pinned public certificate, a fresh empty home
  (`common.conf` only), and no agent or private key. For the rootfs and every
  package it requires:
  - exactly one `GOODSIG` and one `VALIDSIG`;
  - no `BADSIG`/`ERRSIG`/`EXPKEYSIG`/`REVKEYSIG`/`NO_PUBKEY` and similar;
  - signer = primary = pinned fingerprint;
  - signature version 4, pubkey algorithm RSA (1), hash SHA-256 (8) or
    SHA-512 (10), and class `00`.

  The rootfs headers are then inspected with the base helper's `inspect_members`.
  Nothing is extracted on the host.

## Container design

1. **Base image.** `docker import --platform linux/arm64` of the authenticated
   rootfs into a unique tag
   `tf-archarm-runtime-probe-base:r<run>-a1-<sha12>`. Absence of every owned
   tag and name is checked first, so existing references are never overwritten.
2. **Installer container** (root, `docker create` then readback, then
   `start --attach`):
   - Created with `--network none` and `--ipc none`, `--cap-drop ALL`, and only
     `CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETGID, SETUID, SETFCAP` added back.
   - `no-new-privileges`, pids/memory/swap/CPU bounds, `--log-driver none`,
     `--pull never`.
   - No privileged mode, host namespaces, devices, daemon socket or host security
     profile overrides.
   - A single read-only bind of this run's verified `inputs/` directory (the
     packages, signatures, public certificate and `pacman.conf`).
   - Every one of these settings is read back with `docker container inspect`
     and compared exactly before the container is started.
   - Installation state stays in the container layer. Nothing is installed on
     the host.
3. **Signature enforcement stays inside pacman.**
   - A fresh `GPGDir` (`/var/lib/tf-runtime-probe-gnupg`, starting with an empty
     `common.conf`).
   - `gpg --no-options --no-autostart --batch --import` of the exact public
     certificate, then `--import-ownertrust` of the literal public fingerprint.
     The probe checks for exactly one `pub`, validity `u`, and the expected
     fingerprint.
   - Never used: key generation, `--skipinteg`, `SigLevel=Never`, `--nodeps`,
     `--assume-installed`, `--overwrite`, `--noscriptlet`.
   - The config has `LocalFileSigLevel = Required`, `Architecture = aarch64`, and
     no repositories.
   - `pacman -U --noconfirm` runs over all 139 local paths with `.sig` files
     alongside. With no network, no download is possible.
   - The installer also confirms that no base package changed (`comm -23` is
     empty), that exactly 139 packages were added, and that all roots are
     present.
4. **Commit.** The stopped, successful installer is committed to a unique local
   derived tag `tf-archarm-runtime-probe-sdk:r<run>-a1-<sha12>`. It is never
   pushed, saved or exported.
5. **Runtime container:**
   - `--user 65534:65534`, `--read-only`, `--tmpfs /tmp` (`noexec,nosuid,nodev`,
     256 MiB), `--network none`, `--ipc none`.
   - `--cap-drop ALL` with no additions, `no-new-privileges`, the same resource
     bounds, and no host mounts or credentials.
   - These settings are read back the same way. The script itself checks uid/gid,
     that all capability sets are zero, `NoNewPrivs: 1`, a read-only root, `/tmp`
     on tmpfs, and that `lo` is the only interface.

The in-container scripts are fixed source constants. Only fixed `TFI <stage>` /
`TFR <stage>` tokens and one optional closed `fail <label>` token reach stdout;
all tool output goes to `/dev/null` or stays in container files. The controller
refuses any other output.

## Hooks and protected public package state

- The pacman hooks are expected to create these in the **new image only**:
  - `gschemas.compiled`
  - gdk-pixbuf `loaders.cache`, only when external loader modules are installed
  - GTK3 `immodules.cache`
  - `mime.cache`
  - hicolor `icon-theme.cache`
  - fontconfig caches

  The installer checks presence, not freshness. The pinned base and all 139
  packages contain no external gdk-pixbuf loader modules, so their path-triggered
  cache hook does not run. In that case the installer requires the cache to be
  absent; with external modules it requires a nonempty cache. The aggregate
  flag is `hookStateMatchesInputs`.

  Each of the six checks
  has a fixed refusal label (`hooks_schemas`, `hooks_pixbuf`, `hooks_immodules`,
  `hooks_mime`, `hooks_icons`, `hooks_fonts`); failure still stops before commit.
- The GStreamer `.INSTALL` script applies `cap_net_bind_service,cap_net_admin=ep`
  to `usr/lib/gstreamer-1.0/gst-ptp-helper`. The
  `ptpHelperFileCapsSetInInstaller` flag means the xattr is present in the
  installer layer before commit; it is not re-checked in the committed image.
  The runtime container is always nonroot with
  `--cap-drop ALL` and `no-new-privileges`, so they cannot be gained there, and no
  extra runtime capabilities are granted.
- The base rootfs package database, the new package metadata and cache, the dconf
  database placeholder, and Perl Compress/Raw public source members are used or
  created only by pacman inside the isolated container and the fresh image.
  Neither the controller nor any agent reads database contents. No repository
  database content (including the `repo-add` fixture) is kept or uploaded.

## Result (artifact) policy

The artifact is the closed `result.json` only, kept for 7 days.

The schema is `tf.archarm-key-free-runtime-probe.v2`. Compared with v1, the
aggregate hook flag is now `hookStateMatchesInputs`, and the six distinct hook
refusals replace the generic `INSTALL_HOOKS`. Original v1 results remain tied to
their original source and are not accepted by the v2 validator.

It contains:

- source SHA, run ID and attempt;
- rootfs, rootfs-pin, package-pin and public-key digests, plus the fingerprint;
- counts (pinned, downloaded, signatures verified);
- fixed booleans for native host/engine, signatures, inputs, import, installer
  readback and stages, commit, runtime readback and stages;
- fixed-false assertions (no signing secrets, no publication authority, no
  product or full GUI qualification, native gates not closed);
- `cleanupComplete`;
- on failure, one closed refusal label.

It never contains raw tool output, host paths, PIDs, package metadata bodies,
logs, archives, images, SDKs or source bundles.

## Runner and temporary data policy

- Disposable GitHub-hosted `ubuntu-24.04-arm` only. Runs need manual dispatch,
  on `main`, attempt 1. Permissions are `contents: read`; there is no
  environment and there are no secrets.
- The checkout uses `persist-credentials: false`. The job timeout is 90 minutes,
  which is a proposed new policy.
- Docker and GPG get fresh `HOME`/`DOCKER_CONFIG`/`GNUPGHOME` directories inside
  the work root, so no state from the owner or runner leaks in.
- Approximate disk use: 829 MB rootfs, 201 MB packages, the imported image, the
  installed layer, and the committed image.

## Ephemeral lifetime and cleanup

- **Removal order:** runtime container, installer container, derived tag, base
  tag.
- **Identity checks:** a container is removed only after its name resolves to
  the recorded 64-hex ID with the exact owned labels. It is stopped with
  `docker container stop --time 10` if it is still running, then removed by ID.
  An image is removed only after its tag resolves to the recorded `sha256:` ID,
  using `docker image rm --no-prune <tag>`.
- **Absence readback:** after removal the probe confirms the name or tag and the
  ID are both gone. Presence accepts Docker's indented or compact JSON only as
  one object in an array. Absence requires exit status 1 and an empty array;
  malformed, ambiguous or inconsistent readbacks stop cleanup.
  This retains the existing CLI absence convention: an exit-1 empty array does
  not independently distinguish a missing object from every daemon lookup
  error. This probe does not establish a stronger absence guarantee.
- **Never used:** `-f`/`--force`, `prune`, or removal by guessed identity.
- **Workspace:** the work root is removed in two phases. A closed layout scan runs
  first; any unexpected entry aborts deletion. The base helper's
  `remove_fresh_docker_home` handles the Docker client directory.
- **On any doubt:** if ownership or cleanup can't be verified, the probe stops
  cleaning, leaves everything in place for disposable VM teardown, and reports
  `cleanupComplete: false` with a failing status.

## Rollback

Delete exactly these new source files:

- `tools/verification/archarm_runtime_probe/archarm_runtime_probe.py`
- `tools/verification/archarm_runtime_probe/README.md`
- `tests/test_archarm_runtime_probe.py`
- `.github/workflows/probe-current-archarm-runtime.yml`

`PACKAGE-PINS.json` is a fifth new public source path and must also be removed
from the maintained projection on source rollback. Restore both maintained copies,
rerun the public projection generator, and confirm the root equals the recorded
pre-adoption root
`874e6dd07b358f7aa54b37e2378df0abca85fae5fd7581d10bc48fbfb96f42e4`.
The regenerated binding must no longer name any of the five paths. Restore the
public projection through the established review route; do not rewrite history.
The existing base probe files are unchanged. Any runtime resources are this run's own disposable containers,
tags and work root, removed as described above or destroyed with the hosted VM.
Nothing is published, so there is nothing external to roll back.

## Relation to native product qualification

A passing result would show only that pacman can install this pinned package set
with signature enforcement, and that the listed SDK and headless runtime checks
work natively in containers. It does not qualify any product binary, GUI
behaviour, packaging or signing pipeline, or distribution path. Those stay
separate, open gates.

## Pure tests

`tests/test_archarm_runtime_probe.py` uses fake command callbacks and synthetic
files only. It covers:

- pin closure, including the real pin files;
- context and path gates;
- gpgv status parsing;
- downloads: wrong URL, redirect, status, length, hash, timeout;
- Docker argv and inspect readback;
- token parsing;
- full and failing flows: wrong host or engine, name collision, mirror rotation,
  bad signatures, readback mismatch, chroot denial, timeout, cleanup identity and
  workspace preservation.

The tests never run Docker, GPG, pacman or any native code. Passing them does not
show native behaviour.

## Reconciled implementation assumptions

The repository condition and action pins now match the qualified base workflow.
The signed package's upstream pacman version 54d9411 explicitly bypasses chroot
when RootDir is /; SYS_CHROOT is not added. The installed binary's behavior remains
a native check. File capability metadata is set with SETFCAP; NET_ADMIN and
NET_BIND_SERVICE are not granted to either container.

The 90-minute workflow is the outer lifetime limit. Individual stage timeouts can
sum to more than that limit. If the workflow is killed before verified cleanup,
disposable runner teardown is the final custody endpoint and no passing runtime
admission may be inferred. There is no automatic retry.
