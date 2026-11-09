"""PROPOSED, NOT ADMITTED key-free native ArchARM runtime/SDK probe controller.

Source-preparation only. Adoption, hosted execution and any change of policy
require explicit owner review. This controller never signs, publishes, pushes
images, uploads packages, or runs R/Q/GUI product code. It proves nothing about
full native product qualification; Nebular/Burst native gates remain open.

Reuses the existing base helper's pure ``inspect_members``, ``check_file``,
``download``, ``command`` and ``remove_fresh_docker_home`` by importing the exact
local module file. The base helper's ``native_probe`` and ``main`` are never
called and the base helper is never modified.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
BASE_HELPER_PATH = HERE.parent / "archarm_base_probe" / "archarm_base_probe.py"
BASE_MODULE_NAME = "archarm_base_probe"
BASE_CONTRACT = ("Refusal", "require", "NoRedirect", "inspect_members", "check_file",
                 "download", "command", "remove_fresh_docker_home")
PACKAGE_PINS_PATH = HERE / "PACKAGE-PINS.json"
PACKAGE_PINS_BYTES = 78588
PACKAGE_PINS_SHA256 = "a0896233d98b32fde260c6139321dfc64be4efa345585ee16bdbdd4ffdd2f207"
ROOTFS_PIN_PATH = BASE_HELPER_PATH.parent / "ROOTFS-PIN.json"
CERTIFICATE_PATH = BASE_HELPER_PATH.parent / "archlinuxarm-builder-public.gpg"


def load_base_helper(path=BASE_HELPER_PATH):
    """Import the exact local base helper file and register it in sys.modules."""
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
        raise RuntimeError("BASE_HELPER_FILE")
    existing = sys.modules.get(BASE_MODULE_NAME)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if not existing_file or Path(existing_file).resolve() != Path(path).resolve():
            raise RuntimeError("BASE_HELPER_IDENTITY")
        module = existing
    else:
        spec = importlib.util.spec_from_file_location(BASE_MODULE_NAME, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("BASE_HELPER_SPEC")
        module = importlib.util.module_from_spec(spec)
        sys.modules[BASE_MODULE_NAME] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(BASE_MODULE_NAME, None)
            raise
    for attribute in BASE_CONTRACT:
        if not callable(getattr(module, attribute, None)):
            raise RuntimeError("BASE_HELPER_CONTRACT")
    return module


BASE = load_base_helper()
Refusal = BASE.Refusal
require = BASE.require

# --------------------------------------------------------------------------
# Fixed proposal constants (not inputs).
# --------------------------------------------------------------------------
RESULT_SCHEMA = "tf.archarm-key-free-runtime-probe.v2"
PACKAGE_PIN_SCHEMA = "tf.archarm-runtime-package-pins.v1"
FINGERPRINT = "68B3537F39A313B3E574D06777193F152BDBE6A6"
ROOT_NAMES = ("fakeroot", "python", "nodejs-lts-jod", "gtk3", "webkit2gtk-4.1", "xorg-server-xvfb")
VERSION_PINS = {"python": "3.14.9-1", "nodejs-lts-jod": "22.23.4-1", "webkit2gtk-4.1": "2.54.2-1"}
TOOL_PYTHON_VERSION = "3.14.9"
TOOL_NODE_VERSION = "22.23.4"
PACKAGE_URL_PREFIX = "https://fl.us.mirror.archlinuxarm.org/aarch64/"
PACKAGE_REPOS = ("core", "extra", "alarm")
PACKAGE_URL_RE = re.compile(r"https://fl\.us\.mirror\.archlinuxarm\.org/aarch64/"
                            r"(?:core|extra|alarm)/[A-Za-z0-9@._+%~-]+\.pkg\.tar\.xz(?:\.sig)?")
NAME_RE = re.compile(r"[a-z0-9@_+][a-z0-9@._+-]{0,99}")
VERSION_RE = re.compile(r"(?:[0-9]{1,6}:)?[A-Za-z0-9._+~]{1,80}-[0-9]{1,6}(?:\.[0-9]{1,6})?")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
RUN_ID_RE = re.compile(r"[1-9][0-9]{0,19}")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
PATH_RE = re.compile(r"/[A-Za-z0-9._/-]{1,240}")

MAX_PACKAGES = 256
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
MAX_PACKAGE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PIN_FILE_BYTES = 1024 * 1024
MAX_CERTIFICATE_BYTES = 65536
MAX_RESULT_BYTES = 16 * 1024
PACKAGE_DOWNLOAD_SECONDS = 1800
PER_FILE_SECONDS = 300
CONNECT_TIMEOUT_SECONDS = 30

# Real expectations; tests substitute a synthetic dict of the same shape.
REAL_EXPECT = {
    "packageCount": 139,
    "packageBytes": 201488096,
    "rootfsUrl": "https://fl.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz",
    "rootfsBytes": 829367415,
    "rootfsSha256": "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
    "publicKeyBytes": 3857,
    "publicKeySha256": "4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9",
}
EXPECT_KEYS = frozenset(REAL_EXPECT)

# Audited pinned-signature closure: RSA (1) with SHA-256 (8) or SHA-512 (10).
# Every download is rechecked; SHA-1/MD5 and every other value are refused.
ALLOWED_PUBKEY_ALGOS = frozenset({"1"})
ALLOWED_HASH_ALGOS = frozenset({"8", "10"})
BAD_GPG_STATUS = frozenset({"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG",
                            "NO_PUBKEY", "NODATA", "BADARMOR", "UNEXPECTED", "FAILURE",
                            "ERROR", "BADMDC", "DECRYPTION_FAILED"})

# Closed installer capability list after --cap-drop ALL (reviewer must assess).
CAP_ADD = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID", "SETFCAP")
INPUTS_TARGET = "/run/tf-inputs"
CERT_NAME = "archlinuxarm-builder-public.gpg"
HOSTNAME = "tf-runtime-probe"
LABEL_PREFIX = "tf.archarm-runtime-probe."
INSTALLER_MEMORY = 3221225472
RUNTIME_MEMORY = 2147483648
CPUS = "2"
NANO_CPUS = 2000000000
PIDS_LIMIT = 256
TMPFS_OPTIONS = "rw,nosuid,nodev,noexec,size=268435456,mode=1777"
INSTALLER_ENV = ("PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root")
RUNTIME_ENV = ("PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/tmp/home", "TMPDIR=/tmp")
NNP_FORMS = frozenset({"no-new-privileges", "no-new-privileges=true", "no-new-privileges:true"})
PRESENCE_LIMIT = 262144
INSPECT_LIMIT = 65536
IMAGE_FORMAT = "{{.Id}}|{{.Os}}|{{.Architecture}}"
# Field-selective template: no PID or other State fields are requested.
CONTAINER_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
    '"ConfigImage":{{json .Config.Image}},"User":{{json .Config.User}},'
    '"Env":{{json .Config.Env}},"Labels":{{json .Config.Labels}},'
    '"Cmd":{{json .Config.Cmd}},"Entrypoint":{{json .Config.Entrypoint}},'
    '"WorkingDir":{{json .Config.WorkingDir}},"Hostname":{{json .Config.Hostname}},'
    '"Mounts":{{json .Mounts}},"Host":{{json .HostConfig}},'
    '"Status":{{json .State.Status}},"Running":{{json .State.Running}},'
    '"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}}}'
)

# Public pacman configuration: no repositories, signatures required.
PACMAN_CONF = """[options]
RootDir = /
DBPath = /var/lib/pacman/
CacheDir = /var/cache/pacman/pkg/
LogFile = /var/log/pacman.log
GPGDir = /var/lib/tf-runtime-probe-gnupg/
HookDir = /etc/pacman.d/hooks/
Architecture = aarch64
SigLevel = Required DatabaseRequired
LocalFileSigLevel = Required
RemoteFileSigLevel = Required
"""

# Root installer, network none, closed capabilities, read-only input mount.
# Only fixed "TFI <stage>" / "TFI fail <label>" tokens reach stdout (fd 3).
INSTALL_SCRIPT = r'''set -euo pipefail
exec 3>&1 >/dev/null 2>&1
umask 022
export LANG=C LC_ALL=C PATH=/usr/bin:/bin HOME=/root
I=/run/tf-inputs
C=/run/tf-inputs/pacman.conf
K=/run/tf-inputs/key/archlinuxarm-builder-public.gpg
G=/var/lib/tf-runtime-probe-gnupg
T=/var/tmp/tf-runtime-probe-install
FPR=68B3537F39A313B3E574D06777193F152BDBE6A6
mark() { printf 'TFI %s\n' "$1" >&3; }
fail() { printf 'TFI fail %s\n' "$1" >&3; exit 1; }
test "$(id -u):$(id -g)" = 0:0 || fail identity
test "$(uname -m)" = aarch64 || fail identity
test ! -e "$G" || fail inputs
test ! -e "$T" || fail inputs
test -f "$C" || fail inputs
test -f "$K" || fail inputs
set -- "$I"/pkg/[0-9][0-9][0-9].pkg.tar.xz
test "$#" -eq 139 || fail inputs
for p in "$@"; do
  test -f "$p" || fail inputs
  test -f "$p.sig" || fail inputs
done
test "$(ls -A "$I/pkg" | wc -l)" -eq 278 || fail inputs
mark inputs
mkdir -m 0700 "$G" "$T"
: > "$G/common.conf"
gpg --no-options --no-autostart --batch --homedir "$G" --import "$K" || fail keyring
printf '%s:6:\n' "$FPR" | gpg --no-options --no-autostart --batch --homedir "$G" --import-ownertrust || fail keyring
gpg --no-options --no-autostart --batch --homedir "$G" --check-trustdb || fail keyring
gpg --no-options --no-autostart --batch --homedir "$G" --with-colons --list-keys > "$T/keys" || fail keyring
test "$(grep -c '^pub:' "$T/keys")" -eq 1 || fail keyring
test "$(awk -F: '$1 == "pub" { print $2 }' "$T/keys")" = u || fail keyring
test "$(awk -F: '$1 == "fpr" { print $10; exit }' "$T/keys")" = "$FPR" || fail keyring
mark keyring
pacman --config "$C" -Q | LC_ALL=C sort > "$T/before" || fail pacman_query
rc=0
pacman --config "$C" -U --noconfirm --noprogressbar "$@" > "$T/pacman.out" 2>&1 || rc=$?
if grep -q 'could not change the root directory' "$T/pacman.out"; then fail chroot; fi
test "$rc" -eq 0 || fail pacman_exit
if grep -Eq '^error:|command failed to execute correctly' "$T/pacman.out"; then fail pacman_error; fi
mark pacman
pacman --config "$C" -Q | LC_ALL=C sort > "$T/after" || fail pacman_query
test -z "$(LC_ALL=C comm -23 "$T/before" "$T/after")" || fail base_changed
test "$(LC_ALL=C comm -13 "$T/before" "$T/after" | wc -l)" -eq 139 || fail delta
pacman --config "$C" -Q fakeroot python nodejs-lts-jod gtk3 webkit2gtk-4.1 xorg-server-xvfb || fail delta
mark delta
test -s /usr/share/glib-2.0/schemas/gschemas.compiled || fail hooks_schemas
if compgen -G '/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders/*.so' >/dev/null; then
  test -s /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache || fail hooks_pixbuf
else
  test ! -e /usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache || fail hooks_pixbuf
fi
test -s /usr/lib/gtk-3.0/3.0.0/immodules.cache || fail hooks_immodules
test -s /usr/share/mime/mime.cache || fail hooks_mime
test -s /usr/share/icons/hicolor/icon-theme.cache || fail hooks_icons
test -n "$(ls -A /var/cache/fontconfig)" || fail hooks_fonts
mark hooks
case "$(getcap /usr/lib/gstreamer-1.0/gst-ptp-helper)" in
  *' cap_net_bind_service,cap_net_admin=ep') ;;
  *) fail ptpcaps ;;
esac
mark ptpcaps
rm -f -- "$T/keys" "$T/before" "$T/after" "$T/pacman.out"
rmdir -- "$T"
mark done
'''

# Nonroot runtime test, read-only root, tmpfs /tmp only, no capabilities.
RUNTIME_SCRIPT = r'''set -euo pipefail
exec 3>&1 >/dev/null 2>&1
umask 077
export LANG=C LC_ALL=C PATH=/usr/bin:/bin HOME=/tmp/home TMPDIR=/tmp
mark() { printf 'TFR %s\n' "$1" >&3; }
fail() { printf 'TFR fail %s\n' "$1" >&3; exit 1; }
test "$(id -u):$(id -g)" = 65534:65534 || fail identity
for f in CapInh CapPrm CapEff CapBnd CapAmb; do
  grep -Eq "^$f:[[:space:]]+0+\$" /proc/self/status || fail caps
done
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status || fail caps
mark nocaps
test "$(awk '$2 == "/" { print $4 }' /proc/self/mounts | cut -d, -f1)" = ro || fail readonly
test "$(awk '$2 == "/tmp" { print $3 }' /proc/self/mounts)" = tmpfs || fail readonly
if touch /tf-runtime-probe-write-test; then fail readonly; fi
mark readonly
test "$(ls -A /sys/class/net)" = lo || fail network
mark network
mkdir -p -m 0700 /tmp/home /tmp/xdg /tmp/w
cd /tmp/w
python3 -I - <<'PYEOF' || fail python
import sys
import platform
def need(condition):
    if not condition:
        raise SystemExit(3)
need(sys.implementation.name == "cpython")
need(tuple(sys.version_info[:3]) == (3, 14, 9))
need(platform.machine() == "aarch64")
import io
import json
import hashlib
import tarfile
import lzma
import tomllib
import ctypes
need(json.loads(json.dumps({"a": [1, "b"]})) == {"a": [1, "b"]})
need(hashlib.sha256(b"").hexdigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
payload = b"tf-runtime-probe" * 64
need(lzma.decompress(lzma.compress(payload)) == payload)
need(tomllib.loads('a = 1\n[b]\nc = "d"\n') == {"a": 1, "b": {"c": "d"}})
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode="w") as archive:
    info = tarfile.TarInfo("inert.txt")
    info.size = len(payload)
    archive.addfile(info, io.BytesIO(payload))
buffer.seek(0)
with tarfile.open(fileobj=buffer, mode="r") as archive:
    need(archive.getnames() == ["inert.txt"])
    need(archive.extractfile("inert.txt").read() == payload)
need(ctypes.sizeof(ctypes.c_void_p) == 8)
libc = ctypes.CDLL(None)
libc.strlen.restype = ctypes.c_size_t
libc.strlen.argtypes = [ctypes.c_char_p]
need(libc.strlen(b"inert") == 5)
PYEOF
mark python
test "$(node -e 'process.stdout.write([process.version, process.arch, process.platform].join(" "))')" = "v22.23.4 arm64 linux" || fail node
mark node
test "$(fakeroot -- /usr/bin/id -u)" = 0 || fail fakeroot
: > /tmp/w/fakeroot-probe
fakeroot -- /usr/bin/bash -c 'chown 0:0 /tmp/w/fakeroot-probe && test "$(stat -c %u /tmp/w/fakeroot-probe)" = 0' || fail fakeroot
test "$(stat -c %u /tmp/w/fakeroot-probe)" = 65534 || fail fakeroot
mark fakeroot
mkdir -m 0700 /tmp/w/fixture /tmp/w/out /tmp/w/src /tmp/w/build /tmp/w/logs
cat > /tmp/w/fixture/PKGBUILD <<'PKGEOF'
pkgname=tf-inert-fixture
pkgver=1.0.0
pkgrel=1
pkgdesc='Inert runtime probe fixture'
arch=('aarch64')
license=('0BSD')
options=('!strip' '!debug' '!lto' '!emptydirs')
package() {
  install -d -m 0755 "$pkgdir/usr/share/tf-inert-fixture"
  printf 'inert\n' > "$pkgdir/usr/share/tf-inert-fixture/marker"
}
PKGEOF
cd /tmp/w/fixture
PKGEXT=.pkg.tar.zst SOURCE_DATE_EPOCH=1767225600 PKGDEST=/tmp/w/out SRCDEST=/tmp/w/src BUILDDIR=/tmp/w/build LOGDEST=/tmp/w/logs makepkg --nosign --noconfirm --noprogressbar --nocolor || fail makepkg
P=/tmp/w/out/tf-inert-fixture-1.0.0-1-aarch64.pkg.tar.zst
test "$(ls -A /tmp/w/out)" = tf-inert-fixture-1.0.0-1-aarch64.pkg.tar.zst || fail makepkg
test -f "$P" || fail makepkg
mark makepkg
test "$(od -An -tx1 -N4 "$P" | tr -d ' \n')" = 28b52ffd || fail zstd
mark zstd
bsdtar -xOf "$P" .PKGINFO > /tmp/w/pkginfo || fail pkginfo
grep -qx 'pkgname = tf-inert-fixture' /tmp/w/pkginfo || fail pkginfo
grep -qx 'arch = aarch64' /tmp/w/pkginfo || fail pkginfo
grep -qx 'builddate = 1767225600' /tmp/w/pkginfo || fail pkginfo
mark pkginfo
pacman -Qip "$P" > /tmp/w/qip || fail pacman_parse
grep -Eqx 'Architecture +: aarch64' /tmp/w/qip || fail pacman_parse
test "$(pacman -Qqp "$P")" = tf-inert-fixture || fail pacman_parse
mark pacman_parse
mkdir -m 0700 /tmp/w/repo
repo-add -q /tmp/w/repo/tf-fixture.db.tar.zst "$P" || fail repo_add
bsdtar -tf /tmp/w/repo/tf-fixture.db.tar.zst > /tmp/w/repo-list || fail repo_add
grep -qx 'tf-inert-fixture-1.0.0-1/desc' /tmp/w/repo-list || fail repo_add
bsdtar -xOf /tmp/w/repo/tf-fixture.db.tar.zst tf-inert-fixture-1.0.0-1/desc > /tmp/w/repo-desc || fail repo_add
grep -qx aarch64 /tmp/w/repo-desc || fail repo_add
rm -rf -- /tmp/w/repo /tmp/w/repo-list /tmp/w/repo-desc
mark repo_add
export DISPLAY=:99 XDG_RUNTIME_DIR=/tmp/xdg NO_AT_BRIDGE=1 GSETTINGS_BACKEND=memory GDK_BACKEND=x11
Xvfb :99 -nolisten tcp -noreset -screen 0 1024x768x24 &
X=$!
n=0
until test -S /tmp/.X11-unix/X99; do
  kill -0 "$X" || fail xvfb
  n=$((n + 1))
  if test "$n" -gt 200; then fail xvfb; fi
  sleep 0.1
done
mark xvfb
python3 -I - <<'PYEOF' || fail gtk
import ctypes
gtk = ctypes.CDLL("libgtk-3.so.0")
gtk.gtk_init_check.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
gtk.gtk_init_check.restype = ctypes.c_int
raise SystemExit(0 if gtk.gtk_init_check(None, None) == 1 else 4)
PYEOF
mark gtk
python3 -I - <<'PYEOF' || fail webkit
import ctypes
webkit = ctypes.CDLL("libwebkit2gtk-4.1.so.0")
version = []
for symbol in ("webkit_get_major_version", "webkit_get_minor_version", "webkit_get_micro_version"):
    function = getattr(webkit, symbol)
    function.restype = ctypes.c_uint
    function.argtypes = []
    version.append(function())
raise SystemExit(0 if version == [2, 54, 2] else 5)
PYEOF
mark webkit
kill "$X"
wait "$X" || true
mark done
'''

INSTALLER_CMD = ("/usr/bin/bash", "-c", INSTALL_SCRIPT)
RUNTIME_CMD = ("/usr/bin/bash", "-c", RUNTIME_SCRIPT)

INSTALL_STAGES = ("inputs", "keyring", "pacman", "delta", "hooks", "ptpcaps", "done")
INSTALL_FAILURES = ("identity", "inputs", "keyring", "pacman_query", "chroot", "pacman_exit",
                    "pacman_error", "base_changed", "delta", "hooks_schemas",
                    "hooks_pixbuf", "hooks_immodules", "hooks_mime", "hooks_icons",
                    "hooks_fonts", "ptpcaps")
RUNTIME_STAGES = ("nocaps", "readonly", "network", "python", "node", "fakeroot", "makepkg",
                  "zstd", "pkginfo", "pacman_parse", "repo_add", "xvfb", "gtk", "webkit", "done")
RUNTIME_FAILURES = ("identity", "caps", "readonly", "network", "python", "node", "fakeroot",
                    "makepkg", "zstd", "pkginfo", "pacman_parse", "repo_add", "xvfb", "gtk",
                    "webkit")
INSTALL_FLAGS = {"inputs": "installerInputsVisible", "keyring": "publicKeyringReady",
                 "pacman": "pacmanSignedInstall", "delta": "packageDeltaExact",
                 "hooks": "hookStateMatchesInputs", "ptpcaps": "ptpHelperFileCapsSetInInstaller",
                 "done": "installerCompleted"}
RUNTIME_FLAGS = {"nocaps": "nonrootNoCapabilities", "readonly": "readonlyRootTmpfsOnly",
                 "network": "networkIsolated", "python": "python3149Stdlib",
                 "node": "node22Arm64", "fakeroot": "fakerootNative",
                 "makepkg": "makepkgFixture", "zstd": "zstdMagic",
                 "pkginfo": "pkginfoArchAarch64", "pacman_parse": "pacmanQueryParse",
                 "repo_add": "repoAddFixture", "xvfb": "xvfbOwnProcess",
                 "gtk": "gtkInitCheck", "webkit": "webkitVersion", "done": "runtimeCompleted"}
FLAG_KEYS = ("nativeArmHost", "nativeArmEngine", "rootfsSignatureVerified",
             "rootfsHeadersInspected", "packageSignaturesVerified", "inputsReverified",
             "baseImageImported", "installerHostConfigVerified",
             *INSTALL_FLAGS.values(), "derivedImageCommitted", "runtimeHostConfigVerified",
             *RUNTIME_FLAGS.values())
ASSERTION_KEYS = ("signingSecretsUsed", "publicationAuthority", "productQualification",
                  "fullGuiQualification", "nebularBurstNativeGatesClosed")
DIGEST_KEYS = ("rootfsSha256", "rootfsPinSha256", "packagePinsSha256", "publicKeySha256",
               "publicKeyFingerprint")
COUNT_KEYS = ("packagesPinned", "packageBytesPinned", "packagesDownloaded",
              "packageSignaturesVerified")
STAGES = ("context", "pins", "host", "workspace", "engine", "rootfs", "packages", "inputs",
          "import", "installer", "commit", "runtime", "complete")
RESULT_KEYS = frozenset({"schema", "status", "stage", "refusal", "sourceSha", "runId",
                         "runAttempt", "digests", "counts", "flags", "assertions",
                         "cleanupComplete"})
BASE_REFUSALS = ("INPUT_FILE", "INPUT_HASH", "INPUT_REDIRECT", "INPUT_URL", "INPUT_TRANSPORT",
                 "INPUT_SIZE", "INPUT_TIMEOUT", "MEMBER_NAME", "LINK_TARGET", "LINK_ESCAPE",
                 "EXCEPTION_PIN", "ARCHIVE_LIMIT", "DUPLICATE_MEMBER", "SPECIAL_MEMBER",
                 "MEMBER_SIZE", "LITERAL_ESCAPE", "ARCHIVE_INVENTORY", "SETID_INVENTORY",
                 "HARDLINK_TARGET", "COMMAND_TIMEOUT", "COMMAND_OUTPUT_LIMIT",
                 "DOCKER_HOME_CHANGED")
OWN_REFUSALS = ("CONTEXT_RUN_ID", "CONTEXT_RUN_ATTEMPT", "CONTEXT_SOURCE_SHA", "WORK_PATH",
                "RESULT_PATH", "PIN_FILE", "PIN_JSON", "PIN_SCHEMA", "PIN_PACKAGE", "PIN_URL",
                "PIN_COUNT", "PIN_BYTES", "PIN_ROOTS", "PIN_VERSION", "PIN_FINGERPRINT",
                "ROOTFS_PIN", "NATIVE_ARM_HOST", "FRESH_WORK_ROOT", "NATIVE_ARM_ENGINE",
                "OWNED_NAME_COLLISION", "DOCKER_READBACK", "INPUT_AGGREGATE", "INPUT_SET",
                "ROOTFS_SIGNATURE", "PACKAGE_SIGNATURE", "IMPORT_FAILED", "IMAGE_IDENTITY",
                "INSTALLER_CREATE", "INSTALLER_HOST_CONFIG", "INSTALL_OUTPUT",
                "INSTALL_INCOMPLETE", "INSTALL_STATE", "COMMIT_FAILED", "RUNTIME_CREATE",
                "RUNTIME_HOST_CONFIG", "RUNTIME_OUTPUT", "RUNTIME_INCOMPLETE",
                "RUNTIME_STATE", "WORKSPACE_CHANGED", "CLEANUP_INCOMPLETE",
                "INCOMPLETE_FLAGS", "RESULT_SCHEMA", "UNCLASSIFIED_PROBE_FAILURE")
REFUSALS = frozenset(BASE_REFUSALS + OWN_REFUSALS
                     + tuple("INSTALL_" + f.upper() for f in INSTALL_FAILURES)
                     + tuple("RUNTIME_" + f.upper() for f in RUNTIME_FAILURES))


def closed_label(text):
    return text if text in REFUSALS else "UNCLASSIFIED_PROBE_FAILURE"


# --------------------------------------------------------------------------
# Closed input validation.
# --------------------------------------------------------------------------
def _is_int(value):
    return type(value) is int


def read_bounded(path, limit):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        raise Refusal("PIN_FILE") from None
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "PIN_FILE")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) == info.st_size, "PIN_FILE")
    return data


def validate_package_pin_bytes(raw):
    require(isinstance(raw, bytes) and len(raw) == PACKAGE_PINS_BYTES
            and hashlib.sha256(raw).hexdigest() == PACKAGE_PINS_SHA256, "PIN_FILE")
    return raw


def load_json(raw):
    def pairs_hook(pairs):
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise Refusal("PIN_JSON")
        return dict(pairs)

    def reject_constant(_):
        raise Refusal("PIN_JSON")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_hook,
                          parse_constant=reject_constant)
    except Refusal:
        raise
    except (UnicodeDecodeError, ValueError):
        raise Refusal("PIN_JSON") from None


PACKAGE_TOP_KEYS = frozenset({"schema", "rootNames", "publicSigningFingerprint", "packages",
                              "packageCount", "totalBytes", "toolPythonVersion",
                              "toolNodeVersion", "networkDuringInstallOrProbe",
                              "noBasePackageUpgrades"})
PACKAGE_KEYS = frozenset({"name", "version", "architecture", "url", "filename", "bytes",
                          "sha256", "signatureBytes", "signatureSha256", "licenses"})


def _check_license_list(value):
    require(isinstance(value, list) and 1 <= len(value) <= 64, "PIN_PACKAGE")
    for item in value:
        require(isinstance(item, str) and 1 <= len(item) <= 256
                and all(ch.isprintable() for ch in item), "PIN_PACKAGE")


def validate_package_pins(doc, expect):
    require(isinstance(expect, dict) and set(expect) == EXPECT_KEYS, "PIN_SCHEMA")
    require(isinstance(doc, dict) and set(doc) == PACKAGE_TOP_KEYS, "PIN_SCHEMA")
    require(doc["schema"] == PACKAGE_PIN_SCHEMA, "PIN_SCHEMA")
    require(doc["rootNames"] == list(ROOT_NAMES), "PIN_ROOTS")
    require(doc["publicSigningFingerprint"] == FINGERPRINT, "PIN_FINGERPRINT")
    require(doc["toolPythonVersion"] == TOOL_PYTHON_VERSION
            and doc["toolNodeVersion"] == TOOL_NODE_VERSION, "PIN_VERSION")
    require(doc["networkDuringInstallOrProbe"] is False
            and doc["noBasePackageUpgrades"] is True, "PIN_SCHEMA")
    packages = doc["packages"]
    require(isinstance(packages, list) and 0 < len(packages) <= MAX_PACKAGES, "PIN_COUNT")
    require(_is_int(doc["packageCount"]) and doc["packageCount"] == len(packages)
            == expect["packageCount"], "PIN_COUNT")
    names, filenames, total = set(), set(), 0
    for record in packages:
        require(isinstance(record, dict) and set(record) == PACKAGE_KEYS, "PIN_PACKAGE")
        name, version, arch = record["name"], record["version"], record["architecture"]
        require(isinstance(name, str) and NAME_RE.fullmatch(name) is not None, "PIN_PACKAGE")
        require(isinstance(version, str) and VERSION_RE.fullmatch(version) is not None,
                "PIN_PACKAGE")
        require(arch in ("any", "aarch64"), "PIN_PACKAGE")
        require(name not in names, "PIN_PACKAGE")
        names.add(name)
        filename = record["filename"]
        require(filename == f"{name}-{version}-{arch}.pkg.tar.xz", "PIN_PACKAGE")
        require(filename.casefold() not in filenames, "PIN_PACKAGE")
        filenames.add(filename.casefold())
        url = record["url"]
        require(isinstance(url, str) and url.startswith(PACKAGE_URL_PREFIX)
                and PACKAGE_URL_RE.fullmatch(url) is not None, "PIN_URL")
        repo, _, encoded = url[len(PACKAGE_URL_PREFIX):].partition("/")
        require(repo in PACKAGE_REPOS and encoded == filename.replace(":", "%3A"), "PIN_URL")
        require(_is_int(record["bytes"]) and 0 < record["bytes"] <= MAX_PACKAGE_BYTES,
                "PIN_BYTES")
        require(_is_int(record["signatureBytes"])
                and 0 < record["signatureBytes"] <= MAX_SIGNATURE_BYTES, "PIN_BYTES")
        require(isinstance(record["sha256"], str) and HEX64_RE.fullmatch(record["sha256"])
                is not None, "PIN_PACKAGE")
        require(isinstance(record["signatureSha256"], str)
                and HEX64_RE.fullmatch(record["signatureSha256"]) is not None, "PIN_PACKAGE")
        _check_license_list(record["licenses"])
        if name in VERSION_PINS:
            require(version == VERSION_PINS[name], "PIN_VERSION")
        total += record["bytes"]
        require(total <= MAX_PACKAGE_TOTAL_BYTES, "PIN_BYTES")
    require(set(ROOT_NAMES) <= names, "PIN_ROOTS")
    require(_is_int(doc["totalBytes"]) and doc["totalBytes"] == total
            == expect["packageBytes"], "PIN_BYTES")
    return doc


ROOTFS_PIN_KEYS = frozenset({"schema", "rootfsUrl", "rootfsBytes", "rootfsSha256",
                             "signatureBytes", "signatureSha256", "publicKeySha256",
                             "publicKeyFingerprint", "members", "declaredBytes",
                             "literalEscapes", "setIdMembers", "rootDirectoryHeaders",
                             "literalEscapeLinks", "declaredBytesCorrection",
                             "publicKeyBytes"})


def validate_rootfs_pin(pin, expect):
    require(isinstance(pin, dict) and set(pin) == ROOTFS_PIN_KEYS, "ROOTFS_PIN")
    require(pin["rootfsUrl"] == expect["rootfsUrl"]
            and pin["rootfsBytes"] == expect["rootfsBytes"]
            and pin["rootfsSha256"] == expect["rootfsSha256"]
            and pin["publicKeyBytes"] == expect["publicKeyBytes"]
            and pin["publicKeySha256"] == expect["publicKeySha256"]
            and pin["publicKeyFingerprint"] == FINGERPRINT, "ROOTFS_PIN")
    require(_is_int(pin["signatureBytes"]) and 0 < pin["signatureBytes"] <= MAX_SIGNATURE_BYTES
            and isinstance(pin["signatureSha256"], str)
            and HEX64_RE.fullmatch(pin["signatureSha256"]) is not None, "ROOTFS_PIN")
    require(all(_is_int(pin[k]) and pin[k] >= 0
                for k in ("members", "declaredBytes", "rootDirectoryHeaders")), "ROOTFS_PIN")
    require(isinstance(pin["literalEscapes"], list) and len(pin["literalEscapes"]) == 3
            and isinstance(pin["setIdMembers"], list)
            and isinstance(pin["literalEscapeLinks"], list), "ROOTFS_PIN")
    return pin


def validate_context(run_id, run_attempt, source_sha):
    require(isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None,
            "CONTEXT_RUN_ID")
    require(run_attempt == "1", "CONTEXT_RUN_ATTEMPT")
    require(isinstance(source_sha, str) and SOURCE_SHA_RE.fullmatch(source_sha) is not None,
            "CONTEXT_SOURCE_SHA")
    return {"runId": run_id, "sourceSha": source_sha}


def _check_path_text(text, label):
    require(isinstance(text, str) and PATH_RE.fullmatch(text) is not None
            and "//" not in text and not text.endswith("/"), label)
    parts = text.split("/")[1:]
    require(all(p not in ("", ".", "..") and p.casefold() not in ("db", "raw", ".serena")
                for p in parts), label)
    return Path(text)


def _parent_is_plain_dir(path):
    try:
        info = path.parent.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode)


def validate_result_path(text):
    path = _check_path_text(str(text), "RESULT_PATH")
    require(path.name.endswith(".json") and _parent_is_plain_dir(path)
            and not os.path.lexists(path), "RESULT_PATH")
    return path


def validate_work_path(text, result_path):
    path = _check_path_text(str(text), "WORK_PATH")
    require(_parent_is_plain_dir(path) and not os.path.lexists(path), "WORK_PATH")
    require(path not in result_path.parents and path != result_path, "WORK_PATH")
    return path


# --------------------------------------------------------------------------
# Signature status and bounded package download.
# --------------------------------------------------------------------------
def check_gpg_status(code, status, fingerprint, label):
    require(code == 0, label)
    try:
        text = status.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise Refusal(label) from None
    counts = {"NEWSIG": 0, "GOODSIG": 0, "VALIDSIG": 0}
    valid = good = None
    for line in text.splitlines():
        require(line.startswith("[GNUPG:] "), label)
        fields = line.split()
        require(len(fields) >= 2 and fields[1] not in BAD_GPG_STATUS, label)
        if fields[1] in counts:
            counts[fields[1]] += 1
        if fields[1] == "VALIDSIG":
            valid = fields
        elif fields[1] == "GOODSIG":
            good = fields
    require(counts["NEWSIG"] <= 1 and counts["GOODSIG"] == 1 and counts["VALIDSIG"] == 1, label)
    require(len(valid) == 12 and valid[2] == fingerprint and valid[11] == fingerprint, label)
    require(valid[6] == "4" and valid[8] in ALLOWED_PUBKEY_ALGOS
            and valid[9] in ALLOWED_HASH_ALGOS and valid[10] == "00", label)
    require(len(good) >= 3 and (good[2] == fingerprint
                                or (len(good[2]) == 16 and fingerprint.endswith(good[2]))), label)
    return True


def build_package_opener():
    context = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), BASE.NoRedirect(),
                                       urllib.request.HTTPSHandler(context=context))


def download_package(url, destination, size, sha, deadline, *,
                     opener_factory=build_package_opener, clock=time.monotonic):
    """Bounded HTTPS, redirect refused, exact length, then pinned hash. No retry."""
    require(isinstance(url, str) and PACKAGE_URL_RE.fullmatch(url) is not None, "INPUT_URL")
    require(_is_int(size) and 0 < size <= MAX_PACKAGE_BYTES, "INPUT_SIZE")
    file_deadline = min(deadline, clock() + PER_FILE_SECONDS)
    require(clock() <= file_deadline, "INPUT_TIMEOUT")
    total = 0
    try:
        with opener_factory().open(url, timeout=CONNECT_TIMEOUT_SECONDS) as response, \
                Path(destination).open("xb") as output:
            require(response.status == 200 and response.geturl() == url, "INPUT_TRANSPORT")
            require(response.headers.get("Content-Length") == str(size), "INPUT_SIZE")
            while True:
                require(clock() <= file_deadline, "INPUT_TIMEOUT")
                chunk = response.read(min(1024 * 1024, size - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= size, "INPUT_SIZE")
                output.write(chunk)
    except Refusal:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        raise Refusal("INPUT_TRANSPORT") from None
    require(total == size, "INPUT_SIZE")
    BASE.check_file(Path(destination), size, sha)


class LocalHost:
    """Real side effects; tests substitute a fake with the same methods."""

    def __init__(self, base):
        self._base = base

    def uname(self):
        info = os.uname()
        return info.sysname, info.machine

    def monotonic(self):
        return time.monotonic()

    def run(self, argv, env, *, timeout, limit):
        # Base contract: waitid(WNOWAIT) before killpg, then reap; bounded stdout.
        return self._base.command(argv, env, timeout=timeout, limit=limit)

    def download_rootfs(self, url, destination, size, sha):
        try:
            self._base.download(url, destination, size, sha)
        except Refusal:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise Refusal("INPUT_TRANSPORT") from None

    def download_package(self, url, destination, size, sha, deadline):
        download_package(url, destination, size, sha, deadline)

    def inspect_rootfs(self, path, pin):
        return self._base.inspect_members(path, pin)


# --------------------------------------------------------------------------
# Workspace, owned names and Docker argv.
# --------------------------------------------------------------------------
class Layout:
    def __init__(self, work, count):
        self.work = Path(work)
        self.count = count
        self.home = self.work / "public-home"
        self.docker_home = self.work / "docker-home"
        self.rootfs_dir = self.work / "rootfs"
        self.rootfs = self.rootfs_dir / "rootfs.tar.gz"
        self.rootfs_sig = self.rootfs_dir / "rootfs.tar.gz.sig"
        self.inputs = self.work / "inputs"
        self.pkg_dir = self.inputs / "pkg"
        self.key_dir = self.inputs / "key"
        self.cert_copy = self.key_dir / CERT_NAME
        self.pacman_conf = self.inputs / "pacman.conf"

    def package(self, index):
        return self.pkg_dir / f"{index:03d}.pkg.tar.xz"

    def signature(self, index):
        return self.pkg_dir / f"{index:03d}.pkg.tar.xz.sig"

    def package_names(self):
        names = set()
        for index in range(self.count):
            names.add(self.package(index).name)
            names.add(self.signature(index).name)
        return names


class Names:
    def __init__(self, context):
        suffix = f"r{context['runId']}-a1-{context['sourceSha'][:12]}"
        self.base_tag = "tf-archarm-runtime-probe-base:" + suffix
        self.derived_tag = "tf-archarm-runtime-probe-sdk:" + suffix
        self.installer = "tf-archarm-runtime-installer-" + suffix
        self.runtime = "tf-archarm-runtime-test-" + suffix
        self._context = context

    def labels(self, role):
        return {LABEL_PREFIX + "run": self._context["runId"],
                LABEL_PREFIX + "attempt": "1",
                LABEL_PREFIX + "source": self._context["sourceSha"][:12],
                LABEL_PREFIX + "role": role}


class Record:
    def __init__(self, name, labels=None):
        self.name = name
        self.labels = labels
        self.requested = False
        self.id = None


def _label_args(labels):
    args = []
    for key in sorted(labels):
        args += ["--label", f"{key}={labels[key]}"]
    return args


def installer_create_argv(names, inputs_dir):
    argv = ["create", "--name", names.installer, "--platform", "linux/arm64", "--pull", "never",
            *_label_args(names.labels("installer")),
            "--network", "none", "--ipc", "none", "--hostname", HOSTNAME, "--cap-drop", "ALL"]
    for cap in CAP_ADD:
        argv += ["--cap-add", cap]
    argv += ["--security-opt", "no-new-privileges=true", "--pids-limit", str(PIDS_LIMIT),
             "--memory", str(INSTALLER_MEMORY), "--memory-swap", str(INSTALLER_MEMORY),
             "--cpus", CPUS, "--log-driver", "none", "--user", "0:0"]
    for item in INSTALLER_ENV:
        argv += ["--env", item]
    argv += ["--mount", f"type=bind,source={inputs_dir},target={INPUTS_TARGET},readonly",
             "--workdir", "/", names.base_tag, *INSTALLER_CMD]
    return argv


def runtime_create_argv(names):
    argv = ["create", "--name", names.runtime, "--platform", "linux/arm64", "--pull", "never",
            *_label_args(names.labels("runtime")),
            "--network", "none", "--ipc", "none", "--hostname", HOSTNAME, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges=true", "--read-only",
            "--tmpfs", "/tmp:" + TMPFS_OPTIONS, "--pids-limit", str(PIDS_LIMIT),
            "--memory", str(RUNTIME_MEMORY), "--memory-swap", str(RUNTIME_MEMORY),
            "--cpus", CPUS, "--log-driver", "none", "--user", "65534:65534"]
    for item in RUNTIME_ENV:
        argv += ["--env", item]
    argv += ["--workdir", "/tmp", names.derived_tag, *RUNTIME_CMD]
    return argv


def expected_container(role, names, *, image_id, inputs_dir=None):
    if role == "installer":
        return {"name": names.installer, "imageTag": names.base_tag, "imageId": image_id,
                "user": "0:0", "env": INSTALLER_ENV, "labels": names.labels("installer"),
                "cmd": list(INSTALLER_CMD), "workdir": "/", "capAdd": CAP_ADD,
                "readonly": False, "tmpfs": {}, "bind": str(inputs_dir),
                "memory": INSTALLER_MEMORY, "id": None}
    return {"name": names.runtime, "imageTag": names.derived_tag, "imageId": image_id,
            "user": "65534:65534", "env": RUNTIME_ENV, "labels": names.labels("runtime"),
            "cmd": list(RUNTIME_CMD), "workdir": "/tmp", "capAdd": (), "readonly": True,
            "tmpfs": {"/tmp": TMPFS_OPTIONS}, "bind": None, "memory": RUNTIME_MEMORY, "id": None}


def _falsy(value):
    if value is None or value is False or value == "":
        return True
    if isinstance(value, (list, tuple)):
        return len(value) == 0
    if isinstance(value, dict):
        return all(_falsy(v) for v in value.values())
    return False


def _caps(values):
    if values is None:
        return []
    require(isinstance(values, list) and all(isinstance(v, str) for v in values),
            "DOCKER_READBACK")
    out = []
    for value in values:
        value = value.upper()
        out.append(value[4:] if value.startswith("CAP_") else value)
    return sorted(out)


def verify_container(doc, exp, label):
    """Readback of the created container before it is ever started."""
    require(isinstance(doc, dict), label)
    require(doc.get("Id") == exp["id"] and doc.get("Name") == "/" + exp["name"], label)
    require(doc.get("ConfigImage") == exp["imageTag"] and doc.get("Image") == exp["imageId"], label)
    require(doc.get("User") == exp["user"], label)
    env = doc.get("Env")
    require(isinstance(env, list) and len(env) == len(set(env)) and set(env) == set(exp["env"]),
            label)
    require(doc.get("Labels") == exp["labels"], label)
    require(doc.get("Cmd") == exp["cmd"] and doc.get("Entrypoint") in (None, []), label)
    require(doc.get("WorkingDir") == exp["workdir"] and doc.get("Hostname") == HOSTNAME, label)
    mounts = doc.get("Mounts") or []
    require(isinstance(mounts, list), label)
    host = doc.get("Host")
    require(isinstance(host, dict), label)
    host_mounts = host.get("Mounts") or []
    require(isinstance(host_mounts, list), label)
    if exp["bind"]:
        require(len(mounts) == 1 and isinstance(mounts[0], dict), label)
        m = mounts[0]
        require(set(m) <= {"Type", "Source", "Destination", "Mode", "RW", "Propagation"}
                and m.get("Type") == "bind" and m.get("Source") == exp["bind"]
                and m.get("Destination") == INPUTS_TARGET and m.get("RW") is False
                and m.get("Mode", "") == "" and m.get("Propagation", "") in ("", "rprivate"),
                label)
        require(len(host_mounts) == 1 and isinstance(host_mounts[0], dict), label)
        h = host_mounts[0]
        require(h.get("Type") == "bind" and h.get("Source") == exp["bind"]
                and h.get("Target") == INPUTS_TARGET and h.get("ReadOnly") is True
                and all(_falsy(v) for k, v in h.items()
                        if k not in ("Type", "Source", "Target", "ReadOnly")), label)
    else:
        require(mounts == [] and host_mounts == [], label)
    require(host.get("NetworkMode") == "none" and host.get("IpcMode") == "none", label)
    require(all(host.get(k, "") == "" for k in ("PidMode", "UTSMode", "UsernsMode",
                                                   "CgroupParent", "VolumeDriver")), label)
    require(host.get("Privileged") is False, label)
    require(_caps(host.get("CapDrop")) == ["ALL"], label)
    require(_caps(host.get("CapAdd")) == sorted(exp["capAdd"]), label)
    security = host.get("SecurityOpt")
    require(isinstance(security, list) and len(security) == 1 and security[0] in NNP_FORMS, label)
    require(host.get("ReadonlyRootfs") is exp["readonly"], label)
    require((host.get("Tmpfs") or {}) == exp["tmpfs"], label)
    for key in ("Binds", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules",
                "PortBindings", "ExtraHosts", "Links", "GroupAdd", "Sysctls"):
        require(_falsy(host.get(key)), label)
    require(host.get("PublishAllPorts") in (None, False) and host.get("Init") in (None, False)
            and host.get("OomKillDisable") in (None, False)
            and host.get("AutoRemove") in (None, False), label)
    require(host.get("Memory") == exp["memory"] and host.get("MemorySwap") == exp["memory"]
            and host.get("NanoCpus") == NANO_CPUS and host.get("PidsLimit") == PIDS_LIMIT, label)
    log = host.get("LogConfig")
    require(isinstance(log, dict) and log.get("Type") == "none", label)
    restart = host.get("RestartPolicy") or {}
    require(isinstance(restart, dict) and restart.get("Name", "") in ("", "no"), label)
    return True


def verify_state(doc, *, created, label):
    if created:
        require(doc.get("Status") == "created" and doc.get("Running") is False, label)
    else:
        require(doc.get("Status") == "exited" and doc.get("Running") is False
                and doc.get("ExitCode") == 0 and doc.get("OOMKilled") is False, label)


def parse_tokens(output, prefix, stages, failures, label):
    """Accept only fixed in-order stage tokens and at most one closed failure token."""
    try:
        text = output.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise Refusal(label) from None
    require(text == "" or text.endswith("\n"), label)
    lines = text.splitlines()
    require(len(lines) <= len(stages) + 1, label)
    done, failure = [], None
    for line in lines:
        parts = line.split(" ")
        require(failure is None and len(parts) in (2, 3) and parts[0] == prefix, label)
        if len(parts) == 3:
            require(parts[1] == "fail" and parts[2] in failures, label)
            failure = parts[2]
        else:
            require(len(done) < len(stages) and parts[1] == stages[len(done)], label)
            done.append(parts[1])
    return done, failure


def _parse_id(output, pattern, label):
    try:
        text = output.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        raise Refusal(label) from None
    require(pattern.fullmatch(text) is not None, label)
    return text


def presence(docker, kind, ref):
    code, out = docker([kind, "inspect", ref], limit=PRESENCE_LIMIT)
    try:
        documents = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("DOCKER_READBACK") from None
    if code == 1 and documents == []:
        return False
    require(code == 0 and isinstance(documents, list) and len(documents) == 1
            and isinstance(documents[0], dict), "DOCKER_READBACK")
    return True


def image_identity(docker, tag, label):
    code, out = docker(["image", "inspect", "--format", IMAGE_FORMAT, tag])
    require(code == 0, label)
    try:
        parts = out.decode("ascii", "strict").strip().split("|")
    except UnicodeDecodeError:
        raise Refusal(label) from None
    require(len(parts) == 3 and IMAGE_ID_RE.fullmatch(parts[0]) is not None
            and parts[1] == "linux" and parts[2] == "arm64", label)
    return parts[0]


def container_doc(docker, ref, label):
    code, out = docker(["container", "inspect", "--format", CONTAINER_FORMAT, ref],
                       limit=INSPECT_LIMIT)
    require(code == 0, label)
    try:
        doc = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal(label) from None
    require(isinstance(doc, dict), label)
    return doc


# --------------------------------------------------------------------------
# Cleanup: verified exact identity, never forced, never pruned.
# --------------------------------------------------------------------------
def cleanup_container(docker, record):
    if not record.requested:
        return True
    if not presence(docker, "container", record.name):
        return record.id is None or not presence(docker, "container", record.id)
    if record.id is None:
        return False  # exists but identity unknown: preserve for VM teardown
    doc = container_doc(docker, record.name, "DOCKER_READBACK")
    if (doc.get("Id") != record.id or doc.get("Name") != "/" + record.name
            or doc.get("Labels") != record.labels):
        return False
    if doc.get("Running") is not False:
        code, _ = docker(["container", "stop", "--time", "10", record.id], timeout=60)
        if code != 0:
            return False
        doc = container_doc(docker, record.id, "DOCKER_READBACK")
        if doc.get("Id") != record.id or doc.get("Running") is not False:
            return False
    code, _ = docker(["container", "rm", record.id], timeout=120)
    if code != 0:
        return False
    return (not presence(docker, "container", record.name)
            and not presence(docker, "container", record.id))


def cleanup_image(docker, record):
    if not record.requested:
        return True
    if not presence(docker, "image", record.name):
        return record.id is None or not presence(docker, "image", record.id)
    if record.id is None:
        return False
    if image_identity(docker, record.name, "DOCKER_READBACK") != record.id:
        return False
    code, _ = docker(["image", "rm", "--no-prune", record.name], timeout=300)
    if code != 0:
        return False
    return not presence(docker, "image", record.name) and not presence(docker, "image", record.id)


def remove_workspace(layout):
    """Two-phase: scan the closed layout, refuse anything unexpected, then delete."""
    files, directories = [], []

    def scan(directory, allowed_files, allowed_dirs):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode), "WORKSPACE_CHANGED")
        names = set(os.listdir(directory))
        require(names <= set(allowed_files) | set(allowed_dirs), "WORKSPACE_CHANGED")
        for name in names:
            entry = (directory / name).lstat()
            if name in allowed_dirs:
                require(stat.S_ISDIR(entry.st_mode), "WORKSPACE_CHANGED")
            else:
                require(stat.S_ISREG(entry.st_mode), "WORKSPACE_CHANGED")
                files.append(directory / name)
        return names

    top = scan(layout.work, (), ("public-home", "rootfs", "inputs"))
    if "public-home" in top:
        scan(layout.home, ("common.conf",), ())
        directories.append(layout.home)
    if "rootfs" in top:
        scan(layout.rootfs_dir, ("rootfs.tar.gz", "rootfs.tar.gz.sig"), ())
        directories.append(layout.rootfs_dir)
    if "inputs" in top:
        sub = scan(layout.inputs, ("pacman.conf",), ("pkg", "key"))
        if "pkg" in sub:
            scan(layout.pkg_dir, tuple(layout.package_names()), ())
            directories.append(layout.pkg_dir)
        if "key" in sub:
            scan(layout.key_dir, (CERT_NAME,), ())
            directories.append(layout.key_dir)
        directories.append(layout.inputs)
    for path in files:
        path.unlink()
    for path in directories:
        path.rmdir()
    layout.work.rmdir()


def _cleanup(docker, records, layout, workspace_created):
    if not workspace_created:
        return True  # nothing owned was created
    try:
        for record in (records["runtime"], records["installer"]):
            if not cleanup_container(docker, record):
                return False
        for record in (records["derived"], records["base"]):
            if not cleanup_image(docker, record):
                return False
        if os.path.lexists(layout.docker_home):
            BASE.remove_fresh_docker_home(layout.docker_home)
        remove_workspace(layout)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Result schema.
# --------------------------------------------------------------------------
def new_result():
    return {"schema": RESULT_SCHEMA, "status": "fail", "stage": "context", "refusal": None,
            "sourceSha": None, "runId": None, "runAttempt": None,
            "digests": {"rootfsSha256": None, "rootfsPinSha256": None,
                        "packagePinsSha256": None, "publicKeySha256": None,
                        "publicKeyFingerprint": FINGERPRINT},
            "counts": {k: 0 for k in COUNT_KEYS},
            "flags": {k: False for k in FLAG_KEYS},
            "assertions": {k: False for k in ASSERTION_KEYS},
            "cleanupComplete": False}


def validate_result(result):
    label = "RESULT_SCHEMA"
    require(isinstance(result, dict) and set(result) == RESULT_KEYS, label)
    require(result["schema"] == RESULT_SCHEMA and result["status"] in ("pass", "fail")
            and result["stage"] in STAGES, label)
    require(result["refusal"] is None or result["refusal"] in REFUSALS, label)
    require(result["sourceSha"] is None or (isinstance(result["sourceSha"], str)
                                            and SOURCE_SHA_RE.fullmatch(result["sourceSha"])),
            label)
    require(result["runId"] is None or (isinstance(result["runId"], str)
                                        and RUN_ID_RE.fullmatch(result["runId"])), label)
    require(result["runAttempt"] is None or (_is_int(result["runAttempt"])
                                             and result["runAttempt"] == 1), label)
    digests = result["digests"]
    require(isinstance(digests, dict) and set(digests) == set(DIGEST_KEYS), label)
    require(digests["publicKeyFingerprint"] == FINGERPRINT, label)
    for key in DIGEST_KEYS[:-1]:
        value = digests[key]
        require(value is None or (isinstance(value, str) and HEX64_RE.fullmatch(value)), label)
    counts = result["counts"]
    require(isinstance(counts, dict) and set(counts) == set(COUNT_KEYS)
            and all(_is_int(v) and v >= 0 for v in counts.values()), label)
    flags = result["flags"]
    require(isinstance(flags, dict) and set(flags) == set(FLAG_KEYS)
            and all(type(v) is bool for v in flags.values()), label)
    assertions = result["assertions"]
    require(isinstance(assertions, dict) and set(assertions) == set(ASSERTION_KEYS)
            and all(v is False for v in assertions.values()), label)
    require(type(result["cleanupComplete"]) is bool, label)
    if result["status"] == "pass":
        require(result["refusal"] is None and result["cleanupComplete"]
                and all(flags.values()) and result["stage"] == "complete", label)
    else:
        require(result["refusal"] is not None, label)
    return result


def finalize(result):
    if result["refusal"] is None and not result["cleanupComplete"]:
        result["refusal"] = "CLEANUP_INCOMPLETE"
    if result["refusal"] is None and not all(result["flags"].values()):
        result["refusal"] = "INCOMPLETE_FLAGS"
    if result["refusal"] is None:
        result["status"] = "pass"
        result["stage"] = "complete"
    else:
        result["status"] = "fail"
    try:
        return validate_result(result)
    except Refusal:
        fallback = new_result()
        fallback["refusal"] = "RESULT_SCHEMA"
        return validate_result(fallback)


def write_result(path, result):
    data = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("ascii")
    require(len(data) <= MAX_RESULT_BYTES, "RESULT_SCHEMA")
    with Path(path).open("xb") as stream:
        stream.write(data)


# --------------------------------------------------------------------------
# Controller.
# --------------------------------------------------------------------------
def _container_phase(docker, record, argv, exp, flags, *, host_flag, labels, prefix, stages,
                     failures, flag_map, timeout):
    record.requested = True
    code, out = docker(argv, timeout=180)
    require(code == 0, labels["create"])
    record.id = _parse_id(out, HEX64_RE, labels["create"])
    exp = dict(exp, id=record.id)
    doc = container_doc(docker, record.name, labels["config"])
    verify_container(doc, exp, labels["config"])
    verify_state(doc, created=True, label=labels["config"])
    flags[host_flag] = True
    code, out = docker(["start", "--attach", record.id], timeout=timeout, limit=4096)
    done, failure = parse_tokens(out, prefix, stages, failures, labels["output"])
    for stage_name in done:
        flags[flag_map[stage_name]] = True
    if failure is not None:
        raise Refusal(labels["failure"] + failure.upper())
    require(code == 0 and len(done) == len(stages), labels["incomplete"])
    doc = container_doc(docker, record.id, labels["state"])
    require(doc.get("Id") == record.id, labels["state"])
    verify_state(doc, created=False, label=labels["state"])


def run_probe(*, context, package_pins, rootfs_pin, certificate, work, host, digests,
              expect=REAL_EXPECT):
    result = new_result()
    result.update(sourceSha=context["sourceSha"], runId=context["runId"], runAttempt=1)
    result["digests"].update(digests)
    flags, counts = result["flags"], result["counts"]
    packages = package_pins["packages"]
    layout = Layout(work, len(packages))
    names = Names(context)
    records = {"base": Record(names.base_tag), "derived": Record(names.derived_tag),
               "installer": Record(names.installer, names.labels("installer")),
               "runtime": Record(names.runtime, names.labels("runtime"))}
    env = {"PATH": "/usr/bin:/bin", "HOME": str(layout.home), "GNUPGHOME": str(layout.home),
           "LANG": "C", "LC_ALL": "C", "TMPDIR": str(layout.work)}
    docker_env = {**env, "HOME": str(layout.docker_home), "DOCKER_CONFIG": str(layout.docker_home)}

    def docker(args, *, timeout=120, limit=4096):
        return host.run(["docker", *args], docker_env, timeout=timeout, limit=limit)

    workspace_created = False
    try:
        result["stage"] = "pins"
        require(len(packages) == expect["packageCount"], "PIN_COUNT")
        counts["packagesPinned"] = len(packages)
        counts["packageBytesPinned"] = sum(p["bytes"] for p in packages)
        BASE.check_file(Path(certificate), expect["publicKeyBytes"], expect["publicKeySha256"])

        result["stage"] = "host"
        sysname, machine = host.uname()
        require(sysname == "Linux" and machine == "aarch64", "NATIVE_ARM_HOST")
        flags["nativeArmHost"] = True

        result["stage"] = "workspace"
        require(layout.work.is_absolute() and _parent_is_plain_dir(layout.work), "FRESH_WORK_ROOT")
        try:
            layout.work.mkdir(mode=0o700)
        except OSError:
            raise Refusal("FRESH_WORK_ROOT") from None
        workspace_created = True
        for directory in (layout.home, layout.docker_home, layout.rootfs_dir):
            directory.mkdir(mode=0o700)
        for directory in (layout.inputs, layout.pkg_dir, layout.key_dir):
            directory.mkdir(mode=0o700)
        with (layout.home / "common.conf").open("x"):
            pass

        result["stage"] = "engine"
        code, out = docker(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])
        require(code == 0 and out.strip() == b"linux/arm64", "NATIVE_ARM_ENGINE")
        code, out = docker(["info", "--format", "{{.OSType}}/{{.Architecture}}"])
        require(code == 0 and out.strip() in (b"linux/aarch64", b"linux/arm64"),
                "NATIVE_ARM_ENGINE")
        flags["nativeArmEngine"] = True
        for tag in (names.base_tag, names.derived_tag):
            require(not presence(docker, "image", tag), "OWNED_NAME_COLLISION")
        for name in (names.installer, names.runtime):
            require(not presence(docker, "container", name), "OWNED_NAME_COLLISION")

        result["stage"] = "rootfs"
        host.download_rootfs(rootfs_pin["rootfsUrl"], layout.rootfs,
                             rootfs_pin["rootfsBytes"], rootfs_pin["rootfsSha256"])
        host.download_rootfs(rootfs_pin["rootfsUrl"] + ".sig", layout.rootfs_sig,
                             rootfs_pin["signatureBytes"], rootfs_pin["signatureSha256"])
        code, status = host.run(["gpgv", "--homedir", str(layout.home), "--keyring",
                                 str(certificate), "--status-fd", "1", str(layout.rootfs_sig),
                                 str(layout.rootfs)], env, timeout=600, limit=8192)
        check_gpg_status(code, status, FINGERPRINT, "ROOTFS_SIGNATURE")
        flags["rootfsSignatureVerified"] = True
        host.inspect_rootfs(layout.rootfs, rootfs_pin)
        flags["rootfsHeadersInspected"] = True

        result["stage"] = "packages"
        deadline = host.monotonic() + PACKAGE_DOWNLOAD_SECONDS
        aggregate = 0
        for index, record in enumerate(packages):
            aggregate += record["bytes"] + record["signatureBytes"]
            require(aggregate <= MAX_PACKAGE_TOTAL_BYTES + MAX_PACKAGES * MAX_SIGNATURE_BYTES,
                    "INPUT_AGGREGATE")
            host.download_package(record["url"], layout.package(index), record["bytes"],
                                  record["sha256"], deadline)
            host.download_package(record["url"] + ".sig", layout.signature(index),
                                  record["signatureBytes"], record["signatureSha256"], deadline)
            counts["packagesDownloaded"] = index + 1
        for index in range(len(packages)):
            code, status = host.run(["gpgv", "--homedir", str(layout.home), "--keyring",
                                     str(certificate), "--status-fd", "1",
                                     str(layout.signature(index)), str(layout.package(index))],
                                    env, timeout=300, limit=8192)
            check_gpg_status(code, status, FINGERPRINT, "PACKAGE_SIGNATURE")
            counts["packageSignaturesVerified"] = index + 1
        flags["packageSignaturesVerified"] = True

        result["stage"] = "inputs"
        with layout.pacman_conf.open("x") as stream:
            stream.write(PACMAN_CONF)
        certificate_bytes = Path(certificate).read_bytes()
        require(len(certificate_bytes) == expect["publicKeyBytes"], "INPUT_FILE")
        with layout.cert_copy.open("xb") as stream:
            stream.write(certificate_bytes)
        BASE.check_file(layout.cert_copy, expect["publicKeyBytes"], expect["publicKeySha256"])
        for index, record in enumerate(packages):
            BASE.check_file(layout.package(index), record["bytes"], record["sha256"])
            BASE.check_file(layout.signature(index), record["signatureBytes"],
                            record["signatureSha256"])
        require(set(os.listdir(layout.pkg_dir)) == layout.package_names()
                and set(os.listdir(layout.key_dir)) == {CERT_NAME}
                and set(os.listdir(layout.inputs)) == {"pkg", "key", "pacman.conf"}, "INPUT_SET")
        for path in [layout.pacman_conf, layout.cert_copy,
                     *(layout.package(i) for i in range(len(packages))),
                     *(layout.signature(i) for i in range(len(packages)))]:
            os.chmod(path, 0o644)
        for directory in (layout.pkg_dir, layout.key_dir, layout.inputs):
            os.chmod(directory, 0o755)

        result["stage"] = "import"
        # Re-establish rootfs custody after the potentially long package phase.
        BASE.check_file(layout.rootfs, rootfs_pin["rootfsBytes"], rootfs_pin["rootfsSha256"])
        BASE.check_file(layout.rootfs_sig, rootfs_pin["signatureBytes"], rootfs_pin["signatureSha256"])
        flags["inputsReverified"] = True
        records["base"].requested = True
        code, out = docker(["import", "--platform", "linux/arm64", str(layout.rootfs),
                            names.base_tag], timeout=900)
        require(code == 0, "IMPORT_FAILED")
        records["base"].id = _parse_id(out, IMAGE_ID_RE, "IMPORT_FAILED")
        require(image_identity(docker, names.base_tag, "IMAGE_IDENTITY") == records["base"].id,
                "IMAGE_IDENTITY")
        flags["baseImageImported"] = True

        result["stage"] = "installer"
        _container_phase(
            docker, records["installer"], installer_create_argv(names, layout.inputs),
            expected_container("installer", names, image_id=records["base"].id,
                               inputs_dir=layout.inputs),
            flags, host_flag="installerHostConfigVerified",
            labels={"create": "INSTALLER_CREATE", "config": "INSTALLER_HOST_CONFIG",
                    "output": "INSTALL_OUTPUT", "failure": "INSTALL_",
                    "incomplete": "INSTALL_INCOMPLETE", "state": "INSTALL_STATE"},
            prefix="TFI", stages=INSTALL_STAGES, failures=INSTALL_FAILURES,
            flag_map=INSTALL_FLAGS, timeout=1800)

        result["stage"] = "commit"
        records["derived"].requested = True
        code, out = docker(["commit", records["installer"].id, names.derived_tag], timeout=900)
        require(code == 0, "COMMIT_FAILED")
        records["derived"].id = _parse_id(out, IMAGE_ID_RE, "COMMIT_FAILED")
        require(image_identity(docker, names.derived_tag, "IMAGE_IDENTITY")
                == records["derived"].id, "IMAGE_IDENTITY")
        flags["derivedImageCommitted"] = True

        result["stage"] = "runtime"
        _container_phase(
            docker, records["runtime"], runtime_create_argv(names),
            expected_container("runtime", names, image_id=records["derived"].id),
            flags, host_flag="runtimeHostConfigVerified",
            labels={"create": "RUNTIME_CREATE", "config": "RUNTIME_HOST_CONFIG",
                    "output": "RUNTIME_OUTPUT", "failure": "RUNTIME_",
                    "incomplete": "RUNTIME_INCOMPLETE", "state": "RUNTIME_STATE"},
            prefix="TFR", stages=RUNTIME_STAGES, failures=RUNTIME_FAILURES,
            flag_map=RUNTIME_FLAGS, timeout=900)
    except Refusal as error:
        result["refusal"] = closed_label(str(error))
    except Exception:
        result["refusal"] = "UNCLASSIFIED_PROBE_FAILURE"
    result["cleanupComplete"] = _cleanup(docker, records, layout, workspace_created)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Proposed, NOT ADMITTED ArchARM runtime probe.")
    parser.add_argument("--work", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        result_path = validate_result_path(args.result)
    except Refusal:
        return 2
    result = new_result()
    entered = False
    try:
        context = validate_context(args.run_id, args.run_attempt, args.source_sha)
        result.update(sourceSha=context["sourceSha"], runId=context["runId"], runAttempt=1)
        work = validate_work_path(args.work, result_path)
        result["stage"] = "pins"
        package_raw = validate_package_pin_bytes(
            read_bounded(PACKAGE_PINS_PATH, MAX_PIN_FILE_BYTES))
        rootfs_raw = read_bounded(ROOTFS_PIN_PATH, MAX_PIN_FILE_BYTES)
        package_pins = validate_package_pins(load_json(package_raw), REAL_EXPECT)
        rootfs_pin = validate_rootfs_pin(load_json(rootfs_raw), REAL_EXPECT)
        digests = {"rootfsSha256": rootfs_pin["rootfsSha256"],
                   "rootfsPinSha256": hashlib.sha256(rootfs_raw).hexdigest(),
                   "packagePinsSha256": hashlib.sha256(package_raw).hexdigest(),
                   "publicKeySha256": REAL_EXPECT["publicKeySha256"]}
        entered = True
        result = run_probe(context=context, package_pins=package_pins, rootfs_pin=rootfs_pin,
                           certificate=CERTIFICATE_PATH, work=work, host=LocalHost(BASE),
                           digests=digests)
        require(result["digests"]["packagePinsSha256"] == PACKAGE_PINS_SHA256, "PIN_FILE")
    except Refusal as error:
        result["refusal"] = closed_label(str(error))
        result["cleanupComplete"] = not entered
    except Exception:
        result["refusal"] = "UNCLASSIFIED_PROBE_FAILURE"
        result["cleanupComplete"] = not entered
    result = finalize(result)
    write_result(result_path, result)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
