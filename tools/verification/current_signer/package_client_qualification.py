"""Native package-client qualification for the six signed Linux lanes in Theme Forge.
Reuses RS9 client runner, container provisioning, specs, and `client_cycle`.
The current-only pacman-aarch64 lane never provisions: it holds one source-bound
rs9.archarm_sdk lease from the authenticated R checkout and passes that object.
"""
from __future__ import annotations
import os, sys  # noqa: E401

if __name__ == "__main__":  # explicit sibling bootstrap under python3 -I -B
    _HERE = os.path.dirname(os.path.realpath(__file__))
    if sys.path[:1] != [_HERE]:
        sys.path.insert(0, _HERE)

import argparse, hashlib, importlib, re, shutil, stat, subprocess, uuid  # noqa: E401,E402
from contextlib import contextmanager  # noqa: E402
from dataclasses import dataclass, fields  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, Callable, Iterator, Mapping, Sequence  # noqa: E402
import client_artifact_input as cai  # noqa: E402
from client_artifact_input import (  # noqa: E402
    COMMITTED_PUBLIC_KEY_FILENAME, COMMITTED_PUBLIC_KEY_GPG_REL_PATH,
    COMMITTED_PUBLIC_KEY_REL_PATH, COMMITTED_PUBLIC_KEY_SHA256,
    PRODUCTION_PRIMARY_FINGERPRINT, PRODUCTION_SIGNING_SUBKEY, dearmor_and_verify_public_key,
)
import current_release_command_binding as crb  # noqa: E402
import publication_github_api as gh  # noqa: E402
from publication_github_api import PublicationError, refuse  # noqa: E402
import retained_publication as rp  # noqa: E402
import source_closure as sc  # noqa: E402

FIXTURE_ASC_FILENAME = "rs9-candidate-fixture-NONPRODUCTION.asc"
P_NIX_CONTRACT_REL_PATH = "tools/verification/p-current-nix-contract.json"
P_COMMAND_CONTRACT_REL_PATH = "tools/verification/current-command-contracts.json"
P_NIX_CONTRACT_SCHEMA = "theme-forge.p-current-native-three-plan-v2"
P_COMMAND_CONTRACT_SCHEMA = "rs9.command-contracts.v1alpha1"
CLIENT_EVIDENCE_SCHEMA = "tf.current-signer-package-client-evidence.v1"
EXPECTED_PRODUCT_VERSIONS = {
    "theme-forge-stellar-burst": "0.7.0", "theme-forge-stellar-loom": "0.5.0",
    "theme-forge-solar-sail": "0.3.0", "theme-forge-nebular-fusion": "0.8.0",
}
_FORBIDDEN_CLIENT_ENV_PREFIXES = ("GIT_", "GITHUB_", "ACTIONS_", "RUNNER_")


@dataclass(frozen=True)
class LaneSpec:
    lane: str; family: str; pin_family: str; arch: str; host_machine: str; system: str; platform: str

LANE_SPECS: dict[str, LaneSpec] = {
    "apt-amd64": LaneSpec("apt-amd64", "apt", "deb", "amd64", "x86_64", "x86_64-linux", "linux/amd64"),
    "apt-arm64": LaneSpec("apt-arm64", "apt", "deb", "arm64", "aarch64", "aarch64-linux", "linux/arm64"),
    "dnf-x86_64": LaneSpec("dnf-x86_64", "dnf", "rpm", "x86_64", "x86_64", "x86_64-linux", "linux/amd64"),
    "dnf-aarch64": LaneSpec("dnf-aarch64", "dnf", "rpm", "aarch64", "aarch64", "aarch64-linux", "linux/arm64"),
    "pacman-x86_64": LaneSpec("pacman-x86_64", "pacman", "pacman", "x86_64", "x86_64", "x86_64-linux", "linux/amd64"),
    "pacman-aarch64": LaneSpec("pacman-aarch64", "pacman", "pacman", "aarch64", "aarch64", "aarch64-linux", "linux/arm64"),
}

# Current-only ArchARM lane: exact qualified SDK lease, never the old registry provisioner.
ARCHARM_LANE = "pacman-aarch64"
ARCHARM_SDK_MODULE = "rs9.archarm_sdk"
ARCHARM_SDK_REL_PATH = "src/rs9/archarm_sdk.py"
ARCHARM_SDK_WORKSPACE = "archarm-sdk"
ARCHARM_PROBE_OUTPUT = "archarm-probe-output"
ARCHARM_SOURCE_KEYS = ("p_commit", "p_tree", "r_commit", "r_tree", "source_closure_sha256", "rs9_run")
MAX_RUNNER_ID = 2147483647
PROBE_OUTPUT_MAX_ENTRIES = 4096
PROBE_OUTPUT_MAX_DEPTH = 16
_SDK_IMAGE_RE = re.compile(r"(?:sha256:[0-9a-f]{64}|[a-z0-9][a-z0-9._/-]{0,127}(?::[A-Za-z0-9._-]{1,128})?)")


def verify_native_linux_host(lane: str, *, uname_fn: Callable[[], Any] = os.uname) -> LaneSpec:
    """Require native Linux host matching the exact lane architecture; reject macOS/emulation."""
    if lane not in LANE_SPECS:
        refuse("UNSUPPORTED_CLIENT_LANE")
    spec, info = LANE_SPECS[lane], uname_fn()
    if (getattr(info, "sysname", None) or info[0]) != "Linux":
        refuse("NON_LINUX_HOST_FORBIDDEN")
    if (getattr(info, "machine", None) or info[4]) != spec.host_machine:
        refuse("HOST_ARCHITECTURE_MISMATCH")
    return spec


def _read_checked_raw(path: Path, error_code: str) -> bytes:
    try:
        return sc.held_regular_bytes(path)
    except sc.ClosureError:
        raise PublicationError(error_code) from None


def _read_checked_public_key(path: Path) -> bytes:
    raw = _read_checked_raw(path, "PUBLIC_KEY_MISSING_OR_INVALID")
    if hashlib.sha256(raw).hexdigest() != COMMITTED_PUBLIC_KEY_SHA256:
        refuse("PUBLIC_KEY_SHA256_MISMATCH")
    return raw


def _read_checked_json(path: Path, error_code: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_checked_raw(path, error_code)
    try:
        return sc.parse_strict_json(raw, error_code), raw
    except sc.ClosureError as error:
        raise PublicationError(error.code) from None


def authenticate_and_prepare_public_trust(p_root: Path, staged_root: Path, client_work_dir: Path) -> dict[str, Any]:
    """Verify committed + staged public keys and write dearmored keyring into client work dir."""
    from rs9.hosted_deb import _write_public_keyring
    committed_bytes = _read_checked_public_key(p_root / COMMITTED_PUBLIC_KEY_REL_PATH)
    if committed_bytes != _read_checked_raw(staged_root / COMMITTED_PUBLIC_KEY_REL_PATH, "PUBLIC_KEY_MISSING_OR_INVALID"):
        refuse("PUBLIC_KEY_STAGED_MISMATCH")
    binary_key = dearmor_and_verify_public_key(committed_bytes)
    binary_sha256, staged_gpg = hashlib.sha256(binary_key).hexdigest(), staged_root / COMMITTED_PUBLIC_KEY_GPG_REL_PATH
    if staged_gpg.exists() and _read_checked_raw(staged_gpg, "PUBLIC_KEY_GPG_MISMATCH") != binary_key:
        refuse("PUBLIC_KEY_GPG_MISMATCH")
    keyring_dir = client_work_dir / "apt-keyring"
    keyring_dir.mkdir(parents=True, exist_ok=False); keyring_dir.chmod(0o755)
    keyring_path = keyring_dir / "knowledge-forge-ai-packages.gpg"
    _write_public_keyring(keyring_path, binary_key)
    return {"asc_path": staged_root / COMMITTED_PUBLIC_KEY_REL_PATH, "asc_sha256": COMMITTED_PUBLIC_KEY_SHA256,
            "gpg_path": keyring_path, "gpg_sha256": binary_sha256,
            "primary_fingerprint": PRODUCTION_PRIMARY_FINGERPRINT, "signing_subkey": PRODUCTION_SIGNING_SUBKEY}


def adapt_production_dnf_spec(rpm_dir: Path, keys_dir: Path, arch: str) -> dict[str, Any]:
    """Build production DNF spec directly via rs9.hosted_deb.dnf_spec(public_key_filename=...)."""
    from rs9.dnf_commands import command_base
    from rs9.dnf_diagnostics import PRODUCTION_KEY_URI, probe_commands
    from rs9.errors import ContractError
    from rs9.hosted_deb import DNF_REPO_FILE, DNF_REPO_ID, SERVER_ROOT, _printf_file, dnf_spec
    _read_checked_public_key(keys_dir / COMMITTED_PUBLIC_KEY_FILENAME)
    try:
        spec = dnf_spec(
            rpm_dir, keys_dir, arch,
            public_fingerprint=PRODUCTION_PRIMARY_FINGERPRINT,
            public_key_filename=COMMITTED_PUBLIC_KEY_FILENAME,
        )
        expected_probes = probe_commands(command_base(), PRODUCTION_KEY_URI)
    except (ContractError, TypeError):
        raise PublicationError("DNF_SPEC_SHAPE_UNRECOGNIZED") from None
    expected_repo = [f"[{DNF_REPO_ID}]", "name=RS9 Fedora 43 NONPRODUCTION candidate",
                     f"baseurl=file://{SERVER_ROOT}/rpm/fedora/43/{arch}", "enabled=1", "gpgcheck=1",
                     "repo_gpgcheck=1", "skip_if_unavailable=False",
                     f"gpgkey={PRODUCTION_KEY_URI}"]
    expected_mounts = [(str(rpm_dir), f"{SERVER_ROOT}/rpm", False), (str(keys_dir), f"{SERVER_ROOT}/keys", False)]
    expected_keys = {
        "family", "arch", "public_fingerprint", "expected_key_sha256", "key_uri",
        "source_uri", "dnf_probe_commands", "mounts", "configure", "refresh",
        "install", "remove", "query",
    }
    if (not isinstance(spec, dict) or set(spec) != expected_keys
            or spec.get("family") != "dnf" or spec.get("arch") != arch
            or spec.get("key_uri") != PRODUCTION_KEY_URI
            or spec.get("public_fingerprint") != PRODUCTION_PRIMARY_FINGERPRINT
            or spec.get("expected_key_sha256") != COMMITTED_PUBLIC_KEY_SHA256
            or spec.get("source_uri") != f"file://{SERVER_ROOT}/rpm/fedora/43/{arch}"
            or spec.get("mounts") != expected_mounts
            or spec.get("configure") != [_printf_file(DNF_REPO_FILE, expected_repo)]
            or spec.get("dnf_probe_commands") != expected_probes
            or spec.get("refresh") != [*command_base(), "--refresh", "makecache"]
            or not all(callable(spec.get(k)) for k in ("install", "remove", "query"))):
        refuse("DNF_SPEC_SHAPE_UNRECOGNIZED")
    # Project this architecture's signed tree into the unchanged guest trust URI.
    # Downstream identity checks deliberately retain that exact URI contract.
    spec["mounts"] = [
        (str(rpm_dir / arch), f"{SERVER_ROOT}/rpm/fedora/43/{arch}", False),
        expected_mounts[1],
    ]
    return spec


def adapt_production_pacman_spec(pacman_dir: Path, keys_dir: Path, architecture: str = "x86_64") -> dict[str, Any]:
    """Narrowly adapt rs9.hosted_deb.pacman_spec literal fixture key filename to production.

    The default x86_64 call is unchanged. aarch64 uses the R pacman_spec
    ``architecture`` keyword and must keep every shared command byte-identical.
    """
    from rs9.hosted_deb import PACMAN_CONF, SERVER_ROOT, _printf_file, pacman_spec
    if architecture not in ("x86_64", "aarch64"):
        refuse("UNSUPPORTED_CLIENT_LANE")
    _read_checked_public_key(keys_dir / COMMITTED_PUBLIC_KEY_FILENAME)
    if architecture == "x86_64":
        spec = pacman_spec(pacman_dir, keys_dir, PRODUCTION_PRIMARY_FINGERPRINT)
    else:
        from rs9.errors import ContractError
        try:
            spec = pacman_spec(pacman_dir, keys_dir, PRODUCTION_PRIMARY_FINGERPRINT, architecture=architecture)
        except (ContractError, TypeError):
            raise PublicationError("PACMAN_SPEC_SHAPE_UNRECOGNIZED") from None
    expected_conf = ["[options]", f"Architecture = {architecture}", "SigLevel = Required DatabaseRequired", "[rs9]", f"Server = file://{SERVER_ROOT}/pacman/$arch"]
    expected_mounts = [(str(pacman_dir), f"{SERVER_ROOT}/pacman", False), (str(keys_dir), f"{SERVER_ROOT}/keys", False)]
    expected_cfg = [_printf_file(PACMAN_CONF, expected_conf), ["pacman-key", "--init"],
                    ["pacman-key", "--add", f"{SERVER_ROOT}/keys/{FIXTURE_ASC_FILENAME}"], ["pacman-key", "--lsign-key", PRODUCTION_PRIMARY_FINGERPRINT]]
    if (not isinstance(spec, dict) or spec.get("family") != "pacman" or spec.get("mounts") != expected_mounts
            or spec.get("configure") != expected_cfg or not all(callable(spec.get(k)) for k in ("install", "remove", "query"))):
        refuse("PACMAN_SPEC_SHAPE_UNRECOGNIZED")
    # Keep the shared trust commands, but select the signed production database.
    production_conf = [
        "[knowledge-forge-ai]" if line == "[rs9]" else line for line in expected_conf
    ]
    spec["configure"] = [
        _printf_file(PACMAN_CONF, production_conf), expected_cfg[1],
        ["pacman-key", "--add", f"{SERVER_ROOT}/keys/{COMMITTED_PUBLIC_KEY_FILENAME}"],
        expected_cfg[3],
    ]
    base = ["pacman", "--config", PACMAN_CONF]
    if spec["install"]("RS9_PRODUCT") != [*base, "-S", "--noconfirm", "--needed", "rs9/RS9_PRODUCT"]:
        refuse("PACMAN_SPEC_SHAPE_UNRECOGNIZED")
    if architecture != "x86_64" and (
            spec.get("refresh") != [*base, "-Sy", "--noconfirm"]
            or spec["remove"]("RS9_PRODUCT") != [*base, "-R", "--noconfirm", "RS9_PRODUCT"]
            or spec["query"]("RS9_PRODUCT") != ["pacman", "-Q", "RS9_PRODUCT"]):
        # The new lane admits no bypass flag, refresh variant or removal shape change.
        refuse("PACMAN_SPEC_SHAPE_UNRECOGNIZED")
    spec["install"] = lambda package: [*base, "-S", "--noconfirm", "--needed", f"knowledge-forge-ai/{package}"]
    spec["public_fingerprint"], spec["expected_key_sha256"] = PRODUCTION_PRIMARY_FINGERPRINT, COMMITTED_PUBLIC_KEY_SHA256
    return spec


def build_production_client_spec(staged_root: Path, lane_spec: LaneSpec) -> dict[str, Any]:
    """Select the signed deployment directory for a DNF or Pacman client."""
    keys = staged_root / "keys"
    if lane_spec.family == "dnf":
        return adapt_production_dnf_spec(staged_root / "rpm", keys, lane_spec.arch)
    if lane_spec.family == "pacman":
        if lane_spec.arch == "x86_64" and lane_spec.platform == "linux/amd64":
            return adapt_production_pacman_spec(staged_root / "arch", keys)
        if lane_spec == LANE_SPECS[ARCHARM_LANE]:
            # Same signed deployment tree; pacman's $arch selects arch/aarch64.
            return adapt_production_pacman_spec(staged_root / "arch", keys, architecture="aarch64")
        refuse("UNSUPPORTED_CLIENT_LANE")
    refuse("UNSUPPORTED_CLIENT_LANE")


def build_production_apt_spec(apt_dir: Path, keyring_path: Path, arch: str, expected_gpg_sha256: str) -> dict[str, Any]:
    """Build and validate rs9.hosted_deb.apt_spec with production primary fingerprint."""
    from rs9.hosted_deb import CLIENT_KEYRING_PATH, SERVER_ROOT, apt_spec
    spec = apt_spec(apt_dir, keyring_path, arch, public_fingerprint=PRODUCTION_PRIMARY_FINGERPRINT)
    expected_mounts = [(str(apt_dir), f"{SERVER_ROOT}/apt", False), (str(keyring_path), CLIENT_KEYRING_PATH, False)]
    if (not isinstance(spec, dict) or spec.get("family") != "apt" or spec.get("public_fingerprint") != PRODUCTION_PRIMARY_FINGERPRINT
            or spec.get("expected_key_sha256") != expected_gpg_sha256 or spec.get("mounts") != expected_mounts
            or "AllowUnauthenticated=false" not in " ".join(spec.get("refresh", []))):
        refuse("APT_SPEC_SHAPE_UNRECOGNIZED")
    return spec


def derive_burst_record_from_p_contract(p_root: Path, system: str) -> tuple[dict[str, Any], str]:
    """Derive verify_client_burst loader/addon record from tools/verification/p-current-nix-contract.json."""
    from rs9.burst_native import BURST_CLOSED_PREBUILDS
    if system not in ("x86_64-linux", "aarch64-linux"):
        refuse("BURST_CONTRACT_SYSTEM")
    doc, raw = _read_checked_json(p_root / P_NIX_CONTRACT_REL_PATH, "BURST_CONTRACT_SCHEMA")
    if (doc.get("schema") != P_NIX_CONTRACT_SCHEMA or doc.get("productionEnabled") is not False
            or doc.get("publicationAuthority") is not False or not isinstance(doc.get("burstNative"), dict)):
        refuse("BURST_CONTRACT_SCHEMA")
    loader_sha, entry = doc.get("burstLoaderSha256"), doc["burstNative"].get(system)
    expected_artifact = "linux-x64-gnu" if system == "x86_64-linux" else "linux-arm64-gnu"
    if (type(loader_sha) is not str or not gh.HEX64.fullmatch(loader_sha) or not isinstance(entry, dict)
            or entry.get("artifact") != expected_artifact or entry.get("backend") != "native-addon-posix-openat-v1"
            or entry.get("abiVersion") != 1 or type(entry.get("sha256")) is not str
            or not gh.HEX64.fullmatch(entry["sha256"]) or expected_artifact not in BURST_CLOSED_PREBUILDS):
        refuse("BURST_CONTRACT_BINDING")
    return {"platform_specific": True, "target_system": system,
            "target_native_addon": {"path": BURST_CLOSED_PREBUILDS[expected_artifact], "sha256": entry["sha256"]},
            "native_loader": {"path": "package/dist/directory-snapshot-native.js", "sha256": loader_sha}}, hashlib.sha256(raw).hexdigest()


def authenticate_p_command_contracts(p_root: Path) -> tuple[dict[str, Any], str]:
    """Authenticate tools/verification/current-command-contracts.json for CURRENT_GENERATION."""
    from rs9.build_native import REQUIRED_COMMANDS
    doc, raw = _read_checked_json(p_root / P_COMMAND_CONTRACT_REL_PATH, "COMMAND_CONTRACT_SCHEMA")
    commands, expected_cmds = doc.get("commands"), {cmd for cmds in REQUIRED_COMMANDS.values() for cmd in cmds}
    if (doc.get("schema") != P_COMMAND_CONTRACT_SCHEMA or doc.get("generation") != gh.CURRENT_GENERATION
            or doc.get("production_enabled") is not False or not isinstance(commands, dict) or set(commands) != expected_cmds):
        refuse("COMMAND_CONTRACT_SCHEMA")
    for cmd, row in commands.items():
        project = row.get("project") if isinstance(row, dict) else None
        ev = row.get("evidence") if isinstance(row, dict) else None
        if (project not in EXPECTED_PRODUCT_VERSIONS or cmd not in REQUIRED_COMMANDS[project]
                or not isinstance(ev, dict) or ev.get("tag") != "v" + EXPECTED_PRODUCT_VERSIONS[project]):
            refuse("COMMAND_CONTRACT_BINDING")
    return commands, hashlib.sha256(raw).hexdigest()


def archarm_runner_identity(
    *, getuid: Callable[[], int] = os.getuid, getgid: Callable[[], int] = os.getgid,
) -> tuple[int, int]:
    """Actual nonroot runner numeric UID/GID, each 1..2147483647; never a name."""
    uid, gid = getuid(), getgid()
    if (type(uid) is not int or type(gid) is not int
            or not 0 < uid <= MAX_RUNNER_ID or not 0 < gid <= MAX_RUNNER_ID):
        refuse("ARCHARM_RUNNER_IDENTITY")
    return uid, gid


def _plain_context(value: Any, depth: int = 0) -> Any:
    """Closed, comparable copy: nested str-keyed mappings of str/int leaves only."""
    if isinstance(value, Mapping) and depth < 3:
        if any(type(key) is not str for key in value):
            refuse("ARCHARM_LEASE_CONTEXT")
        return {key: _plain_context(value[key], depth + 1) for key in sorted(value)}
    if type(value) in (str, int):
        return value
    refuse("ARCHARM_LEASE_CONTEXT")


def archarm_lease_context(lane_spec: LaneSpec, admitted: Mapping[str, Any]) -> dict[str, Any]:
    """Exact current-generation pacman/aarch64-linux context bound to the admitted source."""
    if lane_spec != LANE_SPECS[ARCHARM_LANE]:
        refuse("ARCHARM_LANE_CONTEXT")
    try:
        source = {key: admitted[key] for key in ARCHARM_SOURCE_KEYS}
    except (KeyError, TypeError):
        raise PublicationError("ARCHARM_SOURCE_IDENTITY") from None
    if (any(type(source[k]) is not str or not gh.HEX40.fullmatch(source[k])
            for k in ("p_commit", "p_tree", "r_commit", "r_tree"))
            or type(source["source_closure_sha256"]) is not str
            or not gh.HEX64.fullmatch(source["source_closure_sha256"])
            or not gh.positive_int(source["rs9_run"])):
        refuse("ARCHARM_SOURCE_IDENTITY")
    return _plain_context({
        "generation": gh.CURRENT_GENERATION, "family": "pacman", "system": "aarch64-linux",
        "architecture": "aarch64", "platform": "linux/arm64", "lane": ARCHARM_LANE, "source": source,
    })


def archarm_sdk_context(source_context: Mapping[str, Any], qualification_run_id: int) -> dict[str, Any]:
    """Join the held P source admission to the SDK's closed run/source API."""
    if not gh.positive_int(qualification_run_id):
        refuse("ARCHARM_SOURCE_IDENTITY")
    if (source_context.get("generation") != gh.CURRENT_GENERATION
            or source_context.get("lane") != ARCHARM_LANE
            or source_context.get("family") != "pacman"
            or source_context.get("system") != "aarch64-linux"):
        refuse("ARCHARM_LANE_CONTEXT")
    return {"generation": gh.CURRENT_GENERATION, "runId": str(qualification_run_id),
            "runAttempt": 1, "sourceSha": source_context["source"]["p_commit"]}


def load_archarm_sdk(r_root: Path) -> tuple[Callable[..., Any], type]:
    """Import rs9.archarm_sdk only from the authenticated R checkout's own file."""
    expected = Path(r_root) / ARCHARM_SDK_REL_PATH
    try:
        info = os.lstat(expected)
    except OSError:
        raise PublicationError("ARCHARM_SDK_UNAVAILABLE") from None
    if not stat.S_ISREG(info.st_mode):
        refuse("ARCHARM_SDK_IDENTITY")
    try:
        module = importlib.import_module(ARCHARM_SDK_MODULE)
    except ImportError:
        raise PublicationError("ARCHARM_SDK_UNAVAILABLE") from None
    mod_file = getattr(module, "__file__", None)
    if (getattr(module, "__name__", None) != ARCHARM_SDK_MODULE or not isinstance(mod_file, str)
            or os.path.realpath(mod_file) != os.path.realpath(expected)):
        refuse("ARCHARM_SDK_IDENTITY")
    acquire, lease_type = getattr(module, "acquire_sdk", None), getattr(module, "ArchArmSDK", None)
    if not callable(acquire) or not isinstance(lease_type, type):
        refuse("ARCHARM_SDK_API")
    return acquire, lease_type


def verify_archarm_lease(lease: Any, lease_type: type, *, context: Mapping[str, Any], uid: int, gid: int) -> None:
    """Accept only the exact typed lease that the authenticated SDK returned for this context."""
    if type(lease) is not lease_type:
        refuse("ARCHARM_LEASE_FORGED")
    lease_context = getattr(lease, "context", None)
    if not isinstance(lease_context, Mapping) or _plain_context(lease_context) != _plain_context(context):
        refuse("ARCHARM_LEASE_CONTEXT")
    image, lease_uid, lease_gid = (getattr(lease, k, None) for k in ("image", "uid", "gid"))
    if (getattr(lease, "platform", None) != "linux/arm64" or type(image) is not str
            or not _SDK_IMAGE_RE.fullmatch(image) or type(lease_uid) is not int or type(lease_gid) is not int
            or lease_uid != uid or lease_gid != gid):
        refuse("ARCHARM_LEASE_IDENTITY")
    if not callable(getattr(lease, "client", None)):
        refuse("ARCHARM_LEASE_API")


def _owned_safe(info: os.stat_result, uid: int, gid: int) -> None:
    if info.st_uid != uid or info.st_gid != gid:
        refuse("PROBE_OUTPUT_OWNER")
    if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
        refuse("PROBE_OUTPUT_SETID")
    if info.st_mode & stat.S_IWOTH:
        refuse("PROBE_OUTPUT_WORLD_WRITABLE")


def create_probe_output_root(work_dir: Path, *, uid: int, gid: int) -> Path:
    """One fresh exclusive 0700 tree; the only writable host path offered to the client."""
    root = Path(work_dir) / ARCHARM_PROBE_OUTPUT
    try:
        os.mkdir(root, 0o700)
        info = os.lstat(root)
    except OSError:
        raise PublicationError("PROBE_OUTPUT_ROOT") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        refuse("PROBE_OUTPUT_ROOT")
    _owned_safe(info, uid, gid)
    return root


_IDENTITY = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)  # noqa: E731
_FILE_IDENTITY = lambda s: (*_IDENTITY(s), s.st_size, s.st_mtime_ns, s.st_nlink)  # noqa: E731
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def verify_probe_output_tree(root: Path, *, uid: int, gid: int) -> dict[str, int]:
    """Post-quiescence custody check of untrusted probe output; returns counts only.

    lstat + no-follow held descriptors; expected numeric owner; rejects symlinks,
    setuid/setgid, world-writable, hard-linked, special or changing entries. No
    name or byte from the tree is retained; this check confers no qualification.
    """
    counts = {"directories": 0, "files": 0, "bytes": 0}

    def walk(dir_fd: int, depth: int) -> None:
        for name in sorted(os.listdir(dir_fd)):
            if counts["directories"] + counts["files"] >= PROBE_OUTPUT_MAX_ENTRIES:
                refuse("PROBE_OUTPUT_BOUNDS")
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                refuse("PROBE_OUTPUT_SYMLINK")
            _owned_safe(info, uid, gid)
            if stat.S_ISDIR(info.st_mode):
                if depth >= PROBE_OUTPUT_MAX_DEPTH:
                    refuse("PROBE_OUTPUT_BOUNDS")
                fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
                try:
                    if _IDENTITY(os.fstat(fd)) != _IDENTITY(info):
                        refuse("PROBE_OUTPUT_UNSTABLE")
                    counts["directories"] += 1
                    walk(fd, depth + 1)
                    if _IDENTITY(os.fstat(fd)) != _IDENTITY(info):
                        refuse("PROBE_OUTPUT_UNSTABLE")
                finally:
                    os.close(fd)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    refuse("PROBE_OUTPUT_LINKED")
                fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
                try:
                    if _FILE_IDENTITY(os.fstat(fd)) != _FILE_IDENTITY(info):
                        refuse("PROBE_OUTPUT_UNSTABLE")
                finally:
                    os.close(fd)
                counts["files"] += 1
                counts["bytes"] += info.st_size
            else:
                refuse("PROBE_OUTPUT_SPECIAL")

    try:
        top = os.lstat(root)
        if not stat.S_ISDIR(top.st_mode):
            refuse("PROBE_OUTPUT_ROOT")
        _owned_safe(top, uid, gid)
        root_fd = os.open(root, _DIR_FLAGS)
        try:
            if _IDENTITY(os.fstat(root_fd)) != _IDENTITY(top):
                refuse("PROBE_OUTPUT_UNSTABLE")
            walk(root_fd, 0)
            if _IDENTITY(os.fstat(root_fd)) != _IDENTITY(top):
                refuse("PROBE_OUTPUT_UNSTABLE")
        finally:
            os.close(root_fd)
    except OSError:
        raise PublicationError("PROBE_OUTPUT_UNREADABLE") from None
    return counts


class ArchArmLeaseHold:
    """Holds the one real SDK lease for a pacman-aarch64 lane run.

    The lease is obtained only through load_archarm_sdk(r_root); no caller,
    CLI option or serialized mapping can supply it. Cleanup is the lease's own
    identity-bound non-forced close; P never force-removes lease resources.
    """

    def __init__(self) -> None:
        self.cm: Any = None
        self.lease: Any = None
        self.entered = False
        self.verified = False
        self.uid: int | None = None
        self.gid: int | None = None
        self.context: dict[str, Any] | None = None
        self.probe_output: Path | None = None
        self.probe_counts: dict[str, int] | None = None
        self.cleanup: str | None = None

    def open(self, *, host: Any, lane_spec: LaneSpec, admitted: Mapping[str, Any], r_root: Path, work_dir: Path) -> Any:
        uid, gid = archarm_runner_identity()
        source_context = archarm_lease_context(lane_spec, admitted)
        context = archarm_sdk_context(source_context, admitted.get("qualification_run_id"))
        acquire, lease_type = load_archarm_sdk(r_root)
        self.uid, self.gid, self.context = uid, gid, context
        self.probe_output = create_probe_output_root(work_dir, uid=uid, gid=gid)
        cm = acquire(host=host, workspace=Path(work_dir) / ARCHARM_SDK_WORKSPACE,
                     context=_plain_context(context), uid=uid, gid=gid)
        if not callable(getattr(cm, "__enter__", None)) or not callable(getattr(cm, "__exit__", None)):
            refuse("ARCHARM_SDK_API")
        self.cm = cm
        lease = cm.__enter__()
        self.entered = True
        verify_archarm_lease(lease, lease_type, context=context, uid=uid, gid=gid)
        self.lease, self.verified = lease, True
        return lease

    def close(self) -> str | None:
        """None when nothing was acquired; acquisition that never completed is unproven."""
        if self.cm is None:
            self.cleanup = None
        elif not self.entered:
            self.cleanup = "failed"
        else:
            try:
                self.cm.__exit__(None, None, None)
                self.cleanup = "complete"
            except Exception:
                self.cleanup = "failed"
        return self.cleanup

    def custody_row(self, lane: str) -> dict[str, Any] | None:
        """Ingest probe output only after the lease closed its writers cleanly."""
        if self.probe_output is None or self.uid is None or self.gid is None:
            return None
        name = f"client.{lane}.probe-output-custody"
        if self.cleanup != "complete" or not self.verified:
            return {"name": name, "status": "fail", "reason": "writers-not-quiesced"}
        try:
            self.probe_counts = verify_probe_output_tree(self.probe_output, uid=self.uid, gid=self.gid)
        except PublicationError as error:
            return {"name": name, "status": "fail", "reason": error.code}
        return {"name": name, "status": "pass"}


def _forced_or_pruning_docker(argv: Sequence[str]) -> bool:
    if len(argv) < 2 or argv[0] != "docker":
        return False
    verb = list(argv[1:3])
    removal = argv[1] in ("rm", "rmi") or (
        len(verb) == 2 and verb[0] in ("container", "image") and verb[1] in ("rm", "remove", "prune"))
    pruning = "prune" in verb or (argv[1] == "system" and "prune" in argv[2:3])
    forced = any(a in ("-f", "--force") or a.startswith("--force=") for a in argv[2:])
    return pruning or (removal and forced)


def _validate_client_env_map(env_map: Mapping[str, str], *, strict_allowlist: bool = False) -> None:
    if cai.signing_or_gpg_env_present(env_map) or any(
        key in cai._TOKEN_ENV_NAMES or key.startswith(_FORBIDDEN_CLIENT_ENV_PREFIXES)
        or (strict_allowlist and key not in cai.ALLOWED_CLIENT_ENV_KEYS) for key in env_map
    ):
        refuse("CLIENT_ENV_CREDENTIAL_LEAK")


@contextmanager
def _scoped_os_environ(env_map: Mapping[str, str]) -> Iterator[None]:
    """Restoring guard: replace os.environ so SubprocessRunner never inherits ambient env."""
    _validate_client_env_map(env_map)
    saved = dict(os.environ)
    try:
        os.environ.clear(); os.environ.update(env_map); yield
    finally:
        os.environ.clear(); os.environ.update(saved)


class IsolatedClientRunner:
    """Wraps a CommandRunner with a restoring os.environ guard and container/image custody tracking."""
    def __init__(self, inner: Any, base_env: Mapping[str, str], *, lease_custody: bool = False) -> None:
        _validate_client_env_map(base_env, strict_allowlist=True)
        self.inner, self._base_env = inner, dict(base_env)
        # Lease custody: the SDK lease owns identity-bound, non-forced cleanup of
        # its containers/images; any forced or pruning removal is refused here.
        self.lease_custody = lease_custody is True
        self.active_containers: set[str] = set()
        self.failed_removals: set[str] = set()
        self.failed_image_removals: set[str] = set()

    @property
    def retained_resources(self) -> set[tuple[str, str]]:
        return (
            {("container", name) for name in (self.active_containers | self.failed_removals)}
            | {("image", tag) for tag in self.failed_image_removals}
        )

    @property
    def retained_custody_count(self) -> int:
        return len(self.retained_resources)

    def which(self, tool_name: str) -> str | None:
        with _scoped_os_environ(self._base_env):
            return self.inner.which(tool_name)

    def run(self, argv: list[str], *, cwd: Path | str | None = None, env: dict[str, str] | None = None) -> Any:
        merged = dict(self._base_env)
        if env:
            _validate_client_env_map(env); merged.update(env)
        if self.lease_custody:
            if _forced_or_pruning_docker(argv):
                refuse("ARCHARM_FORCED_CLEANUP")
            with _scoped_os_environ(merged):
                return self.inner.run(argv, cwd=cwd, env=merged)
        cname: str | None = None
        if len(argv) >= 3 and argv[:2] == ["docker", "run"] and "--rm" not in argv:
            if "--name" in argv and argv.index("--name") + 1 < len(argv):
                cname = argv[argv.index("--name") + 1]
            else:
                cname = next((a[7:] for a in argv[2:] if a.startswith("--name=") and a[7:]), None)
        rm_targets = [t for t in argv[3:] if t] if len(argv) >= 4 and argv[:3] == ["docker", "rm", "-f"] else []
        rmi_targets = [t for t in argv[3:] if t] if len(argv) >= 4 and argv[:3] == ["docker", "rmi", "-f"] else []
        if cname:
            self.active_containers.add(cname)
        elif rm_targets:
            self.failed_removals.update(rm_targets)
        elif rmi_targets:
            self.failed_image_removals.update(rmi_targets)
        with _scoped_os_environ(merged):
            receipt = self.inner.run(argv, cwd=cwd, env=merged)
        if bool(getattr(receipt, "executed", False)) and getattr(receipt, "exit_code", 1) == 0:
            for t in rm_targets:
                self.active_containers.discard(t)
                self.failed_removals.discard(t)
            for t in rmi_targets:
                self.failed_image_removals.discard(t)
        return receipt

    def pin_subprocess_run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        with _scoped_os_environ(self._base_env):
            return subprocess.run(argv, env=dict(self._base_env), **kwargs)


def required_gate_names_for_lane(lane_spec: LaneSpec) -> list[str]:
    """Exact required gate names for all four products in one client_cycle + burst_client_gates."""
    from rs9.build_native import REQUIRED_COMMANDS
    from rs9.hosted_deb import NATIVE_PRODUCT, REQUIRED_PRODUCTS
    prefix, expected = f"client.{lane_spec.lane}", []
    for product in REQUIRED_PRODUCTS:
        label = f"{prefix}.{product}"
        expected.extend((f"{label}.network-denial", *([f"{label}.dnf-client-identity"] if lane_spec.family == "dnf" else []),
                         f"{label}.install", *(f"{label}.command.{c}.supported-behavior" for c in sorted(REQUIRED_COMMANDS[product])),
                         *([f"{label}.burst-native-addon-target", f"{label}.burst-native-addon-load"] if product == "theme-forge-stellar-burst" else []),
                         *([f"{label}.native-closure"] if product == NATIVE_PRODUCT else []),
                         f"{label}.uninstall", f"{label}.inventory", f"{label}.cleanup"))
    if lane_spec == LANE_SPECS[ARCHARM_LANE]:
        expected.append(f"{prefix}.probe-output-custody")
    return [*expected, "burst-native-addon-target", "burst-native-addon-load"]


def evaluate_lane_gates(
    gates: Sequence[Mapping[str, Any]], *, required_names: Sequence[str],
    all_commands_executed: bool, cleanup_complete: bool, retained_custody_count: int,
) -> tuple[str, list[dict[str, Any]], dict[str, int]]:
    """Keep failed/skipped/not-run gates visible; pass only when every required gate passes."""
    visible = [{"name": str(g.get("name", "")), "status": str(g.get("status", "not-run")),
                **({"reason": str(g["reason"])} if g.get("reason") else {})} for g in gates]
    by_name = {row["name"]: row for row in visible}
    for req_name in required_names:
        if req_name not in by_name:
            missing_row = {"name": req_name, "status": "not-run", "reason": "missing-required-gate"}
            visible.append(missing_row); by_name[req_name] = missing_row
    counts = {"pass": sum(1 for r in visible if r["status"] == "pass"), "fail": sum(1 for r in visible if r["status"] == "fail"),
              "not_run": sum(1 for r in visible if r["status"] not in ("pass", "fail")), "total": len(visible)}
    strict_pass = (bool(visible) and all(by_name[name]["status"] == "pass" for name in required_names)
                   and all(r["status"] == "pass" for r in visible)
                   and all_commands_executed is True and cleanup_complete is True and retained_custody_count == 0)
    return ("pass" if strict_pass else "fail"), visible, counts


def qualify_lane(
    admitted: Mapping[str, Any], *, p_root: Path, r_root: Path, work_dir: Path, recheck_fn: Callable[[], None],
    client: Any = None, intake_token: str | None = None,
    inner_runner: Any = None, pin_runner: Callable[..., Any] | None = None, uname_fn: Callable[[], Any] = os.uname,
) -> dict[str, Any]:
    """Bind release commands, revalidate artifact/tree, provision container, and run client_cycle."""
    from rs9.build_native import NativePrerequisiteUnavailable, SubprocessRunner
    from rs9.errors import ContractError
    from rs9.github import PublicClient
    from rs9.hosted_deb import (REQUIRED_PRODUCTS, RecordingRunner, _cleanup_step, _dependency_names,
                                _family_error, burst_client_gates, client_cycle, prepare_environment, provision_image)
    from rs9.hosted_native import provision as provision_native
    from rs9.hosted_pins import resolve_targets
    from rs9.rpm_client_runtime import prepare_client, verify_client_image
    lane_spec, staged_root = verify_native_linux_host(str(admitted["lane"]), uname_fn=uname_fn), Path(str(admitted["destination"]))
    rp.verify_tree(str(staged_root), dict(admitted["inventory"]))
    client_home = work_dir / "client-home"
    client_home.mkdir(parents=True, exist_ok=False); client_home.chmod(0o700)
    base_env = cai.sanitized_client_env(str(client_home))
    trust = authenticate_and_prepare_public_trust(p_root, staged_root, work_dir)
    burst_record, nix_contract_sha256 = derive_burst_record_from_p_contract(p_root, lane_spec.system)
    _, cmd_contract_sha256 = authenticate_p_command_contracts(p_root)
    targets_doc, targets_raw = _read_checked_json(r_root / "operators/live1/targets.json", "TARGETS_SCHEMA")
    archarm = lane_spec == LANE_SPECS[ARCHARM_LANE]
    archarm_hold = ArchArmLeaseHold() if archarm else None
    lease_kwargs: dict[str, Any] = {}
    isolated = IsolatedClientRunner(inner_runner or SubprocessRunner(), base_env, lease_custody=archarm)
    host = RecordingRunner(isolated)
    prep_rows, provisioned_tags, cleanup_results, cycle_rows = [], [], [], []
    binding_work = work_dir / "command-binding"
    command_binding: dict[str, Any] = {
        "schema": crb.BINDING_SCHEMA, "status": "not-run",
        "p_command_contract_sha256": cmd_contract_sha256, "r_command_contract_sha256": None,
        "release_record_sha256": {}, "commands": [],
        "native_client_execution": False, "publication_authority": False,
    }
    capture_client: Any = None
    with _scoped_os_environ(base_env):
        try:
            try:
                capture_client = client if client is not None else PublicClient(api_token=intake_token)
                intake_token = None
                command_binding = crb.bind_current_commands(
                    p_root, r_root, binding_work, r_commit=str(admitted["r_commit"]), client=capture_client,
                )
                recheck_fn()
                rp.verify_tree(str(staged_root), dict(admitted["inventory"]))
                if (
                    _read_checked_public_key(p_root / COMMITTED_PUBLIC_KEY_REL_PATH)
                    != _read_checked_raw(staged_root / COMMITTED_PUBLIC_KEY_REL_PATH, "PUBLIC_KEY_MISSING_OR_INVALID")
                    or hashlib.sha256(_read_checked_raw(trust["gpg_path"], "PUBLIC_KEY_GPG_MISMATCH")).hexdigest() != trust["gpg_sha256"]
                    or derive_burst_record_from_p_contract(p_root, lane_spec.system) != (burst_record, nix_contract_sha256)
                    or crb._checked_contracts(p_root, r_root)[1:] != (cmd_contract_sha256, command_binding["r_command_contract_sha256"])
                    or _read_checked_raw(r_root / "operators/live1/targets.json", "TARGETS_SCHEMA") != targets_raw
                ):
                    refuse("SOURCE_STATE_CHANGED")
                # The ARM SDK carries its own frozen public inputs; old registry pins are never resolved for it.
                pins = None if archarm else resolve_targets(targets_doc, runner=pin_runner or isolated.pin_subprocess_run, verify_source_pins=True)
                tag = f"tf-client-{lane_spec.lane}:{uuid.uuid4().hex[:8]}"
                if lane_spec.family == "apt":
                    env = prepare_environment(host, lane_spec.arch, pins, recorder=prep_rows)
                    deb_deps = list(dict.fromkeys(
                        dep for deb_path in sorted((staged_root / "apt/pool").rglob("*.deb"))
                        if deb_path.name.endswith((f"_{lane_spec.arch}.deb", "_all.deb"))
                        for dep in _dependency_names(sc.held_regular_bytes(deb_path, max_bytes=gh.MAX_FILE_BYTES))
                    ))
                    provisioned_tags.append(tag)
                    provision_image(host, "apt", env["image_ref"], lane_spec.platform, tag, [*deb_deps, "python3", "xvfb", "dbus-x11"], recorder=prep_rows, substage_prefix="client-")
                    client_image, spec = tag, build_production_apt_spec(staged_root / "apt", trust["gpg_path"], lane_spec.arch, trust["gpg_sha256"])
                elif lane_spec.family == "dnf":
                    env = provision_native("rpm", lane_spec.system, pins, runner=host)
                    provisioned_tags.append(tag); rt_ev = prepare_client(host, env, arch=lane_spec.arch, system=lane_spec.system, tag=tag)
                    client_image = verify_client_image(host, tag, rt_ev, environment=env, arch=lane_spec.arch, system=lane_spec.system)
                    spec = build_production_client_spec(staged_root, lane_spec)
                elif archarm:
                    spec = build_production_client_spec(staged_root, lane_spec)
                    lease = archarm_hold.open(host=host, lane_spec=lane_spec, admitted=admitted, r_root=r_root, work_dir=work_dir)
                    client_image = lease.image
                    lease_kwargs = {"sdk_lease": lease, "burst_scratch": archarm_hold.probe_output}
                else:
                    env = provision_native("pacman", "x86_64-linux", pins, runner=host); provisioned_tags.append(tag)
                    provision_image(host, "pacman", env["image_ref"], "linux/amd64", tag, [*env["preprovisioned_packages"], "python", "xorg-server-xvfb", "dbus"], recorder=prep_rows, substage_prefix="client-")
                    client_image, spec = tag, build_production_client_spec(staged_root, lane_spec)
                rows, _ = client_cycle(
                    host, spec, image=client_image, platform=lane_spec.platform, products=REQUIRED_PRODUCTS,
                    repository=r_root, prefix=f"client.{lane_spec.lane}", smoke=None, system=lane_spec.system,
                    burst_record=burst_record, generation=gh.CURRENT_GENERATION,
                    **({"burst_scratch": work_dir / "burst-scratch"} if not archarm else lease_kwargs),
                )
                cycle_rows.extend((*rows, *burst_client_gates(rows)))
            except (PublicationError, ContractError, NativePrerequisiteUnavailable, sc.ClosureError, OSError, ValueError, KeyError, TypeError) as err:
                status = "not-run" if isinstance(err, NativePrerequisiteUnavailable) and command_binding.get("status") == "bound" else "fail"
                reason = err.code if isinstance(err, (PublicationError, sc.ClosureError)) else _family_error(err)
                if command_binding.get("status") != "bound":
                    command_binding = {**command_binding, "status": "fail", "reason": reason}
                cycle_rows.append({"name": f"client.{lane_spec.lane}.setup", "status": status, "reason": reason})
        finally:
            intake_token = None
            lease_kwargs = {}
            if binding_work.exists():
                shutil.rmtree(binding_work, ignore_errors=True)
            if archarm_hold is not None:
                # Close the lease first (strict, identity-bound, never forced); only
                # then are probe-output writers quiesced and the tree inspected.
                lease_cleanup = archarm_hold.close()
                if lease_cleanup is not None:
                    cleanup_results.append(lease_cleanup)
                custody = archarm_hold.custody_row(lane_spec.lane)
                if custody is not None:
                    cycle_rows.append(custody)
            for cname in sorted(isolated.active_containers | isolated.failed_removals):
                try:
                    res = _cleanup_step(host, prep_rows, ["docker", "rm", "-f", cname], "container-cleanup")
                except Exception:
                    res = "failed"
                if res != "complete" or cname in (isolated.active_containers | isolated.failed_removals):
                    res = "failed"
                    isolated.failed_removals.add(cname)
                cleanup_results.append(res)
            for img_tag in list(dict.fromkeys([*provisioned_tags, *sorted(isolated.failed_image_removals)])):
                try:
                    res = _cleanup_step(host, prep_rows, ["docker", "rmi", "-f", img_tag], "image-cleanup")
                except Exception:
                    res = "failed"
                if res != "complete" or img_tag in isolated.failed_image_removals:
                    res = "failed"
                    isolated.failed_image_removals.add(img_tag)
                cleanup_results.append(res)
    scratch_lingering = 1 if binding_work.exists() else 0
    # An unproven lease close is retained until disposable VM teardown.
    lease_retained = 1 if archarm_hold is not None and archarm_hold.cleanup == "failed" else 0
    orphan_count = isolated.retained_custody_count + scratch_lingering + lease_retained
    retained_custody = len(gh._RETAINED_CHILDREN) + orphan_count
    cleanup_ok = all(res == "complete" for res in cleanup_results) and retained_custody == 0
    real_commands = bool(
        host.real_since(0)
        and inner_runner is None
        and pin_runner is None
        and client is None
        and isinstance(isolated.inner, SubprocessRunner)
        and isinstance(capture_client, PublicClient)
        and command_binding.get("status") == "bound"
        and (archarm_hold is None or archarm_hold.verified)
    )
    overall, visible_gates, counts = evaluate_lane_gates(
        cycle_rows, required_names=required_gate_names_for_lane(lane_spec),
        all_commands_executed=real_commands, cleanup_complete=cleanup_ok, retained_custody_count=retained_custody,
    )
    return {
        "schema": CLIENT_EVIDENCE_SCHEMA, "overall_status": overall, "lane": lane_spec.lane, "family": lane_spec.family,
        "arch": lane_spec.arch, "system": lane_spec.system, "platform": lane_spec.platform, "generation": gh.CURRENT_GENERATION,
        **{k: admitted[k] for k in ("p_commit", "p_tree", "r_commit", "r_tree", "source_closure_sha256", "rs9_run",
                                    "qualification_run_id", "artifact_id", "artifact_digest_sha256", "public_inventory_sha256", "public_file_count")},
        "primary_fingerprint": PRODUCTION_PRIMARY_FINGERPRINT, "public_key_sha256": COMMITTED_PUBLIC_KEY_SHA256,
        "dearmored_keyring_sha256": trust["gpg_sha256"], "p_nix_contract_sha256": nix_contract_sha256,
        "p_command_contract_sha256": cmd_contract_sha256,
        "r_command_contract_sha256": command_binding.get("r_command_contract_sha256"),
        "command_source_binding": command_binding,
        "burst_loader_sha256": burst_record["native_loader"]["sha256"],
        "burst_addon_path": burst_record["target_native_addon"]["path"], "burst_addon_sha256": burst_record["target_native_addon"]["sha256"],
        "gui_separately_qualified_by_validate_workflow": True, "all_commands_executed": real_commands,
        "cleanup_complete": cleanup_ok, "retained_custody_count": retained_custody,
        "gate_counts": counts, "gates": visible_gates, "receipt_count": len(host.receipts),
        **({"archarm_sdk": {
            "route": ARCHARM_SDK_MODULE, "lease_verified": archarm_hold.verified,
            "lease_cleanup": archarm_hold.cleanup, "registry_provisioner_used": False,
            "context": {k: v for k, v in (archarm_hold.context or {}).items() if k != "source"},
            "probe_output_counts": archarm_hold.probe_counts,
        }} if archarm_hold is not None else {}),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for field in fields(cai.ClientInputOptions):
        parser.add_argument("--" + field.name.replace("_", "-"), dest=field.name, required=True)
    parser.add_argument("--evidence-out", dest="evidence_out", required=True)
    args = parser.parse_args(argv)
    try:
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            refuse("PYTHON_ISOLATION_FLAGS")
        here = os.path.dirname(os.path.realpath(__file__))
        if any(os.path.dirname(os.path.realpath(m.__file__)) != here for m in (gh, rp, sc, cai, crb)):
            refuse("IMPORT_IDENTITY")
        options = cai.ClientInputOptions(**{f.name: getattr(args, f.name) for f in fields(cai.ClientInputOptions)})
        verify_native_linux_host(options.lane); cai.authenticate_caller_environ(options, os.environ)
        token = cai.pop_intake_token(os.environ)
        sc.configure_worker_sys_path(options.p_root, options.r_root, require_isolated_flags=True)
        admitted, recheck = cai.admit_client_artifact_input(options, gh.GhApiTransport(token, options.work_root), environ=os.environ)
        expected_source_binding = {
            k: admitted[k] for k in ("p_commit", "p_tree", "r_commit", "r_tree", "source_closure_sha256", "rs9_run")
        }
        def recheck_api_source_and_tree() -> None:
            if cai.authenticate_checkouts_and_descriptor(options)[2] != expected_source_binding:
                refuse("SOURCE_STATE_CHANGED")
            recheck()
        client_work = Path(options.work_root) / "client-lane-work"
        client_work.mkdir(parents=True, exist_ok=False); client_work.chmod(0o700)
        evidence = qualify_lane(
            admitted, p_root=Path(options.p_root), r_root=Path(options.r_root),
            work_dir=client_work, recheck_fn=recheck_api_source_and_tree, intake_token=token,
        )
        token = None
        cai.write_exclusive_json(args.evidence_out, evidence)
    except (PublicationError, sc.ClosureError) as error:
        print(f"REFUSED {error.code}", file=sys.stderr)
        if gh._RETAINED_CHILDREN:
            print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    except Exception:
        print("REFUSED INTERNAL", file=sys.stderr)
        if gh._RETAINED_CHILDREN:
            print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    if gh._RETAINED_CHILDREN:
        print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    if evidence["overall_status"] != "pass":
        print(f"FAILED lane={evidence['lane']} pass={evidence['gate_counts']['pass']} fail={evidence['gate_counts']['fail']} not_run={evidence['gate_counts']['not_run']}", file=sys.stderr); return 1
    print(f"PASSED lane={evidence['lane']} gates={evidence['gate_counts']['pass']}"); return 0

if __name__ == "__main__":
    raise SystemExit(main())
