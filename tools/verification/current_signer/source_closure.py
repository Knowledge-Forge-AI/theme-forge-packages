"""Stdlib-only acyclic leaf-manifest, descriptor, Git-scope and sys.path bootstrap."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import sysconfig
from typing import Any, Callable, Mapping, MutableMapping

GIT_BINARY = "/usr/bin/git"
LEAF_MANIFEST_SCHEMA = "tf.current-signer-leaf-manifest.v1"
DESCRIPTOR_SCHEMA = "theme-forge.current-rs9-input-source.v1"
WORKER_RECEIPT_SCHEMA = "tf.current-signer-worker-receipt.v1"
CURRENT_GENERATION = "theme-forge-current-202610"
RS9_REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
P_REPOSITORY = "Knowledge-Forge-AI/theme-forge-packages"

CURRENT_SIGNER_REL_DIR = "tools/verification/current_signer"
LEAF_MANIFEST_REL_PATH = "tools/verification/current_signer/leaf-manifest.json"
ROOT_IMPORTER_REL_PATH = "tools/verification/current_import_routing.py"
DESCRIPTOR_REL_PATH = "tools/verification/current-rs9-inputs.json"
PUBLISH_WORKFLOW_REL_PATH = ".github/workflows/publish.yml"
QUALIFY_WORKFLOW_REL_PATH = ".github/workflows/qualify-current-signer.yml"

FRAME_MAGIC = b"TFC6GPG1"
MAX_FRAME_SECRET_BYTES = 2 * 1024 * 1024
MAX_PROTOCOL_LINE_BYTES = 4096

EXCLUDED_ACYCLIC_PATHS = frozenset({
    LEAF_MANIFEST_REL_PATH, ROOT_IMPORTER_REL_PATH, PUBLISH_WORKFLOW_REL_PATH, QUALIFY_WORKFLOW_REL_PATH,
})

REQUIRED_CURRENT_SIGNER_LEAVES = frozenset({
    "apt_signature_adapter.py", "current_protected_signing.py", "detached_signature_adapter.py",
    "owned_gpg_agent.py", "protected_passphrase_fd.py", "protected_signing_runtime.py",
    "public_repository_files.py", "public_repository_linkage.py", "public_repository_verifier.py",
    "repository_metadata_assembly.py", "rpm_byte_preservation.py", "rpm_public_signature_adapter.py",
    "signer_host_controller.py", "signer_protocol_io.py", "signer_worker.py",
    "signing_linux_isolation.py", "signing_network_gate.py", "signing_status_proof.py", "source_closure.py",
    "publication_github_api.py", "retained_publication.py", "secret_frame_transport.py",
    "client_artifact_input.py", "package_client_qualification.py", "current_release_command_binding.py",
    "runtime_workflow_bridge.py", "signing_image_build.py", "runtime_input_intake.py",
    "keyfree_agent_image_check.py", "container_process_entry.py",
})

REQUIRED_B3_LEAVES = frozenset({
    "tools/verification/b3/b3_fixture_entrypoint.py", "tools/verification/b3/b3_fixture_inputs.py",
    "tools/verification/b3/b3_fixture_types.py", "tools/verification/b3/b3_fixture_workspace.py",
    "tools/verification/b3/probe_current_signer_c6_gpg.py",
    "tools/verification/b3/inputs/current_protected_signing.py",
    "tools/verification/b3/inputs/apt_signature_adapter.py",
    "tools/verification/b3/inputs/signing_status_proof.py",
    "tools/verification/b3/inputs/protected_signing_runtime.py",
    "tools/verification/b3/inputs/owned_gpg_agent.py",
    "tools/verification/b3/inputs/protected_passphrase_fd.py",
    "tools/verification/b3/prepare_isolated_global_config.py",
    "tools/verification/b3/test_prepare_isolated_global_config.py",
})

REQUIRED_DATA_FILES = frozenset({
    "tools/verification/p-current-nix-contract.json",
    "tools/verification/current-command-contracts.json",
})

EXPECTED_LEAF_PATHS = frozenset(
    {f"{CURRENT_SIGNER_REL_DIR}/{name}" for name in REQUIRED_CURRENT_SIGNER_LEAVES} | REQUIRED_B3_LEAVES | REQUIRED_DATA_FILES
)

_BOOTSTRAP_ENTRY_LEAVES = frozenset({
    "source_closure.py", "signer_worker.py", "signer_host_controller.py", "runtime_workflow_bridge.py",
})
_REQUIRED_RS9_KEYS = frozenset({
    "repository", "source_commit", "source_tree", "run_id", "not_before",
    "workflow_path", "workflow_sha256", "contract_sha256", "builder_source_sha256",
    "configuration_sha256", "release_ingestion_sha256", "generation",
    "qualification_scope", "event", "ref", "attempt",
})
_RS9_HASH_KEYS = (
    "workflow_sha256", "contract_sha256", "builder_source_sha256",
    "configuration_sha256", "release_ingestion_sha256",
)
_ALLOWED_GIT_CONFIG_KEYS = frozenset({
    "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_1",
})

MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ClosureError(RuntimeError):
    """Fixed-code refusal; never embeds secret or raw diagnostic content."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zero_bytes(buf: bytearray) -> None:
    for idx in range(len(buf)):
        buf[idx] = 0


def unpack_frame_header(prefix: bytes | bytearray, error_cls: type[RuntimeError] = ClosureError) -> tuple[int, int]:
    if len(prefix) != 16 or bytes(prefix[:8]) != FRAME_MAGIC:
        raise error_cls("STDIN_FRAME_FORMAT", "Invalid secret frame header")
    key_len, phrase_len = struct.unpack(">II", bytes(prefix[8:16]))
    if not (0 < key_len <= MAX_FRAME_SECRET_BYTES and 0 < phrase_len <= MAX_FRAME_SECRET_BYTES):
        raise error_cls("STDIN_FRAME_BOUNDS", "Secret frame lengths out of bounds")
    return key_len, phrase_len


def _stable_stat(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def physical_dir(path: str | os.PathLike[str], label: str = "directory") -> Path:
    raw = os.fspath(path) if isinstance(path, (str, os.PathLike)) else ""
    if (
        not isinstance(raw, str) or not raw.startswith("/") or "\x00" in raw or "*" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise ClosureError("PHYSICAL_PATH_REQUIRED", f"{label} must be an exact physical absolute path")
    candidate = Path(raw)
    for item in (*reversed(candidate.parents), candidate):
        try:
            info = os.lstat(item)
        except OSError as error:
            raise ClosureError("PHYSICAL_PATH_MISSING", f"{label} is unavailable") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ClosureError("PHYSICAL_DIR_REQUIRED", f"{label} and its ancestors must be real directories")
    return candidate


def held_regular_bytes(path: str | os.PathLike[str], max_bytes: int = MAX_SOURCE_FILE_BYTES) -> bytes:
    candidate = Path(os.fspath(path))
    physical_dir(candidate.parent, "file parent")
    try:
        lstat_before = os.lstat(candidate)
    except OSError as error:
        raise ClosureError("SOURCE_FILE_MISSING", "Required source file is missing") from error
    if stat.S_ISLNK(lstat_before.st_mode) or not stat.S_ISREG(lstat_before.st_mode):
        raise ClosureError("REGULAR_SOURCE_REQUIRED", "Source file must be an unaliased regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(candidate, flags)
    except OSError as error:
        raise ClosureError("SOURCE_FILE_OPEN", "Unable to open source file") from error
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= max_bytes:
            raise ClosureError("SOURCE_FILE_BOUND", "Source file exceeds size bound")
        data = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    try:
        lstat_after = os.lstat(candidate)
    except OSError as error:
        raise ClosureError("SOURCE_FILE_CHANGED", "Source file vanished after read") from error
    if (
        len(data) != before.st_size or len(data) > max_bytes or _stable_stat(before) != _stable_stat(after)
        or _stable_stat(lstat_before) != _stable_stat(after) or _stable_stat(lstat_after) != _stable_stat(after)
    ):
        raise ClosureError("SOURCE_FILE_CHANGED", "Source file changed during read")
    return data


def parse_strict_json(raw: bytes, error_code: str = "JSON_SCHEMA") -> dict[str, Any]:
    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ClosureError(error_code, "Duplicate JSON key refused")
            out[key] = value
        return out

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except ClosureError:
        raise
    except (UnicodeError, ValueError) as error:
        raise ClosureError(error_code, "Invalid JSON document") from error
    if not isinstance(parsed, dict):
        raise ClosureError(error_code, "JSON root must be an object")
    return parsed


def scoped_git_env(p_root: str | Path, r_root: str | Path) -> dict[str, str]:
    p_dir, r_dir = physical_dir(p_root, "P source root"), physical_dir(r_root, "R source root")
    if p_dir == r_dir or p_dir in r_dir.parents or r_dir in p_dir.parents:
        raise ClosureError("GIT_SCOPE_OVERLAP", "P and R source roots must be distinct physical trees")
    return {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": str(p_dir),
        "GIT_CONFIG_KEY_1": "safe.directory", "GIT_CONFIG_VALUE_1": str(r_dir),
    }


def apply_process_git_scope(
    p_root: str | Path, r_root: str | Path, target_env: MutableMapping[str, str] | None = None,
) -> dict[str, str]:
    env = os.environ if target_env is None else target_env
    scoped = scoped_git_env(p_root, r_root)
    for key in [k for k in list(env) if k.startswith("GIT_")]:
        del env[key]
    for key, value in scoped.items():
        if key.startswith("GIT_"):
            env[key] = value
    return scoped


def _require_scoped_git_env(git_env: Mapping[str, str], p_or_r_root: Path) -> None:
    if (
        git_env.get("GIT_OPTIONAL_LOCKS") != "0" or git_env.get("GIT_CONFIG_NOSYSTEM") != "1"
        or git_env.get("GIT_CONFIG_GLOBAL") != "/dev/null" or git_env.get("GIT_CONFIG_COUNT") != "2"
        or git_env.get("GIT_CONFIG_KEY_0") != "safe.directory" or git_env.get("GIT_CONFIG_KEY_1") != "safe.directory"
    ):
        raise ClosureError("GIT_SCOPE_INVALID", "Exact two-root process-scoped git safe.directory is required")
    roots = (git_env.get("GIT_CONFIG_VALUE_0", ""), git_env.get("GIT_CONFIG_VALUE_1", ""))
    if any(not r or "*" in r for r in roots) or str(p_or_r_root) not in roots:
        raise ClosureError("GIT_SCOPE_INVALID", "Wildcard or unaligned git safe.directory is forbidden")
    if {k for k in git_env if k.startswith("GIT_CONFIG_")} - _ALLOWED_GIT_CONFIG_KEYS:
        raise ClosureError("GIT_SCOPE_INVALID", "Unexpected GIT_CONFIG_* overrides are forbidden")


def _default_git_runner(argv: tuple[str, ...], cwd: Path, env: Mapping[str, str]) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(
        argv, cwd=str(cwd), env=dict(env), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def verify_clean_git_checkout(
    root: str | Path, expected_commit: str, expected_tree: str, *, git_env: Mapping[str, str],
    git_runner: Callable[[tuple[str, ...], Path, Mapping[str, str]], tuple[int, bytes, bytes]] | None = None,
) -> None:
    repo = physical_dir(root, "git checkout")
    if not isinstance(expected_commit, str) or not _HEX40.fullmatch(expected_commit):
        raise ClosureError("GIT_COMMIT_FORMAT", "Expected commit must be 40-hex")
    if not isinstance(expected_tree, str) or not _HEX40.fullmatch(expected_tree):
        raise ClosureError("GIT_TREE_FORMAT", "Expected tree must be 40-hex")
    _require_scoped_git_env(git_env, repo)
    try:
        marker_info = os.lstat(repo / ".git")
    except OSError as error:
        raise ClosureError("GIT_CHECKOUT_REQUIRED", "Missing .git in source checkout") from error
    if stat.S_ISLNK(marker_info.st_mode):
        raise ClosureError("GIT_CHECKOUT_REQUIRED", "Symlinked .git is forbidden")
    runner = git_runner or _default_git_runner
    try:
        rc_head, out_head, _ = runner((GIT_BINARY, "rev-parse", "HEAD"), repo, git_env)
        rc_tree, out_tree, _ = runner((GIT_BINARY, "rev-parse", f"{expected_commit}^{{tree}}"), repo, git_env)
        rc_stat, out_stat, _ = runner(
            (GIT_BINARY, "status", "--porcelain", "--untracked-files=all", "--ignored"), repo, git_env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ClosureError("GIT_COMMAND_FAILED", "Git checkout inspection failed") from error
    if rc_head != 0 or rc_tree != 0 or rc_stat != 0:
        raise ClosureError("GIT_COMMAND_FAILED", "Git checkout inspection returned non-zero")
    if (
        out_head.decode("ascii", errors="replace").strip() != expected_commit
        or out_tree.decode("ascii", errors="replace").strip() != expected_tree or out_stat
    ):
        raise ClosureError("GIT_CHECKOUT_DIRTY_OR_MISMATCH", "Checkout HEAD, tree, or cleanliness mismatch")


def authenticate_rs9_descriptor(
    p_root: str | Path, *, expected_r_commit: str, expected_r_tree: str, expected_rs9_run: int,
) -> dict[str, Any]:
    descriptor_path = physical_dir(p_root, "P source root") / DESCRIPTOR_REL_PATH
    try:
        os.lstat(descriptor_path)
    except FileNotFoundError as error:
        raise ClosureError("DESCRIPTOR_ABSENT", "RS9 input descriptor is absent") from error
    except OSError as error:
        raise ClosureError("DESCRIPTOR_IO", "Unable to inspect RS9 input descriptor") from error
    raw = held_regular_bytes(descriptor_path)
    doc = parse_strict_json(raw, "DESCRIPTOR_SCHEMA")
    required_keys = {"schema", "generation", "status", "production_enabled", "publication_authority", "rs9"}
    if (
        set(doc) != required_keys or doc.get("schema") != DESCRIPTOR_SCHEMA
        or doc.get("generation") != CURRENT_GENERATION
        or doc.get("production_enabled") is not False or doc.get("publication_authority") is not False
    ):
        raise ClosureError("DESCRIPTOR_SCHEMA", "Descriptor schema or authority flags invalid")
    if doc.get("status") != "qualified-original-run-inputs" or not isinstance(doc.get("rs9"), dict):
        raise ClosureError("DESCRIPTOR_UNADMITTED", "Descriptor has no qualified original RS9 run")
    rs9_info = doc["rs9"]
    if set(rs9_info) != _REQUIRED_RS9_KEYS:
        raise ClosureError("DESCRIPTOR_SCHEMA", "Descriptor rs9 fields are not closed")
    if (
        rs9_info.get("repository") != RS9_REPOSITORY or rs9_info.get("source_commit") != expected_r_commit
        or rs9_info.get("source_tree") != expected_r_tree or type(rs9_info.get("run_id")) is not int
        or rs9_info.get("run_id") != expected_rs9_run or rs9_info.get("event") != "push"
        or rs9_info.get("ref") != "refs/heads/main" or type(rs9_info.get("attempt")) is not int
        or rs9_info.get("attempt") != 1 or rs9_info.get("generation") != CURRENT_GENERATION
    ):
        raise ClosureError("DESCRIPTOR_BINDING_MISMATCH", "Descriptor RS9 coordinates disagree with binding")
    for hash_key in _RS9_HASH_KEYS:
        if not isinstance(rs9_info.get(hash_key), str) or not _HEX64.fullmatch(rs9_info[hash_key]):
            raise ClosureError("DESCRIPTOR_SCHEMA", f"Descriptor {hash_key} must be 64-hex")
    return {"descriptor": doc, "descriptor_sha256": sha256_hex(raw)}


def authenticate_leaf_closure(
    p_root: str | Path, *, expected_leaf_manifest_sha256: str, require_unimported: bool = True,
) -> dict[str, str]:
    if not isinstance(expected_leaf_manifest_sha256, str) or not _HEX64.fullmatch(expected_leaf_manifest_sha256):
        raise ClosureError("LEAF_MANIFEST_PIN_FORMAT", "Expected leaf manifest SHA-256 must be 64-hex")
    if require_unimported:
        guarded = {name[:-3] for name in (REQUIRED_CURRENT_SIGNER_LEAVES - _BOOTSTRAP_ENTRY_LEAVES)}
        if any(mod in sys.modules for mod in guarded):
            raise ClosureError("LEAF_IMPORTED_BEFORE_AUTH", "Leaf module was imported before closure authentication")
    p_dir = physical_dir(p_root, "P source root")
    manifest_raw = held_regular_bytes(p_dir / LEAF_MANIFEST_REL_PATH)
    if sha256_hex(manifest_raw) != expected_leaf_manifest_sha256:
        raise ClosureError("LEAF_MANIFEST_DIGEST_MISMATCH", "Leaf manifest SHA-256 mismatch")
    manifest = parse_strict_json(manifest_raw, "LEAF_MANIFEST_SCHEMA")
    if (
        set(manifest) != {"schema", "excluded_acyclic_roots", "files"}
        or manifest.get("schema") != LEAF_MANIFEST_SCHEMA
        or manifest.get("excluded_acyclic_roots") != sorted(EXCLUDED_ACYCLIC_PATHS)
        or not isinstance(manifest.get("files"), dict)
    ):
        raise ClosureError("LEAF_MANIFEST_SCHEMA", "Leaf manifest structure invalid")
    files = manifest["files"]
    if set(files) != EXPECTED_LEAF_PATHS or (set(files) & EXCLUDED_ACYCLIC_PATHS):
        raise ClosureError("LEAF_MANIFEST_INVENTORY", "Leaf manifest file set is incomplete or cyclic")
    verified: dict[str, str] = {}
    for rel_path, expected_sha in sorted(files.items()):
        if not isinstance(expected_sha, str) or not _HEX64.fullmatch(expected_sha):
            raise ClosureError("LEAF_MANIFEST_SCHEMA", "Leaf file digest must be 64-hex")
        actual_sha = sha256_hex(held_regular_bytes(p_dir / rel_path))
        if actual_sha != expected_sha:
            raise ClosureError("LEAF_FILE_DIGEST_MISMATCH", f"Leaf file digest mismatch for {rel_path}")
        verified[rel_path] = actual_sha
    for mod_name in ("source_closure", "signer_worker", "signer_host_controller",
                     "runtime_workflow_bridge", "client_artifact_input", "package_client_qualification", "__main__"):
        mod_file = getattr(sys.modules.get(mod_name), "__file__", None)
        if isinstance(mod_file, str) and Path(mod_file).name in (
            _BOOTSTRAP_ENTRY_LEAVES | {"client_artifact_input.py", "package_client_qualification.py"}
        ):
            rel_key = f"{CURRENT_SIGNER_REL_DIR}/{Path(mod_file).name}"
            if sha256_hex(held_regular_bytes(Path(mod_file))) != verified[rel_key]:
                raise ClosureError("EXECUTING_BOOTSTRAP_MISMATCH", "Executing bootstrap module differs from P checkout")
    return verified


def configure_worker_sys_path(
    p_root: str | Path, r_root: str | Path, *, require_isolated_flags: bool = True,
) -> tuple[Path, Path, Path]:
    if require_isolated_flags and (not sys.flags.isolated or not sys.flags.dont_write_bytecode):
        raise ClosureError("PYTHON_ISOLATION_FLAGS", "Python -I and -B flags are required")
    p_dir, r_dir = physical_dir(p_root, "P source root"), physical_dir(r_root, "R source root")
    current_signer_dir = physical_dir(p_dir / CURRENT_SIGNER_REL_DIR, "current_signer module root")
    verification_dir = physical_dir(p_dir / "tools/verification", "verification importer root")
    r_src_dir = physical_dir(r_dir / "src", "RS9 src root")
    physical_dir(r_src_dir / "rs9", "RS9 package root")
    top_py = {p.name for p in verification_dir.glob("*.py")}
    leaf_py = {p.name for p in current_signer_dir.glob("*.py")}
    r_top = {p.stem for p in r_src_dir.iterdir() if not p.name.startswith(".")}
    if (
        "current_import_routing.py" not in top_py or not REQUIRED_CURRENT_SIGNER_LEAVES.issubset(leaf_py)
        or (top_py & leaf_py) or ({name[:-3] for name in leaf_py} & r_top) or ("current_import_routing" in r_top)
    ):
        raise ClosureError("DUPLICATE_MODULE_IDENTITY", "Missing or overlapping module names across verification roots")
    stdlib_dirs = {
        Path(p).resolve()
        for key in ("stdlib", "platstdlib")
        if (p := sysconfig.get_path(key)) and Path(p).is_dir()
    }
    extension_dir = sysconfig.get_config_var("DESTSHARED")
    allowed_dirs = set(stdlib_dirs)
    if extension_dir and Path(extension_dir).is_dir():
        allowed_dirs.add(Path(extension_dir).resolve())
    zip_name = f"python{sys.version_info.major}{sys.version_info.minor}.zip"
    allowed_zips = {path.parent / zip_name for path in stdlib_dirs}
    kept_stdlib = []
    for entry in sys.path:
        if not entry or not Path(entry).is_absolute():
            continue
        physical = Path(entry).resolve()
        if physical in allowed_dirs or physical in allowed_zips:
            if str(physical) not in kept_stdlib:
                kept_stdlib.append(str(physical))
    if not kept_stdlib:
        raise ClosureError("STDLIB_PATH_MISSING", "No authenticated standard-library path remains")
    sys.path[:] = [*kept_stdlib, str(current_signer_dir), str(verification_dir), str(r_src_dir)]
    return current_signer_dir, verification_dir, r_src_dir
