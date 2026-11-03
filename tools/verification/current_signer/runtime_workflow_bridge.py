"""Bounded source-only Theme Forge runtime workflow bridge (plan, prepare-image, release-image).

Imports only Python stdlib and source_closure at module load time. Image builder
and runtime quarantine intake modules are imported lazily only after physical P
checkout, leaf-manifest closure, and GitHub workflow context authentication succeed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import email.utils
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping, MutableMapping, Sequence

if __name__ == "__main__":
    _HERE = os.path.dirname(os.path.realpath(__file__))
    if sys.path[:1] != [_HERE]:
        sys.path.insert(0, _HERE)

import source_closure as sc  # noqa: E402

REPOSITORY = "Knowledge-Forge-AI/theme-forge-packages"
REPOSITORY_OWNER = "Knowledge-Forge-AI"
QUALIFY_WORKFLOW_PATH = ".github/workflows/qualify-current-signer.yml"
EXPECTED_WORKFLOW_REF = f"{REPOSITORY}/{QUALIFY_WORKFLOW_PATH}@refs/heads/main"

BINDING_SCHEMA = "tf.current-signer-runtime-binding.v1"
LEASE_RECEIPT_SCHEMA = "tf.current-signer-runtime-image-lease.v1"

RUNTIME_ADMISSION_MANIFEST_REL_PATH = "tools/verification/current_signer/runtime-image-admission.json"
FEDORA_CERT_REL_PATH = "tools/verification/current_signer/RPM-GPG-KEY-fedora-43-primary.asc"
BASE_ROOT_PROOF_REL_PATH = "tools/verification/current_signer/BASE-ROOT-BYTE-IDENTITIES.json"
BASE_METADATA_PROOF_REL_PATH = "tools/verification/current_signer/CURRENT-BASE-NATIVE-QUALIFIED.json"
SUPPLEMENTAL_NOTICE_MANIFEST_REL_PATH = "tools/verification/current_signer/UPSTREAM-NOTICE-PINS.json"
SUPPLEMENTAL_NOTICE_DIR_REL_PATH = "tools/verification/current_signer/upstream-notices"

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NUMERIC_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_OUTPUT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RFC2822_UTC_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} "
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} (?:[+-]0000|GMT|UTC)$"
)
_SIGNING_SECRET_NAMES = frozenset(
    {
        "PACKAGE_SIGNING_KEY",
        "PACKAGE_SIGNING_PASSPHRASE",
        "SIGNING_KEY",
        "SIGNING_PASSPHRASE",
        "GPG_AGENT_INFO",
        "SSH_AUTH_SOCK",
    }
)
_SIGNING_ENV_PREFIXES = ("TF_GPG_", "GPG_", "GNUPG", "SIGNING_", "PACKAGE_SIGNING_", "DOCKER_")
_TOKEN_ENV_NAMES = frozenset(
    {
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    }
)
_EXCLUSIVE_FILE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_APPEND_FILE_FLAGS = (
    os.O_WRONLY
    | os.O_APPEND
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

_RETAINED_BRIDGE_CUSTODY: list[dict[str, Any]] = []


class RuntimeBridgeError(RuntimeError):
    """Fixed-code runtime workflow bridge refusal; never embeds raw paths, logs, or secrets."""

    def __init__(
        self, code: str, message: str = "", *, custody_retained: bool = False,
        cleanup_observation: Mapping[str, str] | None = None,
    ) -> None:
        self.code = code
        self.reason = message or code
        self.custody_retained = custody_retained
        allowed = {
            "category": {
                "ROOT_SYMLINK", "ROOT_NOT_DIRECTORY", "ROOT_FOREIGN_OWNER", "ROOT_ENTRIES",
                "SUBDIR_SYMLINK", "SUBDIR_NOT_DIRECTORY", "SUBDIR_FOREIGN_OWNER",
                "CHILD_SYMLINK", "CHILD_FOREIGN_OWNER", "NESTED_DIRECTORY",
                "GH_CONFIG_NOT_REGULAR", "GH_CONFIG_LINK_COUNT", "GH_CONFIG_FOREIGN_OWNER",
                "CHILD_LINK_COUNT", "CHILD_SPECIAL_FILE", "FILESYSTEM",
            },
            "scope": {"ROOT", "BUILD", "QUARANTINE", "TRANSPORT", "GH_CONFIG", "OTHER"},
            "operation": {"EXISTS", "LSTAT", "LISTDIR", "UNLINK", "RMDIR"},
            "errno": {"NONE", "EACCES", "EPERM", "ENOENT", "ENOTEMPTY", "EBUSY", "EIO", "OTHER"},
        }
        self.cleanup_observation = (
            dict(cleanup_observation)
            if type(cleanup_observation) is dict and set(cleanup_observation) == set(allowed)
            and all(type(cleanup_observation[key]) is str and cleanup_observation[key] in values
                    for key, values in allowed.items())
            else None
        )
        super().__init__(f"{code}: {self.reason}")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_isolated_python(*, require_isolated_flags: bool = True) -> None:
    if require_isolated_flags and (not sys.flags.isolated or not sys.flags.dont_write_bytecode):
        raise RuntimeBridgeError("PYTHON_ISOLATION_FLAGS", "Python -I and -B flags are required")


def verify_native_linux_amd64_host(*, uname_fn: Callable[[], Any] = os.uname) -> None:
    info = uname_fn()
    sysname = getattr(info, "sysname", None) or (info[0] if isinstance(info, tuple) and len(info) > 0 else "")
    machine = getattr(info, "machine", None) or (info[4] if isinstance(info, tuple) and len(info) > 4 else "")
    if sysname != "Linux":
        raise RuntimeBridgeError("NON_LINUX_HOST_FORBIDDEN", "Runtime bridge requires a native Linux host")
    if machine != "x86_64":
        raise RuntimeBridgeError("HOST_ARCHITECTURE_MISMATCH", "Runtime bridge requires native x86_64 architecture")


def _require_nonzero_hex40(value: Any, code: str) -> str:
    if type(value) is not str or not _HEX40.fullmatch(value) or value == ("0" * 40):
        raise RuntimeBridgeError(code, "Expected a non-zero 40-character lowercase hexadecimal digest")
    return value


def _require_nonzero_hex64(value: Any, code: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value) or value == ("0" * 64):
        raise RuntimeBridgeError(code, "Expected a non-zero 64-character lowercase hexadecimal digest")
    return value


def require_key_free_bridge_env(environ: Mapping[str, str], *, allow_gh_token: bool = False) -> None:
    for key in environ:
        if type(key) is not str or "\x00" in key:
            raise RuntimeBridgeError("ENVIRONMENT_INVALID", "Invalid environment variable name")
        upper = key.upper()
        if (
            key in _SIGNING_SECRET_NAMES
            or "SIGNING" in upper
            or "PASSPHRASE" in upper
            or upper.startswith(_SIGNING_ENV_PREFIXES)
        ):
            raise RuntimeBridgeError(
                "SIGNING_SECRET_IN_ENVIRONMENT",
                "Signing secret or GPG variable forbidden in runtime bridge",
            )
        if not allow_gh_token and key in _TOKEN_ENV_NAMES:
            raise RuntimeBridgeError(
                "UNEXPECTED_TOKEN_IN_ENVIRONMENT",
                "Online token forbidden in non-intake bridge operation",
            )
        if allow_gh_token and key in (_TOKEN_ENV_NAMES - {"GH_TOKEN"}):
            raise RuntimeBridgeError(
                "UNEXPECTED_TOKEN_IN_ENVIRONMENT",
                "Only GH_TOKEN may be supplied to prepare-image",
            )


def pop_readonly_gh_token(environ: MutableMapping[str, str]) -> str:
    require_key_free_bridge_env(environ, allow_gh_token=True)
    token = environ.get("GH_TOKEN")
    for name in list(environ):
        if name in _TOKEN_ENV_NAMES or name.startswith("GIT_"):
            del environ[name]
    if (
        type(token) is not str
        or not 1 <= len(token) <= 1024
        or not token.isascii()
        or not token.isprintable()
        or any(ch.isspace() for ch in token)
        or "\x00" in token
    ):
        raise RuntimeBridgeError("TOKEN_ABSENT" if not token else "TOKEN_FORMAT", "Valid read-only GH_TOKEN required")
    return token


def authenticate_workflow_context(
    environ: Mapping[str, str],
    *,
    expected_p_commit: str | None = None,
    expected_run_id: int | None = None,
) -> tuple[str, int]:
    if environ.get("GITHUB_HEAD_REF") or environ.get("GITHUB_BASE_REF"):
        raise RuntimeBridgeError("CALLER_FORK_OR_PR_CONTEXT", "Pull request or fork context is forbidden")
    run_id_raw = environ.get("GITHUB_RUN_ID", "")
    sha_raw = environ.get("GITHUB_SHA", "")
    if (
        environ.get("GITHUB_ACTIONS") != "true"
        or environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or environ.get("GITHUB_REPOSITORY_OWNER") != REPOSITORY_OWNER
        or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environ.get("GITHUB_REF") != "refs/heads/main"
        or environ.get("GITHUB_REF_NAME") != "main"
        or environ.get("GITHUB_REF_TYPE") != "branch"
        or environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or type(run_id_raw) is not str
        or not _NUMERIC_ID.fullmatch(run_id_raw)
        or type(sha_raw) is not str
        or not _HEX40.fullmatch(sha_raw)
        or sha_raw == ("0" * 40)
    ):
        raise RuntimeBridgeError("CALLER_GITHUB_CONTEXT", "GitHub Actions main/manual/attempt-1 context required")
    if environ.get("GITHUB_WORKFLOW_REF") != EXPECTED_WORKFLOW_REF:
        raise RuntimeBridgeError("CALLER_WORKFLOW_REF", "Unexpected GITHUB_WORKFLOW_REF")
    run_id = int(run_id_raw)
    if expected_p_commit is not None and sha_raw != expected_p_commit:
        raise RuntimeBridgeError("CALLER_GITHUB_CONTEXT", "GITHUB_SHA does not match expected P commit")
    if expected_run_id is not None and run_id != expected_run_id:
        raise RuntimeBridgeError("CALLER_GITHUB_CONTEXT", "GITHUB_RUN_ID does not match binding run ID")
    return sha_raw, run_id


def _validate_physical_file_target(path: str | Path, label: str = "file path") -> Path:
    raw = os.fspath(path) if isinstance(path, (str, os.PathLike)) else ""
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\x00" in raw
        or "*" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise RuntimeBridgeError("PHYSICAL_PATH_REQUIRED", f"{label} must be a normalized physical absolute path")
    candidate = Path(raw)
    try:
        sc.physical_dir(candidate.parent, f"{label} parent")
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None
    return candidate


def _require_disjoint_from_checkouts_and_export(
    target: Path,
    *roots: Path,
) -> None:
    if any("current-signer-export" in part for part in target.parts):
        raise RuntimeBridgeError(
            "PATH_OVERLAP_FORBIDDEN",
            "Runtime bridge files and work roots must remain outside worker export mount",
        )
    for root in roots:
        if target == root or root in target.parents or target in root.parents:
            raise RuntimeBridgeError(
                "PATH_OVERLAP_FORBIDDEN",
                "Runtime bridge artifacts and work directories must be outside P and R checkouts",
            )


def _write_exclusive_0600_json(path: Path, payload: Mapping[str, Any], code: str = "EXCLUSIVE_WRITE_FAILED") -> None:
    parent = _validate_physical_file_target(path, "JSON output")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        fd = os.open(parent, _EXCLUSIVE_FILE_FLAGS, 0o600)
    except OSError as error:
        raise RuntimeBridgeError(code, "Failed to create exclusive 0600 JSON file") from error
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise RuntimeBridgeError(code, "Short write to exclusive JSON file")
            view = view[written:]
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeBridgeError(code, "Exclusive JSON file mode or link count invalid")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(parent)
        except OSError:
            pass
        raise
    else:
        os.close(fd)


def _read_held_0600_json(path: str | Path, code: str) -> tuple[dict[str, Any], bytes]:
    target = _validate_physical_file_target(path, "held JSON file")
    try:
        st = os.lstat(target)
    except OSError as error:
        raise RuntimeBridgeError(code, "Required JSON file is missing") from error
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise RuntimeBridgeError(code, "Held JSON file must be an unaliased regular file")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise RuntimeBridgeError(code, "Held JSON file must have mode 0600")
    try:
        raw = sc.held_regular_bytes(target)
        doc = sc.parse_strict_json(raw, code)
    except sc.ClosureError as error:
        raise RuntimeBridgeError(code, str(error)) from None
    return doc, raw


def _validate_github_output_value(key: str, value: str) -> None:
    if type(key) is not str or not _OUTPUT_KEY_RE.fullmatch(key):
        raise RuntimeBridgeError("GITHUB_OUTPUT_INVALID", "Invalid GITHUB_OUTPUT key")
    if (
        type(value) is not str
        or not (1 <= len(value) <= 256)
        or not value.isascii()
        or not value.isprintable()
        or "\n" in value
        or "\r" in value
        or "\x00" in value
        or "<<" in value
    ):
        raise RuntimeBridgeError("GITHUB_OUTPUT_INVALID", "Invalid or unsafe GITHUB_OUTPUT value")


def _append_github_outputs(github_output_path: str | Path, pairs: Sequence[tuple[str, str]]) -> None:
    target = _validate_physical_file_target(github_output_path, "GITHUB_OUTPUT")
    lines: list[str] = []
    for key, val in pairs:
        _validate_github_output_value(key, val)
        lines.append(f"{key}={val}\n")
    payload = "".join(lines).encode("ascii")
    try:
        st_before = os.lstat(target)
    except OSError as error:
        raise RuntimeBridgeError("GITHUB_OUTPUT_WRITE_FAILED", "GITHUB_OUTPUT file does not exist") from error
    if stat.S_ISLNK(st_before.st_mode) or not stat.S_ISREG(st_before.st_mode) or st_before.st_nlink != 1:
        raise RuntimeBridgeError("GITHUB_OUTPUT_WRITE_FAILED", "GITHUB_OUTPUT must be an unaliased regular file")
    try:
        fd = os.open(target, _APPEND_FILE_FLAGS)
    except OSError as error:
        raise RuntimeBridgeError("GITHUB_OUTPUT_WRITE_FAILED", "Unable to open GITHUB_OUTPUT") from error
    try:
        st_open = os.fstat(fd)
        if (
            not stat.S_ISREG(st_open.st_mode)
            or st_open.st_nlink != 1
            or (st_open.st_dev, st_open.st_ino) != (st_before.st_dev, st_before.st_ino)
        ):
            raise RuntimeBridgeError("GITHUB_OUTPUT_WRITE_FAILED", "GITHUB_OUTPUT identity changed on open")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise RuntimeBridgeError("GITHUB_OUTPUT_WRITE_FAILED", "Short write to GITHUB_OUTPUT")
            view = view[written:]
    finally:
        os.close(fd)


def verify_clean_p_checkout_and_resolve_tree(
    p_root: str | Path,
    expected_p_commit: str,
    *,
    git_runner: Callable[[tuple[str, ...], Path, Mapping[str, str]], tuple[int, bytes, bytes]] | None = None,
) -> tuple[Path, str]:
    try:
        p_dir = sc.physical_dir(p_root, "P source root")
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None
    _require_nonzero_hex40(expected_p_commit, "GIT_COMMIT_FORMAT")
    try:
        marker_info = os.lstat(p_dir / ".git")
    except OSError as error:
        raise RuntimeBridgeError("GIT_CHECKOUT_REQUIRED", "Missing .git in P checkout") from error
    if stat.S_ISLNK(marker_info.st_mode):
        raise RuntimeBridgeError("GIT_CHECKOUT_REQUIRED", "Symlinked .git in P checkout is forbidden")
    git_env = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(p_dir),
    }
    runner = git_runner or sc._default_git_runner
    try:
        rc_head, out_head, _ = runner((sc.GIT_BINARY, "rev-parse", "HEAD"), p_dir, git_env)
        rc_tree, out_tree, _ = runner((sc.GIT_BINARY, "rev-parse", f"{expected_p_commit}^{{tree}}"), p_dir, git_env)
        rc_stat, out_stat, _ = runner(
            (sc.GIT_BINARY, "status", "--porcelain", "--untracked-files=all", "--ignored"),
            p_dir,
            git_env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeBridgeError("GIT_COMMAND_FAILED", "P Git checkout inspection failed") from error
    if rc_head != 0 or rc_tree != 0 or rc_stat != 0:
        raise RuntimeBridgeError("GIT_COMMAND_FAILED", "P Git checkout inspection returned non-zero")
    head_str = out_head.decode("ascii", errors="replace").strip()
    tree_str = out_tree.decode("ascii", errors="replace").strip()
    if head_str != expected_p_commit or not _HEX40.fullmatch(tree_str) or tree_str == ("0" * 40) or out_stat:
        raise RuntimeBridgeError("GIT_CHECKOUT_DIRTY_OR_MISMATCH", "P checkout HEAD, tree, or cleanliness mismatch")
    return p_dir, tree_str


def _authenticate_closed_rs9_descriptor_in_p(p_dir: Path) -> tuple[dict[str, Any], str]:
    descriptor_path = p_dir / sc.DESCRIPTOR_REL_PATH
    try:
        raw = sc.held_regular_bytes(descriptor_path)
        doc = sc.parse_strict_json(raw, "DESCRIPTOR_SCHEMA")
    except sc.ClosureError as error:
        code = "DESCRIPTOR_ABSENT" if error.code == "SOURCE_FILE_MISSING" else error.code
        raise RuntimeBridgeError(code, str(error)) from None
    rs9 = doc.get("rs9")
    if not isinstance(rs9, dict):
        raise RuntimeBridgeError("DESCRIPTOR_UNADMITTED", "Descriptor rs9 object is missing")
    r_commit = rs9.get("source_commit")
    r_tree = rs9.get("source_tree")
    rs9_run = rs9.get("run_id")
    if (
        type(r_commit) is not str
        or not _HEX40.fullmatch(r_commit)
        or r_commit == ("0" * 40)
        or type(r_tree) is not str
        or not _HEX40.fullmatch(r_tree)
        or r_tree == ("0" * 40)
        or type(rs9_run) is not int
        or rs9_run <= 0
    ):
        raise RuntimeBridgeError("DESCRIPTOR_BINDING_MISMATCH", "Descriptor RS9 commit, tree, or run_id invalid")
    try:
        auth = sc.authenticate_rs9_descriptor(
            p_dir,
            expected_r_commit=r_commit,
            expected_r_tree=r_tree,
            expected_rs9_run=rs9_run,
        )
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None
    for hash_key in sc._RS9_HASH_KEYS:
        _require_nonzero_hex64(rs9.get(hash_key), "DESCRIPTOR_SCHEMA")
    return auth["descriptor"], auth["descriptor_sha256"]


def _format_rfc2822_utc(now: datetime | None = None) -> str:
    dt = datetime.now(timezone.utc) if now is None else now
    if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise RuntimeBridgeError("RELEASE_DATE_INVALID", "Release timestamp must be UTC")
    formatted = email.utils.format_datetime(dt, usegmt=False)
    if not _RFC2822_UTC_RE.fullmatch(formatted):
        raise RuntimeBridgeError("RELEASE_DATE_INVALID", "Formatted release date failed RFC 2822 UTC validation")
    return formatted


def _validate_binding_document(
    doc: dict[str, Any],
    *,
    expected_p_commit: str,
    expected_run_id: int,
) -> dict[str, Any]:
    required_keys = {
        "schema",
        "generation",
        "repository",
        "workflow_ref",
        "qualification_run_id",
        "run_attempt",
        "p_commit",
        "p_tree",
        "r_commit",
        "r_tree",
        "rs9_run",
        "leaf_manifest_sha256",
        "descriptor_sha256",
        "rs9_hashes",
        "challenge_nonce",
        "release_date",
        "production_authority",
        "signing_authority",
        "publication_authority",
    }
    if (
        set(doc) != required_keys
        or doc.get("schema") != BINDING_SCHEMA
        or doc.get("generation") != sc.CURRENT_GENERATION
        or doc.get("repository") != REPOSITORY
        or doc.get("workflow_ref") != EXPECTED_WORKFLOW_REF
        or type(doc.get("qualification_run_id")) is not int
        or doc.get("qualification_run_id") != expected_run_id
        or type(doc.get("run_attempt")) is not int
        or doc.get("run_attempt") != 1
        or _require_nonzero_hex40(doc.get("p_commit"), "BINDING_SCHEMA_INVALID") != expected_p_commit
        or doc.get("production_authority") is not False
        or doc.get("signing_authority") is not False
        or doc.get("publication_authority") is not False
    ):
        raise RuntimeBridgeError("BINDING_SCHEMA_INVALID", "Binding document schema or run/commit binding mismatch")
    _require_nonzero_hex40(doc.get("p_tree"), "BINDING_SCHEMA_INVALID")
    _require_nonzero_hex40(doc.get("r_commit"), "BINDING_SCHEMA_INVALID")
    _require_nonzero_hex40(doc.get("r_tree"), "BINDING_SCHEMA_INVALID")
    if type(doc.get("rs9_run")) is not int or doc["rs9_run"] <= 0:
        raise RuntimeBridgeError("BINDING_SCHEMA_INVALID", "Binding rs9_run must be a positive integer")
    leaf_sha = _require_nonzero_hex64(doc.get("leaf_manifest_sha256"), "LEAF_MANIFEST_UNADMITTED")
    _require_nonzero_hex64(doc.get("descriptor_sha256"), "BINDING_SCHEMA_INVALID")
    _require_nonzero_hex64(doc.get("challenge_nonce"), "BINDING_SCHEMA_INVALID")
    rel_date = doc.get("release_date")
    if type(rel_date) is not str or not _RFC2822_UTC_RE.fullmatch(rel_date):
        raise RuntimeBridgeError("BINDING_SCHEMA_INVALID", "Binding release_date must be RFC 2822 UTC")
    rs9_hashes = doc.get("rs9_hashes")
    if not isinstance(rs9_hashes, dict) or set(rs9_hashes) != set(sc._RS9_HASH_KEYS):
        raise RuntimeBridgeError("BINDING_SCHEMA_INVALID", "Binding rs9_hashes key set invalid")
    for k in sc._RS9_HASH_KEYS:
        _require_nonzero_hex64(rs9_hashes.get(k), "BINDING_SCHEMA_INVALID")
    if leaf_sha == ("0" * 64):
        raise RuntimeBridgeError("LEAF_MANIFEST_UNADMITTED", "Leaf manifest pin is unadmitted")
    return doc


def execute_plan(
    *,
    p_root: str | Path,
    p_commit: str,
    leaf_manifest_sha256: str,
    binding_out: str | Path,
    github_output: str | Path,
    environ: Mapping[str, str] | None = None,
    git_runner: Callable[[tuple[str, ...], Path, Mapping[str, str]], tuple[int, bytes, bytes]] | None = None,
    uname_fn: Callable[[], Any] = os.uname,
    now_fn: Callable[[], datetime] | None = None,
    nonce_fn: Callable[[], str] | None = None,
    require_isolated_flags: bool = True,
    require_unimported: bool = True,
) -> dict[str, Any]:
    require_isolated_python(require_isolated_flags=require_isolated_flags)
    verify_native_linux_amd64_host(uname_fn=uname_fn)
    env = os.environ if environ is None else environ
    require_key_free_bridge_env(env, allow_gh_token=False)
    _require_nonzero_hex40(p_commit, "GIT_COMMIT_FORMAT")
    if type(leaf_manifest_sha256) is not str or not _HEX64.fullmatch(leaf_manifest_sha256):
        raise RuntimeBridgeError("LEAF_MANIFEST_PIN_FORMAT", "Leaf manifest SHA-256 must be 64-hex")
    if leaf_manifest_sha256 == ("0" * 64):
        raise RuntimeBridgeError("LEAF_MANIFEST_UNADMITTED", "Leaf manifest SHA-256 is zero/unadmitted")
    _, run_id = authenticate_workflow_context(env, expected_p_commit=p_commit)

    p_dir, p_tree = verify_clean_p_checkout_and_resolve_tree(p_root, p_commit, git_runner=git_runner)
    binding_path = _validate_physical_file_target(binding_out, "binding output")
    gh_out_path = _validate_physical_file_target(github_output, "GITHUB_OUTPUT")
    _require_disjoint_from_checkouts_and_export(binding_path, p_dir)
    _require_disjoint_from_checkouts_and_export(gh_out_path, p_dir)

    try:
        sc.authenticate_leaf_closure(
            p_dir,
            expected_leaf_manifest_sha256=leaf_manifest_sha256,
            require_unimported=require_unimported,
        )
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None

    descriptor_doc, descriptor_sha256 = _authenticate_closed_rs9_descriptor_in_p(p_dir)
    rs9 = descriptor_doc["rs9"]
    r_commit = rs9["source_commit"]
    r_tree = rs9["source_tree"]
    rs9_run = rs9["run_id"]

    # Recheck P checkout and leaf closure before emitting outputs
    _, p_tree_recheck = verify_clean_p_checkout_and_resolve_tree(p_dir, p_commit, git_runner=git_runner)
    if p_tree_recheck != p_tree:
        raise RuntimeBridgeError("SOURCE_STATE_CHANGED", "P tree changed during plan verification")
    try:
        sc.authenticate_leaf_closure(
            p_dir,
            expected_leaf_manifest_sha256=leaf_manifest_sha256,
            require_unimported=require_unimported,
        )
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None

    challenge_nonce = secrets.token_hex(32) if nonce_fn is None else nonce_fn()
    _require_nonzero_hex64(challenge_nonce, "CHALLENGE_NONCE_INVALID")
    release_date = _format_rfc2822_utc(None if now_fn is None else now_fn())

    binding: dict[str, Any] = {
        "schema": BINDING_SCHEMA,
        "generation": sc.CURRENT_GENERATION,
        "repository": REPOSITORY,
        "workflow_ref": EXPECTED_WORKFLOW_REF,
        "qualification_run_id": run_id,
        "run_attempt": 1,
        "p_commit": p_commit,
        "p_tree": p_tree,
        "r_commit": r_commit,
        "r_tree": r_tree,
        "rs9_run": rs9_run,
        "leaf_manifest_sha256": leaf_manifest_sha256,
        "descriptor_sha256": descriptor_sha256,
        "rs9_hashes": {k: rs9[k] for k in sc._RS9_HASH_KEYS},
        "challenge_nonce": challenge_nonce,
        "release_date": release_date,
        "production_authority": False,
        "signing_authority": False,
        "publication_authority": False,
    }
    _validate_binding_document(binding, expected_p_commit=p_commit, expected_run_id=run_id)
    _write_exclusive_0600_json(binding_path, binding, "BINDING_WRITE_FAILED")
    try:
        _append_github_outputs(
            gh_out_path,
            (
                ("p_tree", p_tree),
                ("r_commit", r_commit),
                ("r_tree", r_tree),
                ("rs9_run", str(rs9_run)),
                ("leaf_manifest_sha256", leaf_manifest_sha256),
                ("challenge_nonce", challenge_nonce),
                ("release_date", release_date),
            ),
        )
    except BaseException:
        try:
            os.unlink(binding_path)
        except OSError:
            pass
        raise
    return binding


def _authenticate_checkouts_and_binding(
    *,
    p_root: str | Path,
    r_root: str | Path,
    binding_file: str | Path,
    environ: MutableMapping[str, str],
    git_runner: Callable[[tuple[str, ...], Path, Mapping[str, str]], tuple[int, bytes, bytes]] | None,
    require_unimported: bool,
) -> tuple[Path, Path, dict[str, Any]]:
    try:
        p_dir = sc.physical_dir(p_root, "P source root")
        r_dir = sc.physical_dir(r_root, "R source root")
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None
    binding_path = _validate_physical_file_target(binding_file, "binding file")
    _require_disjoint_from_checkouts_and_export(binding_path, p_dir, r_dir)

    sha_raw, run_id = authenticate_workflow_context(environ)
    binding_doc, _ = _read_held_0600_json(binding_path, "BINDING_FILE_INVALID")
    binding = _validate_binding_document(binding_doc, expected_p_commit=sha_raw, expected_run_id=run_id)

    try:
        sc.authenticate_leaf_closure(
            p_dir,
            expected_leaf_manifest_sha256=binding["leaf_manifest_sha256"],
            require_unimported=require_unimported,
        )
        git_env = sc.apply_process_git_scope(p_dir, r_dir, target_env=environ)
        sc.verify_clean_git_checkout(
            p_dir,
            binding["p_commit"],
            binding["p_tree"],
            git_env=git_env,
            git_runner=git_runner,
        )
        sc.verify_clean_git_checkout(
            r_dir,
            binding["r_commit"],
            binding["r_tree"],
            git_env=git_env,
            git_runner=git_runner,
        )
        desc_auth = sc.authenticate_rs9_descriptor(
            p_dir,
            expected_r_commit=binding["r_commit"],
            expected_r_tree=binding["r_tree"],
            expected_rs9_run=binding["rs9_run"],
        )
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None

    rs9_info = desc_auth["descriptor"]["rs9"]
    if (
        desc_auth["descriptor_sha256"] != binding["descriptor_sha256"]
        or {k: rs9_info[k] for k in sc._RS9_HASH_KEYS} != binding["rs9_hashes"]
    ):
        raise RuntimeBridgeError("DESCRIPTOR_BINDING_MISMATCH", "Descriptor digest or R hashes differ from binding")
    return p_dir, r_dir, binding


def _import_authenticated_runtime_leaves(p_dir: Path) -> tuple[Any, Any]:
    """Import image builder and quarantine intake leaves after P and M authentication.

    Under the held root bootstrap (`current_import_routing.py`), `_HeldLeafLoader` guarantees
    that imports execute from the in-memory `leaf_bytes` mapping verified against `LEAF_MANIFEST_SHA256`.
    For direct/non-root execution, this helper also checks each loaded module's `__file__` bytes
    against both the physical file in `p_dir` and the authenticated `leaf-manifest.json` digest.
    """
    current_signer_dir = p_dir / sc.CURRENT_SIGNER_REL_DIR
    if str(current_signer_dir) not in sys.path:
        sys.path.insert(0, str(current_signer_dir))
    import signing_image_build as sib  # noqa: E402
    import runtime_input_intake as rii  # noqa: E402

    try:
        manifest_raw = sc.held_regular_bytes(p_dir / sc.LEAF_MANIFEST_REL_PATH)
        manifest_files = sc.parse_strict_json(manifest_raw, "LEAF_MANIFEST_SCHEMA").get("files", {})
    except sc.ClosureError as error:
        raise RuntimeBridgeError(error.code, str(error)) from None

    for mod, filename in ((sib, "signing_image_build.py"), (rii, "runtime_input_intake.py")):
        mod_file = getattr(mod, "__file__", None)
        if not isinstance(mod_file, str):
            raise RuntimeBridgeError("LEAF_MODULE_IDENTITY", f"Missing __file__ on {filename}")
        rel_key = f"{sc.CURRENT_SIGNER_REL_DIR}/{filename}"
        expected_manifest_sha = manifest_files.get(rel_key)
        expected_bytes = sc.held_regular_bytes(current_signer_dir / filename)
        actual_bytes = sc.held_regular_bytes(Path(mod_file))
        actual_sha = _sha256_hex(actual_bytes)
        if actual_sha != _sha256_hex(expected_bytes) or actual_sha != expected_manifest_sha:
            raise RuntimeBridgeError("EXECUTING_BOOTSTRAP_MISMATCH", f"Loaded {filename} differs from P checkout")
    return sib, rii


def _create_owned_0700_dir(path: Path, code: str = "WORK_ROOT_CREATE_FAILED") -> tuple[int, int, int, int, int]:
    target = _validate_physical_file_target(path, "owned directory")
    try:
        os.mkdir(target, 0o700)
    except OSError as error:
        raise RuntimeBridgeError(code, "Failed to create exclusive 0700 directory") from error
    try:
        os.chmod(target, 0o700)
        info = os.lstat(target)
    except OSError as error:
        try:
            os.rmdir(target)
        except OSError:
            pass
        raise RuntimeBridgeError(code, "Failed to stat exclusive 0700 directory") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        try:
            os.rmdir(target)
        except OSError:
            pass
        raise RuntimeBridgeError(code, "Owned directory mode invalid")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


def _cleanup_owned_tree(
    root: Path, allowed_subdirs: set[str], *, failure_sink: list[dict[str, str]] | None = None,
) -> bool:
    """Keep existing cleanup decisions; optionally retain closed refusal labels."""
    scope, operation = "ROOT", "EXISTS"

    def refused(category: str, error: OSError | None = None) -> bool:
        bucket = "NONE" if error is None else {
            errno.EACCES: "EACCES", errno.EPERM: "EPERM", errno.ENOENT: "ENOENT",
            errno.ENOTEMPTY: "ENOTEMPTY", errno.EBUSY: "EBUSY", errno.EIO: "EIO",
        }.get(error.errno, "OTHER")
        if failure_sink is not None:
            failure_sink.append({
                "category": category, "scope": scope, "operation": operation, "errno": bucket,
            })
        return False

    if not root.exists():
        return True
    try:
        operation = "LSTAT"
        info = os.lstat(root)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            return refused("ROOT_SYMLINK" if stat.S_ISLNK(info.st_mode) else
                           "ROOT_NOT_DIRECTORY" if not stat.S_ISDIR(info.st_mode) else
                           "ROOT_FOREIGN_OWNER")
        operation = "LISTDIR"
        entries = set(os.listdir(root))
        if not entries <= allowed_subdirs:
            return refused("ROOT_ENTRIES")
        for sub_name in sorted(entries):
            scope = {"build": "BUILD", "quarantine": "QUARANTINE", "transport": "TRANSPORT"}.get(sub_name, "OTHER")
            sub_path = root / sub_name
            operation = "LSTAT"
            sub_info = os.lstat(sub_path)
            if stat.S_ISLNK(sub_info.st_mode) or not stat.S_ISDIR(sub_info.st_mode) or sub_info.st_uid != os.geteuid():
                return refused("SUBDIR_SYMLINK" if stat.S_ISLNK(sub_info.st_mode) else
                               "SUBDIR_NOT_DIRECTORY" if not stat.S_ISDIR(sub_info.st_mode) else
                               "SUBDIR_FOREIGN_OWNER")
            operation = "LISTDIR"
            child_names = sorted(os.listdir(sub_path))
            for child_name in child_names:
                scope = {"build": "BUILD", "quarantine": "QUARANTINE", "transport": "TRANSPORT"}.get(sub_name, "OTHER")
                child_path = sub_path / child_name
                operation = "LSTAT"
                cinfo = os.lstat(child_path)
                if stat.S_ISLNK(cinfo.st_mode) or cinfo.st_uid != os.geteuid():
                    return refused("CHILD_SYMLINK" if stat.S_ISLNK(cinfo.st_mode) else
                                   "CHILD_FOREIGN_OWNER")
                if stat.S_ISDIR(cinfo.st_mode):
                    if sub_name != "transport" or child_name != "gh-config":
                        return refused("NESTED_DIRECTORY")
                    scope, operation = "GH_CONFIG", "LISTDIR"
                    for gname in sorted(os.listdir(child_path)):
                        gpath = child_path / gname
                        operation = "LSTAT"
                        ginfo = os.lstat(gpath)
                        if not stat.S_ISREG(ginfo.st_mode) or ginfo.st_nlink != 1 or ginfo.st_uid != os.geteuid():
                            return refused("GH_CONFIG_NOT_REGULAR" if not stat.S_ISREG(ginfo.st_mode) else
                                           "GH_CONFIG_LINK_COUNT" if ginfo.st_nlink != 1 else
                                           "GH_CONFIG_FOREIGN_OWNER")
                        operation = "UNLINK"
                        os.unlink(gpath)
                    operation = "RMDIR"
                    os.rmdir(child_path)
                elif stat.S_ISREG(cinfo.st_mode) and cinfo.st_nlink == 1:
                    operation = "UNLINK"
                    os.unlink(child_path)
                else:
                    return refused("CHILD_LINK_COUNT" if stat.S_ISREG(cinfo.st_mode) else
                                   "CHILD_SPECIAL_FILE")
            scope = {"build": "BUILD", "quarantine": "QUARANTINE", "transport": "TRANSPORT"}.get(sub_name, "OTHER")
            operation = "RMDIR"
            os.rmdir(sub_path)
        scope, operation = "ROOT", "RMDIR"
        os.rmdir(root)
        return True
    except OSError as error:
        return refused("FILESYSTEM", error)


def execute_prepare_image(
    *,
    p_root: str | Path,
    r_root: str | Path,
    binding_file: str | Path,
    work_root: str | Path,
    image_receipt: str | Path,
    github_output: str | Path,
    environ: MutableMapping[str, str] | None = None,
    git_runner: Callable[[tuple[str, ...], Path, Mapping[str, str]], tuple[int, bytes, bytes]] | None = None,
    transport_factory: Callable[[str, str], Any] | None = None,
    engine_factory: Callable[[], Any] | None = None,
    uname_fn: Callable[[], Any] = os.uname,
    require_isolated_flags: bool = True,
    require_unimported: bool = True,
    source_digest_fn: Callable[[str, bytes], tuple[int, str]] | None = None,
) -> dict[str, Any]:
    require_isolated_python(require_isolated_flags=require_isolated_flags)
    verify_native_linux_amd64_host(uname_fn=uname_fn)
    env = os.environ if environ is None else environ
    token = pop_readonly_gh_token(env)
    try:
        p_dir, r_dir, binding = _authenticate_checkouts_and_binding(
            p_root=p_root,
            r_root=r_root,
            binding_file=binding_file,
            environ=env,
            git_runner=git_runner,
            require_unimported=require_unimported,
        )
        work_dir = _validate_physical_file_target(work_root, "work root")
        receipt_path = _validate_physical_file_target(image_receipt, "image receipt")
        gh_out_path = _validate_physical_file_target(github_output, "GITHUB_OUTPUT")
        for target in (work_dir, receipt_path, gh_out_path):
            _require_disjoint_from_checkouts_and_export(target, p_dir, r_dir)
        if receipt_path == work_dir or work_dir in receipt_path.parents:
            raise RuntimeBridgeError("PATH_OVERLAP_FORBIDDEN", "Image receipt must be outside transient work root")

        sib, rii = _import_authenticated_runtime_leaves(p_dir)

        # Refuse zero/unadmitted runtime image class BEFORE any API or Docker engine activity
        if sib.CLASS_ADMISSION_GATE_OPEN is not True or not sib._admitted_pin_matches(sib.ADMITTED_MANIFEST_SHA256):
            raise RuntimeBridgeError(
                "IMAGE_CLASS_NOT_ADMITTED",
                "Runtime image class gate or admitted manifest pin is held/unadmitted in source",
            )

        manifest_path = p_dir / RUNTIME_ADMISSION_MANIFEST_REL_PATH
        certificate_path = p_dir / FEDORA_CERT_REL_PATH
        base_root_proof_path = p_dir / BASE_ROOT_PROOF_REL_PATH
        base_metadata_proof_path = p_dir / BASE_METADATA_PROOF_REL_PATH
        supplemental_notice_manifest_path = p_dir / SUPPLEMENTAL_NOTICE_MANIFEST_REL_PATH
        supplemental_notice_dir = p_dir / SUPPLEMENTAL_NOTICE_DIR_REL_PATH

        try:
            sib.authenticate_admission_manifest(
                manifest_path,
                expected_manifest_sha256=sib.ADMITTED_MANIFEST_SHA256,
            )
            cert_bytes = sib.held_unaliased_bytes(certificate_path, max_bytes=sib.MAX_SMALL_SOURCE_BYTES)
            sib.verify_selected_fedora_certificate_bytes(cert_bytes)
            proof_bytes = sib.held_unaliased_bytes(base_root_proof_path, max_bytes=sib.MAX_SMALL_SOURCE_BYTES)
            if sib.sha256_hex(proof_bytes) != sib.BASE_ROOT_PROOF_SHA256:
                raise sib.ImageBuildError("BASE_ROOT_PROOF_INVALID", "Base-resident root proof digest mismatch")
            metadata_bytes = sib.held_unaliased_bytes(base_metadata_proof_path, max_bytes=sib.MAX_SMALL_SOURCE_BYTES)
            sib._verify_physical_base_metadata_proof(metadata_bytes)
            notice_manifest_bytes = sib.held_unaliased_bytes(
                supplemental_notice_manifest_path,
                max_bytes=sib.MAX_SMALL_SOURCE_BYTES,
            )
            sib._verify_physical_supplemental_notices(
                notice_manifest_bytes,
                supplemental_notice_dir,
                source_digest_fn=source_digest_fn,
            )
        except sib.ImageBuildError as error:
            raise RuntimeBridgeError(error.code, error.reason, custody_retained=error.custody_retained) from None

        _create_owned_0700_dir(work_dir, "WORK_ROOT_CREATE_FAILED")
        transport_dir = work_dir / "transport"
        quarantine_dir = work_dir / "quarantine"
        build_work_dir = work_dir / "build"
        custody_retained = False
        work_root_cleanup_attempted = False
        cleanup_observations: list[dict[str, str]] = []
        try:
            _create_owned_0700_dir(build_work_dir, "WORK_ROOT_CREATE_FAILED")
            try:
                t_factory = transport_factory or (lambda tok, tdir: rii.RuntimeInputTransport(tok, str(tdir)))
                transport = t_factory(token, str(transport_dir))
                token = ""
                rii.prepare_pinned_runtime_inputs(transport, quarantine_dir, environ=env)
            except rii.IntakeError as error:
                custody_retained = custody_retained or error.custody_retained
                raise RuntimeBridgeError(
                    error.code,
                    "Runtime quarantine intake refused",
                    custody_retained=custody_retained,
                ) from None
            except rii.gh.PublicationError as error:
                custody_retained = custody_retained or bool(rii.gh._RETAINED_CHILDREN)
                raise RuntimeBridgeError(
                    error.code,
                    "Runtime quarantine transport initialization refused",
                    custody_retained=custody_retained,
                ) from None
            finally:
                token = ""

            quarantine_json = quarantine_dir / "QUARANTINE.json"
            try:
                q_raw = sib.held_unaliased_bytes(quarantine_json, max_bytes=sib.MAX_SMALL_SOURCE_BYTES)
                if sib.sha256_hex(q_raw) != sib.QUARANTINE_SHA256:
                    raise RuntimeBridgeError("QUARANTINE_MANIFEST_MISMATCH", "Materialized QUARANTINE.json mismatch")
                os.unlink(quarantine_json)
            except sib.ImageBuildError as error:
                raise RuntimeBridgeError(error.code, error.reason) from None
            except OSError as error:
                custody_retained = True
                raise RuntimeBridgeError(
                    "QUARANTINE_UNLINK_FAILED",
                    "Failed to unlink materialized QUARANTINE.json",
                    custody_retained=True,
                ) from error

            # Recheck P/R checkouts and leaf closure immediately before engine execution
            _authenticate_checkouts_and_binding(
                p_root=p_dir,
                r_root=r_dir,
                binding_file=binding_file,
                environ=env,
                git_runner=git_runner,
                require_unimported=False,
            )

            engine = (
                sib.BoundedDockerSubprocessEngine(allow_native_execution=True)
                if engine_factory is None
                else engine_factory()
            )
            try:
                build_result = sib.execute_signing_image_build(
                    manifest_path=manifest_path,
                    expected_manifest_sha256=sib.ADMITTED_MANIFEST_SHA256,
                    archive_dir=quarantine_dir,
                    certificate_path=certificate_path,
                    base_root_proof_path=base_root_proof_path,
                    base_metadata_proof_path=base_metadata_proof_path,
                    supplemental_notice_manifest_path=supplemental_notice_manifest_path,
                    supplemental_notice_dir=supplemental_notice_dir,
                    work_root=build_work_dir,
                    run_id_suffix=str(binding["qualification_run_id"]),
                    engine=engine,
                    caller_env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                    source_digest_fn=source_digest_fn,
                )
            except sib.ImageBuildError as error:
                custody_retained = custody_retained or error.custody_retained
                raise RuntimeBridgeError(
                    error.code,
                    error.reason,
                    custody_retained=custody_retained,
                ) from None

            receipt_written = False
            try:
                host_kwargs = sib.to_host_controller_image_kwargs(build_result)
                lease_doc: dict[str, Any] = {
                    "schema": LEASE_RECEIPT_SCHEMA,
                    "status": "leased-for-same-job-host-controller",
                    "qualification_run_id": binding["qualification_run_id"],
                    "run_id_suffix": str(binding["qualification_run_id"]),
                    "p_commit": binding["p_commit"],
                    "p_tree": binding["p_tree"],
                    "r_commit": binding["r_commit"],
                    "r_tree": binding["r_tree"],
                    "rs9_run": binding["rs9_run"],
                    "leaf_manifest_sha256": binding["leaf_manifest_sha256"],
                    "descriptor_sha256": binding["descriptor_sha256"],
                    "manifest_sha256": build_result.manifest_sha256,
                    "recipe_sha256": build_result.recipe_sha256,
                    "base_image": sib.APPROVED_BASE_IMAGE,
                    "base_image_id": f"sha256:{sib.APPROVED_BASE_IMAGE_DIGEST}",
                    "build_tag": build_result.build_tag,
                    "image_id": build_result.image_id,
                    "container_python": host_kwargs["container_python"],
                    "expected_gpg_sha256": host_kwargs["expected_gpg_sha256"],
                    "expected_rpm_sha256": host_kwargs["expected_rpm_sha256"],
                    "built_image_retained_for_host_controller": True,
                    "image_disposal_obligation": sib.IMAGE_DISPOSAL_OBLIGATION,
                    "custody_retained": False,
                    "signing_authority": False,
                    "publication_authority": False,
                }
                _write_exclusive_0600_json(receipt_path, lease_doc, "LEASE_RECEIPT_WRITE_FAILED")
                receipt_written = True
                _append_github_outputs(
                    gh_out_path,
                    (
                        ("container_image", host_kwargs["container_image"]),
                        ("container_python", host_kwargs["container_python"]),
                        ("expected_gpg_sha256", host_kwargs["expected_gpg_sha256"]),
                        ("expected_rpm_sha256", host_kwargs["expected_rpm_sha256"]),
                    ),
                )
                work_root_cleanup_attempted = True
                if not _cleanup_owned_tree(work_dir, {"transport", "quarantine", "build"}, failure_sink=cleanup_observations):
                    _RETAINED_BRIDGE_CUSTODY.append({"kind": "work_root", "path": str(work_dir)})
                    raise RuntimeBridgeError(
                        "WORK_ROOT_CLEANUP_FAILED",
                        "Failed to clean transient runtime image work root",
                        custody_retained=True,
                        cleanup_observation=cleanup_observations[-1] if cleanup_observations else None,
                    )
            except BaseException as post_err:
                if receipt_written:
                    try:
                        os.unlink(receipt_path)
                    except OSError:
                        custody_retained = True
                try:
                    sib.dispose_built_image(build_result, engine)
                except BaseException:
                    custody_retained = True
                    _RETAINED_BRIDGE_CUSTODY.append(
                        {
                            "kind": "built_image_post_failure",
                            "build_tag": build_result.build_tag,
                            "image_id": build_result.image_id,
                        }
                    )
                if isinstance(post_err, sib.ImageBuildError):
                    raise RuntimeBridgeError(
                        post_err.code,
                        post_err.reason,
                        custody_retained=custody_retained or post_err.custody_retained,
                    ) from None
                if isinstance(post_err, RuntimeBridgeError):
                    raise RuntimeBridgeError(
                        post_err.code,
                        post_err.reason,
                        custody_retained=custody_retained or post_err.custody_retained,
                        cleanup_observation=post_err.cleanup_observation,
                    ) from None
                raise
            return lease_doc
        finally:
            if not work_root_cleanup_attempted:
                cleaned = _cleanup_owned_tree(work_dir, {"transport", "quarantine", "build"}, failure_sink=cleanup_observations)
                if not cleaned:
                    _RETAINED_BRIDGE_CUSTODY.append({"kind": "work_root", "path": str(work_dir)})
                    active_exc = sys.exc_info()[1]
                    if isinstance(active_exc, RuntimeBridgeError):
                        active_exc.custody_retained = True
                        observation = cleanup_observations[-1] if cleanup_observations else None
                        active_exc.cleanup_observation = RuntimeBridgeError(
                            active_exc.code, cleanup_observation=observation,
                        ).cleanup_observation
                    elif active_exc is None:
                        raise RuntimeBridgeError(
                            "WORK_ROOT_CLEANUP_FAILED",
                            "Failed to clean transient runtime image work root",
                            custody_retained=True,
                            cleanup_observation=cleanup_observations[-1] if cleanup_observations else None,
                        )
    finally:
        token = ""


def _validate_lease_receipt(
    doc: dict[str, Any],
    *,
    binding: Mapping[str, Any],
    sib: Any,
    expected_build_tag: str,
) -> dict[str, Any]:
    required_keys = {
        "schema",
        "status",
        "qualification_run_id",
        "run_id_suffix",
        "p_commit",
        "p_tree",
        "r_commit",
        "r_tree",
        "rs9_run",
        "leaf_manifest_sha256",
        "descriptor_sha256",
        "manifest_sha256",
        "recipe_sha256",
        "base_image",
        "base_image_id",
        "build_tag",
        "image_id",
        "container_python",
        "expected_gpg_sha256",
        "expected_rpm_sha256",
        "built_image_retained_for_host_controller",
        "image_disposal_obligation",
        "custody_retained",
        "signing_authority",
        "publication_authority",
    }
    if (
        set(doc) != required_keys
        or doc.get("schema") != LEASE_RECEIPT_SCHEMA
        or doc.get("status") != "leased-for-same-job-host-controller"
        or doc.get("qualification_run_id") != binding["qualification_run_id"]
        or doc.get("run_id_suffix") != str(binding["qualification_run_id"])
        or doc.get("p_commit") != binding["p_commit"]
        or doc.get("p_tree") != binding["p_tree"]
        or doc.get("r_commit") != binding["r_commit"]
        or doc.get("r_tree") != binding["r_tree"]
        or doc.get("rs9_run") != binding["rs9_run"]
        or doc.get("leaf_manifest_sha256") != binding["leaf_manifest_sha256"]
        or doc.get("descriptor_sha256") != binding["descriptor_sha256"]
        or doc.get("base_image") != sib.APPROVED_BASE_IMAGE
        or doc.get("build_tag") != expected_build_tag
        or doc.get("container_python") != sib.CONTAINER_PYTHON_PATH
        or doc.get("built_image_retained_for_host_controller") is not True
        or doc.get("image_disposal_obligation") != sib.IMAGE_DISPOSAL_OBLIGATION
        or doc.get("custody_retained") is not False
        or doc.get("signing_authority") is not False
        or doc.get("publication_authority") is not False
    ):
        raise RuntimeBridgeError("LEASE_RECEIPT_INVALID", "Image lease receipt schema or source/run binding mismatch")
    _require_nonzero_hex64(doc.get("manifest_sha256"), "LEASE_RECEIPT_INVALID")
    if doc.get("recipe_sha256") != sib.EXPECTED_DOCKERFILE_SHA256:
        raise RuntimeBridgeError("LEASE_RECEIPT_INVALID", "Image lease recipe_sha256 mismatch")
    _require_nonzero_hex64(doc.get("expected_gpg_sha256"), "LEASE_RECEIPT_INVALID")
    _require_nonzero_hex64(doc.get("expected_rpm_sha256"), "LEASE_RECEIPT_INVALID")
    try:
        image_id = sib.require_local_image_id(doc.get("image_id"), "LEASE_IMAGE_ID_INVALID")
    except sib.ImageBuildError as error:
        raise RuntimeBridgeError(error.code, error.reason) from None
    base_image_id = doc.get("base_image_id")
    if (
        type(base_image_id) is not str
        or not sib._LOCAL_IMAGE_ID_RE.fullmatch(base_image_id)
        or base_image_id == ("sha256:" + ("0" * 64))
        or image_id == base_image_id
    ):
        raise RuntimeBridgeError("LEASE_IMAGE_ID_INVALID", "Lease image_id must differ from base_image_id")
    return doc


def execute_release_image(
    *,
    p_root: str | Path,
    r_root: str | Path,
    binding_file: str | Path,
    image_receipt: str | Path,
    environ: MutableMapping[str, str] | None = None,
    git_runner: Callable[[tuple[str, ...], Path, Mapping[str, str]], tuple[int, bytes, bytes]] | None = None,
    engine_factory: Callable[[], Any] | None = None,
    uname_fn: Callable[[], Any] = os.uname,
    require_isolated_flags: bool = True,
    require_unimported: bool = True,
) -> dict[str, Any]:
    require_isolated_python(require_isolated_flags=require_isolated_flags)
    verify_native_linux_amd64_host(uname_fn=uname_fn)
    env = os.environ if environ is None else environ
    require_key_free_bridge_env(env, allow_gh_token=False)

    p_dir, r_dir, binding = _authenticate_checkouts_and_binding(
        p_root=p_root,
        r_root=r_root,
        binding_file=binding_file,
        environ=env,
        git_runner=git_runner,
        require_unimported=require_unimported,
    )
    receipt_path = _validate_physical_file_target(image_receipt, "image receipt")
    _require_disjoint_from_checkouts_and_export(receipt_path, p_dir, r_dir)

    sib, _ = _import_authenticated_runtime_leaves(p_dir)
    run_suffix = str(binding["qualification_run_id"])
    plan = sib.build_command_plan(run_suffix, p_dir)

    lease_doc, _ = _read_held_0600_json(receipt_path, "LEASE_RECEIPT_INVALID")
    lease = _validate_lease_receipt(
        lease_doc,
        binding=binding,
        sib=sib,
        expected_build_tag=plan.build_tag,
    )

    engine = (
        sib.BoundedDockerSubprocessEngine(allow_native_execution=True)
        if engine_factory is None
        else engine_factory()
    )
    cleanup_view = sib.ImageBuildResult(
        status="cleanup-only-lease",
        execution_mode="cleanup-only-lease",
        manifest_sha256=lease["manifest_sha256"],
        recipe_sha256=lease["recipe_sha256"],
        image_id=lease["image_id"],
        container_python=sib.CONTAINER_PYTHON_PATH,
        tool_digests={},
        tool_bytes={},
        tool_versions={},
        step_receipts=(),
        context_cleaned=True,
        custody_retained=False,
        retained_custody_count=0,
        native_execution_observed=False,
        native_ready_for_host_controller=False,
        build_tag=plan.build_tag,
        built_image_retained_for_host_controller=False,
        image_disposal_obligation=sib.IMAGE_DISPOSAL_OBLIGATION,
        image_runtime_class_admitted=False,
        native_qualification_satisfied=False,
        license_clearance_admitted=False,
        signing_authority=False,
        publication_authority=False,
    )
    try:
        disposal = sib.dispose_built_image(cleanup_view, engine)
    except sib.ImageBuildError as error:
        if error.code == "IMAGE_ID_INVALID":
            _RETAINED_BRIDGE_CUSTODY.append(
                {
                    "kind": "lease_base_image_collision",
                    "build_tag": plan.build_tag,
                    "image_id": lease["image_id"],
                }
            )
            raise RuntimeBridgeError(
                "LEASE_IMAGE_ID_INVALID",
                "Leased or tagged image ID collides with local base image config ID",
                custody_retained=True,
            ) from None
        if error.code == "IMAGE_TAG_TARGET_MISMATCH":
            _RETAINED_BRIDGE_CUSTODY.append(
                {
                    "kind": "lease_tag_image_mismatch",
                    "build_tag": plan.build_tag,
                    "expected_image_id": lease["image_id"],
                }
            )
            raise RuntimeBridgeError(
                "LEASE_TAG_IMAGE_MISMATCH",
                "Daemon tag-to-image ID disagrees with lease receipt; refusing foreign removal",
                custody_retained=True,
            ) from None
        custody_kind = (
            "lease_disposal_failed"
            if error.code == "IMAGE_DISPOSAL_UNCONFIRMED"
            else "lease_tag_inspect_failed"
        )
        _RETAINED_BRIDGE_CUSTODY.append(
            {"kind": custody_kind, "build_tag": plan.build_tag, "image_id": lease["image_id"]}
        )
        raise RuntimeBridgeError(error.code, error.reason, custody_retained=True) from None
    return {
        "schema": "tf.current-signer-runtime-image-release.v1",
        "qualification_run_id": binding["qualification_run_id"],
        "build_tag": plan.build_tag,
        "image_id": lease["image_id"],
        "tag_removed": disposal["tag_removed"],
        "image_id_removed": disposal["image_id_removed"],
        "custody_retained": False,
        "native_ready_for_host_controller": False,
        "signing_authority": False,
        "publication_authority": False,
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runtime_workflow_bridge.py",
        description="Bounded Theme Forge runtime workflow bridge",
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    plan_p = sub.add_parser("plan", allow_abbrev=False)
    plan_p.add_argument("--p-root", dest="p_root", required=True)
    plan_p.add_argument("--p-commit", dest="p_commit", required=True)
    plan_p.add_argument("--leaf-manifest-sha256", dest="leaf_manifest_sha256", required=True)
    plan_p.add_argument("--binding-out", dest="binding_out", required=True)
    plan_p.add_argument("--github-output", dest="github_output", required=True)

    prep_p = sub.add_parser("prepare-image", allow_abbrev=False)
    prep_p.add_argument("--p-root", dest="p_root", required=True)
    prep_p.add_argument("--r-root", dest="r_root", required=True)
    prep_p.add_argument("--binding-file", dest="binding_file", required=True)
    prep_p.add_argument("--work-root", dest="work_root", required=True)
    prep_p.add_argument("--image-receipt", dest="image_receipt", required=True)
    prep_p.add_argument("--github-output", dest="github_output", required=True)

    rel_p = sub.add_parser("release-image", allow_abbrev=False)
    rel_p.add_argument("--p-root", dest="p_root", required=True)
    rel_p.add_argument("--r-root", dest="r_root", required=True)
    rel_p.add_argument("--binding-file", dest="binding_file", required=True)
    rel_p.add_argument("--image-receipt", dest="image_receipt", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    except SystemExit as error:
        if error.code == 0:
            return 0
        print("REFUSED CLI_ARGUMENTS_INVALID", file=sys.stderr)
        return 2
    try:
        if args.subcommand == "plan":
            execute_plan(
                p_root=args.p_root,
                p_commit=args.p_commit,
                leaf_manifest_sha256=args.leaf_manifest_sha256,
                binding_out=args.binding_out,
                github_output=args.github_output,
            )
        elif args.subcommand == "prepare-image":
            execute_prepare_image(
                p_root=args.p_root,
                r_root=args.r_root,
                binding_file=args.binding_file,
                work_root=args.work_root,
                image_receipt=args.image_receipt,
                github_output=args.github_output,
            )
        elif args.subcommand == "release-image":
            execute_release_image(
                p_root=args.p_root,
                r_root=args.r_root,
                binding_file=args.binding_file,
                image_receipt=args.image_receipt,
            )
        else:
            raise RuntimeBridgeError("UNKNOWN_SUBCOMMAND", "Unsupported runtime bridge subcommand")
    except RuntimeBridgeError as error:
        print(f"REFUSED {error.code}", file=sys.stderr)
        if error.cleanup_observation is not None:
            observation = RuntimeBridgeError(
                error.code, cleanup_observation=error.cleanup_observation,
            ).cleanup_observation
            if observation is not None:
                print("WORK_ROOT_CLEANUP " + " ".join(
                    key.upper() + "=" + observation[key]
                    for key in ("category", "scope", "operation", "errno")
                ), file=sys.stderr)
        if error.custody_retained or _RETAINED_BRIDGE_CUSTODY:
            print("BRIDGE_CUSTODY_RETAINED", file=sys.stderr)
        return 2
    except Exception:
        print("REFUSED INTERNAL", file=sys.stderr)
        if _RETAINED_BRIDGE_CUSTODY:
            print("BRIDGE_CUSTODY_RETAINED", file=sys.stderr)
        return 2
    if _RETAINED_BRIDGE_CUSTODY:
        print("BRIDGE_CUSTODY_RETAINED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
