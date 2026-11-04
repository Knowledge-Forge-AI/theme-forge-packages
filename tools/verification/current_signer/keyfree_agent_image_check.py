"""Credential-free owned-agent check for the prepared signing image.

Called by the existing image inspection in its dedicated single-thread process.
The fresh job lives in the inspection container's private tmpfs. Its disposal
belongs to that container; this module neither recursively deletes GnuPG state
nor treats container teardown as a successful agent cleanup.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import types

SCHEMA = "tf.signing-image-keyfree-agent-check.v1"
WORKER_UID = 1001
WORKER_GID = 1001
WORKSPACE = Path("/work/workspace")
AGENT_SOURCE_SHA256 = "305f613aa989f807d5155c082e568d8e0c79ba63aa4ab8a25252433250c5c2cf"
_FORBIDDEN_ENV = frozenset({"PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "GH_TOKEN", "GITHUB_TOKEN", "GPG_AGENT_INFO"})
_CODES = frozenset(['AGENT_CLEANUP_UNCONFIRMED', 'AGENT_EXEC_IDENTITY', 'AGENT_NOT_LIVE', 'AGENT_NOT_READY', 'AGENT_READINESS_MISMATCH', 'AGENT_READINESS_TIMEOUT', 'AGENT_READINESS_TRANSPORT', 'AGENT_UNEXPECTED_DESCENDANT', 'CLEANUP_PATH_CHANGED', 'CLEANUP_UNCONFIRMED', 'COMMON_CONF_TAMPERED', 'COMMON_CONF_WRITE', 'GLOBAL_CONFIG_REJECTED', 'GPGCONF_FAILED', 'GPGCONF_OUTPUT', 'HOME_NOT_EMPTY', 'JOB_ROOT_CHANGED', 'JOB_ROOT_HOME_MISSING', 'JOB_ROOT_NOT_OWNED', 'LIFECYCLE_STATE', 'LISTENER_HOLDER_UNCONFIRMED', 'LISTENER_STILL_HELD', 'PATH_CHANGED', 'PATH_CUSTODY', 'PATH_FORMAT', 'PATH_SCOPE', 'PATH_UNEXPECTED', 'PIDFD_ENROLLMENT_UNCONFIRMED', 'PROC_VISIBILITY_UNCONFIRMED', 'SIGCHLD_PRECONDITION', 'SOCKETDIR_BINDING_UNCONFIRMED', 'SOCKETDIR_NOT_EMPTY', 'SOCKETDIR_NOT_FRESH', 'SOCKETDIR_REPLACED', 'SOCKET_REPLACED', 'STARTUP_CHILD_EXITED', 'TOOL_CHANGED', 'TOOL_PREFLIGHT_FAILED', 'UNRECORDED_CLEANUP_ENTRY', 'UNSUPPORTED_PLATFORM', 'UNSUPPORTED_SOCKET_PLACEMENT', 'UNSUPPORTED_VERSION'])

_RETAINED_CHECKS: list[object] = []


class CheckRefusal(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _source_bytes(path: Path) -> bytes:
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise CheckRefusal("AGENT_SOURCE_REFUSED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o444
                or not 0 < before.st_size <= 512 * 1024):
            raise CheckRefusal("AGENT_SOURCE_REFUSED")
        body = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
        named = os.lstat(path)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (identity(before) != identity(after) or identity(after) != identity(named)
                or len(body) != before.st_size or hashlib.sha256(body).hexdigest() != AGENT_SOURCE_SHA256):
            raise CheckRefusal("AGENT_SOURCE_REFUSED")
        return body
    finally:
        os.close(fd)


def _load_agent_class():
    path = Path(__file__).with_name("owned_gpg_agent.py")
    body = _source_bytes(path)
    name = "_tf_image_check_owned_gpg_agent"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(body, str(path), "exec", dont_inherit=True), module.__dict__)
    return module.OwnedGpgAgent


def _workspace() -> Path:
    path = WORKSPACE
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise CheckRefusal("WORKSPACE_REFUSED")
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != WORKER_UID
            or info.st_gid != WORKER_GID or stat.S_IMODE(info.st_mode) != 0o700):
        raise CheckRefusal("WORKSPACE_REFUSED")
    job = path / "keyfree-agent-check"
    os.mkdir(job, 0o700)
    os.mkdir(job / "gnupg", 0o700)
    return job


def run_keyfree_agent_check() -> dict:
    """Return fixed fields only; exact native class loading has no fixture seam."""
    phase, code = "PREFLIGHT", "NONE"
    started = cleanup = False
    agent = None
    try:
        if (sys.platform != "linux" or os.getpid() <= 1 or os.getuid() != WORKER_UID
                or os.getgid() != WORKER_GID or any(name in os.environ for name in _FORBIDDEN_ENV)):
            raise CheckRefusal("CHECK_CONTEXT_REFUSED")
        phase = "SOURCE"
        agent_class = _load_agent_class()
        phase = "WORKSPACE"
        job = _workspace()
        phase = "START"
        agent = agent_class(job / "gnupg", job)
        agent.start()
        phase = "LIVE"
        agent.require_live()
        started = True
    except BaseException as error:
        try:
            raw = getattr(error, "code", None)
        except BaseException:
            raw = None
        allowed = _CODES | {"AGENT_SOURCE_REFUSED", "WORKSPACE_REFUSED", "CHECK_CONTEXT_REFUSED"}
        code = raw if type(raw) is str and raw in allowed else "AGENT_CHECK_FAILED"
    finally:
        if agent is not None:
            if code == "NONE":
                phase = "CLOSE"
            try:
                agent.close()
                cleanup = agent.cleanup_confirmed is True
            except BaseException:
                cleanup = False
            if not cleanup:
                _RETAINED_CHECKS.append(agent)
    accepted = started and cleanup and code == "NONE"
    return {
        "schema": SCHEMA,
        "status": "passed" if accepted else "failed-closed",
        "phase": "COMPLETE" if accepted else phase,
        "code": code if code != "NONE" or accepted else "AGENT_CLEANUP_UNCONFIRMED",
        "worker_uid": os.getuid(),
        "worker_gid": os.getgid(),
        "agent_source_sha256": AGENT_SOURCE_SHA256,
        "agent_started_and_live": started,
        "agent_cleanup_confirmed": cleanup,
        "custody_retained": agent is not None and not cleanup,
        "fresh_state_disposal": "owned-container-teardown",
        "signing_credentials_used": False,
        "production_authority": False,
    }
