"""Source-only Linux lifecycle boundary for the observed GnuPG 2.4.9 builder.

No key handling or signer integration lives here. Native operation requires a
dedicated, single-threaded parent, default SIGCHLD and no external reaper.
Future gpg consumers must explicitly use --pinentry-mode loopback as well as
fixed --no-autostart and require_live before AND after each
consumer, with no consumers outstanding at close. A point-in-time proc scan
cannot prove that an escaped grandchild never existed. Exact-image zero-child,
keyboxd and distribution behavior still require native qualification before
private import. Every receipt, including native receipts, grants no authority.

The shim's PDEATHSIG is tied to the spawning thread, not an abstract Python
process. Uncatchable parent death cannot remove disk state; container teardown
must do that. Ordinary signals are masked during child enrollment; arbitrary
asynchronous exception injection inside Popen and external child reapers are
unsupported. Retained custody must remain reachable until cleanup is confirmed;
the caller alone owns subsequent home deletion.

Python 3.11+ is required. All visible procfs process metadata and descriptors
must remain inspectable in the parent's PID namespace, with hidepid disabled.
An isolated same-UID, dumpable process set is the intended supported layout;
foreign-UID or non-dumpable processes require already-authorized visibility or
the layout refuses. No capability, UID or namespace change is attempted. A
target becoming non-dumpable after preflight remains an exact-image concern
and causes coded refusal with retained custody, never weaker holder proof.

The shim deliberately ignores SIGPIPE across exec for supervised Assuan peers.
Its fixed 1 MiB RLIMIT_FSIZE applies to stderr AND every agent-written regular
file; exceeding it can terminate the child via SIGXFSZ. Actual signing-key
compatibility remains unqualified. The agent's own socket checks/inotify are
disabled to avoid their asynchronous socketdir creation; the parent retains
directory/socket custody and validates it before/after every consumer instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping

NATIVE_GPGCONF = "/usr/bin/gpgconf"
NATIVE_GPG_AGENT = "/usr/bin/gpg-agent"
NATIVE_GPG = "/usr/bin/gpg"
TARGET_GNUPG_VERSION = "2.4.9"
START_TIMEOUT_SECONDS = 10.0
CLEANUP_TIMEOUT_SECONDS = 5.0
MAX_GPGCONF_OUTPUT = 4096
_NAMES = ("sysconfdir", "homedir", "socketdir", "agent-socket")
_BARRIER = b"no-autostart\n"


@contextmanager
def _enrollment_mask():
    """Defer catchable signal handlers through resource/child enrollment."""
    blocked = signal.valid_signals() - {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD}
    old = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


class OwnedAgentError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _fail(code: str, message: str) -> None:
    raise OwnedAgentError(code, message)


@dataclass(frozen=True)
class PathIdentity:
    dev: int
    ino: int
    uid: int
    mode: int
    kind: int


def _ident(info: os.stat_result) -> PathIdentity:
    return PathIdentity(info.st_dev, info.st_ino, info.st_uid,
                        stat.S_IMODE(info.st_mode), stat.S_IFMT(info.st_mode))


def _absolute_path(value: str | os.PathLike[str], label: str) -> Path:
    raw = os.fspath(value)
    if (not isinstance(raw, str) or not re.fullmatch(r"/[A-Za-z0-9/._-]+", raw)
            or any(p in {"", ".", ".."} for p in raw.split("/")[1:])):
        _fail("PATH_FORMAT", f"{label} must be a physical absolute ASCII path")
    return Path(raw)


@dataclass(frozen=True)
class BoundAgentPaths:
    homedir: Path
    job_root: Path
    agent_socket: Path
    socketdir_path: Path | None = None

    @property
    def socketdir(self) -> Path:
        return self.homedir if self.socketdir_path is None else self.socketdir_path


@dataclass(frozen=True)
class AgentLifecycleReceipt:
    schema: str
    status: str
    evidence_class: str
    agent_pid: int
    production_authority: bool = False


@dataclass
class _Directory:
    path: Path
    fd: int
    identity: PathIdentity


@dataclass(frozen=True)
class _RuntimeLayout:
    root: PathIdentity
    run: PathIdentity
    var: PathIdentity
    var_run: PathIdentity | None
    alias_target: str | None


@dataclass
class _RetainedCustody:
    """Allocated before resource acquisition; never discarded on uncertainty."""
    paths: BoundAgentPaths | None = None
    directories: list[_Directory] = field(default_factory=list)
    socket_directories: list[_Directory] = field(default_factory=list)
    home_fd: int | None = None
    job_fd: int | None = None
    socketdir_fd: int | None = None
    socketdir_identity: PathIdentity | None = None
    socketdir_owned: bool = False
    socketdir_created_name: str | None = None
    listener_fd: int | None = None
    listener_identity: PathIdentity | None = None
    socket_identity: PathIdentity | None = None
    stderr_fd: int | None = None
    stderr_identity: PathIdentity | None = None
    common_identity: PathIdentity | None = None
    common_digest: str | None = None
    child: Any = None
    pidfd: int | None = None
    reaped: bool = False
    final_exec: bool = False
    tools: dict[str, tuple[PathIdentity, str]] = field(default_factory=dict)
    python: str | None = None
    uncertainty: str | None = None
    cleanup_error: BaseException | None = None
    diagnostic_size: int | None = None
    diagnostic_digest: str | None = None
    runtime_layout: _RuntimeLayout | None = None
    job_members_before: frozenset[str] | None = None
    job_entries_before: dict[str, PathIdentity] | None = None
    home_root_name: str | None = None
    owned_job_entries: dict[str, PathIdentity] = field(default_factory=dict)


def _open_chain(path: Path, custody: _RetainedCustody, *, directory_sink: list[_Directory] | None = None) -> int:
    """Hold physical components; openat prevents traversal through symlinks."""
    if directory_sink is None:
        directory_sink = custody.directories
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    directory_sink.append(_Directory(Path("/"), fd, _ident(os.fstat(fd))))
    current = Path("/")
    for part in path.parts[1:]:
        fd = os.open(part, flags, dir_fd=fd)
        current /= part
        directory_sink.append(_Directory(current, fd, _ident(os.fstat(fd))))
    return fd


def _check_directories(c: _RetainedCustody) -> None:
    _check_job_entries(c)
    for entry in (*c.directories, *c.socket_directories):
        if _ident(os.fstat(entry.fd)) != entry.identity:
            _fail("PATH_CHANGED", "held directory changed")
        # The pathname as well as the held object must still name the same tree.
        if _ident(os.lstat(entry.path)) != entry.identity:
            _fail("PATH_CHANGED", "physical directory component was replaced")


def _private(fd: int) -> None:
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        _fail("PATH_CUSTODY", "job root and fresh home must be owned mode 0700")


def _job_entry_snapshot(fd: int) -> dict[str, PathIdentity]:
    """Record only direct-entry identities; never inspect baseline contents."""
    return {name: _ident(os.lstat(name, dir_fd=fd)) for name in os.listdir(fd)}


def _check_job_entries(c: _RetainedCustody) -> None:
    """Permit only the held baseline plus entries this lifecycle created."""
    if c.job_fd is None or c.job_entries_before is None:
        return
    current = _job_entry_snapshot(c.job_fd)
    baseline = c.job_entries_before
    allowed = set(baseline) | set(c.owned_job_entries)
    if set(current) - allowed:
        _fail("JOB_ROOT_CHANGED", "job root gained an unrecorded entry")
    for name, expected in baseline.items():
        if current.get(name) != expected:
            _fail("JOB_ROOT_CHANGED", "pre-existing job-root entry changed")
    for name, expected in c.owned_job_entries.items():
        if current.get(name) != expected:
            _fail("SOCKETDIR_REPLACED", "owned job-root entry changed")


def parse_gpgconf_single_value(output: bytes, *, name: str) -> str:
    if name not in _NAMES or not isinstance(output, bytes) or len(output) > MAX_GPGCONF_OUTPUT:
        _fail("GPGCONF_OUTPUT", "unsupported or oversized directory response")
    if not output.endswith(b"\n") or output.count(b"\n") != 1:
        _fail("GPGCONF_OUTPUT", "directory response must be exactly one LF-terminated path")
    try:
        value = output[:-1].decode("ascii")
        _absolute_path(value, "gpgconf directory")
    except (UnicodeError, OwnedAgentError) as error:
        raise OwnedAgentError("GPGCONF_OUTPUT", "invalid raw directory response") from error
    return value


def bind_gpgconf_paths(records: Mapping[str, str], *, homedir: Path, job_root: Path) -> BoundAgentPaths:
    if set(records) != set(_NAMES):
        _fail("GPGCONF_OUTPUT", "directory response names are not closed")
    if records["sysconfdir"] != "/etc/gnupg" or records["homedir"] != str(homedir):
        _fail("PATH_UNEXPECTED", "GnuPG directory response does not match the owned home")
    socketdir = _absolute_path(records["socketdir"], "socketdir")
    agent_socket = _absolute_path(records["agent-socket"], "agent-socket")
    if agent_socket != socketdir / "S.gpg-agent":
        _fail("PATH_UNEXPECTED", "agent socket is not the fixed socketdir entry")
    if len(str(agent_socket).encode("ascii")) > 104:
        _fail("PATH_SCOPE", "bound agent socket exceeds the fixed Linux pathname limit")
    if socketdir == homedir:
        return BoundAgentPaths(homedir, job_root, agent_socket)
    # A non-home socketdir is accepted only as a fresh, direct child of this
    # job root.  Ambient runtime paths (/run/user, /var/run, /tmp, etc.) and
    # nested or ancestor paths remain fail-closed.
    if socketdir.parent != job_root:
        _fail("UNSUPPORTED_SOCKET_PLACEMENT", "socketdir is outside the fresh job-root child boundary")
    return BoundAgentPaths(homedir, job_root, agent_socket, socketdir)


def _socket_dir_fd(c: _RetainedCustody) -> int:
    if c.paths is None:
        _fail("LIFECYCLE_STATE", "socket directory is not bound")
    if c.paths.socketdir == c.paths.homedir:
        if c.home_fd is None:
            _fail("LIFECYCLE_STATE", "home directory is not held")
        return c.home_fd
    if c.socketdir_fd is None:
        _fail("LIFECYCLE_STATE", "external socket directory is not held")
    return c.socketdir_fd


def _absent_physical(path: Path, code: str) -> None:
    """No follows. An unrecognized symlink is a refusal, not absence."""
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            _fail(code, "configuration/runtime component exists or redirects")
    _fail(code, "configuration/runtime path exists")


def _runtime_layout() -> _RuntimeLayout:
    """Recognize only the root-controlled conventional /var/run -> /run alias.

    Readlink is interpreted lexically, never followed to inspect an arbitrary
    target. Both accepted spellings name the separately inspected physical
    /run. Physical /var/run directories and absence remain supported, with
    their own candidate paths checked by the caller.
    """
    code = "UNSUPPORTED_SOCKET_PLACEMENT"
    directories = {}
    for name in ("/", "/run", "/var"):
        info = os.lstat(name)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _fail(code, "runtime ancestry is not a safe root-owned physical directory")
        directories[name] = _ident(info)
    target = None
    try:
        info = os.lstat("/var/run")
    except FileNotFoundError:
        alias = None
    else:
        alias = _ident(info)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink("/var/run")
            if info.st_uid != 0 or target not in {"/run", "../run"}:
                _fail(code, "runtime alias is not the conventional root-owned /run alias")
            if _ident(os.lstat("/var/run")) != alias or os.readlink("/var/run") != target:
                _fail(code, "runtime alias changed during inspection")
        elif not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _fail(code, "physical runtime alternative is unsafe")
    for name, identity in directories.items():
        if _ident(os.lstat(name)) != identity:
            _fail(code, "runtime physical ancestry changed during inspection")
    return _RuntimeLayout(directories["/"], directories["/run"], directories["/var"], alias, target)


def _preflight_external_paths(expected: _RuntimeLayout | None = None) -> _RuntimeLayout:
    layout = _runtime_layout()
    if expected is not None and layout != expected:
        _fail("UNSUPPORTED_SOCKET_PLACEMENT", "runtime layout changed after preflight")
    # All alternatives in pinned homedir.c. A recognized alias is checked at
    # its trusted physical /run target; unknown aliases have already refused.
    bases = ["/run/gnupg", "/run"]
    if layout.var_run is not None and layout.alias_target is None:
        bases.extend(("/var/run/gnupg", "/var/run"))
    for base in bases:
        _absent_physical(Path(base) / "user" / str(os.getuid()), "UNSUPPORTED_SOCKET_PLACEMENT")
    # Closure deliberately excludes speculative libexec/control candidates.
    for tool in (NATIVE_GPGCONF, NATIVE_GPG_AGENT, NATIVE_GPG):
        _absent_physical(Path(tool).parent.parent / "bin/gpgconf.ctl", "GLOBAL_CONFIG_REJECTED")
    _absent_physical(Path("/etc/gnupg"), "GLOBAL_CONFIG_REJECTED")
    if _runtime_layout() != layout:
        _fail("UNSUPPORTED_SOCKET_PLACEMENT", "runtime layout changed during path preflight")
    return layout


def _trusted_tool(path: str) -> tuple[PathIdentity, str]:
    current = Path("/")
    root = os.lstat(current)
    if root.st_uid != 0 or root.st_mode & 0o022 or not stat.S_ISDIR(root.st_mode):
        _fail("TOOL_PREFLIGHT_FAILED", "trusted tool root ancestry is unsafe")
    for part in Path(path).parts[1:]:
        current /= part
        info = os.lstat(current)
        if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_mode & 0o6000):
            _fail("TOOL_PREFLIGHT_FAILED", "trusted tool ancestry or mode is unsafe")
        if current != Path(path) and not stat.S_ISDIR(info.st_mode):
            _fail("TOOL_PREFLIGHT_FAILED", "tool ancestor is not a directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or _ident(info) != _ident(os.lstat(path)):
            _fail("TOOL_PREFLIGHT_FAILED", "trusted tool is not a stable regular file")
        if "security.capability" in os.listxattr(fd):
            _fail("TOOL_PREFLIGHT_FAILED", "trusted tool has file capabilities")
        with os.fdopen(os.dup(fd), "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if _ident(os.fstat(fd)) != _ident(info):
            _fail("TOOL_PREFLIGHT_FAILED", "trusted tool changed while hashing")
        return _ident(info), digest
    finally:
        os.close(fd)


def _environment(home: Path) -> dict[str, str]:
    return {"HOME": str(home), "GNUPGHOME": str(home), "PATH": "/usr/bin:/bin", "LC_ALL": "C"}


# Fixed protocol implementation, not copied upstream code. No caller source,
# target executable, argv, environment additions or preexec_fn are accepted.
_EXEC_SHIM_SOURCE = r'''
import ctypes, os, resource, signal, socket, stat, sys
try:
    high = int(sys.argv[1]); expected = tuple(map(int, sys.argv[2].split(':')))
    home = sys.argv[3]; socket_path = sys.argv[4]; parent = int(sys.argv[5])
    expected_home = tuple(map(int, sys.argv[6].split(':')))
    expected_agent = tuple(map(int, sys.argv[7].split(':')))
    if high < 16 or parent <= 1 or sys.platform != 'linux': raise RuntimeError()
    os.umask(0o077)
    a = os.lstat(home); b = os.stat('.')
    if (a.st_dev,a.st_ino) != expected_home or expected_home != (b.st_dev,b.st_ino) or not stat.S_ISDIR(a.st_mode) or a.st_uid != os.getuid() or stat.S_IMODE(a.st_mode) != 0o700: raise RuntimeError()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(1, int(signal.SIGKILL), 0, 0, 0) != 0: raise RuntimeError()
    if os.getppid() != parent: raise RuntimeError()
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576,1048576))
    for sig in signal.valid_signals():
        if sig in (signal.SIGKILL,signal.SIGSTOP): continue
        try: signal.signal(sig, signal.SIG_DFL)
        except OSError: pass
    # The supervised branch relies on its supervisor to ignore broken peers.
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.pthread_sigmask(signal.SIG_SETMASK, [])
    s = os.fstat(high)
    if not stat.S_ISSOCK(s.st_mode) or (s.st_dev,s.st_ino) != expected: raise RuntimeError()
    os.dup2(high,3,inheritable=True)
    for text in os.listdir('/proc/self/fd'):
        fd = int(text)
        if fd >= 4:
            try: os.close(fd)
            except OSError: pass
    actual = set()
    for text in os.listdir('/proc/self/fd'):
        fd = int(text)
        try: os.fstat(fd)
        except OSError: continue
        actual.add(fd)
    if actual != {0,1,2,3}: raise RuntimeError()
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM or listener.getsockname() != socket_path or not listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN): raise RuntimeError()
    listener.detach()
    target = '/usr/bin/gpg-agent'
    t = os.lstat(target)
    if (t.st_dev,t.st_ino) != expected_agent or not stat.S_ISREG(t.st_mode) or t.st_uid != 0 or t.st_mode & 0o6022 or 'security.capability' in os.listxattr(target,follow_symlinks=False): raise RuntimeError()
    env = {'HOME':home,'GNUPGHOME':home,'PATH':'/usr/bin:/bin','LC_ALL':'C','LISTEN_FDS':'1','LISTEN_FDNAMES':'std','LISTEN_PID':str(os.getpid())}
    os.execve(target,(target,'--no-options','--homedir',home,'--supervised','--disable-scdaemon','--no-allow-external-cache','--disable-check-own-socket'),env)
except BaseException:
    os.write(2,b'OWNED_AGENT_SHIM_FAILED\n')
    os._exit(127)
'''


def _pidfd_exited(fd: int, timeout: float = 0) -> bool:
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poll.poll(max(0, int(timeout * 1000))))


def _exe(pid: int) -> PathIdentity:
    try:
        return _ident(os.stat(f"/proc/{pid}/exe"))
    except OSError as error:
        raise OwnedAgentError("PROC_VISIBILITY_UNCONFIRMED", "process executable visibility is unavailable") from error


def _child_exe(c: _RetainedCustody, exited_code: str) -> PathIdentity:
    try:
        return _exe(c.child.pid)
    except OwnedAgentError:
        if _pidfd_exited(c.pidfd):
            _fail(exited_code, "held direct child exited during executable inspection")
        c.uncertainty = "PROC_VISIBILITY_UNCONFIRMED"
        raise


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _fail("AGENT_READINESS_TIMEOUT", "Assuan startup deadline expired")
    return remaining


def _read_response(stream: Any, *, connection: Any = None, deadline: float | None = None) -> list[bytes]:
    total = 0
    data: list[bytes] = []
    comments = 0
    while True:
        if connection is not None:
            # Recompute the absolute deadline for every socket read, including
            # a partial line. Buffered readline could otherwise reset the same
            # timeout repeatedly while a peer slowly drips an unterminated line.
            pending = bytearray()
            while len(pending) <= 1000:
                connection.settimeout(_remaining(deadline))
                value = connection.recv(1)
                if not value:
                    break
                pending.extend(value)
                if value == b"\n":
                    break
            line = bytes(pending)
        else:
            line = stream.readline(1001)
        total += len(line)
        if not line:
            _fail("AGENT_NOT_READY", "Assuan peer closed before response")
        if (len(line) > 1000 or not line.endswith(b"\n") or b"\r" in line
                or b"\x00" in line or total > 4096):
            _fail("AGENT_READINESS_MISMATCH", "Assuan response exceeded protocol bounds")
        line = line[:-1]
        if line.startswith(b"#"):
            comments += 1
            if comments > 16:
                _fail("AGENT_READINESS_MISMATCH", "too many Assuan comments")
        elif line == b"OK" or line.startswith(b"OK "):
            return data
        elif line.startswith(b"D "):
            data.append(line[2:])
        else:
            _fail("AGENT_READINESS_MISMATCH", "unexpected Assuan response")


def _assuan(paths: BoundAgentPaths, pid: int, *, deadline: float | None = None) -> None:
    # SO_PEERCRED would identify the listener creator (the parent), not child.
    deadline = time.monotonic() + START_TIMEOUT_SECONDS if deadline is None else deadline
    try:
        # One connection for the entire remaining startup budget, without
        # abandoned half-second probes accumulating in the inherited backlog.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(_remaining(deadline))
            connection.connect(str(paths.agent_socket))
            if _read_response(None, connection=connection, deadline=deadline):
                _fail("AGENT_READINESS_MISMATCH", "unexpected greeting data")
            for name, expected in ((b"version", TARGET_GNUPG_VERSION.encode("ascii")), (b"pid", str(pid).encode("ascii")),
                                   (b"socket_name", str(paths.agent_socket).encode("ascii"))):
                connection.settimeout(_remaining(deadline))
                connection.sendall(b"GETINFO " + name + b"\n")
                if _read_response(None, connection=connection, deadline=deadline) != [expected]:
                    _fail("AGENT_READINESS_MISMATCH", "Assuan child identity or path mismatch")
            connection.settimeout(_remaining(deadline))
            connection.sendall(b"BYE\n")
            if _read_response(None, connection=connection, deadline=deadline):
                _fail("AGENT_READINESS_MISMATCH", "unexpected BYE data")
    except TimeoutError as error:
        raise OwnedAgentError("AGENT_READINESS_TIMEOUT", "Assuan startup deadline expired") from error
    except OSError as error:
        raise OwnedAgentError("AGENT_READINESS_TRANSPORT", "single Assuan startup connection failed") from error


def _proc_text(path: str) -> str:
    with open(path, "r", encoding="ascii") as stream:
        value = stream.read(1024 * 1024 + 1)
    if len(value) > 1024 * 1024:
        raise ValueError("proc metadata exceeded bound")
    return value


def _proc_preflight() -> None:
    """Refuse unsuitable visibility before tools or agent resources are used."""
    try:
        mounts = []
        for line in _proc_text("/proc/self/mountinfo").split("\n"):
            fields = line.split()
            if len(fields) > 6 and fields[4] == "/proc":
                split = fields.index("-")
                mounts.append((fields[split + 1], fields[5] + "," + fields[split + 3]))
        if len(mounts) != 1 or mounts[0][0] != "proc":
            raise ValueError("unrecognized proc mount")
        options = mounts[0][1].split(",")
        if any(option.startswith("hidepid=") and option not in {"hidepid=0", "hidepid=off"}
               or option == "subset=pid" for option in options):
            raise ValueError("restricted proc mount")
        _exe(os.getpid())
        own = os.stat("/proc/self/ns/pid")
        init = os.stat("/proc/1/ns/pid")
        if (own.st_dev, own.st_ino) != (init.st_dev, init.st_ino):
            raise ValueError("proc PID namespace differs")
        _proc_text("/proc/net/unix")
        _proc_observation(None, stopped=False)
    except (OSError, ValueError, IndexError, UnicodeError) as error:
        raise OwnedAgentError("PROC_VISIBILITY_UNCONFIRMED", "proc layout or visibility is unsuitable") from error


def _proc_observation(c: _RetainedCustody | None, *, stopped: bool) -> None:
    """Strict observable zero-child/holder contract; unknown visibility refuses.

    Deliberately never signals unknown descendants or a process group. Native
    qualification must establish that supported workloads create no children;
    this scan is defense in depth, not proof against transient escaped children.
    """
    if c is not None and (c.child is None or c.listener_identity is None):
        return
    pid = c.child.pid if c is not None else None
    try:
        for text in os.listdir("/proc"):
            if not text.isdecimal():
                continue
            other = int(text)
            try:
                fields = _proc_text(f"/proc/{other}/stat").rsplit(")", 1)[1].split()
                parent, group, session = map(int, fields[1:4])
                if pid is not None and other != pid and pid in (parent, group, session):
                    c.uncertainty = "AGENT_UNEXPECTED_DESCENDANT"
                    _fail(c.uncertainty, "unsupported child/session member observed; custody retained")
                for fd in os.listdir(f"/proc/{other}/fd"):
                    try:
                        value = os.stat(f"/proc/{other}/fd/{fd}")
                    except FileNotFoundError:
                        continue
                    if c is not None and (value.st_dev, value.st_ino) == (c.listener_identity.dev, c.listener_identity.ino):
                        allowed = not stopped and other == pid and fd == "3"
                        if not allowed:
                            c.uncertainty = "LISTENER_HOLDER_UNCONFIRMED"
                            _fail(c.uncertainty, "unexpected listener holder observed")
            except (FileNotFoundError, ProcessLookupError):
                continue
        if stopped:
            for line in _proc_text("/proc/net/unix").split("\n")[1:]:
                columns = line.split()
                if len(columns) >= 7 and columns[6] == str(c.listener_identity.ino):
                    _fail("LISTENER_STILL_HELD", "listener inode remains in kernel socket table")
    except (OSError, ValueError, IndexError, UnicodeError) as error:
        if c is not None:
            c.uncertainty = "PROC_VISIBILITY_UNCONFIRMED"
        raise OwnedAgentError("PROC_VISIBILITY_UNCONFIRMED", "process/holder visibility is incomplete") from error


class _NativeBackend:
    def __init__(self, home: Path, job: Path):
        self.home, self.job = home, job

    def prepare(self, c: _RetainedCustody) -> None:
        if sys.platform != "linux" or sys.version_info < (3, 11) or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            _fail("UNSUPPORTED_PLATFORM", "native lifecycle requires Linux pidfds")
        if (threading.current_thread() is not threading.main_thread() or threading.active_count() != 1
                or len(os.listdir("/proc/self/task")) != 1 or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
            _fail("SIGCHLD_PRECONDITION", "dedicated main-thread parent with default SIGCHLD required")
        _proc_preflight()  # Metadata only, before any GnuPG call or allocation.
        c.job_fd = _open_chain(self.job, c)
        c.home_fd = _open_chain(self.home, c)
        _private(c.job_fd)
        _private(c.home_fd)
        if os.listdir(c.home_fd):
            _fail("HOME_NOT_EMPTY", "GnuPG home must be precreated and empty")
        c.home_root_name = self.home.relative_to(self.job).parts[0]
        c.job_entries_before = _job_entry_snapshot(c.job_fd)
        c.job_members_before = frozenset(c.job_entries_before)
        if c.home_root_name not in c.job_entries_before:
            _fail("JOB_ROOT_HOME_MISSING", "job-root baseline does not contain the owned home")
        if any(identity.uid != os.getuid() for identity in c.job_entries_before.values()):
            _fail("JOB_ROOT_NOT_OWNED", "job-root baseline contains a foreign-owned entry")
        c.runtime_layout = _preflight_external_paths()  # Before even version queries.
        c.python = str(Path(sys.executable).resolve(strict=True))
        for tool in (c.python, NATIVE_GPGCONF, NATIVE_GPG_AGENT, NATIVE_GPG):
            c.tools[tool] = _trusted_tool(tool)
        if _exe(os.getpid()) != c.tools[c.python][0]:
            _fail("TOOL_PREFLIGHT_FAILED", "interpreter does not match running executable")
        for tool, name in ((NATIVE_GPGCONF, "gpgconf"), (NATIVE_GPG_AGENT, "gpg-agent"), (NATIVE_GPG, "gpg")):
            output = self._query(c, (tool, "--version"))
            if output.split(b"\n", 1)[0] != f"{name} (GnuPG) {TARGET_GNUPG_VERSION}".encode("ascii"):
                _fail("UNSUPPORTED_VERSION", f"fixed tools must be exactly GnuPG {TARGET_GNUPG_VERSION}")
        # Each fixed-name query has exactly one raw path response.  Never zip
        # names to a multi-value response: gpgconf's unlabelled ordering is
        # not a contract and differs across versions/platforms.
        records = {}
        for name in _NAMES:
            output = self._query(c, (NATIVE_GPGCONF, "--homedir", str(self.home), "--list-dirs", name))
            records[name] = parse_gpgconf_single_value(output, name=name)
        c.paths = bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)
        self._bind_socketdir(c)
        _check_directories(c)
        if os.listdir(c.home_fd):
            _fail("HOME_NOT_EMPTY", "metadata queries changed fresh home")
        self._allocate(c)

    def _bind_socketdir(self, c: _RetainedCustody) -> None:
        """Hold only the source-bound fresh external socketdir, if any."""
        if c.paths is None:
            _fail("LIFECYCLE_STATE", "socketdir binding requires gpgconf paths")
        if c.paths.socketdir == c.paths.homedir:
            if os.listdir(c.home_fd):
                _fail("HOME_NOT_EMPTY", "homedir socketdir must remain empty before allocation")
            return
        if c.paths.socketdir.parent != self.job or c.job_members_before is None:
            _fail("UNSUPPORTED_SOCKET_PLACEMENT", "external socketdir is outside the fresh job-root boundary")
        before = c.job_entries_before
        if before is None:
            _fail("LIFECYCLE_STATE", "job-root baseline is not held")
        current = frozenset(os.listdir(c.job_fd))
        name = c.paths.socketdir.name
        if name in before or name in current:
            _fail("SOCKETDIR_NOT_FRESH", "external socketdir already appeared before owned creation")
        if current != frozenset(before):
            _fail("JOB_ROOT_CHANGED", "job root changed outside the held baseline")
        try:
            os.mkdir(name, 0o700, dir_fd=c.job_fd)
        except FileExistsError:
            _fail("SOCKETDIR_NOT_FRESH", "external socketdir appeared before exclusive creation")
        c.socketdir_created_name = name
        try:
            created_identity = _ident(os.lstat(name, dir_fd=c.job_fd))
            c.socketdir_identity = created_identity
            c.owned_job_entries[name] = created_identity
            c.socketdir_fd = _open_chain(c.paths.socketdir, c, directory_sink=c.socket_directories)
            c.socketdir_identity = _ident(os.fstat(c.socketdir_fd))
            if c.socketdir_identity != c.owned_job_entries[name]:
                _fail("SOCKETDIR_REPLACED", "fresh external socketdir changed during enrollment")
            _private(c.socketdir_fd)
            if os.listdir(c.socketdir_fd):
                _fail("SOCKETDIR_NOT_EMPTY", "fresh external socketdir contains an unowned entry")
            c.socketdir_owned = True
        except BaseException:
            # A post-mkdir failure is never a confirmed cleanup. Keep the
            # created name, identity handles, and uncertainty reachable; no
            # path is removed until the exact ownership proof completes.
            c.uncertainty = c.uncertainty or "SOCKETDIR_BINDING_UNCONFIRMED"
            raise

    def _query(self, c: _RetainedCustody, argv: tuple[str, ...]) -> bytes:
        _check_directories(c)
        c.runtime_layout = _preflight_external_paths(c.runtime_layout)
        if _trusted_tool(argv[0]) != c.tools[argv[0]]:
            _fail("TOOL_CHANGED", "fixed tool changed after preflight")
        # Trusted fixed queries: output cap is checked after capture, not a live
        # memory cap. The separately launched agent has an enforced FSIZE cap.
        result = subprocess.run(argv, cwd=self.home, env=_environment(self.home), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                                close_fds=True, shell=False, check=False)
        if result.returncode or len(result.stdout) > MAX_GPGCONF_OUTPUT or len(result.stderr) > MAX_GPGCONF_OUTPUT:
            _fail("GPGCONF_FAILED", "fixed tool query failed or exceeded output bound")
        return result.stdout

    def _allocate(self, c: _RetainedCustody) -> None:
        with _enrollment_mask():
            self._allocate_masked(c)

    def _allocate_masked(self, c: _RetainedCustody) -> None:
        _check_directories(c)
        c.stderr_fd = os.open("agent-stderr.log", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=c.job_fd)
        c.stderr_identity = _ident(os.fstat(c.stderr_fd))
        c.owned_job_entries["agent-stderr.log"] = c.stderr_identity
        socket_fd = _socket_dir_fd(c)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(c.paths.agent_socket))
            c.socket_identity = _ident(os.lstat("S.gpg-agent", dir_fd=socket_fd))
            if c.socket_identity.kind != stat.S_IFSOCK:
                _fail("SOCKET_REPLACED", "bound socket entry is not a socket")
            # Directory is private; explicit chmod avoids modifying process umask.
            os.chmod("S.gpg-agent", 0o600, dir_fd=socket_fd)
            c.socket_identity = _ident(os.lstat("S.gpg-agent", dir_fd=socket_fd))
            listener.listen(16)
            c.listener_identity = _ident(os.fstat(listener.fileno()))
            c.listener_fd = fcntl.fcntl(listener.fileno(), fcntl.F_DUPFD_CLOEXEC, 16)

    def spawn(self, c: _RetainedCustody) -> None:
        _check_directories(c)
        _proc_preflight()  # Recheck after preparation, before creating the child.
        c.runtime_layout = _preflight_external_paths(c.runtime_layout)
        for tool, identity in c.tools.items():
            if _trusted_tool(tool) != identity:
                _fail("TOOL_CHANGED", "trusted tool changed before spawn")
        home = _ident(os.fstat(c.home_fd))
        agent = c.tools[NATIVE_GPG_AGENT][0]
        with _enrollment_mask():
            c.child = subprocess.Popen(
                (c.python, "-I", "-S", "-B", "-c", _EXEC_SHIM_SOURCE, str(c.listener_fd),
                 f"{c.listener_identity.dev}:{c.listener_identity.ino}", str(self.home), str(c.paths.agent_socket), str(os.getpid()),
                 f"{home.dev}:{home.ino}", f"{agent.dev}:{agent.ino}"),
                cwd=self.home, env=_environment(self.home), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=c.stderr_fd, shell=False, close_fds=True,
                pass_fds=(c.listener_fd,), restore_signals=True, start_new_session=True, umask=0o077)
            # No poll/wait before pidfd enrollment, even if child already exited.
            c.pidfd = os.pidfd_open(c.child.pid, 0)
        os.close(c.listener_fd)
        c.listener_fd = None

    def ready(self, c: _RetainedCustody) -> None:
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            _check_directories(c)
            if _pidfd_exited(c.pidfd):
                _fail("STARTUP_CHILD_EXITED", "direct child exited during startup")
            actual = _child_exe(c, "STARTUP_CHILD_EXITED")
            if _pidfd_exited(c.pidfd):
                _fail("STARTUP_CHILD_EXITED", "direct child exited during identity check")
            if actual == c.tools[c.python][0] and not c.final_exec:
                time.sleep(0.02)
                continue
            if actual != c.tools[NATIVE_GPG_AGENT][0]:
                _fail("AGENT_EXEC_IDENTITY", "direct child has unexpected executable")
            c.final_exec = True
            self.validate(c, barrier=False)
            _assuan(c.paths, c.child.pid, deadline=deadline)
            self.validate(c, barrier=False)
            self._barrier(c)
            self.validate(c)
            return
        _fail("AGENT_READINESS_TIMEOUT", "fixed child did not become ready before deadline")

    def _barrier(self, c: _RetainedCustody) -> None:
        with _enrollment_mask():
            self._barrier_masked(c)

    def _barrier_masked(self, c: _RetainedCustody) -> None:
        fd = os.open("common.conf", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=c.home_fd)
        try:
            c.common_identity = _ident(os.fstat(fd))
            if os.write(fd, _BARRIER) != len(_BARRIER):
                _fail("COMMON_CONF_WRITE", "short autostart barrier write")
            os.fsync(fd)
            c.common_digest = hashlib.sha256(_BARRIER).hexdigest()
        finally:
            os.close(fd)

    def validate(self, c: _RetainedCustody, *, barrier: bool = True) -> None:
        _check_directories(c)
        c.runtime_layout = _preflight_external_paths(c.runtime_layout)
        for tool, recorded in c.tools.items():
            if _trusted_tool(tool) != recorded:
                _fail("TOOL_CHANGED", "trusted consumer/agent tool changed after spawn")
        if c.uncertainty:
            _fail(c.uncertainty, "prior observation prevents admission")
        if _pidfd_exited(c.pidfd) or _child_exe(c, "AGENT_NOT_LIVE") != c.tools[NATIVE_GPG_AGENT][0] or _pidfd_exited(c.pidfd):
            _fail("AGENT_NOT_LIVE", "held direct child is not the expected live agent")
        if _ident(os.lstat("S.gpg-agent", dir_fd=_socket_dir_fd(c))) != c.socket_identity:
            _fail("SOCKET_REPLACED", "owned listener path changed")
        if barrier:
            self._check_common(c)
        _proc_observation(c, stopped=False)

    def _check_common(self, c: _RetainedCustody) -> None:
        if c.common_identity is None or _ident(os.lstat("common.conf", dir_fd=c.home_fd)) != c.common_identity:
            _fail("COMMON_CONF_TAMPERED", "autostart barrier identity changed")
        fd = os.open("common.conf", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=c.home_fd)
        try:
            if _ident(os.fstat(fd)) != c.common_identity or os.read(fd, 64) != _BARRIER:
                _fail("COMMON_CONF_TAMPERED", "autostart barrier contents changed")
        finally:
            os.close(fd)

    def cleanup(self, c: _RetainedCustody) -> None:
        # Stop exact child even if a path was replaced; never signal by socket PID.
        if c.listener_fd is not None:
            os.close(c.listener_fd)
            c.listener_fd = None
        observation_error = None
        if c.child is not None and not c.reaped:
            try:
                _proc_observation(c, stopped=False)
            except BaseException as error:
                c.cleanup_error = error
                observation_error = error
            if c.pidfd is not None:
                for value in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        signal.pidfd_send_signal(c.pidfd, value)
                    except ProcessLookupError:
                        pass
                    if _pidfd_exited(c.pidfd, CLEANUP_TIMEOUT_SECONDS):
                        break
                else:
                    _fail("AGENT_CLEANUP_UNCONFIRMED", "exact child exit was not confirmed")
            else:
                # Failed pidfd enrollment leaves no race-free process handle.
                # Retain the direct child and every private path; never bind a
                # possibly reused numeric PID and never claim cleanup.
                c.uncertainty = "PIDFD_ENROLLMENT_UNCONFIRMED"
                _fail("AGENT_CLEANUP_UNCONFIRMED", "exact child pidfd was not enrolled; retained custody")
            c.child.wait(timeout=CLEANUP_TIMEOUT_SECONDS)
            c.reaped = True
        if observation_error is not None:
            # Even a KeyboardInterrupt while observing must not turn an
            # incomplete observation into confirmed cleanup.
            raise observation_error
        if c.uncertainty:
            _fail(c.uncertainty, "unproved descendant/holder custody remains")
        if c.socketdir_created_name is not None and not c.socketdir_owned:
            c.uncertainty = "SOCKETDIR_BINDING_UNCONFIRMED"
            _fail(c.uncertainty, "created socketdir ownership proof is incomplete")
        if c.child is not None:
            deadline = time.monotonic() + 0.5
            while True:
                try:
                    _proc_observation(c, stopped=True)
                    break
                except OwnedAgentError as error:
                    if error.code != "LISTENER_STILL_HELD" or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
        _check_directories(c)
        # Validate all entries before unlinking any; replacement keeps custody.
        socket_fd = _socket_dir_fd(c) if c.socket_identity is not None else c.home_fd
        for name, fd, expected in (("S.gpg-agent", socket_fd, c.socket_identity),
                                   ("common.conf", c.home_fd, c.common_identity),
                                   ("agent-stderr.log", c.job_fd, c.stderr_identity)):
            if fd is None:
                continue
            try:
                actual = _ident(os.lstat(name, dir_fd=fd))
            except FileNotFoundError:
                if expected is not None:
                    _fail("CLEANUP_PATH_CHANGED", "owned cleanup entry disappeared")
                continue
            if expected is None:
                _fail("UNRECORDED_CLEANUP_ENTRY", "unrecorded cleanup entry requires retained custody")
            if actual != expected:
                _fail("CLEANUP_PATH_CHANGED", "owned cleanup entry changed; custody retained")
        if c.common_identity is not None and c.common_digest is not None:
            self._check_common(c)
        if c.socket_identity is not None:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.25)
                try:
                    probe.connect(str(c.paths.agent_socket))
                except ConnectionRefusedError:
                    pass
                else:
                    _fail("LISTENER_STILL_HELD", "owned stale socket still accepts connections")
        if c.stderr_fd is not None:
            c.diagnostic_size = os.fstat(c.stderr_fd).st_size
            # Never read raw diagnostics into public receipts or exception text.
            os.lseek(c.stderr_fd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            remaining = 1048576
            while remaining:
                block = os.read(c.stderr_fd, min(65536, remaining))
                if not block:
                    break
                remaining -= len(block)
                digest.update(block)
            c.diagnostic_digest = digest.hexdigest()
        socket_fd = _socket_dir_fd(c) if c.socket_identity is not None else c.home_fd
        for name, fd, attr in (("S.gpg-agent", socket_fd, "socket_identity"),
                               ("common.conf", c.home_fd, "common_identity"),
                               ("agent-stderr.log", c.job_fd, "stderr_identity")):
            expected = getattr(c, attr)
            if expected is not None:
                if _ident(os.lstat(name, dir_fd=fd)) != expected:
                    _fail("CLEANUP_PATH_CHANGED", "cleanup entry changed before unlink")
                os.unlink(name, dir_fd=fd)
                setattr(c, attr, None)
                c.owned_job_entries.pop(name, None)
        if c.socketdir_owned:
            self._remove_socketdir(c)
        for attr in ("pidfd", "stderr_fd"):
            value = getattr(c, attr)
            if value is not None:
                os.close(value)
                setattr(c, attr, None)
        while c.socket_directories:
            os.close(c.socket_directories[-1].fd)
            c.socket_directories.pop()
        c.socketdir_fd = None
        while c.directories:
            os.close(c.directories[-1].fd)
            c.directories.pop()
        c.home_fd = c.job_fd = None

    def _remove_socketdir(self, c: _RetainedCustody) -> None:
        """Remove only the exact empty external directory we enrolled."""
        if not c.socketdir_owned or c.paths is None or c.socketdir_fd is None or c.socketdir_identity is None:
            _fail("CLEANUP_UNCONFIRMED", "external socketdir ownership handle is unavailable")
        _check_directories(c)
        if os.listdir(c.socketdir_fd):
            _fail("CLEANUP_PATH_CHANGED", "external socketdir gained an unowned entry")
        name = c.paths.socketdir.name
        actual = _ident(os.lstat(name, dir_fd=c.job_fd))
        if actual != c.socketdir_identity or c.owned_job_entries.get(name) != actual:
            _fail("CLEANUP_PATH_CHANGED", "external socketdir was replaced")
        os.rmdir(name, dir_fd=c.job_fd)
        try:
            os.lstat(name, dir_fd=c.job_fd)
        except FileNotFoundError:
            c.owned_job_entries.pop(name, None)
            c.socketdir_owned = False
            c.socketdir_created_name = None
            return
        _fail("CLEANUP_UNCONFIRMED", "external socketdir did not disappear after exact removal")


class OwnedGpgAgent:
    """OwnedGpgAgent(home, job_root): source implementation, no signing authority."""
    def __init__(self, home: str | os.PathLike[str], job_root: str | os.PathLike[str]):
        home = _absolute_path(home, "home")
        job = _absolute_path(job_root, "job root")
        if home == job or job not in home.parents or home.name == ".gnupg" or len(str(home / "S.gpg-agent").encode("ascii")) > 104:
            _fail("PATH_SCOPE", "fresh nondefault home must be strictly within job root and socket length bound")
        self._initialize(_NativeBackend(home, job), False)

    def _initialize(self, backend: Any, fixture: bool) -> None:
        self._backend = backend
        self._fixture = fixture
        self._custody = _RetainedCustody()
        self._state = "new"
        self._cleanup_confirmed = False
        self._receipt: AgentLifecycleReceipt | None = None

    @classmethod
    def _for_fixture(cls, backend: Any) -> OwnedGpgAgent:
        """Private inert tests only; never changes the production constructor."""
        instance = cls.__new__(cls)
        instance._initialize(backend, True)
        return instance

    def start(self) -> OwnedGpgAgent:
        if self._state != "new":
            _fail("LIFECYCLE_STATE", "lifetime is not new")
        self._state = "starting"
        try:
            self._backend.prepare(self._custody)
            self._backend.spawn(self._custody)
            self._backend.ready(self._custody)
            self._state = "running"
            self._receipt = AgentLifecycleReceipt("tf.owned-gpg-agent-lifecycle.v3", "owned-agent-running",
                "fixture-only" if self._fixture else "native-unqualified", self._custody.child.pid, False)
            return self
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                original.add_note("Owned agent cleanup remains unconfirmed; retained_custody must be preserved")
                self._custody.cleanup_error = cleanup
            raise

    def require_live(self) -> None:
        if self._state != "running":
            _fail("LIFECYCLE_STATE", "lifetime is not running")
        self._backend.validate(self._custody)

    def close(self) -> None:
        if self._cleanup_confirmed:
            return
        try:
            self._backend.cleanup(self._custody)
        except BaseException as error:
            self._state = "cleanup-failed-retained"
            self._custody.cleanup_error = error
            raise
        self._cleanup_confirmed = True
        self._state = "closed"

    def __enter__(self) -> OwnedGpgAgent:
        return self.start()

    def __exit__(self, _type: Any, body: BaseException | None, _traceback: Any) -> bool:
        try:
            self.close()
        except BaseException as cleanup:
            if body is not None:
                cleanup.body_error = body
                raise cleanup from body
            raise
        return False

    @property
    def paths(self) -> BoundAgentPaths:
        if self._custody.paths is None:
            _fail("LIFECYCLE_STATE", "paths unavailable before binding")
        return self._custody.paths

    @property
    def receipt(self) -> AgentLifecycleReceipt:
        if self._receipt is None:
            _fail("LIFECYCLE_STATE", "receipt unavailable before readiness")
        return self._receipt

    @property
    def retained_custody(self) -> _RetainedCustody:
        return self._custody

    @property
    def cleanup_confirmed(self) -> bool:
        return self._cleanup_confirmed
