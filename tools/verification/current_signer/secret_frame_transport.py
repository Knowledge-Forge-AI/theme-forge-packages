"""Bounded mutable-byte capture owner for the local secret-frame producer.

capture_frame() launches exactly one foreground subprocess in a new session,
drains stdout and stderr concurrently with nonblocking readv() under one
monotonic deadline, and returns stdout as a fresh mutable bytearray. It never
writes output files, never builds immutable aggregate stdout bytes, never logs
or returns stderr, and zeroes every buffer it allocated on every failure path.

Custody model (checked before launch): SIGCHLD has its default disposition and
the host has one Python thread, so only this module reaps the child (it uses
os.waitpid directly, never Popen.poll/wait/communicate). While the root is
unreaped its PID -- also the new session's process-group ID -- cannot be
reused, so killpg() reaches only the owned group. Once the root is reaped no
signal is ever sent; only signal-0 existence probes, which can err only towards
"still present". Unconfirmed cleanup keeps the real Popen/selector/pipe owner
in a process-local registry and refuses every later capture in this process.
"""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import threading
import time
from typing import Mapping, Sequence

__all__ = (
    "FrameTransportError", "capture_frame", "retained_custody_available", "retained_custody_records",
    "MAX_STDOUT_BYTES", "MAX_STDERR_BYTES",
)

FRAME_SECRET_BOUND = 2 * 1024 * 1024
MAX_STDOUT_BYTES = 2 * FRAME_SECRET_BOUND + 16
MAX_STDERR_BYTES = 65536
MAX_TIMEOUT_SECONDS = 3600.0
READ_CHUNK = 65536
TERM_GRACE_SECONDS = 1.0
KILL_GRACE_SECONDS = 2.0
POLL_SECONDS = 0.01

_MESSAGES = {
    "FRAME_ARGUMENT_INVALID": "Frame capture arguments invalid",
    "FRAME_CUSTODY_RETAINED": "Prior frame capture custody is retained; capture refused",
    "FRAME_PRECONDITION_SIGCHLD": "SIGCHLD must have its default disposition",
    "FRAME_PRECONDITION_THREADS": "Frame capture requires a single-threaded host",
    "FRAME_SPAWN_FAILED": "Frame producer could not be started",
    "FRAME_CAPTURE_TIMEOUT": "Frame producer exceeded the capture deadline",
    "FRAME_STDOUT_OVERFLOW": "Frame producer stdout exceeded bound",
    "FRAME_STDERR_OVERFLOW": "Frame producer stderr exceeded bound",
    "FRAME_EMITTER_NONZERO": "Frame producer exited unsuccessfully",
    "FRAME_GROUP_RETAINED": "Frame producer process group not confirmed absent",
    "FRAME_CUSTODY_LOST": "Frame producer root was reaped outside this owner",
    "FRAME_STREAM_CLOSE_FAILED": "Frame producer pipe close failed",
}


class FrameTransportError(RuntimeError):
    """Fixed-code refusal; never embeds frame bytes, stderr, argv or environment."""

    def __init__(self, code: str):
        if code not in _MESSAGES:
            raise ValueError("unknown FrameTransportError code")
        self.code = code
        self.custody_retained = False  # process-wide retained state when raised
        super().__init__(f"{code}: {_MESSAGES[code]}")


class _CaptureOwner:
    """Real Popen, selector and pipe references for one capture."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.selector: selectors.BaseSelector | None = None
        self.spawn_attempted = self.spawn_refused = self.streams_closed = False
        # none -> unreaped -> reaped | lost; "unknown" while a waitpid is in flight
        self.root_state = "none"
        self.reason = "UNSET"
        self.cleanup_errors: list[str] = []
        self.pending_interrupt: BaseException | None = None

    def record(self) -> dict[str, object]:
        proc = self.proc
        return {
            "kind": "secret-frame-capture", "reason": self.reason,
            "pid": None if proc is None else proc.pid, "root_state": self.root_state,
            "root_reaped": self.root_state == "reaped", "streams_closed": self.streams_closed,
            "cleanup_confirmed": False, "cleanup_errors": tuple(self.cleanup_errors),
        }


_RETAINED: list[_CaptureOwner] = []
_popen = subprocess.Popen  # test seam


def retained_custody_available() -> bool:
    """True iff this process retains unconfirmed capture custody (all captures refused)."""
    return bool(_RETAINED)


def retained_custody_records() -> tuple[dict[str, object], ...]:
    """Sanitized records; the owner objects themselves stay referenced in the registry."""
    return tuple(owner.record() for owner in _RETAINED)


def _alloc(size: int) -> bytearray:  # test seam: every capture buffer comes from here
    return bytearray(size)


def _zero(buf: bytearray | None) -> None:
    if buf:
        buf[:] = bytes(len(buf))  # same-length assignment: no resize, allowed with exports


def _readinto(fd: int, view: memoryview) -> int | None:  # test seam
    try:
        return os.readv(fd, [view])
    except BlockingIOError:
        return None


def _env_item_ok(key: object, value: object) -> bool:
    return (
        isinstance(key, str) and isinstance(value, str) and bool(key)
        and "=" not in key and "\x00" not in key and "\x00" not in value
    )


def _validated(argv, cwd, env, timeout, max_stdout) -> tuple[tuple[str, ...], str, float]:
    try:
        args = tuple(argv) if isinstance(argv, (tuple, list)) else ()
        cwd_s = os.fspath(cwd) if isinstance(cwd, (str, os.PathLike)) else ""
    except TypeError:
        args, cwd_s = (), ""
    valid = (
        bool(args) and all(isinstance(a, str) and "\x00" not in a for a in args) and os.path.isabs(args[0])
        and isinstance(cwd_s, str) and os.path.isabs(cwd_s) and "\x00" not in cwd_s
        and isinstance(env, Mapping) and all(_env_item_ok(k, v) for k, v in env.items())
        and isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
        and math.isfinite(timeout) and 0 < timeout <= MAX_TIMEOUT_SECONDS
        and type(max_stdout) is int and 0 < max_stdout <= MAX_STDOUT_BYTES
    )
    if not valid:
        raise FrameTransportError("FRAME_ARGUMENT_INVALID")
    return args, cwd_s, float(timeout)


def _require_single_reaper() -> None:
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise FrameTransportError("FRAME_PRECONDITION_SIGCHLD")
    if threading.active_count() != 1:
        raise FrameTransportError("FRAME_PRECONDITION_THREADS")


def capture_frame(
    argv: Sequence[str], cwd: str | os.PathLike[str], env: Mapping[str, str], timeout: float = 60.0,
    *, max_stdout: int = MAX_STDOUT_BYTES,
) -> bytearray:
    """Run one owned producer; return all of its stdout as a fresh bytearray.

    Success requires stdout EOF, stderr EOF, exit status 0, the owned process
    group confirmed absent and both pipes closed, inside one deadline. The
    caller still validates the frame and any availability record.
    """
    if _RETAINED:
        refusal = FrameTransportError("FRAME_CUSTODY_RETAINED")
        refusal.custody_retained = True
        raise refusal
    args, cwd_s, limit = _validated(argv, cwd, env, timeout, max_stdout)
    _require_single_reaper()
    deadline = time.monotonic() + limit
    owner = _CaptureOwner()
    out = scratch = result = None
    try:
        out, scratch = _alloc(max_stdout + 1), _alloc(READ_CHUNK)
        owner.spawn_attempted = True
        try:
            owner.proc = _popen(
                args, cwd=cwd_s, env=dict(env), bufsize=0, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
            )
        except OSError as error:
            owner.spawn_refused = True  # no child, or CPython already reaped the failed exec
            raise FrameTransportError("FRAME_SPAWN_FAILED") from error
        owner.root_state = "unreaped"
        owner.selector = selectors.DefaultSelector()
        for stream, tag in ((owner.proc.stdout, "stdout"), (owner.proc.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            owner.selector.register(stream, selectors.EVENT_READ, tag)
        filled = _pump(owner.selector, out, scratch, max_stdout, deadline)
        if _await_root(owner, deadline) != 0:
            raise FrameTransportError("FRAME_EMITTER_NONZERO")
        if not _group_absent(owner.proc.pid, min(deadline, time.monotonic() + KILL_GRACE_SECONDS)):
            raise FrameTransportError("FRAME_GROUP_RETAINED")
        if not _close_streams(owner):
            raise FrameTransportError("FRAME_STREAM_CLOSE_FAILED")
        if time.monotonic() >= deadline:
            raise FrameTransportError("FRAME_CAPTURE_TIMEOUT")
        result = _alloc(filled)
        result[:] = memoryview(out)[:filled]
        return result
    except BaseException as error:
        try:
            for buf in (result, out, scratch):
                _zero(buf)
        finally:
            _fail(owner, error)
        if owner.pending_interrupt is not None and isinstance(error, Exception):
            raise owner.pending_interrupt from error
        raise
    finally:
        _zero(out)
        _zero(scratch)


def _pump(sel: selectors.BaseSelector, out: bytearray, scratch: bytearray, max_stdout: int, deadline: float) -> int:
    filled = err_total = 0
    out_view, err_view = memoryview(out), memoryview(scratch)
    while sel.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FrameTransportError("FRAME_CAPTURE_TIMEOUT")
        for key, _ in sel.select(min(remaining, 0.25)):
            if key.data == "stdout":
                n = _readinto(key.fd, out_view[filled:min(max_stdout + 1, filled + READ_CHUNK)])
                if n == 0:
                    sel.unregister(key.fileobj)
                elif n:
                    filled += n
                    if filled > max_stdout:
                        raise FrameTransportError("FRAME_STDOUT_OVERFLOW")
            else:
                n = _readinto(key.fd, err_view[:min(READ_CHUNK, MAX_STDERR_BYTES + 1 - err_total)])
                if n == 0:
                    sel.unregister(key.fileobj)
                elif n:
                    scratch[:n] = bytes(n)  # stderr is discarded immediately
                    err_total += n
                    if err_total > MAX_STDERR_BYTES:
                        raise FrameTransportError("FRAME_STDERR_OVERFLOW")
    return filled


def _poll_root(owner: _CaptureOwner) -> int | None:
    proc = owner.proc
    if owner.root_state == "reaped":
        return proc.returncode
    if owner.root_state == "lost":
        raise FrameTransportError("FRAME_CUSTODY_LOST")
    owner.root_state = "unknown"  # an interrupt inside this window forbids later signals
    try:
        pid, status = os.waitpid(proc.pid, os.WNOHANG)
    except ChildProcessError:
        owner.root_state = "lost"  # dead (a living child is always waitable); status unknown
        raise FrameTransportError("FRAME_CUSTODY_LOST") from None
    if pid == 0:
        owner.root_state = "unreaped"
        return None
    proc.returncode = os.waitstatus_to_exitcode(status)
    owner.root_state = "reaped"
    return proc.returncode


def _await_root(owner: _CaptureOwner, deadline: float) -> int:
    while (rc := _poll_root(owner)) is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FrameTransportError("FRAME_CAPTURE_TIMEOUT")
        time.sleep(min(POLL_SECONDS, remaining))
    return rc


def _signal_group(pgid: int, sig: int) -> None:
    """Only called while the root is unreaped, so pgid names exactly the owned group."""
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass  # the post-reap signal-0 probe is the authority on absence


def _group_absent(pgid: int, until: float) -> bool:
    """Signal-0 probe only. After reaping, a reused ID can only make this say 'present'."""
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        if time.monotonic() >= until:
            return False
        time.sleep(POLL_SECONDS)


def _drain_for(owner: _CaptureOwner, seconds: float) -> None:
    end, scratch = time.monotonic() + seconds, _alloc(READ_CHUNK)
    view = memoryview(scratch)
    try:
        while (remaining := end - time.monotonic()) > 0:
            sel = owner.selector
            if sel is None or not sel.get_map():
                time.sleep(min(remaining, 0.05))
                continue
            for key, _ in sel.select(min(remaining, 0.05)):
                n = _readinto(key.fd, view)
                if n == 0:
                    sel.unregister(key.fileobj)
                elif n:
                    scratch[:n] = bytes(n)
    finally:
        _zero(scratch)


def _close_streams(owner: _CaptureOwner) -> bool:
    proc, ok = owner.proc, True
    closers = (owner.selector.close if owner.selector else None, proc.stdout.close, proc.stderr.close)
    for closer in closers:
        if closer is None:
            continue
        try:
            closer()
        except Exception as error:
            ok = False
            owner.cleanup_errors.append(type(error).__name__)
    owner.streams_closed = ok
    return ok


def _cleanup(owner: _CaptureOwner) -> bool:
    proc = owner.proc
    if proc is None:
        return False
    if owner.root_state in ("none", "unknown"):  # interrupted right after spawn or mid-waitpid
        try:
            _poll_root(owner)  # waitpid resolves to unreaped, reaped or lost
        except FrameTransportError:
            pass
    if owner.root_state == "unreaped":
        try:
            _signal_group(proc.pid, signal.SIGTERM)
            _drain_for(owner, TERM_GRACE_SECONDS)  # no reaping during TERM grace
        finally:
            if owner.root_state == "unreaped":
                _signal_group(proc.pid, signal.SIGKILL)
        reap_deadline = time.monotonic() + KILL_GRACE_SECONDS
        while _poll_root(owner) is None:
            if time.monotonic() >= reap_deadline:
                return False  # root stays unreaped: PID remains pinned in the registry
            _drain_for(owner, POLL_SECONDS)
    if owner.root_state not in ("reaped", "lost"):
        return False
    if not _group_absent(proc.pid, time.monotonic() + KILL_GRACE_SECONDS):
        return False
    return _close_streams(owner)


def _fail(owner: _CaptureOwner, error: BaseException) -> None:
    """Never raises; preserves the caller's original exception."""
    if isinstance(error, FrameTransportError):
        owner.reason = error.code
    elif isinstance(error, (KeyboardInterrupt, SystemExit)):
        owner.reason = type(error).__name__
    else:
        owner.reason = "EXCEPTION"
    if owner.proc is not None or (owner.spawn_attempted and not owner.spawn_refused):
        _RETAINED.append(owner)  # pessimistic custody until cleanup is confirmed
        confirmed = False
        try:
            confirmed = _cleanup(owner)
        except BaseException as cleanup_error:
            owner.cleanup_errors.append(type(cleanup_error).__name__)
            if not isinstance(cleanup_error, Exception):
                owner.pending_interrupt = cleanup_error
        if confirmed:
            _RETAINED.remove(owner)
    try:
        if isinstance(error, FrameTransportError):
            error.custody_retained = bool(_RETAINED)
        else:
            error.frame_custody_retained = bool(_RETAINED)  # type: ignore[attr-defined]
    except Exception:
        pass
