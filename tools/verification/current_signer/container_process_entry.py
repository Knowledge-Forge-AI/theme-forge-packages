"""Fixed container entry for a non-init single-process signing worker.

PID 1 owns only its direct child. It never reads the protocol streams. A
private pipe releases that child only after the parent closes its stream
descriptors and clears its future environment. Initial kernel environment
storage is not claimed erased. No signing credential belongs in this entry.
"""
from __future__ import annotations

import os
import signal
import sys

PYTHON = "/usr/bin/python3"
WORKER = "/work/p/tools/verification/current_import_routing.py"


class EntryRefusal(RuntimeError):
    pass


def _target(argv: list[str]) -> tuple[str, ...]:
    if (type(argv) is not list or len(argv) > 128
            or any(type(s) is not str or not s or "\0" in s or len(s) > 128 * 1024 for s in argv)
            or argv[:4] != ["--", PYTHON, "-I", "-B"]):
        raise EntryRefusal()
    target = tuple(argv[1:])
    inspection = len(target) == 5 and target[3] == "-c"
    worker = len(target) >= 5 and target[3:5] == (WORKER, "--current-signer-worker")
    if not (inspection or worker):
        raise EntryRefusal()
    return target


def _wait_for_child(pid: int) -> int:
    while True:
        try:
            reaped, status = os.waitpid(pid, 0)
        except InterruptedError:
            continue
        if reaped != pid:
            raise EntryRefusal()
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return 128 + os.WTERMSIG(status)
        raise EntryRefusal()


def enter_noninit(argv: list[str]) -> None:
    target = _target(argv)
    if (sys.platform != "linux" or os.getpid() != 1
            or os.getuid() == 0 or os.getgid() == 0
            or os.geteuid() != os.getuid() or os.getegid() != os.getgid()
            or any(k in os.environ for k in ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE"))):
        raise EntryRefusal()
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        os.close(write_fd)
        released = os.read(read_fd, 2)
        eof = os.read(read_fd, 1)
        os.close(read_fd)
        if released != b"G" or eof != b"" or os.getpid() <= 1 or os.getppid() != 1:
            raise EntryRefusal()
        os.execve(PYTHON, target, dict(os.environ))
        raise EntryRefusal()
    os.close(read_fd)
    try:
        # Parent-only caught handler; the exec child keeps normal SIGINT semantics.
        signal.signal(signal.SIGINT, lambda *_: None)
        os.environ.clear()
        for fd in (0, 1, 2):
            os.close(fd)
        if os.write(write_fd, b"G") != 1:
            raise EntryRefusal()
        os.close(write_fd)
        code = _wait_for_child(pid)
    except BaseException:
        # Namespace PID1 exit disposes descendants, never proving private cleanup.
        os._exit(125)
    os._exit(code)


def main() -> int:
    try:
        enter_noninit(sys.argv[1:])
    except BaseException:
        try:
            os.write(2, b"PROCESS_ENTRY_REFUSED\n")
        except OSError:
            pass
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
