"""Framing, detached protocol descriptors, and foreground container IO session.

Owns:
- Worker stdio detachment (`fd 0 -> /dev/null`, `fd 1 -> stderr`) onto private
  non-inheritable protocol descriptors (`ProtocolStreams`).
- Bounded delayed `TFC6GPG1` secret frame validation and zero-on-exit reading
  (`validate_frame_bytes`, `read_secret_frame`).
- Host selector-driven non-deadlocking `stdout`/`stderr`/`stdin` session and
  process-group lifecycle (`ForegroundContainerSession`).
"""

from __future__ import annotations

import os
import selectors
import signal
import time
from typing import Any

from source_closure import (
    MAX_FRAME_SECRET_BYTES, FRAME_MAGIC,
    MAX_PROTOCOL_LINE_BYTES,
    unpack_frame_header,
    zero_bytes,
)

MAX_STDERR_BYTES = 65536


class ProtocolIOError(RuntimeError):
    """Fixed-code protocol or frame IO refusal; never embeds secret payloads."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


class ProtocolStreams:
    """Private non-inheritable protocol descriptors detached from worker stdio."""

    def __init__(self, in_fd: int, out_fd: int, *, detached_stdio: bool = False):
        os.set_inheritable(in_fd, False)
        os.set_inheritable(out_fd, False)
        self.in_fd: int | None = in_fd
        self.out_fd: int | None = out_fd
        self.in_status, self.out_status = "open", "open"
        self.detached_stdio = detached_stdio
        self.close_ledger: list[dict[str, object]] = []
        self.close_errors: list[BaseException] = []

    @classmethod
    def detach_stdio(cls, error_cls: type[RuntimeError] = ProtocolIOError) -> ProtocolStreams:
        devnull = os.open("/dev/null", os.O_RDONLY)
        in_fd = out_fd = None
        try:
            in_fd = os.dup(0)
            os.set_inheritable(in_fd, False)
            os.dup2(devnull, 0)
            out_fd = os.dup(1)
            os.set_inheritable(out_fd, False)
            os.dup2(2, 1)
        except BaseException as error:
            for fd in (in_fd, out_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            raise error_cls("PROTOCOL_STDIO_DETACH", "Unable to detach worker stdio") from error
        finally:
            try:
                os.close(devnull)
            except OSError:
                pass
        return cls(in_fd, out_fd, detached_stdio=True)

    def read_line(self, max_bytes: int = MAX_PROTOCOL_LINE_BYTES) -> bytes:
        if self.in_status != "open" or self.in_fd is None:
            raise ProtocolIOError("PROTOCOL_STDIN_CLOSED", "Protocol input is not open")
        buf = bytearray()
        while len(buf) <= max_bytes:
            chunk = os.read(self.in_fd, 1)
            if not chunk:
                break
            buf.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(buf)

    def read_exact(self, count: int) -> bytearray:
        if self.in_status != "open" or self.in_fd is None:
            raise ProtocolIOError("PROTOCOL_STDIN_CLOSED", "Protocol input is not open")
        if type(count) is not int or not 0 <= count <= MAX_FRAME_SECRET_BYTES:
            raise ProtocolIOError("PROTOCOL_READ_BOUND", "Protocol read bound invalid")
        buf, filled = bytearray(count), 0
        try:
            while filled < count:
                view = memoryview(buf)[filled:min(count, filled + 65536)]
                try:
                    n = os.readv(self.in_fd, [view])
                finally:
                    view.release()
                if n == 0:
                    zero_bytes(buf)
                    del buf[:]
                    break
                filled += n
            return buf
        except BaseException:
            zero_bytes(buf)
            raise

    def write_line(self, data: bytes) -> None:
        if self.out_status != "open" or self.out_fd is None:
            raise ProtocolIOError("PROTOCOL_STDOUT_CLOSED", "Protocol output is not open")
        view = memoryview(data)
        while view:
            written = os.write(self.out_fd, view)
            if written <= 0:
                raise ProtocolIOError("PROTOCOL_WRITE_FAILED", "Protocol output write made no progress")
            view = view[written:]

    def _close_stream(self, attr_fd: str, attr_status: str, label: str) -> None:
        fd = getattr(self, attr_fd)
        if getattr(self, attr_status) in {"closed", "uncertain"} or fd is None:
            return
        setattr(self, attr_fd, None)
        try:
            os.close(fd)
        except BaseException as error:
            setattr(self, attr_status, "uncertain")
            self.close_ledger.append({"stream": label, "fd": fd, "status": "uncertain"})
            self.close_errors.append(error)
            raise ProtocolIOError("PROTOCOL_CLOSE_FAILED", f"Protocol {label} close failed") from error
        setattr(self, attr_status, "closed")
        self.close_ledger.append({"stream": label, "fd": fd, "status": "closed"})

    def close_in(self) -> None:
        self._close_stream("in_fd", "in_status", "in")

    def close_out(self) -> None:
        self._close_stream("out_fd", "out_status", "out")

    def close_all(self) -> None:
        for closer in (self.close_in, self.close_out):
            try:
                closer()
            except BaseException:
                pass
        if self.close_errors:
            raise ProtocolIOError("PROTOCOL_CLOSE_FAILED", "Protocol stream close failed")


def read_secret_frame(
    streams: ProtocolStreams,
    error_cls: type[RuntimeError] = ProtocolIOError,
) -> tuple[bytearray, bytearray]:
    key_buf, phrase_buf, extra = bytearray(), bytearray(), bytearray()
    try:
        key_len, phrase_len = unpack_frame_header(streams.read_exact(16), error_cls)
        key_buf = streams.read_exact(key_len)
        phrase_buf = streams.read_exact(phrase_len)
        extra = streams.read_exact(1)
        if len(key_buf) != key_len or len(phrase_buf) != phrase_len or extra:
            raise error_cls("STDIN_FRAME_TRUNCATED", "Secret frame payload length mismatch")
        if b"\x00" in key_buf or b"\x00" in phrase_buf:
            raise error_cls("STDIN_FRAME_NUL", "Secret frame contains NUL byte")
        streams.close_in()
        return key_buf, phrase_buf
    except BaseException as error:
        zero_bytes(key_buf)
        zero_bytes(phrase_buf)
        try:
            streams.close_in()
        except BaseException as cleanup_error:
            error.protocol_close_error = cleanup_error
        raise
    finally:
        zero_bytes(extra)


def validate_frame_bytes(
    frame: bytes | bytearray,
    error_cls: type[RuntimeError] = ProtocolIOError,
) -> None:
    if len(frame) < 16 or bytes(frame[:8]) != FRAME_MAGIC:
        raise error_cls("FRAME_HEADER_INVALID", "Emitted stdin frame header invalid")
    key_len, phrase_len = unpack_frame_header(frame[:16], error_cls)
    if len(frame) != 16 + key_len + phrase_len or frame.find(b"\x00", 16) != -1:
        raise error_cls("FRAME_PAYLOAD_INVALID", "Emitted stdin frame bounds or NUL check failed")


class ForegroundContainerSession:
    """Manages foreground worker process IO with selector-driven stderr draining."""

    def __init__(self, proc: Any, deadline: float, error_cls: type[RuntimeError] = ProtocolIOError):
        self.proc = proc
        self.deadline = deadline
        self._error_cls = error_cls
        self.selector = selectors.DefaultSelector()
        self._stdout_buf = bytearray()
        self._stdout_eof = False
        self.stderr_buf = bytearray()
        self.cleanup_uncertain = False
        if proc.stdin is not None:
            os.set_blocking(proc.stdin.fileno(), False)
        for stream, tag in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, tag)

    def _remaining(self) -> float:
        rem = self.deadline - time.monotonic()
        if rem <= 0:
            raise self._error_cls("HOST_CONTROLLER_TIMEOUT", "Foreground worker session timed out")
        return rem

    def _pump_once(self, timeout: float) -> None:
        if not self.selector.get_map():
            return
        for key, _ in self.selector.select(timeout=min(timeout, 0.05)):
            chunk = os.read(key.fd, 4096)
            if key.data == "stdout":
                if not chunk:
                    self._stdout_eof = True
                    self.selector.unregister(key.fileobj)
                else:
                    self._stdout_buf.extend(chunk)
                    if len(self._stdout_buf) > MAX_PROTOCOL_LINE_BYTES * 2:
                        raise self._error_cls("PROTOCOL_STDOUT_OVERFLOW", "Worker protocol stdout exceeded bound")
            elif not chunk:
                self.selector.unregister(key.fileobj)
            elif len(self.stderr_buf) < MAX_STDERR_BYTES:
                self.stderr_buf.extend(chunk[: MAX_STDERR_BYTES - len(self.stderr_buf)])

    def read_protocol_line(self) -> bytes:
        while b"\n" not in self._stdout_buf and not self._stdout_eof:
            self._pump_once(self._remaining())
        nl = self._stdout_buf.find(b"\n")
        if nl != -1:
            line = bytes(self._stdout_buf[: nl + 1])
            del self._stdout_buf[: nl + 1]
            return line
        line = bytes(self._stdout_buf)
        self._stdout_buf.clear()
        return line

    def require_no_extra_stdout(self, grace_seconds: float = 0.02) -> None:
        if not self._stdout_buf and not self._stdout_eof:
            self._pump_once(min(self._remaining(), grace_seconds))
        if self._stdout_buf:
            raise self._error_cls("PROTOCOL_EXTRA_STDOUT", "Unexpected extra bytes on worker stdout after ack")

    def require_stdout_clean_eof(self) -> None:
        while not self._stdout_eof:
            self._pump_once(self._remaining())
        if self._stdout_buf:
            raise self._error_cls("PROTOCOL_EXTRA_STDOUT", "Unexpected extra bytes on worker stdout after ack")

    def write_stdin(self, payload: bytes | bytearray, *, close_after: bool = False) -> None:
        if self.proc.stdin is None:
            raise self._error_cls("PROTOCOL_STDIN_UNAVAILABLE", "Worker stdin is already closed")
        fd = self.proc.stdin.fileno()
        view = memoryview(payload)
        while view:
            self._pump_once(0.0)
            rem = self._remaining()
            try:
                written = os.write(fd, view[:65536])
            except BlockingIOError:
                self._pump_once(min(rem, 0.02))
                continue
            if written <= 0:
                raise self._error_cls("PROTOCOL_STDIN_WRITE", "Worker stdin write made no progress")
            view = view[written:]
        if close_after:
            self.close_stdin()

    def close_stdin(self) -> None:
        if self.proc.stdin is None:
            return
        stream, self.proc.stdin = self.proc.stdin, None
        try:
            stream.close()
        except BaseException as error:
            self.cleanup_uncertain = True
            raise self._error_cls("PROTOCOL_STDIN_CLOSE", "Worker stdin close failed") from error

    def wait_for_exit(self) -> int:
        while True:
            rc = self.proc.poll()
            if rc is not None:
                self._pump_once(0.01)
                if not self.selector.get_map():
                    return int(rc)
                break
            self._pump_once(self._remaining())
        return int(self.proc.wait(timeout=1.0))

    def terminate_and_close(self) -> None:
        try:
            if self.proc.poll() is None:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except OSError:
                    self.proc.kill()
                self.proc.wait(timeout=5.0)
        except BaseException:
            self.cleanup_uncertain = True
        try:
            self.selector.close()
        except BaseException:
            self.cleanup_uncertain = True
        for attr in ("stdin", "stdout", "stderr"):
            stream = getattr(self.proc, attr, None)
            if stream is not None:
                setattr(self.proc, attr, None)
                try:
                    stream.close()
                except BaseException:
                    self.cleanup_uncertain = True
