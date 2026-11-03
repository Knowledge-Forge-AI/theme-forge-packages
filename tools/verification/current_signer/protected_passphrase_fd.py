"""Private passphrase pipe preparation; runner integration remains pending.

This module launches/signals no process and performs no filesystem operations.
The future runner must pass only pass_fds to Popen, call child_started()
immediately after successful launch, and register writer_fileno() for selector
write readiness. It must unregister the writer when write_ready() returns True,
and close this owner on launch failure, timeout, interruption or broken pipe.
The runner owns exact-process termination/reaping and both ordinary stdio
channels. A passphrase descriptor is distinct from RPM6's signature-data stdin.

The private bytearray is overwritten before release. This cannot erase the
caller's original inputs, Python/allocator copies, kernel pipe buffers or child
memory; no complete memory-erasure claim is made. Descriptor identity checks
assume serialized descriptor ownership: concurrent close/dup2 in another thread
cannot be made atomic with a subsequent write/close by this Python component.
"""

from dataclasses import dataclass
import fcntl
import os
import stat

# Matches inputs/protected_signing_runtime.py MAX_PROCESS_STDIN. Includes LF.
MAX_PROCESS_INPUT = 2 * 1024 * 1024
_WRITE_QUANTUM = 65536


class PassphrasePipeError(RuntimeError):
    """Stable error category; never incorporates caller data or OS messages."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, repr=False)
class _Endpoint:
    fd: int
    dev: int
    ino: int
    kind: int
    access: int


def _endpoint(fd):
    info = os.fstat(fd)
    return _Endpoint(fd, info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
                     fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE)


def _same(endpoint):
    return _endpoint(endpoint.fd) == endpoint


class _PassphrasePipe:
    """One anonymous pipe; numeric descriptors are metadata, never authority."""
    production_authority = False
    integration_status = "integration-pending"

    def __init__(self, value):
        self._pending = bytearray()
        self._offset = 0
        self._reader = None
        self._writer = None
        self._provisional_reader = None
        self._uncertain = set()
        self._state = "constructing"
        try:
            # Validate/copy the complete bounded bytes-like input BEFORE pipes.
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise PassphrasePipeError("INPUT_TYPE")
            with memoryview(value) as view:
                if not view.c_contiguous or view.nbytes >= MAX_PROCESS_INPUT:
                    raise PassphrasePipeError("INPUT_BOUND")
                with view.cast("B") as octets:
                    self._pending = bytearray(octets)
            if 10 in self._pending or 0 in self._pending:
                raise PassphrasePipeError("INPUT_LINE")
            self._pending.append(10)
            # Python's pipe() descriptors are non-inheritable (PEP 446).
            read_fd, write_fd = os.pipe()
            # Capture each endpoint immediately. fstat failure still leaves its
            # numeric resource tracked; unverifiable resources are never closed.
            self._provisional_reader = _Endpoint(read_fd, -1, -1, -1, os.O_RDONLY)
            self._writer = _Endpoint(write_fd, -1, -1, -1, os.O_WRONLY)
            self._provisional_reader = _endpoint(read_fd)
            self._writer = _endpoint(write_fd)
            high = fcntl.fcntl(read_fd, fcntl.F_DUPFD_CLOEXEC, 16)
            self._reader = _Endpoint(high, -1, -1, -1, os.O_RDONLY)
            self._reader = _endpoint(high)
            self._close_endpoint("_provisional_reader", "provisional-reader")
            os.set_inheritable(self._reader.fd, False)
            os.set_inheritable(self._writer.fd, False)
            os.set_blocking(self._writer.fd, False)
            self._state = "prepared"
            self._validate_transfer()
        except BaseException as error:
            self._abort()
            if self._uncertain:
                error.retained_pipe = self
            raise

    def __repr__(self):
        return f"<_PassphrasePipe state={self._state}>"

    def _clear(self):
        for index in range(len(self._pending)):
            self._pending[index] = 0
        self._pending.clear()
        self._offset = 0

    def _check_endpoint(self, endpoint, label, *, blocking):
        try:
            valid = (endpoint is not None and _same(endpoint)
                     and endpoint.kind == stat.S_IFIFO
                     and endpoint.access == (os.O_RDONLY if label == "reader" else os.O_WRONLY)
                     and not os.get_inheritable(endpoint.fd)
                     and os.get_blocking(endpoint.fd) == blocking)
        except OSError:
            valid = False
        if not valid:
            self._uncertain.add(label)
            raise PassphrasePipeError("DESCRIPTOR_STATE")

    def _validate_transfer(self):
        if self._state != "prepared":
            raise PassphrasePipeError("TRANSFER_STATE")
        self._check_endpoint(self._reader, "reader", blocking=True)
        self._check_endpoint(self._writer, "writer", blocking=False)

    @property
    def reader_fd(self):
        try:
            self._validate_transfer()
            return self._reader.fd
        except BaseException:
            self._abort()
            raise

    @property
    def pass_fds(self):
        """Only the owned reader may be inherited by an explicit Popen call."""
        return (self.reader_fd,)

    def child_started(self):
        """Successful-Popen hook; close parent reader before any streaming."""
        try:
            self._validate_transfer()
            self._close_endpoint("_reader", "reader")
            if self._uncertain:
                raise PassphrasePipeError("DESCRIPTOR_IDENTITY_UNCONFIRMED")
            self._state = "streaming"
        except BaseException:
            self._abort()
            raise

    def writer_fileno(self):
        """Selector registration only; this non-inheritable fd is not pass_fds."""
        try:
            if self._state != "streaming":
                raise PassphrasePipeError("WRITE_STATE")
            self._check_endpoint(self._writer, "writer", blocking=False)
            return self._writer.fd
        except BaseException:
            self._abort()
            raise

    def write_ready(self):
        """Attempt at most one bounded nonblocking write; True means EOF sent.

        EAGAIN/EINTR makes no progress and returns False. Any other failure
        clears pending memory and closes only still-identical owned endpoints.
        """
        try:
            fd = self.writer_fileno()
            with memoryview(self._pending) as view:
                # Release the slice explicitly even if a Python-level write
                # wrapper retains arguments in an exception traceback.
                with view[self._offset:self._offset + _WRITE_QUANTUM] as chunk:
                    written = os.write(fd, chunk)
            if written <= 0:
                raise PassphrasePipeError("WRITE_NO_PROGRESS")
            self._offset += written
            if self._offset == len(self._pending):
                self._close_endpoint("_writer", "writer")
                self._clear()
                if self._uncertain:
                    raise PassphrasePipeError("DESCRIPTOR_IDENTITY_UNCONFIRMED")
                self._state = "complete"
                return True
            return False
        except (BlockingIOError, InterruptedError):
            return False
        except BrokenPipeError:
            self._abort()
            raise PassphrasePipeError("BROKEN_PIPE") from None
        except OSError:
            self._abort()
            raise PassphrasePipeError("WRITE_FAILED") from None
        except BaseException:
            self._abort()
            raise

    def _close_endpoint(self, attribute, label):
        endpoint = getattr(self, attribute)
        if endpoint is None:
            return
        try:
            if not _same(endpoint):
                self._uncertain.add(label)
                return
            os.close(endpoint.fd)
            setattr(self, attribute, None)
        except OSError:
            # EBADF or a failed close is not permission to close a recycled fd.
            self._uncertain.add(label)

    def _abort(self):
        for attribute, label in (("_reader", "reader"), ("_writer", "writer"),
                                 ("_provisional_reader", "provisional-reader")):
            self._close_endpoint(attribute, label)
        self._clear()
        self._state = "unconfirmed" if self._uncertain else "closed"

    def close(self):
        self._abort()
        if self._uncertain:
            raise PassphrasePipeError("DESCRIPTOR_IDENTITY_UNCONFIRMED")

    @property
    def cleanup_confirmed(self):
        return (not self._uncertain and self._reader is None and self._writer is None
                and self._provisional_reader is None and not self._pending)

    @property
    def unconfirmed_endpoints(self):
        return tuple(sorted(self._uncertain))

    def __enter__(self):
        if self._state != "prepared":
            raise PassphrasePipeError("CONTEXT_STATE")
        return self

    def __exit__(self, _type, body, _traceback):
        try:
            self.close()
        except PassphrasePipeError as cleanup:
            if body is not None:
                cleanup.body_error = body
                raise cleanup from body
            raise
        return False


def _passphrase_pipe(value):
    """Private factory. No caller-selected descriptor or command parameters."""
    return _PassphrasePipe(value)
