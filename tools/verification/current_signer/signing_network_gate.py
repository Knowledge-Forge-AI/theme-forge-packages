"""Source-only protocol for delayed signing input after network detachment.

This module does not launch Docker, collect inputs, or own key material. The
host process owner supplies bounded I/O and the existing secret-frame emitter.
Pure protocol acceptance is not native Docker isolation qualification.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Callable

MAX_LINE_BYTES = 4096
DOCKER = "/usr/bin/docker"
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RESOURCE = re.compile(r"tf-current-signer-[0-9]{1,20}-[0-9]{1,4}")
FRAMING_REASONS = frozenset({
    "EMPTY_EOF",
    "NON_BYTES",
    "LINE_OVERFLOW",
    "CR_PRESENT",
    "TRUNCATED_NO_NEWLINE",
    "MULTIPLE_NEWLINES",
})


class GateError(ValueError):
    """Fixed codes only: no transport output, argv, or private input."""

    def __init__(
        self,
        code: str,
        *,
        detail: str | None = None,
        framing_reason: str | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.framing_reason = framing_reason if framing_reason in FRAMING_REASONS else None
        super().__init__(code)


@dataclass(frozen=True)
class SourceBinding:
    p_commit: str
    p_tree: str
    r_commit: str
    r_tree: str
    source_closure_sha256: str
    rs9_run: int

    def record(self) -> dict:
        for value in (self.p_commit, self.p_tree, self.r_commit, self.r_tree):
            if type(value) is not str or not _HEX40.fullmatch(value):
                raise GateError("SOURCE_BINDING")
        if (type(self.source_closure_sha256) is not str
                or not _HEX64.fullmatch(self.source_closure_sha256)
                or type(self.rs9_run) is not int or self.rs9_run <= 0):
            raise GateError("SOURCE_BINDING")
        return dict(self.__dict__)


def _require_worker_pid(worker_pid: int) -> int:
    if type(worker_pid) is not int or not 1 <= worker_pid <= 2147483647:
        raise GateError("WORKER_PID")
    return worker_pid


def encode_message(kind: str, binding: SourceBinding, nonce: str, *, worker_pid: int) -> bytes:
    if kind not in {"ready", "isolation-challenge", "isolated"}:
        raise GateError("MESSAGE_KIND")
    if type(nonce) is not str or not _HEX64.fullmatch(nonce):
        raise GateError("CHALLENGE_FORMAT")
    _require_worker_pid(worker_pid)
    result = json.dumps({"schema": "tf.signer-network-gate.v2", "kind": kind, "worker_pid": worker_pid,
                         "source": binding.record(), "challenge": nonce},
                        sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(result) > MAX_LINE_BYTES:
        raise GateError("MESSAGE_BOUND")
    return result


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise GateError("MESSAGE_DUPLICATE")
        value[key] = item
    return value


def classify_message_framing(line: object) -> str | None:
    if type(line) is not bytes:
        return "NON_BYTES"
    if len(line) == 0:
        return "EMPTY_EOF"
    if len(line) > MAX_LINE_BYTES:
        return "LINE_OVERFLOW"
    if b"\r" in line:
        return "CR_PRESENT"
    if not line.endswith(b"\n"):
        return "TRUNCATED_NO_NEWLINE"
    if line.count(b"\n") != 1:
        return "MULTIPLE_NEWLINES"
    return None


def require_message(line: bytes, kind: str, binding: SourceBinding, nonce: str, *, worker_pid: int | None = None) -> int:
    framing_reason = classify_message_framing(line)
    if framing_reason is not None:
        raise GateError("MESSAGE_FRAMING", framing_reason=framing_reason)
    try:
        actual = json.loads(line.decode("ascii"), object_pairs_hook=_pairs)
        observed_pid = _require_worker_pid(actual.get("worker_pid") if type(actual) is dict else None)
        if worker_pid is None:
            if kind != "ready":
                raise GateError("WORKER_PID")
            worker_pid = _require_worker_pid(observed_pid)
        expected = json.loads(encode_message(kind, binding, nonce, worker_pid=worker_pid))
    except GateError:
        raise
    except (UnicodeError, ValueError):
        raise GateError("MESSAGE_FORMAT") from None
    if actual != expected:
        raise GateError("MESSAGE_BINDING")
    return worker_pid


def docker_gate_commands(network: str, container: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    # The containing process owner must also prove exclusive creation/custody.
    if any(type(x) is not str or not _RESOURCE.fullmatch(x) for x in (network, container)):
        raise GateError("RESOURCE_ID")
    return ((DOCKER, "network", "disconnect", network, container),
            (DOCKER, "container", "inspect", "--format",
             "{{json .NetworkSettings.Networks}}", container))


def require_detached_networks(data: bytes) -> None:
    if type(data) is not bytes or len(data) > MAX_LINE_BYTES:
        raise GateError("NETWORK_READBACK_BOUND")
    try:
        networks = json.loads(data.decode("ascii"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError):
        raise GateError("NETWORK_READBACK_FORMAT") from None
    if type(networks) is not dict or networks:
        raise GateError("NETWORK_ATTACHED")


class HostGate:
    """One-shot host ordering. No operation is retried after failure."""

    def __init__(self, binding: SourceBinding, nonce: str) -> None:
        binding.record()
        if type(nonce) is not str or not _HEX64.fullmatch(nonce):
            raise GateError("CHALLENGE_FORMAT")
        self.worker_pid: int | None = None
        self.binding, self.nonce = binding, nonce
        self.state = "waiting-ready"
        self.failed_phase: str | None = None
        self.frame_emitted = False
        self.retained_error: BaseException | None = None

    def release_frame(self, *, ready: bytes | Callable[[], bytes], disconnect: Callable[[], None],
                      inspect_networks: Callable[[], bytes],
                      exchange_challenge: Callable[[bytes], bytes],
                      emit_existing_frame_and_eof: Callable[[], None]) -> None:
        if self.state != "waiting-ready":
            raise GateError("GATE_REUSED")
        self.state = "checking-ready"
        try:
            ready_line = ready() if callable(ready) else ready
            self.worker_pid = require_message(ready_line, "ready", self.binding, self.nonce)
            self.state = "disconnecting"
            disconnect()
            require_detached_networks(inspect_networks())
            self.state = "checking-isolation"
            ack = exchange_challenge(encode_message("isolation-challenge", self.binding, self.nonce, worker_pid=self.worker_pid))
            require_message(ack, "isolated", self.binding, self.nonce, worker_pid=self.worker_pid)
            self.state = "emitting-frame"
            self.frame_emitted = True
            emit_existing_frame_and_eof()
            self.state = "frame-closed"
        except BaseException as error:
            # The caller owns real child/stream retention and finalization.
            self.failed_phase = self.state
            self.retained_error = error
            self.state = "failed"
            raise


def worker_acknowledgement(challenge: bytes, binding: SourceBinding, nonce: str,
                           prove_isolation: Callable[[], None], *, worker_pid: int) -> bytes:
    require_message(challenge, "isolation-challenge", binding, nonce, worker_pid=worker_pid)
    prove_isolation()  # No private input read until this succeeds and ack is sent.
    return encode_message("isolated", binding, nonce, worker_pid=worker_pid)
