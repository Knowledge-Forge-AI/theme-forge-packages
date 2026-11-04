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


# ---------------------------------------------------------------------------
# Built-in default bridge for the temporary online intake phase.
#
# Pure parsing and fixed argv only. Nothing here creates, deletes or
# reconfigures the built-in bridge. The only network mutation the controller
# performs with these helpers is attaching (at run) and detaching (at the gate)
# its own resolved worker endpoint. Parsed IDs stay internal; every refusal is
# a fixed code without Docker output, IDs, labels or paths. The custom-network
# helpers above are unchanged and remain for the historical probe caller.

import hashlib as _hashlib

DEFAULT_BRIDGE_NAME = "bridge"
OWNER_LABEL_KEY = "tf.current-signer.run"
_OWNER_LABEL_DOMAIN = b"tf.current-signer.default-bridge.owner-label.v1\x00"
_RUN_SUFFIX = re.compile(r"[0-9]{1,20}")
_DEFAULT_BRIDGE_MARKER_OPTION = "com.docker.network.bridge.default_bridge"
DEFAULT_BRIDGE_INSPECT_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},'
    '"scope":{{json .Scope}},"internal":{{json .Internal}},'
    '"default_marker":{{json (index .Options "' + _DEFAULT_BRIDGE_MARKER_OPTION + '")}},'
    '"containers":{{json .Containers}}}'
)
WORKER_NETWORKS_FORMAT = "{{json .NetworkSettings.Networks}}"
_BRIDGE_FIELDS = frozenset({"id", "name", "driver", "scope", "internal", "default_marker", "containers"})
MAX_LISTING_BYTES = 4096
DEFAULT_BRIDGE_ERROR_CODES = frozenset({
    "BRIDGE_IDENTITY_BOUND",
    "BRIDGE_IDENTITY_FORMAT",
    "BRIDGE_IDENTITY_DUPLICATE",
    "BRIDGE_IDENTITY_MISMATCH",
    "BRIDGE_IDENTITY_CHANGED",
    "BRIDGE_PEER_PRESENT",
    "BRIDGE_OWNERSHIP_MISMATCH",
    "WORKER_NETWORK_FORMAT",
    "WORKER_NETWORK_MISMATCH",
    "CONTAINER_ID_FORMAT",
    "CONTAINER_LISTING_FORMAT",
    "CONTAINER_NAME_COLLISION",
    "OWNER_LABEL_INPUT",
    "OWNER_LOOKUP_EMPTY",
    "OWNER_LOOKUP_AMBIGUOUS",
    "RESOURCE_ID",
})


@dataclass(frozen=True, repr=False)
class BridgeObservation:
    network_id: str
    peer_ids: frozenset

    def __repr__(self) -> str:  # IDs are internal only.
        return "BridgeObservation(<withheld>)"


def _strict_pairs(code: str):
    def hook(items):
        value = {}
        for key, item in items:
            if key in value:
                raise GateError(code)
            value[key] = item
        return value
    return hook


def _reject_constant(_name: str):
    raise ValueError("JSON_CONSTANT")


def _strict_line_json(data: object, *, bound_code: str, format_code: str, duplicate_code: str):
    if type(data) is not bytes or len(data) > MAX_LINE_BYTES:
        raise GateError(bound_code)
    if classify_message_framing(data) is not None:
        raise GateError(format_code)
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=_strict_pairs(duplicate_code),
                          parse_constant=_reject_constant)
    except GateError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise GateError(format_code) from None


def require_container_id(value: object) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise GateError("CONTAINER_ID_FORMAT")
    return value


def _require_bridge_id(value: object) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise GateError("BRIDGE_IDENTITY_FORMAT")
    return value


def _require_owner_label(value: object) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise GateError("OWNER_LABEL_INPUT")
    return value


def _require_container_name(value: object) -> str:
    if type(value) is not str or not _RESOURCE.fullmatch(value):
        raise GateError("RESOURCE_ID")
    return value


def default_bridge_owner_label(run_id_suffix: str, challenge_nonce: str) -> str:
    """Run- and nonce-bound unpredictable owner label value (64 lowercase hex)."""
    if (type(run_id_suffix) is not str or not _RUN_SUFFIX.fullmatch(run_id_suffix)
            or type(challenge_nonce) is not str or not _HEX64.fullmatch(challenge_nonce)):
        raise GateError("OWNER_LABEL_INPUT")
    return _hashlib.sha256(
        _OWNER_LABEL_DOMAIN + run_id_suffix.encode("ascii") + challenge_nonce.encode("ascii")
    ).hexdigest()


def default_bridge_inspect_command() -> tuple[str, ...]:
    return (DOCKER, "network", "inspect", "--format", DEFAULT_BRIDGE_INSPECT_FORMAT, DEFAULT_BRIDGE_NAME)


def container_name_listing_command(container_name: str) -> tuple[str, ...]:
    name = _require_container_name(container_name)
    return (DOCKER, "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", f"name=^/{name}$")


def owned_container_listing_command(container_name: str, owner_label: str) -> tuple[str, ...]:
    name = _require_container_name(container_name)
    label = _require_owner_label(owner_label)
    return (DOCKER, "container", "ls", "--all", "--no-trunc", "--quiet",
            "--filter", f"name=^/{name}$", "--filter", f"label={OWNER_LABEL_KEY}={label}")


def worker_networks_command(container_id: str) -> tuple[str, ...]:
    return (DOCKER, "container", "inspect", "--format", WORKER_NETWORKS_FORMAT, require_container_id(container_id))


def default_bridge_gate_commands(bridge_id: str, container_id: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Disconnect/readback bound to the captured bridge ID and resolved immutable container ID."""
    bridge = _require_bridge_id(bridge_id)
    owned = require_container_id(container_id)
    return ((DOCKER, "network", "disconnect", bridge, owned), worker_networks_command(owned))


def owned_container_remove_command(container_id: str) -> tuple[str, ...]:
    """Removal is only ever by resolved immutable ID, never by name."""
    return (DOCKER, "container", "rm", "--force", require_container_id(container_id))


def require_default_bridge_identity(data: bytes, *, expected_id: str | None = None) -> BridgeObservation:
    doc = _strict_line_json(data, bound_code="BRIDGE_IDENTITY_BOUND", format_code="BRIDGE_IDENTITY_FORMAT",
                            duplicate_code="BRIDGE_IDENTITY_DUPLICATE")
    if type(doc) is not dict or set(doc) != _BRIDGE_FIELDS:
        raise GateError("BRIDGE_IDENTITY_FORMAT")
    network_id = doc["id"]
    if type(network_id) is not str or not _HEX64.fullmatch(network_id):
        raise GateError("BRIDGE_IDENTITY_FORMAT")
    if (type(doc["name"]) is not str or doc["name"] != DEFAULT_BRIDGE_NAME
            or type(doc["driver"]) is not str or doc["driver"] != "bridge"
            or type(doc["scope"]) is not str or doc["scope"] != "local"
            or doc["internal"] is not False
            or type(doc["default_marker"]) is not str or doc["default_marker"] != "true"):
        raise GateError("BRIDGE_IDENTITY_MISMATCH")
    containers = doc["containers"]
    if type(containers) is not dict:
        raise GateError("BRIDGE_IDENTITY_FORMAT")
    for key, value in containers.items():
        if not _HEX64.fullmatch(key) or type(value) is not dict:
            raise GateError("BRIDGE_IDENTITY_FORMAT")
    if expected_id is not None and network_id != _require_bridge_id(expected_id):
        raise GateError("BRIDGE_IDENTITY_CHANGED")
    return BridgeObservation(network_id, frozenset(containers))


def require_no_bridge_peers(observation: BridgeObservation) -> None:
    if type(observation) is not BridgeObservation or observation.peer_ids:
        raise GateError("BRIDGE_PEER_PRESENT")


def require_sole_owned_bridge_peer(observation: BridgeObservation, owned_id: str) -> None:
    owned = require_container_id(owned_id)
    if type(observation) is not BridgeObservation:
        raise GateError("BRIDGE_OWNERSHIP_MISMATCH")
    if observation.peer_ids != frozenset({owned}):
        raise GateError("BRIDGE_PEER_PRESENT" if owned in observation.peer_ids else "BRIDGE_OWNERSHIP_MISMATCH")


def require_worker_on_default_bridge(data: bytes, bridge_id: str) -> None:
    expected = _require_bridge_id(bridge_id)
    networks = _strict_line_json(data, bound_code="WORKER_NETWORK_FORMAT", format_code="WORKER_NETWORK_FORMAT",
                                 duplicate_code="WORKER_NETWORK_FORMAT")
    if type(networks) is not dict or set(networks) != {DEFAULT_BRIDGE_NAME}:
        raise GateError("WORKER_NETWORK_MISMATCH")
    endpoint = networks[DEFAULT_BRIDGE_NAME]
    if type(endpoint) is not dict or endpoint.get("NetworkID") != expected:
        raise GateError("WORKER_NETWORK_MISMATCH")


def parse_container_id_listing(data: bytes) -> tuple[str, ...]:
    """Parse `container ls --no-trunc --quiet` output: zero or more distinct 64-hex lines."""
    if type(data) is not bytes or len(data) > MAX_LISTING_BYTES:
        raise GateError("CONTAINER_LISTING_FORMAT")
    if data == b"":
        return ()
    if not data.endswith(b"\n") or b"\r" in data:
        raise GateError("CONTAINER_LISTING_FORMAT")
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise GateError("CONTAINER_LISTING_FORMAT") from None
    rows = text[:-1].split("\n")
    if any(not _HEX64.fullmatch(row) for row in rows) or len(set(rows)) != len(rows):
        raise GateError("CONTAINER_LISTING_FORMAT")
    return tuple(rows)


def require_single_owned_id(ids: tuple[str, ...]) -> str:
    if type(ids) is not tuple:
        raise GateError("CONTAINER_LISTING_FORMAT")
    if not ids:
        raise GateError("OWNER_LOOKUP_EMPTY")
    if len(ids) != 1:
        raise GateError("OWNER_LOOKUP_AMBIGUOUS")
    return require_container_id(ids[0])
