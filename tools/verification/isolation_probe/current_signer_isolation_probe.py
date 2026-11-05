"""Key-free diagnostic probe of the current signer container network lifecycle.

This source authorizes no hosted run. Adoption and invocation require their
current bounded owner disposition. This module never
signs, never reads or maps signing secrets, never mints a production gate
message or admission handle, and never relaxes, replaces or bypasses the
production isolation predicate. Diagnostic completion is not isolation
acceptance, and no result establishes listener identity or root cause.

Roles (one file because ``python -I`` does not import sibling modules):

``--observe`` (inside the container, as the unprivileged runner UID)
    Loads the production ``signing_network_gate``/``signing_linux_isolation``
    leaves only from bytes authenticated by the pinned leaf manifest. It takes
    exactly two fixed snapshots of the same metadata the production predicate
    reads (attached before the host disconnects; after the host-confirmed
    detachment). Raw bytes exist only in local memory and are reduced to
    closed categories plus the unchanged production predicate verdict.

``--host`` (on the hosted runner)
    Authenticates the clean P checkout and unchanged production pins, builds
    the admitted key-free runtime image through the production image-build
    leaves inside one in-memory same-process lease, runs exactly one observed
    lifecycle selected by ``--network-profile``, disposes the image and writes
    one closed-schema (v2, profile-discriminated) RESULT.json.

    ``custom-bridge`` (historical direct-CLI default; not a hosted allowance):
    the production-shaped network create/run/disconnect/inspect lifecycle,
    reusing the production teardown with a deletion-restricted runner. Unknown
    creation is retained; only the captured owned network ID can be deleted,
    and containers are never forced away by name. A remaining container makes
    the diagnostic refuse.

    ``default-bridge`` (selected explicitly by the workflow): the observer joins
    the built-in ``bridge`` with a run/nonce-bound owner label. The authenticated
    controller helpers perform the bridge identity/no-peer/name-free preflight,
    resolve and pin the owned immutable container ID before the detach, and run
    the ownership-bound teardown. No network is created, deleted, connected or
    reconfigured; only the owned worker endpoint is detached, the built-in
    bridge is preserved (``network_removed`` is reported false) and only the
    resolved owned immutable ID can ever be removed. No frame emitter exists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Any, Callable, Mapping, MutableMapping

# --------------------------------------------------------------------------
# Fixed identities. These bind the probe to the exact frozen P production
# closure; any production byte change makes the probe refuse before Docker.
# --------------------------------------------------------------------------
REPOSITORY = "Knowledge-Forge-AI/theme-forge-packages"
REPOSITORY_OWNER = "Knowledge-Forge-AI"
PROBE_WORKFLOW_PATH = ".github/workflows/probe-current-signer-isolation.yml"
EXPECTED_PROBE_WORKFLOW_REF = f"{REPOSITORY}/{PROBE_WORKFLOW_PATH}@refs/heads/main"
PROBE_REL_PATH = "tools/verification/isolation_probe/current_signer_isolation_probe.py"
CURRENT_SIGNER_REL_DIR = "tools/verification/current_signer"
LEAF_MANIFEST_REL_PATH = "tools/verification/current_signer/leaf-manifest.json"
PINNED_LEAF_MANIFEST_SHA256 = "3519f2adf02b3a156a4feae5f146281655effa084fa6a3e5637cf9bf707ff01d"
PRODUCTION_PINS = {
    "tools/verification/current_signer/leaf-manifest.json": PINNED_LEAF_MANIFEST_SHA256,
    "tools/verification/current_import_routing.py": "43b0b20f5836e4564580586d4408b4508dd749d5e32fcefc1df39af46b2d447a",
    ".github/workflows/qualify-current-signer.yml": "b46ff92fe99a340cd2c4108ab9312a015969ec02575b1ffaa6996e4b132475c0",
    "tools/verification/current-rs9-inputs.json": "972fc30c36a5c351bb38cf792c2b4f6d0732f8d0355d4fb0d81b80fce744a665",
}
OBSERVER_LEAVES = ("signing_network_gate", "signing_linux_isolation")
# Only key-free leaves. No signing, frame, agent, passphrase or worker leaf.
HOST_LEAVES = (
    "source_closure", "signing_network_gate", "signing_linux_isolation", "signer_protocol_io",
    "signer_host_controller", "runtime_workflow_bridge", "signing_image_build",
    "publication_github_api", "runtime_input_intake",
)
FORBIDDEN_LEAVES = frozenset({
    "secret_frame_transport", "protected_signing_runtime", "owned_gpg_agent",
    "protected_passphrase_fd", "current_protected_signing", "signer_worker",
    "retained_publication", "detached_signature_adapter", "apt_signature_adapter",
    "rpm_public_signature_adapter", "signing_status_proof", "package_client_qualification",
})
CONTAINER_P_ROOT = "/work/p"
DOCKER = "/usr/bin/docker"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 4096
DOCKER_COMMAND_SECONDS = 30.0
SESSION_SECONDS = 600.0
LINE_SCHEMA = "tf.current-signer-isolation-probe-line.v1"
RESULT_SCHEMA = "tf.current-signer-isolation-probe-result.v2"
# Exactly two closed choices. custom-bridge stays the direct-CLI default for
# compatibility; the hosted workflow selects default-bridge explicitly.
NETWORK_PROFILES = ("custom-bridge", "default-bridge")
DEFAULT_NETWORK_PROFILE = "custom-bridge"
DEFAULT_BRIDGE_NETWORK = "bridge"
OWNER_LABEL_KEY = "tf.current-signer.run"  # Checked against the loaded core leaf before any use.
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[1-9][0-9]{0,19}")

# --------------------------------------------------------------------------
# Closed vocabularies
# --------------------------------------------------------------------------
TABLES = ("route", "ipv6_route", "tcp", "tcp6", "udp", "udp6")
MAX_PROC_BYTES = 1024 * 1024
TCP_CLOSING_STATES = frozenset({"04", "05", "07", "08", "09", "0B"})
TCP_ACTIVE_STATES = frozenset({"01", "02", "03", "0C"})
BUCKETS = ("0", "1", "2", "3", "4_TO_9", "10_OR_MORE")
TABLE_STATUS = frozenset({"OK", "UNAVAILABLE", "OVER_BOUND", "NON_ASCII", "HEADER_MISMATCH"})
PROTOS = frozenset({"TCP", "UDP"})
FAMILIES = frozenset({"V4", "V6"})
STATES = frozenset({"LISTEN", "TIME_WAIT", "ACTIVE", "CLOSING", "TCP_OTHER",
                    "UDP_UNCONNECTED", "UDP_CONNECTED", "UDP_OTHER"})
LOCAL_ADDRESSES = frozenset({
    "V4_DOCKER_DNS_127_0_0_11", "V4_LOOPBACK_OTHER", "V4_WILDCARD", "V4_NONLOOPBACK",
    "V6_LOOPBACK", "V6_WILDCARD", "V6_V4MAPPED_DOCKER_DNS", "V6_V4MAPPED_LOOPBACK_OTHER",
    "V6_V4MAPPED_OTHER", "V6_NONLOOPBACK", "UNPARSEABLE",
})
PORTS = frozenset({"PORT_ZERO", "PORT_53", "PORT_OTHER", "PORT_UNPARSEABLE"})
REMOTES = frozenset({"REMOTE_NONE", "REMOTE_LOOPBACK", "REMOTE_NONLOOPBACK", "REMOTE_UNPARSEABLE"})
UIDS = frozenset({"UID_ZERO", "UID_SELF", "UID_OTHER", "UID_UNPARSEABLE"})
MAX_SOCKET_CATEGORIES = 16  # Worst-case line stays below MAX_LINE_BYTES (tested).
PREDICATE_RESULTS = frozenset({"REFUSED", "WOULD_PASS"})
PREDICATE_CODES = frozenset({
    "NONE", "ISOLATION_INTERFACE_OR_TABLES", "ISOLATION_METADATA_BOUND", "ISOLATION_METADATA_FORMAT",
    "ISOLATION_METADATA_UNAVAILABLE", "ISOLATION_ROUTE_FORMAT", "ISOLATION_EXTERNAL_ROUTE",
    "ISOLATION_SOCKET_FORMAT", "ISOLATION_SOCKET_PRESENT", "UNLISTED_CODE", "PREDICATE_INTERNAL",
})
PREDICATE_DETAILS = frozenset({
    "NONE", "UNLISTED_DETAIL", "LO_INTERFACE_MISSING", "NON_LO_INTERFACE_PRESENT", "PROC_TABLE_SET_MISMATCH",
    "IPV4_NON_LO_ROUTE", "IPV6_NON_LO_ROUTE", "SOCKET_ROW_MALFORMED", "UDP_V4_SOCKET", "UDP_V6_SOCKET",
    "TCP_V4_LISTEN", "TCP_V6_LISTEN", "TCP_V4_CLOSING_STATE", "TCP_V6_CLOSING_STATE",
    "TCP_V4_ACTIVE_STATE", "TCP_V6_ACTIVE_STATE", "TCP_OTHER_STATE",
})
OBSERVER_REFUSALS = frozenset({
    "OBSERVER_FLAGS", "OBSERVER_PLATFORM", "OBSERVER_ENVIRONMENT", "OBSERVER_ARGUMENTS",
    "PRODUCTION_LEAF_MANIFEST", "PRODUCTION_LEAF_DIGEST", "PRODUCTION_LEAF_PREIMPORTED",
    "PRODUCTION_PREDICATE_SHAPE", "CHALLENGE_INVALID", "LINE_BOUND", "OBSERVER_INTERNAL",
})
HOST_REFUSALS = frozenset({
    "NONE", "HOST_FLAGS", "HOST_PLATFORM", "CALLER_CONTEXT", "CREDENTIAL_ENVIRONMENT", "HOST_ARGUMENTS",
    "SOURCE_AUTHENTICATION", "PRODUCTION_PINS_CHANGED", "PRODUCTION_LEAF_MANIFEST", "PRODUCTION_LEAF_DIGEST",
    "PRODUCTION_LEAF_PREIMPORTED", "IMAGE_PREPARE_FAILED", "WORK_ROOT_CLEANUP_FAILED",
    "NETWORK_CREATE_FAILED", "CONTAINER_ARGV_REFUSED", "CONTAINER_SPAWN_FAILED", "READY_INVALID",
    "DISCONNECT_FAILED", "INSPECT_FAILED", "DETACH_NOT_CONFIRMED", "RESULT_INVALID", "OBSERVER_NONZERO_EXIT",
    "OBSERVER_STDOUT_UNCLEAN", "OBSERVER_STDOUT_OVERFLOW", "OBSERVER_STDIN_FAILED", "SESSION_TIMEOUT",
    "TEARDOWN_UNCONFIRMED", "IMAGE_DISPOSAL_UNCONFIRMED", "INTERNAL",
    # default-bridge lifecycle refusals; the closed core category is in bridge_gate_code.
    "BRIDGE_PREFLIGHT_REFUSED", "OWNERSHIP_NOT_PROVEN", "COMMAND_NOT_ALLOWED",
})
CUSTOM_BRIDGE_STEPS = ("network_create", "container_start", "ready", "disconnect", "challenge", "result",
                       "observer_exit")
DEFAULT_BRIDGE_STEPS = ("preflight", "container_start", "ready", "ownership", "disconnect", "challenge", "result",
                        "observer_exit")
# Closed copy of the core DEFAULT_BRIDGE_ERROR_CODES (equality against the loaded leaf is tested).
DEFAULT_BRIDGE_GATE_CODES = frozenset({
    "BRIDGE_IDENTITY_BOUND", "BRIDGE_IDENTITY_FORMAT", "BRIDGE_IDENTITY_DUPLICATE", "BRIDGE_IDENTITY_MISMATCH",
    "BRIDGE_IDENTITY_CHANGED", "BRIDGE_PEER_PRESENT", "BRIDGE_OWNERSHIP_MISMATCH", "WORKER_NETWORK_FORMAT",
    "WORKER_NETWORK_MISMATCH", "CONTAINER_ID_FORMAT", "CONTAINER_LISTING_FORMAT", "CONTAINER_NAME_COLLISION",
    "OWNER_LABEL_INPUT", "OWNER_LOOKUP_EMPTY", "OWNER_LOOKUP_AMBIGUOUS", "RESOURCE_ID",
})
BRIDGE_GATE_VALUES = frozenset({"NONE", "DOCKER_COMMAND_FAILED", "CUSTODY_CHANGED", "UNLISTED"}) | DEFAULT_BRIDGE_GATE_CODES
OWNER_CUSTODY_VALUES = frozenset({"NOT_RUN", "resolved", "absent", "ambiguous", "mismatch", "malformed", "unavailable"})
DEFAULT_TEARDOWN_BOOLS = (
    "teardown_run", "removal_by_immutable_id_only", "container_force_remove_attempted", "container_force_removed",
    "owned_container_absence_confirmed", "container_name_absent_confirmed", "container_absence_confirmed",
    "network_removed", "builtin_bridge_preserved", "builtin_bridge_configuration_commands_issued",
    "owned_worker_endpoint_mutation_attempted", "owned_bridge_endpoint_absent_confirmed",
    "unexpected_bridge_peer_observed",
    "spawn_outcome_uncertain", "session_cleanup_uncertain", "teardown_interrupted",
    "frame_capture_custody_retained", "teardown_is_not_c6_cleanup",
)
_CORE_TEARDOWN_BOOLS = tuple(key for key in DEFAULT_TEARDOWN_BOOLS if key != "teardown_run")
IMAGE_STAGES = frozenset({"NOT_REACHED", "LEAF_IDENTITY", "CLASS_NOT_ADMITTED", "ADMISSION",
                          "WORK_ROOT", "INTAKE", "QUARANTINE", "SOURCE_RECHECK", "BUILD", "BINDING", "READY"})
STEP_VALUES = frozenset({"NOT_REACHED", "OK", "FAILED"})
READBACK_VALUES = frozenset({"NOT_REACHED", "EMPTY_OBJECT", "NETWORK_ATTACHED", "NETWORK_READBACK_FORMAT",
                             "NETWORK_READBACK_BOUND", "COMMAND_FAILED"})
FRAMING_VALUES = frozenset({"NONE", "EMPTY_EOF", "NON_BYTES", "LINE_OVERFLOW", "CR_PRESENT",
                            "TRUNCATED_NO_NEWLINE", "MULTIPLE_NEWLINES"})
OBSERVER_STDERR_VALUES = frozenset({"NOT_READ", "STDERR_EMPTY", "UNRECOGNIZED"}) | OBSERVER_REFUSALS
_SECRET_NAME_TOKENS = ("SECRET", "PASSWORD", "PASSPHRASE", "PRIVATE_KEY", "SIGNING", "CREDENTIAL", "GPG", "TOKEN")


class ProbeRefusal(RuntimeError):
    """Fixed-code refusal. Never carries raw bytes, paths, argv or remote output."""

    def __init__(self, code: str, message: str = "", *, stage: str | None = None,
                 custody_retained: bool = False) -> None:
        self.code = code
        self.stage = stage
        self.custody_retained = custody_retained
        super().__init__(code)


# --------------------------------------------------------------------------
# Authenticated production leaf loading (same discipline as the root bootstrap)
# --------------------------------------------------------------------------
def _held_bytes(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes:
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ProbeRefusal("PRODUCTION_LEAF_DIGEST")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise ProbeRefusal("PRODUCTION_LEAF_DIGEST") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ProbeRefusal("PRODUCTION_LEAF_DIGEST")
        chunks, left = [], limit + 1
        while left:
            block = os.read(fd, min(left, 65536))
            if not block:
                break
            chunks.append(block)
            left -= len(block)
        body = b"".join(chunks)
        after = os.fstat(fd)
        if len(body) != before.st_size or (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns):
            raise ProbeRefusal("PRODUCTION_LEAF_DIGEST")
        return body
    finally:
        os.close(fd)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(raw: bytes, code: str) -> Any:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ProbeRefusal(code)
            out[key] = value
        return out
    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=pairs)
    except ProbeRefusal:
        raise
    except (UnicodeError, ValueError):
        raise ProbeRefusal(code) from None


def load_production_leaves(p_root: Path, names: tuple[str, ...]) -> dict[str, Any]:
    """Import exact manifest-authenticated production bytes; never the filesystem path."""
    import importlib
    import importlib.abc
    import importlib.util

    if set(names) & FORBIDDEN_LEAVES:
        raise ProbeRefusal("PRODUCTION_LEAF_DIGEST")
    manifest_raw = _held_bytes(p_root / LEAF_MANIFEST_REL_PATH, 65536)
    if _sha256(manifest_raw) != PINNED_LEAF_MANIFEST_SHA256:
        raise ProbeRefusal("PRODUCTION_LEAF_MANIFEST")
    files = _strict_json(manifest_raw, "PRODUCTION_LEAF_MANIFEST").get("files")
    if type(files) is not dict:
        raise ProbeRefusal("PRODUCTION_LEAF_MANIFEST")
    held: dict[str, tuple[Path, bytes]] = {}
    for name in names:
        rel = f"{CURRENT_SIGNER_REL_DIR}/{name}.py"
        path = p_root / rel
        body = _held_bytes(path)
        if type(files.get(rel)) is not str or _sha256(body) != files[rel]:
            raise ProbeRefusal("PRODUCTION_LEAF_DIGEST")
        held[name] = (path, body)
    if any(name in sys.modules for name in held):
        raise ProbeRefusal("PRODUCTION_LEAF_PREIMPORTED")

    class HeldLoader(importlib.abc.Loader):
        def __init__(self, name: str) -> None:
            self.name = name

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            path, body = held[self.name]
            module.__file__ = str(path)
            exec(compile(body, str(path), "exec", dont_inherit=True), module.__dict__)

    class HeldFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in held:
                return importlib.util.spec_from_loader(fullname, HeldLoader(fullname), origin=str(held[fullname][0]))
            if fullname in FORBIDDEN_LEAVES:
                raise ImportError("forbidden signing leaf")
            return None

    sys.meta_path.insert(0, HeldFinder())
    return {name: importlib.import_module(name) for name in names}


# --------------------------------------------------------------------------
# Pure classification. Inputs are raw in-memory facts; outputs are closed.
# --------------------------------------------------------------------------
def bucket(count: int) -> str:
    if count < 4:
        return BUCKETS[count]
    return "4_TO_9" if count < 10 else "10_OR_MORE"


def _decode_address(hex_text: str, little_endian: bool) -> bytes | None:
    if not re.fullmatch(r"[0-9A-F]{8}|[0-9A-F]{32}", hex_text):
        return None
    raw = bytes.fromhex(hex_text)
    if not little_endian:
        return None  # Word order on other hosts is not established; report unknown.
    return b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))


def _split_endpoint(text: str) -> tuple[str, str] | None:
    if text.count(":") != 1:
        return None
    address, port = text.split(":")
    if not re.fullmatch(r"[0-9A-F]{4}", port):
        return None
    return address, port


def classify_local_address(text: str, family: str, little_endian: bool = True) -> str:
    endpoint = _split_endpoint(text)
    addr = None if endpoint is None else _decode_address(endpoint[0], little_endian)
    if addr is None or len(addr) != (4 if family == "V4" else 16):
        return "UNPARSEABLE"
    if family == "V4":
        if addr == bytes((127, 0, 0, 11)):
            return "V4_DOCKER_DNS_127_0_0_11"
        if addr[0] == 127:
            return "V4_LOOPBACK_OTHER"
        return "V4_WILDCARD" if addr == bytes(4) else "V4_NONLOOPBACK"
    if addr == bytes(15) + b"\x01":
        return "V6_LOOPBACK"
    if addr == bytes(16):
        return "V6_WILDCARD"
    if addr[:12] == bytes(10) + b"\xff\xff":
        if addr[12:] == bytes((127, 0, 0, 11)):
            return "V6_V4MAPPED_DOCKER_DNS"
        return "V6_V4MAPPED_LOOPBACK_OTHER" if addr[12] == 127 else "V6_V4MAPPED_OTHER"
    return "V6_NONLOOPBACK"


def classify_port(text: str) -> str:
    endpoint = _split_endpoint(text)
    if endpoint is None:
        return "PORT_UNPARSEABLE"
    port = int(endpoint[1], 16)
    return "PORT_ZERO" if port == 0 else ("PORT_53" if port == 53 else "PORT_OTHER")


def classify_remote(text: str, family: str, little_endian: bool = True) -> str:
    endpoint = _split_endpoint(text)
    addr = None if endpoint is None else _decode_address(endpoint[0], little_endian)
    if addr is None or len(addr) != (4 if family == "V4" else 16):
        return "REMOTE_UNPARSEABLE"
    if addr == bytes(len(addr)) and int(endpoint[1], 16) == 0:
        return "REMOTE_NONE"
    v4 = addr if family == "V4" else (addr[12:] if addr[:12] == bytes(10) + b"\xff\xff" else None)
    if (v4 is not None and v4[0] == 127) or addr == bytes(15) + b"\x01":
        return "REMOTE_LOOPBACK"
    return "REMOTE_NONLOOPBACK"


def classify_uid(text: str, self_uid: int) -> str:
    if not re.fullmatch(r"[0-9]{1,10}", text):
        return "UID_UNPARSEABLE"
    value = int(text)
    if value == 0:
        return "UID_ZERO"
    return "UID_SELF" if value == self_uid else "UID_OTHER"


def classify_state(table: str, state: str) -> str:
    if table.startswith("udp"):
        return {"07": "UDP_UNCONNECTED", "01": "UDP_CONNECTED"}.get(state, "UDP_OTHER")
    if state == "06":
        return "TIME_WAIT"
    if state == "0A":
        return "LISTEN"
    if state in TCP_ACTIVE_STATES:
        return "ACTIVE"
    return "CLOSING" if state in TCP_CLOSING_STATES else "TCP_OTHER"


def _table_lines(body: bytes | None) -> tuple[str, list[str] | None]:
    if body is None:
        return "UNAVAILABLE", None
    if len(body) > MAX_PROC_BYTES:
        return "OVER_BOUND", None
    try:
        return "OK", body.decode("ascii").splitlines()
    except UnicodeError:
        return "NON_ASCII", None


def classify_facts(interfaces: tuple[str, ...] | None, tables: Mapping[str, bytes],
                   *, self_uid: int, little_endian: bool = True) -> dict[str, Any]:
    """Reduce raw namespace metadata to closed categories. Nothing raw survives."""
    if interfaces is None:
        iface = {"read": "UNAVAILABLE", "lo_present": False, "non_lo": "0"}
    else:
        iface = {"read": "OK", "lo_present": "lo" in interfaces,
                 "non_lo": bucket(sum(1 for name in interfaces if name != "lo"))}
    status: dict[str, str] = {}
    lines: dict[str, list[str]] = {}
    for name in TABLES:
        state, rows = _table_lines(tables.get(name))
        if rows is not None and name != "ipv6_route":
            header = rows[0].split() if rows else []
            expected = ["Iface"] if name == "route" else ["sl", "local_address"]
            if header[:len(expected)] != expected:
                state, rows = "HEADER_MISMATCH", None
        status[name] = state
        if rows is not None:
            lines[name] = rows[1:] if name != "ipv6_route" else rows
    routes = {}
    for name, label, width in (("route", "v4", 11), ("ipv6_route", "v6", 10)):
        lo = non_lo = malformed = 0
        for row in lines.get(name, ()):
            fields = row.split()
            if len(fields) != width:
                malformed += 1
            elif (fields[0] if name == "route" else fields[-1]) == "lo":
                lo += 1
            else:
                non_lo += 1
        routes.update({f"{label}_lo": bucket(lo), f"{label}_non_lo": bucket(non_lo), f"{label}_malformed": bucket(malformed)})
    counts: dict[tuple[str, ...], int] = {}
    malformed = total = 0
    for name in ("tcp", "tcp6", "udp", "udp6"):
        family = "V6" if name.endswith("6") else "V4"
        for row in lines.get(name, ()):
            fields = row.split()
            total += 1
            if len(fields) < 10:
                malformed += 1
                continue
            key = (
                "UDP" if name.startswith("udp") else "TCP", family, classify_state(name, fields[3]),
                classify_local_address(fields[1], family, little_endian), classify_port(fields[1]),
                classify_remote(fields[2], family, little_endian), classify_uid(fields[7], self_uid),
            )
            counts[key] = counts.get(key, 0) + 1
    ordered = sorted(counts.items())
    rows = [{"proto": k[0], "family": k[1], "state": k[2], "local": k[3], "port": k[4],
             "remote": k[5], "uid": k[6], "count": bucket(v)} for k, v in ordered[:MAX_SOCKET_CATEGORIES]]
    return {
        "interfaces": iface, "tables": status, "routes": routes,
        "sockets": {"rows": rows, "category_overflow": len(ordered) > MAX_SOCKET_CATEGORIES,
                    "malformed_rows": bucket(malformed), "total_rows": bucket(total)},
        "observer_uid_zero": self_uid == 0,
    }


def production_verdict(iso: Any, interfaces: tuple[str, ...] | None, tables: Mapping[str, bytes]) -> dict[str, str]:
    """Exactly the production predicate on the same in-memory bytes; never acted upon."""
    if interfaces is None or set(tables) != set(TABLES):
        # prove_linux_isolation raises this fixed code when any fixed read fails.
        return {"result": "REFUSED", "code": "ISOLATION_METADATA_UNAVAILABLE", "detail": "NONE"}
    try:
        iso.require_isolated_facts(tuple(interfaces), dict(tables))
    except iso.GateError as error:
        code = error.code if error.code in PREDICATE_CODES else "UNLISTED_CODE"
        detail = "NONE" if error.detail is None else (
            error.detail if error.detail in PREDICATE_DETAILS else "UNLISTED_DETAIL")
        return {"result": "REFUSED", "code": code, "detail": detail}
    except Exception:
        return {"result": "REFUSED", "code": "PREDICATE_INTERNAL", "detail": "NONE"}
    return {"result": "WOULD_PASS", "code": "NONE", "detail": "NONE"}


def require_predicate_shape(iso: Any) -> None:
    """The probe's fixed read must equal what prove_linux_isolation reads."""
    if (getattr(iso, "_TABLES", None) != TABLES or getattr(iso, "MAX_PROC_BYTES", None) != MAX_PROC_BYTES
            or getattr(iso, "_TCP_CLOSING_STATES", None) != TCP_CLOSING_STATES
            or getattr(iso, "_TCP_ACTIVE_STATES", None) != TCP_ACTIVE_STATES
            or not callable(getattr(iso, "require_isolated_facts", None))):
        raise ProbeRefusal("PRODUCTION_PREDICATE_SHAPE")


def read_fixed_facts() -> tuple[tuple[str, ...] | None, dict[str, bytes]]:
    """Same fixed paths and bound as prove_linux_isolation; memory only."""
    try:
        interfaces: tuple[str, ...] | None = tuple(sorted(p.name for p in Path("/sys/class/net").iterdir()))
    except OSError:
        interfaces = None
    tables: dict[str, bytes] = {}
    for name in TABLES:
        try:
            with (Path("/proc/net") / name).open("rb") as source:
                tables[name] = source.read(MAX_PROC_BYTES + 1)
        except OSError:
            continue
    return interfaces, tables


def take_snapshot(iso: Any, reader: Callable[[], tuple[tuple[str, ...] | None, dict[str, bytes]]],
                  *, self_uid: int, little_endian: bool) -> dict[str, Any]:
    interfaces, tables = reader()
    try:
        snapshot = classify_facts(interfaces, tables, self_uid=self_uid, little_endian=little_endian)
        snapshot["production_predicate"] = production_verdict(iso, interfaces, tables)
    finally:
        tables.clear()
        del interfaces
    return validate_snapshot(snapshot)


# --------------------------------------------------------------------------
# Closed-schema validation (host re-validates everything the container sends)
# --------------------------------------------------------------------------
def _exact(obj: Any, keys: set[str], code: str) -> dict:
    if type(obj) is not dict or set(obj) != keys:
        raise ProbeRefusal(code)
    return obj


def _enum(value: Any, allowed: frozenset[str] | tuple[str, ...], code: str) -> str:
    if type(value) is not str or value not in allowed:
        raise ProbeRefusal(code)
    return value


def _bool(value: Any, code: str) -> bool:
    if type(value) is not bool:
        raise ProbeRefusal(code)
    return value


def validate_snapshot(obj: Any, code: str = "RESULT_INVALID") -> dict[str, Any]:
    """Return a freshly built copy containing only closed values."""
    obj = _exact(obj, {"interfaces", "tables", "routes", "sockets", "observer_uid_zero", "production_predicate"}, code)
    iface = _exact(obj["interfaces"], {"read", "lo_present", "non_lo"}, code)
    tables = _exact(obj["tables"], set(TABLES), code)
    route_keys = {f"{f}_{k}" for f in ("v4", "v6") for k in ("lo", "non_lo", "malformed")}
    routes = _exact(obj["routes"], route_keys, code)
    sockets = _exact(obj["sockets"], {"rows", "category_overflow", "malformed_rows", "total_rows"}, code)
    pred = _exact(obj["production_predicate"], {"result", "code", "detail"}, code)
    if type(sockets["rows"]) is not list or len(sockets["rows"]) > MAX_SOCKET_CATEGORIES:
        raise ProbeRefusal(code)
    rows = []
    for row in sockets["rows"]:
        row = _exact(row, {"proto", "family", "state", "local", "port", "remote", "uid", "count"}, code)
        rows.append({"proto": _enum(row["proto"], PROTOS, code), "family": _enum(row["family"], FAMILIES, code),
                     "state": _enum(row["state"], STATES, code), "local": _enum(row["local"], LOCAL_ADDRESSES, code),
                     "port": _enum(row["port"], PORTS, code), "remote": _enum(row["remote"], REMOTES, code),
                     "uid": _enum(row["uid"], UIDS, code), "count": _enum(row["count"], BUCKETS, code)})
    return {
        "interfaces": {"read": _enum(iface["read"], frozenset({"OK", "UNAVAILABLE"}), code),
                       "lo_present": _bool(iface["lo_present"], code), "non_lo": _enum(iface["non_lo"], BUCKETS, code)},
        "tables": {name: _enum(tables[name], TABLE_STATUS, code) for name in TABLES},
        "routes": {key: _enum(routes[key], BUCKETS, code) for key in sorted(route_keys)},
        "sockets": {"rows": rows, "category_overflow": _bool(sockets["category_overflow"], code),
                    "malformed_rows": _enum(sockets["malformed_rows"], BUCKETS, code),
                    "total_rows": _enum(sockets["total_rows"], BUCKETS, code)},
        "observer_uid_zero": _bool(obj["observer_uid_zero"], code),
        "production_predicate": {"result": _enum(pred["result"], PREDICATE_RESULTS, code),
                                 "code": _enum(pred["code"], PREDICATE_CODES, code),
                                 "detail": _enum(pred["detail"], PREDICATE_DETAILS, code)},
    }


# --------------------------------------------------------------------------
# Probe-only line protocol (never the production tf.signer-network-gate schema)
# --------------------------------------------------------------------------
def encode_line(kind: str, nonce: str, snapshot: dict | None = None) -> bytes:
    if kind not in {"ready", "challenge", "result"} or type(nonce) is not str or not _HEX64.fullmatch(nonce):
        raise ProbeRefusal("LINE_BOUND")
    doc: dict[str, Any] = {"schema": LINE_SCHEMA, "kind": kind, "nonce": nonce}
    if kind != "challenge":
        doc["snapshot"] = validate_snapshot(snapshot, "LINE_BOUND")
    line = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise ProbeRefusal("LINE_BOUND")
    return line


def parse_line(line: Any, kind: str, nonce: str, code: str) -> dict[str, Any] | None:
    if type(line) is not bytes or not 0 < len(line) <= MAX_LINE_BYTES or not line.endswith(b"\n") \
            or line.count(b"\n") != 1 or b"\r" in line:
        raise ProbeRefusal(code)
    keys = {"schema", "kind", "nonce"} | ({"snapshot"} if kind != "challenge" else set())
    doc = _exact(_strict_json(line, code), keys, code)
    if doc["schema"] != LINE_SCHEMA or doc["kind"] != kind or doc["nonce"] != nonce:
        raise ProbeRefusal(code)
    return validate_snapshot(doc["snapshot"], code) if kind != "challenge" else None


# --------------------------------------------------------------------------
# Observer role
# --------------------------------------------------------------------------
def require_clean_observer_env(environ: Mapping[str, str]) -> None:
    for key, value in environ.items():
        if value and any(token in key.upper() for token in _SECRET_NAME_TOKENS):
            raise ProbeRefusal("OBSERVER_ENVIRONMENT")


def run_observer(nonce: str, iso: Any, *, reader: Callable, read_line: Callable[[], bytes],
                 write: Callable[[bytes], None], self_uid: int, little_endian: bool) -> None:
    require_predicate_shape(iso)
    attached = take_snapshot(iso, reader, self_uid=self_uid, little_endian=little_endian)
    write(encode_line("ready", nonce, attached))
    try:
        parse_line(read_line(), "challenge", nonce, "CHALLENGE_INVALID")
    except ProbeRefusal:
        raise ProbeRefusal("CHALLENGE_INVALID") from None
    detached = take_snapshot(iso, reader, self_uid=self_uid, little_endian=little_endian)
    write(encode_line("result", nonce, detached))


def _fd_read_line(fd: int = 0) -> bytes:
    buf = bytearray()
    while len(buf) <= MAX_LINE_BYTES:
        chunk = os.read(fd, 1)
        if not chunk:
            break
        buf.extend(chunk)
        if chunk == b"\n":
            break
    return bytes(buf)


def _fd_write(data: bytes, fd: int = 1) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise ProbeRefusal("OBSERVER_INTERNAL")
        view = view[written:]


def observer_main(argv: list[str]) -> int:
    try:
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            raise ProbeRefusal("OBSERVER_FLAGS")
        if sys.platform != "linux":
            raise ProbeRefusal("OBSERVER_PLATFORM")
        if len(argv) != 2 or argv[0] != "--nonce" or not _HEX64.fullmatch(argv[1]):
            raise ProbeRefusal("OBSERVER_ARGUMENTS")
        require_clean_observer_env(os.environ)
        iso = load_production_leaves(Path(CONTAINER_P_ROOT), OBSERVER_LEAVES)["signing_linux_isolation"]
        run_observer(argv[1], iso, reader=read_fixed_facts, read_line=_fd_read_line, write=_fd_write,
                     self_uid=os.getuid(), little_endian=sys.byteorder == "little")
    except ProbeRefusal as error:
        code = error.code if error.code in OBSERVER_REFUSALS else "OBSERVER_INTERNAL"
        os.write(2, code.encode("ascii") + b"\n")
        return 2
    except Exception:
        os.write(2, b"OBSERVER_INTERNAL\n")
        return 2
    return 0


# --------------------------------------------------------------------------
# Host role
# --------------------------------------------------------------------------
def authenticate_probe_context(environ: Mapping[str, str]) -> tuple[str, int]:
    """Same checks as runtime_workflow_bridge.authenticate_workflow_context, bound to the probe ref."""
    run_raw, sha_raw = environ.get("GITHUB_RUN_ID", ""), environ.get("GITHUB_SHA", "")
    if (environ.get("GITHUB_HEAD_REF") or environ.get("GITHUB_BASE_REF")
            or environ.get("GITHUB_ACTIONS") != "true" or environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or environ.get("GITHUB_REPOSITORY_OWNER") != REPOSITORY_OWNER
            or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or environ.get("GITHUB_REF") != "refs/heads/main" or environ.get("GITHUB_REF_NAME") != "main"
            or environ.get("GITHUB_REF_TYPE") != "branch" or environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or type(run_raw) is not str or not _RUN_ID.fullmatch(run_raw)
            or type(sha_raw) is not str or not _HEX40.fullmatch(sha_raw) or sha_raw == "0" * 40
            or environ.get("GITHUB_WORKFLOW_REF") != EXPECTED_PROBE_WORKFLOW_REF):
        raise ProbeRefusal("CALLER_CONTEXT")
    return sha_raw, int(run_raw)


def verify_production_pins(p_dir: Path) -> None:
    for rel, expected in PRODUCTION_PINS.items():
        try:
            body = _held_bytes(p_dir / rel)
        except ProbeRefusal:
            raise ProbeRefusal("PRODUCTION_PINS_CHANGED") from None
        if _sha256(body) != expected:
            raise ProbeRefusal("PRODUCTION_PINS_CHANGED")


def build_observer_argv(*, image_id: str, container_python: str, network: str, container: str,
                        p_dir: Path, uid: int, gid: int, nonce: str, hc: Any,
                        owner_label: str | None = None) -> tuple[str, ...]:
    """Production docker-run hardening, minus every env/token/secret and the R/export mounts.

    ``owner_label`` is supplied only by the default-bridge profile: it inserts the
    single fixed run/nonce-bound owner label directly after the network pair.
    """
    label = () if owner_label is None else ("--label", f"{OWNER_LABEL_KEY}={owner_label}")
    argv = (
        DOCKER, "run", "--rm", "-i", "--pull", "never", "--name", container, "--network", network, *label,
        "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--mount", f"type=bind,src={p_dir},dst={CONTAINER_P_ROOT},readonly",
        "--tmpfs", f"/work/workspace:rw,exec,nosuid,nodev,mode=0700,uid={uid},gid={gid}",
        image_id, container_python, "-I", "-B", f"{CONTAINER_P_ROOT}/{PROBE_REL_PATH}", "--observe", "--nonce", nonce,
    )
    validate_observer_argv(argv, hc, container=container, owner_label=owner_label)
    return argv


def _require_profile_argv(argv: tuple[str, ...], image_index: int, container: str | None,
                          owner_label: str | None) -> None:
    """Exact network/label shape per profile, after the generic hardening checks.

    custom-bridge (no owner label): no label at all and never the built-in bridge.
    default-bridge: exactly ``--network bridge``, exactly one ``--label`` pair with
    the fixed key and this run's label right after it, and exactly the expected name.
    """
    options = argv[:image_index]
    networks = [i for i, t in enumerate(options) if t == "--network"]
    labels = [i for i, t in enumerate(options) if t.startswith(("--label", "-l"))]
    if len(networks) != 1:
        raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
    network = argv[networks[0] + 1]
    if owner_label is None:
        if labels or network == DEFAULT_BRIDGE_NETWORK:
            raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
        return
    names = [i for i, t in enumerate(options) if t == "--name" or t.startswith("--name=")]
    if (type(owner_label) is not str or not _HEX64.fullmatch(owner_label) or network != DEFAULT_BRIDGE_NETWORK
            or labels != [networks[0] + 2] or options[labels[0]] != "--label"
            or argv[labels[0] + 1] != f"{OWNER_LABEL_KEY}={owner_label}"
            or len(names) != 1 or options[names[0]] != "--name" or argv[names[0] + 1] != container):
        raise ProbeRefusal("CONTAINER_ARGV_REFUSED")


def validate_observer_argv(argv: tuple[str, ...], hc: Any, *, container: str | None = None,
                           owner_label: str | None = None) -> None:
    forbidden_flags = set(hc._FORBIDDEN_DOCKER_FLAGS) | {
        "-e", "--env", "--env-file", "--cap-add", "--device", "--pid", "--ipc", "--userns", "--volume",
        "--privileged", "--dns", "--add-host", "--net",
    }
    if tuple(argv[:4]) != (DOCKER, "run", "--rm", "-i") or "--observe" not in argv:
        raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
    image_index = argv.index("--observe") - 5
    if not hc._IMAGE_DIGEST_RE.fullmatch(argv[image_index]) or argv[image_index + 1] != "/usr/bin/python3":
        raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
    for index, token in enumerate(argv):
        upper = token.upper() if type(token) is str else ""
        if (type(token) is not str or not token or "\x00" in token or token in forbidden_flags
                or token.startswith(("-v", "--env", "--cap-add", "--network=", "--net="))
                or any(bad in upper for bad in hc._FORBIDDEN_UPPER_SUBSTRINGS) or "TOKEN" in upper
                or "GPG" in upper or "SIGNING" in upper):
            raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
        if token == "--network" and argv[index + 1] in {"host", "none"}:
            raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
    if (argv[argv.index("--cap-drop") + 1] != "ALL" or argv[argv.index("--security-opt") + 1] != "no-new-privileges"
            or not re.fullmatch(r"[1-9][0-9]*:[0-9]+", argv[argv.index("--user") + 1])
            or argv.count("--mount") != 1 or not argv[argv.index("--mount") + 1].endswith(f",dst={CONTAINER_P_ROOT},readonly")):
        raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
    _require_profile_argv(argv, image_index, container, owner_label)


_SESSION_CODE_MAP = {
    "HOST_CONTROLLER_TIMEOUT": "SESSION_TIMEOUT", "PROTOCOL_STDOUT_OVERFLOW": "OBSERVER_STDOUT_OVERFLOW",
    "PROTOCOL_EXTRA_STDOUT": "OBSERVER_STDOUT_UNCLEAN", "PROTOCOL_STDIN_UNAVAILABLE": "OBSERVER_STDIN_FAILED",
    "PROTOCOL_STDIN_WRITE": "OBSERVER_STDIN_FAILED", "PROTOCOL_STDIN_CLOSE": "OBSERVER_STDIN_FAILED",
}


def _label(error: BaseException) -> str:
    code = getattr(error, "code", None)
    code = _SESSION_CODE_MAP.get(code, code)
    return code if type(code) is str and code in HOST_REFUSALS else "INTERNAL"


def parse_observer_stderr(raw: Any) -> str:
    if type(raw) not in (bytes, bytearray) or not raw:
        return "STDERR_EMPTY"
    text = bytes(raw)
    if len(text) > 128 or not text.endswith(b"\n") or text.count(b"\n") != 1:
        return "UNRECOGNIZED"
    try:
        code = text[:-1].decode("ascii")
    except UnicodeError:
        return "UNRECOGNIZED"
    return code if code in OBSERVER_REFUSALS else "UNRECOGNIZED"


def run_lifecycle(*, run_suffix: str, image_id: str, container_python: str, p_dir: Path, mods: Mapping[str, Any],
                  runner: Callable, spawner: Callable, session_factory: Callable, nonce: str,
                  uid: int, gid: int) -> dict[str, Any]:
    """One production-shaped network lifecycle. No retry, no poll, fail-closed teardown."""
    gate, hc = mods["signing_network_gate"], mods["signer_host_controller"]
    network, container = f"tf-current-signer-{run_suffix}-1", f"tf-current-signer-{run_suffix}-2"
    disconnect_cmd, inspect_cmd = gate.docker_gate_commands(network, container)
    create_cmd = (DOCKER, "network", "create", "--driver", "bridge", network)
    remove_cmd = (DOCKER, "network", "rm", network)
    steps = {"network_create": "NOT_REACHED", "container_start": "NOT_REACHED", "ready": "NOT_REACHED",
             "disconnect": "NOT_REACHED", "challenge": "NOT_REACHED", "result": "NOT_REACHED",
             "observer_exit": "NOT_REACHED"}
    out: dict[str, Any] = {"steps": steps, "detached_readback": "NOT_REACHED", "ready_framing": "NONE",
                           "observer_stderr": "NOT_READ", "attached_before_disconnect": None,
                           "after_disconnect": None, "refusal": "NONE"}
    session = None
    succeeded = False
    network_id = None
    teardown, interrupt = None, None
    try:
        argv = build_observer_argv(image_id=image_id, container_python=container_python, network=network,
                                   container=container, p_dir=p_dir, uid=uid, gid=gid, nonce=nonce, hc=hc)
        steps["network_create"] = "FAILED"
        rc, created, _ = runner(create_cmd, DOCKER_COMMAND_SECONDS)
        if rc != 0 or type(created) is not bytes or re.fullmatch(rb"[0-9a-f]{64}\n?", created) is None:
            # A failed/ambiguous create is not ownership authority. Never
            # remove a possibly foreign network or container by its name.
            raise ProbeRefusal("NETWORK_CREATE_FAILED")
        network_id = created.decode("ascii").strip()
        remove_cmd = (DOCKER, "network", "rm", network_id)
        steps["network_create"], steps["container_start"] = "OK", "FAILED"
        try:
            session = session_factory(spawner(argv, {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}),
                                      time.monotonic() + SESSION_SECONDS, ProbeRefusal)
        except Exception:
            raise ProbeRefusal("CONTAINER_SPAWN_FAILED") from None
        steps["container_start"] = "OK"
        steps["ready"] = "FAILED"
        ready = session.read_protocol_line()
        framing = gate.classify_message_framing(ready)
        out["ready_framing"] = framing if framing in FRAMING_VALUES else "NONE"
        out["attached_before_disconnect"] = parse_line(ready, "ready", nonce, "READY_INVALID")
        steps["ready"] = "OK"
        steps["disconnect"] = "FAILED"
        if runner(disconnect_cmd, DOCKER_COMMAND_SECONDS)[0] != 0:
            raise ProbeRefusal("DISCONNECT_FAILED")
        rc, readback, _ = runner(inspect_cmd, DOCKER_COMMAND_SECONDS)
        if rc != 0:
            out["detached_readback"] = "COMMAND_FAILED"
            raise ProbeRefusal("INSPECT_FAILED")
        try:
            gate.require_detached_networks(readback)
        except gate.GateError as error:
            out["detached_readback"] = error.code if error.code in READBACK_VALUES else "NETWORK_READBACK_FORMAT"
            raise ProbeRefusal("DETACH_NOT_CONFIRMED") from None
        out["detached_readback"], steps["disconnect"] = "EMPTY_OBJECT", "OK"
        steps["challenge"] = "FAILED"
        session.write_stdin(encode_line("challenge", nonce), close_after=True)
        steps["challenge"], steps["result"] = "OK", "FAILED"
        out["after_disconnect"] = parse_line(session.read_protocol_line(), "result", nonce, "RESULT_INVALID")
        steps["result"], steps["observer_exit"] = "OK", "FAILED"
        exit_code = session.wait_for_exit()
        session.require_stdout_clean_eof()
        if exit_code != 0:
            raise ProbeRefusal("OBSERVER_NONZERO_EXIT")
        steps["observer_exit"] = "OK"
        succeeded = True
    except Exception as error:
        out["refusal"] = _label(error)
        if session is not None and not succeeded:
            stderr = hc._drain_pre_frame_stderr(session, grace_seconds=1.0)
            out["observer_stderr"] = parse_observer_stderr(stderr)
    finally:
        if network_id is not None:
            def cleanup_runner(command, timeout):
                # Reuse process termination, read-only absence verification
                # and network cleanup, while restricting deletion to the
                # immutable network ID returned by our successful create.
                # The attached --rm container must disappear naturally;
                # uncertain or replaced names never authorize force removal.
                if command == (DOCKER, "rm", "-f", container):
                    return 1, b"", b""
                allowed = {
                    (DOCKER, "container", "ls", "--all", "--quiet", "--filter", f"name=^/{container}$"),
                    remove_cmd,
                }
                if command not in allowed:
                    return 1, b"", b""
                return runner(command, timeout)
            teardown, interrupt = hc._teardown_host_session(
                session, (network, container), remove_cmd, cleanup_runner, succeeded=succeeded)
            # The production helper attempted its callback; the restricted
            # callback did not execute a native forced removal.
            teardown["container_force_remove_attempted"] = False
            teardown["container_force_removed"] = False
    tear = {key: bool(teardown[key]) for key in (
        "container_force_remove_attempted", "container_force_removed", "container_absence_confirmed",
        "network_removed", "session_cleanup_uncertain", "teardown_interrupted")} if teardown else {
        "container_force_remove_attempted": False, "container_force_removed": False,
        "container_absence_confirmed": steps["network_create"] == "NOT_REACHED",
        "network_removed": steps["network_create"] == "NOT_REACHED",
        "session_cleanup_uncertain": False, "teardown_interrupted": False}
    uncertain = (tear["session_cleanup_uncertain"] or not tear["container_absence_confirmed"]
                 or not tear["network_removed"] or tear["teardown_interrupted"]
                 or (tear["container_force_remove_attempted"] and not tear["container_force_removed"]))
    out["teardown"], out["custody_retained"] = tear, uncertain
    if uncertain and out["refusal"] == "NONE":
        out["refusal"] = "TEARDOWN_UNCONFIRMED"
    if interrupt is not None:
        out["interrupt"] = interrupt
    return out


# --------------------------------------------------------------------------
# default-bridge profile: built-in bridge, ownership-bound, core helpers only
# --------------------------------------------------------------------------
def _bridge_gate_value(error: BaseException, gate: Any, hc: Any) -> str:
    """Closed category of a core default-bridge refusal; never its message or Docker output."""
    if isinstance(error, gate.GateError):
        return error.code if error.code in DEFAULT_BRIDGE_GATE_CODES else "UNLISTED"
    code = getattr(error, "code", None)
    if isinstance(error, hc.HostControllerError) and type(code) is str:
        if code == "DEFAULT_BRIDGE_CUSTODY":
            return "CUSTODY_CHANGED"
        if code.startswith("DOCKER_"):
            return "DOCKER_COMMAND_FAILED"
    return "UNLISTED"


class _DefaultBridgeCommandGuard:
    """Closed allow-list wrapped around the native runner for the default-bridge lifecycle.

    Permitted: built-in bridge inspect, the exact name and owner-label listings,
    readback of the pinned owned worker's networks, detaching only the pinned
    owned endpoint from the captured built-in bridge ID, and removing only the
    immutable ID that the immediately preceding owner-label listing resolved
    (and that equals the pinned ID once one exists). Everything else (network
    create/rm/connect/prune, removal by name or of foreign IDs, daemon or
    configuration commands) is refused without execution and recorded.
    """

    def __init__(self, runner: Callable, gate: Any, container: str, owner_label: str,
                 custody: Mapping[str, Any]) -> None:
        self._runner, self._gate, self._custody = runner, gate, custody
        self._fixed = frozenset({gate.default_bridge_inspect_command(), gate.container_name_listing_command(container)})
        self._owner_listing = gate.owned_container_listing_command(container, owner_label)
        self.bridge_id: str | None = None
        self._label_resolved: str | None = None
        self.refused = False

    def _allowed(self, command: tuple) -> bool:
        if command in self._fixed or command == self._owner_listing:
            return True
        target = command[-1] if command else None
        if type(target) is not str or not _HEX64.fullmatch(target):
            return False
        pinned = self._custody.get("owned_id")
        if command == self._gate.owned_container_remove_command(target):
            return target == self._label_resolved and pinned in (None, target)
        if pinned is None or target != pinned:
            return False
        if command == self._gate.worker_networks_command(target):
            return True
        return self.bridge_id is not None and command == self._gate.default_bridge_gate_commands(self.bridge_id, target)[0]

    def __call__(self, command: Any, timeout: float) -> tuple[int, bytes, bytes]:
        command = tuple(command)
        if not self._allowed(command):
            self.refused = True
            return 1, b"", b""
        if command == self._owner_listing:
            self._label_resolved = None
        result = self._runner(command, timeout)
        if command == self._owner_listing:
            try:
                ids = self._gate.parse_container_id_listing(result[1]) if result[0] == 0 else ()
            except self._gate.GateError:
                ids = ()
            self._label_resolved = ids[0] if len(ids) == 1 else None
        return result


def _default_teardown_not_run() -> dict[str, Any]:
    """Nothing was spawned: no container, endpoint or network was ever created by this run."""
    tear: dict[str, Any] = {key: False for key in DEFAULT_TEARDOWN_BOOLS}
    tear.update(owner_custody="NOT_RUN", removal_by_immutable_id_only=True, teardown_is_not_c6_cleanup=True)
    return tear


def _record_default_teardown(teardown: Any) -> tuple[dict[str, Any], bool]:
    """Reduce the core teardown to closed booleans/status; drop names, IDs and labels."""
    source = teardown if type(teardown) is dict else {}
    custody = source.get("owner_custody")
    valid_custody = type(custody) is str and custody in OWNER_CUSTODY_VALUES and custody != "NOT_RUN"
    malformed = (type(teardown) is not dict or not valid_custody
                 or any(type(source.get(key)) is not bool for key in _CORE_TEARDOWN_BOOLS))
    tear: dict[str, Any] = {key: source.get(key) is True for key in _CORE_TEARDOWN_BOOLS}
    tear.update(teardown_run=True, owner_custody=custody if valid_custody else "unavailable")
    return tear, malformed


def run_default_lifecycle(*, run_suffix: str, image_id: str, container_python: str, p_dir: Path,
                          mods: Mapping[str, Any], runner: Callable, spawner: Callable, session_factory: Callable,
                          nonce: str, uid: int, gid: int) -> dict[str, Any]:
    """One built-in default-bridge lifecycle through the authenticated controller helpers.

    Order: owner label -> hardened argv -> core preflight (bridge identity, no
    peers, name free) -> spawn -> ready + attached snapshot -> core
    prepare-disconnect (resolve/pin owned immutable ID, sole peer, worker on
    bridge) -> detach by resolved ID -> empty readback -> challenge -> after
    snapshot -> exit -> core ownership-bound teardown. No retry, no poll, no
    network create/delete/connect/config. No frame emitter exists in this
    process and HostGate/_run_gate_session are never used, so frame custody is
    false by construction. Diagnostic completion is not predicate acceptance.
    """
    gate, hc = mods["signing_network_gate"], mods["signer_host_controller"]
    container = f"tf-current-signer-{run_suffix}-2"
    steps = {key: "NOT_REACHED" for key in DEFAULT_BRIDGE_STEPS}
    out: dict[str, Any] = {"steps": steps, "detached_readback": "NOT_REACHED", "ready_framing": "NONE",
                           "observer_stderr": "NOT_READ", "attached_before_disconnect": None,
                           "after_disconnect": None, "bridge_gate_code": "NONE", "ownership_pinned": False,
                           "command_guard_refused": False, "refusal": "NONE"}
    custody: dict[str, Any] = {}
    session = guard = bridge_id = owner_label = None
    spawn_attempted = spawn_uncertain = succeeded = False
    teardown, interrupt, core_uncertain = None, None, True
    try:
        if gate.DEFAULT_BRIDGE_NAME != DEFAULT_BRIDGE_NETWORK or gate.OWNER_LABEL_KEY != OWNER_LABEL_KEY:
            raise ProbeRefusal("CONTAINER_ARGV_REFUSED")
        try:
            owner_label = gate.default_bridge_owner_label(run_suffix, nonce)
        except gate.GateError:
            raise ProbeRefusal("CONTAINER_ARGV_REFUSED") from None
        argv = build_observer_argv(image_id=image_id, container_python=container_python, network=DEFAULT_BRIDGE_NETWORK,
                                   container=container, p_dir=p_dir, uid=uid, gid=gid, nonce=nonce, hc=hc,
                                   owner_label=owner_label)
        guard = _DefaultBridgeCommandGuard(runner, gate, container, owner_label, custody)
        steps["preflight"] = "FAILED"
        try:
            bridge_id = hc._default_bridge_preflight(guard, container)
        except (gate.GateError, hc.HostControllerError) as error:
            out["bridge_gate_code"] = _bridge_gate_value(error, gate, hc)
            raise ProbeRefusal("BRIDGE_PREFLIGHT_REFUSED") from None
        if type(bridge_id) is not str or not _HEX64.fullmatch(bridge_id):
            raise ProbeRefusal("BRIDGE_PREFLIGHT_REFUSED")
        guard.bridge_id = bridge_id
        steps["preflight"], steps["container_start"] = "OK", "FAILED"
        spawn_attempted = True
        try:
            session = session_factory(spawner(argv, {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}),
                                      time.monotonic() + SESSION_SECONDS, ProbeRefusal)
        except Exception:
            spawn_uncertain = True
            raise ProbeRefusal("CONTAINER_SPAWN_FAILED") from None
        steps["container_start"], steps["ready"] = "OK", "FAILED"
        ready = session.read_protocol_line()
        framing = gate.classify_message_framing(ready)
        out["ready_framing"] = framing if framing in FRAMING_VALUES else "NONE"
        out["attached_before_disconnect"] = parse_line(ready, "ready", nonce, "READY_INVALID")
        steps["ready"], steps["ownership"] = "OK", "FAILED"
        try:
            disconnect_cmd, inspect_cmd = hc._prepare_default_bridge_disconnect(
                guard, container, owner_label, bridge_id, custody)
        except (gate.GateError, hc.HostControllerError) as error:
            out["bridge_gate_code"] = _bridge_gate_value(error, gate, hc)
            raise ProbeRefusal("OWNERSHIP_NOT_PROVEN") from None
        owned_id = custody.get("owned_id")
        if (type(owned_id) is not str or not _HEX64.fullmatch(owned_id)
                or (tuple(disconnect_cmd), tuple(inspect_cmd)) != gate.default_bridge_gate_commands(bridge_id, owned_id)):
            raise ProbeRefusal("OWNERSHIP_NOT_PROVEN")
        out["ownership_pinned"] = True
        steps["ownership"], steps["disconnect"] = "OK", "FAILED"
        if guard(disconnect_cmd, DOCKER_COMMAND_SECONDS)[0] != 0:
            raise ProbeRefusal("DISCONNECT_FAILED")
        rc, readback, _ = guard(inspect_cmd, DOCKER_COMMAND_SECONDS)
        if rc != 0:
            out["detached_readback"] = "COMMAND_FAILED"
            raise ProbeRefusal("INSPECT_FAILED")
        try:
            gate.require_detached_networks(readback)
        except gate.GateError as error:
            out["detached_readback"] = error.code if error.code in READBACK_VALUES else "NETWORK_READBACK_FORMAT"
            raise ProbeRefusal("DETACH_NOT_CONFIRMED") from None
        out["detached_readback"], steps["disconnect"] = "EMPTY_OBJECT", "OK"
        steps["challenge"] = "FAILED"
        session.write_stdin(encode_line("challenge", nonce), close_after=True)
        steps["challenge"], steps["result"] = "OK", "FAILED"
        out["after_disconnect"] = parse_line(session.read_protocol_line(), "result", nonce, "RESULT_INVALID")
        steps["result"], steps["observer_exit"] = "OK", "FAILED"
        exit_code = session.wait_for_exit()
        session.require_stdout_clean_eof()
        if exit_code != 0:
            raise ProbeRefusal("OBSERVER_NONZERO_EXIT")
        steps["observer_exit"] = "OK"
        succeeded = True
    except Exception as error:
        out["refusal"] = _label(error)
        if session is not None and not succeeded:
            stderr = hc._drain_pre_frame_stderr(session, grace_seconds=1.0)
            out["observer_stderr"] = parse_observer_stderr(stderr)
    finally:
        if spawn_attempted:
            # Ownership-bound core teardown: closes only our session, removes only a
            # resolved owned immutable ID (pinned when known), never touches the bridge.
            teardown, interrupt = hc._teardown_default_bridge_session(
                session, container, owner_label, bridge_id, guard, pinned_owned_id=custody.get("owned_id"),
                spawn_attempted=True, spawn_uncertain=spawn_uncertain)
            # Invariant: no secret frame or emitter exists or is invoked in this process.
            teardown["frame_capture_custody_retained"] = False
            core_uncertain = hc._default_bridge_teardown_uncertain(teardown, interrupt)
    if teardown is None:
        tear, uncertain = _default_teardown_not_run(), False
    else:
        tear, malformed = _record_default_teardown(teardown)
        uncertain = (core_uncertain is not False or malformed or tear["network_removed"]
                     or tear["builtin_bridge_configuration_commands_issued"] or not tear["removal_by_immutable_id_only"])
    if guard is not None and guard.refused:
        out["command_guard_refused"] = True
        uncertain = uncertain or teardown is not None
        if out["refusal"] == "NONE":
            out["refusal"] = "COMMAND_NOT_ALLOWED"
    out["teardown"], out["custody_retained"] = tear, uncertain
    if uncertain and out["refusal"] == "NONE":
        out["refusal"] = "TEARDOWN_UNCONFIRMED"
    if interrupt is not None:
        out["interrupt"] = interrupt
    return out


def prepare_runtime_image(*, p_dir: Path, work_dir: Path, run_suffix: str, token: str, environ: MutableMapping[str, str],
                          mods: Mapping[str, Any], recheck: Callable[[], None], leaf_importer: Callable | None = None,
                          transport_factory: Callable | None = None, engine_factory: Callable | None = None) -> dict:
    """Mirror of runtime_workflow_bridge.execute_prepare_image with an in-memory, same-process lease.

    Contract barrier: the production bridge binds callers to the qualification workflow ref, so
    the probe cannot call it. Every image control below is the production leaf call in the same
    order; only the binding file/lease receipt are replaced by process-local custody.
    """
    bridge, sib, rii = mods["runtime_workflow_bridge"], mods["signing_image_build"], mods["runtime_input_intake"]
    lease: dict[str, Any] = {"stage": "LEAF_IDENTITY", "build_result": None, "engine": None,
                             "work_root_cleaned": False, "custody_retained": False}
    imported = (leaf_importer or bridge._import_authenticated_runtime_leaves)(p_dir)
    if imported[0] is not sib or imported[1] is not rii:
        raise ProbeRefusal("IMAGE_PREPARE_FAILED", stage="LEAF_IDENTITY")
    lease["stage"] = "CLASS_NOT_ADMITTED"
    if sib.CLASS_ADMISSION_GATE_OPEN is not True or not sib._admitted_pin_matches(sib.ADMITTED_MANIFEST_SHA256):
        raise ProbeRefusal("IMAGE_PREPARE_FAILED", stage="CLASS_NOT_ADMITTED")
    rel = {"manifest": bridge.RUNTIME_ADMISSION_MANIFEST_REL_PATH, "cert": bridge.FEDORA_CERT_REL_PATH,
           "root": bridge.BASE_ROOT_PROOF_REL_PATH, "meta": bridge.BASE_METADATA_PROOF_REL_PATH,
           "notices": bridge.SUPPLEMENTAL_NOTICE_MANIFEST_REL_PATH, "notice_dir": bridge.SUPPLEMENTAL_NOTICE_DIR_REL_PATH}
    path = {key: p_dir / value for key, value in rel.items()}
    try:
        lease["stage"] = "ADMISSION"
        sib.authenticate_admission_manifest(path["manifest"], expected_manifest_sha256=sib.ADMITTED_MANIFEST_SHA256)
        sib.verify_selected_fedora_certificate_bytes(sib.held_unaliased_bytes(path["cert"], max_bytes=sib.MAX_SMALL_SOURCE_BYTES))
        if sib.sha256_hex(sib.held_unaliased_bytes(path["root"], max_bytes=sib.MAX_SMALL_SOURCE_BYTES)) != sib.BASE_ROOT_PROOF_SHA256:
            raise ProbeRefusal("IMAGE_PREPARE_FAILED", stage="ADMISSION")
        sib._verify_physical_base_metadata_proof(sib.held_unaliased_bytes(path["meta"], max_bytes=sib.MAX_SMALL_SOURCE_BYTES))
        sib._verify_physical_supplemental_notices(
            sib.held_unaliased_bytes(path["notices"], max_bytes=sib.MAX_SMALL_SOURCE_BYTES), path["notice_dir"])
        lease["stage"] = "WORK_ROOT"
        bridge._create_owned_0700_dir(work_dir, "WORK_ROOT_CREATE_FAILED")
    except ProbeRefusal:
        raise
    except Exception as error:
        raise ProbeRefusal("IMAGE_PREPARE_FAILED", stage=lease["stage"],
                           custody_retained=bool(getattr(error, "custody_retained", False))) from None
    try:
        try:
            bridge._create_owned_0700_dir(work_dir / "build", "WORK_ROOT_CREATE_FAILED")
            lease["stage"] = "INTAKE"
            transport = (transport_factory or (lambda tok, tdir: rii.RuntimeInputTransport(tok, str(tdir))))(
                token, str(work_dir / "transport"))
            token = ""
            rii.prepare_pinned_runtime_inputs(transport, work_dir / "quarantine", environ=environ)
            lease["stage"] = "QUARANTINE"
            quarantine = work_dir / "quarantine" / "QUARANTINE.json"
            if sib.sha256_hex(sib.held_unaliased_bytes(quarantine, max_bytes=sib.MAX_SMALL_SOURCE_BYTES)) != sib.QUARANTINE_SHA256:
                raise ProbeRefusal("IMAGE_PREPARE_FAILED", stage="QUARANTINE")
            os.unlink(quarantine)
            lease["stage"] = "SOURCE_RECHECK"
            recheck()
            lease["stage"] = "BUILD"
            engine = engine_factory() if engine_factory is not None else sib.BoundedDockerSubprocessEngine(allow_native_execution=True)
            lease["engine"] = engine
            lease["build_result"] = sib.execute_signing_image_build(
                manifest_path=path["manifest"], expected_manifest_sha256=sib.ADMITTED_MANIFEST_SHA256,
                archive_dir=work_dir / "quarantine", certificate_path=path["cert"], base_root_proof_path=path["root"],
                base_metadata_proof_path=path["meta"], supplemental_notice_manifest_path=path["notices"],
                supplemental_notice_dir=path["notice_dir"], work_root=work_dir / "build", run_id_suffix=run_suffix,
                engine=engine, caller_env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
            lease["stage"] = "BINDING"
            kwargs = sib.to_host_controller_image_kwargs(lease["build_result"])
            lease.update(image_id=kwargs["container_image"], container_python=kwargs["container_python"],
                         manifest_sha256=lease["build_result"].manifest_sha256,
                         recipe_sha256=lease["build_result"].recipe_sha256, stage="READY")
        except ProbeRefusal as error:
            error.custody_retained = error.custody_retained or lease["custody_retained"]
            raise
        except Exception as error:
            raise ProbeRefusal("IMAGE_PREPARE_FAILED", stage=lease["stage"],
                               custody_retained=bool(getattr(error, "custody_retained", False))) from None
        finally:
            token = ""
            lease["work_root_cleaned"] = bool(bridge._cleanup_owned_tree(work_dir, {"transport", "quarantine", "build"}))
        if not lease["work_root_cleaned"]:
            raise ProbeRefusal("WORK_ROOT_CLEANUP_FAILED", stage="READY", custody_retained=True)
        return lease
    except BaseException as error:
        error.probe_lease = lease  # type: ignore[attr-defined]
        if not lease["work_root_cleaned"] and isinstance(error, ProbeRefusal):
            error.custody_retained = True
        raise


def dispose_runtime_image(lease: Mapping[str, Any] | None, mods: Mapping[str, Any]) -> dict[str, bool]:
    if not lease:
        return {"attempted": False, "tag_removed": False, "image_id_removed": False, "confirmed": True}
    if lease.get("build_result") is None:
        # Before BUILD no image creation was attempted. Once BUILD starts,
        # absence of a successful result does not prove image absence.
        confirmed = lease.get("stage") not in {"BUILD", "BINDING", "READY"}
        return {"attempted": False, "tag_removed": False, "image_id_removed": False, "confirmed": confirmed}
    try:
        result = mods["signing_image_build"].dispose_built_image(lease["build_result"], lease["engine"])
        ok = result.get("tag_removed") is True and result.get("image_id_removed") is True \
            and result.get("custody_retained") is False
        return {"attempted": True, "tag_removed": result.get("tag_removed") is True,
                "image_id_removed": result.get("image_id_removed") is True, "confirmed": ok}
    except Exception:
        return {"attempted": True, "tag_removed": False, "image_id_removed": False, "confirmed": False}


def _base_result(source: dict | None, network_profile: str = DEFAULT_NETWORK_PROFILE) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA, "status": "refused", "refusal": "INTERNAL", "source": source,
        "network_profile": network_profile,
        "image": {"stage": "NOT_REACHED", "prepared": False, "manifest_sha256": None, "recipe_sha256": None,
                  "lease_scope": "same-process-in-memory", "work_root_cleaned": False,
                  "disposal_attempted": False, "tag_removed": False, "image_id_removed": False,
                  "disposal_confirmed": True},
        "lifecycle": None, "custody_retained": False,
        "isolation_accepted": False, "signing_performed": False, "signing_secrets_mapped": False,
        "credential_passed_to_container": False, "publication_authority": False,
        "production_admission": False, "listener_identity_established": False,
        "root_cause_established": False, "native_equivalence_claimed": False,
    }


_CONSTANT_FALSE = ("isolation_accepted", "signing_performed", "signing_secrets_mapped", "credential_passed_to_container",
                   "publication_authority", "production_admission", "listener_identity_established",
                   "root_cause_established", "native_equivalence_claimed")
_OBSERVATION_KEYS = frozenset({"steps", "detached_readback", "ready_framing", "observer_stderr",
                               "attached_before_disconnect", "after_disconnect", "teardown"})
_CUSTOM_TEARDOWN_KEYS = frozenset({"container_force_remove_attempted", "container_force_removed",
                                   "container_absence_confirmed", "network_removed",
                                   "session_cleanup_uncertain", "teardown_interrupted"})
_DEFAULT_LIFECYCLE_KEYS = _OBSERVATION_KEYS | {"bridge_gate_code", "ownership_pinned", "command_guard_refused"}
_DEFAULT_COMPLETE_TRUE = ("teardown_run", "removal_by_immutable_id_only", "owned_container_absence_confirmed",
                          "container_name_absent_confirmed", "container_absence_confirmed", "builtin_bridge_preserved",
                          "owned_bridge_endpoint_absent_confirmed", "owned_worker_endpoint_mutation_attempted",
                          "teardown_is_not_c6_cleanup")
_DEFAULT_COMPLETE_FALSE = ("network_removed", "builtin_bridge_configuration_commands_issued", "spawn_outcome_uncertain",
                           "session_cleanup_uncertain", "teardown_interrupted", "frame_capture_custody_retained",
                           "unexpected_bridge_peer_observed")


def _validate_observation(lc: dict, step_names: tuple[str, ...], code: str) -> dict[str, Any]:
    steps = _exact(lc["steps"], set(step_names), code)
    return {
        "steps": {key: _enum(steps[key], STEP_VALUES, code) for key in sorted(step_names)},
        "detached_readback": _enum(lc["detached_readback"], READBACK_VALUES, code),
        "ready_framing": _enum(lc["ready_framing"], FRAMING_VALUES, code),
        "observer_stderr": _enum(lc["observer_stderr"], OBSERVER_STDERR_VALUES, code),
        "attached_before_disconnect": None if lc["attached_before_disconnect"] is None
        else validate_snapshot(lc["attached_before_disconnect"], code),
        "after_disconnect": None if lc["after_disconnect"] is None else validate_snapshot(lc["after_disconnect"], code),
    }


def _validate_custom_lifecycle(obj: Any, code: str) -> dict[str, Any]:
    lc = _exact(obj, set(_OBSERVATION_KEYS), code)
    tear = _exact(lc["teardown"], set(_CUSTOM_TEARDOWN_KEYS), code)
    lifecycle = _validate_observation(lc, CUSTOM_BRIDGE_STEPS, code)
    lifecycle["teardown"] = {key: _bool(value, code) for key, value in sorted(tear.items())}
    return lifecycle


def _validate_default_lifecycle(obj: Any, code: str) -> dict[str, Any]:
    lc = _exact(obj, set(_DEFAULT_LIFECYCLE_KEYS), code)
    tear = _exact(lc["teardown"], {"owner_custody", *DEFAULT_TEARDOWN_BOOLS}, code)
    lifecycle = _validate_observation(lc, DEFAULT_BRIDGE_STEPS, code)
    lifecycle.update(
        bridge_gate_code=_enum(lc["bridge_gate_code"], BRIDGE_GATE_VALUES, code),
        ownership_pinned=_bool(lc["ownership_pinned"], code),
        command_guard_refused=_bool(lc["command_guard_refused"], code),
        teardown={"owner_custody": _enum(tear["owner_custody"], OWNER_CUSTODY_VALUES, code),
                  **{key: _bool(tear[key], code) for key in sorted(DEFAULT_TEARDOWN_BOOLS)}})
    teardown = lifecycle["teardown"]
    if ((teardown["owner_custody"] == "NOT_RUN") == teardown["teardown_run"]
            or lifecycle["ownership_pinned"] != (lifecycle["steps"]["ownership"] == "OK")):
        raise ProbeRefusal(code)
    return lifecycle


def _lifecycle_cleanup_complete(profile: str, lifecycle: Mapping[str, Any]) -> bool:
    tear = lifecycle["teardown"]
    if profile == "custom-bridge":
        return (tear["container_absence_confirmed"] and tear["network_removed"]
                and not tear["session_cleanup_uncertain"] and not tear["teardown_interrupted"])
    # Pinned ownership before the detach is required; a force removal is never the basis.
    return (lifecycle["ownership_pinned"] and not lifecycle["command_guard_refused"]
            and lifecycle["bridge_gate_code"] == "NONE" and tear["owner_custody"] in {"resolved", "absent"}
            and all(tear[key] for key in _DEFAULT_COMPLETE_TRUE)
            and not any(tear[key] for key in _DEFAULT_COMPLETE_FALSE)
            and (not tear["container_force_remove_attempted"] or tear["container_force_removed"]))


def validate_result(doc: Any) -> dict[str, Any]:
    """Closed v2 RESULT.json schema discriminated by network_profile; rebuilt from validated values only."""
    code = "RESULT_SCHEMA"
    keys = {"schema", "status", "refusal", "source", "network_profile", "image", "lifecycle", "custody_retained",
            *_CONSTANT_FALSE}
    doc = _exact(doc, keys, code)
    profile = _enum(doc["network_profile"], NETWORK_PROFILES, code)
    if doc["schema"] != RESULT_SCHEMA or any(doc[key] is not False for key in _CONSTANT_FALSE):
        raise ProbeRefusal(code)
    status = _enum(doc["status"], frozenset({"diagnostic-complete", "refused"}), code)
    refusal = _enum(doc["refusal"], HOST_REFUSALS, code)
    custody = _bool(doc["custody_retained"], code)
    if (status == "diagnostic-complete") != (refusal == "NONE" and not custody):
        raise ProbeRefusal(code)
    source = None
    if doc["source"] is not None:
        src = _exact(doc["source"], {"p_commit", "p_tree", "r_commit", "r_tree", "rs9_run", "leaf_manifest_sha256",
                                     "descriptor_sha256", "probe_source_sha256", "production_pins_verified",
                                     "run_id", "run_attempt"}, code)
        for key in ("p_commit", "p_tree", "r_commit", "r_tree"):
            if type(src[key]) is not str or not _HEX40.fullmatch(src[key]):
                raise ProbeRefusal(code)
        for key in ("leaf_manifest_sha256", "descriptor_sha256", "probe_source_sha256"):
            if type(src[key]) is not str or not _HEX64.fullmatch(src[key]):
                raise ProbeRefusal(code)
        if (type(src["rs9_run"]) is not int or src["rs9_run"] <= 0 or type(src["run_id"]) is not int
                or src["run_id"] <= 0 or src["run_attempt"] != 1 or src["production_pins_verified"] is not True):
            raise ProbeRefusal(code)
        source = dict(src)
    img = _exact(doc["image"], {"stage", "prepared", "manifest_sha256", "recipe_sha256", "lease_scope",
                                "work_root_cleaned", "disposal_attempted", "tag_removed", "image_id_removed",
                                "disposal_confirmed"}, code)
    for key in ("manifest_sha256", "recipe_sha256"):
        if img[key] is not None and (type(img[key]) is not str or not _HEX64.fullmatch(img[key])):
            raise ProbeRefusal(code)
    if img["lease_scope"] != "same-process-in-memory":
        raise ProbeRefusal(code)
    image = {"stage": _enum(img["stage"], IMAGE_STAGES, code), "manifest_sha256": img["manifest_sha256"],
             "recipe_sha256": img["recipe_sha256"], "lease_scope": "same-process-in-memory",
             **{k: _bool(img[k], code) for k in ("prepared", "work_root_cleaned", "disposal_attempted",
                                                  "tag_removed", "image_id_removed", "disposal_confirmed")}}
    lifecycle = None
    if doc["lifecycle"] is not None:
        validate_lifecycle = _validate_default_lifecycle if profile == "default-bridge" else _validate_custom_lifecycle
        lifecycle = validate_lifecycle(doc["lifecycle"], code)
    if status == "diagnostic-complete":
        if (lifecycle is None or lifecycle["attached_before_disconnect"] is None
                or lifecycle["after_disconnect"] is None or source is None
                or any(value != "OK" for value in lifecycle["steps"].values())
                or lifecycle["detached_readback"] != "EMPTY_OBJECT" or lifecycle["ready_framing"] != "NONE"
                or not image["prepared"] or not image["work_root_cleaned"]
                or not all(image[key] for key in ("disposal_attempted", "tag_removed", "image_id_removed", "disposal_confirmed"))
                or not _lifecycle_cleanup_complete(profile, lifecycle)):
            raise ProbeRefusal(code)
    return {"schema": RESULT_SCHEMA, "status": status, "refusal": refusal, "source": source,
            "network_profile": profile, "image": image,
            "lifecycle": lifecycle, "custody_retained": custody, **{key: False for key in _CONSTANT_FALSE}}


def write_result(path: Path, doc: dict) -> None:
    clean = validate_result(doc)
    parent = path.parent
    os.mkdir(parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        payload = (json.dumps(clean, indent=2, sort_keys=True) + "\n").encode("ascii")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
    finally:
        os.close(fd)


def execute_host(*, p_root: str, p_commit: str, work_root: str, environ: MutableMapping[str, str],
                 hooks: Mapping[str, Any] | None = None,
                 network_profile: str = DEFAULT_NETWORK_PROFILE) -> dict[str, Any]:
    """Return closed ordinary failures; interrupts propagate after best-effort cleanup.

    An interrupt can retain the partial image lease and prevent RESULT.json
    emission; final disposal then relies on the bounded hosted VM lifetime.
    The image lease/disposal path is identical for both network profiles.
    """
    if type(network_profile) is not str or network_profile not in NETWORK_PROFILES:
        raise ValueError("network_profile")  # Caller error; refused before any effect.
    hk = dict(hooks or {})
    result = _base_result(None, network_profile)
    mods: dict[str, Any] = {}
    lease: dict[str, Any] | None = None
    interrupt = None
    try:
        if hk.get("require_flags", True) and (not sys.flags.isolated or not sys.flags.dont_write_bytecode):
            raise ProbeRefusal("HOST_FLAGS")
        uname = hk.get("uname", os.uname)()
        if uname.sysname != "Linux" or uname.machine != "x86_64":
            raise ProbeRefusal("HOST_PLATFORM")
        sha, run_id = authenticate_probe_context(environ)
        if sha != p_commit:
            raise ProbeRefusal("CALLER_CONTEXT")
        p_dir = Path(p_root)
        if not p_dir.is_absolute() or any(part in {".", ".."} for part in p_dir.parts):
            raise ProbeRefusal("HOST_ARGUMENTS")
        verify_production_pins(p_dir)
        mods = hk.get("mods") or load_production_leaves(p_dir, HOST_LEAVES)
        bridge, sc = mods["runtime_workflow_bridge"], mods["source_closure"]
        try:
            token = bridge.pop_readonly_gh_token(environ)  # also refuses signing/GPG/DOCKER_ names
            bridge.require_key_free_bridge_env(environ, allow_gh_token=False)
        except bridge.RuntimeBridgeError:
            raise ProbeRefusal("CREDENTIAL_ENVIRONMENT") from None

        def authenticate_source() -> dict[str, Any]:
            try:
                p_dir_ok, p_tree = bridge.verify_clean_p_checkout_and_resolve_tree(p_dir, p_commit, git_runner=hk.get("git_runner"))
                sc.authenticate_leaf_closure(p_dir_ok, expected_leaf_manifest_sha256=PINNED_LEAF_MANIFEST_SHA256,
                                             require_unimported=False)
                descriptor, descriptor_sha = bridge._authenticate_closed_rs9_descriptor_in_p(p_dir_ok)
            except (bridge.RuntimeBridgeError, sc.ClosureError):
                raise ProbeRefusal("SOURCE_AUTHENTICATION") from None
            verify_production_pins(p_dir)
            rs9 = descriptor["rs9"]
            return {"p_commit": p_commit, "p_tree": p_tree, "r_commit": rs9["source_commit"],
                    "r_tree": rs9["source_tree"], "rs9_run": rs9["run_id"],
                    "leaf_manifest_sha256": PINNED_LEAF_MANIFEST_SHA256, "descriptor_sha256": descriptor_sha,
                    "probe_source_sha256": _sha256(_held_bytes(p_dir / PROBE_REL_PATH)),
                    "production_pins_verified": True, "run_id": run_id, "run_attempt": 1}

        source = authenticate_source()
        result["source"] = source

        def recheck() -> None:
            if authenticate_source() != source:
                raise ProbeRefusal("SOURCE_AUTHENTICATION")

        try:
            lease = prepare_runtime_image(
                p_dir=p_dir, work_dir=Path(work_root), run_suffix=str(run_id), token=token, environ=environ,
                mods=mods, recheck=recheck, leaf_importer=hk.get("leaf_importer"),
                transport_factory=hk.get("transport_factory"), engine_factory=hk.get("engine_factory"))
        finally:
            token = ""
        result["image"].update(stage="READY", prepared=True, work_root_cleaned=True,
                               manifest_sha256=lease["manifest_sha256"], recipe_sha256=lease["recipe_sha256"])
        hc, protocol_io = mods["signer_host_controller"], mods["signer_protocol_io"]
        lifecycle = (run_default_lifecycle if network_profile == "default-bridge" else run_lifecycle)(
            run_suffix=str(run_id), image_id=lease["image_id"], container_python=lease["container_python"],
            p_dir=p_dir, mods=mods, runner=hk.get("runner") or hc._default_docker_runner,
            spawner=hk.get("spawner") or hc._default_worker_spawner,
            session_factory=hk.get("session_factory") or protocol_io.ForegroundContainerSession,
            nonce=(hk.get("nonce_fn") or (lambda: secrets.token_hex(32)))(), uid=os.getuid(), gid=os.getgid())
        interrupt = lifecycle.pop("interrupt", None)
        result["refusal"] = lifecycle.pop("refusal")
        result["custody_retained"] = lifecycle.pop("custody_retained")
        result["lifecycle"] = lifecycle
    except ProbeRefusal as error:
        result["refusal"] = _label(error)
        result["custody_retained"] = result["custody_retained"] or error.custody_retained
        lease = getattr(error, "probe_lease", lease)
        if error.stage in IMAGE_STAGES:
            result["image"]["stage"] = error.stage
        if lease is not None:
            result["image"]["work_root_cleaned"] = bool(lease.get("work_root_cleaned"))
    except Exception:
        result["refusal"] = "INTERNAL"
        result["custody_retained"] = True  # Unknown failure is never treated as clean.
    finally:
        disposal = dispose_runtime_image(lease, mods)
        result["image"].update(disposal_attempted=disposal["attempted"], tag_removed=disposal["tag_removed"],
                               image_id_removed=disposal["image_id_removed"], disposal_confirmed=disposal["confirmed"])
        if not disposal["confirmed"]:
            result["custody_retained"] = True
            if result["refusal"] == "NONE":
                result["refusal"] = "IMAGE_DISPOSAL_UNCONFIRMED"
    if result["refusal"] == "NONE" and not result["custody_retained"]:
        result["status"] = "diagnostic-complete"
    elif result["refusal"] == "NONE":
        result["refusal"] = "TEARDOWN_UNCONFIRMED"
    if interrupt is not None:
        result["teardown_interrupt"] = interrupt
    return result


def parse_host_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="current_signer_isolation_probe.py --host", allow_abbrev=False)
    for flag in ("--p-root", "--p-commit", "--work-root", "--result-out"):
        parser.add_argument(flag, required=True)
    # Exactly two closed choices; custom-bridge remains the historical direct-CLI default.
    parser.add_argument("--network-profile", choices=NETWORK_PROFILES, default=DEFAULT_NETWORK_PROFILE)
    return parser.parse_args(argv)


def host_main(argv: list[str]) -> int:
    try:
        args = parse_host_args(argv)
    except SystemExit:
        print("REFUSED HOST_ARGUMENTS", file=sys.stderr)
        return 2
    result = execute_host(p_root=args.p_root, p_commit=args.p_commit, work_root=args.work_root, environ=os.environ,
                          network_profile=args.network_profile)
    interrupt = result.pop("teardown_interrupt", None)
    try:
        write_result(Path(args.result_out), result)
    except Exception:
        print("REFUSED RESULT_WRITE", file=sys.stderr)
        return 2
    print("ISOLATION_PROBE " + result["status"].upper() + " " + result["refusal"])
    if interrupt is not None:
        raise interrupt
    return 0 if result["status"] == "diagnostic-complete" else 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--observe"]:
        return observer_main(argv[1:])
    if argv[:1] == ["--host"]:
        return host_main(argv[1:])
    print("REFUSED MODE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
