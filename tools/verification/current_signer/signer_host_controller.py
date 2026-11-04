"""Host outer controller for Theme Forge full-signer container orchestration."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

from source_closure import (
    ClosureError, MAX_FRAME_SECRET_BYTES, REQUIRED_B3_LEAVES, WORKER_RECEIPT_SCHEMA,
    apply_process_git_scope, authenticate_leaf_closure, authenticate_rs9_descriptor,
    configure_worker_sys_path, held_regular_bytes, parse_strict_json, physical_dir,
    scoped_git_env, sha256_hex, verify_clean_git_checkout, zero_bytes,
)

DOCKER_BINARY = "/usr/bin/docker"
HOST_SUMMARY_SCHEMA = "tf.current-signer-host-controller.v1"
_FORBIDDEN_DOCKER_FLAGS = ("-t", "--tty", "-d", "--detach", "--privileged", "--net=host", "--network=host")
_FORBIDDEN_UPPER_SUBSTRINGS = (
    "--PRIVILEGED", "NET_ADMIN", "SYS_ADMIN", "DOCKER.SOCK",
    "SECRET", "PASSWORD", "PASSPHRASE", "PRIVATE_KEY", "SIGNING_KEY",
    "CREDENTIAL", "GPG_KEY", "TOKEN=", "KEY=",
)
_RUN_SUFFIX_RE = re.compile(r"^[0-9]{1,20}$")
_IMAGE_DIGEST_RE = re.compile(r"^(?:[A-Za-z0-9._/:+-]+@)?sha256:[0-9a-f]{64}$")
_UID_GID_RE = re.compile(r"^[0-9]+:[0-9]+$")
_RETAINED_HOST_SESSIONS: list[dict[str, Any]] = []
_RETAINED_FRAME_AVAILABILITY_DIRS: list[dict[str, Any]] = []

_ALLOWED_BOOTSTRAP_WORKER_CODES = frozenset({
    "CURRENT_SIGNER_MODE_REQUIRED",
    "SIGNER_BOOTSTRAP_FLAGS",
    "SIGNER_BOOTSTRAP_SYMLINK",
    "SIGNER_BOOTSTRAP_FILE",
    "SIGNER_BOOTSTRAP_CHANGED",
    "SIGNER_BOOTSTRAP_MANIFEST_PIN",
    "SIGNER_BOOTSTRAP_DUPLICATE",
    "SIGNER_BOOTSTRAP_SCHEMA",
    "SIGNER_BOOTSTRAP_INVENTORY",
    "SIGNER_BOOTSTRAP_PATH",
    "SIGNER_BOOTSTRAP_HASH",
    "SIGNER_BOOTSTRAP_LEAF_PIN",
    "SIGNER_BOOTSTRAP_MODULE_IDENTITY",
})

_PRE_FRAME_WORKER_CODE_ALLOWLIST = frozenset({
    "ADAPTER_REUSED",
    "ADOPTION_OUTPUT",
    "ARCHIVE_LIMIT",
    "ARCHIVE_ROOT",
    "ARTIFACT_SET",
    "BINARY_PIN_FORMAT",
    "BURST_NATIVE_TARGET",
    "CANDIDATE_PROJECT",
    "CHALLENGE_FORMAT",
    "CLIENT_CONFIGURE_FAILED",
    "CLIENT_INSTALL_FAILED",
    "CLIENT_REFRESH_FAILED",
    "CLIENT_START_FAILED",
    "COMMAND_PATH",
    "CONTAINER_CLEANUP",
    "CONTAINER_DIGEST_MISMATCH",
    "CONTAINER_DIGEST_UNRESOLVED",
    "CONTAINER_PULL_FAILED",
    "CONTEXT_INVALID",
    "CREDENTIAL_DETECTED",
    "CREDENTIAL_ENV_FORBIDDEN",
    "CURRENT_IMPORT_ROUTING",
    "CURRENT_RPM_POLICY_HELD",
    "CURRENT_SIGNING_LEASE",
    "CUSTODY_ARCHITECTURE",
    "CUSTODY_CONFLICT",
    "CUSTODY_FILE",
    "CUSTODY_HASH",
    "CUSTODY_INVENTORY",
    "CUSTODY_RECEIPT",
    "CUSTODY_ROLE",
    "CUSTODY_SCHEMA",
    "CUSTODY_SOURCE",
    "CUSTODY_SOURCE_EVIDENCE",
    "DESCRIPTOR_ABSENT",
    "DESCRIPTOR_BINDING_MISMATCH",
    "DESCRIPTOR_IO",
    "DESCRIPTOR_SCHEMA",
    "DESCRIPTOR_UNADMITTED",
    "DESTINATION_EXISTS",
    "DIAGNOSTIC_LIMIT",
    "DIAGNOSTIC_SCHEMA",
    "DISTRIBUTION_AUTHORITY",
    "DISTRIBUTION_BINARY_SCOPE",
    "DISTRIBUTION_CONFIG",
    "DISTRIBUTION_CUSTODY",
    "DISTRIBUTION_INPUT",
    "DISTRIBUTION_NOT_QUALIFIED",
    "DISTRIBUTION_PROMOTION_HELD",
    "DISTRIBUTION_SOURCE",
    "DUPLICATE_IDENTIFIER",
    "DUPLICATE_MEMBER",
    "DUPLICATE_MODULE_IDENTITY",
    "EXECUTING_BOOTSTRAP_MISMATCH",
    "EXPERIMENT_BINDING",
    "EXPERIMENT_POLICY",
    "EXPERIMENT_RECEIPT",
    "FETCH_FAILED",
    "FETCH_LIMIT",
    "FILE_CHANGED",
    "FILE_CUSTODY",
    "FILE_LIMIT",
    "FILE_MODE",
    "FINGERPRINT_FORMAT",
    "GATE_REUSED",
    "GENERATION_SELECTION",
    "GITHUB_IDENTITY",
    "GIT_CHECKOUT_DIRTY_OR_MISMATCH",
    "GIT_CHECKOUT_REQUIRED",
    "GIT_COMMAND_FAILED",
    "GIT_COMMIT_FORMAT",
    "GIT_SCOPE_INVALID",
    "GIT_SCOPE_OVERLAP",
    "GIT_TREE_FORMAT",
    "GPG_BINARY_CHANGED",
    "GPG_BINARY_CUSTODY",
    "GPG_BINARY_PATH",
    "GPG_CLEANUP_UNCONFIRMED",
    "GPG_OUTPUT_LIMIT",
    "GPG_TIMEOUT",
    "HASH",
    "HOME_IO",
    "HOME_MODE",
    "HOME_NOT_FRESH",
    "HOME_OWNER",
    "HOME_REQUIRED",
    "HOSTED_API",
    "HOSTED_API_LIMIT",
    "HOSTED_ARGUMENT",
    "HOSTED_ARTIFACTS",
    "HOSTED_BINDING",
    "HOSTED_COMMAND",
    "HOSTED_COMPLETENESS",
    "HOSTED_CUSTODY",
    "HOSTED_GATES",
    "HOSTED_JOBS",
    "HOSTED_NOT_QUALIFIED",
    "HOSTED_PACKET_LIMIT",
    "HOSTED_POLICY",
    "HOSTED_PROVENANCE",
    "HOSTED_READ",
    "HOSTED_RECEIPTS",
    "HOSTED_RUN",
    "HOSTED_RUN_CONTEXT",
    "HOSTED_SOURCE_TREE",
    "HOSTED_STEPS",
    "HOSTED_SUMMARY",
    "HOSTED_TIMEOUT",
    "IDENTITY_MISMATCH",
    "IMPORT_FAILED",
    "INPUT_CHANGED",
    "INPUT_UNREADABLE",
    "INVALID_ARCHITECTURE",
    "INVALID_ARCHIVE",
    "INVALID_ARGUMENT",
    "INVALID_CONFIG",
    "INVALID_CONTENT",
    "INVALID_DEB",
    "INVALID_DIRECTORY",
    "INVALID_DISTRIBUTION",
    "INVALID_ECOSYSTEM_NAME",
    "INVALID_ENCODING",
    "INVALID_EVIDENCE",
    "INVALID_FILE",
    "INVALID_HASH",
    "INVALID_HASHES",
    "INVALID_INTEGER",
    "INVALID_INTERPRETER",
    "INVALID_JSON",
    "INVALID_METADATA",
    "INVALID_PLATFORM",
    "INVALID_POLICY",
    "INVALID_REPO",
    "INVALID_REPOSITORY",
    "INVALID_SELECTION",
    "INVALID_SIGNATURE_FORMAT",
    "INVALID_SLUG",
    "INVALID_SPDX_EXPRESSION",
    "INVALID_STRING",
    "INVALID_STRING_TABLE",
    "INVALID_TAMPER_MUTATION",
    "INVALID_TIMESTAMP",
    "INVALID_TOML",
    "INVALID_TYPE",
    "INVALID_URL",
    "INVALID_VERSION",
    "ISOLATION_EXTERNAL_ROUTE",
    "ISOLATION_INTERFACE_OR_TABLES",
    "ISOLATION_METADATA_BOUND",
    "ISOLATION_METADATA_FORMAT",
    "ISOLATION_METADATA_UNAVAILABLE",
    "ISOLATION_REQUIRES_LINUX",
    "ISOLATION_ROUTE_FORMAT",
    "ISOLATION_SOCKET_FORMAT",
    "ISOLATION_SOCKET_PRESENT",
    "JSON_SCHEMA",
    "KEYRING_SCOPE",
    "KEY_DIGEST_MISMATCH",
    "KEY_LISTING_CAPABILITY",
    "KEY_LISTING_COUNT",
    "KEY_LISTING_EXPIRED",
    "KEY_LISTING_FAILED",
    "KEY_LISTING_FORMAT",
    "KEY_LISTING_IDENTITY",
    "KEY_LISTING_LIMIT",
    "KEY_LISTING_REVOKED",
    "KEY_LISTING_TIME",
    "KEY_LISTING_UNEXPECTED",
    "KEY_PATH_NOT_NONPRODUCTION",
    "LANES_MISSING",
    "LANES_POLICY",
    "LANES_SCHEMA",
    "LEAF_FILE_DIGEST_MISMATCH",
    "LEAF_IMPORTED_BEFORE_AUTH",
    "LEAF_MANIFEST_DIGEST_MISMATCH",
    "LEAF_MANIFEST_INVENTORY",
    "LEAF_MANIFEST_PIN_FORMAT",
    "LEAF_MANIFEST_SCHEMA",
    "LEASE_PID_OR_STATE",
    "LIVE1_RELEASE_MISMATCH",
    "MALFORMED_ELF",
    "MALFORMED_TEMPLATE",
    "MESSAGE_BINDING",
    "MESSAGE_BOUND",
    "MESSAGE_DUPLICATE",
    "MESSAGE_FORMAT",
    "MESSAGE_FRAMING",
    "MESSAGE_KIND",
    "METADATA_BUILD_FAILED",
    "MISSING",
    "MISSING_BY_HASH",
    "MISSING_INDEX",
    "MISSING_PACKAGE",
    "MISSING_RELEASE",
    "MISSING_REQUIRED_FILE",
    "MISSING_REQUIRED_KEY",
    "MISSING_SIGNATURE",
    "MODE_MISMATCH",
    "NATIVE_GENERATION_BINDING",
    "NATIVE_REQUIRED",
    "NETWORK_ATTACHED",
    "NETWORK_DENIAL",
    "NETWORK_READBACK_BOUND",
    "NETWORK_READBACK_FORMAT",
    "NIX_CATALOG_BINDING",
    "NON_NFC_LICENSE_EXPRESSION",
    "NON_NFC_PATH",
    "NON_NFC_STRING",
    "OUTPUT_CONFINEMENT",
    "OUTPUT_NOT_EMPTY",
    "OWN_REPOSITORY_ADMISSION",
    "OWN_REPOSITORY_SOURCE",
    "OWN_REPOSITORY_UNADMITTED",
    "PACKAGE",
    "PATH_FORMAT",
    "PATH_IO",
    "PATH_MISSING",
    "PERMISSION_ERROR",
    "PHYSICAL_DIR_REQUIRED",
    "PHYSICAL_PATH_MISSING",
    "PHYSICAL_PATH_REQUIRED",
    "PLAINTEXT_MISMATCH",
    "PLAINTEXT_STATUS",
    "POLICY_CHUNK_LIMIT",
    "PRIVATE_KEY_REJECTED",
    "PRIVATE_PATH",
    "PRIVATE_WORK_PRESENT",
    "PROCESS_OWNER_UNAVAILABLE",
    "PRODUCT",
    "PROTOCOL_CLOSE_FAILED",
    "PROTOCOL_READ_BOUND",
    "PROTOCOL_STDIN_CLOSED",
    "PROTOCOL_STDIO_DETACH",
    "PROTOCOL_STDOUT_CLOSED",
    "PROTOCOL_WRITE_FAILED",
    "PROVISION_FAILED",
    "PUBLIC_DIRECTORY",
    "PUBLIC_DIRECTORY_COUNT",
    "PUBLIC_DIRECTORY_INVENTORY",
    "PUBLIC_DIRECTORY_MUTATED",
    "PUBLIC_FILE_COUNT",
    "PUBLIC_FILE_CUSTODY",
    "PUBLIC_RELAY_ARTIFACT",
    "PUBLIC_RELAY_CONFIG",
    "PUBLIC_RELAY_DIGEST",
    "PUBLIC_RELAY_EXTRACT",
    "PUBLIC_RELAY_HTTP",
    "PUBLIC_RELAY_IDENTITY",
    "PUBLIC_RELAY_LIMIT",
    "PUBLIC_RELAY_MODE",
    "PUBLIC_RELAY_REDIRECT",
    "PUBLIC_RELAY_SCHEMA",
    "PUBLIC_RELAY_SCOPE",
    "PUBLIC_RELAY_SET",
    "PUBLIC_RELAY_SIZE",
    "PUBLIC_RELAY_TIMEOUT",
    "PUBLIC_RELAY_URL",
    "PUBLIC_ROOT",
    "PUBLIC_ROOT_MUTATED",
    "PUBLIC_ROOT_NOT_EMPTY",
    "PUBLIC_SNAPSHOT_MUTATED",
    "PUBLIC_TOTAL_BOUND",
    "PYTHON_ISOLATION_FLAGS",
    "QUALIFICATION_PENDING",
    "RECORD_LIMIT",
    "RECORD_SCHEMA",
    "RECORD_TYPE",
    "REDIRECT_REJECTED",
    "REGULAR_FILE_REQUIRED",
    "REGULAR_SOURCE_REQUIRED",
    "RELEASE_LIMIT",
    "REQUEST_CLASS",
    "REQUEST_HEADER",
    "RESOURCE_ID",
    "RESULT_INVALID",
    "ROOT_OVERLAP",
    "RPMLINT_FAILED",
    "RPM_EVIDENCE_MESSAGE",
    "RPM_EVIDENCE_PROJECTION",
    "RPM_EVIDENCE_SCHEMA",
    "RPM_POLICY_CUSTODY",
    "RPM_REPOSITORY_OPERATION",
    "RPM_SIGNING",
    "RUNNER_COMMAND",
    "RUNNER_CONFIG",
    "RUNNER_CUSTODY_RETAINED",
    "RUNNER_ENV",
    "RUNNER_IO",
    "RUNNER_REQUIRED",
    "SCHEMA",
    "SCHEMA_MISMATCH",
    "SIGCHLD_OR_THREAD_PRECONDITION",
    "SIGNATURE_BODY_MISMATCH",
    "SIGNATURE_COUNT",
    "SIGNATURE_DATE_MISMATCH",
    "SIGNATURE_EXPIRED",
    "SIGNATURE_FORMAT",
    "SIGNATURE_KIND",
    "SIGNATURE_LIMIT",
    "SIGNATURE_REJECTED",
    "SIGNATURE_TIME",
    "SIGNING_SECRET_ENV_FORBIDDEN",
    "SIZE",
    "SIZE_MISMATCH",
    "SOURCE",
    "SOURCE_BINDING",
    "SOURCE_FILE_BOUND",
    "SOURCE_FILE_CHANGED",
    "SOURCE_FILE_MISSING",
    "SOURCE_FILE_OPEN",
    "STAGED_CLEANUP_UNCONFIRMED",
    "STAGED_CLOSE_UNCONFIRMED",
    "STAGED_FILE_CHANGED",
    "STAGE_ROUTING_MISMATCH",
    "STAGE_ROUTING_SCHEMA",
    "STAGE_SOURCE_JOIN_MISMATCH",
    "STAGING_CUSTODY",
    "STAGING_IO",
    "STATUS_FORMAT",
    "STATUS_LIMIT",
    "STATUS_UNEXPECTED",
    "STDLIB_PATH_MISSING",
    "SUMMARY_LANE",
    "SUMMARY_LIMIT",
    "SYMLINK_REJECTED",
    "SYSTEM",
    "TAMPER_DETECTED",
    "TOOL_EXECUTION",
    "TRUNCATED_ELF",
    "UNEXPECTED_TOKEN_ENV",
    "UNINDEXED_PACKAGE",
    "UNKNOWN_ADAPTER",
    "UNKNOWN_KEY",
    "UNKNOWN_PRODUCT",
    "UNPINNED_TRUST",
    "UNSAFE_LINK",
    "UNSAFE_MEMBER",
    "UNSAFE_MODE",
    "UNSAFE_PATH",
    "UNSAFE_URL",
    "UNSELECTED",
    "UNSUPPORTED_ELF",
    "UNSUPPORTED_PLATFORM",
    "VERIFY_FAILED",
    "WEAK_HASH",
    "WITHHELD",
    "WORKER_EXECUTION_FAILED",
    "WORKER_PID",
    "WORKER_PID_CHANGED",
    "WORKSPACE_CUSTODY",
    "WORKSPACE_NOT_EMPTY",
    "WRITE_ERROR",
})

_PRE_FRAME_WORKER_DETAIL_ALLOWLIST = frozenset({
    "LO_INTERFACE_MISSING",
    "NON_LO_INTERFACE_PRESENT",
    "PROC_TABLE_SET_MISMATCH",
    "IPV4_NON_LO_ROUTE",
    "IPV6_NON_LO_ROUTE",
    "SOCKET_ROW_MALFORMED",
    "UDP_V4_SOCKET",
    "UDP_V6_SOCKET",
    "TCP_V4_LISTEN",
    "TCP_V6_LISTEN",
    "TCP_V4_CLOSING_STATE",
    "TCP_V6_CLOSING_STATE",
    "TCP_V4_ACTIVE_STATE",
    "TCP_V6_ACTIVE_STATE",
    "TCP_OTHER_STATE",
})

_ALLOWED_HANDSHAKE_OBSERVATIONS: dict[str, frozenset[str]] = {
    "gate_phase": frozenset({
        "WAITING_READY",
        "CHECKING_READY",
        "DISCONNECTING_NETWORK",
        "CHECKING_ISOLATION",
        "EMITTING_FRAME",
        "POST_FRAME",
    }),
    "framing_reason": frozenset({
        "NONE",
        "EMPTY_EOF",
        "NON_BYTES",
        "LINE_OVERFLOW",
        "CR_PRESENT",
        "TRUNCATED_NO_NEWLINE",
        "MULTIPLE_NEWLINES",
    }),
    "worker_error_code": (
        frozenset({
            "NONE",
            "STDERR_EMPTY",
            "WITHHELD_POST_FRAME",
            "UNRECOGNIZED_STDERR_FORMAT",
            "UNLISTED_WORKER_CODE",
        })
        | _ALLOWED_BOOTSTRAP_WORKER_CODES
        | _PRE_FRAME_WORKER_CODE_ALLOWLIST
    ),
    "worker_error_detail": (
        frozenset({
            "NONE",
            "WITHHELD_POST_FRAME",
            "UNLISTED_WORKER_DETAIL",
        })
        | _PRE_FRAME_WORKER_DETAIL_ALLOWLIST
    ),
}

_ALLOWED_HOST_ERROR_CODES = frozenset({
    "CONTAINER_IMAGE_PIN",
    "CONTAINER_PYTHON_PATH",
    "DOCKER_RUN_PREFIX",
    "DOCKER_RUN_TOKEN",
    "DOCKER_RUN_FORBIDDEN_FLAG",
    "DOCKER_RUN_FORBIDDEN_CONTENT",
    "DOCKER_RUN_HARDENING",
    "FRAME_SOURCE_CHANGED",
    "FRAME_EMITTER_FAILED",
    "FRAME_AVAILABILITY_RETAINED",
    "EXPORT_ROOT_POLLUTED",
    "WORKER_RECEIPT_INVALID",
    "EXPORT_INVENTORY_MISMATCH",
    "RUN_SUFFIX_INVALID",
    "EXPORT_ROOT_NOT_EMPTY",
    "DOCKER_NETWORK_DISCONNECT",
    "DOCKER_NETWORK_INSPECT",
    "DOCKER_NETWORK_CREATE",
    "WORKER_NONZERO_EXIT",
    "HOST_TEARDOWN_UNCONFIRMED",
    "HOST_CONTROLLER_TIMEOUT",
    "PROTOCOL_STDOUT_OVERFLOW",
    "PROTOCOL_EXTRA_STDOUT",
    "PROTOCOL_STDIN_UNAVAILABLE",
    "PROTOCOL_STDIN_WRITE",
    "PROTOCOL_STDIN_CLOSE",
    "FRAME_HEADER_INVALID",
    "FRAME_PAYLOAD_INVALID",
    "STDIN_FRAME_FORMAT",
    "STDIN_FRAME_BOUNDS",
    "HOST_EXECUTION_FAILED",
    "PHYSICAL_PATH_REQUIRED",
    "PHYSICAL_PATH_MISSING",
    "PHYSICAL_DIR_REQUIRED",
    "SOURCE_FILE_MISSING",
    "REGULAR_SOURCE_REQUIRED",
    "SOURCE_FILE_OPEN",
    "SOURCE_FILE_BOUND",
    "SOURCE_FILE_CHANGED",
    "JSON_SCHEMA",
    "AVAILABILITY_SCHEMA",
    "RECEIPT_SCHEMA",
    "GIT_SCOPE_OVERLAP",
    "GIT_SCOPE_INVALID",
    "GIT_COMMIT_FORMAT",
    "GIT_TREE_FORMAT",
    "GIT_CHECKOUT_REQUIRED",
    "GIT_COMMAND_FAILED",
    "GIT_CHECKOUT_DIRTY_OR_MISMATCH",
    "DESCRIPTOR_ABSENT",
    "DESCRIPTOR_IO",
    "DESCRIPTOR_SCHEMA",
    "DESCRIPTOR_UNADMITTED",
    "DESCRIPTOR_BINDING_MISMATCH",
    "LEAF_MANIFEST_PIN_FORMAT",
    "LEAF_IMPORTED_BEFORE_AUTH",
    "LEAF_MANIFEST_DIGEST_MISMATCH",
    "LEAF_MANIFEST_SCHEMA",
    "LEAF_MANIFEST_INVENTORY",
    "LEAF_FILE_DIGEST_MISMATCH",
    "EXECUTING_BOOTSTRAP_MISMATCH",
    "PYTHON_ISOLATION_FLAGS",
    "DUPLICATE_MODULE_IDENTITY",
    "STDLIB_PATH_MISSING",
    "SOURCE_BINDING",
    "WORKER_PID",
    "MESSAGE_KIND",
    "CHALLENGE_FORMAT",
    "MESSAGE_BOUND",
    "MESSAGE_DUPLICATE",
    "MESSAGE_FRAMING",
    "MESSAGE_FORMAT",
    "MESSAGE_BINDING",
    "RESOURCE_ID",
    "NETWORK_READBACK_BOUND",
    "NETWORK_READBACK_FORMAT",
    "NETWORK_ATTACHED",
    "GATE_REUSED",
    "FRAME_ARGUMENT_INVALID",
    "FRAME_CUSTODY_RETAINED",
    "FRAME_PRECONDITION_SIGCHLD",
    "FRAME_PRECONDITION_THREADS",
    "FRAME_SPAWN_FAILED",
    "FRAME_CAPTURE_TIMEOUT",
    "FRAME_STDOUT_OVERFLOW",
    "FRAME_STDERR_OVERFLOW",
    "FRAME_EMITTER_NONZERO",
    "FRAME_GROUP_RETAINED",
    "FRAME_CUSTODY_LOST",
    "FRAME_STREAM_CLOSE_FAILED",
    # Built-in default-bridge intake: fixed closed labels only.
    "DOCKER_BRIDGE_INSPECT",
    "DOCKER_CONTAINER_LIST",
    "DOCKER_WORKER_INSPECT",
    "DEFAULT_BRIDGE_ARGV",
    "DEFAULT_BRIDGE_CUSTODY",
    "DEFAULT_BRIDGE_WORKER_ENV",
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
})

_DEFAULT_BRIDGE_NETWORK = "bridge"
_DEFAULT_BRIDGE_OWNER_LABEL_KEY = "tf.current-signer.run"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNING_SECRET_ENV_MARKERS = ("PACKAGE_SIGNING", "SIGNING_KEY", "PASSPHRASE", "GPG_KEY", "PRIVATE_KEY")

# Post-frame closed diagnostic (PRIVATE, UNADOPTED proposal). Mirrors the worker's fixed vocabulary;
# the record is an untrusted worker claim, never root-cause proof, gate input or release authority.
POST_FRAME_DIAGNOSTIC_SCHEMA = "tf.current-signer-host-post-frame-diagnostic.v1"
_WORKER_POST_FRAME_DIAGNOSTIC_SCHEMA = "tf.current-signer-worker-post-frame-diagnostic.v1"
_MAX_POST_FRAME_RECORD_BYTES = 4096
_POST_FRAME_RECORD_STATES = frozenset({"VALID", "ABSENT", "NOT_SINGLE_RECORD", "INVALID_RECORD"})
_POST_FRAME_WORKER_STEPS = frozenset({
    "PRIVATE_PHASE_ENTERED",
    "PRIVATE_MODULE_IMPORT",
    "FRAME_READ",
    "SIGNING_RUNTIME",
    "CUSTODY_CHECK",
    "PUBLIC_VERIFICATION",
    "PUBLIC_EXPORT",
    "RECEIPT",
    "UNAVAILABLE",
})
_POST_FRAME_WORKER_CODES = frozenset({
    "STDIN_FRAME_FORMAT",
    "PROTOCOL_STDIN_CLOSED",
    "PROTOCOL_READ_BOUND",
    "PROTOCOL_CLOSE_FAILED",
    "WORKER_PID_CHANGED",
    "LEASE_PID_OR_STATE",
    "SIGCHLD_OR_THREAD_PRECONDITION",
    "PRIVATE_CLEANUP_UNCONFIRMED",
    "SIGNING_NATIVE_EXECUTION_REQUIRED",
    "SIGNING_FIXTURE_STATE_INVALID",
    "PUBLIC_VERIFICATION_FAILED",
    "EXPORT_INVENTORY_MISMATCH",
    "SOURCE_FILE_MISSING",
    "SOURCE_FILE_OPEN",
    "SOURCE_FILE_BOUND",
    "SOURCE_FILE_CHANGED",
    "REGULAR_SOURCE_REQUIRED",
    "PHYSICAL_DIR_REQUIRED",
    "GPG_TIMEOUT",
    "GPG_CLEANUP_UNCONFIRMED",
    "GPG_OUTPUT_LIMIT",
    "GPG_BINARY_CHANGED",
    "GPG_BINARY_CUSTODY",
    "HOME_NOT_FRESH",
    "PRIVATE_WORK_PRESENT",
    "RPM_SIGNING",
    "SIGNATURE_REJECTED",
    "PLAINTEXT_MISMATCH",
    "VERIFY_FAILED",
    "TOOL_EXECUTION",
    "CURRENT_SIGNING_LEASE",
    "STAGED_FILE_CHANGED",
    "STAGED_CLEANUP_UNCONFIRMED",
    "PUBLIC_SNAPSHOT_MUTATED",
    "PUBLIC_ROOT_NOT_EMPTY",
    "PUBLIC_FILE_CUSTODY",
    "DESTINATION_EXISTS",
    "NATIVE_REQUIRED",
    "CUSTODY_INVENTORY",
    "PUBLIC_DIRECTORY_MUTATED",
    "PUBLIC_ROOT_MUTATED",
    "MISSING_SIGNATURE",
    "SIGNATURE_COUNT",
    "PYTHON_MODULE_NOT_FOUND",
    "PYTHON_IMPORT_ERROR",
    "PYTHON_UNICODE_ERROR",
    "PYTHON_KEY_ERROR",
    "PYTHON_INDEX_ERROR",
    "PYTHON_ATTRIBUTE_ERROR",
    "PYTHON_TYPE_ERROR",
    "PYTHON_VALUE_ERROR",
    "PYTHON_PERMISSION_ERROR",
    "PYTHON_FILE_NOT_FOUND",
    "PYTHON_FILE_EXISTS",
    "PYTHON_OS_ERROR",
    "PYTHON_MEMORY_ERROR",
    "PYTHON_RECURSION_ERROR",
    "PYTHON_NOT_IMPLEMENTED",
    "PYTHON_ASSERTION_ERROR",
    "PYTHON_RUNTIME_ERROR",
    "UNCLASSIFIED",
})
_POST_FRAME_WORKER_RECORD_KEYS = frozenset({
    "schema", "status", "error_code", "custody_retained",
    "publication_authority", "native_client_qualification", "post_frame_diagnostic",
})


class HostControllerError(RuntimeError):
    """Fixed-code host controller refusal; never embeds secret payloads."""
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def sanitize_handshake_observation(
    observation: Mapping[str, str] | None,
) -> dict[str, str] | None:
    if (
        type(observation) is dict
        and set(observation) == set(_ALLOWED_HANDSHAKE_OBSERVATIONS)
        and all(
            type(observation[key]) is str and observation[key] in allowed_values
            for key, allowed_values in _ALLOWED_HANDSHAKE_OBSERVATIONS.items()
        )
    ):
        return dict(observation)
    return None


def _drain_pre_frame_stderr(session: Any, *, grace_seconds: float = 1.0) -> bytes:
    deadline = min(getattr(session, "deadline", 0.0), time.monotonic() + grace_seconds)
    try:
        while time.monotonic() < deadline:
            sel_map = session.selector.get_map() if hasattr(session, "selector") else {}
            if not any(key.data == "stderr" for key in sel_map.values()):
                break
            session._pump_once(max(0.0, min(0.05, deadline - time.monotonic())))
    except Exception:
        pass
    return bytes(getattr(session, "stderr_buf", b""))


def _parse_untrusted_pre_frame_worker_stderr(raw_stderr: bytes) -> tuple[str, str]:
    """Extract only closed-set pre-frame error tokens from untrusted worker stderr."""
    if not isinstance(raw_stderr, bytes) or not raw_stderr:
        return "STDERR_EMPTY", "NONE"
    if len(raw_stderr) > 4096 or b"\x00" in raw_stderr or b"\r" in raw_stderr:
        return "UNRECOGNIZED_STDERR_FORMAT", "NONE"
    try:
        text = raw_stderr.decode("ascii")
    except UnicodeDecodeError:
        return "UNRECOGNIZED_STDERR_FORMAT", "NONE"
    lines = [line for line in text.split("\n") if line]
    if len(lines) != 1:
        return "UNRECOGNIZED_STDERR_FORMAT", "NONE"
    line = lines[0]
    if line in _ALLOWED_BOOTSTRAP_WORKER_CODES:
        return line, "NONE"
    try:
        doc = parse_strict_json(line.encode("ascii"), "WORKER_STDERR_JSON")
    except ClosureError:
        return "UNRECOGNIZED_STDERR_FORMAT", "NONE"
    required_base = {
        "schema", "status", "error_code", "custody_retained",
        "publication_authority", "native_client_qualification",
    }
    keys = set(doc)
    if (
        not (keys == required_base or keys == (required_base | {"error_detail"}))
        or doc.get("schema") != WORKER_RECEIPT_SCHEMA
        or doc.get("status") != "failed-closed"
        or type(doc.get("custody_retained")) is not bool
        or doc.get("publication_authority") is not False
        or doc.get("native_client_qualification") is not False
        or type(doc.get("error_code")) is not str
    ):
        return "UNRECOGNIZED_STDERR_FORMAT", "NONE"
    raw_code = doc["error_code"]
    code = raw_code if raw_code in _PRE_FRAME_WORKER_CODE_ALLOWLIST else "UNLISTED_WORKER_CODE"
    if "error_detail" not in doc:
        return code, "NONE"
    raw_detail = doc["error_detail"]
    if type(raw_detail) is not str:
        return "UNRECOGNIZED_STDERR_FORMAT", "NONE"
    detail = raw_detail if raw_detail in _PRE_FRAME_WORKER_DETAIL_ALLOWLIST else "UNLISTED_WORKER_DETAIL"
    return code, detail


def _classify_gate_phase(gate: Any) -> str:
    failed_phase = getattr(gate, "failed_phase", None)
    frame_emitted = bool(getattr(gate, "frame_emitted", False))
    if frame_emitted:
        if failed_phase == "emitting-frame":
            return "EMITTING_FRAME"
        return "POST_FRAME"
    phase_map = {
        "waiting-ready": "WAITING_READY",
        "checking-ready": "CHECKING_READY",
        "disconnecting": "DISCONNECTING_NETWORK",
        "checking-isolation": "CHECKING_ISOLATION",
        "emitting-frame": "EMITTING_FRAME",
        "frame-closed": "POST_FRAME",
    }
    if type(failed_phase) is str and failed_phase in phase_map:
        return phase_map[failed_phase]
    state = getattr(gate, "state", None)
    if type(state) is str and state in phase_map:
        return phase_map[state]
    return "WAITING_READY"


def _build_handshake_observation(
    gate: Any, session: Any | None, error: BaseException,
) -> dict[str, str] | None:
    if not isinstance(error, Exception):
        return None
    try:
        gate_phase = _classify_gate_phase(gate)
        raw_reason = getattr(error, "framing_reason", None)
        framing_reason = (
            raw_reason
            if type(raw_reason) is str and raw_reason in _ALLOWED_HANDSHAKE_OBSERVATIONS["framing_reason"]
            else "NONE"
        )
        if bool(getattr(gate, "frame_emitted", False)) or gate_phase in {"EMITTING_FRAME", "POST_FRAME"}:
            worker_code, worker_detail = "WITHHELD_POST_FRAME", "WITHHELD_POST_FRAME"
        elif session is None:
            worker_code, worker_detail = "NONE", "NONE"
        else:
            raw_stderr = _drain_pre_frame_stderr(session, grace_seconds=1.0)
            worker_code, worker_detail = _parse_untrusted_pre_frame_worker_stderr(raw_stderr)
        return sanitize_handshake_observation({
            "gate_phase": gate_phase,
            "framing_reason": framing_reason,
            "worker_error_code": worker_code,
            "worker_error_detail": worker_detail,
        })
    except Exception:
        return None


def _post_frame_diagnostic_view(record: str, step: str = "UNAVAILABLE", code: str = "UNCLASSIFIED") -> dict[str, Any]:
    return {
        "schema": POST_FRAME_DIAGNOSTIC_SCHEMA, "record": record, "step": step, "code": code,
        "untrusted_worker_claim": True,
    }


def sanitize_post_frame_diagnostic(diagnostic: Any) -> dict[str, Any] | None:
    try:
        if (
            type(diagnostic) is dict
            and set(diagnostic) == {"schema", "record", "step", "code", "untrusted_worker_claim"}
            and diagnostic["schema"] == POST_FRAME_DIAGNOSTIC_SCHEMA
            and diagnostic["untrusted_worker_claim"] is True
            and type(diagnostic["record"]) is str and diagnostic["record"] in _POST_FRAME_RECORD_STATES
            and type(diagnostic["step"]) is str and diagnostic["step"] in _POST_FRAME_WORKER_STEPS
            and type(diagnostic["code"]) is str and diagnostic["code"] in _POST_FRAME_WORKER_CODES
            and (diagnostic["record"] == "VALID" or (diagnostic["step"], diagnostic["code"]) == ("UNAVAILABLE", "UNCLASSIFIED"))
        ):
            return _post_frame_diagnostic_view(diagnostic["record"], diagnostic["step"], diagnostic["code"])
    except Exception:
        pass
    return None


def _parse_untrusted_post_frame_worker_stderr(raw_stderr: bytes) -> dict[str, Any]:
    """Validate exactly one bounded closed worker failure record; anything else is a fixed unavailable view."""
    if type(raw_stderr) is not bytes:
        return _post_frame_diagnostic_view("NOT_SINGLE_RECORD")
    if not raw_stderr:
        return _post_frame_diagnostic_view("ABSENT")
    if len(raw_stderr) > _MAX_POST_FRAME_RECORD_BYTES or b"\x00" in raw_stderr or b"\r" in raw_stderr:
        return _post_frame_diagnostic_view("NOT_SINGLE_RECORD")
    try:
        text = raw_stderr.decode("ascii")
    except UnicodeDecodeError:
        return _post_frame_diagnostic_view("NOT_SINGLE_RECORD")
    lines = [line for line in text.split("\n") if line]
    if len(lines) != 1:
        return _post_frame_diagnostic_view("NOT_SINGLE_RECORD")
    try:
        doc = parse_strict_json(lines[0].encode("ascii"), "WORKER_STDERR_JSON")
    except ClosureError:
        return _post_frame_diagnostic_view("INVALID_RECORD")
    diagnostic = doc.get("post_frame_diagnostic")
    if (
        set(doc) != _POST_FRAME_WORKER_RECORD_KEYS
        or doc.get("schema") != WORKER_RECEIPT_SCHEMA
        or doc.get("status") != "failed-closed"
        or doc.get("error_code") != "WITHHELD_POST_FRAME"
        or type(doc.get("custody_retained")) is not bool
        or doc.get("publication_authority") is not False
        or doc.get("native_client_qualification") is not False
        or type(diagnostic) is not dict
        or set(diagnostic) != {"schema", "step", "code"}
        or diagnostic.get("schema") != _WORKER_POST_FRAME_DIAGNOSTIC_SCHEMA
        or type(diagnostic.get("step")) is not str or diagnostic["step"] not in _POST_FRAME_WORKER_STEPS
        or type(diagnostic.get("code")) is not str or diagnostic["code"] not in _POST_FRAME_WORKER_CODES
    ):
        return _post_frame_diagnostic_view("INVALID_RECORD")
    return _post_frame_diagnostic_view("VALID", diagnostic["step"], diagnostic["code"])


def _build_post_frame_diagnostic(gate: Any, session: Any | None, error: BaseException) -> dict[str, Any] | None:
    """Only after the host's own POST_FRAME state and a worker nonzero exit; never alters error, gate or teardown."""
    if not isinstance(error, HostControllerError) or error.code != "WORKER_NONZERO_EXIT":
        return None
    if not bool(getattr(gate, "frame_emitted", False)) or _classify_gate_phase(gate) != "POST_FRAME":
        return None
    if session is None:
        return _post_frame_diagnostic_view("ABSENT")
    return sanitize_post_frame_diagnostic(
        _parse_untrusted_post_frame_worker_stderr(_drain_pre_frame_stderr(session, grace_seconds=1.0))
    )


@dataclass(frozen=True)
class HostControllerConfig:
    p_root: Path
    r_root: Path
    export_root: Path
    p_commit: str
    p_tree: str
    r_commit: str
    r_tree: str
    source_closure_sha256: str
    rs9_run: int
    challenge_nonce: str
    run_id_suffix: str
    container_image: str
    container_python: str
    expected_gpg_sha256: str
    expected_rpm_sha256: str
    release_date: str
    zip_transport: str = "actions"
    pass_online_github_token: bool = True
    timeout_seconds: float = 7500.0
    require_native_signing: bool = True
    require_isolated_python_flags: bool = True
    require_unimported_leaves: bool = True

@dataclass(frozen=True)
class HostControllerHooks:
    git_runner: Callable[..., tuple[int, bytes, bytes]] | None = None
    docker_cmd_runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]] | None = None
    worker_spawner: Callable[[tuple[str, ...], Mapping[str, str]], Any] | None = None
    frame_emitter: Callable[[], bytearray] | None = None

def build_docker_run_argv(config: HostControllerConfig, network_name: str, container_name: str) -> tuple[str, ...]:
    if not _IMAGE_DIGEST_RE.fullmatch(config.container_image):
        raise HostControllerError("CONTAINER_IMAGE_PIN", "Container image must be an immutable repository digest or local content ID")
    if not config.container_python.startswith("/") or "\x00" in config.container_python:
        raise HostControllerError("CONTAINER_PYTHON_PATH", "Container Python must be an absolute path")
    p_dir, r_dir = physical_dir(config.p_root, "P source root"), physical_dir(config.r_root, "R source root")
    exp_dir = physical_dir(config.export_root, "export root")
    uid, gid = os.getuid(), os.getgid()
    env_args = ("-e", "GH_TOKEN") if config.pass_online_github_token else ()
    worker_flags = ("--no-online-token",) if not config.pass_online_github_token else ()
    argv = (
        DOCKER_BINARY, "run", "--rm", "-i", "--pull", "never", "--name", container_name, "--network", network_name,
        "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--mount", f"type=bind,src={p_dir},dst=/work/p,readonly",
        "--mount", f"type=bind,src={r_dir},dst=/work/r,readonly",
        "--mount", f"type=bind,src={exp_dir},dst=/work/export",
        "--tmpfs", f"/work/workspace:rw,exec,nosuid,nodev,mode=0700,uid={uid},gid={gid}",
        *env_args, config.container_image,
        config.container_python, "-I", "-B", "/work/p/tools/verification/current_import_routing.py", "--current-signer-worker",
        "--p-root", "/work/p", "--r-root", "/work/r", "--workspace-root", "/work/workspace", "--export-root", "/work/export",
        "--p-commit", config.p_commit, "--p-tree", config.p_tree, "--r-commit", config.r_commit, "--r-tree", config.r_tree,
        "--source-closure-sha256", config.source_closure_sha256, "--rs9-run", str(config.rs9_run),
        "--challenge-nonce", config.challenge_nonce, "--expected-gpg-sha256", config.expected_gpg_sha256,
        "--expected-rpm-sha256", config.expected_rpm_sha256, "--release-date", config.release_date,
        "--zip-transport", config.zip_transport, *worker_flags,
    )
    validate_docker_run_argv(argv)
    return argv


def validate_docker_run_argv(argv: Sequence[str]) -> None:
    if tuple(argv[:4]) != (DOCKER_BINARY, "run", "--rm", "-i"):
        raise HostControllerError("DOCKER_RUN_PREFIX", "Docker run must start with /usr/bin/docker run --rm -i")
    for idx, token in enumerate(argv):
        if not isinstance(token, str) or not token or "\x00" in token:
            raise HostControllerError("DOCKER_RUN_TOKEN", "Invalid token in docker run argv")
        if token in _FORBIDDEN_DOCKER_FLAGS or token.startswith("-v"):
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_FLAG", f"Forbidden docker run flag: {token}")
        if token in {"--network", "--net"} and idx + 1 < len(argv) and argv[idx + 1] == "host":
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_FLAG", "Host network mode is forbidden")
        upper = token.upper()
        if any(bad in upper for bad in _FORBIDDEN_UPPER_SUBSTRINGS):
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_CONTENT", "Forbidden capability, socket, or secret in argv")
        if "TOKEN" in upper and token not in {"GH_TOKEN", "--no-online-token"}:
            raise HostControllerError("DOCKER_RUN_FORBIDDEN_CONTENT", "Unexpected token argument in docker run argv")
    if (
        "--user" not in argv or not _UID_GID_RE.fullmatch(argv[argv.index("--user") + 1])
        or "--cap-drop" not in argv or argv[argv.index("--cap-drop") + 1] != "ALL"
        or "--security-opt" not in argv or argv[argv.index("--security-opt") + 1] != "no-new-privileges"
        or not any(t.endswith(",dst=/work/p,readonly") for t in argv)
        or not any(t.endswith(",dst=/work/r,readonly") for t in argv)
        or not any(t.startswith("/work/workspace:") and "mode=0700,uid=" in t for t in argv)
    ):
        raise HostControllerError("DOCKER_RUN_HARDENING", "Missing user, mount readonly, tmpfs uid, or capability hardening")


def build_default_bridge_run_argv(config: HostControllerConfig, container_name: str, owner_label: str) -> tuple[str, ...]:
    """Production worker argv on the built-in default bridge with the run/nonce-bound owner label.

    The generic custom-network builder is reused unchanged; only the fixed label pair is inserted.
    """
    if type(owner_label) is not str or not _HEX64_RE.fullmatch(owner_label):
        raise HostControllerError("DEFAULT_BRIDGE_ARGV", "Default-bridge owner label invalid")
    base = build_docker_run_argv(config, _DEFAULT_BRIDGE_NETWORK, container_name)
    index = base.index("--network")
    argv = base[:index + 2] + ("--label", f"{_DEFAULT_BRIDGE_OWNER_LABEL_KEY}={owner_label}") + base[index + 2:]
    validate_docker_run_argv(argv)
    _require_default_bridge_argv(argv, container_name, owner_label)
    return argv


def _require_default_bridge_argv(argv: Sequence[str], container_name: str, owner_label: str) -> None:
    tokens = tuple(argv)
    try:
        # Docker options end before the image, which precedes "<python> -I".
        options = tokens[:tokens.index("-I") - 2] + ("",)
    except ValueError:
        raise HostControllerError("DEFAULT_BRIDGE_ARGV", "Default-bridge argv shape invalid") from None
    network_flags = [i for i, t in enumerate(options) if t in {"--network", "--net"} or t.startswith(("--network=", "--net="))]
    label_flags = [i for i, t in enumerate(options) if t in {"--label", "-l", "--label-file"} or t.startswith(("--label=", "--label-file="))]
    name_flags = [i for i, t in enumerate(options) if t == "--name" or t.startswith("--name=")]
    env_flags = [i for i, t in enumerate(options) if t in {"-e", "--env", "--env-file"} or t.startswith(("--env=", "--env-file=", "-e"))]
    if (
        len(options) < 5
        or len(network_flags) != 1 or options[network_flags[0]] != "--network"
        or options[network_flags[0] + 1] != _DEFAULT_BRIDGE_NETWORK
        or len(label_flags) != 1 or options[label_flags[0]] != "--label"
        or options[label_flags[0] + 1] != f"{_DEFAULT_BRIDGE_OWNER_LABEL_KEY}={owner_label}"
        or len(name_flags) != 1 or options[name_flags[0] + 1] != container_name
        or any(options[i] != "-e" or options[i + 1] != "GH_TOKEN" for i in env_flags)
        or any(marker in token.upper() for token in tokens for marker in _SIGNING_SECRET_ENV_MARKERS)
    ):
        raise HostControllerError("DEFAULT_BRIDGE_ARGV", "Default-bridge argv selection invalid")


def _require_default_worker_env(env: Mapping[str, str]) -> None:
    # Host env may hold signing secrets for the later frame emitter; the worker env never does.
    if any(type(key) is not str or any(marker in key.upper() for marker in _SIGNING_SECRET_ENV_MARKERS) for key in env):
        raise HostControllerError("DEFAULT_BRIDGE_WORKER_ENV", "Signing secret name in worker environment")


def _default_docker_runner(argv: tuple[str, ...], timeout: float) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(
        argv, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr

def _default_worker_spawner(argv: tuple[str, ...], env: Mapping[str, str]) -> Any:
    return subprocess.Popen(
        argv, env=dict(env), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
    )

def _availability_identity(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)

def _release_availability_dir(tmp_dir: str, expected_identity: tuple) -> bool:
    """Remove only the known nonsecret availability leaf and its original empty directory."""
    import stat
    fd = None
    try:
        fd = os.open(tmp_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if _availability_identity(os.fstat(fd)) != expected_identity:
            raise ValueError("AVAILABILITY_DIRECTORY_CHANGED")
        names = set(os.listdir(fd))
        if not names <= {"availability.json"}:
            raise ValueError("AVAILABILITY_UNKNOWN_ENTRY")
        if names:
            info = os.stat("availability.json", dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or info.st_size > 65536):
                raise ValueError("AVAILABILITY_ENTRY_CHANGED")
            os.unlink("availability.json", dir_fd=fd)
        if os.listdir(fd) or _availability_identity(os.lstat(tmp_dir)) != expected_identity:
            raise ValueError("AVAILABILITY_DIRECTORY_CHANGED")
        os.rmdir(tmp_dir)
    except BaseException as error:
        if not any(row["path"] == tmp_dir for row in _RETAINED_FRAME_AVAILABILITY_DIRS):
            _RETAINED_FRAME_AVAILABILITY_DIRS.append({"path": tmp_dir, "identity": expected_identity})
        if not isinstance(error, Exception):
            raise
        return False
    finally:
        if fd is not None:
            os.close(fd)
    return True

def _frame_custody_retained() -> bool:
    module = sys.modules.get("secret_frame_transport")
    return bool(_RETAINED_FRAME_AVAILABILITY_DIRS) or bool(
        module is not None and module.retained_custody_available()
    )

def _default_frame_emitter(p_root: Path, verified_leaves: Mapping[str, str]) -> bytearray:
    # Deferred until host source authentication and the detached-worker acknowledgement.
    from secret_frame_transport import FrameTransportError, capture_frame, retained_custody_available
    probe_script = p_root / "tools/verification/b3/probe_current_signer_c6_gpg.py"
    for rel in REQUIRED_B3_LEAVES:
        expected = verified_leaves.get(rel)
        if expected is None or sha256_hex(held_regular_bytes(p_root / rel)) != expected:
            raise HostControllerError("FRAME_SOURCE_CHANGED", "Authenticated producer source changed")
    probe_sha = verified_leaves["tools/verification/b3/probe_current_signer_c6_gpg.py"]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
    for key in ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "HOME", "USER", "LOGNAME"):
        if key in os.environ:
            env[key] = os.environ[key]
    tmp_dir = tempfile.mkdtemp(prefix="tf-frame-avail-")
    os.chmod(tmp_dir, 0o700)
    identity = _availability_identity(os.lstat(tmp_dir))
    out_buf, clear, removed = bytearray(), True, False
    try:
        avail_path = Path(tmp_dir) / "availability.json"
        clear = False
        try:
            out_buf = capture_frame(
                (sys.executable, "-I", "-B", str(probe_script), "--emit-stdin-frame",
                 "--expected-probe-sha256", probe_sha, "--availability-out", str(avail_path)),
                str(p_root), env, timeout=60.0, max_stdout=MAX_FRAME_SECRET_BYTES * 2 + 16,
            )
        except BaseException as error:
            clear = not retained_custody_available()
            if isinstance(error, FrameTransportError):
                raise HostControllerError(error.code, "Existing frame producer capture failed") from None
            raise
        clear = True
        if parse_strict_json(held_regular_bytes(avail_path, max_bytes=65536), "AVAILABILITY_SCHEMA").get("status") != "pass":
            raise HostControllerError("FRAME_EMITTER_FAILED", "Existing frame producer availability refused")
        if not _release_availability_dir(tmp_dir, identity):
            raise HostControllerError("FRAME_AVAILABILITY_RETAINED", "Availability cleanup uncertain")
        removed = True
    except BaseException:
        zero_bytes(out_buf)
        if not removed and not any(row["path"] == tmp_dir for row in _RETAINED_FRAME_AVAILABILITY_DIRS):
            if clear:
                _release_availability_dir(tmp_dir, identity)
            else:
                _RETAINED_FRAME_AVAILABILITY_DIRS.append({"path": tmp_dir, "identity": identity})
        raise
    return out_buf

def _verify_exported_artifacts(
    export_root: Path, expected_binding: Mapping[str, object], *, expected_worker_pid: int, require_native_signing: bool = True,
) -> dict[str, Any]:
    import public_repository_files as pub_files_mod
    if set(os.listdir(export_root)) != {"public-repository", "outer-controller-receipt.json"}:
        raise HostControllerError("EXPORT_ROOT_POLLUTED", "Export root must contain only public-repository and receipt")
    receipt = parse_strict_json(held_regular_bytes(export_root / "outer-controller-receipt.json"), "RECEIPT_SCHEMA")
    expected_native, expected_status = (True, "observed") if require_native_signing else (False, "test-only")
    if (
        receipt.get("schema") != WORKER_RECEIPT_SCHEMA or receipt.get("status") != "pass"
        or receipt.get("source_binding") != dict(expected_binding)
        or type(receipt.get("worker_pid")) is not int or receipt["worker_pid"] <= 0
        or receipt.get("worker_pid") != expected_worker_pid
        or receipt.get("lease_owner_pid") != receipt.get("worker_pid") or receipt.get("same_pid_verified") is not True
        or receipt.get("native_signing_execution") is not expected_native or receipt.get("signing_status") != expected_status
        or receipt.get("c6_agent_and_private_work_cleanup_confirmed") is not True
        or receipt.get("lease_closed_confirmed") is not True or receipt.get("stage_snapshot_joined_to_fresh_admission") is not True
        or receipt.get("public_verification_status") != "pass" or receipt.get("public_native_crypto_verified") is not expected_native
        or receipt.get("custody_retained") is not False or receipt.get("publication_authority") is not False
        or receipt.get("native_client_qualification") is not False
    ):
        raise HostControllerError("WORKER_RECEIPT_INVALID", "Worker receipt failed required invariants")
    snap = pub_files_mod.snapshot(export_root / "public-repository")
    if pub_files_mod.inventory(snap.members) != receipt.get("exported_files"):
        raise HostControllerError("EXPORT_INVENTORY_MISMATCH", "Exported public repository does not match worker receipt")
    return receipt

def _authenticate_host_sources(config: HostControllerConfig, hooks: HostControllerHooks) -> tuple[Path, Path, Path, dict[str, str]]:
    if not _RUN_SUFFIX_RE.fullmatch(config.run_id_suffix):
        raise HostControllerError("RUN_SUFFIX_INVALID", "run_id_suffix must be 1..20 ASCII digits")
    p_root, r_root = physical_dir(config.p_root, "P source root"), physical_dir(config.r_root, "R source root")
    exp_root = physical_dir(config.export_root, "export root")
    if os.listdir(exp_root):
        raise HostControllerError("EXPORT_ROOT_NOT_EMPTY", "Export root must be empty before run")
    git_env = apply_process_git_scope(p_root, r_root)
    verify_clean_git_checkout(p_root, config.p_commit, config.p_tree, git_env=git_env, git_runner=hooks.git_runner)
    verify_clean_git_checkout(r_root, config.r_commit, config.r_tree, git_env=git_env, git_runner=hooks.git_runner)
    authenticate_rs9_descriptor(p_root, expected_r_commit=config.r_commit, expected_r_tree=config.r_tree, expected_rs9_run=config.rs9_run)
    verified_leaves = authenticate_leaf_closure(p_root, expected_leaf_manifest_sha256=config.source_closure_sha256, require_unimported=config.require_unimported_leaves)
    configure_worker_sys_path(p_root, r_root, require_isolated_flags=config.require_isolated_python_flags)
    return p_root, r_root, exp_root, verified_leaves


def _run_gate_session(
    gate: Any, session: Any, gate_cmds: tuple[tuple[str, ...], tuple[str, ...]] | None,
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], emitter: Callable[[], bytearray],
    *, prepare_disconnect: Callable[[], tuple[tuple[str, ...], tuple[str, ...]]] | None = None,
) -> str:
    from signer_protocol_io import validate_frame_bytes

    if (gate_cmds is None) == (prepare_disconnect is None):
        raise HostControllerError("DEFAULT_BRIDGE_CUSTODY", "Exactly one gate command source is required")
    resolved: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    if gate_cmds is not None:
        disconnect_cmd, inspect_cmd = gate_cmds
        resolved.append((disconnect_cmd, inspect_cmd))

    def _disconnect() -> None:
        if prepare_disconnect is not None:
            # Invoked only by HostGate inside its disconnect step, after ready validated.
            if resolved:
                raise HostControllerError("DEFAULT_BRIDGE_CUSTODY", "Disconnect preparation reused")
            prepared_disconnect, prepared_inspect = prepare_disconnect()
            resolved.append((prepared_disconnect, prepared_inspect))
        if runner(resolved[0][0], 30.0)[0] != 0:
            raise HostControllerError("DOCKER_NETWORK_DISCONNECT", "Failed to disconnect worker network")

    def _inspect() -> bytes:
        if not resolved:
            raise HostControllerError("DEFAULT_BRIDGE_CUSTODY", "Readback without resolved worker custody")
        rc, out, _ = runner(resolved[0][1], 30.0)
        if rc != 0:
            raise HostControllerError("DOCKER_NETWORK_INSPECT", "Failed to inspect worker networks")
        return out

    def _exchange(challenge: bytes) -> bytes:
        session.write_stdin(challenge, close_after=False)
        ack = session.read_protocol_line()
        session.require_no_extra_stdout()
        return ack

    def _emit_frame() -> None:
        frame_buf = emitter()
        try:
            validate_frame_bytes(frame_buf, HostControllerError)
            session.write_stdin(frame_buf, close_after=True)
        finally:
            zero_bytes(frame_buf)

    gate.release_frame(
        ready=session.read_protocol_line, disconnect=_disconnect, inspect_networks=_inspect,
        exchange_challenge=_exchange, emit_existing_frame_and_eof=_emit_frame,
    )
    return str(gate.state)


def _teardown_host_session(
    session: Any | None, resources: tuple[str, str], remove_net_cmd: tuple[str, ...],
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], *, succeeded: bool,
) -> tuple[dict[str, Any], BaseException | None]:
    network_name, container_name = resources
    interrupt = None
    session_uncertain = False
    if session is not None:
        try:
            session.terminate_and_close()
        except BaseException as error:
            session_uncertain = True
            if not isinstance(error, Exception):
                interrupt = error
        session_uncertain = session_uncertain or session.cleanup_uncertain
    force_remove_attempted = not succeeded or session_uncertain
    container_force_removed = network_removed = container_absent = False
    if force_remove_attempted:
        try:
            container_force_removed = runner((DOCKER_BINARY, "rm", "-f", container_name), 30.0)[0] == 0
        except BaseException as error:
            if not isinstance(error, Exception) and interrupt is None:
                interrupt = error
    try:
        rc, out, _err = runner(
            (DOCKER_BINARY, "container", "ls", "--all", "--quiet", "--filter", f"name=^/{container_name}$"), 30.0)
        container_absent = rc == 0 and not out.strip()
    except BaseException as error:
        if not isinstance(error, Exception) and interrupt is None:
            interrupt = error
    try:
        network_removed = runner(remove_net_cmd, 30.0)[0] == 0
    except BaseException as error:
        if not isinstance(error, Exception) and interrupt is None:
            interrupt = error
    return {
        "network": network_name, "container": container_name,
        "container_force_remove_attempted": force_remove_attempted,
        "container_force_removed": container_force_removed, "container_absence_confirmed": container_absent,
        "network_removed": network_removed, "session_cleanup_uncertain": bool(session_uncertain),
        "teardown_interrupted": interrupt is not None, "teardown_is_not_c6_cleanup": True,
    }, interrupt


def _docker_output(
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], argv: tuple[str, ...], code: str,
) -> bytes:
    # Docker stdout/stderr never enter error text; only the fixed code does.
    rc, out, _err = runner(argv, 30.0)
    if rc != 0 or type(out) is not bytes:
        raise HostControllerError(code, "Docker query refused")
    return out


def _default_bridge_preflight(
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], container_name: str,
) -> str:
    """Capture the built-in bridge ID; refuse peers and any same-name container before spawn."""
    import signing_network_gate as network_gate

    observation = network_gate.require_default_bridge_identity(
        _docker_output(runner, network_gate.default_bridge_inspect_command(), "DOCKER_BRIDGE_INSPECT"))
    network_gate.require_no_bridge_peers(observation)
    if network_gate.parse_container_id_listing(_docker_output(
            runner, network_gate.container_name_listing_command(container_name), "DOCKER_CONTAINER_LIST")):
        raise network_gate.GateError("CONTAINER_NAME_COLLISION")
    return observation.network_id


def _prepare_default_bridge_disconnect(
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], container_name: str, owner_label: str,
    bridge_id: str, custody: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve and pin the owned immutable ID, then prove sole bridge ownership before detach."""
    import signing_network_gate as network_gate

    owned_id = network_gate.require_single_owned_id(network_gate.parse_container_id_listing(_docker_output(
        runner, network_gate.owned_container_listing_command(container_name, owner_label), "DOCKER_CONTAINER_LIST")))
    if custody.get("owned_id") not in (None, owned_id):
        raise HostControllerError("DEFAULT_BRIDGE_CUSTODY", "Owned worker identity changed")
    custody["owned_id"] = owned_id
    observation = network_gate.require_default_bridge_identity(
        _docker_output(runner, network_gate.default_bridge_inspect_command(), "DOCKER_BRIDGE_INSPECT"),
        expected_id=bridge_id)
    network_gate.require_sole_owned_bridge_peer(observation, owned_id)
    network_gate.require_worker_on_default_bridge(
        _docker_output(runner, network_gate.worker_networks_command(owned_id), "DOCKER_WORKER_INSPECT"), bridge_id)
    return network_gate.default_bridge_gate_commands(bridge_id, owned_id)


def _teardown_default_bridge_session(
    session: Any | None, container_name: str, owner_label: str, bridge_id: str | None,
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], *,
    pinned_owned_id: str | None, spawn_attempted: bool, spawn_uncertain: bool,
) -> tuple[dict[str, Any], BaseException | None]:
    """Close only our session; delete only a resolved owned immutable ID; never touch the bridge."""
    import signing_network_gate as network_gate

    interrupt: BaseException | None = None

    def _keep(error: BaseException) -> None:
        nonlocal interrupt
        if not isinstance(error, Exception) and interrupt is None:
            interrupt = error

    session_uncertain = False
    if session is not None:
        try:
            session.terminate_and_close()
        except BaseException as error:
            session_uncertain = True
            _keep(error)
        try:
            session_uncertain = session_uncertain or bool(session.cleanup_uncertain)
        except BaseException as error:
            session_uncertain = True
            _keep(error)

    owner_cmd = network_gate.owned_container_listing_command(container_name, owner_label)
    owner_custody, owned_id = "unavailable", None
    try:
        ids = network_gate.parse_container_id_listing(_docker_output(runner, owner_cmd, "DOCKER_CONTAINER_LIST"))
        if not ids:
            owner_custody = "absent"
        elif len(ids) != 1:
            owner_custody = "ambiguous"
        elif pinned_owned_id is not None and ids[0] != pinned_owned_id:
            owner_custody = "mismatch"
        else:
            owner_custody, owned_id = "resolved", network_gate.require_container_id(ids[0])
    except network_gate.GateError:
        owner_custody = "malformed"
    except BaseException as error:
        _keep(error)

    remove_attempted = removed = False
    if owned_id is not None:
        remove_attempted = True
        try:
            removed = runner(network_gate.owned_container_remove_command(owned_id), 30.0)[0] == 0
        except BaseException as error:
            _keep(error)

    owned_absent = name_absent = False
    if owner_custody in {"resolved", "absent"}:
        try:
            owned_absent = not network_gate.parse_container_id_listing(
                _docker_output(runner, owner_cmd, "DOCKER_CONTAINER_LIST"))
        except BaseException as error:
            _keep(error)
    try:
        name_absent = not network_gate.parse_container_id_listing(_docker_output(
            runner, network_gate.container_name_listing_command(container_name), "DOCKER_CONTAINER_LIST"))
    except BaseException as error:
        _keep(error)

    bridge_preserved = owned_endpoint_absent = False
    unexpected_bridge_peer = True
    if bridge_id is not None:
        try:
            observation = network_gate.require_default_bridge_identity(
                _docker_output(runner, network_gate.default_bridge_inspect_command(), "DOCKER_BRIDGE_INSPECT"),
                expected_id=bridge_id)
            bridge_preserved = True
            owned_endpoint_absent = not ({owned_id, pinned_owned_id} - {None}) & observation.peer_ids
            unexpected_bridge_peer = bool(observation.peer_ids - ({owned_id, pinned_owned_id} - {None}))
        except BaseException as error:
            _keep(error)

    return {
        "network": _DEFAULT_BRIDGE_NETWORK, "network_kind": "builtin-default-bridge", "container": container_name,
        "owner_custody": owner_custody, "removal_by_immutable_id_only": True,
        "container_force_remove_attempted": remove_attempted, "container_force_removed": removed,
        "owned_container_absence_confirmed": owned_absent, "container_name_absent_confirmed": name_absent,
        "container_absence_confirmed": owned_absent and name_absent,
        "network_removed": False, "builtin_bridge_preserved": bridge_preserved,
        "unexpected_bridge_peer_observed": unexpected_bridge_peer,
        "builtin_bridge_configuration_commands_issued": False,
        "owned_worker_endpoint_mutation_attempted": bool(spawn_attempted),
        "owned_bridge_endpoint_absent_confirmed": owned_endpoint_absent,
        "spawn_outcome_uncertain": bool(spawn_uncertain), "session_cleanup_uncertain": bool(session_uncertain),
        "teardown_interrupted": interrupt is not None, "teardown_is_not_c6_cleanup": True,
    }, interrupt


def _default_bridge_teardown_uncertain(teardown: Mapping[str, Any], interrupt: BaseException | None) -> bool:
    return (
        interrupt is not None
        or teardown.get("owner_custody") not in {"resolved", "absent"}
        or any(teardown.get(key) is not True for key in (
            "container_absence_confirmed", "builtin_bridge_preserved", "owned_bridge_endpoint_absent_confirmed"))
        or any(teardown.get(key) is not False for key in (
            "session_cleanup_uncertain", "spawn_outcome_uncertain", "frame_capture_custody_retained",
            "unexpected_bridge_peer_observed"))
        or (teardown.get("container_force_remove_attempted") is not False
            and teardown.get("container_force_removed") is not True)
    )


def execute_host_controller(config: HostControllerConfig, *, hooks: HostControllerHooks | None = None) -> dict[str, Any]:
    hk = hooks or HostControllerHooks()
    p_root, r_root, exp_root, verified_leaves = _authenticate_host_sources(config, hk)
    from signer_protocol_io import ForegroundContainerSession
    from signing_network_gate import HostGate, SourceBinding, default_bridge_owner_label

    binding = SourceBinding(
        config.p_commit, config.p_tree, config.r_commit, config.r_tree, config.source_closure_sha256, config.rs9_run,
    )
    gate = HostGate(binding, config.challenge_nonce)
    # Production uses the fixed built-in default bridge; the custom-network helpers stay for the historical probe.
    container_name = f"tf-current-signer-{config.run_id_suffix}-2"
    owner_label = default_bridge_owner_label(config.run_id_suffix, config.challenge_nonce)
    docker_run_argv = build_default_bridge_run_argv(config, container_name, owner_label)
    runner = hk.docker_cmd_runner or _default_docker_runner
    spawner = hk.worker_spawner or _default_worker_spawner
    emitter = hk.frame_emitter or (lambda: _default_frame_emitter(p_root, verified_leaves))

    bridge_id = _default_bridge_preflight(runner, container_name)
    custody: dict[str, Any] = {"owned_id": None}
    session: ForegroundContainerSession | None = None
    caught_error: BaseException | None = None
    run_succeeded = False
    spawn_attempted = spawn_uncertain = False
    try:
        spawn_env = dict(scoped_git_env(p_root, r_root))
        if config.pass_online_github_token and "GH_TOKEN" in os.environ:
            spawn_env["GH_TOKEN"] = os.environ["GH_TOKEN"]
        _require_default_worker_env(spawn_env)
        spawn_attempted = spawn_uncertain = True
        session = ForegroundContainerSession(
            spawner(docker_run_argv, spawn_env), time.monotonic() + config.timeout_seconds, HostControllerError,
        )
        spawn_uncertain = False
        gate_state = _run_gate_session(
            gate, session, None, runner, emitter,
            prepare_disconnect=lambda: _prepare_default_bridge_disconnect(
                runner, container_name, owner_label, bridge_id, custody),
        )
        exit_code = session.wait_for_exit()
        session.require_stdout_clean_eof()
        if exit_code != 0:
            raise HostControllerError("WORKER_NONZERO_EXIT", f"Worker container exited with status {exit_code}")
        worker_receipt = _verify_exported_artifacts(
            exp_root, binding.record(), expected_worker_pid=gate.worker_pid, require_native_signing=config.require_native_signing,
        )
        run_succeeded = True
    except BaseException as error:
        caught_error = error
        try:
            error.handshake_observation = _build_handshake_observation(gate, session, error)  # type: ignore[attr-defined]
        except Exception:
            error.handshake_observation = None  # type: ignore[attr-defined]
        except BaseException as interruption:
            caught_error = interruption
            raise
        try:
            error.post_frame_diagnostic = _build_post_frame_diagnostic(gate, session, error)  # type: ignore[attr-defined]
        except Exception:
            pass
        except BaseException as interruption:
            caught_error = interruption
            raise
        raise
    finally:
        teardown, teardown_interrupt = _teardown_default_bridge_session(
            session, container_name, owner_label, bridge_id, runner,
            pinned_owned_id=custody["owned_id"], spawn_attempted=spawn_attempted, spawn_uncertain=spawn_uncertain,
        )
        teardown["frame_capture_custody_retained"] = _frame_custody_retained()
        uncertain = _default_bridge_teardown_uncertain(teardown, teardown_interrupt)
        if caught_error is not None:
            caught_error.host_teardown = teardown
            if teardown_interrupt is not None:
                caught_error.teardown_interrupt = teardown_interrupt
        if uncertain:
            _RETAINED_HOST_SESSIONS.append({
                "container": container_name, "session": session, "teardown": teardown, "error": caught_error,
            })
            if caught_error is None:
                if teardown_interrupt is not None:
                    teardown_interrupt.host_teardown = teardown
                    raise teardown_interrupt
                error = HostControllerError("HOST_TEARDOWN_UNCONFIRMED", "Owned host teardown unconfirmed")
                error.host_teardown = teardown
                _RETAINED_HOST_SESSIONS[-1]["error"] = error
                raise error
    return {
        "schema": HOST_SUMMARY_SCHEMA, "status": "pass", "gate_state": gate_state, "worker_receipt": worker_receipt,
        "host_container_and_network_teardown": teardown,
        "c6_agent_and_private_work_cleanup_confirmed": worker_receipt["c6_agent_and_private_work_cleanup_confirmed"],
        "publication_authority": False, "native_client_qualification": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Theme Forge full-signer host controller")
    for flag in ("--p-root", "--r-root", "--export-root"):
        parser.add_argument(flag, type=Path, required=True)
    for flag in (
        "--p-commit", "--p-tree", "--r-commit", "--r-tree", "--source-closure-sha256",
        "--challenge-nonce", "--run-id-suffix", "--container-image", "--container-python",
        "--expected-gpg-sha256", "--expected-rpm-sha256", "--release-date",
    ):
        parser.add_argument(flag, required=True)
    parser.add_argument("--rs9-run", type=int, required=True)
    parser.add_argument("--zip-transport", choices=("actions", "public-release-relay"), default="actions")
    parser.add_argument("--no-online-token", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=7500.0)
    args = parser.parse_args(argv)
    cfg = HostControllerConfig(
        p_root=args.p_root, r_root=args.r_root, export_root=args.export_root,
        p_commit=args.p_commit, p_tree=args.p_tree, r_commit=args.r_commit, r_tree=args.r_tree,
        source_closure_sha256=args.source_closure_sha256, rs9_run=args.rs9_run,
        challenge_nonce=args.challenge_nonce, run_id_suffix=args.run_id_suffix,
        container_image=args.container_image, container_python=args.container_python,
        expected_gpg_sha256=args.expected_gpg_sha256, expected_rpm_sha256=args.expected_rpm_sha256,
        release_date=args.release_date, zip_transport=args.zip_transport,
        pass_online_github_token=not args.no_online_token, timeout_seconds=args.timeout_seconds,
    )
    try:
        execute_host_controller(cfg)
    except Exception as error:
        raw_code = getattr(error, "code", None) or (
            error.args[0] if error.args and isinstance(error.args[0], str) else None
        )
        code = raw_code if type(raw_code) is str and raw_code in _ALLOWED_HOST_ERROR_CODES else "HOST_EXECUTION_FAILED"
        payload: dict[str, Any] = {
            "schema": HOST_SUMMARY_SCHEMA, "status": "failed-closed", "error_code": code,
            "custody_retained": bool(_RETAINED_HOST_SESSIONS) or _frame_custody_retained(),
            "host_container_and_network_teardown": getattr(error, "host_teardown", None),
            "publication_authority": False, "native_client_qualification": False,
        }
        observation = sanitize_handshake_observation(getattr(error, "handshake_observation", None))
        if observation is not None:
            payload["handshake_observation"] = observation
        post_frame = sanitize_post_frame_diagnostic(getattr(error, "post_frame_diagnostic", None))
        if (
            post_frame is not None and code == "WORKER_NONZERO_EXIT"
            and observation is not None and observation["gate_phase"] == "POST_FRAME"
        ):
            payload["post_frame_diagnostic"] = post_frame
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
