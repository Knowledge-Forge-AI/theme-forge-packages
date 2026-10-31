"""Small private types and fixed provenance for the lifecycle-only bridge."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


SCHEMA = "tf.current-signer-native-b3-fixture-preparation.v1"
RECEIPT_SCHEMA = "tf.current-signer-native-b3-lifecycle-receipt.v1"
FACTS_SCHEMA = "tf.current-signer-native-b3-tool-facts.v1"
STAGE1_AUTH_SCHEMA = "tf.current-signer-native-b3-stage1-authentication.v1"
STAGE2_METADATA_SCHEMA = "tf.current-signer-native-b3-stage2-metadata.v1"
CURRENT_TOOLCHAIN_CATALOG_SCHEMA = "tf.current-signer-native-b3-toolchain-catalog.v1"
TARGET_GNUPG_VERSION = "2.4.9"
TARGET_AGENT_MODE = "--supervised"
TARGET_RPM_VERSION = "6.0.2"
NATIVE_TOOLS = {
    "gpgconf": "/usr/bin/gpgconf",
    "gpg-agent": "/usr/bin/gpg-agent",
    "gpg": "/usr/bin/gpg",
}
STAGE2_PROVISIONED_TOOLS = {
    "gpgconf": "/usr/bin/gpgconf",
    "gpg-agent": "/usr/bin/gpg-agent",
    "gpg": "/usr/bin/gpg",
    "rpm": "/usr/bin/rpm",
    "rpmsign": "/usr/bin/rpmsign",
}
_PACKET_ROOT = Path(__file__).resolve(strict=True).parent
_PACKET_INPUTS = _PACKET_ROOT / "inputs"
IMAGE_CATALOG_PATH = _PACKET_INPUTS / "DIST1-VALIDATION-WORKFLOW-CONTRACT.json"
IMAGE_CATALOG_SHA256 = "87852f8671c061c68ae83e56cd6d30e8dbcda559d83b435aa45c3af2ec8c7fe2"
CURRENT_TOOLCHAIN_CATALOG_PATH = _PACKET_INPUTS / "CURRENT-B3-TOOLCHAIN-CATALOG.json"
CURRENT_TOOLCHAIN_CATALOG_SHA256 = "23c78119024c0f8a1072768eb7c318ec4ea23b52dfa69070cd7de4d6049ce882"
CANONICAL_SUBSET_PATH = _PACKET_INPUTS / "CANONICAL-C6-SUBSET.json"
CANONICAL_SUBSET_SHA256 = "60b0c748b4fc618bde2d52cd759180871636c1597074188434ecb879c93c3801"
IMAGE_CATALOG_SELECTORS = {
    "rpm": "jobs.validate-linux.matrix.x86_64.fedora_container",
    "pacman": "jobs.validate-linux.matrix.x86_64.arch_container",
}
CURRENT_IMAGE_CATALOG_SELECTORS = {
    "rpm": "base_images.rpm",
    "pacman": "base_images.pacman",
}
REVIEWED_C6_SOURCE_PATH = _PACKET_INPUTS / "owned_gpg_agent.py"
REVIEWED_C6_SOURCE_SHA256 = "305f613aa989f807d5155c082e568d8e0c79ba63aa4ab8a25252433250c5c2cf"
REVIEWED_C6_TESTS_PATH = _PACKET_INPUTS / "test_owned_gpg_agent.py"
REVIEWED_C6_TESTS_SHA256 = "56e9ffa9fcde85dfe3b0d0802e9994b36985515e5c1b2736315cc639dedaf304"
MAX_JSON_BYTES = 1_048_576
MAX_SOURCE_BYTES = 2_000_000


class FixtureError(RuntimeError):
    """Safe boundary error; callers must not print arbitrary exception text."""

    def __init__(
        self,
        code: str,
        *,
        retained_custody: bool = False,
        retained_root: Path | None = None,
        sanitized_detail: Mapping[str, object] | None = None,
    ):
        self.code = code
        self.retained_custody = retained_custody
        self.retained_root = retained_root
        self.sanitized_detail = dict(sanitized_detail) if sanitized_detail is not None else None
        super().__init__(code)


@dataclass(frozen=True)
class FixtureSpec:
    canonical_commit: str
    canonical_source_bytes: int
    canonical_source_sha256: str
    option_table_lines: str
    canonical_disposition_path: Path
    owned_agent_source: Path
    owned_agent_source_sha256: str
    target_gnupg_version: str
    target_agent_mode: str
    target_rpm_version: str
    images: Mapping[str, str]
    image_catalog_path: Path
    image_catalog_sha256: str


@dataclass(frozen=True)
class FsIdentity:
    dev: int
    ino: int
    uid: int
    mode: int
    kind: int


@dataclass
class WorkspaceBinding:
    parent: Path
    root: Path
    home: Path
    parent_fd: int
    root_fd: int
    home_fd: int
    parent_identity: FsIdentity
    root_identity: FsIdentity
    home_identity: FsIdentity
