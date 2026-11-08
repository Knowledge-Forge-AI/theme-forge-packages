"""Fail-closed plan adapter for protected signing of qualified objects.

The current RS9/P route supplies unsigned, byte-authenticated package objects.
This module validates those descriptors and emits a protected-workflow plan;
it never invokes GPG, RPM, Pacman, a container, or a build.  A later protected
workflow may consume the plan with the historical signer boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping, Sequence


SCHEMA = "tf.current-protected-signing-plan.v1"
PUBLIC_KEY_SHA256 = "6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95"
PRIMARY_FINGERPRINT = "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF"
SIGNING_SUBKEY_FINGERPRINT = "C021E00EE3D37C459B0E1CB3199F8028126E8A8C"
RPM_IMAGE = "registry.fedoraproject.org/fedora@sha256:c5e15bd1e07c25904d0c5b9865fb7ee4589f8ca234e635742b0c1195838f4bfd"
PACMAN_IMAGE = "docker.io/library/archlinux@sha256:eb8f6dcc89a38977c9735f10fcf6ae4afe496283e7008eb7a3420cdba31fbd04"
MAX_OBJECT_BYTES = 512 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 8 * 1024 * 1024
CURRENT_VERSIONS = {
    "theme-forge-stellar-burst": "0.7.0",
    "theme-forge-stellar-loom": "0.5.0",
    "theme-forge-solar-sail": "0.3.0",
    "theme-forge-nebular-fusion": "0.8.0",
}
CHANNEL_ARCHITECTURES = {
    "apt": frozenset({"amd64", "arm64"}),
    "rpm": frozenset({"x86_64", "aarch64", "noarch"}),
    "pacman": frozenset({"x86_64"}),
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FPR40 = re.compile(r"^[0-9A-F]{40}$")


class ProtectedSigningError(ValueError):
    """Stable failure for invalid input or an unavailable protected boundary."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class SignerBinding:
    public_key_sha256: str = PUBLIC_KEY_SHA256
    primary_fingerprint: str = PRIMARY_FINGERPRINT
    signing_subkey_fingerprint: str = SIGNING_SUBKEY_FINGERPRINT


@dataclass(frozen=True)
class UnsignedObject:
    channel: str
    product: str
    version: str
    architecture: str
    origin: str
    path: str | Path
    sha256: str
    size: int


@dataclass(frozen=True)
class SignedArtifact:
    channel: str
    product: str
    version: str
    architecture: str
    origin: str
    path: str | Path
    sha256: str
    size: int


@dataclass(frozen=True)
class RpmPreservationEvidence:
    unsigned_sha256: str
    signed_sha256: str
    unsigned_main_header_sha256: str
    signed_main_header_sha256: str
    unsigned_payload_sha256: str
    signed_payload_sha256: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_hash(value: str, label: str) -> None:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProtectedSigningError("HASH_FORMAT", f"{label} must be lowercase SHA-256")


def _require_fingerprint(value: str, label: str) -> None:
    if not isinstance(value, str) or not _FPR40.fullmatch(value):
        raise ProtectedSigningError("FINGERPRINT_FORMAT", f"{label} must be a full fingerprint")


def validate_signer_binding(binding: SignerBinding) -> None:
    """Require the committed public key and historical signing identities."""
    if binding.public_key_sha256 != PUBLIC_KEY_SHA256:
        raise ProtectedSigningError("PUBLIC_KEY_MISMATCH", "Committed public-key digest mismatch")
    if binding.primary_fingerprint != PRIMARY_FINGERPRINT:
        raise ProtectedSigningError("PRIMARY_KEY_MISMATCH", "Committed primary fingerprint mismatch")
    if binding.signing_subkey_fingerprint != SIGNING_SUBKEY_FINGERPRINT:
        raise ProtectedSigningError("SIGNING_KEY_MISMATCH", "Committed signing-subkey mismatch")
    _require_hash(binding.public_key_sha256, "public key digest")
    _require_fingerprint(binding.primary_fingerprint, "primary fingerprint")
    _require_fingerprint(binding.signing_subkey_fingerprint, "signing-subkey fingerprint")


def verify_committed_public_key(public_key_bytes: bytes, binding: SignerBinding = SignerBinding()) -> None:
    """Verify supplied public-key bytes without opening a key path or secret."""
    validate_signer_binding(binding)
    if not isinstance(public_key_bytes, bytes) or not public_key_bytes or len(public_key_bytes) > MAX_PUBLIC_KEY_BYTES:
        raise ProtectedSigningError("PUBLIC_KEY_LIMIT", "Public-key bytes are missing or oversized")
    if b"BEGIN PGP PRIVATE KEY BLOCK" in public_key_bytes:
        raise ProtectedSigningError("PRIVATE_KEY_REJECTED", "Private key material is forbidden")
    if _sha256(public_key_bytes) != binding.public_key_sha256:
        raise ProtectedSigningError("PUBLIC_KEY_DIGEST", "Supplied public-key bytes do not match the committed key")


def _path_parts(path: str | Path, label: str) -> tuple[Path, ...]:
    raw = os.fspath(path)
    if not raw or not os.path.isabs(raw) or "\x00" in raw:
        raise ProtectedSigningError("PATH_FORMAT", f"{label} must be an absolute path")
    if any(part in {".", ".."} for part in raw.split(os.sep)):
        raise ProtectedSigningError("PATH_TRAVERSAL", f"{label} contains traversal")
    candidate = Path(raw)
    return (candidate, *tuple(candidate.parents))


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def _read_stable(path: str | Path, expected_sha256: str, expected_size: int, label: str) -> bytes:
    """Read one held regular file without following a path or replacing it."""
    _require_hash(expected_sha256, f"{label} digest")
    if not isinstance(expected_size, int) or expected_size < 0 or expected_size > MAX_OBJECT_BYTES:
        raise ProtectedSigningError("SIZE_LIMIT", f"{label} size is outside the bound")
    candidate = _path_parts(path, label)[0]
    current = Path(candidate.anchor or "/")
    for part in candidate.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except OSError:
            raise ProtectedSigningError("PATH_MISSING", f"{label} is missing") from None
        if stat.S_ISLNK(info.st_mode):
            raise ProtectedSigningError("SYMLINK_REJECTED", f"{label} contains a symlink")
    try:
        fd = os.open(str(candidate), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ProtectedSigningError("PATH_IO", f"Unable to open {label}") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ProtectedSigningError("REGULAR_FILE_REQUIRED", f"{label} must be regular")
        if before.st_size != expected_size:
            raise ProtectedSigningError("SIZE_MISMATCH", f"{label} size changed")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_OBJECT_BYTES:
            block = os.read(fd, min(1024 * 1024, MAX_OBJECT_BYTES + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > MAX_OBJECT_BYTES:
                break
        data = b"".join(chunks)
        after = os.fstat(fd)
        if len(data) != expected_size or _identity(before) != _identity(after):
            raise ProtectedSigningError("FILE_CHANGED", f"{label} changed during read")
        if _sha256(data) != expected_sha256:
            raise ProtectedSigningError("HASH_MISMATCH", f"{label} digest mismatch")
        return data
    finally:
        os.close(fd)


def _validate_object(obj: UnsignedObject, expected_origin: str) -> None:
    if obj.channel not in CHANNEL_ARCHITECTURES:
        raise ProtectedSigningError("CHANNEL", f"Unsupported channel {obj.channel!r}")
    if obj.product not in CURRENT_VERSIONS or obj.version != CURRENT_VERSIONS[obj.product]:
        raise ProtectedSigningError("VERSION", f"Unsupported current product/version for {obj.product!r}")
    if obj.architecture not in CHANNEL_ARCHITECTURES[obj.channel]:
        raise ProtectedSigningError("ARCHITECTURE", f"Unsupported {obj.channel} architecture")
    if not isinstance(expected_origin, str) or not expected_origin or obj.origin != expected_origin:
        raise ProtectedSigningError("ORIGIN", "Unsigned object origin does not match the held origin")
    if not isinstance(obj.size, int) or obj.size < 1:
        raise ProtectedSigningError("SIZE", "Unsigned object size must be positive")
    _read_stable(obj.path, obj.sha256, obj.size, f"{obj.channel} object")


def validate_unsigned_objects(objects: Sequence[UnsignedObject], expected_origin: str) -> tuple[UnsignedObject, ...]:
    """Validate exact current product identity and held unsigned bytes."""
    if not objects:
        raise ProtectedSigningError("EMPTY_INPUT", "At least one qualified unsigned object is required")
    seen_identity: set[tuple[str, str, str]] = set()
    seen_paths: set[str] = set()
    checked: list[UnsignedObject] = []
    for obj in objects:
        if not isinstance(obj, UnsignedObject):
            raise ProtectedSigningError("OBJECT_TYPE", "Unsigned object descriptor required")
        _validate_object(obj, expected_origin)
        identity = (obj.channel, obj.product, obj.architecture)
        path_text = os.fspath(obj.path)
        if identity in seen_identity:
            raise ProtectedSigningError("DUPLICATE_OBJECT", "Duplicate channel/product/architecture")
        if path_text in seen_paths:
            raise ProtectedSigningError("DUPLICATE_PATH", "One held file cannot represent two objects")
        seen_identity.add(identity)
        seen_paths.add(path_text)
        checked.append(obj)
    return tuple(checked)


def _object_record(obj: UnsignedObject) -> dict[str, object]:
    return {
        "channel": obj.channel,
        "product": obj.product,
        "version": obj.version,
        "architecture": obj.architecture,
        "origin": obj.origin,
        "path": os.fspath(obj.path),
        "sha256": obj.sha256,
        "size": obj.size,
    }


class ProtectedSigningAdapter:
    """Build a signer-only plan and expose the existing APT retention seam."""

    def __init__(self, binding: SignerBinding = SignerBinding()):
        validate_signer_binding(binding)
        self.binding = binding

    def prepare(self, objects: Sequence[UnsignedObject], *, origin: str) -> dict[str, object]:
        checked = validate_unsigned_objects(objects, origin)
        operations: list[dict[str, object]] = []
        for obj in checked:
            path = os.fspath(obj.path)
            if obj.channel == "rpm":
                operations.append({
                    "kind": "rpm-package-sign",
                    "input": _object_record(obj),
                    "image": RPM_IMAGE,
                    "command": ("rpmsign", "--addsign", path),
                    "mutates": "signed-copy-required",
                    "preservation": "rpm-main-header-and-payload",
                })
            elif obj.channel == "pacman":
                operations.append({
                    "kind": "pacman-package-sign",
                    "input": _object_record(obj),
                    "image": PACMAN_IMAGE,
                    "command": ("gpg", "--detach-sign", "--armor", "-u", f"{self.binding.signing_subkey_fingerprint}!", path),
                    "secret_channel": "protected-pinentry",
                })
        apt_objects = [obj for obj in checked if obj.channel == "apt"]
        if apt_objects:
            operations.append({
                "kind": "apt-external-signature-retain",
                "inputs": tuple(_object_record(obj) for obj in apt_objects),
                "signature_kinds": ("inrelease", "release.gpg"),
                "validator": "APT4-native-adapter-only",
            })
        noarch = [obj for obj in checked if obj.channel == "rpm" and obj.architecture == "noarch"]
        for obj in noarch:
            operations.append({
                "kind": "rpm-noarch-signed-object-reuse",
                "product": obj.product,
                "version": obj.version,
                "source_unsigned_sha256": obj.sha256,
                "repositories": ("x86_64", "aarch64"),
                "requires_byte_identity": True,
            })
        if any(obj.channel == "rpm" for obj in checked):
            operations.extend(self._rpm_metadata_operations(checked))
        if any(obj.channel == "pacman" for obj in checked):
            operations.append({
                "kind": "pacman-repository-database-sign",
                "image": PACMAN_IMAGE,
                "command": ("repo-add", "-s", "-k", f"{self.binding.signing_subkey_fingerprint}!"),
                "secret_channel": "protected-pinentry",
            })
        return {
            "schema": SCHEMA,
            "origin": origin,
            "signer": {
                "public_key_sha256": self.binding.public_key_sha256,
                "primary_fingerprint": self.binding.primary_fingerprint,
                "signing_subkey_fingerprint": self.binding.signing_subkey_fingerprint,
            },
            "objects": tuple(_object_record(obj) for obj in checked),
            "operations": tuple(operations),
            "execution": {
                "mode": "protected-workflow-only",
                "native_execution_observed": False,
                "qualified_unsigned_objects_rebuilt": False,
                "secret_material": "never-in-plan",
            },
        }

    @staticmethod
    def _rpm_metadata_operations(objects: Sequence[UnsignedObject]) -> tuple[dict[str, object], ...]:
        arches = sorted({obj.architecture for obj in objects if obj.channel == "rpm"})
        return tuple({
            "kind": "rpm-repomd-sign",
            "repository_architecture": arch,
            "image": RPM_IMAGE,
            "command": ("gpg", "--detach-sign", "--armor", "-u", f"{SIGNING_SUBKEY_FINGERPRINT}!", "repodata/repomd.xml"),
            "secret_channel": "protected-pinentry",
        } for arch in arches)

    @staticmethod
    def execution_pending() -> None:
        raise ProtectedSigningError("PROTECTED_EXECUTION_REQUIRED", "This candidate does not invoke the native signer")

    @staticmethod
    def retain_apt_signatures(
        apt_candidate: Any,
        signed_store: Any,
        *,
        inrelease_bytes: bytes,
        release_gpg_bytes: bytes,
        issuer: str,
        evidence: Mapping[str, object],
        inrelease_adapter: Any,
        detached_adapter: Any,
    ) -> tuple[Any, Any]:
        """Use APT4's native-only callback through the existing candidate API."""
        if issuer != PRIMARY_FINGERPRINT:
            raise ProtectedSigningError("APT_ISSUER", "APT issuer must be the committed primary fingerprint")
        if not isinstance(inrelease_bytes, bytes) or not inrelease_bytes:
            raise ProtectedSigningError("APT_SIGNATURE", "InRelease bytes are required")
        if not isinstance(release_gpg_bytes, bytes) or not release_gpg_bytes:
            raise ProtectedSigningError("APT_SIGNATURE", "Release.gpg bytes are required")
        records: list[Any] = []
        for inline, signature, adapter in (
            (True, inrelease_bytes, inrelease_adapter), (False, release_gpg_bytes, detached_adapter)
        ):
            factory = getattr(adapter, "as_signed_store_validator", None)
            if not callable(factory):
                raise ProtectedSigningError("APT_ADAPTER", "APT4 native adapter callback is required")
            validator = factory()
            if not callable(validator):
                raise ProtectedSigningError("APT_ADAPTER", "APT4 callback must be callable")
            try:
                record = apt_candidate.retain_external_signature(
                    signed_store,
                    signature,
                    inline=inline,
                    issuer=issuer,
                    evidence=dict(evidence),
                    validator=validator,
                )
            except Exception as error:
                raise ProtectedSigningError("APT_RETAIN_FAILED", "Existing APT/SignedStore retention failed") from error
            records.append(record)
        return records[0], records[1]


def verify_unchanged_package(original: UnsignedObject, observed_path: str | Path) -> None:
    """Prove DEB/Pacman package bytes remained unchanged after sidecar signing."""
    if original.channel not in {"apt", "pacman"}:
        raise ProtectedSigningError("PRESERVATION_CHANNEL", "Only DEB and Pacman packages use byte preservation")
    expected = _read_stable(original.path, original.sha256, original.size, "original package")
    observed = _read_stable(observed_path, original.sha256, original.size, "observed package")
    if observed != expected:
        raise ProtectedSigningError("PACKAGE_MUTATED", "Package bytes changed during protected signing")


def verify_rpm_preservation(original: UnsignedObject, evidence: RpmPreservationEvidence) -> None:
    """Check the independent RPM header/payload preservation facts."""
    if original.channel != "rpm":
        raise ProtectedSigningError("PRESERVATION_CHANNEL", "RPM evidence requires an RPM object")
    for field in evidence.__dataclass_fields__:
        _require_hash(getattr(evidence, field), field)
    if evidence.unsigned_sha256 != original.sha256:
        raise ProtectedSigningError("RPM_INPUT_HASH", "RPM evidence is for a different unsigned object")
    if evidence.signed_sha256 == evidence.unsigned_sha256:
        raise ProtectedSigningError("RPM_UNSIGNED_OUTPUT", "RPM output was not changed by signing")
    if evidence.unsigned_main_header_sha256 != evidence.signed_main_header_sha256:
        raise ProtectedSigningError("RPM_HEADER_CHANGED", "RPM main header was changed")
    if evidence.unsigned_payload_sha256 != evidence.signed_payload_sha256:
        raise ProtectedSigningError("RPM_PAYLOAD_CHANGED", "RPM compressed payload was changed")


def verify_noarch_reuse(source: SignedArtifact, destinations: Sequence[SignedArtifact]) -> None:
    """Prove one signed noarch object is byte-identical in both RPM repos."""
    if source.channel != "rpm" or source.architecture != "noarch" or len(destinations) != 2:
        raise ProtectedSigningError("NOARCH_SCOPE", "Exactly two RPM noarch destinations are required")
    if {item.architecture for item in destinations} != {"x86_64", "aarch64"}:
        raise ProtectedSigningError("NOARCH_SCOPE", "Noarch destinations must be x86_64 and aarch64")
    source_bytes = _read_stable(source.path, source.sha256, source.size, "signed noarch source")
    for item in destinations:
        if (item.channel, item.product, item.version, item.origin) != (
            source.channel, source.product, source.version, source.origin
        ):
            raise ProtectedSigningError("NOARCH_IDENTITY", "Noarch destination identity mismatch")
        destination = _read_stable(item.path, item.sha256, item.size, "signed noarch destination")
        if item.sha256 != source.sha256 or item.size != source.size or destination != source_bytes:
            raise ProtectedSigningError("NOARCH_BYTES", "Signed noarch object was not reused byte-for-byte")


__all__ = [
    "CURRENT_VERSIONS", "PACMAN_IMAGE", "PRIMARY_FINGERPRINT", "PUBLIC_KEY_SHA256",
    "RPM_IMAGE", "RpmPreservationEvidence", "SCHEMA", "SIGNING_SUBKEY_FINGERPRINT",
    "ProtectedSigningAdapter", "ProtectedSigningError", "SignedArtifact", "SignerBinding",
    "UnsignedObject", "validate_signer_binding", "validate_unsigned_objects",
    "verify_committed_public_key",
    "verify_noarch_reuse", "verify_rpm_preservation", "verify_unchanged_package",
]
