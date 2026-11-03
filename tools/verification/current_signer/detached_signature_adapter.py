"""Pinned public-key-only generic detached-signature validation adapter.

Closed purposes: ``pacman-package``, ``pacman-database`` and ``rpm-metadata``.
This module adds no native or tool capability.  It reuses the reviewed APT
adapter protocol unchanged: committed public-key hash and private-block
refusal, ``_stage_file`` descriptor custody, the fixed import/list/verify
command builders, ``_parse_key_listing``, ``_parse_status(kind="release.gpg")``
(class 00 detached binary-document signature, no plaintext) and the concrete
``NativeGpgRunner``.  ``"release.gpg"`` is used only as the internal protocol
selector; staged filenames are neutral and returned evidence never names APT
Release objects.  ``NativeGpgRunner`` still labels its bounded process phase
``apt-public-signature-verification``; that internal label is not evidence.

Generic content is bounded by ``current_protected_signing.MAX_OBJECT_BYTES``,
not the APT 64 MiB Release bound.  Signature, key, status and stderr bounds are
the existing APT limits.  Verification refuses while any private signing
runtime is active or retained.  Native identity fields are returned only for a
concrete trusted ``NativeGpgRunner`` whose binary hash equals the caller's
expected pin both before and after the full fixed protocol.  Uncertain
resources stay strongly owned; there is no retry, reuse or directory cleanup.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable, Mapping

import apt_signature_adapter as _apt
from apt_signature_adapter import (
    CommandResult,
    NativeGpgRunner,
    SignatureValidationError,
    StagedFile,
    build_import_command,
    build_key_listing_command,
    build_verify_command,
)
from current_protected_signing import MAX_OBJECT_BYTES


SCHEMA = "tf.detached-public-signature-validation.v1"
PURPOSES = frozenset({"pacman-package", "pacman-database", "rpm-metadata"})
MAX_CONTENT_BYTES = MAX_OBJECT_BYTES
MAX_SIGNATURE_BYTES = _apt.MAX_SIGNATURE_BYTES
MAX_PUBLIC_KEY_BYTES = _apt.MAX_PUBLIC_KEY_BYTES
# Internal selector for the existing class-00 detached GPG protocol only.
_PROTOCOL_KIND = "release.gpg"
_STAGED_KEY, _STAGED_CONTENT, _STAGED_SIGNATURE = "public-key.asc", "content", "detached.sig"
_UNUSED_PLAINTEXT = "detached-plaintext-unused"
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_signature_encoding(purpose: str, signature: bytes) -> None:
    """Check client-compatible framing; native GPG still proves the signature."""
    begin, end = b"-----BEGIN PGP SIGNATURE-----\n", b"-----END PGP SIGNATURE-----\n"
    if purpose == "rpm-metadata":
        valid = (signature.startswith(begin) and signature.endswith(end)
                 and signature.count(begin) == signature.count(end) == 1
                 and b"\r" not in signature and b"\x00" not in signature)
    elif purpose in {"pacman-package", "pacman-database"}:
        # OpenPGP Signature packet: old-format tag2 or new-format tag2.
        # Full packet lengths, content and cryptography remain GPG's job.
        valid = len(signature) >= 2 and signature[0] in {0x88, 0x89, 0x8a, 0x8b, 0xc2}
    else:
        valid = False
    if not valid:
        raise SignatureValidationError("SIGNATURE_ENCODING", "Signature encoding differs from its purpose")


def _require_private_work_closed() -> None:
    """Refuse public verification while private signing work may exist."""
    try:
        import protected_signing_runtime as runtime
    except ImportError:
        raise SignatureValidationError(
            "PRIVATE_RUNTIME_UNKNOWN", "Private signing runtime state is unavailable",
        ) from None
    try:
        active = runtime._ACTIVE_SIGNING_RUNTIMES
        retained = runtime._RETAINED_RUNTIME_CUSTODIES
    except AttributeError:
        raise SignatureValidationError(
            "PRIVATE_RUNTIME_UNKNOWN", "Private signing runtime state is unavailable",
        ) from None
    if active or retained:
        raise SignatureValidationError(
            "PRIVATE_WORK_ACTIVE", "Public verification requires private signing work to be closed",
        )


class DetachedSignatureAdapter:
    """Validate held generic content and its detached signature once."""

    def __init__(
        self, *, purpose: str, gpg_binary: str | Path, public_key: str | Path,
        verification_home: str | Path, keyring: str | Path, runner: Callable[..., CommandResult],
        expected_gpg_sha256: str,
    ) -> None:
        if type(purpose) is not str or purpose not in PURPOSES:
            raise SignatureValidationError("DETACHED_PURPOSE", "Only the closed detached purposes are supported")
        if type(expected_gpg_sha256) is not str or not _SHA256_HEX.fullmatch(expected_gpg_sha256):
            raise SignatureValidationError("GPG_BINARY_PIN_FORMAT", "Expected GPG SHA-256 must be 64 lowercase hex")
        self.purpose = purpose
        self.expected_gpg_sha256 = expected_gpg_sha256
        self.gpg_binary = _apt._absolute_path(gpg_binary, "GnuPG binary")
        self.public_key = _apt._absolute_path(public_key, "public key")
        self.home = _apt._validate_home(verification_home, require_empty=False)
        self.keyring = _apt._validate_scoped_path(keyring, self.home, "keyring")
        if not callable(runner):
            raise SignatureValidationError("RUNNER_REQUIRED", "Callable GPG runner required")
        self.runner = runner
        self._used = False
        self._retained_staged: tuple[StagedFile, ...] = ()
        self._retained_allocations: tuple[object, ...] = ()

    @property
    def retained_custody(self) -> object | None:
        """Read-only handoff of uncertain public verification ownership."""
        owner = self.runner.retained_custody if type(self.runner) is NativeGpgRunner else None
        if owner is not None or self._retained_staged or self._retained_allocations:
            return (owner, self._retained_staged + self._retained_allocations)
        return None

    @property
    def process_cleanup_confirmed(self) -> bool:
        return type(self.runner) is NativeGpgRunner and self.runner.process_cleanup_confirmed

    @property
    def _real_runner(self) -> bool:
        return type(self.runner) is NativeGpgRunner and self.runner.trusted_native is True

    def _retain(self, *items: object) -> None:
        self._retained_allocations += items
        _apt._retain_public_verifier(self)

    def _read_inputs(self, content: bytes, signature: bytes) -> bytes:
        if type(content) is not bytes or not content or len(content) > MAX_CONTENT_BYTES:
            raise SignatureValidationError("CONTENT_LIMIT", "Content bytes are missing or oversized")
        if type(signature) is not bytes or not signature or len(signature) > MAX_SIGNATURE_BYTES:
            raise SignatureValidationError("SIGNATURE_LIMIT", "Signature bytes are missing or oversized")
        require_signature_encoding(self.purpose, signature)
        key_bytes, _ = _apt._read_regular(self.public_key, "public key", MAX_PUBLIC_KEY_BYTES)
        if b"BEGIN PGP PRIVATE KEY BLOCK" in key_bytes:
            raise SignatureValidationError("PRIVATE_KEY_REJECTED", "Private key material is forbidden")
        if _sha256(key_bytes) != _apt.PUBLIC_KEY_SHA256:
            raise SignatureValidationError("KEY_DIGEST_MISMATCH", "Public key is not the committed key bundle")
        return key_bytes

    def _require_binary_pin(self) -> None:
        """Hash the fixed binary via the runner's own validation; never execute."""
        observed = self.runner._validate_native_binary()
        if observed != self.expected_gpg_sha256:
            raise SignatureValidationError("GPG_BINARY_PIN_MISMATCH", "GnuPG binary is not the expected build")

    def _invoke(self, argv: tuple[str, ...], env: Mapping[str, str], phase: str, code: str) -> CommandResult:
        _require_private_work_closed()
        result = self.runner(argv, env, phase)
        if not isinstance(result, CommandResult) or result.returncode != 0:
            raise SignatureValidationError(code, f"GPG {phase} phase failed")
        return result

    def validate(
        self, content_bytes: bytes, signature_bytes: bytes, evidence: Mapping[str, object] | None = None,
    ) -> dict[str, str]:
        if self._used:
            raise SignatureValidationError("ADAPTER_REUSED", "A fresh verification home is single-use")
        self._used = True
        if evidence is not None and not isinstance(evidence, Mapping):
            raise SignatureValidationError("EVIDENCE_TYPE", "Caller evidence must be a mapping or None")
        native_authority = self._real_runner
        _require_private_work_closed()
        if type(self.runner) is NativeGpgRunner and not self.runner.process_cleanup_confirmed:
            raise SignatureValidationError("RUNNER_CUSTODY_RETAINED", "Public verification cleanup remains unconfirmed")
        _apt._validate_home(self.home, require_empty=True)
        _apt._validate_destination(self.keyring, self.home, "keyring")
        staged: list[StagedFile] = []
        body_error: BaseException | None = None
        try:
            key_bytes = self._read_inputs(content_bytes, signature_bytes)
            if native_authority:
                self._require_binary_pin()
            stage_dir = _apt._mkdir_owned(self.home, "staged")
            staged_key = _apt._stage_file(stage_dir, _STAGED_KEY, key_bytes, MAX_PUBLIC_KEY_BYTES)
            staged.append(staged_key)
            staged_content = _apt._stage_file(stage_dir, _STAGED_CONTENT, content_bytes, MAX_CONTENT_BYTES)
            staged.append(staged_content)
            staged_signature = _apt._stage_file(stage_dir, _STAGED_SIGNATURE, signature_bytes, MAX_SIGNATURE_BYTES)
            staged.append(staged_signature)
            env = {"GNUPGHOME": str(self.home), "HOME": str(self.home), "LC_ALL": "C", "LANG": "C"}
            import_argv = build_import_command(
                self.gpg_binary, home=self.home, keyring=self.keyring, public_key=staged_key.path)
            listing_argv = build_key_listing_command(self.gpg_binary, home=self.home, keyring=self.keyring)
            # The detached builder branch ignores plaintext; no output is created.
            verify_argv = build_verify_command(
                self.gpg_binary, kind=_PROTOCOL_KIND, home=self.home, keyring=self.keyring,
                signed=staged_signature.path, release=staged_content.path,
                plaintext=stage_dir / _UNUSED_PLAINTEXT,
            )
            self._invoke(import_argv, env, "import", "IMPORT_FAILED")
            for item in staged:
                item.assert_unchanged()
            listed = self._invoke(listing_argv, env, "inspect", "KEY_LISTING_FAILED")
            key_facts = _apt._parse_key_listing(listed.stdout)
            for item in staged:
                item.assert_unchanged()
            verified = self._invoke(verify_argv, env, "verify", "VERIFY_FAILED")
            for item in staged:
                item.assert_unchanged()
            identity = _apt._parse_status(verified.stdout, _PROTOCOL_KIND)
            if (identity["primary_fingerprint"] != key_facts["primary_fingerprint"]
                    or identity["signing_fingerprint"] != key_facts["signing_fingerprint"]):
                raise SignatureValidationError("IDENTITY_MISMATCH", "Status and key listing disagree")
            native = False
            if native_authority:
                if not self._real_runner or self.runner.executable_sha256 != self.expected_gpg_sha256:
                    raise SignatureValidationError(
                        "GPG_BINARY_PIN_MISMATCH", "Executed GnuPG binary is not the expected build")
                native = True
            return self._result(content_bytes, signature_bytes, key_facts, identity, native)
        except BaseException as error:
            body_error = error
            allocations = getattr(error, "retained_descriptors", ())
            if allocations:
                self._retain(*allocations)
            raise
        finally:
            self._release_staged(staged, body_error)

    def _release_staged(self, staged: list[StagedFile], body_error: BaseException | None) -> None:
        if type(self.runner) is NativeGpgRunner and not self.runner.process_cleanup_confirmed:
            # A live or uncertain process may still use these descriptors/paths.
            self._retained_staged = tuple(staged)
            _apt._retain_public_verifier(self)
            return
        failures: list[BaseException] = []
        retained: list[StagedFile] = []
        for item in staged:
            try:
                item.close()
            except BaseException as error:
                failures.append(error)
                retained.append(item)
        if not failures:
            return
        self._retained_staged = tuple(retained)
        failure = SignatureValidationError("STAGED_CLEANUP_UNCONFIRMED", "Staged verification cleanup is unconfirmed")
        failure.original_error = body_error
        failure.cleanup_errors = tuple(failures)
        self._retain(failure)
        if body_error is not None and not isinstance(body_error, Exception):
            return  # Keep the original body interruption as the primary error.
        for cleanup_error in failures:
            if not isinstance(cleanup_error, Exception):
                # The composed failure remains strongly owned in retained
                # custody, while interruption keeps its observable semantics.
                raise cleanup_error from None
        raise failure from None

    def _result(
        self, content: bytes, signature: bytes, key_facts: Mapping[str, str],
        identity: Mapping[str, str], native: bool,
    ) -> dict[str, str]:
        result = {
            "schema": SCHEMA,
            "status": "valid",
            "purpose": self.purpose,
            "content_sha256": _sha256(content),
            "signature_sha256": _sha256(signature),
            "public_key_sha256": _apt.PUBLIC_KEY_SHA256,
            "trust_status": identity["trust_status"],
            "key_listing": key_facts["key_listing"],
            "verification_mode": "native" if native else "fixture",
            "confers_signature_authentication": "true" if native else "false",
            "gpg_binary_sha256": self.runner.executable_sha256 if native else "fixture-not-recorded",
        }
        if native:
            result.update({
                "verified_issuer": _apt.PRIMARY_FINGERPRINT,
                "primary_fingerprint": identity["primary_fingerprint"],
                "signing_subkey": identity["signing_fingerprint"],
            })
        else:
            result.update({
                "fixture_primary_fingerprint": identity["primary_fingerprint"],
                "fixture_signing_fingerprint": identity["signing_fingerprint"],
            })
        return result

    def as_signed_store_validator(self) -> Callable[[bytes, bytes, dict[str, object]], dict[str, str]]:
        """Return the SignedStore callback; fixture runners never authorize."""
        def validator(unsigned: bytes, signed: bytes, evidence: dict[str, object]) -> dict[str, str]:
            if not self._real_runner:
                raise SignatureValidationError("NATIVE_REQUIRED", "Only the fixed native GPG runner may authorize retention")
            result = self.validate(unsigned, signed, evidence)
            if (result.get("verification_mode") != "native"
                    or result.get("confers_signature_authentication") != "true"
                    or result.get("gpg_binary_sha256") != self.expected_gpg_sha256):
                raise SignatureValidationError("NATIVE_REQUIRED", "Native pinned GPG verification required")
            return result
        return validator


__all__ = [
    "DetachedSignatureAdapter", "MAX_CONTENT_BYTES", "MAX_PUBLIC_KEY_BYTES", "MAX_SIGNATURE_BYTES",
    "PURPOSES", "SCHEMA",
]
