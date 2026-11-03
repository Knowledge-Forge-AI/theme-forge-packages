"""Pinned public-key-only RPM package verification adapter (source only).

Independent public proof for a signed RPM before SignedStore retention, run
only after private signing work is confirmed closed.  The private runtime's
mechanical RPM check is not a substitute.  This module adds no tool
capability: it reuses, unchanged, the generic detached private-work guard,
the APT helpers (committed public-key hash/private-block refusal, safe reads,
``_stage_file`` custody, fixed GPG import/listing builders, ``_parse_key_listing``
and ``NativeGpgRunner``) and C6 ``inspect_rpm_preservation``,
``_rpm_verification_status`` and ``NativeProtectedProcessRunner.run`` with
exactly two fixed public RPM argv shapes. It also verifies the actual
embedded header signature and exact main-header bytes with the existing fixed
GPG detached class-00 protocol. RPM6 reports the primary fingerprint, not the
subkey; only GPG VALIDSIG establishes the expected CI signing subkey.  No private key, passphrase, agent or
caller-supplied argv/tool exists here.

Native identity fields are returned only for an exact trusted
``NativeGpgRunner`` (executor None) plus an exact
``NativeProtectedProcessRunner`` with confirmed cleanup, and only after both
actual binaries matched their pins before and after every command.  Every other
runner yields fixture markers only.  Both RPM commands use the shared C6
``_rpm_keyring_options`` scope (explicit ``%_keyring fs`` and
``%_keyringpath`` under the fresh owned ``--dbpath``), never host/vendor macro
selection.  The C6 RPM grammar, native RPM6 keystore behavior under that scope,
and the effective native policy remain unqualified; a hosted native gate is
still required.  Uncertain resources stay strongly owned, with no retry, reuse
or directory deletion.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping

import apt_signature_adapter as _apt
from apt_signature_adapter import (
    GPG_BINARY, CommandResult, NativeGpgRunner, SignatureValidationError, StagedFile,
    build_import_command, build_key_listing_command, build_verify_command,
)
from current_protected_signing import MAX_OBJECT_BYTES
from detached_signature_adapter import _require_private_work_closed
import protected_signing_runtime as _runtime
from rpm_byte_preservation import header_signature, PreservationError


SCHEMA = "tf.rpm-public-signature-validation.v1"
RPM_BINARY = _runtime.NATIVE_RPM
MAX_RPM_BYTES = MAX_OBJECT_BYTES
MAX_PUBLIC_KEY_BYTES = _apt.MAX_PUBLIC_KEY_BYTES
MAX_RPM_BINARY_BYTES = _apt.MAX_GPG_BINARY_BYTES
FIXTURE_HASH = "fixture-not-recorded"
_STAGED_KEY, _STAGED_PACKAGE = "public-key.asc", "signed-package.rpm"
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_RPM_ERRORS = {"COMMAND_TIMEOUT": "RPM_TIMEOUT", "COMMAND_OUTPUT_LIMIT": "RPM_OUTPUT_LIMIT",
               "COMMAND_POLICY": "RPM_RUNNER_CONFIG"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _executable_sha256(path: str | Path, label: str, code: str) -> str:
    """Hash a root-owned, non-symlinked, single-link executable; never run it."""
    candidate = _apt._absolute_path(path, label)
    info = _apt._lstat_no_symlink(candidate, label)
    if (info is None or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or not stat.S_IMODE(info.st_mode) & 0o111 or stat.S_IMODE(info.st_mode) & 0o022):
        raise SignatureValidationError(code, f"{label} must be a root-owned unaliased executable")
    data, identity = _apt._read_regular(candidate, label, MAX_RPM_BINARY_BYTES)
    if identity != _apt._file_identity(info):
        raise SignatureValidationError(code, f"{label} changed during inspection")
    return _sha256(data)


def _rpm_binary_sha256() -> str:
    return _executable_sha256(RPM_BINARY, "RPM binary", "RPM_BINARY_CUSTODY")


class RpmSignatureAdapter:
    """Validate one held unsigned/signed RPM pair through public-only tools."""

    def __init__(
        self, *, public_key: str | Path, verification_home: str | Path,
        expected_gpg_sha256: str, expected_rpm_sha256: str,
        gpg_runner: NativeGpgRunner | None = None, rpm_runner: object | None = None,
    ) -> None:
        for name, pin in (("GPG", expected_gpg_sha256), ("RPM", expected_rpm_sha256)):
            if type(pin) is not str or not _SHA256_HEX.fullmatch(pin):
                raise SignatureValidationError(f"{name}_BINARY_PIN_FORMAT", f"Expected {name} SHA-256 must be 64 lowercase hex")
        self.expected_gpg_sha256, self.expected_rpm_sha256 = expected_gpg_sha256, expected_rpm_sha256
        self.public_key = _apt._absolute_path(public_key, "public key")
        self.home = _apt._validate_home(verification_home, require_empty=False)
        self.keyring = self.home / "public-keyring.kbx"
        try:
            # Closed macro-safe scope, refused before any staging or command.
            self._rpm_scope = _runtime._rpm_keyring_options(self.home / "rpmdb")
        except _runtime.ProtectedSigningError as error:
            raise SignatureValidationError(error.code, "Verification home cannot scope an RPM keyring") from None
        self.gpg_runner = NativeGpgRunner(GPG_BINARY) if gpg_runner is None else gpg_runner
        if not isinstance(self.gpg_runner, NativeGpgRunner) or self.gpg_runner.gpg_binary != GPG_BINARY:
            raise SignatureValidationError("RUNNER_REQUIRED", "The fixed GPG runner is required")
        self.rpm_runner = _runtime.NativeProtectedProcessRunner() if rpm_runner is None else rpm_runner
        if not callable(getattr(self.rpm_runner, "run", None)):
            raise SignatureValidationError("RUNNER_REQUIRED", "A bounded RPM process runner is required")
        # A native-capable runner beside a fixture seam would execute a real
        # tool without pins; only all-native or all-fixture pairs are allowed.
        if ((self.gpg_runner._executor is None or isinstance(self.rpm_runner, _runtime.NativeProtectedProcessRunner))
                and not self._native_authority):
            raise SignatureValidationError("RUNNER_MIXED_AUTHORITY", "Native and fixture runners cannot be combined")
        self._used = False
        self._observed_rpm_sha256: str | None = None
        self._rpm_custody: _runtime._LifecycleFailure | None = None
        self._retained_staged: tuple[StagedFile, ...] = ()
        self._retained_allocations: tuple[object, ...] = ()

    @property
    def retained_custody(self) -> object | None:
        """Read-only handoff of uncertain ownership; never serialize or retry."""
        gpg_owner = NativeGpgRunner.retained_custody.fget(self.gpg_runner)
        if gpg_owner is not None or self._rpm_custody is not None or self._retained_staged or self._retained_allocations:
            return (gpg_owner, self._rpm_custody, self._retained_staged + self._retained_allocations)
        return None

    @property
    def process_cleanup_confirmed(self) -> bool:
        return NativeGpgRunner.process_cleanup_confirmed.fget(self.gpg_runner) and self._rpm_custody is None

    @property
    def _native_authority(self) -> bool:
        return (type(self.gpg_runner) is NativeGpgRunner and self.gpg_runner.trusted_native is True
                and type(self.rpm_runner) is _runtime.NativeProtectedProcessRunner)

    def _retain(self, *items: object) -> None:
        self._retained_allocations += items
        _apt._retain_public_verifier(self)

    def _read_inputs(self, unsigned: bytes, signed: bytes) -> bytes:
        for label, value in (("UNSIGNED", unsigned), ("SIGNED", signed)):
            if type(value) is not bytes or not value or len(value) > MAX_RPM_BYTES:
                raise SignatureValidationError(f"{label}_RPM_LIMIT", "RPM bytes are missing or oversized")
        key_bytes, _ = _apt._read_regular(self.public_key, "public key", MAX_PUBLIC_KEY_BYTES)
        if b"BEGIN PGP PRIVATE KEY BLOCK" in key_bytes:
            raise SignatureValidationError("PRIVATE_KEY_REJECTED", "Private key material is forbidden")
        if _sha256(key_bytes) != _apt.PUBLIC_KEY_SHA256:
            raise SignatureValidationError("KEY_DIGEST_MISMATCH", "Public key is not the committed key bundle")
        return key_bytes

    @staticmethod
    def _preservation(unsigned: bytes, signed: bytes) -> dict[str, object]:
        try:
            return _runtime.inspect_rpm_preservation(unsigned, signed)
        except _runtime.ProtectedSigningError as error:
            raise SignatureValidationError(error.code, "RPM byte preservation refused") from None

    def _require_pins(self) -> None:
        """Actual binary identity via existing safe reads; never executes."""
        if self.gpg_runner._validate_native_binary() != self.expected_gpg_sha256:
            raise SignatureValidationError("GPG_BINARY_PIN_MISMATCH", "GnuPG binary is not the expected build")
        observed = _rpm_binary_sha256()
        if observed != self.expected_rpm_sha256:
            raise SignatureValidationError("RPM_BINARY_PIN_MISMATCH", "RPM binary is not the expected build")
        self._observed_rpm_sha256 = observed

    def _after_command(self, staged: list[StagedFile], native: bool) -> None:
        for item in staged:
            item.assert_unchanged()
        if native:
            self._require_pins()

    def _gpg(self, argv: tuple[str, ...], phase: str, code: str, staged: list[StagedFile], native: bool) -> CommandResult:
        _require_private_work_closed()
        env = {"GNUPGHOME": str(self.home), "HOME": str(self.home), "LC_ALL": "C", "LANG": "C"}
        result = self.gpg_runner(argv, env, phase)
        if not isinstance(result, CommandResult) or result.returncode != 0:
            raise SignatureValidationError(code, f"GPG {phase} phase failed")
        self._after_command(staged, native)
        return result

    def _rpm(self, argv: tuple[str, ...], phase: str, code: str | None, staged: list[StagedFile],
             native: bool) -> _runtime.ProcessResult:
        _require_private_work_closed()
        env = {"HOME": str(self.home), "GNUPGHOME": str(self.home), "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
        try:
            result = self.rpm_runner.run(argv, cwd=self.home, env=env, stdin=b"", phase=phase)
        except _runtime._LifecycleFailure as error:
            # Keep the actual C6 failure with its process/resources before it
            # can lose ownership; no serialization, retry or extra signaling.
            self._rpm_custody = error
            _apt._retain_public_verifier(self)
            if isinstance(error.original_error, BaseException) and not isinstance(error.original_error, Exception):
                raise error.original_error from None
            failure = SignatureValidationError("RPM_CLEANUP_UNCONFIRMED", "Public RPM process cleanup is unconfirmed")
            failure.cleanup_confirmed = False
            raise failure from None
        except _runtime.ProtectedSigningError as error:
            raise SignatureValidationError(_RPM_ERRORS.get(error.code, "RPM_RUNNER_IO"), "Bounded RPM phase failed") from None
        except Exception:
            raise SignatureValidationError("RPM_RUNNER_IO", "Unable to run bounded RPM phase") from None
        if type(result) is not _runtime.ProcessResult or (code is not None and result.returncode != 0):
            raise SignatureValidationError(code or "RPM_VERIFY_STATUS", f"RPM {phase} phase failed")
        self._after_command(staged, native)
        return result

    def validate(
        self, unsigned_rpm_bytes: bytes, signed_rpm_bytes: bytes, evidence: Mapping[str, object] | None = None,
    ) -> dict[str, str]:
        if self._used:
            raise SignatureValidationError("ADAPTER_REUSED", "A fresh verification home is single-use")
        self._used = True
        if evidence is not None and not isinstance(evidence, Mapping):
            raise SignatureValidationError("EVIDENCE_TYPE", "Caller evidence must be a mapping or None")
        native = self._native_authority
        _require_private_work_closed()
        if not self.process_cleanup_confirmed:
            raise SignatureValidationError("RUNNER_CUSTODY_RETAINED", "Public verification cleanup remains unconfirmed")
        _apt._validate_home(self.home, require_empty=True)
        staged: list[StagedFile] = []
        body_error: BaseException | None = None
        try:
            key_bytes = self._read_inputs(unsigned_rpm_bytes, signed_rpm_bytes)
            preservation = self._preservation(unsigned_rpm_bytes, signed_rpm_bytes)
            try:
                header_bytes, signature_bytes = header_signature(signed_rpm_bytes, _apt.MAX_SIGNATURE_BYTES)
            except PreservationError:
                raise SignatureValidationError("RPM_HEADER_SIGNATURE", "RPM header signature format refused") from None
            if native:
                self._require_pins()
            stage_dir = _apt._mkdir_owned(self.home, "staged")
            _apt._mkdir_owned(self.home, "rpmdb")  # exactly the scoped self.home / "rpmdb"
            staged_key = _apt._stage_file(stage_dir, _STAGED_KEY, key_bytes, MAX_PUBLIC_KEY_BYTES)
            staged.append(staged_key)
            package = _apt._stage_file(stage_dir, _STAGED_PACKAGE, signed_rpm_bytes, MAX_RPM_BYTES)
            staged.append(package)
            header = _apt._stage_file(stage_dir, "rpm-header.bin", header_bytes, MAX_RPM_BYTES)
            staged.append(header)
            signature = _apt._stage_file(stage_dir, "rpm-header.sig", signature_bytes, _apt.MAX_SIGNATURE_BYTES)
            staged.append(signature)
            self._gpg(build_import_command(GPG_BINARY, home=self.home, keyring=self.keyring, public_key=staged_key.path),
                      "import", "IMPORT_FAILED", staged, native)
            listed = self._gpg(build_key_listing_command(GPG_BINARY, home=self.home, keyring=self.keyring),
                               "inspect", "KEY_LISTING_FAILED", staged, native)
            key_facts = _apt._parse_key_listing(listed.stdout)
            self._rpm((RPM_BINARY, *self._rpm_scope, "--import", str(staged_key.path)),
                      "rpm-public-key-import", "RPM_IMPORT_FAILED", staged, native)
            checked = self._rpm(
                (RPM_BINARY, "--define", "%_pkgverify_level all", "--define", "%_pkgverify_flags 0",
                 *self._rpm_scope, "--checksig", "--verbose", str(package.path)),
                "rpm-public-package-verify", None, staged, native)
            try:
                proof = _runtime._rpm_verification_status(checked, package.path)
            except _runtime.ProtectedSigningError as error:
                raise SignatureValidationError(error.code, "RPM verification proof refused") from None
            if (proof.get("verified_primary_fingerprint") != key_facts["primary_fingerprint"]
                    or proof.get("expected_primary_fingerprint") != key_facts["primary_fingerprint"]
                    or proof.get("signature_count") != 1 or proof.get("status") != "source-contract-match"):
                raise SignatureValidationError("IDENTITY_MISMATCH", "RPM proof and public key listing disagree")
            verified = self._gpg(build_verify_command(
                GPG_BINARY, kind="release.gpg", home=self.home, keyring=self.keyring,
                signed=signature.path, release=header.path, plaintext=stage_dir / "unused-plaintext"),
                "verify", "HEADER_SIGNATURE_VERIFY_FAILED", staged, native)
            identity = _apt._parse_status(verified.stdout, "release.gpg")
            if (identity["primary_fingerprint"] != key_facts["primary_fingerprint"]
                    or identity["signing_fingerprint"] != key_facts["signing_fingerprint"]):
                raise SignatureValidationError("IDENTITY_MISMATCH", "Header signature and key listing disagree")
            if native and not (self._native_authority and self.process_cleanup_confirmed
                               and self.gpg_runner.executable_sha256 == self.expected_gpg_sha256
                               and self._observed_rpm_sha256 == self.expected_rpm_sha256):
                raise SignatureValidationError("GPG_BINARY_PIN_MISMATCH", "Executed GnuPG binary is not the expected build")
            return self._result(unsigned_rpm_bytes, signed_rpm_bytes, preservation, key_facts, proof, identity, native)
        except BaseException as error:
            body_error = error
            allocations = getattr(error, "retained_descriptors", ())
            if allocations:
                self._retain(*allocations)
            raise
        finally:
            self._release_staged(staged, body_error)

    def _release_staged(self, staged: list[StagedFile], body_error: BaseException | None) -> None:
        if not self.process_cleanup_confirmed:
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
            return  # Never replace KeyboardInterrupt/SystemExit; custody is retained.
        for cleanup_error in failures:
            if not isinstance(cleanup_error, Exception):
                # The composed failure remains strongly owned in retained
                # custody, while interruption keeps its observable semantics.
                raise cleanup_error from None
        raise failure from None

    def _result(self, unsigned: bytes, signed: bytes, preservation: Mapping[str, object],
                key_facts: Mapping[str, str], proof: Mapping[str, object], identity: Mapping[str, str], native: bool) -> dict[str, str]:
        result = {
            "schema": SCHEMA, "status": "valid", "purpose": "rpm-package",
            "unsigned_sha256": _sha256(unsigned), "signed_sha256": _sha256(signed),
            "public_key_sha256": _apt.PUBLIC_KEY_SHA256,
            "preserved_lead_sha256": str(preservation["lead_sha256"]),
            "preserved_main_header_sha256": str(preservation["main_header_sha256"]),
            "preserved_main_header_bytes": str(preservation["main_header_bytes"]),
            "preserved_payload_sha256": str(preservation["compressed_payload_sha256"]),
            "preserved_payload_bytes": str(preservation["compressed_payload_bytes"]),
            "key_listing": key_facts["key_listing"],
            "rpm_proof_schema": str(proof["schema"]),
            "rpm_signature_count": str(proof["signature_count"]),
            "rpm_signature_format": str(proof["signature_format"]),
            "rpm_digest_count": str(proof["digest_count"]),
            "rpm_verification_level": str(proof["verification_level"]),
            "rpm_native_grammar_qualified": "false",
            "verification_mode": "native" if native else "fixture",
            "confers_signature_authentication": "true" if native else "false",
            "gpg_binary_sha256": self.gpg_runner.executable_sha256 if native else FIXTURE_HASH,
            "rpm_binary_sha256": self._observed_rpm_sha256 if native else FIXTURE_HASH,
        }
        if native:
            result.update({
                "rpm_primary_fingerprint": str(proof["verified_primary_fingerprint"]),
                "rpm_header_subkey_proof": "gpg-validsig",
                "verified_issuer": _apt.PRIMARY_FINGERPRINT,
                "primary_fingerprint": key_facts["primary_fingerprint"],
                "signing_subkey": identity["signing_fingerprint"],
            })
        else:
            result.update({
                "fixture_rpm_primary_fingerprint": str(proof["verified_primary_fingerprint"]),
                "fixture_rpm_header_subkey_proof": "fixture",
                "fixture_primary_fingerprint": key_facts["primary_fingerprint"],
                "fixture_signing_fingerprint": identity["signing_fingerprint"],
            })
        return result

    def as_signed_store_validator(self) -> Callable[[bytes, bytes, dict[str, object]], dict[str, str]]:
        """Return the SignedStore callback; fixture runners never authorize."""
        def validator(unsigned: bytes, signed: bytes, evidence: dict[str, object]) -> dict[str, str]:
            if not self._native_authority:
                raise SignatureValidationError("NATIVE_REQUIRED", "Only the fixed native runners may authorize retention")
            result = self.validate(unsigned, signed, evidence)
            if (result.get("verification_mode") != "native"
                    or result.get("confers_signature_authentication") != "true"
                    or result.get("gpg_binary_sha256") != self.expected_gpg_sha256
                    or result.get("rpm_binary_sha256") != self.expected_rpm_sha256):
                raise SignatureValidationError("NATIVE_REQUIRED", "Native pinned RPM verification required")
            return result
        return validator


__all__ = ["MAX_RPM_BYTES", "RPM_BINARY", "RpmSignatureAdapter", "SCHEMA"]
