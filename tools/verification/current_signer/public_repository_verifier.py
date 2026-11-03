"""UNADOPTED post-cleanup native verification and retained-byte assembly.

This entrypoint cannot establish fresh RS9 admission or authorize publication.
It requires actual native crypto; test seams cannot replace its adapter types.
No signing, secret input, key rotation, cleanup retry or deployment API exists.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

import apt_signature_adapter as apt
import current_import_routing as routing
import protected_signing_runtime as runtime
from detached_signature_adapter import DetachedSignatureAdapter, _require_private_work_closed
from rpm_public_signature_adapter import RpmSignatureAdapter
from rs9.repo_apt import AptRepositoryCandidate
from rs9.signed_store import SignedStore

from public_repository_files import inventory, physical_root, snapshot, unchanged, write_new
from public_repository_linkage import public_inventory, plan_public_repository

_HEX = re.compile(r"[0-9a-f]{64}")
GENERATION = "current-four-071"


def _refuse(code):
    raise apt.SignatureValidationError(code, "Public repository verification refused")


def require_all_custody_closed():
    _require_private_work_closed()
    if (runtime._RETAINED_READ_DESCRIPTORS or apt._RETAINED_PUBLIC_VERIFIERS
            or any(getattr(routing, name) for name in (
                "_SIGNING_RETENTION", "_LEASE_RETENTION", "_OWNER_RETENTION", "_PREHANDLE_RETENTION"))):
        _refuse("PUBLIC_CUSTODY_RETAINED")


def _new(parent: Path, name: str) -> Path:
    return apt._mkdir_owned(parent, name)


def _validator(obj, public_key, homes, number, gpg_pin, rpm_pin):
    """Construct concrete adapters here; callers cannot supply validators."""
    require_all_custody_closed()
    home = _new(homes, f"verify-{number}")
    if obj.kind == "rpm-package":
        adapter = RpmSignatureAdapter(public_key=public_key, verification_home=home,
                                      expected_gpg_sha256=gpg_pin, expected_rpm_sha256=rpm_pin)
    else:
        runner = apt.NativeGpgRunner(apt.GPG_BINARY)
        if type(runner) is not apt.NativeGpgRunner or not runner.trusted_native:
            _refuse("NATIVE_REQUIRED")
        if runner._validate_native_binary() != gpg_pin:
            _refuse("GPG_BINARY_PIN_MISMATCH")
        common = dict(gpg_binary=apt.GPG_BINARY, public_key=public_key,
                      verification_home=home, keyring=home / "public-keyring.kbx", runner=runner)
        if obj.kind in {"apt-inrelease", "apt-release-gpg"}:
            kind = "inrelease" if obj.kind == "apt-inrelease" else "release.gpg"
            adapter = apt.AptSignatureAdapter(kind=kind, **common)
        else:
            purpose = {"rpm-metadata": "rpm-metadata", "pacman-package": "pacman-package",
                       "pacman-database": "pacman-database"}.get(obj.kind)
            if purpose is None:
                _refuse("PUBLIC_OBJECT_KIND")
            adapter = DetachedSignatureAdapter(purpose=purpose, expected_gpg_sha256=gpg_pin, **common)
    concrete = adapter.as_signed_store_validator()
    def validate(unsigned, signed, evidence):
        require_all_custody_closed()
        result = concrete(unsigned, signed, evidence)
        if (result.get("verification_mode") != "native"
                or result.get("confers_signature_authentication") != "true"
                or result.get("gpg_binary_sha256") != gpg_pin
                or adapter.retained_custody is not None or not adapter.process_cleanup_confirmed):
            _refuse("PUBLIC_NATIVE_PROOF")
        if obj.kind == "rpm-package" and result.get("rpm_binary_sha256") != rpm_pin:
            _refuse("RPM_BINARY_PIN_MISMATCH")
        return result
    return adapter, validate


def verify_and_assemble(*, unsigned_stage, signed_output, public_key, work_root, deployment_root,
                        expected_gpg_sha256: str, expected_rpm_sha256: str) -> dict:
    """New roots only. Any failure leaves non-exportable state for its owner.

    The outer same-PID worker must bind the input stage to its fresh lease and
    must not export anything without this function's completed receipt. This
    function independently verifies crypto/linkage, never original-run admission.
    """
    require_all_custody_closed()
    for pin in (expected_gpg_sha256, expected_rpm_sha256):
        if type(pin) is not str or not _HEX.fullmatch(pin):
            _refuse("PUBLIC_BINARY_PIN_FORMAT")
    work = apt._validate_home(work_root, require_empty=True)
    deploy = physical_root(deployment_root, empty=True)
    stage, output = snapshot(unsigned_stage), snapshot(signed_output)
    roots = (work, deploy, stage.root, output.root)
    if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(roots) for b in roots[i + 1:]):
        _refuse("PUBLIC_ROOT_OVERLAP")
    key, _ = apt._read_regular(Path(public_key), "committed public key", apt.MAX_PUBLIC_KEY_BYTES)
    if hashlib.sha256(key).hexdigest() != apt.PUBLIC_KEY_SHA256 or b"PRIVATE KEY BLOCK" in key:
        _refuse("KEY_DIGEST_MISMATCH")
    plan = plan_public_repository(stage.members, output.members)
    homes, stores, assembled = (_new(work, name) for name in ("verification-homes", "stores", "assembled"))
    apt_store = SignedStore(_new(stores, "apt"), generation=GENERATION)
    packages_store = SignedStore(_new(stores, "packages"), generation=GENERATION)
    apt_root = _new(work, "apt-candidate")
    write_new(apt_root, {name[4:]: body for name, body in plan.companions.items() if name.startswith("apt/")})
    candidate = AptRepositoryCandidate(apt_root, distribution="resolute")
    retained = []
    # Concrete adapter ownership stays reachable until every phase has closed.
    adapters = []
    for number, obj in enumerate(plan.signed):
        require_all_custody_closed()
        adapter, validator = _validator(obj, Path(public_key), homes, number,
                                        expected_gpg_sha256, expected_rpm_sha256)
        adapters.append(adapter)
        if obj.store == "apt":
            record = candidate.retain_external_signature(
                apt_store, obj.signed, inline=obj.kind == "apt-inrelease",
                issuer=apt.PRIMARY_FINGERPRINT, evidence={}, validator=validator)
        else:
            record = packages_store.retain(obj.rel_path, obj.signed, obj.unsigned,
                                            apt.PRIMARY_FINGERPRINT, {}, validator=validator)
        retained.append(record)
        require_all_custody_closed()
    if any(a.retained_custody is not None or not a.process_cleanup_confirmed for a in adapters):
        _refuse("PUBLIC_CUSTODY_RETAINED")
    for store in (apt_store, packages_store):
        store.verify_store_integrity()
    apt_assembled, packages_assembled = _new(assembled, "apt"), _new(assembled, "packages")
    apt_store.assemble_deployment(apt_assembled)
    packages_store.assemble_deployment(packages_assembled)
    actual_signed = {**{"apt/" + n: b for n, b in snapshot(apt_assembled).members.items()},
                     **snapshot(packages_assembled).members}
    if actual_signed != {obj.deploy_path: obj.signed for obj in plan.signed}:
        _refuse("SIGNED_STORE_ASSEMBLY")
    by_hash = {}
    for obj in plan.signed:
        if obj.store == "apt":
            name = "dists/resolute/by-hash/SHA256/" + hashlib.sha256(obj.signed).hexdigest()
            data, _ = apt._read_regular(apt_root / name, "APT signature by-hash", apt.MAX_INRELEASE_BYTES)
            by_hash["apt/" + name] = data
    members = public_inventory(plan, by_hash, key)
    # Use bytes read back from the stores for every retained signed object.
    members.update(actual_signed)
    unchanged(stage)
    unchanged(output)
    require_all_custody_closed()
    write_new(deploy, members)
    actual = snapshot(deploy)
    if actual.members != members:
        _refuse("FINAL_PUBLIC_INVENTORY")
    return {"schema": "tf.current-public-repository-verification.v1", "status": "pass",
            "native_crypto_verified": True, "source_admission": "unestablished",
            "publication_authority": False, "native_client_qualification": False,
            "signed_store_records": len(retained), "public_key_sha256": apt.PUBLIC_KEY_SHA256,
            "files": inventory(actual.members)}
