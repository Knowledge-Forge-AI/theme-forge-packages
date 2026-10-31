"""Private manifest, facts, catalog, and reviewed-source binding boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType
from typing import Any, Mapping

_MODULE_DIR = str(Path(__file__).resolve(strict=True).parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from b3_fixture_types import (
    CANONICAL_SUBSET_PATH,
    CANONICAL_SUBSET_SHA256,
    CURRENT_IMAGE_CATALOG_SELECTORS,
    CURRENT_TOOLCHAIN_CATALOG_PATH,
    CURRENT_TOOLCHAIN_CATALOG_SCHEMA,
    CURRENT_TOOLCHAIN_CATALOG_SHA256,
    FACTS_SCHEMA,
    IMAGE_CATALOG_PATH,
    IMAGE_CATALOG_SELECTORS,
    IMAGE_CATALOG_SHA256,
    MAX_JSON_BYTES,
    MAX_SOURCE_BYTES,
    NATIVE_TOOLS,
    REVIEWED_C6_SOURCE_PATH,
    REVIEWED_C6_SOURCE_SHA256,
    SCHEMA,
    STAGE1_AUTH_SCHEMA,
    TARGET_AGENT_MODE,
    TARGET_GNUPG_VERSION,
    TARGET_RPM_VERSION,
    FixtureError,
    FixtureSpec,
)


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_FORBIDDEN_FACT_KEYS = {"private", "passphrase", "password", "secret", "credential", "token", "key_path", "secret_path"}


def _absolute_path(value: str | os.PathLike[str], label: str) -> Path:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or "\x00" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise FixtureError(f"{label.upper().replace(' ', '_')}_PATH")
    return Path(raw)


def _packet_role_path(value: str | os.PathLike[str], label: str) -> Path:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or not raw
        or raw.startswith("/")
        or "\x00" in raw
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise FixtureError(f"{label.upper().replace(' ', '_')}_PORTABLE_PATH")
    root = Path(__file__).resolve(strict=True).parent
    parts = raw.split("/")
    current = root
    for part in parts[:-1]:
        current /= part
        try:
            info = os.lstat(current)
        except OSError as error:
            raise FixtureError(f"{label.upper().replace(' ', '_')}_PATH_COMPONENT") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise FixtureError(f"{label.upper().replace(' ', '_')}_PATH_COMPONENT")
    return root.joinpath(*parts)


def _regular_nonsymlink(path: Path, label: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise FixtureError(f"{label.upper().replace(' ', '_')}_MISSING") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise FixtureError(f"{label.upper().replace(' ', '_')}_FILE")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json_bytes(path: Path, label: str) -> tuple[bytes, Mapping[str, Any]]:
    _regular_nonsymlink(path, label)
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_JSON_BYTES + 1)
    except OSError as error:
        raise FixtureError(f"{label.upper().replace(' ', '_')}_READ") from error
    if len(data) > MAX_JSON_BYTES:
        raise FixtureError(f"{label.upper().replace(' ', '_')}_TOO_LARGE")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"{label.upper().replace(' ', '_')}_JSON") from error
    if not isinstance(value, dict):
        raise FixtureError(f"{label.upper().replace(' ', '_')}_SHAPE")
    return data, value


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    return _read_json_bytes(path, label)[1]


def _load_current_toolchain_catalog(
    path: Path = CURRENT_TOOLCHAIN_CATALOG_PATH,
    expected_sha256: str = CURRENT_TOOLCHAIN_CATALOG_SHA256,
) -> dict[str, Any]:
    """Authenticate the current B3 toolchain catalog and its base-vs-provisioned contract."""
    data, catalog = _read_json_bytes(path, "image catalog")
    if _sha256_bytes(data) != expected_sha256:
        raise FixtureError("IMAGE_CATALOG_CHANGED")
    if (
        catalog.get("schema") != CURRENT_TOOLCHAIN_CATALOG_SCHEMA
        or catalog.get("production_authority") is not False
    ):
        raise FixtureError("IMAGE_CATALOG_SHAPE")
    base_images = catalog.get("base_images")
    base_vs = catalog.get("base_vs_provisioned")
    attestations = catalog.get("field_attestations")
    historical = catalog.get("historical_g_catalog")
    guards = catalog.get("fixed_tool_guards")
    if (
        not isinstance(base_images, Mapping)
        or not isinstance(base_vs, Mapping)
        or not isinstance(attestations, Mapping)
        or not isinstance(historical, Mapping)
        or not isinstance(guards, Mapping)
    ):
        raise FixtureError("IMAGE_CATALOG_SHAPE")
    images = {"rpm": base_images.get("rpm"), "pacman": base_images.get("pacman")}
    if set(images) != {"rpm", "pacman"} or any(
        not isinstance(value, str) or "@sha256:" not in value for value in images.values()
    ):
        raise FixtureError("IMAGE_CATALOG_VALUES")
    if (
        base_vs.get("bare_base_is_fully_provisioned") is not False
        or base_vs.get("approved_package_subset") != ["gnupg2", "rpm-sign", "python3"]
        or base_vs.get("package_nevr_locked_by_base_digest") is not False
    ):
        raise FixtureError("IMAGE_CATALOG_PROVISIONING_SCOPE")
    if (
        attestations.get("base_images") != "catalog-derived-not-measured"
        or attestations.get("base_vs_provisioned") != "catalog-derived-not-measured"
        or attestations.get("fixed_tool_guards") != "catalog-guard-target-not-measured"
        or attestations.get("historical_g_catalog") != "catalog-derived-not-measured"
        or attestations.get("r_readback_provenance") != "historical-r-readback-not-measured-in-b3"
    ):
        raise FixtureError("IMAGE_CATALOG_ATTESTATION")
    if (
        historical.get("path") != "inputs/DIST1-VALIDATION-WORKFLOW-CONTRACT.json"
        or historical.get("sha256") != IMAGE_CATALOG_SHA256
        or historical.get("supplies_current_tools") is not False
    ):
        raise FixtureError("IMAGE_CATALOG_HISTORICAL_BINDING")
    return dict(catalog)


def _load_image_catalog(path: Path = IMAGE_CATALOG_PATH, expected_sha256: str = IMAGE_CATALOG_SHA256) -> dict[str, str]:
    """Derive image bindings from one bounded, hash-checked catalog buffer."""
    if path.name == CURRENT_TOOLCHAIN_CATALOG_PATH.name or expected_sha256 == CURRENT_TOOLCHAIN_CATALOG_SHA256:
        current = _load_current_toolchain_catalog(path, expected_sha256)
        base_images = current["base_images"]
        return {"rpm": str(base_images["rpm"]), "pacman": str(base_images["pacman"])}
    data, catalog = _read_json_bytes(path, "image catalog")
    if _sha256_bytes(data) != expected_sha256:
        raise FixtureError("IMAGE_CATALOG_CHANGED")
    try:
        matrix = catalog["jobs"]["validate-linux"]["matrix"]["x86_64"]
        images = {"rpm": matrix["fedora_container"], "pacman": matrix["arch_container"]}
    except (KeyError, TypeError) as error:
        raise FixtureError("IMAGE_CATALOG_SHAPE") from error
    if set(images) != {"rpm", "pacman"} or any(not isinstance(value, str) or "@sha256:" not in value for value in images.values()):
        raise FixtureError("IMAGE_CATALOG_VALUES")
    return images


def _reject_secret_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and any(part in key.lower() for part in _FORBIDDEN_FACT_KEYS):
                raise FixtureError("FACTS_SECRET_FIELD")
            _reject_secret_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_fields(child)


def _canonical_manifest_fields(
    disposition: Mapping[str, Any], canonical_data: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Authenticate the canonical subset and return its fixed spec fields."""
    disposition_path = _packet_role_path(disposition.get("path", ""), "canonical disposition")
    expected_disposition_sha = disposition.get("sha256")
    if not isinstance(expected_disposition_sha, str) or not _HEX64.fullmatch(expected_disposition_sha):
        raise FixtureError("CANONICAL_DIGEST")
    if (
        disposition_path != CANONICAL_SUBSET_PATH
        or expected_disposition_sha != CANONICAL_SUBSET_SHA256
    ):
        raise FixtureError("CANONICAL_BINDING")
    if canonical_data is None:
        canonical_bytes, canonical_data = _read_json_bytes(disposition_path, "canonical disposition")
        if _sha256_bytes(canonical_bytes) != expected_disposition_sha:
            raise FixtureError("CANONICAL_CHANGED")

    fields = {
        "canonical_commit": canonical_data.get("canonicalCommit"),
        "canonical_source_bytes": canonical_data.get("canonicalAgentBytes"),
        "canonical_source_sha256": canonical_data.get("canonicalAgentSha256"),
        "option_table_lines": canonical_data.get("optionTableVerifiedLines"),
        "canonical_disposition_path": disposition_path,
    }
    if (
        not isinstance(fields["canonical_commit"], str)
        or not _HEX40.fullmatch(fields["canonical_commit"])
        or not isinstance(fields["canonical_source_bytes"], int)
        or fields["canonical_source_bytes"] <= 0
        or not isinstance(fields["canonical_source_sha256"], str)
        or not _HEX64.fullmatch(fields["canonical_source_sha256"])
        or fields["option_table_lines"] != "160-318"
    ):
        raise FixtureError("CANONICAL_FIELDS")
    return fields


def _reviewed_manifest_fields(owned: Mapping[str, Any]) -> dict[str, Any]:
    """Bind only the independently reviewed source role and digest."""
    source_path = _packet_role_path(owned.get("path", ""), "owned agent source")
    source_sha256 = owned.get("sha256")
    if source_path != REVIEWED_C6_SOURCE_PATH or source_sha256 != REVIEWED_C6_SOURCE_SHA256:
        raise FixtureError("REVIEWED_SOURCE_REQUIRED")
    return {"owned_agent_source": source_path, "owned_agent_source_sha256": source_sha256}


def _target_manifest_fields(
    target: Mapping[str, Any], image_catalog: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the fixed tool target and its source-owned catalog binding."""
    if target.get("gnupg_version") != TARGET_GNUPG_VERSION or target.get("agent_mode") != TARGET_AGENT_MODE:
        raise FixtureError("TARGET_GNUPG")
    if target.get("rpm_version") != TARGET_RPM_VERSION:
        raise FixtureError("TARGET_RPM")

    catalog_path = _packet_role_path(image_catalog.get("path", ""), "image catalog")
    catalog_sha256 = image_catalog.get("sha256")
    selectors = image_catalog.get("selectors")
    is_historical = (
        catalog_path == IMAGE_CATALOG_PATH
        and catalog_sha256 == IMAGE_CATALOG_SHA256
        and selectors == IMAGE_CATALOG_SELECTORS
    )
    is_current = (
        catalog_path == CURRENT_TOOLCHAIN_CATALOG_PATH
        and catalog_sha256 == CURRENT_TOOLCHAIN_CATALOG_SHA256
        and selectors == CURRENT_IMAGE_CATALOG_SELECTORS
    )
    if not (is_historical or is_current):
        raise FixtureError("IMAGE_CATALOG_BINDING")
    catalog_images = _load_image_catalog(catalog_path, catalog_sha256)
    if target.get("images") != catalog_images:
        raise FixtureError("TARGET_IMAGES")
    return {
        "target_gnupg_version": target["gnupg_version"],
        "target_agent_mode": target["agent_mode"],
        "target_rpm_version": target["rpm_version"],
        "images": dict(catalog_images),
        "image_catalog_path": catalog_path,
        "image_catalog_sha256": catalog_sha256,
    }


def validate_manifest(raw: Mapping[str, Any], *, canonical_data: Mapping[str, Any] | None = None) -> FixtureSpec:
    """Validate private source/input bindings and derive canonical fields from C6 JSON."""
    if raw.get("schema") != SCHEMA or raw.get("production_authority") is not False:
        raise FixtureError("MANIFEST_SCHEMA")
    sections = {name: raw.get(name) for name in (
        "canonical_disposition", "owned_agent", "target", "image_catalog",
    )}
    if not all(isinstance(value, Mapping) for value in sections.values()):
        raise FixtureError("MANIFEST_SHAPE")
    historical = raw.get("historical_image_catalog")
    if historical is not None:
        if not isinstance(historical, Mapping):
            raise FixtureError("MANIFEST_SHAPE")
        hist_path = _packet_role_path(historical.get("path", ""), "historical image catalog")
        if (
            hist_path != IMAGE_CATALOG_PATH
            or historical.get("sha256") != IMAGE_CATALOG_SHA256
            or historical.get("selectors") != IMAGE_CATALOG_SELECTORS
            or historical.get("supplies_current_tools") is not False
        ):
            raise FixtureError("HISTORICAL_CATALOG_BINDING")
        _load_image_catalog(hist_path, IMAGE_CATALOG_SHA256)
    return FixtureSpec(
        **_canonical_manifest_fields(sections["canonical_disposition"], canonical_data),
        **_reviewed_manifest_fields(sections["owned_agent"]),
        **_target_manifest_fields(sections["target"], sections["image_catalog"]),
    )


def load_manifest(path: str | os.PathLike[str]) -> FixtureSpec:
    manifest_path = _absolute_path(path, "manifest")
    _, raw = _read_json_bytes(manifest_path, "manifest")
    return validate_manifest(raw)


def validate_measured_facts(raw: Mapping[str, Any], spec: FixtureSpec) -> dict[str, Any]:
    """Validate supplied non-secret declarations or Stage 2 container measurements."""
    _reject_secret_fields(raw)
    if raw.get("schema") != FACTS_SCHEMA or raw.get("execution_mode") not in {"hosted-native", "fixture"}:
        raise FixtureError("FACTS_SCHEMA")
    attestation = raw.get("attestation", "caller-declared-not-measured")
    if attestation not in {"caller-declared-not-measured", "measured-in-container-stage2"}:
        raise FixtureError("FACTS_ATTESTATION_INVALID")
    if attestation == "measured-in-container-stage2" and raw.get("execution_mode") != "hosted-native":
        raise FixtureError("FACTS_ATTESTATION_INVALID")
    images_attestation = raw.get("images_attestation", "catalog-derived-not-measured")
    if images_attestation != "catalog-derived-not-measured":
        raise FixtureError("FACTS_CATALOG_ATTESTATION_INVALID")
    tools = raw.get("tools")
    if not isinstance(tools, Mapping) or set(tools) != set(NATIVE_TOOLS):
        raise FixtureError("FACTS_TOOLS")
    expected_tool_attestation = (
        "measured-in-container"
        if attestation == "measured-in-container-stage2"
        else "caller-declared-not-measured"
    )
    tool_summary: dict[str, Any] = {}
    for name, path in NATIVE_TOOLS.items():
        fact = tools.get(name)
        if not isinstance(fact, Mapping):
            raise FixtureError("FACTS_TOOL_SHAPE")
        if fact.get("path") != path or fact.get("version_line") != f"{name} (GnuPG) {TARGET_GNUPG_VERSION}":
            raise FixtureError("FACTS_TOOL_TARGET")
        if not isinstance(fact.get("sha256"), str) or not _HEX64.fullmatch(fact["sha256"]):
            raise FixtureError("FACTS_TOOL_DIGEST")
        fact_attestation = fact.get("sha256_attestation", expected_tool_attestation)
        if fact_attestation != expected_tool_attestation:
            raise FixtureError("FACTS_ATTESTATION_INVALID")
        tool_summary[name] = {
            "path": path,
            "version_line": fact["version_line"],
            "sha256": fact["sha256"],
            "sha256_attestation": expected_tool_attestation,
        }
    if raw.get("images") != dict(spec.images):
        raise FixtureError("FACTS_IMAGES")
    result: dict[str, Any] = {
        "attestation": attestation,
        "execution_mode": raw["execution_mode"],
        "tools": tool_summary,
        "images": dict(spec.images),
    }
    if "images_attestation" in raw or attestation == "measured-in-container-stage2":
        result["images_attestation"] = "catalog-derived-not-measured"
    return result


def _load_owned_agent(spec: FixtureSpec) -> ModuleType:
    """Execute only the independently reviewed, exact-hash C6 source bytes."""
    if spec.owned_agent_source != REVIEWED_C6_SOURCE_PATH or spec.owned_agent_source_sha256 != REVIEWED_C6_SOURCE_SHA256:
        raise FixtureError("REVIEWED_SOURCE_REQUIRED")
    _regular_nonsymlink(spec.owned_agent_source, "owned agent source")
    try:
        with spec.owned_agent_source.open("rb") as handle:
            source_bytes = handle.read(MAX_SOURCE_BYTES + 1)
    except OSError as error:
        raise FixtureError("OWNED_SOURCE_READ") from error
    if len(source_bytes) > MAX_SOURCE_BYTES:
        raise FixtureError("OWNED_SOURCE_TOO_LARGE")
    if _sha256_bytes(source_bytes) != REVIEWED_C6_SOURCE_SHA256:
        raise FixtureError("OWNED_SOURCE_CHANGED")
    module_name = f"tf_b3_owned_gpg_agent_{REVIEWED_C6_SOURCE_SHA256}"
    module = ModuleType(module_name)
    module.__file__ = str(spec.owned_agent_source)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(source_bytes, str(spec.owned_agent_source), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException as error:
        if sys.modules.get(module_name) is module:
            sys.modules.pop(module_name, None)
        raise FixtureError("OWNED_SOURCE_IMPORT") from error
    if (
        getattr(module, "TARGET_GNUPG_VERSION", None) != spec.target_gnupg_version
        or getattr(module, "NATIVE_GPGCONF", None) != NATIVE_TOOLS["gpgconf"]
        or getattr(module, "NATIVE_GPG_AGENT", None) != NATIVE_TOOLS["gpg-agent"]
        or getattr(module, "NATIVE_GPG", None) != NATIVE_TOOLS["gpg"]
        or not hasattr(module, "OwnedGpgAgent")
    ):
        raise FixtureError("OWNED_SOURCE_CONTRACT")
    return module


def authenticate_stage1(manifest_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Authenticate C6 source, B3 modules, toolchain catalogs, and promotion list without native execution."""
    resolved_manifest = _absolute_path(manifest_path, "manifest")
    manifest_bytes, raw = _read_json_bytes(resolved_manifest, "manifest")
    spec = validate_manifest(raw)
    module = _load_owned_agent(spec)
    current_catalog = _load_current_toolchain_catalog()
    historical_images = _load_image_catalog(IMAGE_CATALOG_PATH, IMAGE_CATALOG_SHA256)

    prepared = raw.get("prepared_modules")
    if not isinstance(prepared, Mapping) or set(prepared) != {"entrypoint", "inputs", "tests", "types", "workspace"}:
        raise FixtureError("PREPARED_MODULES_SHAPE")
    verified_modules: dict[str, str] = {}
    for role, entry in prepared.items():
        if not isinstance(entry, Mapping):
            raise FixtureError("PREPARED_MODULES_SHAPE")
        mod_path = _packet_role_path(entry.get("path", ""), f"prepared module {role}")
        expected_sha = entry.get("sha256")
        if not isinstance(expected_sha, str) or not _HEX64.fullmatch(expected_sha):
            raise FixtureError("PREPARED_MODULE_DIGEST")
        _regular_nonsymlink(mod_path, f"prepared module {role}")
        actual_sha = _sha256_bytes(mod_path.read_bytes())
        if actual_sha != expected_sha:
            raise FixtureError("PREPARED_MODULE_CHANGED")
        verified_modules[role] = actual_sha

    promo_rel = raw.get("promotion_list")
    if not isinstance(promo_rel, str):
        raise FixtureError("PROMOTION_LIST_BINDING")
    promo_path = _packet_role_path(promo_rel, "promotion list")
    _, promo = _read_json_bytes(promo_path, "promotion list")
    if promo.get("schema") != "tf.current-signer-native-b3-fixture-promotion-list.v1" or promo.get("intended_promotion") is not True:
        raise FixtureError("PROMOTION_LIST_SCHEMA")
    promo_files = promo.get("files")
    if not isinstance(promo_files, list) or not promo_files:
        raise FixtureError("PROMOTION_LIST_FILES")
    manifest_sha = _sha256_bytes(manifest_bytes)
    verified_count = 0
    for item in promo_files:
        if not isinstance(item, Mapping):
            raise FixtureError("PROMOTION_LIST_FILES")
        item_path = _packet_role_path(item.get("path", ""), "promotion file")
        item_sha = item.get("sha256")
        if not isinstance(item_sha, str) or not _HEX64.fullmatch(item_sha):
            raise FixtureError("PROMOTION_FILE_DIGEST")
        _regular_nonsymlink(item_path, "promotion file")
        if _sha256_bytes(item_path.read_bytes()) != item_sha:
            raise FixtureError("PROMOTION_FILE_CHANGED")
        verified_count += 1

    return {
        "schema": STAGE1_AUTH_SCHEMA,
        "status": "stage1-authenticated",
        "production_authority": False,
        "native_execution_observed": False,
        "canonical_commit": spec.canonical_commit,
        "owned_agent_sha256": spec.owned_agent_source_sha256,
        "owned_agent_contract_verified": getattr(module, "TARGET_GNUPG_VERSION", None) == TARGET_GNUPG_VERSION,
        "manifest_sha256": manifest_sha,
        "current_toolchain_catalog_sha256": CURRENT_TOOLCHAIN_CATALOG_SHA256,
        "historical_image_catalog_sha256": IMAGE_CATALOG_SHA256,
        "current_images": dict(current_catalog["base_images"]),
        "historical_images": historical_images,
        "images_attestation": "catalog-derived-not-measured",
        "bare_base_is_fully_provisioned": False,
        "approved_package_subset": list(current_catalog["base_vs_provisioned"]["approved_package_subset"]),
        "prepared_modules_verified": verified_modules,
        "promotion_files_verified": verified_count,
    }
