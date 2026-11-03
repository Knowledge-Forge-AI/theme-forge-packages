"""Bind installed-client probes through fresh authenticated public releases.

This source proof grants no signing, installation or publication authority.
The existing RS9 factory owns the process-local probe capabilities. No receipt
or serialized mapping is used to reconstruct those capabilities.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import re
import shutil
import tarfile
from typing import Any

from publication_github_api import PublicationError, refuse
from source_closure import ClosureError, held_regular_bytes, parse_strict_json

GENERATION = "theme-forge-current-202610"
P_CONTRACT = "tools/verification/current-command-contracts.json"
R_CONTRACT = "operators/theme-forge-current-202610/command-contracts.json"
CONTRACT_SCHEMA = "rs9.command-contracts.v1alpha1"
BINDING_SCHEMA = "tf.current-client-command-source-binding.v1"
PRODUCTS = frozenset({
    "theme-forge-stellar-burst",
    "theme-forge-stellar-loom",
    "theme-forge-solar-sail",
    "theme-forge-nebular-fusion",
})
COMMAND_PROJECTS = {
    "tfsb": "theme-forge-stellar-burst",
    "tfsb-studio-service": "theme-forge-stellar-burst",
    "tfsl": "theme-forge-stellar-loom",
    "tfsl-batch": "theme-forge-stellar-loom",
    "tfss": "theme-forge-solar-sail",
    "tfnf": "theme-forge-nebular-fusion",
}
STUDIO_EXTRA_GUARD_FILES = frozenset({
    "dist/service-protocol/v1-types.js",
    "dist/service-protocol/v1-validate.js",
    "dist/service-protocol/v1-registry.js",
})
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_IMPLEMENTATION_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100000


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_contract_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = held_regular_bytes(path)
        return parse_strict_json(raw, "COMMAND_CONTRACT"), raw
    except ClosureError:
        raise PublicationError("COMMAND_CONTRACT") from None


def _checked_contracts(p_root: Path, r_root: Path) -> tuple[dict[str, Any], str, str]:
    p_doc, p_bytes = _read_contract_json(p_root / P_CONTRACT)
    r_doc, r_bytes = _read_contract_json(r_root / R_CONTRACT)
    if (p_doc.get("schema") != CONTRACT_SCHEMA or r_doc.get("schema") != CONTRACT_SCHEMA
            or p_doc.get("generation") != GENERATION or r_doc.get("generation") != GENERATION
            or p_doc.get("production_enabled") is not False):
        refuse("COMMAND_CONTRACT")
    p_rows, r_rows = p_doc.get("commands"), r_doc.get("commands")
    if (not isinstance(p_rows, dict) or not isinstance(r_rows, dict)
            or set(p_rows) != set(r_rows) or set(p_rows) != set(COMMAND_PROJECTS)):
        refuse("COMMAND_CONTRACT")
    if any(not isinstance(row, dict) for row in p_rows.values()) or any(not isinstance(row, dict) for row in r_rows.values()):
        refuse("COMMAND_CONTRACT")
    if {row.get("project") for row in p_rows.values()} != PRODUCTS:
        refuse("COMMAND_CONTRACT")
    for name, row in p_rows.items():
        other = r_rows[name]
        if row.get("project") != COMMAND_PROJECTS[name]:
            refuse("COMMAND_CONTRACT")
        for field in ("project", "implementation_paths", "source_guards"):
            if row.get(field) != other.get(field):
                refuse("COMMAND_CONTRACT")
        impl_paths = row.get("implementation_paths")
        guards = row.get("source_guards")
        if (not isinstance(impl_paths, list) or not impl_paths
                or any(not isinstance(p, str) or not p for p in impl_paths)
                or not isinstance(guards, list) or not guards
                or any(not isinstance(g, str) or not g for g in guards)):
            refuse("COMMAND_CONTRACT")
        ev, other_ev = row.get("evidence"), other.get("evidence")
        if not isinstance(ev, dict) or not isinstance(other_ev, dict):
            refuse("COMMAND_CONTRACT")
        for field in ("repository", "commit", "tag"):
            val = ev.get(field)
            if not isinstance(val, str) or not val or val != other_ev.get(field):
                refuse("COMMAND_CONTRACT")
        if not HEX40.fullmatch(ev["commit"]):
            refuse("COMMAND_CONTRACT")
        expected, other_expected = row.get("implementation_sha256"), other.get("implementation_sha256")
        if (not isinstance(expected, dict) or not expected
                or not isinstance(other_expected, dict) or not other_expected
                or any(not isinstance(k, str) or not k or not isinstance(v, str) or not HEX64.fullmatch(v)
                       for k, v in expected.items())
                or any(not isinstance(k, str) or not k or not isinstance(v, str) or not HEX64.fullmatch(v)
                       for k, v in other_expected.items())
                or any(expected.get(k) != v for k, v in other_expected.items())):
            refuse("COMMAND_CONTRACT")
        extra_impl = set(expected) - set(other_expected)
        if extra_impl and (name != "tfsb-studio-service" or extra_impl != STUDIO_EXTRA_GUARD_FILES):
            refuse("COMMAND_CONTRACT")
        probes, old_probes = row.get("probes"), other.get("probes")
        if (not isinstance(probes, list) or not isinstance(old_probes, list)
                or not probes or len(probes) != len(old_probes)):
            refuse("COMMAND_CONTRACT")
        for probe, old in zip(probes, old_probes):
            if (not isinstance(probe, dict) or not probe
                    or not isinstance(old, dict) or not old
                    or any(probe.get(k) != v for k, v in old.items())):
                refuse("COMMAND_CONTRACT")
            extras = set(probe) - set(old)
            if extras and (name != "tfsb-studio-service" or extras != {"exchange", "protocol", "selectedVersion"}
                          or probe["exchange"] != ["initialize", "initialized", "shutdown", "exit"]
                          or probe["protocol"] != "tfsb.studio" or probe["selectedVersion"] != "1.0"):
                refuse("COMMAND_CONTRACT")
    return p_rows, _sha(p_bytes), _sha(r_bytes)


def _check_capture(capture: Any, intent: Any, rows: Any, authenticate: Any) -> tuple[str, str]:
    if not callable(authenticate):
        refuse("COMMAND_CAPTURE_AUTH")
    try:
        release_hash = authenticate(capture)
    except Exception:
        raise PublicationError("COMMAND_CAPTURE_AUTH") from None
    if not isinstance(release_hash, str) or not HEX64.fullmatch(release_hash):
        refuse("COMMAND_CAPTURE_AUTH")
    if not isinstance(intent, dict) or not isinstance(intent.get("project"), dict):
        refuse("COMMAND_CAPTURE_SET")
    project = intent["project"].get("id")
    if not isinstance(project, str) or project not in PRODUCTS or not isinstance(rows, dict) or not rows:
        refuse("COMMAND_CAPTURE_SET")
    if any(not isinstance(r, dict) for r in rows.values()):
        refuse("COMMAND_CONTRACT")
    selected = {name: row for name, row in rows.items() if row.get("project") == project}
    if not selected:
        refuse("COMMAND_CAPTURE_SET")
    for row in selected.values():
        impl = row.get("implementation_sha256")
        ev = row.get("evidence")
        if (not isinstance(impl, dict) or not impl
                or any(not isinstance(k, str) or not k or not isinstance(v, str) or not HEX64.fullmatch(v)
                       for k, v in impl.items())
                or not isinstance(ev, dict)
                or any(not isinstance(ev.get(f), str) or not ev.get(f) for f in ("repository", "commit", "tag"))
                or not HEX40.fullmatch(ev["commit"])):
            refuse("COMMAND_CONTRACT")
    record = getattr(capture, "record", None)
    archives = getattr(capture, "archives", None)
    source = getattr(capture, "source", None)
    if not isinstance(record, dict) or not isinstance(archives, dict) or not isinstance(source, dict):
        refuse("COMMAND_CAPTURE_SET")
    if any(not isinstance(k, str) or not isinstance(v, bytes) for k, v in source.items()):
        refuse("COMMAND_IMPLEMENTATION_CHANGED")
    payloads = record.get("payloads")
    if not isinstance(payloads, list) or not payloads:
        refuse("COMMAND_CAPTURE_SET")
    paths = set().union(*(set(row["implementation_sha256"]) for row in selected.values()))
    archived: dict[str, bytes] = {}
    for payload in payloads:
        if (not isinstance(payload, dict) or "id" not in payload
                or not isinstance(payload.get("sha256"), str) or not HEX64.fullmatch(payload["sha256"])
                or payload["id"] not in archives):
            refuse("COMMAND_ARCHIVE_CHANGED")
        try:
            data = archives[payload["id"]].read_bytes()
        except Exception:
            raise PublicationError("COMMAND_ARCHIVE_CHANGED") from None
        if not isinstance(data, bytes) or _sha(data) != payload["sha256"]:
            refuse("COMMAND_ARCHIVE_CHANGED")
        seen_in_payload: set[str] = set()
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for count, member in enumerate(archive, 1):
                    if count > MAX_ARCHIVE_ENTRIES:
                        refuse("COMMAND_ARCHIVE_BOUND")
                    suffix = member.name.split("/", 1)[-1]
                    if suffix in paths:
                        if not member.isfile() or suffix in seen_in_payload:
                            refuse("COMMAND_IMPLEMENTATION_CHANGED")
                        seen_in_payload.add(suffix)
                        if not 0 <= member.size <= MAX_IMPLEMENTATION_BYTES:
                            refuse("COMMAND_IMPLEMENTATION_BOUND")
                        handle = archive.extractfile(member)
                        if handle is None:
                            refuse("COMMAND_IMPLEMENTATION_MISSING")
                        with handle:
                            body = handle.read(MAX_IMPLEMENTATION_BYTES + 1)
                        if len(body) != member.size or (suffix in archived and archived[suffix] != body):
                            refuse("COMMAND_IMPLEMENTATION_CHANGED")
                        archived[suffix] = body
        except PublicationError:
            raise
        except (tarfile.TarError, OSError, EOFError):
            raise PublicationError("COMMAND_ARCHIVE_CHANGED") from None
    repo_info = record.get("repository")
    tag_info = record.get("tag")
    rel_info = record.get("release")
    if not isinstance(repo_info, dict) or not isinstance(tag_info, dict) or not isinstance(rel_info, dict):
        refuse("COMMAND_RELEASE_CHANGED")
    evidence = dict(source)
    evidence.update(archived)
    for row in selected.values():
        if (repo_info.get("full_name") != row["evidence"]["repository"]
                or tag_info.get("commit") != row["evidence"]["commit"]
                or rel_info.get("tag") != row["evidence"]["tag"]):
            refuse("COMMAND_RELEASE_CHANGED")
        for path, digest in row["implementation_sha256"].items():
            if path not in evidence or _sha(evidence[path]) != digest:
                refuse("COMMAND_IMPLEMENTATION_CHANGED")
            if path in source and _sha(source[path]) != digest:
                refuse("COMMAND_IMPLEMENTATION_CHANGED")
        for path in row.get("implementation_paths", ()):
            if path in archived and path in source and source[path] != archived[path]:
                refuse("COMMAND_IMPLEMENTATION_CHANGED")
    return project, release_hash


def bind_current_commands(p_root: Path, r_root: Path, work_root: Path, *, r_commit: str, client: Any) -> dict[str, Any]:
    """Capture/inspect public releases, then call the existing live RS9 factory."""
    from rs9.candidate import capture_generation
    from rs9.hosted_commands import _BOUND, _CAPABILITIES, bind_commands
    from rs9.release_core import authenticated_record_hash
    if type(r_commit) is not str or not HEX40.fullmatch(r_commit):
        refuse("COMMAND_SOURCE")
    if client is None:
        refuse("COMMAND_CLIENT")
    rows, p_sha, r_sha = _checked_contracts(p_root, r_root)
    try:
        work_root.mkdir(mode=0o700)
        captures_root = work_root / "captures"
        captures_root.mkdir(mode=0o700)
    except OSError:
        raise PublicationError("COMMAND_WORK_ROOT") from None
    try:
        try:
            captures = capture_generation(
                r_root, captures_root, client=client,
                checkout_binding="hosted:" + r_commit, generation=GENERATION,
            )
        except PublicationError:
            raise
        except OSError:
            raise PublicationError("COMMAND_CAPTURE_IO") from None
        except Exception:
            raise PublicationError("COMMAND_CAPTURE") from None
        if not isinstance(captures, (list, tuple)) or len(captures) != len(PRODUCTS):
            refuse("COMMAND_CAPTURE_SET")
        releases: dict[str, str] = {}
        for item in captures:
            if not isinstance(item, (list, tuple)) or len(item) != 3:
                refuse("COMMAND_CAPTURE_SET")
            capture, intent, _profile = item
            project, digest = _check_capture(capture, intent, rows, authenticated_record_hash)
            if project in releases:
                refuse("COMMAND_CAPTURE_SET")
            releases[project] = digest
        if set(releases) != PRODUCTS:
            refuse("COMMAND_CAPTURE_SET")
        try:
            receipt_path = bind_commands(captures, r_root, work_root, generation=GENERATION)
            receipt = parse_strict_json(held_regular_bytes(receipt_path), "COMMAND_BINDING")
        except PublicationError:
            raise
        except Exception:
            raise PublicationError("COMMAND_BINDING") from None
        bindings = receipt.get("commands")
        if (receipt.get("generation") != GENERATION or not isinstance(bindings, dict)
                or set(bindings) != set(rows)
                or any(not isinstance(row, dict) or row.get("status") != "bound"
                       or row.get("release_record_sha256") != releases.get(rows[name]["project"])
                       for name, row in bindings.items())):
            refuse("COMMAND_BINDING")
        if (set(_BOUND) != set(rows) or set(_CAPABILITIES) != set(rows)
                or any(_CAPABILITIES.get(name) is not _BOUND.get(name)
                       or not isinstance(_BOUND.get(name), dict)
                       or _BOUND[name].get("status") != "bound"
                       or _BOUND[name].get("generation") != GENERATION
                       or _BOUND[name].get("release_record_sha256") != releases.get(rows[name]["project"])
                       for name in rows)):
            refuse("COMMAND_BINDING")
    finally:
        if captures_root.exists():
            shutil.rmtree(captures_root, ignore_errors=True)
    if captures_root.exists():
        refuse("COMMAND_CAPTURE_CLEANUP")
    return {
        "schema": BINDING_SCHEMA,
        "status": "bound",
        "p_command_contract_sha256": p_sha,
        "r_command_contract_sha256": r_sha,
        "release_record_sha256": dict(sorted(releases.items())),
        "commands": sorted(bindings),
        "native_client_execution": False,
        "publication_authority": False,
    }
