"""PROPOSED, UNADOPTED pure linkage for the post-cleanup public repository join.

Input is two bounded byte snapshots taken after the single private signing
runtime is confirmed closed: the unsigned routing stage and the private signed
output.  The routing record is DATA, never source admission: every row,
destination, APT member, pool DEB and package byte is re-derived and bound
here; source admission stays unestablished until the overall orchestrator
supplies a fresh RS9/ProductionSource proof.  No crypto runs here.  The plan
names exactly which signed objects concrete pinned native adapters must
authenticate, and binds every unsigned companion (APT tree, RPM repodata,
pacman databases/aliases, pacman packages) to those signed objects by bytes.

Reuses (unchanged): the importer's Release/Packages/member-map helpers, the
private metadata parsers ``_rpm_metadata``/``_pacman_entries``/``_gunzip``,
``inspect_rpm_preservation`` and RS9 ``parse_deb_control``/``clearsigned_body``.
Only the public pacman NAME/VERSION/ARCH and %FILES% grammar is new.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import tarfile
from typing import Mapping
from types import MappingProxyType

import apt_signature_adapter as _apt
import current_import_routing as routing
import protected_signing_runtime as _runtime
import repository_metadata_assembly as metadata
from detached_signature_adapter import require_signature_encoding
from current_protected_signing import ProtectedSigningError
from rs9.errors import ContractError
from rs9.repo_apt import clearsigned_body, parse_deb_control
from rs9.scratch import canonical

ROUTING_FILE = "unsigned-routing.json"
ROUTING_SCHEMA = "theme-forge.current-unsigned-routing.v1"
APT_DIST = "dists/" + routing.APT_DISTRIBUTION
INRELEASE, RELEASE_GPG = APT_DIST + "/InRelease", APT_DIST + "/Release.gpg"
APT_BY_HASH = APT_DIST + "/by-hash/SHA256/"
RPM_ARCHES = metadata.RPM_ARCHITECTURES
PACMAN_ARCHES = metadata.PACMAN_ARCHITECTURES
PACMAN_BASES = {arch: "arch/" + arch for arch in PACMAN_ARCHES}
PACMAN_BASE = PACMAN_BASES[metadata.PACMAN_ARCHITECTURE]  # established x86_64 name, unchanged
PACMAN_ARCHIVES = (metadata.PACMAN_DATABASE, metadata.PACMAN_FILES)
# Deliberate export of the committed P public key; path mirrors the P source path.
PUBLIC_KEY_PATH = "keys/knowledge-forge-ai-packages.asc"
SIGNED_KINDS = ("apt-inrelease", "apt-release-gpg", "rpm-package", "rpm-metadata",
                "pacman-package", "pacman-database")
_MARKER = {"deb": "all", "rpm": "noarch", "pacman": "any"}
_NATIVE_ARCHES = {"deb": ("amd64", "arm64"), "rpm": RPM_ARCHES, "pacman": PACMAN_ARCHES}
_PURE = frozenset({"theme-forge-stellar-loom", "theme-forge-solar-sail"})
_ROW_KEYS = frozenset({"family", "product", "name", "version", "architecture", "sha256", "size",
                       "origins", "destinations"})
_ROUTING_KEYS = frozenset({"schema", "p_source", "rs9_original", "own_repository_admission", "objects",
                           "apt_indices", "signed", "assembly_ready", "production_enabled",
                           "publication_authority", "pending"})
_HEX = re.compile(r"[0-9a-f]{64}")
_DESC_KEY = re.compile(r"%[A-Z0-9]{1,32}%")


class PublicJoinError(ContractError):
    """Stable, non-sensitive refusal; messages never echo input values."""


def fail(code: str, message: str):
    raise PublicJoinError(code, message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class SignedObject:
    """One object a pinned native adapter must authenticate before retention.

    ``rel_path`` is in its SignedStore namespace: the APT store is rooted at
    ``apt/`` (``AptRepositoryCandidate`` paths); the package store at the
    deployment root.
    """
    store: str
    rel_path: str
    kind: str
    unsigned: bytes
    signed: bytes

    @property
    def deploy_path(self) -> str:
        return "apt/" + self.rel_path if self.store == "apt" else self.rel_path


@dataclass(frozen=True)
class PublicPlan:
    signed: tuple[SignedObject, ...]
    companions: Mapping[str, bytes]
    release: bytes
    counts: Mapping[str, int]
    source_admission: str = "unestablished"


def _member(tree: Mapping[str, bytes], relative: str, digest: str, size: int) -> bytes:
    data = tree.get(relative)
    if type(data) is not bytes or len(data) != size or sha(data) != digest:
        fail("UNSIGNED_MEMBER", "Unsigned stage member is missing or differs from routing")
    return data


def _pacman_identity(name: str, product: str, version: str, arch: str) -> tuple[str, str, str]:
    suffix = ".pkg.tar.zst"
    stem = name[:-len(suffix)] if name.endswith(suffix) else ""
    rest, _, found_arch = stem.rpartition("-")
    base, _, pkgrel = rest.rpartition("-")
    if base != f"{product}-{version}" or found_arch != arch or not re.fullmatch(r"[1-9][0-9]{0,5}", pkgrel):
        fail("ROUTING_RECORD", "Pacman package filename disagrees with routing identity")
    return product, f"{version}-{pkgrel}", arch


def _routing_rows(stage: Mapping[str, bytes]) -> tuple[list[dict], dict]:
    """Re-validate the routing record as data; it confers no admission."""
    data = stage.get(ROUTING_FILE)
    try:
        frozen = json.loads(data.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, ValueError):
        fail("ROUTING_RECORD", "Unsigned routing record is not JSON")
    if (type(frozen) is not dict or set(frozen) != _ROUTING_KEYS or canonical(frozen) != data
            or frozen["schema"] != ROUTING_SCHEMA
            or any(frozen[key] is not False for key in
                   ("signed", "assembly_ready", "production_enabled", "publication_authority"))):
        fail("ROUTING_RECORD", "Unsigned routing record is not the canonical non-admitting shape")
    rows = frozen["objects"]
    if type(rows) is not list or not 0 < len(rows) <= routing.MAX_SIGNING_MEMBERS:
        fail("ROUTING_RECORD", "Routing object list is not closed")
    identities, names, arches = set(), set(), {}
    for row in rows:
        if (type(row) is not dict or set(row) != _ROW_KEYS
                or any(type(row[key]) is not str for key in ("family", "product", "name", "version",
                                                             "architecture", "sha256"))
                or row["family"] not in _MARKER or row["product"] not in routing.VERSIONS
                or row["version"] != routing.VERSIONS[row["product"]]
                or PurePosixPath(row["name"]).name != row["name"] or not _HEX.fullmatch(row["sha256"])
                or type(row["size"]) is not int or not 0 < row["size"] <= routing.MAX_PACKAGE):
            fail("ROUTING_RECORD", "Routing row is not closed")
        family, product, arch, name = row["family"], row["product"], row["architecture"], row["name"]
        if arch != _MARKER[family] if product in _PURE else arch not in _NATIVE_ARCHES[family]:
            fail("ROUTING_RECORD", "Routing architecture disagrees with product scope")
        version = row["version"]
        if family == "deb":
            if not (name.startswith(f"{product}_{version}-") and name.endswith(f"_{arch}.deb")):
                fail("ROUTING_RECORD", "DEB filename disagrees with routing identity")
        elif family == "rpm":
            if not (name.startswith(f"{product}-{version}-") and name.endswith(f".{arch}.rpm")):
                fail("ROUTING_RECORD", "RPM filename disagrees with routing identity")
        else:
            _pacman_identity(name, product, version, arch)
        expected = ([f"unsigned/rpm/{a}/{name}" for a in (sorted(RPM_ARCHES) if arch == "noarch" else (arch,))]
                    if family == "rpm" else [f"unsigned/{family}/{name}"])
        if (row["destinations"] != expected or (family, product, arch) in identities
                or (family, name) in names):
            fail("ROUTING_RECORD", "Routing destination or identity is not exact")
        identities.add((family, product, arch))
        names.add((family, name))
        arches.setdefault((family, product), set()).add(arch)
    for family, native in _NATIVE_ARCHES.items():
        for product in routing.VERSIONS:
            want = {_MARKER[family]} if product in _PURE else set(native)
            if arches.get((family, product)) != want:
                fail("ROUTING_RECORD", "Routing does not cover the exact current products and systems")
    return rows, frozen["apt_indices"]


def _apt_members(stage: Mapping[str, bytes], anchor, deb_rows: dict) -> tuple[dict, bytes]:
    """Re-derive the exact APT member map from stage bytes (importer helpers)."""
    keys = {"distribution", "release_sha256", "release_size", "indices", "members"}
    if (type(anchor) is not dict or set(anchor) != keys or anchor["distribution"] != routing.APT_DISTRIBUTION
            or type(anchor["members"]) is not list or type(anchor["indices"]) is not dict
            or type(anchor["release_size"]) is not int or type(anchor["release_sha256"]) is not str):
        fail("APT_LINKAGE", "Routing APT anchor is not closed")
    frozen = {}
    for item in anchor["members"]:
        if type(item) is not dict or set(item) != {"path", "sha256", "size"} or item.get("path") in frozen:
            fail("APT_LINKAGE", "Routing APT member inventory is not closed")
        frozen[item["path"]] = (item["sha256"], item["size"])
    if list(frozen) != sorted(frozen):
        fail("APT_LINKAGE", "Routing APT member inventory is not canonical")
    release = _member(stage, "apt/" + routing.APT_RELEASE, anchor["release_sha256"], anchor["release_size"])
    entries, architectures = routing._apt_release_entries(release)
    if {path: digest for path, (digest, _) in entries.items()} != anchor["indices"]:
        fail("APT_LINKAGE", "APT Release differs from routing indices")
    indices = {path: _member(stage, f"apt/{APT_DIST}/{path}", digest, size)
               for path, (digest, size) in entries.items()}
    pool = {}
    for arch in architectures:
        prefix = f"{routing.APT_COMPONENTS[0]}/binary-{arch}/"
        plain = indices[prefix + "Packages"]
        for name in routing.APT_INDEX_NAMES[1:]:
            if routing._bounded_decompress(indices[prefix + name], name) != plain:
                fail("APT_LINKAGE", "APT compressed index differs from Packages")
        listed = set()
        for stanza in routing._apt_package_stanzas(plain):
            name = PurePosixPath(stanza["Filename"]).name
            row = deb_rows.get(name)
            if (row is None or name in listed or row["architecture"] not in (arch, "all")
                    or (stanza["SHA256"], int(stanza["Size"])) != (row["sha256"], row["size"])
                    or (stanza["Package"], stanza["Version"], stanza["Architecture"])
                    != (row["product"], name.split("_")[1], row["architecture"])
                    or pool.setdefault(name, stanza["Filename"]) != stanza["Filename"]):
                fail("APT_LINKAGE", "APT index package row differs from routing")
            listed.add(name)
        if listed != {name for name, row in deb_rows.items() if row["architecture"] in (arch, "all")}:
            fail("APT_LINKAGE", "APT index package set differs from routing")
    if set(pool) != set(deb_rows):
        fail("APT_LINKAGE", "APT pool differs from routing")
    derived = routing._apt_member_map(anchor["release_sha256"], anchor["release_size"], entries,
                                      [(pool[n], deb_rows[n]["sha256"], deb_rows[n]["size"]) for n in sorted(pool)])
    if derived != frozen:
        fail("APT_LINKAGE", "APT tree differs from routing member inventory")
    for path, (digest, size) in derived.items():
        _member(stage, "apt/" + path, digest, size)
    return derived, release


def _desc_fields(body: bytes) -> dict[str, list[str]]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        fail("PACMAN_LINKAGE", "Pacman desc is not UTF-8")
    fields = {}
    for block in text.strip("\n").split("\n\n") if text.endswith("\n") else ():
        lines = block.split("\n")
        if not _DESC_KEY.fullmatch(lines[0]) or lines[0] in fields or len(lines) < 2:
            fail("PACMAN_LINKAGE", "Pacman desc is malformed")
        fields[lines[0]] = lines[1:]
    return fields


def _files_list(body: bytes) -> None:
    """Pinned repo-add v7.0.0 grammar: %FILES% then LC_ALL=C sort -u relative paths."""
    if (len(body) > metadata.MAX_FILE_LIST_BYTES or not body.startswith(b"%FILES%\n")
            or not body.endswith(b"\n")):
        fail("PACMAN_LINKAGE", "Pacman files list is unbounded or not framed")
    previous = None
    for line in body[8:-1].split(b"\n") if len(body) > 8 else ():
        parts = line[:-1].split(b"/") if line.endswith(b"/") else line.split(b"/")
        if (not line or line.startswith((b"/", b".")) or b"\r" in line or b"\x00" in line
                or any(part in {b"", b".", b".."} for part in parts)
                or (previous is not None and line <= previous)):
            fail("PACMAN_LINKAGE", "Pacman files list entry is unsafe, duplicated or unsorted")
        try:
            line.decode("utf-8")
        except UnicodeDecodeError:
            fail("PACMAN_LINKAGE", "Pacman files list entry is not UTF-8")
        previous = line


def _pacman_archive(archive: bytes, *, files: bool, known: dict, identities: dict) -> None:
    """Existing binding parser, then exact NAME/VERSION/ARCH and files grammar."""
    try:
        bindings = metadata._pacman_entries(archive, files=files)
    except ProtectedSigningError as error:
        fail("PACMAN_LINKAGE", f"Pacman database refused by the existing parser ({error.code})")
    if bindings != known:
        fail("PACMAN_LINKAGE", "Pacman database differs from the signed packages")
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(metadata._gunzip(archive)), mode="r:") as opened:
        for member in opened:
            if not member.isfile():
                continue
            entry, name = member.name.split("/")
            body = opened.extractfile(member).read(metadata.MAX_FILE_LIST_BYTES + 1)
            if name == "files":
                _files_list(body)
                continue
            fields = _desc_fields(body)
            filename = fields["%FILENAME%"][0]
            values = tuple(fields.get(key, ()) for key in ("%NAME%", "%VERSION%", "%ARCH%"))
            if (filename not in identities or any(len(value) != 1 for value in values)
                    or tuple(value[0] for value in values) != identities[filename]
                    or entry != f"{values[0][0]}-{values[1][0]}" or filename in seen):
                fail("PACMAN_LINKAGE", "Pacman desc NAME/VERSION/ARCH differs from routing")
            seen.add(filename)
    if seen != set(identities):
        fail("PACMAN_LINKAGE", "Pacman database entry set differs from routing")


def _signature(data: bytes, *, armored: bool, limit: int) -> bytes:
    if type(data) is not bytes or not 0 < len(data) <= limit or (
            data.startswith(b"-----BEGIN PGP SIGNATURE-----\n") != armored) or (
            not armored and not data[0] & 0x80):
        fail("SIGNATURE_SHAPE", "Signature object is missing, unbounded or has the wrong framing")
    try:
        require_signature_encoding("rpm-metadata" if armored else "pacman-package", data)
    except _apt.SignatureValidationError:
        fail("SIGNATURE_SHAPE", "Signature encoding is incompatible with its package client")
    return data


def _pacman_linkage(rows, unsigned: Mapping[str, bytes], take) -> tuple[dict, list]:
    """Each arch/<arch>: its own native rows plus the SAME any bytes+signature.

    Every database/files index is bound to exactly that architecture's package
    set; the any package is one held original, published byte-identically with
    one identical signature in every repository.
    """
    if any(row["architecture"] not in {*PACMAN_ARCHES, "any"} for row in rows):
        fail("PACMAN_LINKAGE", "Pacman row architecture is foreign")
    companions, signed, shared = {}, [], {}
    for arch in PACMAN_ARCHES:
        base = PACMAN_BASES[arch]
        selected = [row for row in rows if row["architecture"] in (arch, "any")]
        if not any(row["architecture"] == arch for row in selected):
            fail("PACMAN_LINKAGE", "Pacman repository has no native package rows")
        known, identities = {}, {}
        for row in selected:
            relative = f"{base}/{row['name']}"
            package = take(relative)
            if package != unsigned[f"{row['name']}@unsigned/pacman/{row['name']}"]:
                fail("PACMAN_LINKAGE", "Published pacman package differs from its original")
            sig = _signature(take(relative + ".sig"), armored=False, limit=metadata.MAX_PACKAGE_SIGNATURE_BYTES)
            if row["architecture"] == "any" and shared.setdefault(row["name"], (package, sig)) != (package, sig):
                fail("PACMAN_LINKAGE", "Reused any pacman bytes or signature differ between architectures")
            companions[relative] = package
            signed.append(SignedObject("packages", relative + ".sig", "pacman-package", package, sig))
            known[row["name"]] = (sha(package), len(package), sig)
            identities[row["name"]] = _pacman_identity(row["name"], row["product"], row["version"],
                                                       row["architecture"])
        for archive, alias in zip(PACMAN_ARCHIVES, metadata.PACMAN_ALIASES):
            data, sig = take(f"{base}/{archive}"), take(f"{base}/{archive}.sig")
            _pacman_archive(data, files=archive == metadata.PACMAN_FILES, known=known, identities=identities)
            if take(f"{base}/{alias}") != data or take(f"{base}/{alias}.sig") != sig:
                fail("PACMAN_LINKAGE", "Pacman alias is not an exact regular copy")
            companions.update({f"{base}/{archive}": data, f"{base}/{alias}": data, f"{base}/{alias}.sig": sig})
            signed.append(SignedObject("packages", f"{base}/{archive}.sig", "pacman-database", data,
                                       _signature(sig, armored=False, limit=metadata.MAX_PACKAGE_SIGNATURE_BYTES)))
    return companions, signed


def plan_public_repository(stage: Mapping[str, bytes], output: Mapping[str, bytes]) -> PublicPlan:
    """Exact inventory and linkage plan; refuses unknown, missing or mutated entries."""
    rows, anchor = _routing_rows(stage)
    by_family = {family: [row for row in rows if row["family"] == family] for family in _MARKER}
    destinations = {path for row in rows for path in row["destinations"]}
    unsigned = {row["name"] + "@" + path: _member(stage, path, row["sha256"], row["size"])
                for row in rows for path in row["destinations"]}
    deb_rows = {row["name"]: row for row in by_family["deb"]}
    for row in by_family["deb"]:
        control = parse_deb_control(stage[f"unsigned/deb/{row['name']}"])
        if (control["Package"], control["Version"], control["Architecture"]) != (
                row["product"], row["name"].split("_")[1], row["architecture"]):
            fail("APT_LINKAGE", "DEB control disagrees with routing identity")
    apt_members, release = _apt_members(stage, anchor, deb_rows)
    if set(stage) != {ROUTING_FILE, *destinations, *("apt/" + path for path in apt_members)}:
        fail("UNSIGNED_INVENTORY", "Unsigned stage has unknown or missing members")
    companions, signed = {}, []

    def take(relative: str) -> bytes:
        if relative not in output:
            fail("OUTPUT_INVENTORY", "Signed output member is missing")
        return output[relative]

    for path in apt_members:
        if take("apt/" + path) != stage["apt/" + path]:
            fail("APT_LINKAGE", "Signed output APT member differs from the held stage")
        companions["apt/" + path] = stage["apt/" + path]
    inrelease = take("apt/" + INRELEASE)
    if not 0 < len(inrelease) <= _apt.MAX_INRELEASE_BYTES:
        fail("SIGNATURE_SHAPE", "InRelease is missing or unbounded")
    _apt._validate_clearsigned_structure(inrelease)
    if clearsigned_body(inrelease).rstrip(b"\n") != release.rstrip(b"\n"):
        fail("APT_LINKAGE", "InRelease cleartext differs from the held Release")
    signed += [SignedObject("apt", INRELEASE, "apt-inrelease", release, inrelease),
               SignedObject("apt", RELEASE_GPG, "apt-release-gpg", release,
                            _signature(take("apt/" + RELEASE_GPG), armored=True, limit=_apt.MAX_SIGNATURE_BYTES))]
    rpm = {arch: {} for arch in RPM_ARCHES}
    for row in by_family["rpm"]:
        for arch in (RPM_ARCHES if row["architecture"] == "noarch" else (row["architecture"],)):
            original = unsigned[f"{row['name']}@unsigned/rpm/{arch}/{row['name']}"]
            relative = f"rpm/{arch}/Packages/{row['name']}"
            package = take(relative)
            try:
                _runtime.inspect_rpm_preservation(original, package)
            except ProtectedSigningError as error:
                fail("RPM_PRESERVATION", f"Signed RPM does not preserve its original ({error.code})")
            rpm[arch][row["name"]] = package
            signed.append(SignedObject("packages", relative, "rpm-package", original, package))
        if row["architecture"] == "noarch" and len({rpm[arch][row["name"]] for arch in RPM_ARCHES}) != 1:
            fail("RPM_PRESERVATION", "Reused noarch RPM bytes differ between architectures")
    for arch in RPM_ARCHES:
        prefix = f"rpm/{arch}/"
        repodata = {key[len(prefix):]: value for key, value in output.items()
                    if key.startswith(prefix + "repodata/") and key != prefix + "repodata/repomd.xml.asc"}
        try:
            metadata._rpm_metadata({key: ((), value) for key, value in repodata.items()}, rpm[arch])
        except ProtectedSigningError as error:
            fail("RPM_LINKAGE", f"RPM repodata does not link the signed packages ({error.code})")
        companions.update({prefix + key: value for key, value in repodata.items()})
        asc = _signature(take(prefix + "repodata/repomd.xml.asc"), armored=True, limit=metadata.MAX_SIGNATURE_BYTES)
        signed.append(SignedObject("packages", prefix + "repodata/repomd.xml.asc", "rpm-metadata",
                                   repodata["repodata/repomd.xml"], asc))
    pacman_companions, pacman_signed = _pacman_linkage(by_family["pacman"], unsigned, take)
    companions.update(pacman_companions)
    signed += pacman_signed
    deploy = [obj.deploy_path for obj in signed]
    if len(set(deploy)) != len(deploy) or set(deploy) & set(companions):
        fail("OUTPUT_INVENTORY", "Signed and companion paths overlap")
    if set(output) != set(companions) | set(deploy):
        fail("OUTPUT_INVENTORY", "Signed output has unknown or missing members")
    counts = {kind: sum(obj.kind == kind for obj in signed) for kind in SIGNED_KINDS}
    counts.update(companions=len(companions), signed=len(signed), routed_rows=len(rows))
    return PublicPlan(tuple(signed), MappingProxyType(dict(companions)), release, MappingProxyType(counts))


def public_inventory(plan: PublicPlan, by_hash: Mapping[str, bytes], public_key: bytes) -> dict[str, bytes]:
    """Exact final deployment map: retained signed objects plus bound companions."""
    if type(public_key) is not bytes or sha(public_key) != _apt.PUBLIC_KEY_SHA256:
        fail("PUBLIC_KEY_IDENTITY", "Public export must use the committed key bytes")
    result = dict(plan.companions)
    for obj in plan.signed:
        result[obj.deploy_path] = obj.signed
    apt_signatures = {obj.signed for obj in plan.signed if obj.store == "apt"}
    if (set(by_hash) != {"apt/" + APT_BY_HASH + sha(data) for data in apt_signatures}
            or any(by_hash[path] not in apt_signatures or path[-64:] != sha(by_hash[path]) for path in by_hash)
            or set(by_hash) & set(result) or PUBLIC_KEY_PATH in result):
        fail("FINAL_INVENTORY", "APT by-hash signature copies or public key path are not exact")
    result.update(by_hash)
    result[PUBLIC_KEY_PATH] = public_key
    return result


__all__ = ["PUBLIC_KEY_PATH", "PublicJoinError", "PublicPlan", "SignedObject", "plan_public_repository",
           "public_inventory"]
