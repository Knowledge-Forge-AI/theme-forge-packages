"""PROPOSED, UNADOPTED live RPM/pacman repository metadata assembly.

Runs only inside the active ProtectedSigningRuntime live lifetime (same lease,
agent, key import and private work) after package signing and live APT
assembly, before final inventory. Tools, flags, paths and phases are fixed;
callers supply no tool, path, callback or validator. Tool output is accepted
only through exact no-link inventories bound to the runtime's own registered
signed packages. repo-add runs without -s/-v/-k (pinned v7.0.0 never reaches
GnuPG); its .db/.files aliases are accepted only as exact relative symlink,
same-inode hardlink or byte copy, and only regular nlink-1 copies publish.
createrepo_c is a proposed, unapproved tool class; nothing here is native-
qualified, publicly verified, adopted or production authority.
"""

from __future__ import annotations

import base64
import binascii
import io
import os
from pathlib import Path
import re
import stat
import tarfile
import xml.etree.ElementTree as ET
import zlib

import protected_signing_runtime as _rt
from current_protected_signing import ProtectedSigningError, _sha256

REPOSITORY_NAME = "knowledge-forge-ai"
RPM_ARCHITECTURES, PACMAN_ARCHITECTURES = ("x86_64", "aarch64"), _rt.LIVE_PACMAN_ARCHITECTURES
# x86_64 keeps the established scratch leaf "pacman"; not a _pacman_repository default.
PACMAN_ARCHITECTURE = PACMAN_ARCHITECTURES[0]
PACMAN_SUFFIX = ".pkg.tar.zst"
CREATEREPO_FLAGS = ("--general-compress-type", "gz", "--no-database", "-s", "sha256")
REPO_ADD_FLAGS = ("--nocolor", "--include-sigs")
PACMAN_DATABASE, PACMAN_FILES = REPOSITORY_NAME + ".db.tar.gz", REPOSITORY_NAME + ".files.tar.gz"
PACMAN_ALIASES = {REPOSITORY_NAME + ".db": PACMAN_DATABASE, REPOSITORY_NAME + ".files": PACMAN_FILES}
MAX_REPOMD_BYTES, MAX_METADATA_BYTES = 1024 ** 2, 64 * 1024 ** 2
MAX_SIGNATURE_BYTES, MAX_PACKAGE_SIGNATURE_BYTES, MAX_DESC_BYTES = 64 * 1024, 16384, 64 * 1024
# The current Nebular native package needs about200KiB of pacman file-list
# metadata. Keep descriptions small while allowing bounded full file lists.
MAX_FILE_LIST_BYTES = 1024 * 1024
MAX_DIRECTORY_ENTRIES, MAX_ARCHIVE_MEMBERS = 64, 256
_ENTRY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
_HEX = re.compile(r"[0-9a-f]{64}")
_NUMBER = re.compile(r"[0-9]{1,20}")
_DESC_KEY = re.compile(r"%[A-Z0-9]{1,32}%")
_REPO = "{http://linux.duke.edu/metadata/repo}"
_XML_ROOTS = {"primary": ("{http://linux.duke.edu/metadata/common}", "metadata"),
              "filelists": ("{http://linux.duke.edu/metadata/filelists}", "filelists"),
              "other": ("{http://linux.duke.edu/metadata/other}", "otherdata")}


def _fail(code: str, message: str):
    # PACKAGE_MUTATED/OUTPUT_INVENTORY are terminal live custody codes in the runtime (retain
    # lease + private work); REPOSITORY_METADATA is a grammar refusal with ordinary cleanup.
    raise ProtectedSigningError(code, message)


_identity = _rt.ProtectedSigningRuntime._output_identity  # the runtime's own output identity tuple


def _lstat(path: Path, code: str):
    try:
        return os.lstat(path)
    except OSError as error:
        raise ProtectedSigningError(code, "Private repository entry is unavailable") from error


def _list_directory(path: Path) -> tuple[str, ...]:
    """Names from one held no-follow directory fd; uncertain close is retained."""
    info = _lstat(path, "OUTPUT_INVENTORY")
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022):
        _fail("OUTPUT_INVENTORY", "Private repository directory custody is invalid")
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProtectedSigningError("OUTPUT_INVENTORY", "Private repository directory cannot be opened") from error
    # Enrolled immediately; an uncertain close keeps this ledger strongly reachable.
    descriptor = {"fd": fd, "status": "open", "path": path, "original_error": None, "cleanup_error": None,
                  "close_attempted": False, "close_confirmed": False}
    body_error = cleanup_error = names = None
    try:
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISDIR(opened.st_mode):
                _fail("OUTPUT_INVENTORY", "Private repository directory was replaced")
            names = os.listdir(fd)
            if len(names) > MAX_DIRECTORY_ENTRIES:
                _fail("OUTPUT_INVENTORY", "Private repository directory exceeds its entry bound")
        except BaseException as error:
            body_error = error
            descriptor["original_error"] = error
    finally:
        descriptor["close_attempted"] = True
        try:
            os.close(fd)
        except BaseException as error:
            cleanup_error = error
            descriptor.update(status="close-uncertain", cleanup_error=error)
            _rt._RETAINED_READ_DESCRIPTORS.append(descriptor)
        else:
            descriptor.update(status="closed", close_confirmed=True)
    if cleanup_error is not None:
        raise _rt._LifecycleFailure(_rt.READ_DESCRIPTOR_CLEANUP, body_error, (cleanup_error,),
                                    resources=(descriptor,)) from None
    if isinstance(body_error, OSError):
        raise ProtectedSigningError("OUTPUT_INVENTORY", "Private repository directory listing failed") from body_error
    if body_error is not None:
        raise body_error
    return tuple(sorted(names))


def _record(path: Path, *, alias: bool = False, shared: bool = False) -> tuple[tuple[int, ...], bytes]:
    """(identity, payload) for one owned regular file or exact alias symlink."""
    info = _lstat(path, "OUTPUT_INVENTORY")
    identity = _identity(info)
    if info.st_uid != os.getuid():
        _fail("OUTPUT_INVENTORY", "Private repository member owner differs")
    if stat.S_ISLNK(info.st_mode) and alias:
        try:
            payload = os.fsencode(os.readlink(path))
            after = os.lstat(path)
        except OSError as error:
            raise ProtectedSigningError("OUTPUT_INVENTORY", "Repository alias cannot be inspected") from error
        if _identity(after) != identity or len(payload) > 255:
            _fail("PACKAGE_MUTATED", "Repository alias changed during inspection")
        return identity, payload
    limit = MAX_SIGNATURE_BYTES if path.name.endswith((".sig", ".asc")) else _rt.MAX_OBJECT_BYTES
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022
            or not 1 <= info.st_nlink <= (2 if alias or shared else 1) or not 0 < info.st_size <= limit):
        _fail("OUTPUT_INVENTORY", "Private repository member is not a bounded unaliased regular file")
    data = _rt._read_regular_unpinned(path, "private repository member")
    if _identity(_lstat(path, "PACKAGE_MUTATED")) != identity or len(data) != info.st_size:
        _fail("PACKAGE_MUTATED", "Private repository member changed during readback")
    return identity, data


def _snapshot(repo: Path, directories: tuple[str, ...], *, expected=None, aliases=(), shared=()) -> dict:
    """Exact bounded tree: only listed directories, otherwise regular members."""
    result = {}
    for directory in directories:
        for name in _list_directory(repo / directory if directory else repo):
            key = f"{directory}/{name}" if directory else name
            if key in directories:
                continue
            if not _ENTRY.fullmatch(name) or (expected is not None and key not in expected):
                _fail("OUTPUT_INVENTORY", "Unexpected private repository member")
            result[key] = _record(repo / key, alias=key in aliases, shared=key in shared)
    if expected is not None and set(result) != set(expected):
        _fail("OUTPUT_INVENTORY", "Private repository member is missing")
    return result


def _same(before: dict, after: dict, added) -> dict:
    if set(after) != set(before) | set(added):
        _fail("OUTPUT_INVENTORY", "Private repository membership changed across commands")
    for key, value in before.items():
        if after[key] != value:
            _fail("PACKAGE_MUTATED", "Private repository member changed across commands")
    return after


def _number(value) -> int:
    if type(value) is not str or not _NUMBER.fullmatch(value):
        _fail("REPOSITORY_METADATA", "Repository metadata number is malformed")
    return int(value)


def _xml(data: bytes):
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        _fail("REPOSITORY_METADATA", "Repository metadata declarations are forbidden")
    try:
        return ET.fromstring(data.decode("utf-8"))
    except (ET.ParseError, UnicodeDecodeError, ValueError):
        _fail("REPOSITORY_METADATA", "Repository metadata XML is malformed")


def _child(node, namespace: str, name: str):
    matches = node.findall(namespace + name)
    if len(matches) != 1:
        _fail("REPOSITORY_METADATA", "Repository metadata field is missing or ambiguous")
    return matches[0]


def _gunzip(data: bytes) -> bytes:
    if len(data) > MAX_METADATA_BYTES or not data.startswith(b"\x1f\x8b"):
        _fail("REPOSITORY_METADATA", "Repository metadata is not bounded gzip")
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        opened = inflater.decompress(data, MAX_METADATA_BYTES + 1)
    except zlib.error:
        _fail("REPOSITORY_METADATA", "Repository metadata gzip is malformed")
    if (len(opened) > MAX_METADATA_BYTES or inflater.unconsumed_tail
            or not inflater.eof or inflater.unused_data):
        _fail("REPOSITORY_METADATA", "Repository metadata gzip is unbounded or has trailing data")
    return opened


def _rpm_metadata(snapshot: dict, packages: dict[str, bytes]) -> None:
    """Bind repomd -> exact core gzip XML -> known Packages/ hrefs, sizes and hashes."""
    if "repodata/repomd.xml" not in snapshot or len(snapshot["repodata/repomd.xml"][1]) > MAX_REPOMD_BYTES:
        _fail("OUTPUT_INVENTORY", "repomd.xml is missing or exceeds its bound")
    repomd = _xml(snapshot["repodata/repomd.xml"][1])
    if repomd.tag != _REPO + "repomd" or any(child.tag not in {_REPO + "data", _REPO + "revision"} for child in repomd):
        _fail("REPOSITORY_METADATA", "repomd.xml root or children are not closed")
    objects = {}
    for node in repomd.findall(_REPO + "data"):
        kind = node.get("type")
        href = _child(node, _REPO, "location").get("href") or ""
        if (kind not in _XML_ROOTS or kind in objects or not href.startswith("repodata/")
                or not _ENTRY.fullmatch(href[9:]) or not href.endswith(f"{kind}.xml.gz")):
            _fail("REPOSITORY_METADATA", "repomd.xml data entry is not one exact core gzip object")
        digests = [_child(node, _REPO, field) for field in ("checksum", "open-checksum")]
        if any(item.get("type") != "sha256" or not _HEX.fullmatch(item.text or "") for item in digests):
            _fail("REPOSITORY_METADATA", "repomd.xml checksum is not sha256")
        objects[kind] = (href, digests[0].text, digests[1].text,
                         _number(_child(node, _REPO, "size").text), _number(_child(node, _REPO, "open-size").text))
    names = {"repodata/repomd.xml", *(item[0] for item in objects.values())}
    if set(objects) != set(_XML_ROOTS) or len(names) != 4 or {k for k in snapshot if k.startswith("repodata/")} != names:
        _fail("OUTPUT_INVENTORY", "RPM repodata membership is not exactly repomd.xml plus core metadata")
    expected = {f"Packages/{name}": (_sha256(data), len(data)) for name, data in packages.items()}
    identifiers = {}
    for kind, (href, digest, open_digest, size, open_size) in objects.items():
        data = snapshot[href][1]
        if len(data) != size or _sha256(data) != digest:
            _fail("PACKAGE_MUTATED", "RPM metadata object differs from repomd.xml")
        opened = _gunzip(data)
        if len(opened) != open_size or _sha256(opened) != open_digest:
            _fail("PACKAGE_MUTATED", "RPM metadata open content differs from repomd.xml")
        namespace, tag = _XML_ROOTS[kind]
        root = _xml(opened)
        nodes = root.findall(namespace + "package")
        if (root.tag != namespace + tag or len(nodes) != len(root)
                or _number(root.get("packages")) != len(nodes)):
            _fail("REPOSITORY_METADATA", "RPM metadata package list is not closed")
        if kind == "primary":
            found = {}
            for package in nodes:
                checksum = _child(package, namespace, "checksum")
                location = _child(package, namespace, "location").get("href")
                for field in ("name", "arch", "version"):
                    _child(package, namespace, field)
                if (package.get("type") != "rpm" or checksum.get("type") != "sha256"
                        or checksum.get("pkgid") != "YES" or location in found):
                    _fail("REPOSITORY_METADATA", "RPM primary package entry is malformed")
                found[location] = (checksum.text, _number(_child(package, namespace, "size").get("package")))
            if found != expected:
                _fail("PACKAGE_MUTATED", "RPM primary metadata differs from the known signed packages")
            identifiers[kind] = sorted(value[0] for value in found.values())
        else:
            identifiers[kind] = sorted(package.get("pkgid") or "" for package in nodes)
    if not identifiers["primary"] or not identifiers["filelists"] == identifiers["other"] == identifiers["primary"]:
        _fail("PACKAGE_MUTATED", "RPM filelists/other metadata do not link the known packages")


def _desc(body: bytes) -> tuple[str, tuple[str, int, bytes]]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        _fail("REPOSITORY_METADATA", "Pacman desc entry is not UTF-8")
    fields = {}
    for block in text.strip("\n").split("\n\n") if text.endswith("\n") else ():
        lines = block.split("\n")
        if not _DESC_KEY.fullmatch(lines[0]) or lines[0] in fields or len(lines) < 2:
            _fail("REPOSITORY_METADATA", "Pacman desc entry is malformed")
        fields[lines[0]] = lines[1:]
    values = [fields.get(key, ()) for key in ("%FILENAME%", "%CSIZE%", "%SHA256SUM%", "%PGPSIG%")]
    if any(len(value) != 1 for value in values) or not _ENTRY.fullmatch(values[0][0]) or not _HEX.fullmatch(values[2][0]):
        _fail("REPOSITORY_METADATA", "Pacman desc binding fields are missing or malformed")
    try:
        signature = base64.b64decode(values[3][0], validate=True)
    except (binascii.Error, ValueError):
        _fail("REPOSITORY_METADATA", "Pacman desc signature is not base64")
    return values[0][0], (values[2][0], _number(values[1][0]), signature)


def _pacman_entries(data: bytes, *, files: bool) -> dict[str, tuple[str, int, bytes]]:
    """Bounded tar parse: only <entry>/ dirs plus desc (and files) regular members."""
    opened = _gunzip(data)
    directories, members = set(), {}
    allowed = {"desc", "files"} if files else {"desc"}
    try:
        with tarfile.open(fileobj=io.BytesIO(opened), mode="r:") as archive:
            for index, member in enumerate(archive):
                parts = member.name.rstrip("/").split("/")
                if (index >= MAX_ARCHIVE_MEMBERS or member.name.startswith("/")
                        or any(not _ENTRY.fullmatch(part) for part in parts)):
                    _fail("OUTPUT_INVENTORY", "Pacman database member is unbounded or unsafe")
                if member.isdir() and len(parts) == 1 and parts[0] not in directories:
                    directories.add(parts[0])
                    continue
                limit = MAX_FILE_LIST_BYTES if len(parts) == 2 and parts[1] == "files" else MAX_DESC_BYTES
                if (not member.isfile() or len(parts) != 2 or parts[1] not in allowed
                        or tuple(parts) in members or member.size > limit):
                    _fail("OUTPUT_INVENTORY", "Pacman database member is not an exact entry file")
                members[tuple(parts)] = archive.extractfile(member).read(limit + 1)
    except (tarfile.TarError, EOFError, OSError):
        _fail("REPOSITORY_METADATA", "Pacman database archive is malformed")
    if not directories or set(members) != {(entry, name) for entry in directories for name in allowed}:
        _fail("OUTPUT_INVENTORY", "Pacman database entries are incomplete")
    result = {}
    for entry in sorted(directories):
        name, binding = _desc(members[(entry, "desc")])
        if name in result or (files and not members[(entry, "files")].startswith(b"%FILES%\n")):
            _fail("REPOSITORY_METADATA", "Pacman database entry is duplicated or malformed")
        result[name] = binding
    return result


def _sign(runtime, target: Path, signature: Path, home: Path, work: Path, passphrase: bytes, phase: str,
          *, armor: bool) -> None:
    if os.path.lexists(signature):
        _fail("OUTPUT_INVENTORY", "Repository metadata signature already exists")
    argv = (*runtime._gpg_base(home), "--pinentry-mode", "loopback", "--passphrase-fd", "0",
            *(("--armor",) if armor else ()), "--detach-sign", "--output", str(signature),
            "-u", f"{runtime.binding.signing_subkey_fingerprint}!", str(target))
    with _rt._private_umask():
        runtime._run(argv, cwd=work, env=runtime._env(home), stdin=passphrase, phase=phase)


def _verify(runtime, target: Path, signature: Path, home: Path, work: Path, phase: str, code: str) -> None:
    result = runtime._run((*runtime._gpg_base(home), "--status-fd", "1", "--verify", str(signature), str(target)),
                          cwd=work, env=runtime._env(home), stdin=b"", phase=phase)
    _rt._status_proof(_rt.inspect_detached_verification, code, "Repository metadata signature status proof failed",
                      result.stdout, runtime.binding, returncode=result.returncode)


def _registered(runtime, base: Path, relatives) -> dict[str, bytes]:
    """Exact runtime-registered signed outputs under base; never caller paths."""
    files = runtime._output_files
    present = {path for path in files if base in path.parents}
    if present != {base / relative for relative in relatives}:
        _fail("OUTPUT_INVENTORY", "Registered package outputs differ before repository metadata")
    result = {}
    for relative in relatives:
        path = base / relative
        identity, digest, size = files[path]
        data = _rt._read_regular_unpinned(path, "registered package output")
        if len(data) != size or _sha256(data) != digest or _identity(os.lstat(path)) != identity:
            _fail("PACKAGE_MUTATED", "Registered package output changed before repository metadata")
        result[relative] = data
    return result


def _metadata_tool_env(runtime, home: Path, staging: Path, name: str) -> dict[str, str]:
    """Keep non-GPG tool scratch in this invocation's owned private work."""
    temporary = _rt._new_owned_directory(staging / ("metadata-tmp-" + name), "metadata tool scratch")
    return {**runtime._env(home), "TMPDIR": str(temporary.path)}


def _rpm_repository(runtime, arch, packages, home, work, staging, root, passphrase) -> set[Path]:
    repo = _rt._new_owned_directory(staging / f"rpm-repository-{arch}", "private RPM repository").path
    _rt._new_owned_directory(repo / "Packages", "private RPM repository packages")
    for name in sorted(packages):
        _rt._exclusive_write(repo / "Packages" / name, packages[name], "private repository RPM")
    staged = _snapshot(repo, ("", "Packages"), expected={f"Packages/{name}" for name in packages})
    if {key[9:]: value[1] for key, value in staged.items()} != packages:
        _fail("PACKAGE_MUTATED", "Private repository RPM differs from its signed output")
    with _rt._private_umask():
        runtime._run((_rt.NATIVE_CREATEREPO, *CREATEREPO_FLAGS, str(repo)), cwd=work,
                     env=_metadata_tool_env(runtime, home, staging, "rpm-" + arch),
                     stdin=b"", phase="rpm-metadata-create")
    created = _snapshot(repo, ("", "Packages", "repodata"))
    repodata = {key for key in created if key.startswith("repodata/")}
    _same(staged, created, repodata)
    _rpm_metadata(created, packages)
    repomd, asc = repo / "repodata/repomd.xml", repo / "repodata/repomd.xml.asc"
    _sign(runtime, repomd, asc, home, work, passphrase, "rpm-metadata-sign", armor=True)
    signed = _same(created, _snapshot(repo, ("", "Packages", "repodata")), {"repodata/repomd.xml.asc"})
    _verify(runtime, repomd, asc, home, work, "rpm-metadata-verify", "RPM_METADATA_VERIFY_STATUS")
    _same(signed, _snapshot(repo, ("", "Packages", "repodata")), ())
    written = set()
    for key in sorted({*repodata, "repodata/repomd.xml.asc"}):
        written.add(root / "rpm" / arch / key)
        runtime._write_output("rpm-metadata-output", root / "rpm" / arch / key, signed[key][1],
                              "RPM repository metadata output")
    return written


def _pacman_filename_architecture(name) -> str:
    """Trailing <arch> of <pkgname>-<pkgver>-<pkgrel>-<arch>.pkg.tar.zst; never trusted alone."""
    stem = name[:-len(PACMAN_SUFFIX)] if type(name) is str and name.endswith(PACMAN_SUFFIX) else ""
    rest, _, arch = stem.rpartition("-")
    if not rest or not arch:
        _fail("REPOSITORY_METADATA", "Pacman package filename has no architecture")
    return arch


def _pacman_architecture_sets(pacman_rows) -> dict[str, tuple[str, ...]]:
    """Exact per-repository package names: own native rows plus every shared any row.

    Each repository needs native rows; every native product must exist for every
    architecture; any products are never native; filenames must name their row
    architecture. Refusals are pre-filesystem grammar failures.
    """
    native, shared, identities = {arch: {} for arch in PACMAN_ARCHITECTURES}, {}, set()
    for row in pacman_rows:
        arch, name, product = row.get("architecture"), row.get("name"), row.get("product")
        if (type(product) is not str or (product, arch) in identities
                or _pacman_filename_architecture(name) != arch
                or any(name in names.values() for names in (*native.values(), shared))):
            _fail("REPOSITORY_METADATA", "Pacman package row identity is not exact")
        identities.add((product, arch))
        if arch == "any":
            shared[product] = name
        elif arch in native:
            native[arch][product] = name
        else:
            _fail("REPOSITORY_METADATA", "Pacman package row architecture is foreign")
    products = {frozenset(names) for names in native.values()}
    if len(products) != 1 or not next(iter(products)) or set(shared) & next(iter(products)):
        _fail("REPOSITORY_METADATA", "Each pacman architecture requires the same native products")
    return {arch: tuple(sorted({*native[arch].values(), *shared.values()})) for arch in PACMAN_ARCHITECTURES}


def _paired_any(pacman: dict[str, dict[str, bytes]], any_names) -> None:
    """One any package/signature is reused byte-for-byte in every repository."""
    for name in any_names:
        for relative in (name, name + ".sig"):
            if len({pacman[arch][relative] for arch in PACMAN_ARCHITECTURES}) != 1:
                _fail("PACKAGE_MUTATED", "Reused any pacman bytes or signature differ between architectures")


def _pacman_inputs_for(arch, inputs) -> list[str]:
    """Closed package/signature pairs with no other repository's native package.

    Exact filename grammar and the per-architecture set are already enforced by
    _pacman_architecture_sets/_registered before this; this is defense in depth.
    """
    if arch not in PACMAN_ARCHITECTURES:
        _fail("REPOSITORY_METADATA", "Pacman repository architecture is not supported")
    packages = sorted(name for name in inputs if not name.endswith(".sig"))
    foreign = set(PACMAN_ARCHITECTURES) - {arch}
    if (not packages or set(inputs) != {*packages, *(name + ".sig" for name in packages)}
            or any(name.removesuffix(PACMAN_SUFFIX).rpartition("-")[2] in foreign for name in packages)):
        _fail("OUTPUT_INVENTORY", "Pacman repository inputs differ from its architecture package set")
    return packages


def _pacman_repository(runtime, inputs, home, work, staging, root, passphrase, *, arch: str) -> set[Path]:
    # arch is required: every caller names its repository; there is no default.
    packages = _pacman_inputs_for(arch, inputs)
    repo = _rt._new_owned_directory(staging / f"pacman-repository-{arch}",
                                    "private pacman repository").path
    for name in sorted(inputs):
        _rt._exclusive_write(repo / name, inputs[name], "private repository pacman input")
    staged = _snapshot(repo, ("",), expected=set(inputs))
    if {key: value[1] for key, value in staged.items()} != inputs:
        _fail("PACKAGE_MUTATED", "Private pacman input differs from its signed output")
    # x86_64 keeps the established "pacman" scratch leaf; others are arch-suffixed.
    scratch = "pacman" if arch == PACMAN_ARCHITECTURE else "pacman-" + arch
    with _rt._private_umask():
        runtime._run((_rt.NATIVE_REPO_ADD, *REPO_ADD_FLAGS, str(repo / PACMAN_DATABASE),
                      *(str(repo / name) for name in packages)),
                     cwd=work, env=_metadata_tool_env(runtime, home, staging, scratch),
                     stdin=b"", phase="pacman-database-create")
    outputs = {PACMAN_DATABASE, PACMAN_FILES, *PACMAN_ALIASES}

    def inventory(signatures=()):
        return _snapshot(repo, ("",), expected={*inputs, *outputs, *signatures}, aliases=set(PACMAN_ALIASES),
                         shared={PACMAN_DATABASE, PACMAN_FILES})

    current = _same(staged, inventory(), outputs)
    for alias, target in PACMAN_ALIASES.items():
        (identity, payload), (target_identity, target_data) = current[alias], current[target]
        hardlink = identity[:2] == target_identity[:2]
        if not (stat.S_ISLNK(identity[2]) and payload == target.encode() and target_identity[3] == 1
                or stat.S_ISREG(identity[2]) and payload == target_data
                and identity[3] == target_identity[3] == (2 if hardlink else 1)):
            _fail("OUTPUT_INVENTORY", "repo-add alias is not an exact corresponding target")
    known = {name: (_sha256(inputs[name]), len(inputs[name]), inputs[name + ".sig"]) for name in packages}
    if any(not 0 < len(value[2]) <= MAX_PACKAGE_SIGNATURE_BYTES for value in known.values()):
        _fail("OUTPUT_INVENTORY", "Pacman package signature is outside its bound")
    for archive in (PACMAN_DATABASE, PACMAN_FILES):
        if _pacman_entries(current[archive][1], files=archive == PACMAN_FILES) != known:
            _fail("PACKAGE_MUTATED", "Pacman database differs from the known signed packages")
    signatures = []
    for archive in (PACMAN_DATABASE, PACMAN_FILES):
        signatures.append(archive + ".sig")
        _sign(runtime, repo / archive, repo / signatures[-1], home, work, passphrase, "pacman-database-sign",
              armor=False)
        current = _same(current, inventory(signatures), {signatures[-1]})
        _verify(runtime, repo / archive, repo / signatures[-1], home, work, "pacman-database-verify",
                "PACMAN_DATABASE_VERIFY_STATUS")
        current = _same(current, inventory(signatures), ())
    base, written = root / "arch" / arch, set()
    for alias, target in PACMAN_ALIASES.items():
        for name, source in ((target, target), (target + ".sig", target + ".sig"),
                             (alias, target), (alias + ".sig", target + ".sig")):
            written.add(base / name)  # every published alias is a fresh regular copy
            runtime._write_output("pacman-database-output", base / name, current[source][1],
                                  "pacman repository database output")
    return written


def assemble_live_repository_metadata(runtime, lease, rows, *, home: Path, work: Path, staging: Path,
                                      output, passphrase: bytes) -> None:
    """Create, sign and status-verify RPM/pacman metadata; register outputs only."""
    if (lease is None or runtime._active_live_lease is not lease or runtime._output_root is not output
            or type(passphrase) is not bytes or not passphrase):
        _fail("LIFECYCLE_STATE", "Repository metadata requires the active live lease lifetime")
    root = output.path
    rpm_rows = [row for row in rows if row.get("channel") == "rpm"]
    pacman_rows = [row for row in rows if row.get("channel") == "pacman"]
    if (not rpm_rows or not pacman_rows
            or any(row.get("architecture") not in {*PACMAN_ARCHITECTURES, "any"} for row in pacman_rows)):
        _fail("REPOSITORY_METADATA", "Live RPM and pacman package rows are required")
    pacman_sets = _pacman_architecture_sets(pacman_rows)
    rpm = {}
    for arch in RPM_ARCHITECTURES:
        names = sorted(row["name"] for row in rpm_rows if row.get("architecture") in {arch, "noarch"})
        if not names:
            _fail("REPOSITORY_METADATA", "Each RPM architecture requires packages before metadata creation")
        rpm[arch] = {key[9:]: value for key, value in
                     _registered(runtime, root / "rpm" / arch, [f"Packages/{name}" for name in names]).items()}
    if any(rpm["x86_64"][row["name"]] != rpm["aarch64"][row["name"]] for row in rpm_rows
           if row.get("architecture") == "noarch"):
        _fail("PACKAGE_MUTATED", "Reused noarch RPM bytes differ between architectures")
    digests = {row["name"]: row.get("package_sha256") for row in pacman_rows}
    pacman = {}
    for arch, names in pacman_sets.items():
        pacman[arch] = _registered(runtime, root / "arch" / arch, [*names, *(name + ".sig" for name in names)])
        if any(_sha256(pacman[arch][name]) != digests[name] for name in names):
            _fail("PACKAGE_MUTATED", "Pacman package output differs from its signed row")
    _paired_any(pacman, sorted(row["name"] for row in pacman_rows if row.get("architecture") == "any"))

    def published():
        return {path for path in runtime._output_files if {root / "rpm", root / "arch"} & set(path.parents)}

    before, written = published(), set()
    for arch in RPM_ARCHITECTURES:
        written |= _rpm_repository(runtime, arch, rpm[arch], home, work, staging, root, passphrase)
    for arch in PACMAN_ARCHITECTURES:
        written |= _pacman_repository(runtime, pacman[arch], home, work, staging, root, passphrase, arch=arch)
    if published() != before | written or before & written:
        _fail("OUTPUT_INVENTORY", "Registered repository metadata differs from the assembled set")
