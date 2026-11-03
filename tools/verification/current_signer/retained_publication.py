"""Authenticate and stage ALREADY qualified signed public repository bytes for Pages.

Never signs, re-signs, regenerates metadata, rebuilds packages or moves tags.
Downloads one ZIP from the exact original qualification run, binds it to the
API digest, the worker receipt and the P checkout descriptor, then writes the
exact payload bytes into a NEW destination. The worker receipt is non-publishing
source proof; authenticated native-client and GUI jobs supply the other gates;
owner approval of the protected github-pages environment deploys separately.
"""
from __future__ import annotations

import os
import sys

if __name__ == "__main__":  # explicit sibling bootstrap; -I omits the script directory
    _HERE = os.path.dirname(os.path.realpath(__file__))
    if sys.path[:1] != [_HERE]:
        sys.path.insert(0, _HERE)

import argparse  # noqa: E402
from dataclasses import dataclass, fields  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import struct  # noqa: E402
import zipfile  # noqa: E402
import zlib  # noqa: E402

import publication_github_api as gh  # noqa: E402
from publication_github_api import PublicationError, refuse  # noqa: E402

LEAF_MANIFEST_REL_PATH = "tools/verification/current_signer/leaf-manifest.json"
AUDIT_SCHEMA = "tf.retained-publication-admission-audit.v1"
RECEIPT_NAME = "outer-controller-receipt.json"
PAYLOAD_PREFIX = "public-repository/"
MAX_FILES = 256
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
MAX_ENTRIES = 1024
CHUNK = 1024 * 1024
_RUN_ARG = re.compile(r"[1-9][0-9]{0,19}")
_ALLOWED_FLAGS = 0x0002 | 0x0004 | 0x0008 | 0x0800  # deflate options, data descriptor, UTF-8
_ALLOWED_EXTRA_IDS = frozenset({0x0001, 0x000A, 0x5455, 0x7875})
_ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, ValueError, NotImplementedError)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class Options:
    repository: str
    p_root: str
    p_commit: str
    p_tree: str
    qualification_run_id: str
    gui_run_id: str
    leaf_manifest_sha256: str
    work_root: str
    destination: str
    audit_out: str


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parents(rels) -> set:
    return {"/".join(r.split("/")[:i]) for r in rels for i in range(1, r.count("/") + 1)}


def _pread(fd: int, size: int, offset: int) -> bytes:
    data = os.pread(fd, size, offset) if size else b""
    return data if len(data) == size else refuse("ZIP_TRUNCATED")


def _hash_fd(fd: int, expected_size: int, code: str) -> str:
    digest, offset = hashlib.sha256(), 0
    while chunk := os.pread(fd, CHUNK, offset):
        offset += len(chunk)
        if offset > expected_size:
            refuse(code)
        digest.update(chunk)
    if offset != expected_size or os.fstat(fd).st_size != expected_size:
        refuse(code)
    return digest.hexdigest()


def central_directory_bounds(fd: int, size: int) -> tuple:
    """Comment-free EOCD (optionally zip64); central directory must end flush with it."""
    if size < 22:
        refuse("ZIP_EOCD")
    sig, disk, cd_disk, n_disk, n_total, cd_size, cd_off, comment = struct.unpack(
        "<4sHHHHIIH", _pread(fd, 22, size - 22))
    if sig != b"PK\x05\x06" or comment or disk or cd_disk or n_disk != n_total:
        refuse("ZIP_EOCD")
    end = size - 22
    if 0xFFFFFFFF in (cd_size, cd_off) or n_total == 0xFFFF:
        lsig, ldisk, z64_off, ldisks = struct.unpack("<4sIQI", _pread(fd, 20, size - 42)) \
            if size >= 98 else refuse("ZIP_EOCD")
        if lsig != b"PK\x06\x07" or ldisk or ldisks != 1 or z64_off != size - 98:
            refuse("ZIP_EOCD")
        rsig, rsize, _m, _n, rdisk, rcd_disk, n_disk, n_total, cd_size, cd_off = struct.unpack(
            "<4sQHHIIQQQQ", _pread(fd, 56, z64_off))
        if rsig != b"PK\x06\x06" or rsize != 44 or rdisk or rcd_disk or n_disk != n_total:
            refuse("ZIP_EOCD")
        end = z64_off
    if cd_off + cd_size != end:
        refuse("ZIP_UNACCOUNTED_BYTES")
    if not 0 < n_total <= MAX_ENTRIES:
        refuse("ZIP_DIRECTORY")
    return cd_off, n_total


def _check_extra(blob: bytes) -> None:
    index = 0
    while index < len(blob):
        if index + 4 > len(blob):
            refuse("ZIP_EXTRA_FIELD")
        ident, length = struct.unpack_from("<HH", blob, index)
        if ident not in _ALLOWED_EXTRA_IDS or index + 4 + length > len(blob):
            refuse("ZIP_EXTRA_FIELD")
        index += 4 + length


def _classify(info: zipfile.ZipInfo) -> tuple:
    name = info.filename
    if (info.orig_filename != name or info.flag_bits & ~_ALLOWED_FLAGS or info.create_system not in (0, 3)
            or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            or (info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size)):
        refuse("ZIP_ENTRY_POLICY")
    _check_extra(info.extra)
    kind = stat.S_IFMT(info.external_attr >> 16) if info.create_system == 3 else 0
    if name.endswith("/"):
        if kind not in (0, stat.S_IFDIR) or info.file_size or info.compress_size:
            refuse("ZIP_SPECIAL_ENTRY")
        if name == PAYLOAD_PREFIX:
            return "dir", ""
        if not name.startswith(PAYLOAD_PREFIX):
            refuse("ZIP_ENTRY_UNACCOUNTED")
        return "dir", gh.safe_relative(name[len(PAYLOAD_PREFIX):-1])
    if kind not in (0, stat.S_IFREG) or info.external_attr & 0x10:
        refuse("ZIP_SPECIAL_ENTRY")
    if name == RECEIPT_NAME:
        return "receipt", name
    if not name.startswith(PAYLOAD_PREFIX):
        refuse("ZIP_ENTRY_UNACCOUNTED")
    return "file", gh.safe_relative(name[len(PAYLOAD_PREFIX):])


def _plan_entries(infos: list) -> tuple:
    files, dirs, receipt, seen = {}, set(), None, set()
    for info in infos:
        if info.filename.casefold() in seen:
            refuse("ZIP_DUPLICATE_OR_COLLIDING_NAME")
        seen.add(info.filename.casefold())
        kind, rel = _classify(info)
        if kind == "receipt":
            receipt = info
        elif kind == "dir":
            dirs.add(rel)
        else:
            files[rel] = info
    if receipt is None or receipt.file_size > MAX_RECEIPT_BYTES:
        refuse("ZIP_RECEIPT_MEMBER")
    if not 0 < len(files) <= MAX_FILES:
        refuse("ZIP_FILE_COUNT")
    parents = _parents(files)
    if parents & set(files) or not dirs <= parents | {""}:
        refuse("ZIP_PATH_CONFLICT")
    if (any(i.file_size > gh.MAX_FILE_BYTES for i in files.values())
            or sum(i.file_size for i in files.values()) > MAX_TOTAL_BYTES):
        refuse("ZIP_SIZE_BOUND")
    return files, receipt


def _local_ends(fd: int, info: zipfile.ZipInfo) -> set:
    """Possible end offsets of one local entry (header, name, extra, data, descriptor)."""
    sig, _v, flags, method, _t, _d, crc, csize, usize, nlen, xlen = struct.unpack(
        "<4sHHHHHIIIHH", _pread(fd, 30, info.header_offset))
    if (sig != b"PK\x03\x04" or flags != info.flag_bits or method != info.compress_type
            or _pread(fd, nlen, info.header_offset + 30) != info.orig_filename.encode("ascii")):
        refuse("ZIP_LOCAL_HEADER")
    _check_extra(_pread(fd, xlen, info.header_offset + 30 + nlen))
    data_end = info.header_offset + 30 + nlen + xlen + info.compress_size
    if not flags & 0x0008:
        if crc != info.CRC or (csize, usize) not in ((info.compress_size, info.file_size), (0xFFFFFFFF,) * 2):
            refuse("ZIP_LOCAL_HEADER")
        return {data_end}
    ends = set()
    for sig_len in (4, 0):
        if sig_len and os.pread(fd, 4, data_end) != b"PK\x07\x08":
            continue
        for fmt in ("<III", "<IQQ"):
            body = os.pread(fd, struct.calcsize(fmt), data_end + sig_len)
            if len(body) == struct.calcsize(fmt) and struct.unpack(fmt, body) == (
                    info.CRC, info.compress_size, info.file_size):
                ends.add(data_end + sig_len + len(body))
    return ends or refuse("ZIP_DATA_DESCRIPTOR")


def _check_layout(fd: int, infos: list, cd_offset: int) -> None:
    """Local entries must tile [0, central directory) exactly: no gaps, overlaps or prefixes."""
    ordered = sorted(infos, key=lambda i: i.header_offset)
    if ordered[0].header_offset != 0:
        refuse("ZIP_UNACCOUNTED_BYTES")
    for index, info in enumerate(ordered):
        following = ordered[index + 1].header_offset if index + 1 < len(ordered) else cd_offset
        if following not in _local_ends(fd, info):
            refuse("ZIP_UNACCOUNTED_BYTES")


def _stream(zf: zipfile.ZipFile, info: zipfile.ZipInfo, sink=None) -> str:
    digest, total = hashlib.sha256(), 0
    try:
        with zf.open(info) as source:
            while (chunk := source.read(CHUNK)) and total <= info.file_size:
                total += len(chunk)
                digest.update(chunk)
                if sink is not None and total <= info.file_size:
                    sink(chunk)
    except _ZIP_ERRORS:
        raise PublicationError("ZIP_MEMBER_CORRUPT") from None
    if total != info.file_size:
        refuse("ZIP_MEMBER_SIZE")
    return digest.hexdigest()


def _write_all(fd: int, chunk: bytes) -> None:
    view = memoryview(chunk)
    while view:
        written = os.write(fd, view)
        view = view[written:] if written > 0 else refuse("DESTINATION_WRITE")


class _NewTree:
    """Exclusive dir_fd-relative writer for a NEW, phase-owned destination."""

    def __init__(self, destination: str):
        if not os.path.isabs(destination) or os.path.normpath(destination) != destination:
            refuse("DESTINATION_PATH")
        try:
            if not stat.S_ISDIR(os.lstat(os.path.dirname(destination)).st_mode):
                refuse("DESTINATION_PARENT")
            os.mkdir(destination, 0o700)
        except FileExistsError:
            raise PublicationError("DESTINATION_EXISTS") from None
        except FileNotFoundError:
            raise PublicationError("DESTINATION_PARENT") from None
        self._fds = {"": os.open(destination, _DIR_FLAGS)}
        held, linked = os.fstat(self._fds[""]), os.lstat(destination)
        if (held.st_dev, held.st_ino) != (linked.st_dev, linked.st_ino) or os.listdir(self._fds[""]):
            self.close()
            refuse("DESTINATION_POLLUTED")
        os.fchmod(self._fds[""], 0o755)

    def _dir(self, rel: str) -> int:
        if rel not in self._fds:
            parent_rel, _, name = rel.rpartition("/")
            parent = self._dir(parent_rel)
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                raise PublicationError("DESTINATION_POLLUTED") from None
            self._fds[rel] = os.open(name, _DIR_FLAGS, dir_fd=parent)
            os.fchmod(self._fds[rel], 0o755)
        return self._fds[rel]

    def create(self, rel: str) -> int:
        parent_rel, _, name = rel.rpartition("/")
        try:
            fd = os.open(name, _NEW_FILE_FLAGS, 0o600, dir_fd=self._dir(parent_rel))
        except FileExistsError:
            raise PublicationError("DESTINATION_POLLUTED") from None
        os.fchmod(fd, 0o644)
        return fd

    def close(self) -> None:
        fds, self._fds = list(self._fds.values()), {}
        for fd in fds:
            os.close(fd)


def verify_tree(destination: str, inventory: dict) -> None:
    """Readback: exactly the inventoried regular files and their parents, modes 0644/0755."""
    seen_files, seen_dirs = set(), set()
    for current, dirnames, filenames in os.walk(destination, followlinks=False,
                                                onerror=lambda _e: refuse("DESTINATION_READBACK")):
        rel_dir = "" if current == destination else os.path.relpath(current, destination)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755 or any(
                not stat.S_ISDIR(os.lstat(os.path.join(current, d)).st_mode) for d in dirnames):
            refuse("DESTINATION_READBACK")
        seen_dirs.add(rel_dir)
        for name in filenames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            seen_files.add(rel)
            try:
                fd = os.open(os.path.join(current, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError:
                raise PublicationError("DESTINATION_READBACK") from None
            try:
                held = os.fstat(fd)
                if (rel not in inventory or not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                        or stat.S_IMODE(held.st_mode) != 0o644
                        or _hash_fd(fd, inventory[rel]["bytes"], "DESTINATION_READBACK") != inventory[rel]["sha256"]):
                    refuse("DESTINATION_READBACK")
            finally:
                os.close(fd)
    if seen_files != set(inventory) or seen_dirs != _parents(inventory) | {""}:
        refuse("DESTINATION_READBACK")


def admit_archive(fd: int, size: int, *, binding: dict, descriptor_sha256: str, destination: str) -> dict:
    """Structure → receipt → inventory binding → exclusive writes → readback. Never extractall."""
    cd_offset, entry_count = central_directory_bounds(fd, size)
    receipt_buf = bytearray()
    with open(os.dup(fd), "rb") as handle:
        try:
            zf = zipfile.ZipFile(handle)
        except _ZIP_ERRORS:
            raise PublicationError("ZIP_STRUCTURE") from None
        with zf:
            infos = zf.infolist()
            if (not 0 < len(infos) <= MAX_ENTRIES or len(infos) != entry_count
                    or zf.start_dir != cd_offset or zf.comment):
                refuse("ZIP_DIRECTORY")
            files, receipt_info = _plan_entries(infos)
            _check_layout(fd, infos, cd_offset)
            _stream(zf, receipt_info, receipt_buf.extend)
            inventory = gh.check_receipt(bytes(receipt_buf), binding, descriptor_sha256)
            if set(inventory) != set(files):
                refuse("INVENTORY_MEMBERS")
            for rel, info in sorted(files.items()):
                if inventory[rel]["bytes"] != info.file_size or _stream(zf, info) != inventory[rel]["sha256"]:
                    refuse("INVENTORY_BYTES")
            tree = _NewTree(destination)
            try:
                for rel, info in sorted(files.items()):
                    out = tree.create(rel)
                    try:
                        digest = _stream(zf, info, lambda chunk, out=out: _write_all(out, chunk))
                    finally:
                        os.close(out)
                    if digest != inventory[rel]["sha256"]:
                        refuse("DESTINATION_BYTES")
            finally:
                tree.close()
    verify_tree(destination, inventory)
    return {"inventory": inventory, "receipt_sha256": _sha(bytes(receipt_buf))}


def _validated(options: Options) -> tuple:
    if (options.repository != gh.REPOSITORY or not os.path.isabs(options.p_root)
            or not gh.HEX40.fullmatch(options.p_commit) or not gh.HEX40.fullmatch(options.p_tree)
            or not gh.HEX64.fullmatch(options.leaf_manifest_sha256)
            or not _RUN_ARG.fullmatch(options.qualification_run_id) or not _RUN_ARG.fullmatch(options.gui_run_id)
            or options.qualification_run_id == options.gui_run_id):
        refuse("OPTIONS")
    destination = os.path.realpath(options.destination)
    audit = os.path.realpath(options.audit_out)
    if os.path.commonpath([destination, audit]) == destination:
        refuse("AUDIT_INSIDE_DESTINATION")
    return int(options.qualification_run_id), int(options.gui_run_id)


def run_admission(options: Options, api, *, now=None, environ=None) -> dict:
    if gh.signing_secret_names_present(os.environ if environ is None else environ):
        refuse("SIGNING_SECRET_IN_ENVIRONMENT")
    now = datetime.now(timezone.utc) if now is None else now
    qual_id, gui_id = _validated(options)
    leaf = gh.read_small_regular(os.path.join(options.p_root, LEAF_MANIFEST_REL_PATH), "LEAF_MANIFEST_ABSENT")
    if _sha(leaf) != options.leaf_manifest_sha256:
        refuse("LEAF_MANIFEST_DIGEST")
    rs9, descriptor_sha256 = gh.authenticate_descriptor(options.p_root)
    binding = {"p_commit": options.p_commit, "p_tree": options.p_tree, "r_commit": rs9["source_commit"],
               "r_tree": rs9["source_tree"], "source_closure_sha256": options.leaf_manifest_sha256,
               "rs9_run": rs9["run_id"]}

    def admitted():
        return (gh.admit_run(api, qual_id, gh.QUALIFICATION, options.p_commit),
                gh.admit_run(api, gui_id, gh.GUI_VALIDATION, options.p_commit),
                gh.select_artifact(api, qual_id, options.p_commit, gh.ARTIFACT_PREFIX + str(rs9["run_id"]), now))

    qualification, gui, artifact = admitted()
    fd = api.download_zip(artifact.artifact_id, artifact.size)
    try:
        held = os.fstat(fd)
        if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or held.st_size != artifact.size:
            refuse("ARCHIVE_SIZE")
        if _hash_fd(fd, artifact.size, "ARCHIVE_SIZE") != artifact.sha256:
            refuse("ARCHIVE_DIGEST")
        staged = admit_archive(fd, artifact.size, binding=binding, descriptor_sha256=descriptor_sha256,
                               destination=options.destination)
    finally:
        os.close(fd)
    if admitted() != (qualification, gui, artifact):  # fresh revalidation: no rerun/replacement
        refuse("API_STATE_CHANGED")
    inventory = staged["inventory"]
    audit = dict(binding, schema=AUDIT_SCHEMA, status="admitted-awaiting-attended-deployment",
                 repository=gh.REPOSITORY, descriptor_sha256=descriptor_sha256,
                 qualification_run_id=qual_id, gui_validation_run_id=gui_id,
                 qualification_workflow_id=qualification["workflow_id"], gui_workflow_id=gui["workflow_id"],
                 native_client_jobs_authenticated=list(qualification["jobs"]),
                 gui_jobs_authenticated=list(gui["jobs"]), artifact_id=artifact.artifact_id,
                 artifact_name=artifact.name, artifact_digest_sha256=artifact.sha256, archive_bytes=artifact.size,
                 receipt_sha256=staged["receipt_sha256"], public_file_count=len(inventory),
                 public_total_bytes=sum(e["bytes"] for e in inventory.values()),
                 public_inventory_sha256=_sha(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()),
                 worker_receipt_role="non-publishing-source-proof", worker_receipt_publication_authority=False,
                 worker_receipt_native_client_qualification=False, signing_performed=False, deployed=False)
    _write_audit(options.audit_out, audit)
    return audit


def _write_audit(path: str, audit: dict) -> None:
    try:
        fd = os.open(path, _NEW_FILE_FLAGS, 0o600) if os.path.isabs(path) else refuse("AUDIT_PATH")
    except OSError:
        raise PublicationError("AUDIT_PATH") from None
    try:
        os.fchmod(fd, 0o644)
        _write_all(fd, (json.dumps(audit, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for field in fields(Options):
        parser.add_argument("--" + field.name.replace("_", "-"), dest=field.name, required=True)
    args = parser.parse_args(argv)
    try:
        if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
            refuse("PYTHON_ISOLATION_FLAGS")
        if os.path.dirname(os.path.realpath(gh.__file__)) != os.path.dirname(os.path.realpath(__file__)):
            refuse("IMPORT_IDENTITY")
        if gh.signing_secret_names_present(os.environ):
            refuse("SIGNING_SECRET_IN_ENVIRONMENT")
        options = Options(**{f.name: getattr(args, f.name) for f in fields(Options)})
        token = os.environ.get("GH_TOKEN") or refuse("TOKEN_ABSENT")
        audit = run_admission(options, gh.GhApiTransport(token, options.work_root))
    except PublicationError as error:
        print(f"REFUSED {error.code}", file=sys.stderr)
        if gh._RETAINED_CHILDREN:
            print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    except Exception:
        print("REFUSED INTERNAL", file=sys.stderr)
        if gh._RETAINED_CHILDREN:
            print("TRANSPORT_CHILD_RETAINED", file=sys.stderr)
        return 2
    print(f"ADMITTED artifact_id={audit['artifact_id']} public_file_count={audit['public_file_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
