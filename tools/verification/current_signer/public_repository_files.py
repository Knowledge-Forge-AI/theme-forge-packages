"""Bounded physical snapshots and new-output writes for public verification."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from types import MappingProxyType

import apt_signature_adapter as apt
from rs9.scratch import ConfinedWriter, verify_public_tree_modes
from rs9.security import validate_safe_relative_posix_path

MAX_FILES = 256
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class Snapshot:
    root: Path
    members: object
    identities: object


def _refuse(code):
    raise apt.SignatureValidationError(code, "Public repository filesystem check refused")


def physical_root(root, *, empty=False) -> Path:
    path = apt._absolute_path(root, "public repository root")
    info = apt._lstat_no_symlink(path, "public repository root")
    if (info is None or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022):
        _refuse("PUBLIC_ROOT")
    if empty and os.listdir(path):
        _refuse("PUBLIC_ROOT_NOT_EMPTY")
    return path


def _directory_identity(path):
    info = path.lstat()
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_mtime_ns, info.st_ctime_ns)


def _capture(root) -> Snapshot:
    path = physical_root(root)
    members, identities, directories, total = {}, {"": _directory_identity(path)}, {""}, 0
    def walk_error(error):
        raise error
    for directory, names, files in os.walk(path, followlinks=False, onerror=walk_error):
        current = Path(directory)
        for name in sorted(names):
            child = current / name
            if name == ".protected-work":
                _refuse("PRIVATE_WORK_PRESENT")
            info = child.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022):
                _refuse("PUBLIC_DIRECTORY")
            relative = child.relative_to(path).as_posix()
            validate_safe_relative_posix_path(relative)
            if len(Path(relative).parts) > 16 or len(directories) >= MAX_FILES:
                _refuse("PUBLIC_DIRECTORY_COUNT")
            directories.add(relative)
            identities[relative + "/"] = _directory_identity(child)
        for name in sorted(files):
            relative = (current / name).relative_to(path).as_posix()
            validate_safe_relative_posix_path(relative)
            if len(members) >= MAX_FILES:
                _refuse("PUBLIC_FILE_COUNT")
            info = (current / name).lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022):
                _refuse("PUBLIC_FILE_CUSTODY")
            body, identity = apt._read_regular(current / name, "public repository member", MAX_FILE_BYTES)
            total += len(body)
            if total > MAX_TOTAL_BYTES:
                _refuse("PUBLIC_TOTAL_BOUND")
            members[relative], identities[relative] = body, identity
    expected = {""}
    for relative in members:
        expected.update(str(p) for p in Path(relative).parents if str(p) != ".")
    if directories != expected:
        _refuse("PUBLIC_DIRECTORY_INVENTORY")
    if identities[""] != _directory_identity(path):
        _refuse("PUBLIC_ROOT_MUTATED")
    for relative in directories - {""}:
        if identities[relative + "/"] != _directory_identity(path / relative):
            _refuse("PUBLIC_DIRECTORY_MUTATED")
    return Snapshot(path, MappingProxyType(members), MappingProxyType(identities))


def snapshot(root) -> Snapshot:
    try:
        return _capture(root)
    except BaseException as error:
        # Preserve actual exception frames and existing safe-reader ownership.
        # This is process-local custody, never serialized or retried.
        apt._retain_public_verifier({"snapshot_error": error})
        raise


def unchanged(prior: Snapshot) -> None:
    current = snapshot(prior.root)
    if current.members != prior.members or current.identities != prior.identities:
        _refuse("PUBLIC_SNAPSHOT_MUTATED")


def write_new(root, members) -> None:
    path = physical_root(root, empty=True)
    writer = None
    try:
        with ConfinedWriter(path, file_mode=0o644, dir_mode=0o755) as writer:
            for relative in sorted(members):
                writer.write(relative, members[relative])
            # Only this new, public-only output tree is normalized. Keep the
            # existing root descriptor held through permission readback.
            linked = apt._lstat_no_symlink(path, "public repository root")
            if linked is None or apt._file_identity(linked) != apt._file_identity(os.fstat(writer.fd)):
                _refuse("PUBLIC_ROOT_MUTATED")
            os.fchmod(writer.fd, 0o755)
            verify_public_tree_modes(path, raise_on_error=True)
    except BaseException as error:
        apt._retain_public_verifier({"writer": writer, "original_error": error})
        raise


def inventory(members) -> dict:
    return {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(members.items())}
