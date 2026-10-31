"""Private fresh-workspace identity binding and fail-closed cleanup."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile

_MODULE_DIR = str(Path(__file__).resolve(strict=True).parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from b3_fixture_types import FixtureError, FsIdentity, WorkspaceBinding


def _validate_job_parent(path: str | os.PathLike[str]) -> Path:
    parent = _absolute_path(path, "job parent")
    try:
        info = os.lstat(parent)
    except OSError as error:
        raise FixtureError("JOB_PARENT_MISSING") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise FixtureError("JOB_PARENT_DIRECTORY")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise FixtureError("JOB_PARENT_CUSTODY")
    return parent


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


def _fs_identity(info: os.stat_result) -> FsIdentity:
    return FsIdentity(
        dev=info.st_dev,
        ino=info.st_ino,
        uid=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
        kind=stat.S_IFMT(info.st_mode),
    )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _close_partial_fds(*descriptors: int | None) -> None:
    """Close only this wrapper's acquired handles, including partial allocation."""
    for fd in descriptors:
        if fd is None:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _close_workspace_binding(binding: WorkspaceBinding | None) -> None:
    if binding is not None:
        _close_partial_fds(binding.home_fd, binding.root_fd, binding.parent_fd)


def _same_path_identity(path: Path, expected: FsIdentity) -> bool:
    try:
        return _fs_identity(os.lstat(path)) == expected
    except OSError:
        return False


def _same_fd_identity(fd: int, expected: FsIdentity) -> bool:
    try:
        return _fs_identity(os.fstat(fd)) == expected
    except OSError:
        return False


def _fresh_workspace(parent: Path) -> WorkspaceBinding:
    """Create one fresh home and retain physical identities plus directory FDs."""
    parent = _validate_job_parent(parent)
    parent_fd: int | None = None
    root_fd: int | None = None
    home_fd: int | None = None
    job_root: Path | None = None
    try:
        parent_identity = _fs_identity(os.lstat(parent))
        parent_fd = os.open(parent, _directory_open_flags())
        if not _same_fd_identity(parent_fd, parent_identity):
            raise FixtureError("WORKSPACE_PARENT_CHANGED")
        job_root = Path(tempfile.mkdtemp(prefix="tf-b3-life-", dir=parent))
        root_fd = os.open(job_root.name, _directory_open_flags(), dir_fd=parent_fd)
        os.fchmod(root_fd, 0o700)
        root_identity = _fs_identity(os.fstat(root_fd))
        if not _same_path_identity(job_root, root_identity):
            raise FixtureError("WORKSPACE_ROOT_REPLACED")
        if not _same_path_identity(parent, parent_identity):
            raise FixtureError("WORKSPACE_PARENT_CHANGED")
        os.mkdir("home", 0o700, dir_fd=root_fd)
        home_fd = os.open("home", _directory_open_flags(), dir_fd=root_fd)
        os.fchmod(home_fd, 0o700)
        home = job_root / "home"
        home_identity = _fs_identity(os.fstat(home_fd))
        if not _same_path_identity(home, home_identity):
            raise FixtureError("WORKSPACE_HOME_REPLACED")
        if not _same_path_identity(parent, parent_identity):
            raise FixtureError("WORKSPACE_PARENT_CHANGED")
        return WorkspaceBinding(parent, job_root, home, parent_fd, root_fd, home_fd,
                                parent_identity, root_identity, home_identity)
    except FixtureError as error:
        _close_partial_fds(home_fd, root_fd, parent_fd)
        if job_root is not None and not error.retained_custody:
            raise FixtureError(error.code, retained_custody=True, retained_root=job_root,
                               sanitized_detail=error.sanitized_detail) from error
        raise
    except OSError as error:
        _close_partial_fds(home_fd, root_fd, parent_fd)
        raise FixtureError("WORKSPACE_CREATE", retained_custody=job_root is not None, retained_root=job_root) from error


def _remove_fresh_workspace(binding: WorkspaceBinding) -> None:
    """Remove only the exact empty entries proven by the held identities."""
    root = binding.root
    try:
        if (
            not _same_fd_identity(binding.parent_fd, binding.parent_identity)
            or not _same_path_identity(binding.parent, binding.parent_identity)
            or not _same_fd_identity(binding.root_fd, binding.root_identity)
            or not _same_path_identity(root, binding.root_identity)
            or not _same_fd_identity(binding.home_fd, binding.home_identity)
            or not _same_path_identity(binding.home, binding.home_identity)
        ):
            raise FixtureError("WORKSPACE_IDENTITY_CHANGED", retained_custody=True, retained_root=root)
        root_entries = os.listdir(binding.root_fd)
        home_entries = os.listdir(binding.home_fd)
        if set(root_entries) != {binding.home.name} or home_entries:
            extra_root = len([name for name in root_entries if name != binding.home.name])
            raise FixtureError(
                "WORKSPACE_CLEANUP_UNCONFIRMED",
                retained_custody=True,
                retained_root=root,
                sanitized_detail={
                    "workspace_removed_confirmed": False,
                    "unexpected_root_entry_count": extra_root,
                    "unexpected_home_entry_count": len(home_entries),
                },
            )
        os.rmdir(binding.home.name, dir_fd=binding.root_fd)
        try:
            os.lstat(binding.home.name, dir_fd=binding.root_fd)
        except FileNotFoundError:
            pass
        else:
            raise FixtureError("WORKSPACE_CLEANUP_UNCONFIRMED", retained_custody=True, retained_root=root)
        os.rmdir(root.name, dir_fd=binding.parent_fd)
        try:
            os.lstat(root.name, dir_fd=binding.parent_fd)
        except FileNotFoundError:
            return
        raise FixtureError("WORKSPACE_CLEANUP_UNCONFIRMED", retained_custody=True, retained_root=root)
    except FixtureError:
        raise
    except OSError as error:
        raise FixtureError("WORKSPACE_CLEANUP_UNCONFIRMED", retained_custody=True, retained_root=root) from error
    finally:
        _close_workspace_binding(binding)
