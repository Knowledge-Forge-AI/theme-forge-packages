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

_MAX_DIAGNOSTIC_ENTRIES = 64
_PRIVATE_KEYS_DIR_NAME = "private-keys-v1.d"
_HOME_NAME_CATEGORIES = (
    "private_keys_directory",
    "random_seed",
    "primary_socket",
    "extra_socket",
    "browser_socket",
    "ssh_socket",
    "common_config",
    "other",
)
_KNOWN_HOME_ENTRY_NAMES = {
    _PRIVATE_KEYS_DIR_NAME: "private_keys_directory",
    "random_seed": "random_seed",
    "S.gpg-agent": "primary_socket",
    "S.gpg-agent.extra": "extra_socket",
    "S.gpg-agent.browser": "browser_socket",
    "S.gpg-agent.ssh": "ssh_socket",
    "common.conf": "common_config",
}
_HOME_TYPE_CATEGORIES = (
    "regular",
    "directory",
    "symlink",
    "socket",
    "other",
    "vanished",
    "unreadable",
)
_MODE_TYPE_LABELS = (
    (stat.S_ISREG, "regular"),
    (stat.S_ISDIR, "directory"),
    (stat.S_ISLNK, "symlink"),
    (stat.S_ISSOCK, "socket"),
)


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


def _entry_type_key(name: str, home_fd: int) -> str:
    try:
        mode = os.lstat(name, dir_fd=home_fd).st_mode
    except FileNotFoundError:
        return "vanished"
    except OSError:
        return "unreadable"
    for check, label in _MODE_TYPE_LABELS:
        if check(mode):
            return label
    return "other"


def _private_keys_dir_summary(
    status: str = "absent",
    *,
    empty: bool = False,
    entry_count: int = 0,
) -> dict[str, int | bool | str]:
    return {
        "present": status != "absent",
        "status": status,
        "identity_verified": status in {"complete", "truncated"},
        "empty": empty,
        "entry_count": entry_count,
        "truncated": status == "truncated",
    }


def _inspect_private_keys_dir(home_fd: int, present: bool) -> dict[str, int | bool | str]:
    if not present:
        return _private_keys_dir_summary()
    pk_fd: int | None = None
    try:
        info = os.lstat(_PRIVATE_KEYS_DIR_NAME, dir_fd=home_fd)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return _private_keys_dir_summary("not-directory")
        expected = _fs_identity(info)
        pk_fd = os.open(_PRIVATE_KEYS_DIR_NAME, _directory_open_flags(), dir_fd=home_fd)
        if info.st_uid != os.getuid() or not _same_fd_identity(pk_fd, expected):
            return _private_keys_dir_summary("identity-mismatch")
        children = os.listdir(pk_fd)
    except FileNotFoundError:
        return _private_keys_dir_summary("vanished")
    except Exception:
        return _private_keys_dir_summary("unreadable")
    finally:
        _close_partial_fds(pk_fd)
    truncated = len(children) > _MAX_DIAGNOSTIC_ENTRIES
    count = min(len(children), _MAX_DIAGNOSTIC_ENTRIES)
    return _private_keys_dir_summary(
        "truncated" if truncated else "complete",
        empty=(not truncated and count == 0),
        entry_count=count,
    )


def _summarize_cleanup_leftovers(
    home_fd: int,
    root_entries: list[str],
    home_entries: list[str],
    home_name: str,
) -> dict[str, object]:
    category_counts = dict.fromkeys(_HOME_NAME_CATEGORIES, 0)
    type_counts = dict.fromkeys(_HOME_TYPE_CATEGORIES, 0)
    extra_root = len(root_entries) - int(home_name in root_entries)
    bounded_home = home_entries[:_MAX_DIAGNOSTIC_ENTRIES]
    home_truncated = len(home_entries) > _MAX_DIAGNOSTIC_ENTRIES
    truncated = home_truncated or len(root_entries) > _MAX_DIAGNOSTIC_ENTRIES
    incomplete = False
    inspected = 0
    try:
        for name in bounded_home:
            inspected += 1
            category_counts[_KNOWN_HOME_ENTRY_NAMES.get(name, "other")] += 1
            type_counts[_entry_type_key(name, home_fd)] += 1
    except Exception:
        incomplete = True
    pk_summary = _inspect_private_keys_dir(home_fd, _PRIVATE_KEYS_DIR_NAME in home_entries)
    incomplete = (
        incomplete
        or type_counts["vanished"] > 0
        or type_counts["unreadable"] > 0
        or pk_summary["status"] in {"identity-mismatch", "vanished", "unreadable"}
    )
    status = (
        "incomplete"
        if incomplete
        else ("truncated" if (truncated or bool(pk_summary["truncated"])) else "complete")
    )
    return {
        "workspace_removed_confirmed": False,
        "unexpected_root_entry_count": extra_root,
        "unexpected_home_entry_count": len(home_entries),
        "home_diagnostics_status": status,
        "home_entries_inspected_count": inspected,
        "home_entries_truncated": home_truncated,
        "home_entry_category_counts": category_counts,
        "home_entry_type_counts": type_counts,
        "private_keys_directory": pk_summary,
    }


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
            raise FixtureError(
                "WORKSPACE_CLEANUP_UNCONFIRMED",
                retained_custody=True,
                retained_root=root,
                sanitized_detail=_summarize_cleanup_leftovers(
                    binding.home_fd,
                    root_entries,
                    home_entries,
                    binding.home.name,
                ),
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
