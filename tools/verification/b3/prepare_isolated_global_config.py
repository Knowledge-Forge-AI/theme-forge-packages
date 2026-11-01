"""Proposed-unadopted build-time global-config isolation helper for the B3 Fedora 43 builder.

Supports two strict, authenticated preparation modes inside the disposable builder:
1. Packaged regular-config relocation (relocated-packaged-regular-config): relocates
   unmodified /etc/gnupg/gpgconf.conf into image quarantine and removes empty /etc/gnupg.
2. Package-owned empty ghost-config directory removal (removed-empty-rpm-ghost-config-dir):
   verifies installed RPM %ghost %config(noreplace) metadata (flags 81, size 0, empty
   digest) and clean rpm -V, removes proved-empty /etc/gnupg, and writes a receipt-only
   custody proof. Refuses if /usr/bin/gpgconf.ctl is present or any guard fails.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping

SCHEMA = "tf.current-signer-native-b3-global-config-preparation.v1"
SOURCE_AUTH_SCHEMA = "tf.current-signer-native-b3-global-config-source-auth.v1"
PROPOSAL_STATUS = "proposed-unadopted"

REGULAR_CONFIG_MODE = "relocated-packaged-regular-config"
EMPTY_GHOST_DIR_MODE = "removed-empty-rpm-ghost-config-dir"

RPMFILE_CONFIG = 1
RPMFILE_NOREPLACE = 16
RPMFILE_GHOST = 64
EXPECTED_GHOST_CONFIG_FILEFLAGS = RPMFILE_CONFIG | RPMFILE_NOREPLACE | RPMFILE_GHOST
EXPECTED_GHOST_CONFIG_FILESIZE = 0
EXPECTED_GHOST_CONFIG_FILEDIGEST = ""
EXPECTED_GHOST_CONFIG_DECLARATION = "ghost+config(noreplace)"

EXPECTED_PACKAGE_NAME = "gnupg2-gpgconf"
EXPECTED_PACKAGE_VERSION = "2.4.9"
EXPECTED_PACKAGE_RELEASE = "5.fc43"
EXPECTED_PACKAGE_ARCH = "x86_64"
EXPECTED_PACKAGE_NEVRA = "gnupg2-gpgconf-2.4.9-5.fc43.x86_64"
EXPECTED_PACKAGE_TUPLE = (
    EXPECTED_PACKAGE_NAME,
    EXPECTED_PACKAGE_VERSION,
    EXPECTED_PACKAGE_RELEASE,
    EXPECTED_PACKAGE_ARCH,
)

REVIEWED_C6_SOURCE_SHA256 = "305f613aa989f807d5155c082e568d8e0c79ba63aa4ab8a25252433250c5c2cf"

ETC_GNUPG_PATH = "/etc/gnupg"
SOURCE_CONFIG_PATH = "/etc/gnupg/gpgconf.conf"
SOURCE_CONFIG_NAME = "gpgconf.conf"
QUARANTINE_DIR_NAME = "tf-b3-global-config-quarantine"
QUARANTINE_DIR_PATH = "/etc/tf-b3-global-config-quarantine"
QUARANTINE_CONFIG_PATH = "/etc/tf-b3-global-config-quarantine/gpgconf.conf"
QUARANTINE_RECEIPT_NAME = "b3-global-config-preparation.json"
QUARANTINE_RECEIPT_PATH = "/etc/tf-b3-global-config-quarantine/b3-global-config-preparation.json"
GPGCONF_CTL_PATH = "/usr/bin/gpgconf.ctl"
RPM_BINARY_PATH = "/usr/bin/rpm"

MAX_CONFIG_BYTES = 65_536
MAX_JSON_BYTES = 65_536
MAX_RPM_OUTPUT_BYTES = 4_096
MAX_SOURCE_BYTES = 2_000_000

_DECIMAL_INT = re.compile(r"^[0-9]+$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ABS_PATH = re.compile(r"^/[A-Za-z0-9/._-]+$")
_FORBIDDEN_ENV_TOKENS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSPHRASE",
    "PRIVATE_KEY",
    "SIGNING_KEY",
    "CREDENTIAL",
)


class GlobalConfigError(RuntimeError):
    """Closed error boundary; callers must never emit raw exception strings or paths."""

    def __init__(
        self, code: str, *, original_bytes_preserved: bool = True,
        mutation_performed: bool = False, rollback_verified: bool | None = None,
    ):
        self.code = code
        self.original_bytes_preserved = bool(original_bytes_preserved)
        self.mutation_performed = bool(mutation_performed)
        self.rollback_verified = None if rollback_verified is None else bool(rollback_verified)
        super().__init__(code)


@dataclass(frozen=True)
class FsIdentity:
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    kind: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _OpenedGnupgDir:
    root_dir: Path
    etc_dir: Path
    etc_fd: int
    etc_identity: FsIdentity
    gnupg_dir: Path
    gnupg_fd: int
    gnupg_identity: FsIdentity
    expected_uid: int
    expected_gid: int | None
    entries: tuple[str, ...]


@dataclass(frozen=True)
class _SourceConfigSnapshot:
    etc_dir: Path
    etc_identity: FsIdentity
    gnupg_dir: Path
    gnupg_identity: FsIdentity
    config_identity: FsIdentity
    config_bytes: bytes
    config_sha256: str


def _fs_identity(info: os.stat_result) -> FsIdentity:
    return FsIdentity(
        dev=info.st_dev,
        ino=info.st_ino,
        uid=info.st_uid,
        gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
        kind=stat.S_IFMT(info.st_mode),
        nlink=info.st_nlink,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _file_read_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _file_create_flags() -> int:
    return (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _close_fds(*fds: int | None) -> None:
    for fd in fds:
        if fd is None:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _owner_matches(info: os.stat_result, expected_uid: int, expected_gid: int | None) -> bool:
    return info.st_uid == expected_uid and (expected_gid is None or info.st_gid == expected_gid)


def _check_credential_free_env(env_map: Mapping[str, str] | None = None) -> None:
    env = os.environ if env_map is None else env_map
    for key, value in env.items():
        upper = key.upper()
        if value and any(token in upper for token in _FORBIDDEN_ENV_TOKENS):
            raise GlobalConfigError("CREDENTIAL_ENV_FORBIDDEN")


def check_native_support() -> None:
    if sys.platform != "linux" or sys.version_info < (3, 11):
        raise GlobalConfigError("UNSUPPORTED_PLATFORM")


def _validate_hex64(value: str | None, code: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise GlobalConfigError(code)
    return value


def _absolute_output_path(value: str | os.PathLike[str], label: str) -> Path:
    raw = os.fspath(value)
    if (
        not isinstance(raw, str)
        or not _SAFE_ABS_PATH.fullmatch(raw)
        or any(part in {"", ".", ".."} for part in raw.split("/")[1:])
    ):
        raise GlobalConfigError(f"{label.upper().replace(' ', '_')}_PATH")
    return Path(raw)


def _read_opened_regular_fd(
    fd: int, expected_identity: FsIdentity, max_bytes: int, error_prefix: str
) -> bytes:
    fstat_info = os.fstat(fd)
    if _fs_identity(fstat_info) != expected_identity:
        raise GlobalConfigError(f"{error_prefix}_CHANGED")
    if fstat_info.st_size <= 0 or fstat_info.st_size > max_bytes:
        raise GlobalConfigError(f"{error_prefix}_SIZE_INVALID")
    chunks: list[bytes] = []
    remaining = fstat_info.st_size + 1
    while remaining > 0:
        chunk = os.read(fd, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) != fstat_info.st_size or _fs_identity(os.fstat(fd)) != expected_identity:
        raise GlobalConfigError(f"{error_prefix}_CHANGED")
    return data


def _sha256_regular_file(path: Path, max_bytes: int, error_prefix: str) -> str:
    try:
        lstat_info = os.lstat(path)
    except OSError as error:
        raise GlobalConfigError(f"{error_prefix}_MISSING") from error
    if stat.S_ISLNK(lstat_info.st_mode) or not stat.S_ISREG(lstat_info.st_mode):
        raise GlobalConfigError(f"{error_prefix}_NOT_REGULAR")
    fd: int | None = None
    try:
        fd = os.open(path, _file_read_flags())
        data = _read_opened_regular_fd(fd, _fs_identity(lstat_info), max_bytes, error_prefix)
        return hashlib.sha256(data).hexdigest()
    except GlobalConfigError:
        raise
    except OSError as error:
        raise GlobalConfigError(f"{error_prefix}_READ") from error
    finally:
        _close_fds(fd)


def _default_command_runner(argv: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            close_fds=True,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise GlobalConfigError("RPM_COMMAND_EXEC_FAILED") from error
    if len(completed.stdout) > MAX_RPM_OUTPUT_BYTES:
        raise GlobalConfigError("RPM_COMMAND_OUTPUT_TOO_LARGE")
    try:
        text = completed.stdout.decode("utf-8")
    except UnicodeError as error:
        raise GlobalConfigError("RPM_COMMAND_OUTPUT_ENCODING") from error
    if "\x00" in text:
        raise GlobalConfigError("RPM_COMMAND_OUTPUT_NUL")
    return completed.returncode, text


def _validate_safe_dir_stat(
    info: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int | None,
    forbidden_mode_mask: int,
    error_code: str,
) -> FsIdentity:
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or not _owner_matches(info, expected_uid, expected_gid)
        or (info.st_mode & forbidden_mode_mask) != 0
    ):
        raise GlobalConfigError(error_code)
    return _fs_identity(info)


def _ensure_absent_at(dir_fd: int | None, path_or_name: Path | str, error_code: str) -> None:
    try:
        if dir_fd is None:
            os.lstat(path_or_name)
        else:
            os.lstat(path_or_name, dir_fd=dir_fd)
    except FileNotFoundError:
        return
    except OSError as error:
        raise GlobalConfigError(error_code) from error
    raise GlobalConfigError(error_code)


def _verify_usr_bin_and_absent_gpgconf_ctl(
    root_dir: Path, *, expected_uid: int, expected_gid: int | None
) -> None:
    for rel in (Path("."), Path("usr"), Path("usr/bin")):
        target = root_dir if rel == Path(".") else root_dir / rel
        try:
            info = os.lstat(target)
        except OSError as error:
            raise GlobalConfigError("USR_BIN_ANCESTRY_UNSAFE") from error
        _validate_safe_dir_stat(
            info,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            forbidden_mode_mask=0o022,
            error_code="USR_BIN_ANCESTRY_UNSAFE",
        )
    _ensure_absent_at(None, root_dir / "usr/bin/gpgconf.ctl", "GPGCONF_CTL_PRESENT_REFUSED")


def _verify_rpm_tool(root_dir: Path, *, expected_uid: int, expected_gid: int | None) -> None:
    rpm_path = root_dir / "usr/bin/rpm"
    try:
        lstat_info = os.lstat(rpm_path)
    except OSError as error:
        raise GlobalConfigError("RPM_TOOL_UNSAFE") from error
    if (
        stat.S_ISLNK(lstat_info.st_mode)
        or not stat.S_ISREG(lstat_info.st_mode)
        or not _owner_matches(lstat_info, expected_uid, expected_gid)
        or (lstat_info.st_mode & 0o6022) != 0
        or (lstat_info.st_mode & 0o111) == 0
    ):
        raise GlobalConfigError("RPM_TOOL_UNSAFE")
    fd: int | None = None
    try:
        fd = os.open(rpm_path, _file_read_flags())
        if _fs_identity(os.fstat(fd)) != _fs_identity(lstat_info):
            raise GlobalConfigError("RPM_TOOL_UNSAFE")
    except GlobalConfigError:
        raise
    except OSError as error:
        raise GlobalConfigError("RPM_TOOL_UNSAFE") from error
    finally:
        _close_fds(fd)


def _verify_rpm_owner_tuple(command_runner: Callable[[list[str]], tuple[int, str]]) -> None:
    rc, owner_text = command_runner([
        RPM_BINARY_PATH,
        "-qf",
        "--queryformat",
        "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n",
        ETC_GNUPG_PATH,
        SOURCE_CONFIG_PATH,
    ])
    if rc != 0 or not owner_text:
        raise GlobalConfigError("RPM_OWNER_QUERY_FAILED")
    owner_lines = [line.strip() for line in owner_text.splitlines() if line.strip()]
    if len(owner_lines) != 2:
        raise GlobalConfigError("RPM_OWNER_QUERY_FAILED")
    for line in owner_lines:
        parts = tuple(line.split("\t"))
        if len(parts) != 4:
            raise GlobalConfigError("RPM_OWNER_QUERY_FAILED")
        if parts != EXPECTED_PACKAGE_TUPLE:
            raise GlobalConfigError("RPM_PACKAGE_TUPLE_MISMATCH")


def _verify_rpm_package_inventory(command_runner: Callable[[list[str]], tuple[int, str]]) -> None:
    rc, list_text = command_runner([RPM_BINARY_PATH, "-ql", EXPECTED_PACKAGE_NEVRA])
    if rc != 0 or not list_text:
        raise GlobalConfigError("RPM_PACKAGE_INVENTORY_MISMATCH")
    pkg_files = [line.strip() for line in list_text.splitlines() if line.strip()]
    if GPGCONF_CTL_PATH in pkg_files:
        raise GlobalConfigError("GPGCONF_CTL_PRESENT_REFUSED")
    etc_files = [p for p in pkg_files if p == "/etc" or p.startswith("/etc/")]
    if len(etc_files) != 2 or sorted(etc_files) != [ETC_GNUPG_PATH, SOURCE_CONFIG_PATH]:
        raise GlobalConfigError("RPM_PACKAGE_INVENTORY_MISMATCH")


def _parse_rpm_file_digests(digest_text: str) -> dict[str, str]:
    digest_map: dict[str, str] = {}
    for raw_line in digest_text.splitlines():
        if not raw_line.strip():
            continue
        if "\t" not in raw_line:
            raise GlobalConfigError("RPM_CONFIG_DIGEST_QUERY_FAILED")
        path_part, digest_part = raw_line.split("\t", 1)
        path_key = path_part.strip()
        if not path_key or path_key in digest_map:
            raise GlobalConfigError("RPM_CONFIG_DIGEST_QUERY_FAILED")
        digest_map[path_key] = digest_part.strip().lower()
    return digest_map


def _verify_rpm_config_digest(
    command_runner: Callable[[list[str]], tuple[int, str]], expected_config_sha256: str
) -> None:
    rc, digest_text = command_runner([
        RPM_BINARY_PATH,
        "-q",
        "--queryformat",
        "[%{FILENAMES}\t%{FILEDIGESTS}\n]",
        EXPECTED_PACKAGE_NEVRA,
    ])
    if rc != 0 or not digest_text:
        raise GlobalConfigError("RPM_CONFIG_DIGEST_QUERY_FAILED")
    digest_map = _parse_rpm_file_digests(digest_text)
    rpm_cfg_digest = digest_map.get(SOURCE_CONFIG_PATH)
    if not isinstance(rpm_cfg_digest, str) or not _HEX64.fullmatch(rpm_cfg_digest):
        raise GlobalConfigError("RPM_CONFIG_DIGEST_QUERY_FAILED")
    if rpm_cfg_digest != expected_config_sha256:
        raise GlobalConfigError("RPM_CONFIG_DIGEST_MISMATCH")


def _verify_rpm_package_clean(command_runner: Callable[[list[str]], tuple[int, str]]) -> None:
    rc, verify_text = command_runner([
        RPM_BINARY_PATH,
        "-V",
        "--nodeps",
        "--noscripts",
        EXPECTED_PACKAGE_NEVRA,
    ])
    if rc != 0 or verify_text.strip() != "":
        raise GlobalConfigError("RPM_VERIFY_MODIFIED_OR_FAILED")


def _verify_rpm_package_and_config(
    command_runner: Callable[[list[str]], tuple[int, str]], *, expected_config_sha256: str
) -> None:
    _verify_rpm_owner_tuple(command_runner)
    _verify_rpm_package_inventory(command_runner)
    _verify_rpm_config_digest(command_runner, expected_config_sha256)
    _verify_rpm_package_clean(command_runner)


def _parse_rpm_file_metadata_line(raw_line: str) -> tuple[str, tuple[int, int, str]]:
    parts = raw_line.split("\t")
    if len(parts) != 4:
        raise GlobalConfigError("RPM_GHOST_CONFIG_METADATA_QUERY_FAILED")
    path_key, flags_raw, size_raw, digest_raw = (p.strip() for p in parts)
    if not path_key or not _DECIMAL_INT.fullmatch(flags_raw) or not _DECIMAL_INT.fullmatch(size_raw):
        raise GlobalConfigError("RPM_GHOST_CONFIG_METADATA_QUERY_FAILED")
    return path_key, (int(flags_raw), int(size_raw), digest_raw.lower())


def _parse_rpm_file_metadata(metadata_text: str) -> dict[str, tuple[int, int, str]]:
    metadata_map: dict[str, tuple[int, int, str]] = {}
    for raw_line in metadata_text.splitlines():
        if not raw_line.strip():
            continue
        path_key, entry = _parse_rpm_file_metadata_line(raw_line)
        if path_key in metadata_map:
            raise GlobalConfigError("RPM_GHOST_CONFIG_METADATA_QUERY_FAILED")
        metadata_map[path_key] = entry
    return metadata_map


def _verify_rpm_ghost_config_metadata(
    command_runner: Callable[[list[str]], tuple[int, str]],
) -> None:
    rc, metadata_text = command_runner([
        RPM_BINARY_PATH, "-q", "--queryformat",
        "[%{FILENAMES}\t%{FILEFLAGS}\t%{FILESIZES}\t%{FILEDIGESTS}\n]",
        EXPECTED_PACKAGE_NEVRA,
    ])
    if rc != 0 or not metadata_text:
        raise GlobalConfigError("RPM_GHOST_CONFIG_METADATA_QUERY_FAILED")
    metadata_map = _parse_rpm_file_metadata(metadata_text)
    dir_meta = metadata_map.get(ETC_GNUPG_PATH)
    cfg_meta = metadata_map.get(SOURCE_CONFIG_PATH)
    if dir_meta is None or cfg_meta is None:
        raise GlobalConfigError("RPM_GHOST_CONFIG_METADATA_QUERY_FAILED")
    if dir_meta != (0, 0, ""):
        raise GlobalConfigError("RPM_GNUPG_DIR_METADATA_MISMATCH")
    flags, size, digest = cfg_meta
    if flags != EXPECTED_GHOST_CONFIG_FILEFLAGS:
        raise GlobalConfigError("RPM_GHOST_CONFIG_FLAGS_MISMATCH")
    if size != EXPECTED_GHOST_CONFIG_FILESIZE:
        raise GlobalConfigError("RPM_GHOST_CONFIG_SIZE_MISMATCH")
    if digest != EXPECTED_GHOST_CONFIG_FILEDIGEST:
        raise GlobalConfigError("RPM_GHOST_CONFIG_DIGEST_MISMATCH")


def _verify_rpm_package_and_ghost_config(
    command_runner: Callable[[list[str]], tuple[int, str]],
) -> None:
    _verify_rpm_owner_tuple(command_runner)
    _verify_rpm_package_inventory(command_runner)
    _verify_rpm_ghost_config_metadata(command_runner)
    _verify_rpm_package_clean(command_runner)


def _path_matches_identity(
    path_or_name: Path | str, expected: FsIdentity, *, dir_fd: int | None = None
) -> bool:
    try:
        info = os.lstat(path_or_name) if dir_fd is None else os.lstat(path_or_name, dir_fd=dir_fd)
    except OSError:
        return False
    return _fs_identity(info) == expected


def _gnupg_ancestry_matches(
    etc_fd: int, gnupg_fd: int, etc_dir: Path, etc_identity: FsIdentity,
    gnupg_dir: Path, gnupg_identity: FsIdentity,
) -> bool:
    return (
        _fs_identity(os.fstat(etc_fd)) == etc_identity
        and _path_matches_identity(etc_dir, etc_identity)
        and _fs_identity(os.fstat(gnupg_fd)) == gnupg_identity
        and _path_matches_identity(gnupg_dir, gnupg_identity)
        and _path_matches_identity("gnupg", gnupg_identity, dir_fd=etc_fd)
    )


def _write_exact_file_at(dir_fd: int, name: str, data: bytes, mode: int) -> None:
    fd: int | None = None
    try:
        fd = os.open(name, _file_create_flags(), mode, dir_fd=dir_fd)
        os.fchmod(fd, mode)
        total = 0
        while total < len(data):
            written = os.write(fd, data[total:])
            if written <= 0:
                raise OSError("short write")
            total += written
        os.fsync(fd)
    finally:
        _close_fds(fd)


def _validate_regular_file_lstat(
    lstat_info: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int | None,
    max_bytes: int,
    error_prefix: str,
) -> FsIdentity:
    if stat.S_ISLNK(lstat_info.st_mode) or not stat.S_ISREG(lstat_info.st_mode):
        raise GlobalConfigError(f"{error_prefix}_NOT_REGULAR")
    if not _owner_matches(lstat_info, expected_uid, expected_gid):
        raise GlobalConfigError(f"{error_prefix}_OWNER_MISMATCH")
    if lstat_info.st_nlink != 1:
        raise GlobalConfigError(f"{error_prefix}_HARDLINK_REJECTED")
    if (lstat_info.st_mode & 0o7133) != 0:
        raise GlobalConfigError(f"{error_prefix}_MODE_UNSAFE")
    if lstat_info.st_size <= 0 or lstat_info.st_size > max_bytes:
        raise GlobalConfigError(f"{error_prefix}_SIZE_INVALID")
    return _fs_identity(lstat_info)


def _read_verified_file_at(
    dir_fd: int,
    name: str,
    *,
    expected_uid: int,
    expected_gid: int | None,
    max_bytes: int,
    error_prefix: str,
) -> tuple[FsIdentity, bytes, str]:
    try:
        lstat_info = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError as error:
        raise GlobalConfigError(f"{error_prefix}_MISSING") from error
    except OSError as error:
        raise GlobalConfigError(f"{error_prefix}_STAT") from error
    ident = _validate_regular_file_lstat(
        lstat_info,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        max_bytes=max_bytes,
        error_prefix=error_prefix,
    )
    fd: int | None = None
    try:
        fd = os.open(name, _file_read_flags(), dir_fd=dir_fd)
        data = _read_opened_regular_fd(fd, ident, max_bytes, error_prefix)
        return ident, data, hashlib.sha256(data).hexdigest()
    except GlobalConfigError:
        raise
    except OSError as error:
        raise GlobalConfigError(f"{error_prefix}_READ") from error
    finally:
        _close_fds(fd)


def _verify_execution_and_helper_digest(
    *,
    expected_helper_sha256: str | None,
    support_checker: Callable[[], None],
    env_map: Mapping[str, str] | None,
    uid_getter: Callable[[], tuple[int, int]],
    helper_path: Path | None,
) -> tuple[Path, str]:
    _check_credential_free_env(env_map)
    support_checker()
    uid, euid = uid_getter()
    if uid != 0 or euid != 0:
        raise GlobalConfigError("CONTAINER_ROOT_UID_REQUIRED")
    resolved_helper = Path(__file__).resolve(strict=True) if helper_path is None else helper_path
    actual_helper_sha = _sha256_regular_file(resolved_helper, MAX_SOURCE_BYTES, "HELPER_SOURCE")
    if expected_helper_sha256 is not None:
        expected_helper = _validate_hex64(expected_helper_sha256, "EXPECTED_HELPER_SHA256_INVALID")
        if actual_helper_sha != expected_helper:
            raise GlobalConfigError("HELPER_SOURCE_DIGEST_MISMATCH")
    return resolved_helper, actual_helper_sha


def _verify_optional_c6_source(
    resolved_helper: Path, c6_source_path: Path | None, *, require_c6_source: bool
) -> bool:
    resolved_c6 = (
        resolved_helper.parent / "inputs" / "owned_gpg_agent.py"
        if c6_source_path is None
        else c6_source_path
    )
    if not (require_c6_source or resolved_c6.exists()):
        return False
    actual_c6 = _sha256_regular_file(resolved_c6, MAX_SOURCE_BYTES, "REVIEWED_C6_SOURCE")
    if actual_c6 != REVIEWED_C6_SOURCE_SHA256:
        raise GlobalConfigError("REVIEWED_C6_SOURCE_CHANGED")
    return True


def authenticate_helper_source(
    *,
    expected_helper_sha256: str,
    expected_tests_sha256: str | None = None,
    helper_path: Path | None = None,
    tests_path: Path | None = None,
    c6_source_path: Path | None = None,
    require_c6_source: bool = False,
) -> dict[str, Any]:
    """Authenticate helper source, optional test module, and immutable C6 source when present."""
    expected_helper = _validate_hex64(expected_helper_sha256, "EXPECTED_HELPER_SHA256_INVALID")
    expected_tests = (
        _validate_hex64(expected_tests_sha256, "EXPECTED_TESTS_SHA256_INVALID")
        if expected_tests_sha256 is not None
        else None
    )
    resolved_helper = Path(__file__).resolve(strict=True) if helper_path is None else helper_path
    actual_helper = _sha256_regular_file(resolved_helper, MAX_SOURCE_BYTES, "HELPER_SOURCE")
    if actual_helper != expected_helper:
        raise GlobalConfigError("HELPER_SOURCE_DIGEST_MISMATCH")

    tests_verified = False
    if expected_tests is not None:
        resolved_tests = (
            resolved_helper.with_name("test_prepare_isolated_global_config.py")
            if tests_path is None
            else tests_path
        )
        actual_tests = _sha256_regular_file(resolved_tests, MAX_SOURCE_BYTES, "HELPER_TESTS")
        if actual_tests != expected_tests:
            raise GlobalConfigError("HELPER_TESTS_DIGEST_MISMATCH")
        tests_verified = True

    c6_verified = _verify_optional_c6_source(
        resolved_helper, c6_source_path, require_c6_source=require_c6_source
    )
    return {
        "admitting": False,
        "c6_source_sha256": REVIEWED_C6_SOURCE_SHA256,
        "c6_source_verified": c6_verified,
        "helper_source_sha256": actual_helper,
        "helper_tests_verified": tests_verified,
        "original_failed_guard_identified": False,
        "production_authority": False,
        "proposal_status": PROPOSAL_STATUS,
        "schema": SOURCE_AUTH_SCHEMA,
        "status": "helper-source-authenticated",
    }


def _open_verified_etc_ancestry(
    root_dir: Path,
    *,
    expected_uid: int,
    expected_gid: int | None,
    verify_etc_path: bool = True,
) -> tuple[int, int, FsIdentity]:
    root_fd: int | None = None
    etc_fd: int | None = None
    try:
        try:
            root_lstat = os.lstat(root_dir)
        except OSError as error:
            raise GlobalConfigError("ETC_ANCESTRY_UNSAFE") from error
        expected_root_id = _validate_safe_dir_stat(
            root_lstat,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            forbidden_mode_mask=0o022,
            error_code="ETC_ANCESTRY_UNSAFE",
        )
        root_fd = os.open(root_dir, _directory_open_flags())
        if _fs_identity(os.fstat(root_fd)) != expected_root_id:
            raise GlobalConfigError("ETC_ANCESTRY_UNSAFE")

        try:
            etc_lstat = os.lstat("etc", dir_fd=root_fd)
        except OSError as error:
            raise GlobalConfigError("ETC_ANCESTRY_UNSAFE") from error
        expected_etc_id = _validate_safe_dir_stat(
            etc_lstat,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            forbidden_mode_mask=0o022,
            error_code="ETC_ANCESTRY_UNSAFE",
        )
        etc_fd = os.open("etc", _directory_open_flags(), dir_fd=root_fd)
        etc_identity = _fs_identity(os.fstat(etc_fd))
        if etc_identity != expected_etc_id or (
            verify_etc_path and not _path_matches_identity(root_dir / "etc", etc_identity)
        ):
            raise GlobalConfigError("ETC_ANCESTRY_UNSAFE")
        return root_fd, etc_fd, etc_identity
    except BaseException:
        _close_fds(etc_fd, root_fd)
        raise


def _lstat_verified_gnupg_dir(
    etc_fd: int, *, expected_uid: int, expected_gid: int | None
) -> FsIdentity:
    try:
        gnupg_lstat = os.lstat("gnupg", dir_fd=etc_fd)
    except FileNotFoundError as error:
        raise GlobalConfigError("GLOBAL_CONFIG_DIR_MISSING") from error
    except OSError as error:
        raise GlobalConfigError("GLOBAL_CONFIG_DIR_NOT_PHYSICAL_DIR") from error
    if stat.S_ISLNK(gnupg_lstat.st_mode) or not stat.S_ISDIR(gnupg_lstat.st_mode):
        raise GlobalConfigError("GLOBAL_CONFIG_DIR_NOT_PHYSICAL_DIR")
    if (
        not _owner_matches(gnupg_lstat, expected_uid, expected_gid)
        or (gnupg_lstat.st_mode & 0o7022) != 0
    ):
        raise GlobalConfigError("GLOBAL_CONFIG_DIR_UNSAFE_MODE_OR_OWNER")
    return _fs_identity(gnupg_lstat)


def _open_verified_gnupg_directory(
    root_dir: Path,
    etc_fd: int,
    etc_identity: FsIdentity,
    *,
    expected_uid: int,
    expected_gid: int | None,
) -> _OpenedGnupgDir:
    etc_dir = root_dir / "etc"
    gnupg_dir = etc_dir / "gnupg"
    expected_gnupg_id = _lstat_verified_gnupg_dir(
        etc_fd, expected_uid=expected_uid, expected_gid=expected_gid
    )
    gnupg_fd = os.open("gnupg", _directory_open_flags(), dir_fd=etc_fd)
    try:
        gnupg_identity = _fs_identity(os.fstat(gnupg_fd))
        if (
            gnupg_identity != expected_gnupg_id
            or not _path_matches_identity(gnupg_dir, gnupg_identity)
        ):
            raise GlobalConfigError("GLOBAL_CONFIG_DIR_CHANGED")
        entries = tuple(sorted(os.listdir(gnupg_fd)))
        if entries not in ((), (SOURCE_CONFIG_NAME,)):
            raise GlobalConfigError("GLOBAL_CONFIG_DIR_INVENTORY_MISMATCH")
        return _OpenedGnupgDir(
            root_dir=root_dir,
            etc_dir=etc_dir,
            etc_fd=etc_fd,
            etc_identity=etc_identity,
            gnupg_dir=gnupg_dir,
            gnupg_fd=gnupg_fd,
            gnupg_identity=gnupg_identity,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            entries=entries,
        )
    except BaseException:
        _close_fds(gnupg_fd)
        raise


def _snapshot_regular_source_config(opened: _OpenedGnupgDir) -> _SourceConfigSnapshot:
    cfg_identity, cfg_bytes, cfg_sha256 = _read_verified_file_at(
        opened.gnupg_fd,
        SOURCE_CONFIG_NAME,
        expected_uid=opened.expected_uid,
        expected_gid=opened.expected_gid,
        max_bytes=MAX_CONFIG_BYTES,
        error_prefix="GLOBAL_CONFIG_FILE",
    )
    return _SourceConfigSnapshot(
        etc_dir=opened.etc_dir,
        etc_identity=opened.etc_identity,
        gnupg_dir=opened.gnupg_dir,
        gnupg_identity=opened.gnupg_identity,
        config_identity=cfg_identity,
        config_bytes=cfg_bytes,
        config_sha256=cfg_sha256,
    )


def _recheck_source_layout_after_rpm(
    root_dir: Path,
    etc_fd: int,
    gnupg_fd: int,
    snapshot: _SourceConfigSnapshot,
    *,
    expected_uid: int,
    expected_gid: int | None,
) -> None:
    post_rpm_identity, post_rpm_bytes, post_rpm_sha256 = _read_verified_file_at(
        gnupg_fd,
        SOURCE_CONFIG_NAME,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        max_bytes=MAX_CONFIG_BYTES,
        error_prefix="GLOBAL_CONFIG_FILE",
    )
    if (
        not _gnupg_ancestry_matches(
            etc_fd,
            gnupg_fd,
            snapshot.etc_dir,
            snapshot.etc_identity,
            snapshot.gnupg_dir,
            snapshot.gnupg_identity,
        )
        or os.listdir(gnupg_fd) != [SOURCE_CONFIG_NAME]
        or post_rpm_identity != snapshot.config_identity
        or post_rpm_bytes != snapshot.config_bytes
        or post_rpm_sha256 != snapshot.config_sha256
    ):
        raise GlobalConfigError("GLOBAL_CONFIG_LAYOUT_CHANGED")
    _verify_usr_bin_and_absent_gpgconf_ctl(
        root_dir, expected_uid=expected_uid, expected_gid=expected_gid
    )


def _rollback_quarantine_dir(
    etc_fd: int, quarantine_fd: int | None, *, close_fd: bool = True
) -> bool:
    if quarantine_fd is not None:
        for name in (SOURCE_CONFIG_NAME, QUARANTINE_RECEIPT_NAME):
            try:
                os.unlink(name, dir_fd=quarantine_fd)
            except OSError:
                pass
        if close_fd:
            _close_fds(quarantine_fd)
    try:
        os.rmdir(QUARANTINE_DIR_NAME, dir_fd=etc_fd)
    except OSError:
        pass
    try:
        os.lstat(QUARANTINE_DIR_NAME, dir_fd=etc_fd)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _create_and_open_quarantine_dir(
    etc_fd: int, *, expected_uid: int, expected_gid: int | None
) -> int:
    try:
        os.mkdir(QUARANTINE_DIR_NAME, 0o700, dir_fd=etc_fd)
    except FileExistsError as error:
        raise GlobalConfigError("QUARANTINE_DESTINATION_PREEXISTING") from error
    except OSError as error:
        raise GlobalConfigError("QUARANTINE_CREATE_FAILED") from error

    quarantine_fd: int | None = None
    try:
        quarantine_lstat = os.lstat(QUARANTINE_DIR_NAME, dir_fd=etc_fd)
        if stat.S_ISLNK(quarantine_lstat.st_mode) or not stat.S_ISDIR(quarantine_lstat.st_mode):
            raise GlobalConfigError("QUARANTINE_CREATE_FAILED")
        quarantine_fd = os.open(QUARANTINE_DIR_NAME, _directory_open_flags(), dir_fd=etc_fd)
        os.fchmod(quarantine_fd, 0o700)
        fstat_info = os.fstat(quarantine_fd)
        if (
            not _path_matches_identity(
                QUARANTINE_DIR_NAME, _fs_identity(fstat_info), dir_fd=etc_fd
            )
            or not _owner_matches(fstat_info, expected_uid, expected_gid)
            or os.listdir(quarantine_fd) != []
        ):
            raise GlobalConfigError("QUARANTINE_CREATE_FAILED")
        return quarantine_fd
    except BaseException as error:
        cleanup_ok = _rollback_quarantine_dir(etc_fd, quarantine_fd)
        code = error.code if isinstance(error, GlobalConfigError) else "QUARANTINE_CREATE_FAILED"
        raise GlobalConfigError(
            code, original_bytes_preserved=cleanup_ok,
            mutation_performed=True, rollback_verified=cleanup_ok,
        ) from error


def _populate_and_verify_quarantine_config(
    quarantine_fd: int,
    snapshot: _SourceConfigSnapshot,
    *,
    expected_uid: int,
    expected_gid: int | None,
    quarantine_writer: Callable[[int, str, bytes, int], None],
) -> None:
    try:
        quarantine_writer(quarantine_fd, SOURCE_CONFIG_NAME, snapshot.config_bytes, 0o600)
    except GlobalConfigError:
        raise
    except Exception as error:
        raise GlobalConfigError("QUARANTINE_COPY_FAILED") from error

    try:
        _, retained_bytes, retained_sha256 = _read_verified_file_at(
            quarantine_fd,
            SOURCE_CONFIG_NAME,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            max_bytes=MAX_CONFIG_BYTES,
            error_prefix="QUARANTINE_FILE",
        )
    except GlobalConfigError as error:
        raise GlobalConfigError("QUARANTINE_VERIFY_FAILED") from error

    if (
        len(retained_bytes) != len(snapshot.config_bytes)
        or retained_sha256 != snapshot.config_sha256
    ):
        raise GlobalConfigError("QUARANTINE_VERIFY_FAILED")


def _stage_verified_quarantine_copy(
    root_dir: Path,
    etc_fd: int,
    gnupg_fd: int,
    snapshot: _SourceConfigSnapshot,
    *,
    expected_uid: int,
    expected_gid: int | None,
    command_runner: Callable[[list[str]], tuple[int, str]],
    quarantine_writer: Callable[[int, str, bytes, int], None],
) -> int:
    _ensure_absent_at(etc_fd, QUARANTINE_DIR_NAME, "QUARANTINE_DESTINATION_PREEXISTING")
    _verify_rpm_package_and_config(command_runner, expected_config_sha256=snapshot.config_sha256)
    _recheck_source_layout_after_rpm(
        root_dir, etc_fd, gnupg_fd, snapshot, expected_uid=expected_uid, expected_gid=expected_gid
    )
    quarantine_fd = _create_and_open_quarantine_dir(
        etc_fd, expected_uid=expected_uid, expected_gid=expected_gid
    )
    try:
        _populate_and_verify_quarantine_config(
            quarantine_fd,
            snapshot,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            quarantine_writer=quarantine_writer,
        )
        return quarantine_fd
    except BaseException as error:
        cleanup_ok = _rollback_quarantine_dir(etc_fd, quarantine_fd)
        code = error.code if isinstance(error, GlobalConfigError) else "QUARANTINE_COPY_FAILED"
        raise GlobalConfigError(
            code, original_bytes_preserved=cleanup_ok,
            mutation_performed=True, rollback_verified=cleanup_ok,
        ) from error


def _unlink_source_config(
    etc_fd: int,
    gnupg_fd: int,
    quarantine_fd: int,
    snapshot: _SourceConfigSnapshot,
    unlink_runner: Callable[[int, str], None],
) -> None:
    if (
        os.listdir(gnupg_fd) != [SOURCE_CONFIG_NAME]
        or not _path_matches_identity(
            SOURCE_CONFIG_NAME, snapshot.config_identity, dir_fd=gnupg_fd
        )
    ):
        cleanup_ok = _rollback_quarantine_dir(etc_fd, quarantine_fd, close_fd=False)
        raise GlobalConfigError(
            "GLOBAL_CONFIG_LAYOUT_CHANGED", original_bytes_preserved=cleanup_ok,
            mutation_performed=True, rollback_verified=cleanup_ok,
        )
    try:
        unlink_runner(gnupg_fd, SOURCE_CONFIG_NAME)
    except OSError as error:
        cleanup_ok = _rollback_quarantine_dir(etc_fd, quarantine_fd, close_fd=False)
        raise GlobalConfigError(
            "GLOBAL_CONFIG_UNLINK_FAILED", original_bytes_preserved=cleanup_ok,
            mutation_performed=True, rollback_verified=cleanup_ok,
        ) from error


def _restore_unlinked_source_config(
    gnupg_fd: int,
    snapshot: _SourceConfigSnapshot,
    *,
    expected_uid: int,
    expected_gid: int | None,
) -> bool:
    try:
        if SOURCE_CONFIG_NAME not in os.listdir(gnupg_fd):
            _write_exact_file_at(
                gnupg_fd, SOURCE_CONFIG_NAME, snapshot.config_bytes, snapshot.config_identity.mode
            )
        _, restored_bytes, restored_sha256 = _read_verified_file_at(
            gnupg_fd,
            SOURCE_CONFIG_NAME,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            max_bytes=MAX_CONFIG_BYTES,
            error_prefix="GLOBAL_CONFIG_FILE",
        )
        return (
            len(restored_bytes) == len(snapshot.config_bytes)
            and restored_sha256 == snapshot.config_sha256
        )
    except (OSError, GlobalConfigError):
        return False


def _remove_empty_gnupg_dir(
    etc_fd: int,
    gnupg_fd: int,
    snapshot: _SourceConfigSnapshot,
    *,
    expected_uid: int,
    expected_gid: int | None,
    rmdir_runner: Callable[[int, str], None],
) -> None:
    try:
        if os.listdir(gnupg_fd) != []:
            raise GlobalConfigError("GLOBAL_CONFIG_RMDIR_FAILED")
        rmdir_runner(etc_fd, "gnupg")
        _ensure_absent_at(etc_fd, "gnupg", "GLOBAL_CONFIG_RMDIR_FAILED")
    except BaseException as error:
        restored_ok = _restore_unlinked_source_config(
            gnupg_fd, snapshot, expected_uid=expected_uid, expected_gid=expected_gid
        )
        if not restored_ok:
            raise GlobalConfigError(
                "GLOBAL_CONFIG_RMDIR_RESTORE_FAILED", original_bytes_preserved=False,
                mutation_performed=True, rollback_verified=False,
            ) from error
        code = error.code if isinstance(error, GlobalConfigError) else "GLOBAL_CONFIG_RMDIR_FAILED"
        raise GlobalConfigError(
            code, original_bytes_preserved=True, mutation_performed=True, rollback_verified=True
        ) from error


def _verify_post_removal_quarantine(
    root_dir: Path,
    quarantine_fd: int,
    snapshot: _SourceConfigSnapshot,
    *,
    expected_uid: int,
    expected_gid: int | None,
) -> tuple[bytes, str]:
    try:
        _verify_usr_bin_and_absent_gpgconf_ctl(
            root_dir, expected_uid=expected_uid, expected_gid=expected_gid
        )
        _, post_bytes, post_sha256 = _read_verified_file_at(
            quarantine_fd,
            SOURCE_CONFIG_NAME,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            max_bytes=MAX_CONFIG_BYTES,
            error_prefix="QUARANTINE_FILE",
        )
        if (
            len(post_bytes) != len(snapshot.config_bytes)
            or post_sha256 != snapshot.config_sha256
        ):
            raise GlobalConfigError("QUARANTINE_VERIFY_FAILED", original_bytes_preserved=False)
        return post_bytes, post_sha256
    except GlobalConfigError as error:
        raise GlobalConfigError(
            error.code, original_bytes_preserved=False,
            mutation_performed=True, rollback_verified=False,
        ) from error


def _empty_gnupg_still_intact(opened: _OpenedGnupgDir) -> bool:
    try:
        etc_fstat = os.fstat(opened.etc_fd)
        etc_lstat = os.lstat(opened.etc_dir)
        etc_key = (opened.etc_identity.dev, opened.etc_identity.ino)
        return (
            (etc_fstat.st_dev, etc_fstat.st_ino) == etc_key
            and (etc_lstat.st_dev, etc_lstat.st_ino) == etc_key
            and _fs_identity(os.fstat(opened.gnupg_fd)) == opened.gnupg_identity
            and _path_matches_identity(opened.gnupg_dir, opened.gnupg_identity)
            and _path_matches_identity("gnupg", opened.gnupg_identity, dir_fd=opened.etc_fd)
            and os.listdir(opened.gnupg_fd) == []
        )
    except OSError:
        return False


def _verify_opened_empty_gnupg_unchanged(opened: _OpenedGnupgDir) -> None:
    if (
        not _gnupg_ancestry_matches(
            opened.etc_fd, opened.gnupg_fd, opened.etc_dir, opened.etc_identity,
            opened.gnupg_dir, opened.gnupg_identity,
        )
        or os.listdir(opened.gnupg_fd) != []
    ):
        raise GlobalConfigError("GLOBAL_CONFIG_LAYOUT_CHANGED")


def _stage_verified_empty_ghost_custody(
    opened: _OpenedGnupgDir, command_runner: Callable[[list[str]], tuple[int, str]]
) -> int:
    _ensure_absent_at(opened.etc_fd, QUARANTINE_DIR_NAME, "QUARANTINE_DESTINATION_PREEXISTING")
    _verify_rpm_package_and_ghost_config(command_runner)
    _verify_opened_empty_gnupg_unchanged(opened)
    _verify_usr_bin_and_absent_gpgconf_ctl(
        opened.root_dir, expected_uid=opened.expected_uid, expected_gid=opened.expected_gid
    )
    return _create_and_open_quarantine_dir(
        opened.etc_fd, expected_uid=opened.expected_uid, expected_gid=opened.expected_gid
    )


def _remove_empty_ghost_gnupg_dir(
    opened: _OpenedGnupgDir, rmdir_runner: Callable[[int, str], None]
) -> None:
    try:
        rmdir_runner(opened.etc_fd, "gnupg")
    except GlobalConfigError:
        raise
    except BaseException as error:
        raise GlobalConfigError("GLOBAL_CONFIG_RMDIR_FAILED") from error
    _ensure_absent_at(opened.etc_fd, "gnupg", "GLOBAL_CONFIG_RMDIR_FAILED")


def _verify_post_removal_empty_ghost_custody(
    opened: _OpenedGnupgDir, quarantine_fd: int
) -> None:
    _verify_usr_bin_and_absent_gpgconf_ctl(
        opened.root_dir, expected_uid=opened.expected_uid, expected_gid=opened.expected_gid
    )
    _ensure_absent_at(opened.etc_fd, "gnupg", "GLOBAL_CONFIG_RMDIR_FAILED")
    if os.listdir(quarantine_fd) != []:
        raise GlobalConfigError("QUARANTINE_VERIFY_FAILED", original_bytes_preserved=False)


def _empty_ghost_failure_preserved(
    opened: _OpenedGnupgDir, *, cleanup_ok: bool, rmdir_attempted: bool, gnupg_removed: bool
) -> bool:
    if not cleanup_ok or gnupg_removed:
        return False
    return True if not rmdir_attempted else _empty_gnupg_still_intact(opened)


def _expected_package_payload(config_sha256: str) -> dict[str, Any]:
    return {
        "arch": EXPECTED_PACKAGE_ARCH,
        "name": EXPECTED_PACKAGE_NAME,
        "nevra": EXPECTED_PACKAGE_NEVRA,
        "owner_verified": True,
        "release": EXPECTED_PACKAGE_RELEASE,
        "rpm_filedigest_sha256": config_sha256,
        "rpm_filedigest_verified": True,
        "rpm_verify_clean": True,
        "version": EXPECTED_PACKAGE_VERSION,
    }


def _expected_ghost_package_payload() -> dict[str, Any]:
    return {
        "arch": EXPECTED_PACKAGE_ARCH,
        "config_declaration": EXPECTED_GHOST_CONFIG_DECLARATION,
        "config_member_path": SOURCE_CONFIG_PATH,
        "etc_inventory": [ETC_GNUPG_PATH, SOURCE_CONFIG_PATH],
        "name": EXPECTED_PACKAGE_NAME,
        "nevra": EXPECTED_PACKAGE_NEVRA,
        "owner_verified": True,
        "release": EXPECTED_PACKAGE_RELEASE,
        "rpm_filedigest": EXPECTED_GHOST_CONFIG_FILEDIGEST,
        "rpm_fileflags": EXPECTED_GHOST_CONFIG_FILEFLAGS,
        "rpm_filesize": EXPECTED_GHOST_CONFIG_FILESIZE,
        "rpm_ghost_config_verified": True,
        "rpm_verify_clean": True,
        "version": EXPECTED_PACKAGE_VERSION,
    }


def _build_preparation_receipt(
    *,
    helper_source_sha256: str,
    config_bytes_len: int,
    config_sha256: str,
    retained_bytes_len: int,
    retained_sha256: str,
) -> dict[str, Any]:
    return {
        "admitting": False,
        "config_bytes": config_bytes_len,
        "config_sha256": config_sha256,
        "etc_gnupg_absent_confirmed": True,
        "etc_gnupg_initial_entry_count": 1,
        "etc_gnupg_sole_member_verified": True,
        "gpgconf_ctl_absent_confirmed": True,
        "gpgconf_ctl_modified": False,
        "helper_source_sha256": helper_source_sha256,
        "original_failed_guard_identified": False,
        "package": _expected_package_payload(config_sha256),
        "preparation_mode": REGULAR_CONFIG_MODE,
        "production_authority": False,
        "proposal_status": PROPOSAL_STATUS,
        "quarantine_copy_verified": True,
        "quarantine_retained_bytes": retained_bytes_len,
        "quarantine_retained_sha256": retained_sha256,
        "schema": SCHEMA,
        "status": "isolated-global-config-prepared",
    }


def _build_empty_ghost_preparation_receipt(*, helper_source_sha256: str) -> dict[str, Any]:
    return {
        "admitting": False,
        "c6_source_sha256": REVIEWED_C6_SOURCE_SHA256,
        "c6_source_verified": False,
        "config_file_present_at_prepare": False,
        "etc_gnupg_absent_confirmed": True,
        "etc_gnupg_empty_verified_before_and_after_rpm": True,
        "etc_gnupg_initial_entry_count": 0,
        "gpgconf_ctl_absent_confirmed": True,
        "gpgconf_ctl_modified": False,
        "helper_source_sha256": helper_source_sha256,
        "original_failed_guard_identified": False,
        "package": _expected_ghost_package_payload(),
        "preparation_mode": EMPTY_GHOST_DIR_MODE,
        "production_authority": False,
        "proposal_status": PROPOSAL_STATUS,
        "quarantine_copy_verified": False,
        "quarantine_custody_files": [QUARANTINE_RECEIPT_NAME],
        "schema": SCHEMA,
        "status": "isolated-global-config-prepared",
    }


def _write_quarantine_receipt(
    etc_fd: int, quarantine_fd: int, receipt: Mapping[str, Any]
) -> None:
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        _write_exact_file_at(quarantine_fd, QUARANTINE_RECEIPT_NAME, receipt_bytes, 0o600)
        os.fsync(quarantine_fd)
        os.fsync(etc_fd)
    except OSError as error:
        raise GlobalConfigError(
            "QUARANTINE_RECEIPT_WRITE_FAILED", original_bytes_preserved=False,
            mutation_performed=True, rollback_verified=False,
        ) from error


def _prepare_regular_source_config(
    opened: _OpenedGnupgDir, *, actual_helper_sha: str,
    command_runner: Callable[[list[str]], tuple[int, str]],
    quarantine_writer: Callable[[int, str, bytes, int], None],
    unlink_runner: Callable[[int, str], None], rmdir_runner: Callable[[int, str], None],
) -> dict[str, Any]:
    snapshot = _snapshot_regular_source_config(opened)
    quarantine_fd = _stage_verified_quarantine_copy(
        opened.root_dir, opened.etc_fd, opened.gnupg_fd, snapshot,
        expected_uid=opened.expected_uid, expected_gid=opened.expected_gid,
        command_runner=command_runner, quarantine_writer=quarantine_writer,
    )
    try:
        _unlink_source_config(
            opened.etc_fd, opened.gnupg_fd, quarantine_fd, snapshot, unlink_runner
        )
        _remove_empty_gnupg_dir(
            opened.etc_fd, opened.gnupg_fd, snapshot,
            expected_uid=opened.expected_uid, expected_gid=opened.expected_gid,
            rmdir_runner=rmdir_runner,
        )
        post_bytes, post_sha256 = _verify_post_removal_quarantine(
            opened.root_dir, quarantine_fd, snapshot,
            expected_uid=opened.expected_uid, expected_gid=opened.expected_gid,
        )
        receipt = _build_preparation_receipt(
            helper_source_sha256=actual_helper_sha, config_bytes_len=len(snapshot.config_bytes),
            config_sha256=snapshot.config_sha256, retained_bytes_len=len(post_bytes),
            retained_sha256=post_sha256,
        )
        _write_quarantine_receipt(opened.etc_fd, quarantine_fd, receipt)
        return receipt
    finally:
        _close_fds(quarantine_fd)


def _prepare_empty_ghost_gnupg_dir(
    opened: _OpenedGnupgDir, *, actual_helper_sha: str,
    command_runner: Callable[[list[str]], tuple[int, str]],
    rmdir_runner: Callable[[int, str], None],
) -> dict[str, Any]:
    quarantine_fd: int | None = _stage_verified_empty_ghost_custody(opened, command_runner)
    rmdir_attempted = False
    gnupg_removed = False
    try:
        if not _empty_gnupg_still_intact(opened):
            raise GlobalConfigError("GLOBAL_CONFIG_LAYOUT_CHANGED")
        rmdir_attempted = True
        _remove_empty_ghost_gnupg_dir(opened, rmdir_runner)
        gnupg_removed = True
        _verify_post_removal_empty_ghost_custody(opened, quarantine_fd)
        receipt = _build_empty_ghost_preparation_receipt(helper_source_sha256=actual_helper_sha)
        _write_quarantine_receipt(opened.etc_fd, quarantine_fd, receipt)
        return receipt
    except BaseException as error:
        cleanup_ok = _rollback_quarantine_dir(opened.etc_fd, quarantine_fd)
        quarantine_fd = None
        preserved = _empty_ghost_failure_preserved(
            opened, cleanup_ok=cleanup_ok,
            rmdir_attempted=rmdir_attempted, gnupg_removed=gnupg_removed,
        )
        code = error.code if isinstance(error, GlobalConfigError) else "GLOBAL_CONFIG_RMDIR_FAILED"
        raise GlobalConfigError(
            code, original_bytes_preserved=preserved,
            mutation_performed=True, rollback_verified=preserved,
        ) from error
    finally:
        _close_fds(quarantine_fd)


def prepare_isolated_global_config(
    *,
    expected_helper_sha256: str | None = None,
    support_checker: Callable[[], None] = check_native_support,
    command_runner: Callable[[list[str]], tuple[int, str]] = _default_command_runner,
    env_map: Mapping[str, str] | None = None,
    uid_getter: Callable[[], tuple[int, int]] = lambda: (os.getuid(), os.geteuid()),
    fs_root: Path = Path("/"),
    expected_file_uid: int = 0,
    expected_file_gid: int | None = 0,
    helper_path: Path | None = None,
    quarantine_writer: Callable[[int, str, bytes, int], None] = _write_exact_file_at,
    unlink_runner: Callable[[int, str], None] = lambda dir_fd, name: os.unlink(name, dir_fd=dir_fd),
    rmdir_runner: Callable[[int, str], None] = lambda dir_fd, name: os.rmdir(name, dir_fd=dir_fd),
) -> dict[str, Any]:
    """Validate and isolate /etc/gnupg via packaged regular-config or empty ghost-dir mode."""
    _, actual_helper_sha = _verify_execution_and_helper_digest(
        expected_helper_sha256=expected_helper_sha256,
        support_checker=support_checker,
        env_map=env_map,
        uid_getter=uid_getter,
        helper_path=helper_path,
    )
    root_dir = Path("/") if fs_root == Path("/") else fs_root.resolve(strict=True)
    _verify_usr_bin_and_absent_gpgconf_ctl(
        root_dir, expected_uid=expected_file_uid, expected_gid=expected_file_gid
    )
    _verify_rpm_tool(root_dir, expected_uid=expected_file_uid, expected_gid=expected_file_gid)

    root_fd, etc_fd, etc_identity = _open_verified_etc_ancestry(
        root_dir, expected_uid=expected_file_uid, expected_gid=expected_file_gid
    )
    opened: _OpenedGnupgDir | None = None
    try:
        opened = _open_verified_gnupg_directory(
            root_dir, etc_fd, etc_identity,
            expected_uid=expected_file_uid, expected_gid=expected_file_gid,
        )
        if opened.entries == ():
            return _prepare_empty_ghost_gnupg_dir(
                opened, actual_helper_sha=actual_helper_sha,
                command_runner=command_runner, rmdir_runner=rmdir_runner,
            )
        return _prepare_regular_source_config(
            opened, actual_helper_sha=actual_helper_sha,
            command_runner=command_runner, quarantine_writer=quarantine_writer,
            unlink_runner=unlink_runner, rmdir_runner=rmdir_runner,
        )
    finally:
        _close_fds(None if opened is None else opened.gnupg_fd, etc_fd, root_fd)


def _open_verified_quarantine_dir(
    etc_fd: int, *, expected_uid: int, expected_gid: int | None
) -> tuple[int, tuple[str, ...]]:
    try:
        quarantine_lstat = os.lstat(QUARANTINE_DIR_NAME, dir_fd=etc_fd)
    except FileNotFoundError as error:
        raise GlobalConfigError("QUARANTINE_DIR_MISSING") from error
    except OSError as error:
        raise GlobalConfigError("QUARANTINE_DIR_UNSAFE") from error
    if (
        stat.S_ISLNK(quarantine_lstat.st_mode)
        or not stat.S_ISDIR(quarantine_lstat.st_mode)
        or not _owner_matches(quarantine_lstat, expected_uid, expected_gid)
        or stat.S_IMODE(quarantine_lstat.st_mode) != 0o700
    ):
        raise GlobalConfigError("QUARANTINE_DIR_UNSAFE")
    quarantine_fd = os.open(QUARANTINE_DIR_NAME, _directory_open_flags(), dir_fd=etc_fd)
    try:
        if _fs_identity(os.fstat(quarantine_fd)) != _fs_identity(quarantine_lstat):
            raise GlobalConfigError("QUARANTINE_DIR_UNSAFE")
        q_entries = tuple(sorted(os.listdir(quarantine_fd)))
        valid_inventories = (
            (QUARANTINE_RECEIPT_NAME,),
            tuple(sorted((QUARANTINE_RECEIPT_NAME, SOURCE_CONFIG_NAME))),
        )
        if q_entries not in valid_inventories:
            raise GlobalConfigError("QUARANTINE_INVENTORY_MISMATCH")
        return quarantine_fd, q_entries
    except BaseException:
        _close_fds(quarantine_fd)
        raise


def _read_quarantine_receipt_json(
    quarantine_fd: int, *, expected_uid: int, expected_gid: int | None
) -> dict[str, Any]:
    _, receipt_bytes, _ = _read_verified_file_at(
        quarantine_fd,
        QUARANTINE_RECEIPT_NAME,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        max_bytes=MAX_JSON_BYTES,
        error_prefix="QUARANTINE_RECEIPT",
    )
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GlobalConfigError("QUARANTINE_RECEIPT_INVALID") from error
    if not isinstance(receipt, dict):
        raise GlobalConfigError("QUARANTINE_RECEIPT_INVALID")
    return receipt


def _exact_value_matches(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual.keys()) == set(expected.keys()) and all(
            _exact_value_matches(actual[k], expected[k]) for k in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _exact_value_matches(a, e) for a, e in zip(actual, expected)
        )
    return bool(actual == expected)


def _validate_exact_receipt_dict(
    receipt: Mapping[str, Any], expected: Mapping[str, Any]
) -> None:
    if not _exact_value_matches(dict(receipt), dict(expected)):
        raise GlobalConfigError("QUARANTINE_RECEIPT_MISMATCH")


def _verify_quarantine_mode_and_contents(
    quarantine_fd: int,
    q_entries: tuple[str, ...],
    receipt: Mapping[str, Any],
    *,
    actual_helper_sha: str,
    expected_uid: int,
    expected_gid: int | None,
) -> None:
    mode = receipt.get("preparation_mode")
    if mode == REGULAR_CONFIG_MODE:
        if q_entries != tuple(sorted((QUARANTINE_RECEIPT_NAME, SOURCE_CONFIG_NAME))):
            raise GlobalConfigError("QUARANTINE_INVENTORY_MISMATCH")
        _, retained_bytes, retained_sha256 = _read_verified_file_at(
            quarantine_fd,
            SOURCE_CONFIG_NAME,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            max_bytes=MAX_CONFIG_BYTES,
            error_prefix="QUARANTINE_FILE",
        )
        expected = _build_preparation_receipt(
            helper_source_sha256=actual_helper_sha,
            config_bytes_len=len(retained_bytes),
            config_sha256=retained_sha256,
            retained_bytes_len=len(retained_bytes),
            retained_sha256=retained_sha256,
        )
        _validate_exact_receipt_dict(receipt, expected)
        return
    if mode == EMPTY_GHOST_DIR_MODE:
        if q_entries != (QUARANTINE_RECEIPT_NAME,):
            raise GlobalConfigError("QUARANTINE_INVENTORY_MISMATCH")
        expected = _build_empty_ghost_preparation_receipt(
            helper_source_sha256=actual_helper_sha,
        )
        _validate_exact_receipt_dict(receipt, expected)
        return
    raise GlobalConfigError("QUARANTINE_RECEIPT_MODE_INVALID")


def verify_prepared_global_config(
    *,
    expected_helper_sha256: str | None = None,
    support_checker: Callable[[], None] = check_native_support,
    env_map: Mapping[str, str] | None = None,
    uid_getter: Callable[[], tuple[int, int]] = lambda: (os.getuid(), os.geteuid()),
    fs_root: Path = Path("/"),
    expected_file_uid: int = 0,
    expected_file_gid: int | None = 0,
    helper_path: Path | None = None,
    c6_source_path: Path | None = None,
) -> dict[str, Any]:
    """Verify the prepared builder image state before Stage 2 measurement."""
    resolved_helper, actual_helper_sha = _verify_execution_and_helper_digest(
        expected_helper_sha256=expected_helper_sha256,
        support_checker=support_checker,
        env_map=env_map,
        uid_getter=uid_getter,
        helper_path=helper_path,
    )
    _verify_optional_c6_source(resolved_helper, c6_source_path, require_c6_source=False)

    root_dir = Path("/") if fs_root == Path("/") else fs_root.resolve(strict=True)
    _verify_usr_bin_and_absent_gpgconf_ctl(
        root_dir, expected_uid=expected_file_uid, expected_gid=expected_file_gid
    )
    root_fd, etc_fd, _ = _open_verified_etc_ancestry(
        root_dir,
        expected_uid=expected_file_uid,
        expected_gid=expected_file_gid,
        verify_etc_path=False,
    )
    quarantine_fd: int | None = None
    try:
        _ensure_absent_at(etc_fd, "gnupg", "GLOBAL_CONFIG_DIR_STILL_PRESENT")
        quarantine_fd, q_entries = _open_verified_quarantine_dir(
            etc_fd, expected_uid=expected_file_uid, expected_gid=expected_file_gid
        )
        receipt = _read_quarantine_receipt_json(
            quarantine_fd, expected_uid=expected_file_uid, expected_gid=expected_file_gid
        )
        _verify_quarantine_mode_and_contents(
            quarantine_fd,
            q_entries,
            receipt,
            actual_helper_sha=actual_helper_sha,
            expected_uid=expected_file_uid,
            expected_gid=expected_file_gid,
        )
        return dict(receipt)
    finally:
        _close_fds(quarantine_fd, etc_fd, root_fd)


def _write_json_output(path_str: str | None, payload: Mapping[str, Any]) -> None:
    if not path_str:
        return
    target = _absolute_output_path(path_str, "receipt out")
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd: int | None = None
    try:
        flags = (
            os.O_CREAT
            | os.O_TRUNC
            | os.O_WRONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(target, flags, 0o644)
        total = 0
        while total < len(data):
            written = os.write(fd, data[total:])
            if written <= 0:
                raise OSError("short write")
            total += written
        os.fsync(fd)
    except OSError as error:
        raise GlobalConfigError("RECEIPT_OUT_WRITE_FAILED") from error
    finally:
        _close_fds(fd)


def _failure_payload(
    code: str, *, schema: str = SCHEMA, preserved: bool = True,
    mutation_performed: bool = False, rollback_verified: bool | None = None,
) -> dict[str, Any]:
    return {
        "admitting": False,
        "error_code": code,
        "mutation_performed": bool(mutation_performed),
        "original_bytes_preserved": bool(preserved),
        "original_failed_guard_identified": False,
        "production_authority": False,
        "proposal_status": PROPOSAL_STATUS,
        "rollback_verified": None if rollback_verified is None else bool(rollback_verified),
        "schema": schema,
        "status": "failed-closed",
    }


def _refused_payload(code: str, *, schema: str = SCHEMA) -> dict[str, Any]:
    return {
        "admitting": False,
        "error_code": code,
        "original_failed_guard_identified": False,
        "production_authority": False,
        "proposal_status": PROPOSAL_STATUS,
        "schema": schema,
        "status": "refused",
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--authenticate-source",
        action="store_true",
        help="authenticate helper source and immutable C6 source without native execution",
    )
    parser.add_argument(
        "--prepare-image",
        action="store_true",
        help="validate rpm ownership/integrity and relocate /etc/gnupg/gpgconf.conf into image quarantine",
    )
    parser.add_argument(
        "--verify-prepared",
        action="store_true",
        help="verify prepared image quarantine and absent global config before Stage 2",
    )
    parser.add_argument(
        "--expected-helper-sha256",
        default=None,
        help="required 64-hex SHA-256 of prepare_isolated_global_config.py",
    )
    parser.add_argument(
        "--expected-tests-sha256",
        default=None,
        help="optional 64-hex SHA-256 of test_prepare_isolated_global_config.py",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="optional absolute output path for closed JSON receipt",
    )
    return parser.parse_args(argv)


def _validate_cli_args(args: argparse.Namespace) -> dict[str, Any] | None:
    selected = (
        int(bool(args.authenticate_source))
        + int(bool(args.prepare_image))
        + int(bool(args.verify_prepared))
    )
    if selected == 0:
        return _refused_payload("EXPLICIT_MODE_REQUIRED")
    if selected > 1:
        return _refused_payload("MUTUALLY_EXCLUSIVE_MODE_FLAGS")
    if not args.expected_helper_sha256:
        target_schema = SOURCE_AUTH_SCHEMA if args.authenticate_source else SCHEMA
        return _refused_payload("EXPECTED_HELPER_SHA256_REQUIRED", schema=target_schema)
    return None


def _cli_fallback_error(args: argparse.Namespace) -> tuple[str, str]:
    if args.authenticate_source:
        return "HELPER_SOURCE_AUTH_FAILED", SOURCE_AUTH_SCHEMA
    if args.prepare_image:
        return "GLOBAL_CONFIG_PREPARATION_FAILED", SCHEMA
    return "GLOBAL_CONFIG_VERIFICATION_FAILED", SCHEMA


def _execute_selected_cli_action(args: argparse.Namespace) -> dict[str, Any]:
    if args.authenticate_source:
        return authenticate_helper_source(
            expected_helper_sha256=args.expected_helper_sha256,
            expected_tests_sha256=args.expected_tests_sha256,
            require_c6_source=True,
        )
    if args.prepare_image:
        return prepare_isolated_global_config(expected_helper_sha256=args.expected_helper_sha256)
    return verify_prepared_global_config(expected_helper_sha256=args.expected_helper_sha256)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    refusal = _validate_cli_args(args)
    if refusal is not None:
        print(json.dumps(refusal, sort_keys=True))
        return 2

    fallback_code, target_schema = _cli_fallback_error(args)
    try:
        receipt = _execute_selected_cli_action(args)
        _write_json_output(args.out, receipt)
    except GlobalConfigError as error:
        failure = _failure_payload(
            error.code, schema=target_schema, preserved=error.original_bytes_preserved,
            mutation_performed=error.mutation_performed, rollback_verified=error.rollback_verified,
        )
        try:
            _write_json_output(args.out, failure)
        except GlobalConfigError:
            pass
        print(json.dumps(failure, sort_keys=True))
        return 2
    except Exception:
        failure = _failure_payload(fallback_code, schema=target_schema)
        print(json.dumps(failure, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
