"""Pure unit tests for prepare_isolated_global_config.py.

All platform and rpm command seams are substituted; filesystem operations run
against isolated temporary directories.  No native rpm, GnuPG, Docker, key,
secret, or network execution is used.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

_MODULE_DIR = str(Path(__file__).resolve(strict=True).parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

import b3_fixture_entrypoint as entry
import prepare_isolated_global_config as helper

EXPECTED_HELPER_SHA256 = "c6a8cf05d3c46fd1497fd9de490366e4ad7fb3caafbb61c049a15bc669526a11"
SAMPLE_CONFIG_BYTES = (
    b"# Default packaged Fedora 43 gpgconf.conf fixture\n"
    b"# Must never appear in any receipt or diagnostic output\n"
    b"*\t/dev/null\n"
)
SAMPLE_CONFIG_SHA256 = hashlib.sha256(SAMPLE_CONFIG_BYTES).hexdigest()


def _valid_rpm_runner(argv: list[str]) -> tuple[int, str]:
    if argv[:4] == [
        "/usr/bin/rpm",
        "-qf",
        "--queryformat",
        "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n",
    ]:
        line = "gnupg2-gpgconf\t2.4.9\t5.fc43\tx86_64\n"
        return 0, line + line
    if argv == ["/usr/bin/rpm", "-ql", "gnupg2-gpgconf-2.4.9-5.fc43.x86_64"]:
        return (
            0,
            "\n".join([
                "/etc/gnupg",
                "/etc/gnupg/gpgconf.conf",
                "/usr/bin/gpgconf",
                "/usr/share/man/man1/gpgconf.1.gz",
            ])
            + "\n",
        )
    if argv == [
        "/usr/bin/rpm",
        "-q",
        "--queryformat",
        "[%{FILENAMES}\t%{FILEDIGESTS}\n]",
        "gnupg2-gpgconf-2.4.9-5.fc43.x86_64",
    ]:
        return (
            0,
            "\n".join([
                "/etc/gnupg\t",
                f"/etc/gnupg/gpgconf.conf\t{SAMPLE_CONFIG_SHA256}",
                f"/usr/bin/gpgconf\t{'a' * 64}",
                f"/usr/share/man/man1/gpgconf.1.gz\t{'b' * 64}",
            ])
            + "\n",
        )
    if argv == [
        "/usr/bin/rpm",
        "-V",
        "--nodeps",
        "--noscripts",
        "gnupg2-gpgconf-2.4.9-5.fc43.x86_64",
    ]:
        return 0, ""
    return 1, ""


def _valid_ghost_rpm_runner(argv: list[str]) -> tuple[int, str]:
    if argv == [
        "/usr/bin/rpm",
        "-q",
        "--queryformat",
        "[%{FILENAMES}\t%{FILEFLAGS}\t%{FILESIZES}\t%{FILEDIGESTS}\n]",
        "gnupg2-gpgconf-2.4.9-5.fc43.x86_64",
    ]:
        return (
            0,
            "\n".join([
                "/etc/gnupg\t0\t0\t",
                "/etc/gnupg/gpgconf.conf\t81\t0\t",
                f"/usr/bin/gpgconf\t0\t120112\t{'a' * 64}",
                f"/usr/share/man/man1/gpgconf.1.gz\t2\t5843\t{'b' * 64}",
            ])
            + "\n",
        )
    return _valid_rpm_runner(argv)


def _ghost_rpm_runner_override(
    match_arg: str,
    rc: int,
    out: str,
    argv: list[str],
) -> tuple[int, str]:
    if match_arg in argv:
        return rc, out
    return _valid_ghost_rpm_runner(argv)


def _stat_with_target_owner(
    st: os.stat_result,
    path: object,
    target_name: str,
    uid: int,
    gid: int,
) -> os.stat_result:
    if path != target_name:
        return st
    return os.stat_result((
        st.st_mode,
        st.st_ino,
        st.st_dev,
        st.st_nlink,
        uid,
        gid,
        st.st_size,
        st.st_atime,
        st.st_mtime,
        st.st_ctime,
    ))


def _stat_with_config_owner(
    st: os.stat_result,
    path: object,
    uid: int,
    gid: int,
) -> os.stat_result:
    return _stat_with_target_owner(st, path, helper.SOURCE_CONFIG_NAME, uid, gid)


def _rpm_runner_override(
    match_arg: str,
    rc: int,
    out: str,
    argv: list[str],
) -> tuple[int, str]:
    if match_arg in argv:
        return rc, out
    return _valid_rpm_runner(argv)


def _failing_quarantine_writer(dir_fd: int, name: str, data: bytes, mode: int) -> None:
    helper._write_exact_file_at(dir_fd, name, data[:4], mode)
    raise OSError("simulated disk write failure")


def _corrupting_quarantine_writer(dir_fd: int, name: str, data: bytes, mode: int) -> None:
    helper._write_exact_file_at(dir_fd, name, b"corrupted-" + data, mode)


def _failing_unlink(_dir_fd: int, _name: str) -> None:
    raise OSError("simulated unlink failure")


def _unlink_then_crash(dir_fd: int, name: str) -> None:
    os.unlink(name, dir_fd=dir_fd)
    raise RuntimeError("simulated post-unlink crash")


def _failing_rmdir(_dir_fd: int, _name: str) -> None:
    raise OSError("simulated rmdir failure")


def _fail_restore_write(
    real_write_exact,
    dir_fd: int,
    name: str,
    data: bytes,
    mode: int,
) -> None:
    if mode == 0o644:
        raise OSError("simulated restore write failure")
    real_write_exact(dir_fd, name, data, mode)


def _rmdir_then_corrupt_quarantine(root: Path, dir_fd: int, name: str) -> None:
    os.rmdir(name, dir_fd=dir_fd)
    q_cfg = root / "etc" / helper.QUARANTINE_DIR_NAME / "gpgconf.conf"
    q_cfg.chmod(0o600)
    q_cfg.write_bytes(b"post-rmdir-tamper\n")


def _ghost_rpm_runner_add_late_member(root: Path, argv: list[str]) -> tuple[int, str]:
    if "-V" in argv:
        (root / "etc/gnupg/late.conf").write_bytes(b"late\n")
    return _valid_ghost_rpm_runner(argv)


def _ghost_rpm_runner_replace_gnupg_dir(root: Path, argv: list[str]) -> tuple[int, str]:
    if "-V" in argv:
        moved = root / "etc/gnupg-moved"
        (root / "etc/gnupg").rename(moved)
        replacement = root / "etc/gnupg"
        replacement.mkdir(mode=0o755)
    return _valid_ghost_rpm_runner(argv)


def _ghost_rpm_runner_replace_etc_dir(root: Path, argv: list[str]) -> tuple[int, str]:
    if "-V" in argv:
        moved = root / "etc-moved"
        (root / "etc").rename(moved)
        replacement = root / "etc/gnupg"
        replacement.mkdir(parents=True, mode=0o755)
        (root / "etc").chmod(0o755)
    return _valid_ghost_rpm_runner(argv)


def _rmdir_then_raise(dir_fd: int, name: str) -> None:
    os.rmdir(name, dir_fd=dir_fd)
    raise OSError("simulated uncertain post-rmdir failure")


def _rmdir_with_stuck_quarantine(root: Path, _dir_fd: int, _name: str) -> None:
    (root / "etc" / helper.QUARANTINE_DIR_NAME / "stuck").write_bytes(b"stuck\n")
    raise OSError("simulated rmdir failure with stuck quarantine")


def _rooted_c6_lstat(root: Path, uid: int, path: object, *args, **kwargs):
    if kwargs.get("dir_fd") is not None:
        return os.lstat(path, *args, **kwargs)
    raw = str(path)
    mapped = root if raw == "/" else root / raw.lstrip("/")
    st = os.lstat(mapped)
    return types.SimpleNamespace(
        st_dev=st.st_dev,
        st_ino=st.st_ino,
        st_uid=0 if st.st_uid == uid else st.st_uid,
        st_mode=st.st_mode,
    )


class PrepareIsolatedGlobalConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="tf-b3-global-cfg-"))
        self.root.chmod(0o755)
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.uid = os.getuid()
        self._populate_valid_layout()
        self.gid = (self.root / "etc/gnupg/gpgconf.conf").lstat().st_gid

    def _populate_valid_layout(self) -> None:
        usr_dir = self.root / "usr"
        usr_bin = usr_dir / "bin"
        etc_dir = self.root / "etc"
        gnupg_dir = etc_dir / "gnupg"
        for d in (usr_dir, usr_bin, etc_dir, gnupg_dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o755)
        rpm_bin = usr_bin / "rpm"
        rpm_bin.write_bytes(b"#!/bin/sh\nexit 0\n")
        rpm_bin.chmod(0o755)
        cfg = gnupg_dir / "gpgconf.conf"
        cfg.write_bytes(SAMPLE_CONFIG_BYTES)
        cfg.chmod(0o644)

    def _run_prepare(self, **overrides):
        kwargs = {
            "expected_helper_sha256": EXPECTED_HELPER_SHA256,
            "support_checker": lambda: None,
            "command_runner": _valid_rpm_runner,
            "env_map": {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            "uid_getter": lambda: (0, 0),
            "fs_root": self.root,
            "expected_file_uid": self.uid,
            "expected_file_gid": self.gid,
        }
        kwargs.update(overrides)
        return helper.prepare_isolated_global_config(**kwargs)

    def _run_verify(self, **overrides):
        kwargs = {
            "expected_helper_sha256": EXPECTED_HELPER_SHA256,
            "support_checker": lambda: None,
            "env_map": {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            "uid_getter": lambda: (0, 0),
            "fs_root": self.root,
            "expected_file_uid": self.uid,
            "expected_file_gid": self.gid,
        }
        kwargs.update(overrides)
        return helper.verify_prepared_global_config(**kwargs)

    def test_default_invocation_and_mutually_exclusive_flags_refuse_closed(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = helper.main([])
        self.assertEqual(rc, 2)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["status"], "refused")
        self.assertEqual(payload["error_code"], "EXPLICIT_MODE_REQUIRED")
        self.assertFalse(payload["production_authority"])
        self.assertFalse(payload["admitting"])

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = helper.main(["--prepare-image", "--verify-prepared"])
        self.assertEqual(rc, 2)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["error_code"], "MUTUALLY_EXCLUSIVE_MODE_FLAGS")

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = helper.main(["--prepare-image"])
        self.assertEqual(rc, 2)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["error_code"], "EXPECTED_HELPER_SHA256_REQUIRED")

    def test_source_authentication_verifies_helper_and_immutable_c6_source(self) -> None:
        receipt = helper.authenticate_helper_source(
            expected_helper_sha256=EXPECTED_HELPER_SHA256,
            require_c6_source=True,
        )
        self.assertEqual(receipt["schema"], helper.SOURCE_AUTH_SCHEMA)
        self.assertEqual(receipt["status"], "helper-source-authenticated")
        self.assertEqual(receipt["helper_source_sha256"], EXPECTED_HELPER_SHA256)
        self.assertEqual(receipt["c6_source_sha256"], helper.REVIEWED_C6_SOURCE_SHA256)
        self.assertTrue(receipt["c6_source_verified"])
        self.assertFalse(receipt["production_authority"])
        self.assertFalse(receipt["admitting"])

        with self.assertRaisesRegex(helper.GlobalConfigError, "HELPER_SOURCE_DIGEST_MISMATCH"):
            helper.authenticate_helper_source(
                expected_helper_sha256="0" * 64,
                require_c6_source=True,
            )

        tampered_c6 = self.root / "tampered_c6.py"
        tampered_c6.write_bytes(b"# tampered\n")
        with self.assertRaisesRegex(helper.GlobalConfigError, "REVIEWED_C6_SOURCE_CHANGED"):
            helper.authenticate_helper_source(
                expected_helper_sha256=EXPECTED_HELPER_SHA256,
                c6_source_path=tampered_c6,
                require_c6_source=True,
            )

    def test_successful_relocation_retains_exact_bytes_removes_empty_etc_gnupg_and_verifies(self) -> None:
        receipt = self._run_prepare()
        self.assertEqual(receipt["schema"], helper.SCHEMA)
        self.assertEqual(receipt["status"], "isolated-global-config-prepared")
        self.assertEqual(receipt["proposal_status"], "proposed-unadopted")
        self.assertEqual(receipt["preparation_mode"], helper.REGULAR_CONFIG_MODE)
        self.assertFalse(receipt["production_authority"])
        self.assertFalse(receipt["admitting"])
        self.assertFalse(receipt["original_failed_guard_identified"])
        self.assertTrue(receipt["etc_gnupg_absent_confirmed"])
        self.assertTrue(receipt["gpgconf_ctl_absent_confirmed"])
        self.assertFalse(receipt["gpgconf_ctl_modified"])
        self.assertTrue(receipt["quarantine_copy_verified"])
        self.assertEqual(receipt["config_bytes"], len(SAMPLE_CONFIG_BYTES))
        self.assertEqual(receipt["quarantine_retained_bytes"], len(SAMPLE_CONFIG_BYTES))
        self.assertEqual(receipt["config_sha256"], SAMPLE_CONFIG_SHA256)
        self.assertEqual(receipt["quarantine_retained_sha256"], SAMPLE_CONFIG_SHA256)
        self.assertEqual(receipt["helper_source_sha256"], EXPECTED_HELPER_SHA256)
        self.assertEqual(
            receipt["package"],
            {
                "arch": "x86_64",
                "name": "gnupg2-gpgconf",
                "nevra": "gnupg2-gpgconf-2.4.9-5.fc43.x86_64",
                "owner_verified": True,
                "release": "5.fc43",
                "rpm_filedigest_sha256": SAMPLE_CONFIG_SHA256,
                "rpm_filedigest_verified": True,
                "rpm_verify_clean": True,
                "version": "2.4.9",
            },
        )

        self.assertFalse((self.root / "etc/gnupg").exists())
        self.assertFalse((self.root / "usr/bin/gpgconf.ctl").exists())
        q_dir = self.root / "etc" / helper.QUARANTINE_DIR_NAME
        self.assertTrue(q_dir.is_dir())
        self.assertEqual(stat.S_IMODE(q_dir.lstat().st_mode), 0o700)
        q_cfg = q_dir / "gpgconf.conf"
        self.assertEqual(q_cfg.read_bytes(), SAMPLE_CONFIG_BYTES)
        self.assertEqual(stat.S_IMODE(q_cfg.lstat().st_mode), 0o600)
        self.assertEqual(q_cfg.lstat().st_nlink, 1)

        verified = self._run_verify()
        self.assertEqual(verified, receipt)

    def test_empty_ghost_dir_mode_removes_empty_etc_gnupg_writes_receipt_only_and_verifies(
        self,
    ) -> None:
        (self.root / "etc/gnupg/gpgconf.conf").unlink()
        receipt = self._run_prepare(command_runner=_valid_ghost_rpm_runner)
        self.assertEqual(
            receipt,
            {
                "admitting": False,
                "c6_source_sha256": helper.REVIEWED_C6_SOURCE_SHA256,
                "c6_source_verified": False,
                "config_file_present_at_prepare": False,
                "etc_gnupg_absent_confirmed": True,
                "etc_gnupg_empty_verified_before_and_after_rpm": True,
                "etc_gnupg_initial_entry_count": 0,
                "gpgconf_ctl_absent_confirmed": True,
                "gpgconf_ctl_modified": False,
                "helper_source_sha256": EXPECTED_HELPER_SHA256,
                "original_failed_guard_identified": False,
                "package": {
                    "arch": "x86_64",
                    "config_declaration": "ghost+config(noreplace)",
                    "config_member_path": "/etc/gnupg/gpgconf.conf",
                    "etc_inventory": ["/etc/gnupg", "/etc/gnupg/gpgconf.conf"],
                    "name": "gnupg2-gpgconf",
                    "nevra": "gnupg2-gpgconf-2.4.9-5.fc43.x86_64",
                    "owner_verified": True,
                    "release": "5.fc43",
                    "rpm_filedigest": "",
                    "rpm_fileflags": 81,
                    "rpm_filesize": 0,
                    "rpm_ghost_config_verified": True,
                    "rpm_verify_clean": True,
                    "version": "2.4.9",
                },
                "preparation_mode": helper.EMPTY_GHOST_DIR_MODE,
                "production_authority": False,
                "proposal_status": "proposed-unadopted",
                "quarantine_copy_verified": False,
                "quarantine_custody_files": [helper.QUARANTINE_RECEIPT_NAME],
                "schema": helper.SCHEMA,
                "status": "isolated-global-config-prepared",
            },
        )
        self.assertFalse((self.root / "etc/gnupg").exists())
        self.assertFalse((self.root / "usr/bin/gpgconf.ctl").exists())
        q_dir = self.root / "etc" / helper.QUARANTINE_DIR_NAME
        self.assertEqual(sorted(os.listdir(q_dir)), [helper.QUARANTINE_RECEIPT_NAME])
        self.assertFalse((q_dir / "gpgconf.conf").exists())
        q_rcpt = q_dir / helper.QUARANTINE_RECEIPT_NAME
        self.assertEqual(stat.S_IMODE(q_rcpt.lstat().st_mode), 0o600)
        self.assertEqual(q_rcpt.lstat().st_nlink, 1)
        self.assertEqual(self._run_verify(), receipt)

    def test_rejects_non_linux_non_root_and_credential_environment_before_mutation(self) -> None:
        with self.assertRaisesRegex(helper.GlobalConfigError, "CREDENTIAL_ENV_FORBIDDEN"):
            self._run_prepare(
                env_map={"PACKAGE_SIGNING_PASSPHRASE": "forbidden"},
                command_runner=lambda _: self.fail("must not run rpm"),
            )
        with self.assertRaisesRegex(helper.GlobalConfigError, "UNSUPPORTED_PLATFORM"):
            self._run_prepare(
                support_checker=lambda: (_ for _ in ()).throw(
                    helper.GlobalConfigError("UNSUPPORTED_PLATFORM")
                ),
                command_runner=lambda _: self.fail("must not run rpm"),
            )
        with self.assertRaisesRegex(helper.GlobalConfigError, "CONTAINER_ROOT_UID_REQUIRED"):
            self._run_prepare(
                uid_getter=lambda: (1000, 1000),
                command_runner=lambda _: self.fail("must not run rpm"),
            )
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )

    def test_rejects_gpgconf_ctl_present_regular_or_symlink_and_never_removes_it(self) -> None:
        ctl = self.root / "usr/bin/gpgconf.ctl"
        ctl.write_bytes(b"rootdir = /etc/gnupg\n")
        with self.assertRaisesRegex(helper.GlobalConfigError, "GPGCONF_CTL_PRESENT_REFUSED"):
            self._run_prepare(command_runner=lambda _: self.fail("must refuse before rpm"))
        self.assertTrue(ctl.is_file())
        self.assertEqual(ctl.read_bytes(), b"rootdir = /etc/gnupg\n")
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )

        ctl.unlink()
        ctl.symlink_to("/dev/null")
        with self.assertRaisesRegex(helper.GlobalConfigError, "GPGCONF_CTL_PRESENT_REFUSED"):
            self._run_prepare(command_runner=lambda _: self.fail("must refuse symlink ctl"))
        self.assertTrue(ctl.is_symlink())
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )

    def test_rejects_symlinks_for_directories_config_file_and_rpm_tool(self) -> None:
        cfg = self.root / "etc/gnupg/gpgconf.conf"
        outside = self.root / "etc/outside.conf"
        outside.write_bytes(SAMPLE_CONFIG_BYTES)
        cfg.unlink()
        cfg.symlink_to(outside)
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_FILE_NOT_REGULAR"):
            self._run_prepare(command_runner=lambda _: self.fail("must reject symlink config"))
        self.assertTrue(cfg.is_symlink())
        cfg.unlink()
        outside.unlink()
        cfg.write_bytes(SAMPLE_CONFIG_BYTES)
        cfg.chmod(0o644)

        gnupg_dir = self.root / "etc/gnupg"
        real_gnupg = self.root / "etc/gnupg-real"
        gnupg_dir.rename(real_gnupg)
        gnupg_dir.symlink_to(real_gnupg)
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_NOT_PHYSICAL_DIR"):
            self._run_prepare(command_runner=lambda _: self.fail("must reject symlink dir"))
        gnupg_dir.unlink()
        real_gnupg.rename(gnupg_dir)

        rpm_bin = self.root / "usr/bin/rpm"
        rpm_real = self.root / "usr/bin/rpm-real"
        rpm_bin.rename(rpm_real)
        rpm_bin.symlink_to(rpm_real)
        with self.assertRaisesRegex(helper.GlobalConfigError, "RPM_TOOL_UNSAFE"):
            self._run_prepare(command_runner=lambda _: self.fail("must reject symlink rpm"))
        rpm_bin.unlink()
        rpm_real.rename(rpm_bin)

    def test_rejects_extra_member_empty_dir_or_wrong_member_name_in_etc_gnupg(self) -> None:
        extra = self.root / "etc/gnupg/gpg-agent.conf"
        extra.write_bytes(b"disable-scdaemon\n")
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_INVENTORY_MISMATCH"):
            self._run_prepare(command_runner=lambda _: self.fail("must reject extra member"))
        self.assertTrue(extra.is_file())
        self.assertTrue((self.root / "etc/gnupg/gpgconf.conf").is_file())
        extra.unlink()

        cfg = self.root / "etc/gnupg/gpgconf.conf"
        wrong = self.root / "etc/gnupg/wrong.conf"
        cfg.rename(wrong)
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_INVENTORY_MISMATCH"):
            self._run_prepare(command_runner=lambda _: self.fail("must reject wrong member name"))
        wrong.unlink()

        with self.assertRaisesRegex(
            helper.GlobalConfigError, "RPM_GHOST_CONFIG_METADATA_QUERY_FAILED"
        ):
            self._run_prepare()
        cfg.write_bytes(SAMPLE_CONFIG_BYTES)
        cfg.chmod(0o644)

    def test_rejects_hardlink_alias_unsafe_modes_and_wrong_owner_uid_or_gid(self) -> None:
        cfg = self.root / "etc/gnupg/gpgconf.conf"
        alias = self.root / "etc/gpgconf-alias.conf"
        os.link(cfg, alias)
        try:
            with self.assertRaisesRegex(
                helper.GlobalConfigError, "GLOBAL_CONFIG_FILE_HARDLINK_REJECTED"
            ):
                self._run_prepare(command_runner=lambda _: self.fail("must reject hardlink"))
        finally:
            alias.unlink(missing_ok=True)

        cfg.chmod(0o755)
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_FILE_MODE_UNSAFE"):
            self._run_prepare(command_runner=lambda _: self.fail("must reject executable config"))
        cfg.chmod(0o666)
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_FILE_MODE_UNSAFE"):
            self._run_prepare(command_runner=lambda _: self.fail("must reject writable config"))
        cfg.chmod(0o644)

        gnupg_dir = self.root / "etc/gnupg"
        gnupg_dir.chmod(0o777)
        with self.assertRaisesRegex(
            helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_UNSAFE_MODE_OR_OWNER"
        ):
            self._run_prepare(command_runner=lambda _: self.fail("must reject writable gnupg dir"))
        gnupg_dir.chmod(0o755)

        with self.assertRaisesRegex(helper.GlobalConfigError, "USR_BIN_ANCESTRY_UNSAFE"):
            self._run_prepare(
                expected_file_uid=self.uid + 1,
                command_runner=lambda _: self.fail("must reject wrong owner uid"),
            )
        with self.assertRaisesRegex(helper.GlobalConfigError, "USR_BIN_ANCESTRY_UNSAFE"):
            self._run_prepare(
                expected_file_gid=self.gid + 1,
                command_runner=lambda _: self.fail("must reject wrong owner gid"),
            )

        real_lstat = os.lstat
        for bad_uid, bad_gid in ((self.uid + 1, self.gid), (self.uid, self.gid + 1)):
            with patch(
                "prepare_isolated_global_config.os.lstat",
                side_effect=lambda p, *a, _u=bad_uid, _g=bad_gid, **kw: _stat_with_config_owner(
                    real_lstat(p, *a, **kw), p, _u, _g
                ),
            ):
                with self.assertRaisesRegex(
                    helper.GlobalConfigError, "GLOBAL_CONFIG_FILE_OWNER_MISMATCH"
                ):
                    self._run_prepare(
                        command_runner=lambda _: self.fail("must reject cfg owner mismatch")
                    )

    def test_rejects_rpm_owner_tuple_inventory_and_verify_failures(self) -> None:
        with self.assertRaisesRegex(helper.GlobalConfigError, "RPM_OWNER_QUERY_FAILED"):
            self._run_prepare(command_runner=lambda _: (1, ""))

        valid_line = "gnupg2-gpgconf\t2.4.9\t5.fc43\tx86_64\n"
        wrong_name_line = "gnupg2\t2.4.9\t5.fc43\tx86_64\n"
        wrong_ver_line = "gnupg2-gpgconf\t2.4.8\t5.fc43\tx86_64\n"
        cases = [
            ("-qf", 0, valid_line + wrong_name_line + valid_line, "RPM_OWNER_QUERY_FAILED"),
            ("-qf", 0, wrong_name_line + valid_line, "RPM_PACKAGE_TUPLE_MISMATCH"),
            ("-qf", 0, wrong_name_line * 2, "RPM_PACKAGE_TUPLE_MISMATCH"),
            ("-qf", 0, wrong_ver_line * 2, "RPM_PACKAGE_TUPLE_MISMATCH"),
            (
                "-ql",
                0,
                "/etc/gnupg\n/etc/gnupg/gpgconf.conf\n/etc/gnupg/extra.conf\n",
                "RPM_PACKAGE_INVENTORY_MISMATCH",
            ),
            (
                "[%{FILENAMES}\t%{FILEDIGESTS}\n]",
                0,
                f"/etc/gnupg\t\n/etc/gnupg/gpgconf.conf\t{'0' * 64}\n",
                "RPM_CONFIG_DIGEST_MISMATCH",
            ),
            ("-V", 1, "S.5....T.  c /etc/gnupg/gpgconf.conf\n", "RPM_VERIFY_MODIFIED_OR_FAILED"),
        ]
        for match_arg, rc, out, expected_code in cases:
            with self.assertRaisesRegex(helper.GlobalConfigError, expected_code):
                self._run_prepare(
                    command_runner=lambda argv, m=match_arg, r=rc, o=out: _rpm_runner_override(
                        m, r, o, argv
                    )
                )

        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

    def test_rejects_preexisting_quarantine_destination(self) -> None:
        q_dir = self.root / "etc" / helper.QUARANTINE_DIR_NAME
        q_dir.mkdir(mode=0o700)
        (q_dir / "existing").write_bytes(b"preexisting")
        with self.assertRaisesRegex(
            helper.GlobalConfigError, "QUARANTINE_DESTINATION_PREEXISTING"
        ):
            self._run_prepare(command_runner=lambda _: self.fail("must reject preexisting dest"))
        self.assertEqual((q_dir / "existing").read_bytes(), b"preexisting")
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )

    def test_copy_failure_and_digest_mismatch_roll_back_and_preserve_original_config(self) -> None:
        with self.assertRaisesRegex(helper.GlobalConfigError, "QUARANTINE_COPY_FAILED") as cm:
            self._run_prepare(quarantine_writer=_failing_quarantine_writer)
        self.assertTrue(cm.exception.original_bytes_preserved)
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

        with self.assertRaisesRegex(helper.GlobalConfigError, "QUARANTINE_VERIFY_FAILED") as cm:
            self._run_prepare(quarantine_writer=_corrupting_quarantine_writer)
        self.assertTrue(cm.exception.original_bytes_preserved)
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_UNLINK_FAILED") as cm:
            self._run_prepare(unlink_runner=_failing_unlink)
        self.assertTrue(cm.exception.original_bytes_preserved)
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

        with self.assertRaisesRegex(RuntimeError, "simulated post-unlink crash"):
            self._run_prepare(unlink_runner=_unlink_then_crash)
        self.assertFalse((self.root / "etc/gnupg/gpgconf.conf").exists())
        self.assertEqual(
            (self.root / "etc" / helper.QUARANTINE_DIR_NAME / "gpgconf.conf").read_bytes(),
            SAMPLE_CONFIG_BYTES,
        )
        shutil.rmtree(self.root / "etc" / helper.QUARANTINE_DIR_NAME)
        self._populate_valid_layout()

    def test_rmdir_failure_restores_original_config_and_retains_quarantine_copy(self) -> None:
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_RMDIR_FAILED") as cm:
            self._run_prepare(rmdir_runner=_failing_rmdir)
        self.assertTrue(cm.exception.original_bytes_preserved)
        self.assertEqual(
            (self.root / "etc/gnupg/gpgconf.conf").read_bytes(), SAMPLE_CONFIG_BYTES
        )
        self.assertEqual(
            stat.S_IMODE((self.root / "etc/gnupg/gpgconf.conf").lstat().st_mode), 0o644
        )
        self.assertEqual(
            (self.root / "etc" / helper.QUARANTINE_DIR_NAME / "gpgconf.conf").read_bytes(),
            SAMPLE_CONFIG_BYTES,
        )
        shutil.rmtree(self.root / "etc" / helper.QUARANTINE_DIR_NAME)

        real_write_exact = helper._write_exact_file_at
        with patch(
            "prepare_isolated_global_config._write_exact_file_at",
            side_effect=lambda dfd, n, d, m: _fail_restore_write(
                real_write_exact, dfd, n, d, m
            ),
        ):
            with self.assertRaisesRegex(
                helper.GlobalConfigError, "GLOBAL_CONFIG_RMDIR_RESTORE_FAILED"
            ) as cm:
                self._run_prepare(rmdir_runner=_failing_rmdir)
            self.assertFalse(cm.exception.original_bytes_preserved)
        self._populate_valid_layout()
        shutil.rmtree(self.root / "etc" / helper.QUARANTINE_DIR_NAME, ignore_errors=True)

        with self.assertRaisesRegex(
            helper.GlobalConfigError, "QUARANTINE_VERIFY_FAILED"
        ) as cm:
            self._run_prepare(
                rmdir_runner=lambda dfd, n: _rmdir_then_corrupt_quarantine(self.root, dfd, n)
            )
        self.assertFalse(cm.exception.original_bytes_preserved)

    def test_verify_prepared_rejects_reappearing_etc_gnupg_or_tampered_quarantine(self) -> None:
        self._run_prepare()
        (self.root / "etc/gnupg").mkdir(mode=0o755)
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_STILL_PRESENT"):
            self._run_verify()
        (self.root / "etc/gnupg").rmdir()

        q_cfg = self.root / "etc" / helper.QUARANTINE_DIR_NAME / "gpgconf.conf"
        q_cfg.chmod(0o600)
        q_cfg.write_bytes(SAMPLE_CONFIG_BYTES + b"# mutated\n")
        with self.assertRaisesRegex(helper.GlobalConfigError, "QUARANTINE_RECEIPT_MISMATCH"):
            self._run_verify()

    def test_cli_subprocess_and_privacy_invariants(self) -> None:
        helper_file = Path(helper.__file__).resolve(strict=True)
        source_text = helper_file.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(helper_file.read_bytes()).hexdigest(), EXPECTED_HELPER_SHA256
        )
        self.assertNotIn("rmtree", source_text)
        self.assertNotIn("--kill", source_text)
        for forbidden in ("--passphrase", "--private-key", "--secret-key", "--key-file"):
            self.assertNotIn(forbidden, source_text)

        auth_out = self.root / "source-auth.json"
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(helper_file),
                "--authenticate-source",
                "--expected-helper-sha256",
                EXPECTED_HELPER_SHA256,
                "--out",
                str(auth_out),
            ],
            cwd=str(self.root),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        auth_json = json.loads(completed.stdout)
        self.assertEqual(auth_json["status"], "helper-source-authenticated")
        self.assertEqual(json.loads(auth_out.read_text(encoding="utf-8")), auth_json)
        auth_out.unlink()

        receipt = self._run_prepare()
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("/dev/null", serialized)
        self.assertNotIn("Default packaged Fedora", serialized)
        self.assertNotIn(str(self.root), serialized)

    def test_real_c6_preflight_external_paths_before_and_after_relocation(self) -> None:
        real_spec = entry.load_manifest(Path(entry.__file__).with_name("manifest.json"))
        real_c6 = entry._load_owned_agent(real_spec)
        for d in ("run", "var"):
            p = self.root / d
            p.mkdir(parents=True, exist_ok=True)
            p.chmod(0o755)
        var_run = self.root / "var/run"
        if not var_run.exists():
            var_run.symlink_to("/run")

        c6_os = types.SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
        c6_os.lstat = lambda p, *a, **kw: _rooted_c6_lstat(self.root, self.uid, p, *a, **kw)
        c6_os.readlink = lambda p: os.readlink(self.root / str(p).lstrip("/"))
        c6_os.getuid = lambda: 0

        with patch.object(real_c6, "os", c6_os):
            with self.assertRaises(real_c6.OwnedAgentError) as before_err:
                real_c6._preflight_external_paths()
            self.assertEqual(before_err.exception.code, "GLOBAL_CONFIG_REJECTED")

            self._run_prepare()
            layout = real_c6._preflight_external_paths()
            self.assertEqual(layout.alias_target, "/run")

            shutil.rmtree(self.root / "etc" / helper.QUARANTINE_DIR_NAME)
            (self.root / "etc/gnupg").mkdir(mode=0o755)
            with self.assertRaises(real_c6.OwnedAgentError) as empty_err:
                real_c6._preflight_external_paths()
            self.assertEqual(empty_err.exception.code, "GLOBAL_CONFIG_REJECTED")
            self._run_prepare(command_runner=_valid_ghost_rpm_runner)
            layout_after_empty = real_c6._preflight_external_paths()
            self.assertEqual(layout_after_empty.alias_target, "/run")

    def test_empty_ghost_dir_rejects_invalid_rpm_ghost_metadata_owner_inventory_or_verify(
        self,
    ) -> None:
        (self.root / "etc/gnupg/gpgconf.conf").unlink()
        qfmt = "[%{FILENAMES}\t%{FILEFLAGS}\t%{FILESIZES}\t%{FILEDIGESTS}\n]"
        wrong_owner = "gnupg2\t2.4.9\t5.fc43\tx86_64\n"
        cases = [
            ("-qf", 1, "", "RPM_OWNER_QUERY_FAILED"),
            ("-qf", 0, wrong_owner * 2, "RPM_PACKAGE_TUPLE_MISMATCH"),
            (
                "-ql",
                0,
                "/etc/gnupg\n/etc/gnupg/gpgconf.conf\n/etc/gnupg/extra.conf\n",
                "RPM_PACKAGE_INVENTORY_MISMATCH",
            ),
            (
                "-ql",
                0,
                "/etc/gnupg\n/etc/gnupg/gpgconf.conf\n/usr/bin/gpgconf.ctl\n",
                "GPGCONF_CTL_PRESENT_REFUSED",
            ),
            (qfmt, 1, "", "RPM_GHOST_CONFIG_METADATA_QUERY_FAILED"),
            (qfmt, 0, "/etc/gnupg\t0\t0\n", "RPM_GHOST_CONFIG_METADATA_QUERY_FAILED"),
            (qfmt, 0, "/etc/gnupg\tx\t0\t\n/etc/gnupg/gpgconf.conf\t81\t0\t\n", "RPM_GHOST_CONFIG_METADATA_QUERY_FAILED"),
            (
                qfmt,
                0,
                "/etc/gnupg\t0\t0\t\n/etc/gnupg/gpgconf.conf\t81\t0\t\n/etc/gnupg/gpgconf.conf\t81\t0\t\n",
                "RPM_GHOST_CONFIG_METADATA_QUERY_FAILED",
            ),
            (qfmt, 0, "/etc/gnupg\t0\t0\t\n", "RPM_GHOST_CONFIG_METADATA_QUERY_FAILED"),
            (qfmt, 0, "/etc/gnupg\t16\t0\t\n/etc/gnupg/gpgconf.conf\t81\t0\t\n", "RPM_GNUPG_DIR_METADATA_MISMATCH"),
            (qfmt, 0, "/etc/gnupg\t0\t4096\t\n/etc/gnupg/gpgconf.conf\t81\t0\t\n", "RPM_GNUPG_DIR_METADATA_MISMATCH"),
            (
                qfmt,
                0,
                f"/etc/gnupg\t0\t0\t{'c' * 64}\n/etc/gnupg/gpgconf.conf\t81\t0\t\n",
                "RPM_GNUPG_DIR_METADATA_MISMATCH",
            ),
            (qfmt, 0, "/etc/gnupg\t0\t0\t\n/etc/gnupg/gpgconf.conf\t0\t0\t\n", "RPM_GHOST_CONFIG_FLAGS_MISMATCH"),
            (qfmt, 0, "/etc/gnupg\t0\t0\t\n/etc/gnupg/gpgconf.conf\t17\t0\t\n", "RPM_GHOST_CONFIG_FLAGS_MISMATCH"),
            (qfmt, 0, "/etc/gnupg\t0\t0\t\n/etc/gnupg/gpgconf.conf\t64\t0\t\n", "RPM_GHOST_CONFIG_FLAGS_MISMATCH"),
            (qfmt, 0, "/etc/gnupg\t0\t0\t\n/etc/gnupg/gpgconf.conf\t65\t0\t\n", "RPM_GHOST_CONFIG_FLAGS_MISMATCH"),
            (qfmt, 0, "/etc/gnupg\t0\t0\t\n/etc/gnupg/gpgconf.conf\t81\t110\t\n", "RPM_GHOST_CONFIG_SIZE_MISMATCH"),
            (
                qfmt,
                0,
                f"/etc/gnupg\t0\t0\t\n/etc/gnupg/gpgconf.conf\t81\t0\t{'a' * 64}\n",
                "RPM_GHOST_CONFIG_DIGEST_MISMATCH",
            ),
            ("-V", 1, "missing   c /etc/gnupg/gpgconf.conf\n", "RPM_VERIFY_MODIFIED_OR_FAILED"),
        ]
        for match_arg, rc, out, expected_code in cases:
            with self.assertRaisesRegex(helper.GlobalConfigError, expected_code) as cm:
                self._run_prepare(
                    command_runner=lambda argv, m=match_arg, r=rc, o=out: _ghost_rpm_runner_override(
                        m, r, o, argv
                    )
                )
            self.assertTrue(cm.exception.original_bytes_preserved)
            self.assertFalse(cm.exception.mutation_performed)
            self.assertIsNone(cm.exception.rollback_verified)
        self.assertTrue((self.root / "etc/gnupg").is_dir())
        self.assertEqual(os.listdir(self.root / "etc/gnupg"), [])
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

    def test_empty_ghost_dir_layout_change_rmdir_and_receipt_failures_never_fabricate_config(
        self,
    ) -> None:
        (self.root / "etc/gnupg/gpgconf.conf").unlink()
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_LAYOUT_CHANGED") as cm:
            self._run_prepare(
                command_runner=lambda argv: _ghost_rpm_runner_add_late_member(self.root, argv)
            )
        self.assertTrue(cm.exception.original_bytes_preserved)
        self.assertFalse(cm.exception.mutation_performed)
        self.assertIsNone(cm.exception.rollback_verified)
        self.assertEqual((self.root / "etc/gnupg/late.conf").read_bytes(), b"late\n")
        (self.root / "etc/gnupg/late.conf").unlink()
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_LAYOUT_CHANGED") as cm:
            self._run_prepare(
                command_runner=lambda argv: _ghost_rpm_runner_replace_gnupg_dir(self.root, argv)
            )
        self.assertTrue(cm.exception.original_bytes_preserved)
        self.assertFalse(cm.exception.mutation_performed)
        self.assertIsNone(cm.exception.rollback_verified)
        self.assertTrue((self.root / "etc/gnupg").is_dir())
        shutil.rmtree(self.root / "etc/gnupg-moved", ignore_errors=True)
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_LAYOUT_CHANGED") as cm:
            self._run_prepare(
                command_runner=lambda argv: _ghost_rpm_runner_replace_etc_dir(self.root, argv)
            )
        self.assertTrue(cm.exception.original_bytes_preserved)
        self.assertFalse(cm.exception.mutation_performed)
        self.assertIsNone(cm.exception.rollback_verified)
        shutil.rmtree(self.root / "etc-moved", ignore_errors=True)
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

    def test_empty_ghost_dir_rmdir_and_receipt_rollback_semantics(self) -> None:
        (self.root / "etc/gnupg/gpgconf.conf").unlink()
        for intact_rmdir in (_failing_rmdir, lambda _dfd, _name: None):
            with self.assertRaisesRegex(
                helper.GlobalConfigError, "GLOBAL_CONFIG_RMDIR_FAILED"
            ) as cm:
                self._run_prepare(
                    command_runner=_valid_ghost_rpm_runner,
                    rmdir_runner=intact_rmdir,
                )
            self.assertTrue(cm.exception.original_bytes_preserved)
            self.assertTrue(cm.exception.mutation_performed)
            self.assertTrue(cm.exception.rollback_verified)
            self.assertTrue((self.root / "etc/gnupg").is_dir())
            self.assertFalse((self.root / "etc/gnupg/gpgconf.conf").exists())
            self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

        with self.assertRaisesRegex(
            helper.GlobalConfigError, "GLOBAL_CONFIG_RMDIR_FAILED"
        ) as cm:
            self._run_prepare(
                command_runner=_valid_ghost_rpm_runner,
                rmdir_runner=lambda dfd, n: _rmdir_with_stuck_quarantine(self.root, dfd, n),
            )
        self.assertFalse(cm.exception.original_bytes_preserved)
        self.assertTrue(cm.exception.mutation_performed)
        self.assertFalse(cm.exception.rollback_verified)
        shutil.rmtree(self.root / "etc" / helper.QUARANTINE_DIR_NAME, ignore_errors=True)

        with self.assertRaisesRegex(
            helper.GlobalConfigError, "GLOBAL_CONFIG_RMDIR_FAILED"
        ) as cm:
            self._run_prepare(
                command_runner=_valid_ghost_rpm_runner,
                rmdir_runner=_rmdir_then_raise,
            )
        self.assertFalse(cm.exception.original_bytes_preserved)
        self.assertTrue(cm.exception.mutation_performed)
        self.assertFalse(cm.exception.rollback_verified)
        self.assertFalse((self.root / "etc/gnupg").exists())
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())
        (self.root / "etc/gnupg").mkdir(mode=0o755)

        with patch(
            "prepare_isolated_global_config._write_exact_file_at",
            side_effect=OSError("simulated receipt write failure"),
        ):
            with self.assertRaisesRegex(
                helper.GlobalConfigError, "QUARANTINE_RECEIPT_WRITE_FAILED"
            ) as cm:
                self._run_prepare(command_runner=_valid_ghost_rpm_runner)
        self.assertFalse(cm.exception.original_bytes_preserved)
        self.assertTrue(cm.exception.mutation_performed)
        self.assertFalse(cm.exception.rollback_verified)
        self.assertFalse((self.root / "etc/gnupg").exists())
        self.assertFalse((self.root / "etc" / helper.QUARANTINE_DIR_NAME).exists())

    def test_verify_prepared_enforces_mode_inventory_and_strict_receipt_types(self) -> None:
        (self.root / "etc/gnupg/gpgconf.conf").unlink()
        receipt = self._run_prepare(command_runner=_valid_ghost_rpm_runner)
        q_dir = self.root / "etc" / helper.QUARANTINE_DIR_NAME
        q_rcpt = q_dir / helper.QUARANTINE_RECEIPT_NAME

        (self.root / "etc/gnupg").mkdir(mode=0o755)
        with self.assertRaisesRegex(helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_STILL_PRESENT"):
            self._run_verify()
        (self.root / "etc/gnupg").rmdir()

        with self.assertRaisesRegex(helper.GlobalConfigError, "HELPER_SOURCE_DIGEST_MISMATCH"):
            self._run_verify(expected_helper_sha256="0" * 64)

        extra_cfg = q_dir / "gpgconf.conf"
        extra_cfg.write_bytes(SAMPLE_CONFIG_BYTES)
        extra_cfg.chmod(0o600)
        with self.assertRaisesRegex(helper.GlobalConfigError, "QUARANTINE_INVENTORY_MISMATCH"):
            self._run_verify()
        extra_cfg.unlink()

        bad_mode = dict(receipt, preparation_mode="forged-mode")
        q_rcpt.chmod(0o600)
        q_rcpt.write_text(json.dumps(bad_mode, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(helper.GlobalConfigError, "QUARANTINE_RECEIPT_MODE_INVALID"):
            self._run_verify()

        wrong_mode = dict(receipt, preparation_mode=helper.REGULAR_CONFIG_MODE)
        q_rcpt.write_text(json.dumps(wrong_mode, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(helper.GlobalConfigError, "QUARANTINE_INVENTORY_MISMATCH"):
            self._run_verify()

        tampered_receipts = [
            dict(receipt, etc_gnupg_initial_entry_count=False),
            dict(receipt, helper_source_sha256="0" * 64),
            dict(receipt, package=dict(receipt["package"], rpm_fileflags=17)),
            dict(receipt, package=dict(receipt["package"], rpm_filesize=1)),
            dict(receipt, package=dict(receipt["package"], rpm_filedigest="a" * 64)),
            dict(receipt, package=dict(receipt["package"], nevra="gnupg2-2.4.9-5.fc43.x86_64")),
        ]
        for tampered in tampered_receipts:
            q_rcpt.write_text(json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(helper.GlobalConfigError, "QUARANTINE_RECEIPT_MISMATCH"):
                self._run_verify()

    def test_empty_ghost_dir_rejects_symlinks_unsafe_modes_ctl_and_preexisting_quarantine(
        self,
    ) -> None:
        (self.root / "etc/gnupg/gpgconf.conf").unlink()
        with self.assertRaisesRegex(helper.GlobalConfigError, "HELPER_SOURCE_DIGEST_MISMATCH"):
            self._run_prepare(
                expected_helper_sha256="0" * 64,
                command_runner=lambda _: self.fail("must refuse helper drift before rpm"),
            )

        ctl = self.root / "usr/bin/gpgconf.ctl"
        ctl.write_bytes(b"rootdir = /etc/gnupg\n")
        with self.assertRaisesRegex(helper.GlobalConfigError, "GPGCONF_CTL_PRESENT_REFUSED"):
            self._run_prepare(command_runner=lambda _: self.fail("must refuse ctl before rpm"))
        ctl.unlink()

        gnupg_dir = self.root / "etc/gnupg"
        gnupg_dir.chmod(0o777)
        with self.assertRaisesRegex(
            helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_UNSAFE_MODE_OR_OWNER"
        ):
            self._run_prepare(command_runner=lambda _: self.fail("must refuse unsafe dir mode"))
        gnupg_dir.chmod(0o755)

        real_lstat = os.lstat
        for bad_uid, bad_gid in ((self.uid + 1, self.gid), (self.uid, self.gid + 1)):
            with patch(
                "prepare_isolated_global_config.os.lstat",
                side_effect=lambda p, *a, _u=bad_uid, _g=bad_gid, **kw: _stat_with_target_owner(
                    real_lstat(p, *a, **kw), p, "gnupg", _u, _g
                ),
            ):
                with self.assertRaisesRegex(
                    helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_UNSAFE_MODE_OR_OWNER"
                ):
                    self._run_prepare(
                        command_runner=lambda _: self.fail("must refuse gnupg owner mismatch")
                    )

        real_gnupg = self.root / "etc/gnupg-real"
        gnupg_dir.rename(real_gnupg)
        gnupg_dir.symlink_to(real_gnupg)
        with self.assertRaisesRegex(
            helper.GlobalConfigError, "GLOBAL_CONFIG_DIR_NOT_PHYSICAL_DIR"
        ):
            self._run_prepare(command_runner=lambda _: self.fail("must refuse symlink dir"))
        gnupg_dir.unlink()
        real_gnupg.rename(gnupg_dir)

        etc_dir = self.root / "etc"
        real_etc = self.root / "etc-real"
        etc_dir.rename(real_etc)
        etc_dir.symlink_to(real_etc)
        with self.assertRaisesRegex(helper.GlobalConfigError, "ETC_ANCESTRY_UNSAFE"):
            self._run_prepare(command_runner=lambda _: self.fail("must refuse symlink etc"))
        etc_dir.unlink()
        real_etc.rename(etc_dir)

        q_dir = self.root / "etc" / helper.QUARANTINE_DIR_NAME
        q_dir.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            helper.GlobalConfigError, "QUARANTINE_DESTINATION_PREEXISTING"
        ):
            self._run_prepare(command_runner=lambda _: self.fail("must refuse preexisting dest"))
        q_dir.rmdir()


if __name__ == "__main__":
    unittest.main(verbosity=2)
