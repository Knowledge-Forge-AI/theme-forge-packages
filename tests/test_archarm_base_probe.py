"""Source-level archive and probe custody regressions; no native admission."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "archarm_base_probe.py"
if not SOURCE.is_file():
    SOURCE = HERE.parent / "tools/verification/archarm_base_probe/archarm_base_probe.py"
spec = importlib.util.spec_from_file_location("archarm_base_probe", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def archive(rows):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as out:
        for name, kind, body, link, mode in rows:
            row = tarfile.TarInfo(name)
            row.type, row.linkname, row.mode = kind, link, mode
            row.size = len(body) if kind == tarfile.REGTYPE else 0
            out.addfile(row, io.BytesIO(body) if row.size else None)
    return data.getvalue()


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.rows = [(f"usr/lib/systemd/system/example\\x2d{n}.slice", tarfile.REGTYPE,
                      f"public-unit-{n}".encode(), "", 0o644) for n in range(3)]
        self.pin = {"members": 3, "declaredBytes": sum(len(r[2]) for r in self.rows),
                    "rootDirectoryHeaders": 0, "setIdMembers": [], "literalEscapeLinks": [],
                    "literalEscapes": [{"path": r[0], "mode": r[4], "size": len(r[2]),
                                        "sha256": hashlib.sha256(r[2]).hexdigest()} for r in self.rows]}

    def check(self, rows=None, pin=None):
        raw = archive(rows if rows is not None else self.rows)
        with patch.object(m.tarfile, "open", side_effect=lambda *_: tarfile.TarFile.open(
                fileobj=io.BytesIO(raw), mode="r|gz")):
            return m.inspect_members(Path("opaque-input.tar.gz"), pin or self.pin)

    def test_exact_three_literal_escapes_accepted_without_extraction(self):
        self.assertEqual(self.check(), {"members": 3, "declaredBytes": self.pin["declaredBytes"],
                                       "literalEscapes": 3, "setIdMembers": 0,
                                       "filesystemExtraction": False})

    def test_unrecognized_or_replaced_literal_escape_refused(self):
        for row in [("usr/unknown\\x2dunit", tarfile.REGTYPE, b"x", "", 0o644),
                    (self.rows[0][0], tarfile.REGTYPE, b"modified-unit", "", 0o644),
                    (self.rows[0][0], tarfile.SYMTYPE, b"", "other", 0o644)]:
            with self.subTest(row=row), self.assertRaises(m.Refusal):
                self.check([row, *self.rows[1:]])

    def test_parent_absolute_duplicate_special_members_refused(self):
        for row in [("../escape", tarfile.REGTYPE, b"x", "", 0o644),
                    ("/absolute", tarfile.REGTYPE, b"x", "", 0o644),
                    self.rows[1],
                    ("device", tarfile.CHRTYPE, b"", "", 0o600)]:
            with self.subTest(row=row), self.assertRaises(m.Refusal):
                self.check([row, *self.rows[1:]])

    def test_hardlink_target_must_exist(self):
        row = ("hard", tarfile.LNKTYPE, b"", "missing", 0o644)
        pin = copy.deepcopy(self.pin)
        pin["members"] += 1
        with self.assertRaisesRegex(m.Refusal, "HARDLINK_TARGET"):
            self.check([*self.rows, row], pin)

    def test_setid_and_count_and_total_are_closed(self):
        for field, value in [("members", 2), ("members", 4), ("declaredBytes", 1),
                             ("rootDirectoryHeaders", 1), ("setIdMembers", [{"path": "extra", "type": "0", "mode": 0o4755, "size": 0}])]:
            pin = copy.deepcopy(self.pin)
            pin[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(m.Refusal):
                self.check(pin=pin)

    def test_link_paths_stay_in_container_root(self):
        self.assertEqual(m._link_target("usr/bin/link", "../lib/file", hardlink=False), "usr/lib/file")
        self.assertEqual(m._link_target("usr/bin/link", "/proc/mounts", hardlink=False), "proc/mounts")
        for name, target, hard in [("x", "../outside", False), ("x", "/absolute", True),
                                   ("x", "a/../../outside", True)]:
            with self.subTest(target=target), self.assertRaises(m.Refusal):
                m._link_target(name, target, hardlink=hard)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="archarm-pure-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pin = json.loads((SOURCE.parent / "ROOTFS-PIN.json").read_text())
        self.commands = []

    def command(self, argv, env, **kwargs):
        self.commands.append((list(argv), dict(env)))
        if argv[0] == "gpgv":
            fp = self.pin["publicKeyFingerprint"]
            return 0, f"[GNUPG:] VALIDSIG {fp} 2026-08-05 1785945600 0 4 0 1 10 00 {fp}\n".encode()
        if argv[1:3] == ["info", "--format"]:
            return 0, b"linux/aarch64\n"
        if argv[1:3] == ["image", "inspect"]:
            if "--format" in argv:
                return 0, b"arm64\n"
            return 1, b"[]\n"
        if argv[1:3] == ["container", "inspect"]:
            return 1, b"[]\n"
        return 0, b""

    def run_probe(self, command=None):
        def fetch(url, dest, size, sha):
            dest.write_bytes(b"opaque public input")
        with patch.object(m.platform, "system", return_value="Linux"), \
             patch.object(m.platform, "machine", return_value="aarch64"), \
             patch.object(m, "download", side_effect=fetch), \
             patch.object(m, "check_file"), patch.object(m, "inspect_members", return_value={"fixture": True}), \
             patch.object(m, "command", side_effect=command or self.command):
            return m.native_probe(self.root / "work", self.pin, SOURCE.parent / "archlinuxarm-builder-public.gpg")

    def test_success_is_native_offline_nonroot_keyfree_and_cleans_owned_names(self):
        result = self.run_probe()
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["cleanupComplete"])
        self.assertFalse(result["signingSecretsUsed"])
        run = next(a for a, _ in self.commands if a[1:2] == ["run"])
        for flag, value in [("--platform", "linux/arm64"), ("--network", "none"),
                            ("--user", "65534:65534"), ("--cap-drop", "ALL"),
                            ("--security-opt", "no-new-privileges")]:
            self.assertEqual(run[run.index(flag) + 1], value)
        self.assertIn("--read-only", run)
        self.assertTrue(any(a[1:3] == ["rmi", "--no-prune"] for a, _ in self.commands))
        for argv, env in self.commands:
            expected = {"PATH", "HOME", "GNUPGHOME", "LANG", "LC_ALL", "TMPDIR"}
            if argv[0] == "docker":
                expected.add("DOCKER_CONFIG")
                self.assertEqual(env["HOME"], env["DOCKER_CONFIG"])
                self.assertNotEqual(env["HOME"], env["GNUPGHOME"])
            self.assertEqual(set(env), expected)

    def test_import_failure_is_not_claimed_clean(self):
        def fail(argv, env, **kw):
            return (1, b"") if argv[1:2] == ["import"] else self.command(argv, env, **kw)
        result = self.run_probe(fail)
        self.assertEqual(result["refusal"], "IMPORT_FAILED")
        self.assertFalse(result["cleanupComplete"])

    def test_cleanup_failure_is_terminal(self):
        def fail(argv, env, **kw):
            return (1, b"") if argv[1:2] == ["rmi"] else self.command(argv, env, **kw)
        self.assertEqual(self.run_probe(fail)["status"], "fail")

    def test_public_signature_failure_never_imports(self):
        def fail(argv, env, **kw):
            return (1, b"") if argv[0] == "gpgv" else self.command(argv, env, **kw)
        result = self.run_probe(fail)
        self.assertEqual(result["refusal"], "PUBLIC_SIGNATURE")
        self.assertFalse(any(a[1:2] == ["import"] for a, _ in self.commands))

    def test_wrong_host_refused_before_io(self):
        with patch.object(m.platform, "system", return_value="Darwin"), self.assertRaisesRegex(m.Refusal, "NATIVE_ARM_HOST"):
            m.native_probe(self.root / "work", self.pin, SOURCE.parent / "archlinuxarm-builder-public.gpg")

    def test_wrong_primary_fingerprint_never_imports(self):
        def fail(argv, env, **kw):
            if argv[0] == "gpgv":
                fp = self.pin["publicKeyFingerprint"]
                return 0, f"[GNUPG:] VALIDSIG {fp} 2026-08-05 1 0 4 0 1 10 00 {'0'*40}\n".encode()
            return self.command(argv, env, **kw)
        result = self.run_probe(fail)
        self.assertEqual(result["refusal"], "PUBLIC_SIGNATURE")
        self.assertFalse(any(a[1:2] == ["import"] for a, _ in self.commands))

    def test_owned_docker_json_metadata_removed_without_reading_contents(self):
        root = self.root / "docker-client"
        (root / "contexts/meta/fixture").mkdir(parents=True)
        (root / "contexts/meta/fixture/meta.json").write_text('{}')
        m.remove_fresh_docker_home(root)
        self.assertFalse(root.exists())

    def test_docker_symlinks_and_foreign_types_are_preserved(self):
        for name, kind in [("link.json", "link"), ("unknown.txt", "file")]:
            root = self.root / name.replace('.', '-')
            root.mkdir()
            path = root / name
            if kind == "link":
                path.symlink_to("/not-opened")
            elif kind == "directory":
                path.mkdir()
            else:
                path.write_text("opaque")
            with self.subTest(name=name), self.assertRaises(m.Refusal):
                m.remove_fresh_docker_home(root)
            self.assertTrue(root.exists())

    def test_protected_component_refused_using_metadata_only(self):
        root = self.root / "docker-virtual-metadata"
        root.mkdir()
        with patch.object(m.os, "walk", return_value=[(str(root), ["DB"], [])]), \
             self.assertRaisesRegex(m.Refusal, "DOCKER_HOME_CHANGED"):
            m.remove_fresh_docker_home(root)
        self.assertEqual(list(root.iterdir()), [])

    def test_replaced_docker_home_root_symlink_is_preserved(self):
        root = self.root / "docker-root-link"
        root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(m.Refusal, "DOCKER_HOME_CHANGED"):
            m.remove_fresh_docker_home(root)
        self.assertTrue(root.is_symlink())


if __name__ == "__main__":
    unittest.main()
