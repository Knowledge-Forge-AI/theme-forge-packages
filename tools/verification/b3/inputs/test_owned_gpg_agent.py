"""Inert stdlib fixture evidence. No native GnuPG or private inputs are used."""
from __future__ import annotations

import io
import ast
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import owned_gpg_agent as a

def _workspace():
    # Review copies may be nested below inputs/after; avoid import-time I/O.
    start = Path(__file__).resolve().parent
    for candidate in (start, *start.parents):
        if (candidate / "FIXTURE-ROOT.json").is_file():
            return candidate
    raise RuntimeError("fixture workspace unavailable")


class _SyntheticProc:
    """Metadata seams only: never inspects a real process or uses a fake PID."""
    def __init__(self):
        self.processes = {1: (0, 1, 1), 42001: (700, 42001, 42001)}
        self.fds = {1: {"0": (9, 11)}, 42001: {"3": (19, 42)}}
        self.failures = {}
        self.net = "Num RefCount Protocol Flags Type St Inode Path\n"
        self.mount = "1 0 0:1 / /proc rw - proc proc rw\n"
        self.exe_identity = SimpleNamespace(st_dev=5, st_ino=6, st_uid=0, st_mode=stat.S_IFREG | 0o755)

    def text(self, path):
        self.failure("text", path)
        if path == "/proc/net/unix": return self.net
        if path == "/proc/self/mountinfo": return self.mount
        parts = path.split("/")
        if len(parts) == 4 and parts[-1] == "stat":
            pid = int(parts[2])
            if pid not in self.processes: raise FileNotFoundError()
            parent, group, session = self.processes[pid]
            return f"{pid} (inert ) comm) S {parent} {group} {session} 0 0 0\n"
        raise AssertionError("unexpected synthetic proc text")

    def failure(self, operation, path):
        error = self.failures.get((operation, path))
        if error is not None: raise error

    @contextmanager
    def install(self):
        real_listdir, real_stat = os.listdir, os.stat
        def listing(path):
            self.failure("list", path)
            if path == "/proc": return [*map(str, self.processes), "net", "self"]
            if isinstance(path, str) and path.startswith("/proc/") and path.endswith("/fd"):
                pid = int(path.split("/")[2])
                if pid not in self.fds: raise FileNotFoundError()
                return list(self.fds[pid])
            return real_listdir(path)
        def metadata(path, **kwargs):
            self.failure("stat", path)
            if isinstance(path, str) and path.startswith("/proc/"):
                if path.endswith("/ns/pid"): return SimpleNamespace(st_dev=1, st_ino=2)
                if path.endswith("/exe"): return self.exe_identity
                parts = path.split("/")
                if len(parts) == 5 and parts[3] == "fd":
                    value = self.fds[int(parts[2])][parts[4]]
                    if isinstance(value, BaseException): raise value
                    return SimpleNamespace(st_dev=value[0], st_ino=value[1])
                raise AssertionError("unexpected synthetic proc stat")
            return real_stat(path, **kwargs)
        with ExitStack() as stack:
            stack.enter_context(patch.object(a.os, "listdir", side_effect=listing))
            stack.enter_context(patch.object(a.os, "stat", side_effect=metadata))
            stack.enter_context(patch.object(a, "_proc_text", side_effect=self.text))
            yield self


class _RuntimeMetadata:
    """Synthetic root-controlled Linux metadata; no host paths are touched."""
    def __init__(self, target="/run"):
        self.target = target
        self.seen = []
        self.info = {}
        for inode, name in enumerate(("/", "/run", "/var", "/usr", "/usr/bin", "/etc",
                                       "/run/gnupg", "/run/gnupg/user", "/run/user"), 1):
            self.info[name] = SimpleNamespace(st_dev=1, st_ino=inode, st_uid=0,
                                             st_mode=stat.S_IFDIR | 0o755)
        self.info["/var/run"] = SimpleNamespace(st_dev=1, st_ino=20, st_uid=0,
                                               st_mode=stat.S_IFLNK | 0o777)

    def lstat(self, path, **kwargs):
        name = str(path)
        self.seen.append(name)
        if name not in self.info:
            raise FileNotFoundError(name)
        return self.info[name]

    def readlink(self, path):
        if str(path) != "/var/run":
            raise AssertionError("unexpected synthetic readlink")
        return self.target


class _Fixture:
    """Private backend: no launch capability and no production authority."""
    def __init__(self, home: Path, job: Path):
        self.home, self.job = home, job
        self.events = []
        self.fail = None
        self.cleanup_fail = False
        self.before_barrier = False

    def prepare(self, c):
        self.events.append("prepare")
        c.paths = a.BoundAgentPaths(self.home, self.job, self.home / "S.gpg-agent")
        c.job_fd = a._open_chain(self.job, c)
        c.home_fd = a._open_chain(self.home, c)
        if self.fail == "prepare":
            raise ValueError("fixture prepare failure")

    def spawn(self, c):
        self.events.append("spawn")
        c.child = SimpleNamespace(pid=42001)
        if self.fail == "spawn":
            raise KeyboardInterrupt("fixture startup interrupt")

    def ready(self, c):
        self.events.append("ready")
        self.before_barrier = not (self.home / "common.conf").exists()
        if self.fail == "ready":
            raise a.OwnedAgentError("AGENT_READINESS_MISMATCH", "fixture mismatch")
        a._NativeBackend(self.home, self.job)._barrier(c)

    def validate(self, c):
        self.events.append("validate")
        a._check_directories(c)
        a._NativeBackend(self.home, self.job)._check_common(c)

    def cleanup(self, c):
        self.events.append("cleanup")
        if self.cleanup_fail:
            raise a.OwnedAgentError("AGENT_CLEANUP_UNCONFIRMED", "fixture unresolved")
        if c.common_identity is not None:
            a._NativeBackend(self.home, self.job)._check_common(c)
            os.unlink("common.conf", dir_fd=c.home_fd)
            c.common_identity = None
        while c.directories:
            os.close(c.directories[-1].fd)
            c.directories.pop()
        c.home_fd = c.job_fd = None


class Tests(unittest.TestCase):
    def setUp(self):
        self.workspace = _workspace()
        root = Path(json.loads((self.workspace / "FIXTURE-ROOT.json").read_text())["path"])
        info = os.lstat(root)
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(info.st_mode & 0o777, 0o700)
        self.temp = tempfile.TemporaryDirectory(prefix="u-", dir=root)
        self.job = Path(self.temp.name)
        self.home = self.job / "h"
        self.home.mkdir(mode=0o700)
        self.backend = _Fixture(self.home, self.job)
        self.lifetimes = []
        self.custodies = []

    def tearDown(self):
        # Only inert fixture state; explicitly resolve deliberate retained cases.
        for lifetime in self.lifetimes:
            self.backend.cleanup_fail = False
            if not lifetime.cleanup_confirmed:
                lifetime.close()
        for c in self.custodies:
            for name in ("pidfd", "listener_fd", "stderr_fd"):
                fd = getattr(c, name)
                if fd is not None:
                    os.close(fd)
                    setattr(c, name, None)
            while c.socket_directories:
                os.close(c.socket_directories.pop().fd)
            c.socketdir_fd = None
            while c.directories:
                os.close(c.directories.pop().fd)
        self.temp.cleanup()

    def lifetime(self):
        obj = a.OwnedGpgAgent._for_fixture(self.backend)
        self.lifetimes.append(obj)
        return obj

    def custody(self):
        c = a._RetainedCustody(paths=a.BoundAgentPaths(self.home, self.job, self.home / "S.gpg-agent"))
        self.custodies.append(c)
        c.job_fd = a._open_chain(self.job, c)
        c.home_fd = a._open_chain(self.home, c)
        c.home_root_name = self.home.relative_to(self.job).parts[0]
        c.job_entries_before = a._job_entry_snapshot(c.job_fd)
        c.job_members_before = frozenset(c.job_entries_before)
        return c

    def _external_custody(self, name="socket-runtime"):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        socketdir = self.job / name
        records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home),
                   "socketdir": str(socketdir), "agent-socket": str(socketdir / "S.gpg-agent")}
        c.paths = a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)
        return backend, c, socketdir

    def _assert_unconfirmed_external_bind(self, backend, c, socketdir, installer, expected):
        with installer(c, socketdir):
            with self.assertRaises(expected):
                backend._bind_socketdir(c)
        self.assertEqual(c.socketdir_created_name, socketdir.name)
        self.assertFalse(c.socketdir_owned)
        self.assertEqual(c.uncertainty, "SOCKETDIR_BINDING_UNCONFIRMED")
        obj = a.OwnedGpgAgent.__new__(a.OwnedGpgAgent)
        obj._initialize(backend, False)
        obj._custody = c
        obj._state = "starting"
        with self.assertRaisesRegex(a.OwnedAgentError, "SOCKETDIR_BINDING_UNCONFIRMED"):
            obj.close()
        self.assertFalse(obj.cleanup_confirmed)
        self.assertEqual(obj._state, "cleanup-failed-retained")
        self.assertIsNotNone(c.job_fd)
        self.assertIsNotNone(c.home_fd)
        self.assertTrue(socketdir.is_dir())

    def test_fixture_lifecycle_is_live_only_after_barrier_and_has_no_authority(self):
        obj = self.lifetime()
        with obj:
            self.assertTrue(self.backend.before_barrier)
            self.assertEqual((self.home / "common.conf").read_bytes(), b"no-autostart\n")
            obj.require_live()
            self.assertEqual(obj.receipt.evidence_class, "fixture-only")
            self.assertFalse(obj.receipt.production_authority)
            self.assertFalse(obj.cleanup_confirmed)
        obj.close()
        self.assertTrue(obj.cleanup_confirmed)
        self.assertTrue(self.home.is_dir())
        self.assertEqual(self.backend.events, ["prepare", "spawn", "ready", "validate", "cleanup"])

    def test_startup_baseexception_cleans_enrolled_custody(self):
        for stage, expected in (("prepare", ValueError), ("spawn", KeyboardInterrupt), ("ready", a.OwnedAgentError)):
            with self.subTest(stage=stage):
                self.backend.fail = stage
                obj = self.lifetime()
                with self.assertRaises(expected):
                    obj.start()
                self.assertTrue(obj.cleanup_confirmed)
                self.assertFalse(obj.retained_custody.directories)
                obj.close()

    def test_startup_original_error_and_failed_cleanup_both_remain_accessible(self):
        self.backend.fail = "spawn"
        self.backend.cleanup_fail = True
        obj = self.lifetime()
        with self.assertRaises(KeyboardInterrupt) as caught:
            obj.start()
        self.assertFalse(obj.cleanup_confirmed)
        self.assertIsInstance(obj.retained_custody.cleanup_error, a.OwnedAgentError)
        self.assertTrue(caught.exception.__notes__)
        self.assertTrue(obj.retained_custody.directories)
        self.backend.cleanup_fail = False
        obj.close()
        self.assertTrue(obj.cleanup_confirmed)

    def test_body_error_is_preserved_if_close_also_fails(self):
        obj = self.lifetime()
        self.backend.cleanup_fail = True
        with self.assertRaises(a.OwnedAgentError) as caught:
            with obj:
                raise SystemExit("fixture body failure")
        self.assertIsInstance(caught.exception.body_error, SystemExit)
        self.assertIs(caught.exception.__cause__, caught.exception.body_error)
        self.assertFalse(obj.cleanup_confirmed)
        os.fstat(obj.retained_custody.home_fd)

    def test_live_rejects_mutated_barrier_even_when_inode_unchanged(self):
        obj = self.lifetime().start()
        (self.home / "common.conf").write_bytes(b"use-keyboxd\n")
        with self.assertRaisesRegex(a.OwnedAgentError, "COMMON_CONF_TAMPERED"):
            obj.require_live()
        (self.home / "common.conf").write_bytes(b"no-autostart\n")

    def test_lifecycle_requires_start_and_cannot_restart_after_close(self):
        obj = self.lifetime()
        with self.assertRaisesRegex(a.OwnedAgentError, "LIFECYCLE_STATE"):
            obj.require_live()
        obj.start().close()
        with self.assertRaisesRegex(a.OwnedAgentError, "LIFECYCLE_STATE"):
            obj.start()

    def test_closed_raw_directory_protocol_and_homedir_only_binding(self):
        good = str(self.home).encode() + b"\n"
        self.assertEqual(a.parse_gpgconf_single_value(good, name="homedir"), str(self.home))
        for bad in (good + b"\n", good[:-1], b"relative\n", b"/x/../y\n", b"/x:y\n", b"/x%20y\n", b"/x\r\n", b"/x\x0cy\n", b"/x\x00\n", b"x" * 5000):
            with self.subTest(value=bad[:20]):
                with self.assertRaisesRegex(a.OwnedAgentError, "GPGCONF_OUTPUT"):
                    a.parse_gpgconf_single_value(bad, name="homedir")
        records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home), "socketdir": str(self.home), "agent-socket": str(self.home / "S.gpg-agent")}
        self.assertEqual(a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job).socketdir, self.home)
        records["socketdir"] = str(self.job)
        with self.assertRaisesRegex(a.OwnedAgentError, "PATH_UNEXPECTED"):
            a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)

    def test_external_socketdir_is_created_by_owner_and_allows_ctime_change(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        socketdir = self.job / "socket-runtime"
        records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home),
                   "socketdir": str(socketdir), "agent-socket": str(socketdir / "S.gpg-agent")}
        c.paths = a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)
        backend._bind_socketdir(c)
        self.assertEqual(c.paths.socketdir, socketdir)
        self.assertTrue(c.socketdir_owned)
        self.assertEqual(c.owned_job_entries, {socketdir.name: c.socketdir_identity})
        os.chmod(socketdir, 0o750)
        os.chmod(socketdir, 0o700)
        a._check_directories(c)
        backend.cleanup(c)
        self.assertFalse(socketdir.exists())
        self.assertTrue(self.home.is_dir())

        def fail_snapshot(_c, _socketdir):
            return patch.object(a, "_ident", side_effect=a.OwnedAgentError("SOCKETDIR_SNAPSHOT_FAILED", "fixture"))

        def fail_open(_c, _socketdir):
            return patch.object(a, "_open_chain", side_effect=OSError("fixture open failure"))

        def replace_before_open(_c, socketdir):
            saved = socketdir.parent / f"saved-{socketdir.name}"
            real_open_chain = a._open_chain
            def replacing(path, custody, *, directory_sink=None):
                socketdir.rename(saved)
                socketdir.mkdir(mode=0o700)
                return real_open_chain(path, custody, directory_sink=directory_sink)
            return patch.object(a, "_open_chain", side_effect=replacing)

        def fail_private(_c, _socketdir):
            return patch.object(a, "_private", side_effect=a.OwnedAgentError("PATH_CUSTODY", "fixture"))

        def seed_foreign_entry(_c, socketdir):
            real_open_chain = a._open_chain
            def opening_and_seeding(path, custody, *, directory_sink=None):
                fd = real_open_chain(path, custody, directory_sink=directory_sink)
                (socketdir / "foreign-entry").write_bytes(b"fixture-foreign")
                return fd
            return patch.object(a, "_open_chain", side_effect=opening_and_seeding)

        cases = (("snapshot", fail_snapshot, a.OwnedAgentError),
                 ("open", fail_open, OSError),
                 ("identity-replacement", replace_before_open, a.OwnedAgentError),
                 ("private", fail_private, a.OwnedAgentError),
                 ("empty-foreign", seed_foreign_entry, a.OwnedAgentError))
        for index, (label, installer, expected) in enumerate(cases):
            with self.subTest(stage=label):
                failed_backend, failed_custody, failed_socketdir = self._external_custody(f"sr{index}")
                self._assert_unconfirmed_external_bind(failed_backend, failed_custody, failed_socketdir, installer, expected)
                if label == "identity-replacement":
                    self.assertTrue((self.job / f"saved-{failed_socketdir.name}").is_dir())
                if label == "empty-foreign":
                    self.assertEqual((failed_socketdir / "foreign-entry").read_bytes(), b"fixture-foreign")

    def test_external_socketdir_precreated_by_same_uid_is_refused(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        socketdir = self.job / "socket-runtime"
        socketdir.mkdir(mode=0o700)
        records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home),
                   "socketdir": str(socketdir), "agent-socket": str(socketdir / "S.gpg-agent")}
        c.paths = a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)
        with self.assertRaisesRegex(a.OwnedAgentError, "SOCKETDIR_NOT_FRESH"):
            backend._bind_socketdir(c)
        self.assertFalse(c.socketdir_owned)
        self.assertFalse(c.owned_job_entries)
        self.assertTrue(socketdir.is_dir())

    def test_external_socketdir_rejects_foreign_entry_and_retains_physical_custody(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        socketdir = self.job / "socket-runtime"
        socketdir.mkdir(mode=0o700)
        (socketdir / "foreign-entry").write_bytes(b"fixture")
        records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home),
                   "socketdir": str(socketdir), "agent-socket": str(socketdir / "S.gpg-agent")}
        c.paths = a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)
        with self.assertRaisesRegex(a.OwnedAgentError, "SOCKETDIR_NOT_FRESH"):
            backend._bind_socketdir(c)
        self.assertFalse(c.socketdir_owned)
        self.assertFalse(c.socket_directories)
        self.assertTrue((socketdir / "foreign-entry").exists())

    def test_external_socketdir_rejects_ancestor_symlink_and_ambient_runtime_path(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        link = self.job / "socket-runtime"
        link.symlink_to(self.home)
        records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home),
                   "socketdir": str(link), "agent-socket": str(link / "S.gpg-agent")}
        c.paths = a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)
        with self.assertRaisesRegex(a.OwnedAgentError, "SOCKETDIR_NOT_FRESH"):
            backend._bind_socketdir(c)
        self.assertTrue(link.is_symlink())
        ambient = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home),
                   "socketdir": f"/run/user/{os.getuid()}/gnupg",
                   "agent-socket": f"/run/user/{os.getuid()}/gnupg/S.gpg-agent"}
        with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_SOCKET_PLACEMENT"):
            a.bind_gpgconf_paths(ambient, homedir=self.home, job_root=self.job)

    def test_external_socketdir_replacement_is_detected_before_cleanup(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        socketdir = self.job / "socket-runtime"
        records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home),
                   "socketdir": str(socketdir), "agent-socket": str(socketdir / "S.gpg-agent")}
        c.paths = a.bind_gpgconf_paths(records, homedir=self.home, job_root=self.job)
        backend._bind_socketdir(c)
        saved = self.job / "saved-socket-runtime"
        socketdir.rename(saved)
        socketdir.mkdir(mode=0o700)
        with self.assertRaisesRegex(a.OwnedAgentError, "SOCKETDIR_REPLACED|JOB_ROOT_CHANGED"):
            a._check_directories(c)
        socketdir.rmdir()
        saved.rename(socketdir)
        backend.cleanup(c)

    def test_constructor_has_no_caller_executor_and_rejects_unsafe_paths(self):
        for home, job in ((self.home, self.home), (self.job / ".gnupg", self.job), (str(self.home) + "/", self.job), (str(self.home) + "/../x", self.job), (self.job / "x y", self.job)):
            with self.subTest(home=home):
                with self.assertRaises(a.OwnedAgentError):
                    a.OwnedGpgAgent(home, job)
        with self.assertRaises(TypeError):
            a.OwnedGpgAgent(self.home, self.job, runner=lambda: None)

    def test_every_fixed_agent_option_is_present_in_pinned_upstream_option_table(self):
        # Parse the retained canonical upstream option table itself. Metadata
        # may record the expected spelling, but cannot establish support.
        provenance = json.loads((self.workspace / "PRIMARY-2.4.9-PROVENANCE.json").read_text())
        source_path = self.workspace / provenance["source_file"]
        source = source_path.read_text()
        self.assertEqual(provenance["version"], a.TARGET_GNUPG_VERSION)
        self.assertEqual(provenance["commit"], "21c7d29d6ed2eb891f7f66f83bcf764fcaaa6752")
        self.assertEqual(len(provenance["commit"]), 40)
        self.assertEqual(provenance["source_bytes"], len(source.encode("utf-8")))
        self.assertEqual(provenance["source_sha256"], hashlib.sha256(source.encode("utf-8")).hexdigest())
        table_start = source.index("static gpgrt_opt_t opts[] = {")
        table_end = source.index("};", table_start)
        option_table = source[table_start:table_end]
        supported = set(re.findall(
            r'ARGPARSE_[A-Za-z0-9_]+\s*\(\s*[A-Za-z0-9_]+\s*,\s*"([^"]+)"',
            option_table,
        ))
        self.assertIn("no-options", supported)
        self.assertIn("no-allow-external-cache", supported)
        self.assertIn("disable-check-own-socket", supported)
        calls = [node for node in ast.walk(ast.parse(a._EXEC_SHIM_SOURCE))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == "os"
                 and node.func.attr == "execve"]
        self.assertEqual(len(calls), 1)
        argv = calls[0].args[1]
        self.assertIsInstance(argv, ast.Tuple)
        options = {node.value[2:] for node in argv.elts if isinstance(node, ast.Constant)
                   and isinstance(node.value, str) and node.value.startswith("--")}
        self.assertTrue(options)
        self.assertFalse(options - supported, f"unsupported pinned-agent CLI options: {options - supported}")
        self.assertIn("supervised", options)
        self.assertNotIn("deprecated-supervised", options)

    def test_physical_open_rejects_symlink_and_detects_ancestor_replacement(self):
        c = self.custody()
        self.home.rename(self.job / "old")
        self.home.mkdir(mode=0o700)
        with self.assertRaisesRegex(a.OwnedAgentError, "PATH_CHANGED|JOB_ROOT_CHANGED"):
            a._check_directories(c)
        link = self.job / "link"
        link.symlink_to(self.home)
        with self.assertRaises(OSError):
            a._open_chain(link, c)

    def test_runtime_preflight_fails_before_query_even_for_named_homedir(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        with patch.object(a, "_preflight_external_paths", side_effect=a.OwnedAgentError("UNSUPPORTED_SOCKET_PLACEMENT", "fixture runtime exists")), patch.object(a.subprocess, "run", side_effect=AssertionError("must not launch")):
            with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_SOCKET_PLACEMENT"):
                backend._query(c, (a.NATIVE_GPGCONF, "--homedir", str(self.home), "--list-dirs", "homedir"))

    def test_absence_probe_rejects_unrecognized_redirect_instead_of_assuming_absence(self):
        (self.job / "redirect").symlink_to(self.home)
        with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_SOCKET_PLACEMENT"):
            a._absent_physical(self.job / "redirect/user/4242", "UNSUPPORTED_SOCKET_PLACEMENT")
        a._absent_physical(self.job / "absent/user/4242", "UNSUPPORTED_SOCKET_PLACEMENT")

    def test_conventional_runtime_alias_checks_canonical_user_dirs_before_query(self):
        backend = a._NativeBackend(self.home, self.job)
        for spelling in ("/run", "../run"):
            with self.subTest(spelling=spelling):
                metadata = _RuntimeMetadata(spelling)
                c = a._RetainedCustody()
                c.tools[a.NATIVE_GPGCONF] = ("fixture", "digest")
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv)
                    uid = str(os.getuid())
                    self.assertIn("/run/gnupg/user/" + uid, metadata.seen)
                    self.assertIn("/run/user/" + uid, metadata.seen)
                    self.assertFalse(any(path.startswith("/var/run/") for path in metadata.seen))
                    return SimpleNamespace(returncode=0, stdout=str(self.home).encode() + b"\n", stderr=b"")
                with patch.object(a.os, "lstat", side_effect=metadata.lstat), patch.object(a.os, "readlink", side_effect=metadata.readlink), patch.object(a.os, "stat", side_effect=AssertionError("must not follow alias")), patch.object(a, "_trusted_tool", return_value=("fixture", "digest")), patch.object(a.subprocess, "run", side_effect=run):
                    c.runtime_layout = a._preflight_external_paths()
                    result = backend._query(c, (a.NATIVE_GPGCONF, "--homedir", str(self.home), "--list-dirs", "homedir"))
                self.assertEqual(result, str(self.home).encode() + b"\n")
                self.assertEqual(len(calls), 1)

    def test_changed_or_unexpected_runtime_alias_refuses_before_tool_launch(self):
        backend = a._NativeBackend(self.home, self.job)
        for change in ("target", "inode", "unsafe-var", "unsafe-run", "unowned-alias"):
            with self.subTest(change=change):
                metadata = _RuntimeMetadata()
                c = a._RetainedCustody()
                with patch.object(a.os, "lstat", side_effect=metadata.lstat), patch.object(a.os, "readlink", side_effect=metadata.readlink), patch.object(a.subprocess, "run", side_effect=AssertionError("must refuse before launch")):
                    c.runtime_layout = a._preflight_external_paths()
                    if change == "target":
                        metadata.target = "/unexpected-runtime"
                    elif change == "inode":
                        metadata.info["/var/run"].st_ino += 1
                    elif change == "unsafe-var":
                        metadata.info["/var"].st_mode |= 0o002
                    elif change == "unsafe-run":
                        metadata.info["/run"].st_uid = 1000
                    else:
                        metadata.info["/var/run"].st_uid = 1000
                    with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_SOCKET_PLACEMENT"):
                        backend._query(c, (a.NATIVE_GPGCONF, "--version"))

    def test_runtime_alias_readlink_change_during_inspection_refuses(self):
        metadata = _RuntimeMetadata()
        with patch.object(a.os, "lstat", side_effect=metadata.lstat), patch.object(a.os, "readlink", side_effect=["/run", "../run"]), patch.object(a.subprocess, "run", side_effect=AssertionError("must not launch")):
            with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_SOCKET_PLACEMENT"):
                a._preflight_external_paths()

    def test_present_canonical_runtime_user_directory_refuses_even_with_valid_alias(self):
        metadata = _RuntimeMetadata()
        metadata.info["/run/user/" + str(os.getuid())] = SimpleNamespace(
            st_dev=1, st_ino=30, st_uid=os.getuid(), st_mode=stat.S_IFDIR | 0o700)
        with patch.object(a.os, "lstat", side_effect=metadata.lstat), patch.object(a.os, "readlink", side_effect=metadata.readlink), patch.object(a.subprocess, "run", side_effect=AssertionError("must not launch")):
            with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_SOCKET_PLACEMENT"):
                a._preflight_external_paths()

    def test_query_uses_one_fixed_name_and_closed_environment(self):
        c = self.custody()
        c.tools[a.NATIVE_GPGCONF] = ("fixture", "digest")
        backend = a._NativeBackend(self.home, self.job)
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=str(self.home).encode() + b"\n", stderr=b"")
        with patch.object(a, "_preflight_external_paths"), patch.object(a, "_trusted_tool", return_value=("fixture", "digest")), patch.object(a.subprocess, "run", side_effect=run):
            output = backend._query(c, (a.NATIVE_GPGCONF, "--homedir", str(self.home), "--list-dirs", "homedir"))
        self.assertEqual(output, str(self.home).encode() + b"\n")
        self.assertEqual(calls[0][1]["env"], {"HOME": str(self.home), "GNUPGHOME": str(self.home), "PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        self.assertFalse(calls[0][1]["shell"])

    def test_inert_socket_allocation_and_confirmed_cleanup_preserve_home(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        backend._allocate(c)
        self.assertGreaterEqual(c.listener_fd, 16)
        self.assertEqual(os.fstat(c.listener_fd).st_ino, c.listener_identity.ino)
        marker = self.home / "caller-owned-marker"
        marker.write_bytes(b"inert preserved data")
        backend.cleanup(c)
        self.assertIsNone(c.listener_fd)
        self.assertFalse(c.directories)
        self.assertFalse((self.home / "S.gpg-agent").exists())
        self.assertTrue(marker.exists())

    def test_cleanup_replacement_retains_diagnostic_and_directory_handles(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        backend._allocate(c)
        original = self.home / "saved-owned-socket"
        (self.home / "S.gpg-agent").rename(original)
        (self.home / "S.gpg-agent").write_bytes(b"foreign replacement")
        with self.assertRaisesRegex(a.OwnedAgentError, "CLEANUP_PATH_CHANGED"):
            backend.cleanup(c)
        self.assertEqual((self.home / "S.gpg-agent").read_bytes(), b"foreign replacement")
        os.fstat(c.stderr_fd)
        os.fstat(c.home_fd)
        self.assertTrue(c.directories)
        # Restore only the inert test-owned entry for exact teardown.
        (self.home / "S.gpg-agent").unlink()
        original.rename(self.home / "S.gpg-agent")
        backend.cleanup(c)

    def test_pidfd_enrollment_failure_retains_child_without_numeric_signal_or_wait(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        backend._allocate(c)
        events = []
        c.child = SimpleNamespace(pid=42003, wait=lambda **kwargs: events.append("wait"))
        with patch.object(a.os, "kill", side_effect=AssertionError("numeric PID cleanup is forbidden")) as numeric_kill, patch.object(a, "_proc_observation"):
            with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_CLEANUP_UNCONFIRMED"):
                backend.cleanup(c)
        numeric_kill.assert_not_called()
        self.assertEqual(events, [])
        self.assertEqual(c.uncertainty, "PIDFD_ENROLLMENT_UNCONFIRMED")
        self.assertFalse(c.reaped)
        os.fstat(c.home_fd)
        os.fstat(c.stderr_fd)
        self.assertTrue(c.directories)
        self.assertTrue((self.home / "S.gpg-agent").exists())

    def test_full_start_close_retains_native_jobfd_on_pidfd_enrollment_failure(self):
        obj = a.OwnedGpgAgent(self.home, self.job)
        backend = obj._backend
        real_listdir = a.os.listdir
        tool_identity = a.PathIdentity(1, 2, 0, 0o755, stat.S_IFREG)
        socketdir = self.job / "socket-runtime"
        events = []
        def listing(path):
            return ["main-thread"] if path == "/proc/self/task" else real_listdir(path)
        def query(c, argv):
            if argv[-1] == "--version":
                return f"{Path(argv[0]).name} (GnuPG) 2.4.9\n".encode()
            records = {
                "sysconfdir": "/etc/gnupg",
                "homedir": str(self.home),
                "socketdir": str(socketdir),
                "agent-socket": str(socketdir / "S.gpg-agent"),
            }
            return (records[argv[-1]] + "\n").encode()
        def enrollment_failure(c):
            c.child = SimpleNamespace(pid=42004, wait=lambda **kwargs: events.append("wait"))
            raise OSError("inert pidfd enrollment failure")
        with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "pidfd_open", create=True), patch.object(
                a.signal, "pidfd_send_signal", create=True), patch.object(a.os, "listdir", side_effect=listing), patch.object(
                a, "_proc_preflight"), patch.object(a, "_preflight_external_paths", return_value=None), patch.object(
                a, "_trusted_tool", return_value=(tool_identity, "fixture-tool")), patch.object(
                a, "_exe", return_value=tool_identity), patch.object(backend, "_query", side_effect=query), patch.object(
                backend, "spawn", side_effect=enrollment_failure), patch.object(a, "_proc_observation"):
            with self.assertRaises(OSError):
                obj.start()
        c = obj.retained_custody
        self.assertFalse(obj.cleanup_confirmed)
        self.assertEqual(obj._state, "cleanup-failed-retained")
        self.assertEqual(c.uncertainty, "PIDFD_ENROLLMENT_UNCONFIRMED")
        self.assertEqual(events, [])
        os.fstat(c.job_fd)
        os.fstat(c.home_fd)
        os.fstat(c.stderr_fd)
        self.assertIsNotNone(c.child)
        self.assertTrue(socketdir.exists())
        self.assertTrue((socketdir / "S.gpg-agent").exists())
        # Teardown is explicit and inert: no numeric PID is ever adopted.
        c.child = None
        c.uncertainty = None
        obj.close()
        self.assertTrue(obj.cleanup_confirmed)
        self.assertTrue(self.home.is_dir())

    def test_exact_held_pidfd_cleanup_reaps_and_removes_only_owned_entries(self):
        backend, c, proc = self.proc_custody()
        events = []
        with proc.install(), patch.object(a, "_proc_observation"), patch.object(
                a, "_pidfd_exited", side_effect=lambda fd, timeout=0: True), patch.object(
                a.signal, "pidfd_send_signal", side_effect=lambda fd, sig: events.append(sig), create=True):
            backend.cleanup(c)
        self.assertEqual(events, [signal.SIGTERM])
        self.assertTrue(c.reaped)
        self.assertFalse(c.directories)
        self.assertFalse((self.home / "S.gpg-agent").exists())
        self.assertFalse((self.home / "common.conf").exists())
        self.assertTrue(self.home.is_dir())

    def test_pidfd_timeout_keeps_all_custody_and_never_reaps_or_unlinks(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        backend._allocate(c)
        # Ordinary inert file descriptor stands in for a held pidfd; all kernel
        # process operations are replaced and no signal reaches a real PID.
        c.pidfd = os.open(self.home, os.O_RDONLY)
        sent = []
        c.child = SimpleNamespace(pid=42001, wait=lambda **kwargs: self.fail("must not reap unconfirmed child"))
        with patch.object(a.signal, "pidfd_send_signal", side_effect=lambda fd, sig: sent.append(sig), create=True), patch.object(a, "_pidfd_exited", return_value=False), patch.object(a, "_proc_observation"):
            with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_CLEANUP_UNCONFIRMED"):
                backend.cleanup(c)
        self.assertEqual(sent, [signal.SIGTERM, signal.SIGKILL])
        os.fstat(c.pidfd)
        os.fstat(c.stderr_fd)
        os.fstat(c.home_fd)
        self.assertTrue((self.home / "S.gpg-agent").exists())
        self.assertFalse(c.reaped)

    def test_interrupted_cleanup_observation_stops_child_but_retains_handles(self):
        c = self.custody()
        c.pidfd = os.open(self.home, os.O_RDONLY)
        events = []
        c.child = SimpleNamespace(pid=42001, wait=lambda **kwargs: events.append("reaped"))
        backend = a._NativeBackend(self.home, self.job)
        with patch.object(a.signal, "pidfd_send_signal", side_effect=lambda fd, sig: events.append(sig), create=True), patch.object(a, "_pidfd_exited", return_value=True), patch.object(a, "_proc_observation", side_effect=KeyboardInterrupt("fixture observation interruption")):
            with self.assertRaises(KeyboardInterrupt):
                backend.cleanup(c)
        self.assertEqual(events, [signal.SIGTERM, "reaped"])
        os.fstat(c.pidfd)
        os.fstat(c.home_fd)

    def test_spawn_enrolls_pidfd_before_unmasking_without_poll_or_wait(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        backend._allocate(c)
        c.python = "/fixture/python"
        c.tools[c.python] = (a.PathIdentity(1, 2, 0, 0o755, stat.S_IFREG), "digest")
        c.tools[a.NATIVE_GPG_AGENT] = c.tools[c.python]
        events = []
        child = SimpleNamespace(pid=42003)
        def popen(argv, **kwargs):
            events.append("popen")
            self.assertEqual(argv[:5], (c.python, "-I", "-S", "-B", "-c"))
            self.assertEqual(kwargs["pass_fds"], (c.listener_fd,))
            self.assertNotIn("preexec_fn", kwargs)
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(argv[-2], f"{os.fstat(c.home_fd).st_dev}:{os.fstat(c.home_fd).st_ino}")
            self.assertEqual(argv[-1], "1:2")
            return child
        def enroll(pid, flags):
            self.assertIs(c.child, child)
            events.append("pidfd")
            raise OSError("fixture unsupported pidfd")
        def mask(how, values):
            events.append("block" if how == signal.SIG_BLOCK else "restore")
            return set()
        with patch.object(a, "_proc_preflight"), patch.object(a, "_preflight_external_paths"), patch.object(a, "_trusted_tool", return_value=c.tools[c.python]), patch.object(a.signal, "pthread_sigmask", side_effect=mask), patch.object(a.subprocess, "Popen", side_effect=popen), patch.object(a.os, "pidfd_open", side_effect=enroll, create=True):
            with self.assertRaises(OSError):
                backend.spawn(c)
        self.assertIs(c.child, child)
        self.assertIsNone(c.pidfd)
        self.assertEqual(events, ["block", "popen", "pidfd", "restore"])

    def test_readiness_allows_only_initial_interpreter_transition(self):
        c = self.custody()
        c.child = SimpleNamespace(pid=42001)
        c.python = "python"
        c.tools = {"python": ("python-id", "digest"), a.NATIVE_GPG_AGENT: ("agent-id", "digest")}
        c.pidfd = None
        backend = a._NativeBackend(self.home, self.job)
        events = []
        def validate(c, **kwargs):
            events.append("live-barrier" if kwargs.get("barrier", True) else "live")
        with patch.object(a, "_pidfd_exited", return_value=False), patch.object(a, "_exe", side_effect=["python-id", "agent-id"]), patch.object(a.time, "sleep"), patch.object(backend, "validate", side_effect=validate), patch.object(a, "_assuan", side_effect=lambda paths, pid, **kwargs: events.append("assuan")):
            backend.ready(c)
        self.assertTrue(c.final_exec)
        self.assertEqual(events, ["live", "assuan", "live", "live-barrier"])
        self.assertEqual((self.home / "common.conf").read_bytes(), b"no-autostart\n")
        (self.home / "common.conf").unlink()
        c.common_identity = None
        with patch.object(a, "_pidfd_exited", return_value=False), patch.object(a, "_exe", return_value="python-id"):
            with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_EXEC_IDENTITY"):
                backend.ready(c)

    def test_assuan_mismatch_is_fatal_and_does_not_install_barrier(self):
        c = self.custody()
        c.child = SimpleNamespace(pid=42001)
        c.python = "python"
        c.tools = {"python": ("python-id", "digest"), a.NATIVE_GPG_AGENT: ("agent-id", "digest")}
        backend = a._NativeBackend(self.home, self.job)
        with patch.object(a, "_pidfd_exited", return_value=False), patch.object(a, "_exe", return_value="agent-id"), patch.object(backend, "validate"), patch.object(a, "_assuan", side_effect=a.OwnedAgentError("AGENT_READINESS_MISMATCH", "fixture mismatch")):
            with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_READINESS_MISMATCH"):
                backend.ready(c)
        self.assertFalse((self.home / "common.conf").exists())

    def test_unsupported_version_refuses_before_directory_queries_or_spawn(self):
        c = a._RetainedCustody()
        self.custodies.append(c)
        backend = a._NativeBackend(self.home, self.job)
        real_listdir = a.os.listdir
        def listing(path):
            return ["main-thread"] if path == "/proc/self/task" else real_listdir(path)
        fake_identity = ("python-id", "hash")
        calls = []
        def query(c, argv):
            calls.append(argv)
            return b"gpgconf (GnuPG) 2.4.8\n"
        with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "pidfd_open", create=True), patch.object(a.signal, "pidfd_send_signal", create=True), patch.object(a.os, "listdir", side_effect=listing), patch.object(a, "_proc_preflight"), patch.object(a, "_preflight_external_paths"), patch.object(a, "_trusted_tool", return_value=fake_identity), patch.object(a, "_exe", return_value="python-id"), patch.object(backend, "_query", side_effect=query), patch.object(a.subprocess, "Popen", side_effect=AssertionError("must not spawn")):
            with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_VERSION"):
                backend.prepare(c)
        self.assertEqual(calls, [(a.NATIVE_GPGCONF, "--version")])
        self.assertIsNone(c.child)

    def test_assuan_protocol_bounds_reject_error_multiple_data_and_cr(self):
        for data in (b"ERR 1\n", b"OK\r\n", b"D " + b"x" * 1000 + b"\nOK\n", b"# x\n" * 17 + b"OK\n"):
            with self.subTest(data=data[:20]):
                with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_READINESS_MISMATCH"):
                    a._read_response(io.BytesIO(data))
        self.assertEqual(a._read_response(io.BytesIO(b"# comment\nD 2.4.9\nOK\n")), [b"2.4.9"])

    def test_real_inert_assuan_socket_ignores_creator_peer_credentials(self):
        path = self.home / "S.gpg-agent"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(1)
        errors = []
        accepts = []
        def serve():
            try:
                conn, _ = server.accept()
                accepts.append(True)
                with conn, conn.makefile("rb") as stream:
                    # Slower than the removed half-second probe churn window.
                    time.sleep(0.6)
                    conn.sendall(b"OK inert fixture\n")
                    for command, value in ((b"version", b"2.4.9"), (b"pid", b"42001"), (b"socket_name", str(path).encode())):
                        if stream.readline() != b"GETINFO " + command + b"\n":
                            raise AssertionError("unexpected fixture command")
                        conn.sendall(b"D " + value + b"\nOK\n")
                    if stream.readline() != b"BYE\n":
                        raise AssertionError("missing BYE")
                    conn.sendall(b"OK\n")
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            # No getsockopt/SO_PEERCRED is needed: server reports the held-child
            # PID, deliberately distinct from this listener-creating process.
            a._assuan(a.BoundAgentPaths(self.home, self.job, path), 42001, deadline=time.monotonic() + 3)
        finally:
            thread.join(timeout=2)
            server.close()
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertEqual(len(accepts), 1)

    def proc_custody(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        backend._allocate(c)
        backend._barrier(c)
        c.child = SimpleNamespace(pid=42001, wait=lambda **kwargs: 0)
        c.pidfd = os.open(self.home, os.O_RDONLY)
        proc = _SyntheticProc()
        proc.fds[42001]["3"] = (c.listener_identity.dev, c.listener_identity.ino)
        c.tools = {tool: (a._ident(proc.exe_identity), "fixture-digest")
                   for tool in (a.NATIVE_GPG, a.NATIVE_GPG_AGENT)}
        return backend, c, proc

    @contextmanager
    def live_metadata(self, c, proc):
        with proc.install(), patch.object(a, "_preflight_external_paths", return_value=c.runtime_layout), patch.object(
            a, "_trusted_tool", side_effect=lambda tool: c.tools[tool]
        ), patch.object(a, "_pidfd_exited", return_value=False):
            yield

    def test_proc_scan_directly_accepts_only_expected_live_listener_holder(self):
        c = a._RetainedCustody(child=SimpleNamespace(pid=42001), listener_identity=a.PathIdentity(19, 42, 0, 0, stat.S_IFSOCK))
        proc = _SyntheticProc()
        with proc.install():
            a._proc_observation(c, stopped=False)
        self.assertIsNone(c.uncertainty)
        for relation in range(3):
            proc = _SyntheticProc()
            links = [1, 2, 3]
            links[relation] = 42001
            proc.processes[2] = tuple(links)
            proc.fds[2] = {}
            c.uncertainty = None
            with proc.install():
                with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_UNEXPECTED_DESCENDANT"):
                    a._proc_observation(c, stopped=False)
            self.assertEqual(c.uncertainty, "AGENT_UNEXPECTED_DESCENDANT")

    def test_proc_scan_directly_rejects_foreign_or_extra_child_listener_descriptors(self):
        for owner in (1, 42001):
            proc = _SyntheticProc()
            proc.fds[owner]["7"] = (19, 42)
            c = a._RetainedCustody(child=SimpleNamespace(pid=42001), listener_identity=a.PathIdentity(19, 42, 0, 0, stat.S_IFSOCK))
            with proc.install():
                with self.assertRaisesRegex(a.OwnedAgentError, "LISTENER_HOLDER_UNCONFIRMED"):
                    a._proc_observation(c, stopped=False)
            self.assertEqual(c.uncertainty, "LISTENER_HOLDER_UNCONFIRMED")

    def test_proc_scan_directly_codes_visibility_parse_and_root_failures(self):
        cases = [("list", "/proc"), ("list", "/proc/1/fd"), ("stat", "/proc/1/fd/0"), ("text", "/proc/1/stat")]
        for operation, path in cases:
            proc = _SyntheticProc()
            proc.failures[(operation, path)] = PermissionError("inert denied metadata")
            c = a._RetainedCustody(child=SimpleNamespace(pid=42001), listener_identity=a.PathIdentity(19, 42, 0, 0, stat.S_IFSOCK))
            with proc.install():
                with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                    a._proc_observation(c, stopped=False)
            self.assertEqual(c.uncertainty, "PROC_VISIBILITY_UNCONFIRMED")
        proc = _SyntheticProc()
        proc.processes[1] = ("invalid", 1, 1)
        with proc.install(), self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
            a._proc_observation(c, stopped=False)

    def test_proc_scan_tolerates_metadata_disappearance_but_not_stopped_holders(self):
        proc = _SyntheticProc()
        proc.processes[2] = (1, 1, 1)
        proc.failures[("text", "/proc/2/stat")] = FileNotFoundError()
        proc.fds[1]["8"] = FileNotFoundError()
        c = a._RetainedCustody(child=SimpleNamespace(pid=42001), listener_identity=a.PathIdentity(19, 42, 0, 0, stat.S_IFSOCK))
        with proc.install():
            a._proc_observation(c, stopped=False)
            with self.assertRaisesRegex(a.OwnedAgentError, "LISTENER_HOLDER_UNCONFIRMED"):
                a._proc_observation(c, stopped=True)

    def test_stopped_proc_scan_checks_kernel_unix_table_and_visibility(self):
        proc = _SyntheticProc()
        proc.fds[42001] = {}
        c = a._RetainedCustody(child=SimpleNamespace(pid=42001), listener_identity=a.PathIdentity(19, 42, 0, 0, stat.S_IFSOCK))
        with proc.install():
            a._proc_observation(c, stopped=True)
            proc.net += "1: 2 0 0 1 1 42 inert\n"
            with self.assertRaisesRegex(a.OwnedAgentError, "LISTENER_STILL_HELD"):
                a._proc_observation(c, stopped=True)
            self.assertIsNone(c.uncertainty)
            proc.failures[("text", "/proc/net/unix")] = PermissionError("inert denied table")
            with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                a._proc_observation(c, stopped=True)
        self.assertEqual(c.uncertainty, "PROC_VISIBILITY_UNCONFIRMED")

    def test_cleanup_retries_kernel_listener_release_using_real_scanner(self):
        backend, c, proc = self.proc_custody()
        c.reaped = True
        proc.fds[42001] = {}
        original = proc.text
        calls = []
        def text(path):
            if path == "/proc/net/unix":
                calls.append(path)
                return proc.net + (f"1: 2 0 0 1 1 {c.listener_identity.ino} inert\n" if len(calls) == 1 else "")
            return original(path)
        with proc.install(), patch.object(a, "_proc_text", side_effect=text), patch.object(a.time, "sleep"):
            backend.cleanup(c)
        self.assertEqual(len(calls), 2)
        self.assertFalse(c.directories)
        self.assertFalse((self.home / "S.gpg-agent").exists())

    def test_cleanup_exhausted_kernel_release_retry_retains_exact_custody(self):
        backend, c, proc = self.proc_custody()
        c.reaped = True
        proc.fds[42001] = {}
        proc.net += f"1: 2 0 0 1 1 {c.listener_identity.ino} inert\n"
        with proc.install(), patch.object(a.time, "monotonic", side_effect=[0, 1]):
            with self.assertRaisesRegex(a.OwnedAgentError, "LISTENER_STILL_HELD"):
                backend.cleanup(c)
        os.fstat(c.pidfd)
        os.fstat(c.stderr_fd)
        os.fstat(c.home_fd)
        self.assertTrue((self.home / "S.gpg-agent").exists())

    def test_native_validate_executes_all_live_checks_without_stubbing_scanner(self):
        backend, c, proc = self.proc_custody()
        with self.live_metadata(c, proc):
            backend.validate(c)
            with patch.object(a, "_pidfd_exited", return_value=True):
                with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_NOT_LIVE"):
                    backend.validate(c)
            with patch.object(a, "_exe", return_value=a.PathIdentity(5, 7, 0, 0o755, stat.S_IFREG)):
                with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_NOT_LIVE"):
                    backend.validate(c)
            (self.home / "common.conf").write_bytes(b"use-keyboxd\n")
            with self.assertRaisesRegex(a.OwnedAgentError, "COMMON_CONF_TAMPERED"):
                backend.validate(c)
            (self.home / "common.conf").write_bytes(a._BARRIER)
            original = self.home / "saved-socket"
            (self.home / "S.gpg-agent").rename(original)
            (self.home / "S.gpg-agent").write_bytes(b"inert replacement")
            with self.assertRaisesRegex(a.OwnedAgentError, "SOCKET_REPLACED"):
                backend.validate(c)
            (self.home / "S.gpg-agent").unlink()
            original.rename(self.home / "S.gpg-agent")
            proc.failures[("list", "/proc/1/fd")] = PermissionError("inert denied")
            with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                backend.validate(c)
            # A later successful scan cannot erase the prior loss of custody.
            proc.failures.clear()
            with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                backend.validate(c)
        self.assertEqual(c.uncertainty, "PROC_VISIBILITY_UNCONFIRMED")

    def test_validate_refuses_actual_synthetic_runtime_and_config_drift(self):
        for path, code in ((f"/run/user/{os.getuid()}", "UNSUPPORTED_SOCKET_PLACEMENT"),
                           ("/etc/gnupg", "GLOBAL_CONFIG_REJECTED"),
                           ("/usr/bin/gpgconf.ctl", "GLOBAL_CONFIG_REJECTED")):
            metadata = _RuntimeMetadata()
            c = a._RetainedCustody()
            with patch.object(a.os, "lstat", side_effect=metadata.lstat), patch.object(a.os, "readlink", side_effect=metadata.readlink):
                c.runtime_layout = a._preflight_external_paths()
                metadata.info[path] = SimpleNamespace(st_dev=1, st_ino=100, st_uid=0, st_mode=stat.S_IFDIR | 0o700)
                with self.assertRaisesRegex(a.OwnedAgentError, code):
                    a._NativeBackend(self.home, self.job).validate(c)

    def test_validate_rechecks_both_consumer_and_agent_tool_identity(self):
        backend, c, proc = self.proc_custody()
        for changed in (a.NATIVE_GPG, a.NATIVE_GPG_AGENT):
            with self.live_metadata(c, proc), patch.object(a, "_trusted_tool", side_effect=lambda tool: (c.tools[tool][0], "changed") if tool == changed else c.tools[tool]):
                with self.assertRaisesRegex(a.OwnedAgentError, "TOOL_CHANGED"):
                    backend.validate(c)

    def test_proc_preflight_accepts_visible_namespace_and_refuses_restricted_layouts(self):
        proc = _SyntheticProc()
        with proc.install():
            a._proc_preflight()
        for case in ("hidepid", "foreign-fd", "missing-mount", "namespace"):
            proc = _SyntheticProc()
            if case == "hidepid": proc.mount = proc.mount.replace("rw -", "rw,hidepid=2 -")
            elif case == "foreign-fd": proc.failures[("list", "/proc/1/fd")] = PermissionError("inert denied")
            elif case == "missing-mount": proc.mount = ""
            else: proc.failures[("stat", "/proc/1/ns/pid")] = PermissionError("inert namespace denied")
            with proc.install(), self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                a._proc_preflight()

    def test_prepare_refuses_proc_layout_before_any_gnupg_call_or_socket_allocation(self):
        c = a._RetainedCustody()
        real_listdir = os.listdir
        def listing(path): return ["main"] if path == "/proc/self/task" else real_listdir(path)
        backend = a._NativeBackend(self.home, self.job)
        with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "pidfd_open", create=True), patch.object(a.signal, "pidfd_send_signal", create=True), patch.object(a.os, "listdir", side_effect=listing), patch.object(a, "_proc_preflight", side_effect=a.OwnedAgentError("PROC_VISIBILITY_UNCONFIRMED", "inert refusal")), patch.object(backend, "_query", side_effect=AssertionError("must not query")), patch.object(backend, "_allocate", side_effect=AssertionError("must not allocate")):
            with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                backend.prepare(c)
        self.assertFalse(c.directories)
        self.assertIsNone(c.child)

    def test_prepare_holds_owned_staging_baseline_and_creates_only_external_child(self):
        staging = self.job / "staging"
        staging.mkdir(mode=0o700)
        marker = staging / "caller-owned"
        marker.write_bytes(b"inert baseline payload")
        c = a._RetainedCustody()
        self.custodies.append(c)
        backend = a._NativeBackend(self.home, self.job)
        real_listdir = a.os.listdir
        def listing(path):
            return ["main-thread"] if path == "/proc/self/task" else real_listdir(path)
        tool_identity = a.PathIdentity(1, 2, 0, 0o755, stat.S_IFREG)
        socketdir = self.job / "socket-runtime"
        def query(c, argv):
            if argv[-1] == "--version":
                return f"{Path(argv[0]).name} (GnuPG) 2.4.9\n".encode()
            records = {
                "sysconfdir": "/etc/gnupg",
                "homedir": str(self.home),
                "socketdir": str(socketdir),
                "agent-socket": str(socketdir / "S.gpg-agent"),
            }
            return (records[argv[-1]] + "\n").encode()
        with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "pidfd_open", create=True), patch.object(
                a.signal, "pidfd_send_signal", create=True), patch.object(a, "_proc_preflight"), patch.object(
                a.os, "listdir", side_effect=listing), patch.object(
                a, "_preflight_external_paths", return_value=None), patch.object(
                a, "_trusted_tool", return_value=(tool_identity, "fixture-tool")), patch.object(
                a, "_exe", return_value=tool_identity), patch.object(
                backend, "_query", side_effect=query):
            backend.prepare(c)
        self.assertEqual(c.job_members_before, frozenset({"h", "staging"}))
        self.assertEqual(set(c.job_entries_before), {"h", "staging"})
        self.assertEqual(set(c.owned_job_entries), {"socket-runtime", "agent-stderr.log"})
        self.assertTrue(staging.is_dir())
        self.assertTrue(socketdir.is_dir())
        backend.cleanup(c)
        self.assertTrue(staging.is_dir())
        self.assertTrue(marker.exists())
        self.assertFalse(socketdir.exists())

    def test_prepare_refuses_foreign_job_root_entry_after_baseline_is_held(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        late = self.job / "late-entry"
        real_listdir = a.os.listdir
        def listing(path):
            if path == "/proc/self/task":
                return ["main-thread"]
            return real_listdir(path)
        def query(c, argv):
            if argv[-1] == "--version":
                late.mkdir(mode=0o700)
                a._check_job_entries(c)
                return f"{Path(argv[0]).name} (GnuPG) 2.4.9\n".encode()
            raise AssertionError("baseline drift must stop before directory queries")
        with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "pidfd_open", create=True), patch.object(
                a.signal, "pidfd_send_signal", create=True), patch.object(a.os, "listdir", side_effect=listing), patch.object(
                a, "_proc_preflight"), patch.object(a, "_preflight_external_paths", return_value=None), patch.object(
                a, "_trusted_tool", return_value=(a.PathIdentity(1, 2, 0, 0o755, stat.S_IFREG), "fixture-tool")), patch.object(
                a, "_exe", return_value=a.PathIdentity(1, 2, 0, 0o755, stat.S_IFREG)), patch.object(
                backend, "_query", side_effect=query):
            with self.assertRaisesRegex(a.OwnedAgentError, "JOB_ROOT_CHANGED"):
                backend.prepare(c)
        self.assertTrue(c.job_entries_before)
        self.assertTrue(c.directories)
        os.fstat(c.job_fd)
        os.fstat(c.home_fd)

    def test_executable_denial_is_coded_and_retains_custody_after_live_failure(self):
        backend, c, proc = self.proc_custody()
        proc.failures[("stat", "/proc/42001/exe")] = PermissionError("inert nondumpable target")
        with self.live_metadata(c, proc):
            with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                backend.validate(c)
        self.assertEqual(c.uncertainty, "PROC_VISIBILITY_UNCONFIRMED")
        with proc.install(), patch.object(a.signal, "pidfd_send_signal", create=True), patch.object(a, "_pidfd_exited", return_value=True):
            with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
                backend.cleanup(c)
        self.assertTrue(c.reaped)
        os.fstat(c.pidfd)
        os.fstat(c.home_fd)
        proc.failures[("stat", "/proc/42001/exe")] = FileNotFoundError()
        with proc.install(), patch.object(a, "_pidfd_exited", return_value=True):
            with self.assertRaisesRegex(a.OwnedAgentError, "STARTUP_CHILD_EXITED"):
                a._child_exe(c, "STARTUP_CHILD_EXITED")

    def test_shim_ignores_sigpipe_after_default_resets_and_checks_exec_identities(self):
        tree = ast.parse(a._EXEC_SHIM_SOURCE)
        reset = [node for node in ast.walk(tree) if isinstance(node, ast.For) and "SIG_DFL" in ast.unparse(node)]
        ignored = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and ast.unparse(node.func) == "signal.signal"
                   and [ast.unparse(arg) for arg in node.args] == ["signal.SIGPIPE", "signal.SIG_IGN"]]
        self.assertEqual(len(reset), 1)
        self.assertEqual(len(ignored), 1)
        self.assertGreater(ignored[0].lineno, reset[0].end_lineno)
        # These comparisons guard the real exec boundary, rather than accepting
        # any safe-looking replacement home or root-owned executable.
        comparisons = [ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Compare)]
        self.assertTrue(any("(a.st_dev, a.st_ino) != expected_home" in text for text in comparisons))
        self.assertTrue(any("(t.st_dev, t.st_ino) != expected_agent" in text for text in comparisons))

    def test_enrollment_blocks_all_catchable_signals_except_sigchld(self):
        masks = []
        with patch.object(a.signal, "pthread_sigmask", side_effect=lambda how, values: masks.append((how, set(values))) or set()):
            with a._enrollment_mask(): pass
        self.assertIn(signal.SIGALRM, masks[0][1])
        self.assertIn(signal.SIGUSR1, masks[0][1])
        self.assertFalse({signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD} & masks[0][1])
        self.assertEqual(masks[-1][0], signal.SIG_SETMASK)

    def test_partial_owned_barrier_is_removed_after_identity_confirmed_cleanup(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        original_write = os.write
        with patch.object(a.os, "write", side_effect=lambda fd, data: original_write(fd, data[:2])):
            with self.assertRaisesRegex(a.OwnedAgentError, "COMMON_CONF_WRITE"):
                backend._barrier(c)
        self.assertIsNotNone(c.common_identity)
        self.assertIsNone(c.common_digest)
        backend.cleanup(c)
        self.assertFalse((self.home / "common.conf").exists())
        self.assertFalse(c.directories)

    def test_unrecorded_created_entry_never_claims_confirmed_cleanup(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        with patch.object(a.os, "fstat", side_effect=KeyboardInterrupt("inert enrollment interruption")):
            with self.assertRaises(KeyboardInterrupt): backend._barrier(c)
        self.assertIsNone(c.common_identity)
        with self.assertRaisesRegex(a.OwnedAgentError, "UNRECORDED_CLEANUP_ENTRY"):
            backend.cleanup(c)
        self.assertTrue((self.home / "common.conf").exists())
        os.fstat(c.home_fd)

    def test_single_assuan_transport_failure_is_coded_without_reconnect(self):
        connection = SimpleNamespace(settimeout=lambda value: None,
            connect=lambda value: (_ for _ in ()).throw(BlockingIOError("inert full backlog")))
        wrapper = unittest.mock.MagicMock()
        wrapper.__enter__.return_value = connection
        with patch.object(a.socket, "socket", return_value=wrapper) as factory:
            with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_READINESS_TRANSPORT"):
                a._assuan(a.BoundAgentPaths(self.home, self.job, self.home / "S.gpg-agent"), 42001)
        self.assertEqual(factory.call_count, 1)

    def test_assuan_absolute_deadline_applies_to_partial_lines(self):
        connection = SimpleNamespace(settimeout=unittest.mock.Mock(),
                                     recv=unittest.mock.Mock(side_effect=[b"O", b"K", b"\n"]))
        with patch.object(a.time, "monotonic", side_effect=[0, 0.5, 1.1]):
            with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_READINESS_TIMEOUT"):
                a._read_response(None, connection=connection, deadline=1)
        self.assertEqual(connection.recv.call_count, 2)
        self.assertEqual([call.args[0] for call in connection.settimeout.call_args_list], [1, 0.5])

    def test_readiness_deadline_and_early_child_exit_are_coded(self):
        c = self.custody()
        backend = a._NativeBackend(self.home, self.job)
        with patch.object(a.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(a.OwnedAgentError, "AGENT_READINESS_TIMEOUT"):
                backend.ready(c)
        with patch.object(a, "_pidfd_exited", return_value=True):
            with self.assertRaisesRegex(a.OwnedAgentError, "STARTUP_CHILD_EXITED"):
                backend.ready(c)

    def test_physical_and_absent_var_run_layouts_check_the_correct_alternatives(self):
        for physical in (True, False):
            metadata = _RuntimeMetadata()
            if physical:
                metadata.info["/var/run"] = SimpleNamespace(st_dev=1, st_ino=20, st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            else:
                del metadata.info["/var/run"]
            with patch.object(a.os, "lstat", side_effect=metadata.lstat), patch.object(a.os, "readlink", side_effect=AssertionError("physical/absent layout must not readlink")):
                layout = a._preflight_external_paths()
            self.assertIsNone(layout.alias_target)
            self.assertEqual(any(path.startswith("/var/run/") for path in metadata.seen), physical)

    def test_prepare_parent_signal_and_thread_preconditions_fail_before_proc_tools(self):
        for case in ("sigchld", "threads"):
            c = a._RetainedCustody()
            with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "pidfd_open", create=True), patch.object(a.signal, "pidfd_send_signal", create=True), patch.object(a.signal, "getsignal", return_value=signal.SIG_IGN if case == "sigchld" else signal.SIG_DFL), patch.object(a.threading, "active_count", return_value=2 if case == "threads" else 1), patch.object(a.os, "listdir", return_value=["one"]), patch.object(a, "_proc_preflight", side_effect=AssertionError("must refuse before proc check")):
                with self.assertRaisesRegex(a.OwnedAgentError, "SIGCHLD_PRECONDITION"):
                    a._NativeBackend(self.home, self.job).prepare(c)
            self.assertFalse(c.directories)

    def test_prepare_rejects_nonempty_home_before_queries_and_postquery_changes(self):
        for before in (True, False):
            c = a._RetainedCustody()
            self.custodies.append(c)
            marker = self.home / "inert-extra-entry"
            if before: marker.write_bytes(b"inert")
            real_listdir = os.listdir
            def listing(path): return ["one"] if path == "/proc/self/task" else real_listdir(path)
            calls = []
            def query(c, argv):
                calls.append(argv)
                if argv[-1] == "--version":
                    return f"{Path(argv[0]).name} (GnuPG) 2.4.9\n".encode()
                records = {"sysconfdir": "/etc/gnupg", "homedir": str(self.home), "socketdir": str(self.home), "agent-socket": str(self.home / "S.gpg-agent")}
                if argv[-1] == "agent-socket": marker.write_bytes(b"inert")
                return (records[argv[-1]] + "\n").encode()
            backend = a._NativeBackend(self.home, self.job)
            with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "pidfd_open", create=True), patch.object(a.signal, "pidfd_send_signal", create=True), patch.object(a.os, "listdir", side_effect=listing), patch.object(a, "_proc_preflight"), patch.object(a, "_preflight_external_paths"), patch.object(a, "_trusted_tool", return_value=("fixture", "hash")), patch.object(a, "_exe", return_value="fixture"), patch.object(backend, "_query", side_effect=query), patch.object(backend, "_allocate", side_effect=AssertionError("must not allocate")):
                with self.assertRaisesRegex(a.OwnedAgentError, "HOME_NOT_EMPTY"):
                    backend.prepare(c)
            self.assertEqual(bool(calls), not before)
            marker.unlink()

    def test_trusted_tool_metadata_refusals_and_mid_hash_change(self):
        path = self.job / "inert-tool-bytes"
        path.write_bytes(b"inert fixture data, never executable")
        for case in ("safe", "symlink", "owner", "writable", "setuid", "capability", "changed"):
            root = SimpleNamespace(st_dev=1, st_ino=1, st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            parent = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            file = SimpleNamespace(st_dev=1, st_ino=3, st_uid=0, st_mode=stat.S_IFREG | 0o755)
            if case == "symlink": parent.st_mode = stat.S_IFLNK | 0o777
            elif case == "owner": file.st_uid = 1000
            elif case == "writable": file.st_mode |= 0o002
            elif case == "setuid": file.st_mode |= 0o4000
            actual_fd = os.open(path, os.O_RDONLY)
            opened = []
            def opening(name, flags):
                self.assertEqual(name, "/trusted/tool")
                result = os.dup(actual_fd)
                opened.append(result)
                return result
            count = 0
            def fstat(fd):
                nonlocal count
                count += 1
                if case == "changed" and count > 1:
                    return SimpleNamespace(**{**file.__dict__, "st_ino": 4})
                return file
            try:
                with patch.object(a.os, "lstat", side_effect=lambda name: {"/": root, "/trusted": parent, "/trusted/tool": file}[str(name)]), patch.object(a.os, "open", side_effect=opening), patch.object(a.os, "fstat", side_effect=fstat), patch.object(a.os, "listxattr", return_value=["security.capability"] if case == "capability" else [], create=True):
                    if case == "safe":
                        recorded, digest = a._trusted_tool("/trusted/tool")
                        self.assertEqual(recorded, a._ident(file))
                        self.assertEqual(digest, a.hashlib.sha256(path.read_bytes()).hexdigest())
                    else:
                        with self.assertRaisesRegex(a.OwnedAgentError, "TOOL_PREFLIGHT_FAILED"):
                            a._trusted_tool("/trusted/tool")
            finally:
                os.close(actual_fd)
            for fd in opened:
                with self.assertRaises(OSError): os.fstat(fd)
    def test_unknown_proc_visibility_retains_custody_even_after_child_reaped(self):
        c = self.custody()
        c.uncertainty = "PROC_VISIBILITY_UNCONFIRMED"
        c.child = SimpleNamespace(pid=42001)
        c.reaped = True
        backend = a._NativeBackend(self.home, self.job)
        with self.assertRaisesRegex(a.OwnedAgentError, "PROC_VISIBILITY_UNCONFIRMED"):
            backend.cleanup(c)
        os.fstat(c.home_fd)

    @unittest.skipUnless(sys.platform == "linux", "Linux-native PID/proc/shim qualification unavailable on Darwin; no native GPG experiment authorized")
    def test_native_qualification_is_outside_fixture_authority(self):
        self.skipTest("native GPG/image/zero-child/PDEATHSIG/keyboxd qualification requires later explicit phase")

    def test_darwin_refuses_before_any_gnupg_invocation(self):
        obj = a.OwnedGpgAgent(self.home, self.job)
        with patch.object(a.sys, "platform", "darwin"), patch.object(a.subprocess, "run", side_effect=AssertionError("native GPG prohibited")), patch.object(a.subprocess, "Popen", side_effect=AssertionError("native launch prohibited")):
            with self.assertRaisesRegex(a.OwnedAgentError, "UNSUPPORTED_PLATFORM"):
                obj.start()
        self.assertTrue(obj.cleanup_confirmed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
