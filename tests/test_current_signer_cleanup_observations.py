"""Fixed cleanup observations: behavior preservation and bounded public output."""
import ast
import contextlib
import errno
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
import sys
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/verification/current_signer"))
import runtime_workflow_bridge as bridge

SOURCE = ROOT / "tests/fixtures/current_signer_cleanup_baseline.py"
node = next(n for n in ast.parse(SOURCE.read_text()).body
            if isinstance(n, ast.FunctionDef) and n.name == "_cleanup_owned_tree")
namespace = {"Path": Path, "os": os, "stat": stat}
exec(compile(ast.Module(body=[node], type_ignores=[]), "<original-cleanup>", "exec"), namespace)
original_cleanup = namespace["_cleanup_owned_tree"]
ALLOWED = {"transport", "quarantine", "build"}

def layout(root):
    root.mkdir()
    for name in sorted(ALLOWED):
        (root / name).mkdir()
    (root / "transport/gh-config").mkdir()
    for name in ("metadata-0001.bin", "metadata-0002.bin", "archive-0003.bin",
                 "metadata-0004.bin", "metadata-0005.bin"):
        (root / "transport" / name).write_bytes(b"public fixture")
    for index in range(30):
        (root / "quarantine" / (str(index) + ".rpm")).write_bytes(b"public rpm fixture")

def snapshot(root):
    if not root.exists():
        return None
    rows = {}
    for path in root.rglob("*"):
        info = path.lstat()
        kind = stat.S_IFMT(info.st_mode)
        rows[path.relative_to(root).as_posix()] = (
            kind, stat.S_IMODE(info.st_mode), info.st_nlink,
            path.read_bytes() if stat.S_ISREG(info.st_mode) else None,
        )
    return rows

class CleanupObservationTests(unittest.TestCase):
    def test_real_transport_shape_and_thirty_archives_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "owned"
            layout(root)
            details = []
            self.assertTrue(bridge._cleanup_owned_tree(root, ALLOWED, failure_sink=details))
            self.assertEqual(details, [])
            self.assertFalse(root.exists())

    def test_failure_decisions_and_remaining_bytes_match_original(self):
        cases = {
            "foreign_root": ("ROOT_ENTRIES", "ROOT"),
            "build_directory": ("NESTED_DIRECTORY", "BUILD"),
            "transport_directory": ("NESTED_DIRECTORY", "TRANSPORT"),
            "gh_config_directory": ("GH_CONFIG_NOT_REGULAR", "GH_CONFIG"),
            "gh_config_symlink": ("GH_CONFIG_NOT_REGULAR", "GH_CONFIG"),
            "transport_symlink": ("CHILD_SYMLINK", "TRANSPORT"),
            "hardlink": ("CHILD_LINK_COUNT", "QUARANTINE"),
            "fifo": ("CHILD_SPECIAL_FILE", "QUARANTINE"),
        }
        for case, expected in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                roots = [Path(temporary) / name for name in ("old", "new")]
                for root in roots:
                    layout(root)
                    private_name = "INPUT_NAME_MUST_NOT_BE_REPORTED"
                    if case == "foreign_root":
                        (root / private_name).write_bytes(b"keep")
                    elif case == "build_directory":
                        (root / "build" / private_name).mkdir()
                    elif case == "transport_directory":
                        (root / "transport" / private_name).mkdir()
                    elif case == "gh_config_directory":
                        (root / "transport/gh-config" / private_name).mkdir()
                    elif case == "gh_config_symlink":
                        (root / "transport/gh-config" / private_name).symlink_to("../../metadata-0001.bin")
                    elif case == "transport_symlink":
                        (root / "transport" / private_name).symlink_to("metadata-0001.bin")
                    elif case == "hardlink":
                        os.link(root / "quarantine/0.rpm", root / "quarantine" / private_name)
                    elif case == "fifo":
                        os.mkfifo(root / "quarantine" / private_name)
                details = []
                self.assertFalse(original_cleanup(roots[0], ALLOWED))
                self.assertFalse(bridge._cleanup_owned_tree(roots[1], ALLOWED, failure_sink=details))
                self.assertEqual(snapshot(roots[0]), snapshot(roots[1]))
                self.assertEqual(len(details), 1)
                self.assertEqual((details[0]["category"], details[0]["scope"]), expected)
                self.assertNotIn("INPUT_NAME", repr(details))

    def test_foreign_owner_labels_at_each_scope_preserve_original_behavior(self):
        cases = {
            ".": ("ROOT_FOREIGN_OWNER", "ROOT"),
            "build": ("SUBDIR_FOREIGN_OWNER", "BUILD"),
            "quarantine/0.rpm": ("CHILD_FOREIGN_OWNER", "QUARANTINE"),
            "transport/gh-config/config.yml": ("GH_CONFIG_FOREIGN_OWNER", "GH_CONFIG"),
        }
        real_lstat = os.lstat
        for selected, expected in cases.items():
            with self.subTest(scope=selected), tempfile.TemporaryDirectory() as temporary:
                roots = [Path(temporary) / name for name in ("old", "new")]
                outcomes, details = [], []
                for index, root in enumerate(roots):
                    layout(root)
                    (root / "transport/gh-config/config.yml").write_bytes(b"public config fixture")
                    target = root if selected == "." else root / selected
                    def foreign_owner(path, *args, **kwargs):
                        info = real_lstat(path, *args, **kwargs)
                        if Path(path) == target:
                            fields = list(info)
                            fields[4] = info.st_uid + 1
                            return os.stat_result(fields)
                        return info
                    with mock.patch.object(os, "lstat", side_effect=foreign_owner):
                        outcomes.append(
                            original_cleanup(root, ALLOWED) if index == 0 else
                            bridge._cleanup_owned_tree(root, ALLOWED, failure_sink=details)
                        )
                self.assertEqual(outcomes, [False, False])
                self.assertEqual(snapshot(roots[0]), snapshot(roots[1]))
                self.assertEqual((details[0]["category"], details[0]["scope"]), expected)

    def test_oserror_reports_operation_and_closed_errno(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "owned"
            layout(root)
            details = []
            with mock.patch.object(os, "unlink", side_effect=PermissionError(errno.EACCES, "PRIVATE ERROR TEXT")):
                self.assertFalse(bridge._cleanup_owned_tree(root, ALLOWED, failure_sink=details))
            self.assertEqual(details, [{
                "category": "FILESYSTEM", "scope": "QUARANTINE",
                "operation": "UNLINK", "errno": "EACCES",
            }])
            self.assertNotIn("PRIVATE", repr(details))

    def run_main(self, observation):
        error = bridge.RuntimeBridgeError("WORK_ROOT_CLEANUP_FAILED",
                                          custody_retained=True,
                                          cleanup_observation=observation)
        stderr = io.StringIO()
        with mock.patch.object(bridge, "execute_prepare_image", side_effect=error), contextlib.redirect_stderr(stderr):
            result = bridge.main([
                "prepare-image", "--p-root", "/fixture/p", "--r-root", "/fixture/r",
                "--binding-file", "/fixture/binding", "--work-root", "/fixture/work",
                "--image-receipt", "/fixture/receipt", "--github-output", "/fixture/output",
            ])
        return result, stderr.getvalue()

    def test_cli_retains_failure_and_reports_only_closed_labels(self):
        observation = {"category": "GH_CONFIG_NOT_REGULAR", "scope": "GH_CONFIG",
                       "operation": "LSTAT", "errno": "NONE"}
        result, output = self.run_main(observation)
        self.assertEqual(result, 2)
        self.assertEqual(output, (
            "REFUSED WORK_ROOT_CLEANUP_FAILED\n"
            "WORK_ROOT_CLEANUP CATEGORY=GH_CONFIG_NOT_REGULAR SCOPE=GH_CONFIG OPERATION=LSTAT ERRNO=NONE\n"
            "BRIDGE_CUSTODY_RETAINED\n"
        ))

    def test_invalid_or_private_observation_never_reaches_cli(self):
        for observation in [
            {"category": "/" + "private" + "/input", "scope": "GH_CONFIG", "operation": "LSTAT", "errno": "NONE"},
            {"category": "FILESYSTEM", "scope": "ROOT", "operation": "LSTAT", "errno": "secret"},
            {"category": "ROOT_ENTRIES", "scope": "ROOT", "operation": "LISTDIR", "errno": "NONE",
             "path": "/" + "private" + "/input"},
        ]:
            with self.subTest(observation=observation):
                result, output = self.run_main(observation)
                self.assertEqual(result, 2)
                self.assertEqual(output, "REFUSED WORK_ROOT_CLEANUP_FAILED\nBRIDGE_CUSTODY_RETAINED\n")

if __name__ == "__main__":
    unittest.main()
