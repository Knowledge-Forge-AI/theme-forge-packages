"""Exercise the real isolated bootstrap without keys, network or native execution."""
from pathlib import Path
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
IMPORTER = Path('tools/verification/current_import_routing.py')
MANIFEST = Path('tools/verification/current_signer/leaf-manifest.json')
MODES = ('runtime', 'host', 'worker', 'client', 'publish')
ISOLATION = Path('tools/verification/isolation_probe/current_signer_isolation_probe.py')
QUALIFY = Path('.github/workflows/qualify-current-signer.yml')
PUBLISH = Path('.github/workflows/publish.yml')
GUI = Path('.github/workflows/validate.yml')


def assignment(path, name):
    matches = [node.value for node in ast.parse(path.read_text()).body
               if isinstance(node, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)]
    if len(matches) != 1:
        raise AssertionError('Expected exactly one fixed pin assignment')
    return matches[0]


def workflow_pin(path, name):
    # Read only the current workflows' fixed scalar pins; this is not a YAML parser.
    matches = re.findall(r'^[ \t]*' + re.escape(name)
                         + r':[ \t]*"([0-9a-f]{64})"[ \t]*$',
                         path.read_text(), re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError('Expected exactly one fixed workflow pin')
    return matches[0]


class IsolatedBootstrapTests(unittest.TestCase):
    def invoke(self, root, mode='runtime', *, isolated=True):
        flags = ['-I', '-B'] if isolated else ['-E', '-s', '-B']
        return subprocess.run(
            [sys.executable, *flags, str(root / IMPORTER),
             '--current-signer-' + mode, '--help'],
            env={'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C'},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15, check=False)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        manifest = json.loads((ROOT / MANIFEST).read_bytes())
        for relative in [str(IMPORTER), str(MANIFEST), *manifest['files']]:
            path = Path(relative)
            self.assertFalse(path.is_absolute())
            self.assertNotIn('..', path.parts)
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        return root

    def assert_refused(self, result, code):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr.strip(), code.encode('ascii'))

    def test_all_real_entry_points_authenticate_the_committed_closure(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                result = self.invoke(ROOT, mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b'usage:', result.stdout.lower())
                self.assertEqual(result.stderr, b'')

    def test_runtime_plan_parser_is_reached_without_executing_a_plan(self):
        result = subprocess.run(
            [sys.executable, '-I', '-B', str(ROOT / IMPORTER),
             '--current-signer-runtime', 'plan', '--help'],
            env={'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C'},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--binding-out', result.stdout)
        self.assertEqual(result.stderr, b'')

    def test_missing_isolation_flag_is_rejected(self):
        self.assert_refused(self.invoke(ROOT, isolated=False), 'SIGNER_BOOTSTRAP_FLAGS')

    def test_current_manifest_pins_match_the_committed_manifest(self):
        expected = hashlib.sha256((ROOT / MANIFEST).read_bytes()).hexdigest()
        pins = {
            'bootstrap': ast.literal_eval(assignment(ROOT / IMPORTER, 'LEAF_MANIFEST_SHA256')),
            'isolation': ast.literal_eval(assignment(ROOT / ISOLATION, 'PINNED_LEAF_MANIFEST_SHA256')),
            'qualification': workflow_pin(ROOT / QUALIFY, 'LEAF_MANIFEST_SHA256'),
            'publication': workflow_pin(ROOT / PUBLISH, 'LEAF_MANIFEST_SHA256'),
        }
        for source, value in pins.items():
            with self.subTest(source=source):
                self.assertEqual(value, expected)

    def test_publication_workflow_pins_match_the_actual_workflows(self):
        for name, relative in [('QUALIFY_WORKFLOW_SHA256', QUALIFY),
                               ('GUI_WORKFLOW_SHA256', GUI)]:
            with self.subTest(name=name):
                self.assertEqual(workflow_pin(ROOT / PUBLISH, name),
                                 hashlib.sha256((ROOT / relative).read_bytes()).hexdigest())

    def test_isolation_source_pins_match_the_real_entry_sources(self):
        pins = assignment(ROOT / ISOLATION, 'PRODUCTION_PINS')
        self.assertIsInstance(pins, ast.Dict)
        for relative in [IMPORTER, QUALIFY]:
            with self.subTest(path=str(relative)):
                matches = [ast.literal_eval(value) for key, value in zip(pins.keys, pins.values)
                           if isinstance(key, ast.Constant) and key.value == str(relative)]
                self.assertEqual(matches, [hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()])

    def test_changed_manifest_is_rejected_before_entry(self):
        root = self.fixture()
        path = root / MANIFEST
        path.write_bytes(path.read_bytes() + b'\n')
        self.assert_refused(self.invoke(root), 'SIGNER_BOOTSTRAP_MANIFEST_PIN')

    def test_changed_leaf_is_rejected_after_authenticating_manifest(self):
        root = self.fixture()
        path = root / 'tools/verification/current_signer/runtime_workflow_bridge.py'
        path.write_bytes(path.read_bytes() + b'\n')
        self.assert_refused(self.invoke(root), 'SIGNER_BOOTSTRAP_LEAF_PIN')

    def test_symlinked_manifest_is_rejected(self):
        root = self.fixture()
        path = root / MANIFEST
        real = path.with_name('original-manifest.json')
        path.rename(real)
        path.symlink_to(real.name)
        self.assert_refused(self.invoke(root), 'SIGNER_BOOTSTRAP_SYMLINK')


if __name__ == '__main__':
    unittest.main()
