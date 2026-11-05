"""Origin-routing contracts over the actual planning function and byte reader.

Use controlled package bodies, a fixture error type and fixture DEB/path-validation
interfaces. Digests use SHA-256. These component checks do not authenticate source
provenance or establish signing or native qualification.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'tools/verification/current_import_routing.py'


class FixtureRefusal(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(f'[{code}] {message}')


def load_component():
    wanted = {'VERSIONS', 'SYSTEMS', 'ARCH_SYSTEM', 'MAX_PACKAGE',
              'fail', '_stable', 'held_bytes', '_plan_inputs'}
    nodes, found = [], set()
    for node in ast.parse(SOURCE.read_text()).body:
        name = node.name if isinstance(node, ast.FunctionDef) else None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            name = target.id if isinstance(target, ast.Name) else None
        if name in wanted:
            nodes.append(node)
            found.add(name)
    if found != wanted:
        raise AssertionError('Routing component source inventory changed')
    module = types.ModuleType('routing_origin_component')
    module.__dict__.update(Path=Path, os=os, stat=stat, hashlib=hashlib,
        ContractError=FixtureRefusal,
        sha=lambda data: hashlib.sha256(data).hexdigest(),
        parse_deb_control=lambda data: json.loads(data))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), module.__dict__)
    return module


def validate_fixture_path(value):
    if (not isinstance(value, str) or not value or PurePosixPath(value).is_absolute()
            or any(p in {'', '.', '..'} for p in value.split('/'))):
        raise FixtureRefusal('FIXTURE_PATH', 'Unsafe fixture relative path')


def package_name(family, product, version, arch):
    if family == 'deb':
        return f'{product}_{version}-1_{arch}.deb'
    if family == 'rpm':
        return f'{product}-{version}-1.fc43.{arch}.rpm'
    return f'{product}-{version}-1-{arch}.pkg.tar.zst'


class RoutingOriginContracts(unittest.TestCase):
    def setUp(self):
        self.subject = load_component()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        package = types.ModuleType('rs9')
        package.__path__ = []
        security = types.ModuleType('rs9.security')
        security.validate_safe_relative_posix_path = validate_fixture_path
        modules = patch.dict(sys.modules, {'rs9': package, 'rs9.security': security})
        modules.start()
        self.addCleanup(modules.stop)
        self.inventory = {'binaries': self.make_inventory()}

    def make_inventory(self):
        rows = []
        pure = {'theme-forge-stellar-loom', 'theme-forge-solar-sail'}
        independent = {'deb': 'all', 'rpm': 'noarch', 'pacman': 'any'}
        for family in sorted(self.subject.SYSTEMS):
            for product, version in sorted(self.subject.VERSIONS.items()):
                arches = [independent[family]] if product in pure else sorted(self.subject.ARCH_SYSTEM[family])
                for arch in arches:
                    name = package_name(family, product, version, arch)
                    body = json.dumps({'Package': product, 'Version': version + '-1',
                                       'Architecture': arch}, sort_keys=True).encode()
                    systems = self.subject.SYSTEMS[family] if product in pure else {self.subject.ARCH_SYSTEM[family][arch]}
                    prefixes = ['custody-deb/files'] if family == 'deb' else ['unsigned', 'unsigned-custody/files']
                    origins = []
                    for system in sorted(systems):
                        artifact = f'candidate-{family}-{system}'
                        selected_prefixes = (['canonical-any/files']
                            if family == 'pacman' and arch == 'any' and system == 'aarch64-linux'
                            else prefixes)
                        for prefix in selected_prefixes:
                            relative = f'objects/lane-work/{prefix}/{name}'
                            path = self.root / artifact / relative
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(body)
                            origins.append({'artifact': artifact, 'system': system, 'path': relative})
                    rows.append({'family': family, 'product': product, 'name': name,
                                 'version': version, 'architecture': arch, 'size': len(body),
                                 'sha256': hashlib.sha256(body).hexdigest(), 'origins': origins})
        return rows

    def plan(self):
        return self.subject._plan_inputs(self.inventory, self.root)

    def row(self, family, product):
        return next(r for r in self.inventory['binaries']
                    if r['family'] == family and r['product'] == product)

    def refused(self, message=None):
        with self.assertRaises(FixtureRefusal) as caught:
            self.plan()
        if message:
            self.assertIn(message, str(caught.exception))

    def test_distinct_declared_copies_preserve_all_origins(self):
        before = copy.deepcopy(self.inventory)
        plan = self.plan()
        self.assertEqual(self.inventory, before)
        self.assertEqual(len(plan), 18)
        self.assertEqual([row for row, _, _ in plan], before['binaries'])
        self.assertEqual(sum(len(row['origins']) for row, _, _ in plan), 38)

    def test_every_declared_copy_is_read(self):
        with patch.object(self.subject, 'held_bytes', wraps=self.subject.held_bytes) as read:
            self.plan()
        expected = {self.root / o['artifact'] / o['path']
                    for row in self.inventory['binaries'] for o in row['origins']}
        self.assertEqual({Path(c.args[0]) for c in read.call_args_list}, expected)
        self.assertEqual(len(read.call_args_list), 38)

    def test_current_pacman_contains_native_arm_and_shared_any_origins(self):
        rows = [r for r in self.inventory['binaries'] if r['family'] == 'pacman']
        self.assertEqual(len(rows), 6)
        for product in ('theme-forge-stellar-burst', 'theme-forge-nebular-fusion'):
            self.assertEqual({r['architecture'] for r in rows if r['product'] == product},
                             {'x86_64', 'aarch64'})
        for product in ('theme-forge-stellar-loom', 'theme-forge-solar-sail'):
            row = self.row('pacman', product)
            self.assertEqual(row['architecture'], 'any')
            self.assertEqual(len(row['origins']), 3)
            self.assertEqual({o['system'] for o in row['origins']},
                             {'x86_64-linux', 'aarch64-linux'})

    def test_changed_arm_any_origin_refuses(self):
        row = self.row('pacman', 'theme-forge-stellar-loom')
        origins = [o for o in row['origins'] if o['system'] == 'aarch64-linux']
        self.assertEqual(len(origins), 1)
        for origin in origins:
            with self.subTest(path=origin['path']):
                path = self.root / origin['artifact'] / origin['path']
                original = path.read_bytes()
                try:
                    path.write_bytes(b'changed ARM copy')
                    self.refused('Original unsigned package changed')
                finally:
                    path.write_bytes(original)

    def test_arm_any_bytes_cannot_claim_a_second_constructor_path(self):
        row = self.row('pacman', 'theme-forge-stellar-loom')
        origin = next(o for o in row['origins'] if o['system'] == 'aarch64-linux')
        source = self.root / origin['artifact'] / origin['path']
        body = source.read_bytes()
        origin['path'] = 'objects/lane-work/unsigned/' + row['name']
        target = self.root / origin['artifact'] / origin['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        self.refused('second constructor')

    def test_missing_arm_any_origin_refuses(self):
        row = self.row('pacman', 'theme-forge-stellar-loom')
        row['origins'] = [o for o in row['origins'] if o['system'] != 'aarch64-linux']
        self.refused()

    def test_repeated_origin_identity_refuses(self):
        row = self.inventory['binaries'][0]
        row['origins'].append(copy.deepcopy(row['origins'][0]))
        self.refused()

    def test_missing_required_source_system_refuses(self):
        row = self.row('deb', 'theme-forge-solar-sail')
        row['origins'] = [o for o in row['origins'] if o['system'] != 'arm64']
        self.refused()

    def test_wrong_source_system_refuses(self):
        self.inventory['binaries'][0]['origins'][0]['system'] = 'arm64'
        self.refused()

    def test_changed_custody_copy_refuses(self):
        row = self.row('pacman', 'theme-forge-solar-sail')
        origin = row['origins'][1]
        path = self.root / origin['artifact'] / origin['path']
        body = bytearray(path.read_bytes())
        body[0] ^= 1
        path.write_bytes(body)
        self.refused('Original unsigned package changed')

    def test_symlink_custody_copy_refuses(self):
        row = self.row('pacman', 'theme-forge-solar-sail')
        self.assertEqual(len(row['origins']), 3)
        first, second = row['origins'][:2]
        target = self.root / first['artifact'] / first['path']
        path = self.root / second['artifact'] / second['path']
        path.unlink()
        path.symlink_to(target)
        self.refused('Aliased input forbidden')

    def test_missing_product_architecture_refuses(self):
        self.inventory['binaries'] = [r for r in self.inventory['binaries']
            if not (r['family'] == 'rpm' and r['product'] == 'theme-forge-stellar-burst'
                    and r['architecture'] == 'aarch64')]
        self.refused()

    def test_changed_version_refuses(self):
        self.inventory['binaries'][0]['version'] = '0.99.0'
        self.refused()

    def test_repeated_binary_row_refuses(self):
        self.inventory['binaries'].append(copy.deepcopy(self.inventory['binaries'][0]))
        self.refused()


if __name__ == '__main__':
    unittest.main()
