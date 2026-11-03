"""Fresh GitHub CLI transport privacy and fail-closed configuration contract."""
import importlib.util, pathlib, sys, os, tempfile, stat, unittest
from unittest import mock
SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'tools/verification/current_signer/publication_github_api.py'
spec = importlib.util.spec_from_file_location('publication_api_parent_telemetry_test', SOURCE)
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)

class TransportPrivacyContract(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.token = 'PUBLIC-UNIT-FIXTURE-NOT-A-CREDENTIAL'

    def tearDown(self):
        self.tmp.cleanup()

    def construct(self):
        return api.GhApiTransport(self.token, str(self.root / 'transport'))

    def test_exact_private_noncredential_config(self):
        transport = self.construct()
        p = pathlib.Path(transport._config) / 'config.yml'
        self.assertEqual(p.read_bytes(), b'telemetry: disabled\n')
        st = p.lstat()
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 384)
        self.assertEqual(st.st_uid, os.geteuid())
        self.assertEqual(st.st_nlink, 1)
        self.assertNotIn(self.token.encode(), p.read_bytes())
        self.assertEqual(list(p.parent.iterdir()), [p])

    def test_contract_under_restrictive_umask(self):
        prior = os.umask(511)
        try:
            transport = self.construct()
        finally:
            os.umask(prior)
        self.assertEqual(stat.S_IMODE((pathlib.Path(transport._config) / 'config.yml').stat().st_mode), 384)

    def test_child_environment_and_api_are_unchanged(self):
        transport = self.construct()
        env = transport.child_env()
        self.assertEqual(set(env), {'PATH', 'LANG', 'LC_ALL', 'HOME', 'GH_CONFIG_DIR', 'GH_HOST', 'GH_TOKEN', 'GH_PROMPT_DISABLED', 'GH_NO_UPDATE_NOTIFIER', 'NO_COLOR'})
        self.assertEqual(env['GH_TOKEN'], self.token)
        self.assertEqual(env['HOME'], env['GH_CONFIG_DIR'])
        self.assertEqual(env['PATH'], '/usr/bin:/bin')
        self.assertEqual(api.GH_BINARY, '/usr/bin/gh')
        self.assertEqual(transport.argv('PUBLIC-PATH')[0:4], ('/usr/bin/gh', 'api', '--method', 'GET'))

    def preoccupied(self, kind):
        original = api._new_private_dir
        target = self.root / 'outside-fixture'
        target.write_bytes(b'PUBLIC-PRESERVED-FIXTURE')

        def make(path):
            result = original(path)
            if pathlib.Path(path).name == 'gh-config':
                config = pathlib.Path(path) / 'config.yml'
                if kind == 'regular':
                    config.write_bytes(b'PUBLIC-OCCUPIED-FIXTURE')
                elif kind == 'symlink':
                    config.symlink_to(target)
                elif kind == 'directory':
                    config.mkdir(mode=448)
            return result
        with mock.patch.object(api, '_new_private_dir', side_effect=make):
            with self.assertRaises(api.PublicationError):
                self.construct()
        self.assertEqual(target.read_bytes(), b'PUBLIC-PRESERVED-FIXTURE')
        config = self.root / 'transport/gh-config/config.yml'
        if kind == 'regular':
            self.assertEqual(config.read_bytes(), b'PUBLIC-OCCUPIED-FIXTURE')
        elif kind == 'symlink':
            self.assertTrue(config.is_symlink())
        else:
            self.assertTrue(config.is_dir())

    def test_occupied_config_is_not_overwritten(self):
        self.preoccupied('regular')

    def test_config_symlink_is_not_followed(self):
        self.preoccupied('symlink')

    def test_config_directory_is_not_replaced(self):
        self.preoccupied('directory')

    def test_short_writes_complete_fixed_config(self):
        original = api.os.write

        def short(fd, data):
            return original(fd, data[:1])
        with mock.patch.object(api.os, 'write', side_effect=short):
            transport = self.construct()
        self.assertEqual((pathlib.Path(transport._config) / 'config.yml').read_bytes(), b'telemetry: disabled\n')

    def test_zero_write_refuses_and_closes_fd(self):
        original = api.os.close
        with mock.patch.object(api.os, 'write', return_value=0), mock.patch.object(api.os, 'close', wraps=original) as close:
            with self.assertRaises(api.PublicationError) as caught:
                self.construct()
        self.assertEqual(caught.exception.code, 'TRANSPORT_CONFIG_WRITE')
        close.assert_called_once()

    def test_write_failure_is_sanitized_and_fd_closed(self):
        original = api.os.close
        with mock.patch.object(api.os, 'write', side_effect=OSError('PRIVATE-DIAGNOSTIC-MUST-NOT-ESCAPE')), mock.patch.object(api.os, 'close', wraps=original) as close:
            with self.assertRaises(api.PublicationError) as caught:
                self.construct()
        self.assertEqual(caught.exception.code, 'TRANSPORT_CONFIG_WRITE')
        self.assertNotIn('PRIVATE-DIAGNOSTIC', str(caught.exception))
        close.assert_called_once()

    def test_metadata_failure_is_sanitized_and_fd_closed(self):
        original = api.os.close
        with mock.patch.object(api.os, 'fstat', side_effect=OSError('PRIVATE-DIAGNOSTIC-MUST-NOT-ESCAPE')), mock.patch.object(api.os, 'close', wraps=original) as close:
            with self.assertRaises(api.PublicationError) as caught:
                self.construct()
        self.assertEqual(caught.exception.code, 'TRANSPORT_CONFIG_WRITE')
        self.assertNotIn('PRIVATE-DIAGNOSTIC', str(caught.exception))
        close.assert_called_once()
if __name__ == '__main__':
    unittest.main(verbosity=2)
