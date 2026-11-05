"""Production client URLs and repository names must resolve the signed deployment layout.

Run with python3 -I -B tests/test_current_signer_client_layout.py --r-root ../r.
The R checkout is read-only. No package manager, container or GPG command runs.
Repository URI projection uses the provider-verified original public member list;
metadata contents are not parsed here and native client gates remain required.
"""
from pathlib import Path, PurePosixPath
import argparse
import copy
from dataclasses import replace
import hashlib
import json
import tempfile
import shutil
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
args = argparse.ArgumentParser()
args.add_argument("--r-root", required=True, type=Path)
options, remaining = args.parse_known_args()
sys.path[:0] = [str(ROOT / "tools/verification/current_signer"), str(options.r_root.resolve() / "src")]
import package_client_qualification as subject
from rs9.hosted_deb import dnf_spec, pacman_spec, _printf_file, DNF_REPO_FILE, DNF_REPO_ID, PACMAN_CONF, SERVER_ROOT

PUBLIC = None
KEYS = None
FIXTURE = ROOT / "tests/fixtures/current-signer-public-layout.json"
FIXTURE_SHA256 = "00f89bab15bd7db5c0e59f1e00ef60d982231fdced326ef95bdad5f811e0c51b"
fixture_raw = FIXTURE.read_bytes()
assert hashlib.sha256(fixture_raw).hexdigest() == FIXTURE_SHA256
fixture = json.loads(fixture_raw)
assert fixture["originalArtifact"] == 13383527253
assert fixture["archiveSha256"] == "c86b61da85811663fa4e7caf3392845fe6621805aaea3f337f7c8ff02079f951"
METADATA = frozenset(fixture["files"])
PRODUCTS = ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion")

def resolve_mounted_file(spec, uri):
    parsed = urlparse(uri)
    if parsed.scheme != "file" or parsed.netloc:
        raise AssertionError("Expected a local, offline repository")
    guest = PurePosixPath(parsed.path)
    matches = []
    for source, target, writable in spec["mounts"]:
        target = PurePosixPath(target)
        if guest.is_relative_to(target):
            if writable:
                raise AssertionError("Repository mount became writable")
            host = Path(source) / str(guest.relative_to(target))
            matches.append(host.relative_to(PUBLIC).as_posix())
    if len(matches) != 1:
        raise AssertionError("Repository path lacks one unambiguous read-only mount")
    return matches[0]

def config_lines(spec):
    # _printf_file emits one already-validated shell printf command.
    return next(command[-1] for command in spec["configure"] if command[:2] == ["sh", "-c"])

class ClientLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global PUBLIC, KEYS
        cls.temporary = tempfile.TemporaryDirectory(prefix="public-client-layout-")
        PUBLIC = Path(cls.temporary.name)
        KEYS = PUBLIC / "keys"
        KEYS.mkdir()
        key = subject.COMMITTED_PUBLIC_KEY_FILENAME
        shutil.copyfile(ROOT / "keys" / key, KEYS / key)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def dnf(self, arch):
        lane = subject.LANE_SPECS["dnf-" + arch]
        return subject.build_production_client_spec(PUBLIC, lane)

    def test_dnf_amd64_metadata_and_signature_are_present(self):
        spec = self.dnf("x86_64")
        for suffix in ("/repodata/repomd.xml", "/repodata/repomd.xml.asc"):
            self.assertIn(resolve_mounted_file(spec, spec["source_uri"] + suffix), METADATA)

    def test_dnf_arm64_metadata_and_signature_are_present(self):
        spec = self.dnf("aarch64")
        for suffix in ("/repodata/repomd.xml", "/repodata/repomd.xml.asc"):
            self.assertIn(resolve_mounted_file(spec, spec["source_uri"] + suffix), METADATA)

    def test_dnf_config_and_observer_agree_without_weakened_checks(self):
        from rs9.dnf_commands import command_base
        for arch in ("x86_64", "aarch64"):
            spec = self.dnf(arch)
            expected = [
                f"[{DNF_REPO_ID}]", "name=RS9 Fedora 43 NONPRODUCTION candidate",
                f"baseurl=file://{SERVER_ROOT}/rpm/fedora/43/{arch}", "enabled=1",
                "gpgcheck=1", "repo_gpgcheck=1", "skip_if_unavailable=False",
                f"gpgkey=file://{SERVER_ROOT}/keys/{subject.COMMITTED_PUBLIC_KEY_FILENAME}",
            ]
            self.assertEqual(spec["configure"], [_printf_file(DNF_REPO_FILE, expected)])
            self.assertEqual(spec["source_uri"], f"file://{SERVER_ROOT}/rpm/fedora/43/{arch}")
            self.assertEqual(spec["refresh"], [*command_base(), "--refresh", "makecache"])

    def test_dnf_changed_shared_profile_still_refused(self):
        def changed(*args, **kwargs):
            value = dnf_spec(*args, **kwargs)
            value["source_uri"] = "file:///different"
            return value
        with patch("rs9.hosted_deb.dnf_spec", side_effect=changed):
            with self.assertRaises(subject.PublicationError) as result:
                self.dnf("x86_64")
        self.assertEqual(result.exception.code, "DNF_SPEC_SHAPE_UNRECOGNIZED")

    def test_pacman_database_and_signature_are_present(self):
        spec = subject.build_production_client_spec(PUBLIC, subject.LANE_SPECS["pacman-x86_64"])
        expected = [
            "[options]", "Architecture = x86_64", "SigLevel = Required DatabaseRequired",
            "[knowledge-forge-ai]", f"Server = file://{SERVER_ROOT}/pacman/$arch",
        ]
        self.assertEqual(spec["configure"], [
            _printf_file(PACMAN_CONF, expected), ["pacman-key", "--init"],
            ["pacman-key", "--add", f"{SERVER_ROOT}/keys/{subject.COMMITTED_PUBLIC_KEY_FILENAME}"],
            ["pacman-key", "--lsign-key", subject.PRODUCTION_PRIMARY_FINGERPRINT],
        ])
        for suffix in ("/knowledge-forge-ai.db", "/knowledge-forge-ai.db.sig"):
            self.assertIn(resolve_mounted_file(spec, f"file://{SERVER_ROOT}/pacman/x86_64" + suffix), METADATA)

    def test_pacman_install_selects_the_authenticated_repository(self):
        spec = subject.adapt_production_pacman_spec(PUBLIC / "arch", KEYS)
        for product in PRODUCTS:
            self.assertEqual(spec["install"](product), ["pacman", "--config", PACMAN_CONF, "-S", "--noconfirm", "--needed", "knowledge-forge-ai/" + product])

    def test_pacman_changed_shared_trust_profile_still_refused(self):
        def changed(*args, **kwargs):
            value = pacman_spec(*args, **kwargs)
            value["configure"] = copy.deepcopy(value["configure"])
            value["configure"][0] = ["false"]
            return value
        with patch("rs9.hosted_deb.pacman_spec", side_effect=changed):
            with self.assertRaises(subject.PublicationError) as result:
                subject.adapt_production_pacman_spec(PUBLIC / "arch", KEYS)
        self.assertEqual(result.exception.code, "PACMAN_SPEC_SHAPE_UNRECOGNIZED")

    def test_shared_helper_selects_actual_production_directories(self):
        for arch in ("x86_64", "aarch64"):
            self.assertEqual(self.dnf(arch)["mounts"][0], (str(PUBLIC / "rpm" / arch), f"{SERVER_ROOT}/rpm/fedora/43/{arch}", False))
        spec = subject.build_production_client_spec(PUBLIC, subject.LANE_SPECS["pacman-x86_64"])
        self.assertEqual(spec["mounts"][0], (str(PUBLIC / "arch"), f"{SERVER_ROOT}/pacman", False))

    def test_dnf_only_changes_architecture_repository_mount(self):
        for arch in ("x86_64", "aarch64"):
            expected = dnf_spec(PUBLIC / "rpm", KEYS, arch, public_fingerprint=subject.PRODUCTION_PRIMARY_FINGERPRINT, public_key_filename=subject.COMMITTED_PUBLIC_KEY_FILENAME)
            actual = self.dnf(arch)
            self.assertEqual(set(expected), set(actual))
            for key in expected:
                if key == "mounts":
                    self.assertEqual(actual[key][1:], expected[key][1:])
                elif callable(expected[key]):
                    for product in (*PRODUCTS, "RS9_PRODUCT"):
                        self.assertEqual(actual[key](product), expected[key](product))
                else:
                    self.assertEqual(actual[key], expected[key])

    def test_package_payloads_and_detached_signatures_resolve(self):
        for arch in ("x86_64", "aarch64"):
            spec = self.dnf(arch)
            prefix = f"rpm/{arch}/"
            packages = sorted(p for p in METADATA if p.startswith(prefix + "Packages/") and p.endswith(".rpm"))
            self.assertEqual(len(packages), 4)
            for name in packages:
                self.assertEqual(resolve_mounted_file(spec, spec["source_uri"] + "/" + name.removeprefix(prefix)), name)
        spec = subject.build_production_client_spec(PUBLIC, subject.LANE_SPECS["pacman-x86_64"])
        packages = sorted(p for p in METADATA if p.startswith("arch/x86_64/") and p.endswith((".pkg.tar.zst", ".pkg.tar.zst.sig")))
        self.assertEqual(len(packages), 8)
        for name in packages:
            self.assertEqual(resolve_mounted_file(spec, f"file://{SERVER_ROOT}/pacman/x86_64/" + name.rsplit("/", 1)[1]), name)

    def test_changed_pacman_install_shape_is_refused_eagerly(self):
        for bad in ("flags", "repository"):
            def changed(*args, **kwargs):
                value = pacman_spec(*args, **kwargs)
                if bad == "flags":
                    value["install"] = lambda pkg: ["pacman", "--nodeps", "-S", "rs9/" + pkg]
                else:
                    value["install"] = lambda pkg: ["pacman", "--config", PACMAN_CONF, "-S", "--noconfirm", "--needed", "other/" + pkg]
                return value
            with self.subTest(shape=bad), patch("rs9.hosted_deb.pacman_spec", side_effect=changed):
                with self.assertRaises(subject.PublicationError) as result:
                    subject.adapt_production_pacman_spec(PUBLIC / "arch", KEYS)
                self.assertEqual(result.exception.code, "PACMAN_SPEC_SHAPE_UNRECOGNIZED")

    def test_unimplemented_pacman_arm64_cannot_select_x86_64(self):
        for arch, platform in (("aarch64", "linux/amd64"), ("x86_64", "linux/arm64"), ("aarch64", "linux/arm64")):
            lane = replace(subject.LANE_SPECS["pacman-x86_64"], arch=arch, platform=platform)
            self.assertEqual(lane.family, "pacman")
            with self.subTest(arch=arch, platform=platform):
                with self.assertRaises(subject.PublicationError) as result:
                    subject.build_production_client_spec(PUBLIC, lane)
                self.assertEqual(result.exception.code, "UNSUPPORTED_CLIENT_LANE")

    def test_non_pacman_dnf_helper_lane_is_refused(self):
        with self.assertRaises(subject.PublicationError) as result:
            subject.build_production_client_spec(PUBLIC, subject.LANE_SPECS["apt-amd64"])
        self.assertEqual(result.exception.code, "UNSUPPORTED_CLIENT_LANE")

if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *remaining])
