"""Pure and real-filesystem checks. Native tools and Docker are replaced explicitly."""
from pathlib import Path
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import types
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

P_ROOT = Path(__file__).resolve().parents[1]
PROBE = P_ROOT / "tools/verification/rpm_metadata_probe"
spec = importlib.util.spec_from_file_location("rpm_probe_entry", PROBE / "entry.py")
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
PROFILE = entry.load_bundle(PROBE)
import tf_rpm_probe_core as core
import tf_rpm_probe_inputs as inputs
import tf_rpm_probe_host as host
runtime, metadata = entry.runtime_modules(P_ROOT)


def small_metadata(repo, packages, variant="valid"):
    """Small RPM-MD test data; the real production parser remains the subject."""
    digest = lambda body: hashlib.sha256(body).hexdigest()
    primary = []
    other = []
    for name, body in packages.items():
        checksum = digest(body)
        primary.append(
            '<package type="rpm"><name>fixture</name><arch>noarch</arch><version ver="1"/>'
            '<checksum type="sha256" pkgid="YES">' + checksum + '</checksum>'
            '<size package="' + str(len(body)) + '"/><location href="Packages/' + name + '"/></package>')
        other.append('<package pkgid="' + checksum + '"/>')
    definitions = {
        "primary": ("http://linux.duke.edu/metadata/common", "metadata", "".join(primary)),
        "filelists": ("http://linux.duke.edu/metadata/filelists", "filelists", "".join(other)),
        "other": ("http://linux.duke.edu/metadata/other", "otherdata", "".join(other)),
    }
    repodata = repo / "repodata"
    repodata.mkdir(mode=0o700)
    records = []
    for kind, (namespace, root, content) in definitions.items():
        xml = ('<' + root + ' xmlns="' + namespace + '" packages="' + str(len(packages)) + '">'
               + content + '</' + root + '>').encode()
        if variant == "grammar" and kind == "primary":
            xml = b"<invalid/>"
        compressed = gzip.compress(xml, mtime=0)
        name = digest(compressed) + "-" + kind + ".xml.gz"
        (repodata / name).write_bytes(compressed)
        records.append(
            '<data type="' + kind + '"><checksum type="sha256">' + digest(compressed)
            + '</checksum><open-checksum type="sha256">' + digest(xml)
            + '</open-checksum><location href="repodata/' + name + '"/><size>'
            + str(len(compressed)) + '</size><open-size>' + str(len(xml)) + '</open-size></data>')
    (repodata / "repomd.xml").write_text(
        '<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>'
        + "".join(records) + '</repomd>')
    if variant == "inventory":
        (repodata / "unexpected").write_bytes(b"public")
    if variant == "mutation":
        (repo / "Packages" / next(iter(packages))).write_bytes(b"changed")


class CreatorStub:
    def __init__(self, packages, variant="valid", exit_code=0, stderr=b""):
        self.packages, self.variant = packages, variant
        self.exit_code, self.stderr, self.calls = exit_code, stderr, []

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.exit_code == 0:
            small_metadata(Path(argv[-1]), self.packages, self.variant)
        return runtime.ProcessResult(self.exit_code, b"PRIVATE_CANARY_NEVER_FORWARD", self.stderr)


class MetadataBoundaryTests(unittest.TestCase):
    def execute(self, *, variant="valid", exit_code=0, stderr=b""):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            packages = {"fixture-1.noarch.rpm": b"public-RPM-test-bytes"}
            runner = CreatorStub(packages, variant, exit_code, stderr)
            case = {"architecture": "x86_64", "inputClass": "unsigned"}
            with patch.object(runtime.ProtectedSigningRuntime, "__init__", side_effect=AssertionError("NO_SIGNER")):
                result = core.run_one(case, packages, work, runtime, metadata, runner)
            core.validate_result(result)
            return result, runner.calls

    def test_real_filesystem_and_production_parser_accept_valid_creator_output(self):
        result, calls = self.execute()
        self.assertTrue(result["metadataAccepted"])
        self.assertEqual((result["stage"], result["code"]), ("DONE", "NONE"))
        self.assertEqual(len(calls), 1)

    def test_only_exact_creator_tool_flags_and_empty_input_are_requested(self):
        _, calls = self.execute()
        argv, kwargs = calls[0]
        self.assertEqual(argv[:-1], ("/usr/bin/createrepo_c", "--general-compress-type", "gz",
                                    "--no-database", "-s", "sha256"))
        self.assertEqual(kwargs["stdin"], b"")
        self.assertEqual(kwargs["phase"], "rpm-metadata-create")
        self.assertEqual(set(kwargs["env"]), {"HOME", "GNUPGHOME", "PATH", "LANG", "LC_ALL", "TMPDIR"})
        self.assertEqual({k:v for k,v in kwargs["env"].items() if k != "TMPDIR"},
                         runtime.ProtectedSigningRuntime._env(None, Path(kwargs["env"]["HOME"])))
        self.assertEqual(Path(kwargs["env"]["TMPDIR"]).name, "metadata-tmp-rpm-x86_64")

    def test_tool_nonzero_is_distinct_from_metadata_refusal(self):
        result, _ = self.execute(exit_code=1, stderr=b"signature public key rejected")
        self.assertEqual((result["stage"], result["code"], result["stderrMarker"]),
                         ("TOOL", "COMMAND_FAILED", "RPM_SIGNATURE_POLICY"))
        self.assertNotIn("PRIVATE_CANARY_NEVER_FORWARD", json.dumps(result))

    def test_real_metadata_grammar_refusal_is_reported(self):
        result, _ = self.execute(variant="grammar")
        self.assertEqual((result["stage"], result["code"]), ("METADATA", "REPOSITORY_METADATA"))

    def test_extra_metadata_members_are_refused(self):
        result, _ = self.execute(variant="inventory")
        self.assertEqual(result["code"], "OUTPUT_INVENTORY")
        self.assertFalse(result["metadataAccepted"])

    def test_known_package_bytes_are_not_allowed_to_change(self):
        result, _ = self.execute(variant="mutation")
        self.assertEqual((result["stage"], result["code"]), ("PRESERVATION", "PACKAGE_MUTATED"))

    def test_typed_tool_exceptions_keep_only_fixed_codes(self):
        case = {"architecture": "x86_64", "inputClass": "unsigned"}
        for code in ("COMMAND_TIMEOUT", "COMMAND_OUTPUT_LIMIT", "COMMAND_CLEANUP"):
            runner = types.SimpleNamespace(run=lambda *a, **k: (_ for _ in ()).throw(
                runtime.ProtectedSigningError(code, "PRIVATE_CANARY_NEVER_FORWARD")))
            with tempfile.TemporaryDirectory() as temp:
                result = core.run_one(case, {"fixture.rpm": b"public"}, Path(temp),
                                      runtime, metadata, runner)
            self.assertEqual(result["code"], code)
            self.assertNotIn("PRIVATE_CANARY_NEVER_FORWARD", json.dumps(result))

    def test_stderr_marker_is_fixed_and_ambiguous_matches_collapse(self):
        for body, expected in [(b"UNKNOWN PRIVATE_CANARY", "UNCLASSIFIED"),
                               (b"permission denied", "PERMISSION"),
                               (b"error while loading shared libraries", "SHARED_LIBRARY"),
                               (b"unknown option", "OPTION"),
                               (b"cannot create lock", "LOCK"),
                               (b"signature permission denied", "UNCLASSIFIED")]:
            self.assertEqual(core.marker(body, 1), expected)
        self.assertEqual(core.marker(b"signature PRIVATE_CANARY", 0), "NONE")

    def test_size_buckets_do_not_retain_exact_sizes(self):
        for size, expected in [(0, "ZERO"), (1, "UP_TO_4K"), (4096, "UP_TO_4K"),
                               (4097, "UP_TO_64K"), (65536, "UP_TO_64K"),
                               (65537, "UP_TO_256K")]:
            self.assertEqual(core.size_bucket(size), expected)

    def test_result_rejects_extra_keys_unknown_values_and_false_acceptance(self):
        result, _ = self.execute()
        for key, value in [("extra", "PRIVATE_CANARY"), ("code", "UNLISTED"),
                           ("stage", "BAD"), ("inputClass", "private"),
                           ("toolExit", "NONZERO"), ("metadataAccepted", 1),
                           ("stage", []), ("metadataAccepted", False)]:
            changed = {**result, key: value}
            with self.assertRaises((ValueError, TypeError)):
                core.validate_result(changed)

    def test_held_file_refuses_links_and_oversized_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "body").write_bytes(b"public")
            (root / "link").symlink_to(root / "body")
            for path, bound in [(root / "link", 100), (root / "body", 2)]:
                with self.assertRaises(ValueError):
                    core.held_file(path, bound)

    def test_duplicate_fields_and_nonfinite_json_are_refused(self):
        for value in [b'{"stage":"DONE","stage":"TOOL"}', b'{"value":NaN}', b'{"value":Infinity}']:
            with self.assertRaises(ValueError):
                core.strict_json(value)


def synthetic_profile():
    profile = copy.deepcopy(PROFILE)
    for index, case in enumerate(profile["cases"]):
        case["artifactId"] = 1 if case["architecture"] == "x86_64" else 2
        for item in case["packages"]:
            body = ("public-" + str(index) + item["name"]).encode()
            item.update(bytes=len(body), sha256=core.sha(body))
    profile["artifacts"] = [
        {"id": number, "name": "candidate-rpm-" + arch + "-linux"}
        for number, arch in [(1, "x86_64"), (2, "aarch64")]
    ] + [{"id": i, "name": "unused"} for i in range(3, 13)]
    return profile


def synthetic_zip(cases):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for index, case in enumerate(cases):
            original_index = (0 if case["architecture"] == "x86_64" else 2) + (
                0 if case["inputClass"] == "unsigned" else 1)
            for item in case["packages"]:
                info = zipfile.ZipInfo(item["member"])
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, ("public-" + str(original_index) + item["name"]).encode())
    return buffer.getvalue()


class InputBoundaryTests(unittest.TestCase):
    def test_real_original_profile_has_four_cases_and_two_exact_artifacts(self):
        self.assertIs(inputs.validate_profile(PROFILE), PROFILE)
        self.assertEqual(len(inputs.selected_artifacts(PROFILE)), 2)

    def test_modified_coordinates_case_order_or_path_are_refused(self):
        for change in ("RCommit", "RRun", "order", "member", "hash", "count"):
            profile = copy.deepcopy(PROFILE)
            if change == "RCommit":
                profile["RCommit"] = "0" * 40
            elif change == "RRun":
                profile["RRun"] += 1
            elif change == "order":
                profile["cases"].reverse()
            elif change == "member":
                profile["cases"][0]["packages"][0]["member"] = "../private"
            elif change == "hash":
                profile["cases"][0]["packages"][0]["sha256"] = "not-a-hash"
            else:
                profile["cases"][0]["packages"].pop()
            with self.assertRaises(ValueError):
                inputs.validate_profile(profile)

    def test_original_zip_digest_precedes_members_and_payload_admission(self):
        profile = synthetic_profile()
        cases = profile["cases"][:2]
        raw = synthetic_zip(cases)
        artifact = {"size_in_bytes": len(raw), "digest": "sha256:" + core.sha(raw)}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);target = root / "original.zip";target.write_bytes(raw)
            destination = root / "inputs";destination.mkdir(mode=0o700)
            inputs.admit_zip(target, artifact, cases, destination)
            self.assertEqual(len(list(destination.iterdir())), 8)
            self.assertEqual(len(core.public_packages(cases[0], destination)), 4)
            with self.assertRaises(ValueError):
                inputs.admit_zip(target, {**artifact, "digest": "sha256:" + "0" * 64}, cases, destination)

    def test_missing_package_hash_tampering_and_existing_foreign_link_refuse(self):
        profile = synthetic_profile()
        item = profile["cases"][0]["packages"][0]
        body = ("public-0" + item["name"]).encode()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                inputs.write_package(root, b"wrong", item)
            (root / "foreign").write_bytes(body)
            (root / (item["sha256"] + ".rpm")).symlink_to(root / "foreign")
            with self.assertRaises(ValueError):
                inputs.write_package(root, body, item)


class ContainerEntryTests(unittest.TestCase):
    def observe(self, variant="valid", exit_code=0):
        profile = synthetic_profile()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);workspace = root / "workspace";workspace.mkdir(mode=0o700)
            destination = root / "inputs";destination.mkdir(mode=0o700)
            creators = []
            for index, case in enumerate(profile["cases"]):
                for item in case["packages"]:
                    inputs.write_package(destination, ("public-" + str(index) + item["name"]).encode(), item)
                packages = core.public_packages(case, destination)
                creators.append(CreatorStub(packages, variant if index == 0 else "valid",
                                            exit_code if index == 0 else 0))
            mapping = {"/work/workspace": workspace, "/work/inputs": destination, "/work/p": P_ROOT}
            tool = {"status": "MEASURED", "path": "/usr/bin/createrepo_c", "bytes": 100,
                    "sha256": "a" * 64, "versionObserved": False}
            with patch.object(entry.sys, "platform", "linux"), \
                    patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=True), \
                    patch.object(entry, "Path", side_effect=lambda p: mapping[str(p)]), \
                    patch.object(entry, "runtime_modules", return_value=(runtime, metadata)), \
                    patch.object(core, "binary_identity", return_value=tool), \
                    patch.object(runtime, "NativeProtectedProcessRunner", side_effect=creators) as factory:
                result = entry.container_observation(profile)
            return result, factory.call_count

    def test_container_body_runs_four_fixed_cases_through_real_filesystem_and_validator(self):
        result, count = self.observe()
        self.assertEqual(count, 4)
        self.assertTrue(all(r["metadataAccepted"] for r in result["cases"]))
        self.assertFalse(result["privateKeyAccess"])
        self.assertFalse(result["signingPerformed"])

    def test_command_refusal_continues_independent_public_cases(self):
        result, count = self.observe(exit_code=1)
        self.assertEqual(count, 4)
        self.assertEqual(result["cases"][0]["code"], "COMMAND_FAILED")

    def test_inventory_uncertainty_stops_later_cases_conservatively(self):
        result, count = self.observe(variant="inventory")
        self.assertEqual(count, 1)
        self.assertEqual(result["cases"][0]["code"], "OUTPUT_INVENTORY")

    def test_disallowed_signer_modules_cannot_be_imported(self):
        with self.assertRaises(ImportError):
            __import__("detached_signature_adapter")

    def test_main_returns_only_closed_refusal_for_an_invalid_source_digest(self):
        env = {k:v for k,v in os.environ.items() if k in {"PATH", "LANG", "LC_ALL", "TMPDIR"}}
        result = subprocess.run([sys.executable, "-I", "-B", str(PROBE / "entry.py"),
                                 "--container", "--expected-entry-sha256", "PRIVATE_CANARY"],
                                env=env, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["code"], "ENTRY_REFUSED")
        self.assertNotIn(b"PRIVATE_CANARY", result.stdout + result.stderr)

    def test_measured_tool_record_and_impossible_result_states_are_refused(self):
        valid = {"status": "MEASURED", "path": "/usr/bin/createrepo_c", "bytes": 100,
                 "sha256": "a" * 64, "versionObserved": False}
        self.assertIs(core.validate_tool(valid), valid)
        for key,value in [("path","/private"),("sha256","bad"),("bytes",0),("versionObserved",True)]:
            with self.assertRaises(ValueError):
                core.validate_tool({**valid, key:value})
        row = {"architecture":"x86_64","inputClass":"unsigned","stage":"TOOL","code":"NONE",
               "toolExit":"ZERO","stderrMarker":"NONE","stdoutSize":"ZERO","stderrSize":"ZERO",
               "metadataAccepted":False}
        with self.assertRaises(ValueError):
            core.validate_result(row)
        with self.assertRaises(ValueError):
            core.validate_result({**row, "code":"REPOSITORY_METADATA", "toolExit":"NONZERO"})
        for changes in [
            {"stage":"DONE","code":"NONE","toolExit":"NONZERO","metadataAccepted":False},
            {"stage":"SETUP","code":"INTERNAL","toolExit":"ZERO","metadataAccepted":False},
            {"stage":"TOOL","code":"COMMAND_TIMEOUT","toolExit":"ZERO","metadataAccepted":False},
        ]:
            with self.assertRaises(ValueError):
                core.validate_result({**row, **changes})

    def test_binary_measurement_requires_root_owned_readonly_executable_elf(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        body = b"\x7fELF-public-test"
        with patch.object(core.os, "lstat", return_value=info), \
                patch.object(core, "held_file", return_value=body):
            measured = core.binary_identity()
            self.assertEqual(measured["sha256"], core.sha(body))
            self.assertEqual(measured["bytes"], len(body))
            for mode, uid in [(stat.S_IFREG | 0o644,0),(stat.S_IFREG | 0o777,0),
                              (stat.S_IFLNK | 0o755,0),(stat.S_IFREG | 0o755,501)]:
                info.st_mode, info.st_uid = mode, uid
                with self.assertRaises(ValueError):
                    core.binary_identity()


if __name__ == "__main__":
    unittest.main()

