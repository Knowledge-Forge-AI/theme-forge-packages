"""Inert fixtures for the public-base query contract and bounded subprocesses."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("signing_base_metadata", Path(__file__).with_name("signing_base_metadata.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

CONTEXT = {"GITHUB_REPOSITORY": m.REPOSITORY, "GITHUB_REPOSITORY_OWNER": "Knowledge-Forge-AI",
           "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
           "GITHUB_REF_TYPE": "branch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true",
           "GITHUB_RUN_ID": "7000000001", "GITHUB_SHA": "a" * 40}
PREFIX = b"sample\t0\t1.2\t3.fc43\tx86_64\t"
DATA = {"packages": PREFIX + b"sample-1.2-3.fc43.src.rpm\tMIT\n",
        "members": PREFIX + b"/usr/bin/sample\t33261\t2\tabcd\t8\troot\troot\t0\t\t0\n",
        "provides": PREFIX + b"sample\t8\t1.2-3.fc43\n",
        "requires": PREFIX + b"libc.so.6()(64bit)\t0\t\n",
        "conflicts": PREFIX + b"other\t0\t\n",
        "obsoletes": PREFIX + b"old-sample\t8\t1.0\n",
        "scripts": PREFIX + b'POSTIN\t"public script\\nsecond line"\n'}


class FakeDocker:
    def __init__(self, failure=None, removal_failure=False, remains=False):
        self.calls = []
        self.failure = failure
        self.removal_failure = removal_failure
        self.remains = remains

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if argv[:2] == ["docker", "run"]:
            kind = next(k for k, fmt in m.QUERY_FORMATS.items() if fmt == argv[-1])
            if self.failure == "exception":
                raise subprocess.TimeoutExpired("inert", 1)
            if self.failure == kind:
                return 2, b"", b"unused public diagnostic"
            return 0, DATA[kind], b""
        if argv[:3] == ["docker", "rm", "-f"] and self.removal_failure:
            return 1, b"", b""
        if argv[:2] == ["docker", "ps"]:
            names = [a[a.index("--name") + 1] for a, _ in self.calls if a[:2] == ["docker", "run"]]
            return 0, ("/" + names[0] + "\n").encode() if self.remains and names else b"", b""
        return 0, b"", b""


class ContractTests(unittest.TestCase):
    def run_fake(self, docker):
        with tempfile.TemporaryDirectory() as tmp:
            result = m.inspect_base(Path(tmp) / "result", execute=docker, environ=CONTEXT)
            self.assertEqual(result, json.loads((Path(tmp) / "result/RESULT.json").read_text()))
            return result

    def test_context_each_field_required(self):
        for key in CONTEXT:
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                m.check_context({k: v for k, v in CONTEXT.items() if k != key})

    def test_context_rejects_attempt_or_fork(self):
        for changes in ({"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_REPOSITORY": "fork/repo"}, {"GITHUB_REF": "refs/tags/main"}):
            with self.subTest(changes=changes), self.assertRaises(m.Refusal):
                m.check_context({**CONTEXT, **changes})

    def test_child_environment_closed(self):
        self.assertEqual(set(m.child_env(Path("/tmp/inert"))), {"PATH", "HOME", "LANG", "LC_ALL"})
        self.assertNotIn("GH_TOKEN", m.child_env(Path("/tmp/inert")))

    def test_query_has_no_mount_or_network_or_shell(self):
        for kind in m.QUERY_FORMATS:
            argv = m.query_argv(kind, "inert")
            self.assertIn("--network=none", argv)
            self.assertIn("--read-only", argv)
            self.assertIn("--cap-drop=ALL", argv)
            self.assertIn("--user=65534:65534", argv)
            self.assertIn("--pull=never", argv)
            self.assertEqual(argv[-5:], ["--noplugins", "--query", "--all", "--queryformat", m.QUERY_FORMATS[kind]])
            self.assertFalse(any(x.startswith(("--mount", "--volume")) or x in ("-v", "sh", "bash") for x in argv))

    def test_parse_all_fixed_formats(self):
        for kind, raw in DATA.items():
            self.assertEqual(len(m.parse_rows(kind, raw)), 1)
        self.assertEqual(m.parse_rows("scripts", DATA["scripts"])[0][6], "public script\nsecond line")
        self.assertEqual(m.parse_rows("scripts", b""), [])

    def test_bad_row_shapes(self):
        for kind in DATA:
            for raw in (b"wrong\n", DATA[kind][:-1], b"\x00\n", b"\xff\n"):
                with self.subTest(kind=kind, raw=raw[:10]), self.assertRaises(m.Refusal):
                    m.parse_rows(kind, raw)

    def test_bad_member_path_and_digest(self):
        for raw in (DATA["members"].replace(b"/usr/bin/sample", b"/usr/../sample"), DATA["members"].replace(b"abcd", b"not-a-digest")):
            with self.assertRaises(m.Refusal):
                m.parse_rows("members", raw)

    def test_script_tag_or_type_closed(self):
        for raw in (PREFIX + b'UNKNOWN\t"text"\n', PREFIX + b'POSTIN\tfalse\n', PREFIX + b'POSTIN\t{}\n'):
            with self.assertRaises(m.Refusal):
                m.parse_rows("scripts", raw)

    def test_success_never_grants_production(self):
        docker = FakeDocker()
        result = self.run_fake(docker)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["container_cleanup_confirmed"])
        self.assertEqual(set(result["outputs"]), set(DATA))
        self.assertFalse(result["production_acceptance"])
        self.assertFalse(result["candidate_packages_installed"])
        self.assertEqual(sum(a[:3] == ["docker", "rm", "-f"] for a, _ in docker.calls), 7)

    def test_failed_query_still_removes_possible_container(self):
        docker = FakeDocker(failure="members")
        result = self.run_fake(docker)
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["container_cleanup_confirmed"])
        self.assertEqual(result["error_code"], "QUERY_COMMAND_FAILED")
        self.assertEqual(sum(a[:3] == ["docker", "rm", "-f"] for a, _ in docker.calls), 2)

    def test_exception_still_removes_possible_container(self):
        docker = FakeDocker(failure="exception")
        result = self.run_fake(docker)
        self.assertEqual(result["error_code"], "INTERNAL")
        self.assertFalse(result["container_cleanup_confirmed"])
        self.assertEqual(result["uncertain_creation_count"], 1)
        self.assertTrue(any(a[:3] == ["docker", "rm", "-f"] for a, _ in docker.calls))

    def test_failed_removal_keeps_custody(self):
        result = self.run_fake(FakeDocker(removal_failure=True))
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["retained_container_count"], 1)
        self.assertFalse(result["container_cleanup_confirmed"])

    def test_absence_is_required_independently(self):
        result = self.run_fake(FakeDocker(remains=True))
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["container_cleanup_confirmed"])
        self.assertEqual(result["error_code"], "CLEANUP_UNCONFIRMED")

    def test_full_package_keys_and_unknown_rows(self):
        rows = m.parse_rows("packages", DATA["packages"])
        keys = m.package_join("packages", rows, set())
        self.assertEqual(len(keys), 1)
        with self.assertRaisesRegex(m.Refusal, "DUPLICATE_PACKAGE_KEY"):
            m.package_join("packages", rows + rows, set())
        changed = m.parse_rows("members", DATA["members"].replace(b"1.2", b"1.3"))
        with self.assertRaisesRegex(m.Refusal, "UNKNOWN_PACKAGE_KEY"):
            m.package_join("members", changed, keys)

    def test_legal_version_markers_and_public_key_metadata(self):
        rows = m.parse_rows("packages", DATA["packages"].replace(b"1.2", b"1.2~rc1^git"))
        self.assertEqual(rows[0][2], "1.2~rc1^git")
        rows = m.parse_rows("packages", b"gpg-pubkey\t0\t1234abcd\t1234abcd\t(none)\t(none)\tpubkey\n")
        self.assertEqual(rows[0][4], "(none)")

    def test_unicode_line_separator_is_not_tsv_newline(self):
        raw = DATA["packages"].replace(b"MIT", "MIT\u2028AND BSD".encode())
        self.assertEqual(len(m.parse_rows("packages", raw)), 1)

    def test_failed_query_has_hashes_not_raw_diagnostics(self):
        result = self.run_fake(FakeDocker(failure="members"))
        self.assertIn("stdout_sha256", result["query_facts"]["members"])
        self.assertIn("stderr_sha256", result["query_facts"]["members"])
        self.assertNotIn("unused public diagnostic", json.dumps(result))

    def test_rejected_line_record(self):
        try:
            m.parse_rows("packages", DATA["packages"] + b"bad\n")
        except m.Refusal as error:
            self.assertEqual(error.line, 2)
        else:
            self.fail("invalid row accepted")

    def test_parser_failure_categories_are_fixed_and_content_free(self):
        cases = [
            (b"bad\n", "QUERY_FIELD_COUNT"),
            (DATA["scripts"].replace(b"sample", b"bad/name", 1), "QUERY_IDENTITY_SHAPE"),
            (PREFIX + b'UNKNOWN\t"text"\n', "SCRIPT_TAG_SHAPE"),
            (PREFIX + b'POSTIN\t(not-json)\n', "SCRIPT_JSON_SHAPE"),
            (PREFIX + b'POSTIN\tfalse\n', "SCRIPT_VALUE_SHAPE"),
        ]
        for raw, expected in cases:
            with self.subTest(expected=expected):
                try:
                    m.parse_rows("scripts", raw)
                except m.Refusal as error:
                    self.assertEqual(str(error), expected)
                    self.assertEqual(error.line, 1)
                    self.assertNotIn("not-json", str(error))
                else:
                    self.fail("invalid row accepted")

    def test_script_failure_records_label_and_line_through_full_controller(self):
        class MalformedScriptDocker(FakeDocker):
            def __call__(self, argv, **kwargs):
                code, raw, err = super().__call__(argv, **kwargs)
                if argv[:2] == ["docker", "run"] and argv[-1] == m.QUERY_FORMATS["scripts"]:
                    raw = DATA["scripts"] * 84 + PREFIX + b"POSTIN\t(not-json)\n"
                return code, raw, err
        result = self.run_fake(MalformedScriptDocker())
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error_code"], "SCRIPT_JSON_SHAPE")
        self.assertEqual(result["query_facts"]["scripts"]["first_rejected_line"], 85)
        self.assertTrue(result["container_cleanup_confirmed"])
        self.assertEqual(result["retained_container_count"], 0)
        self.assertNotIn("not-json", json.dumps(result))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                m.inspect_base(Path(tmp), execute=FakeDocker(), environ=CONTEXT)

    def test_actual_existing_python_bounded_output(self):
        code, out, err = m.bounded([sys.executable, "-I", "-B", "-c", "print('inert')"], env=m.child_env(Path("/tmp")), seconds=5)
        self.assertEqual((code, out, err), (0, b"inert\n", b""))

    def test_actual_existing_python_output_limit(self):
        with self.assertRaisesRegex(m.Refusal, "COMMAND_OUTPUT_LIMIT"):
            m.bounded([sys.executable, "-I", "-B", "-c", "print('x'*10000)"], env=m.child_env(Path("/tmp")), seconds=5, limit=100)

    def test_actual_existing_python_timeout(self):
        with self.assertRaisesRegex(m.Refusal, "COMMAND_TIMEOUT"):
            m.bounded([sys.executable, "-I", "-B", "-c", "import time; time.sleep(10)"], env=m.child_env(Path("/tmp")), seconds=1)


if __name__ == "__main__":
    unittest.main()
