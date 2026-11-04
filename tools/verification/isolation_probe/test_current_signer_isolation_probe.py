"""Pure fixture tests for the proposed key-free isolation diagnostic probe.

Run: python3 -I -B tools/verification/isolation_probe/test_current_signer_isolation_probe.py [P_ROOT]
P_ROOT defaults to the repository root containing this file. No Docker, network,
Git, GPG, credential or product process is started; every effect is faked. The
production leaves are the real manifest-authenticated bytes from P_ROOT.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(os.path.abspath(__file__)).parent
PROPOSAL_ROOT = HERE.parents[2]
P_ROOT = Path(os.path.abspath(sys.argv[1])) if len(sys.argv) > 1 else PROPOSAL_ROOT
PROBE_FILE = HERE / "current_signer_isolation_probe.py"
WORKFLOW_FILE = PROPOSAL_ROOT / ".github/workflows/probe-current-signer-isolation.yml"

_spec = importlib.util.spec_from_file_location("current_signer_isolation_probe", PROBE_FILE)
probe = importlib.util.module_from_spec(_spec)
sys.modules["current_signer_isolation_probe"] = probe
_spec.loader.exec_module(probe)
PROD = probe.load_production_leaves(P_ROOT, probe.HOST_LEAVES)
iso, gate, hc, bridge = (PROD["signing_linux_isolation"], PROD["signing_network_gate"],
                         PROD["signer_host_controller"], PROD["runtime_workflow_bridge"])
NONCE = "c" * 64
SELF_UID = 1001

TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
UDP_HEADER = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"
ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"
V6_LO_ROUTE = ("00000000000000000000000000000001 80 00000000000000000000000000000000 00 "
               "00000000000000000000000000000000 00000000 00000001 00000000 00000001       lo")


def sock(local: str, state: str, uid: str = "0", remote: str | None = None, inode: str = "987654") -> str:
    remote = remote or ("0" * (8 if len(local.split(":")[0]) == 8 else 32) + ":0000")
    return (f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 {uid:>6}        0 "
            f"{inode} 1 0000000000000000 100 0 0 10 0")


def facts(*, tcp=(), tcp6=(), udp=(), udp6=(), route=(), v6route=(V6_LO_ROUTE,), interfaces=("lo",), drop=()):
    def table(header, rows):
        return ("\n".join(([header] if header else []) + list(rows)) + "\n").encode("ascii")
    tables = {"route": table(ROUTE_HEADER, route), "ipv6_route": table(None, v6route),
              "tcp": table(TCP_HEADER, tcp), "tcp6": table(TCP_HEADER, tcp6),
              "udp": table(UDP_HEADER, udp), "udp6": table(UDP_HEADER, udp6)}
    for name in drop:
        tables.pop(name)
    return interfaces, tables


def snapshot(fx, *, little_endian=True):
    interfaces, tables = fx
    return probe.take_snapshot(iso, lambda: (interfaces, dict(tables)), self_uid=SELF_UID, little_endian=little_endian)


DNS_LISTEN = sock("0B00007F:9C41", "0A")


class Classification(unittest.TestCase):
    def test_clean_namespace_would_pass_without_acceptance(self):
        snap = snapshot(facts())
        self.assertEqual(snap["production_predicate"], {"result": "WOULD_PASS", "code": "NONE", "detail": "NONE"})
        self.assertEqual(snap["sockets"]["rows"], [])

    def test_docker_dns_tcp_listener_is_refused_and_categorized(self):
        snap = snapshot(facts(tcp=[DNS_LISTEN]))
        self.assertEqual(snap["production_predicate"],
                         {"result": "REFUSED", "code": "ISOLATION_SOCKET_PRESENT", "detail": "TCP_V4_LISTEN"})
        self.assertEqual(snap["sockets"]["rows"], [{"proto": "TCP", "family": "V4", "state": "LISTEN",
                         "local": "V4_DOCKER_DNS_127_0_0_11", "port": "PORT_OTHER", "remote": "REMOTE_NONE",
                         "uid": "UID_ZERO", "count": "1"}])

    def test_address_port_uid_categories(self):
        cases = {("0B00007F:0035", "V4"): "V4_DOCKER_DNS_127_0_0_11", ("0100007F:0035", "V4"): "V4_LOOPBACK_OTHER",
                 ("00000000:0035", "V4"): "V4_WILDCARD", ("0200A8C0:0035", "V4"): "V4_NONLOOPBACK",
                 ("00000000000000000000000001000000:0035", "V6"): "V6_LOOPBACK",
                 ("00000000000000000000000000000000:0035", "V6"): "V6_WILDCARD",
                 ("0000000000000000FFFF00000B00007F:0035", "V6"): "V6_V4MAPPED_DOCKER_DNS",
                 ("0000000000000000FFFF00000100007F:0035", "V6"): "V6_V4MAPPED_LOOPBACK_OTHER",
                 ("0000000000000000FFFF00000200A8C0:0035", "V6"): "V6_V4MAPPED_OTHER",
                 ("000080FE000000000000000001000000:0035", "V6"): "V6_NONLOOPBACK",
                 ("0b00007f:0035", "V4"): "UNPARSEABLE", ("0B00007F", "V4"): "UNPARSEABLE",
                 ("0B00007F:0035", "V6"): "UNPARSEABLE", ("0B00007F:35:00", "V4"): "UNPARSEABLE"}
        for (text, family), expected in cases.items():
            self.assertEqual(probe.classify_local_address(text, family), expected, text)
        self.assertEqual(probe.classify_port("0B00007F:0035"), "PORT_53")
        self.assertEqual(probe.classify_port("0B00007F:0000"), "PORT_ZERO")
        self.assertEqual(probe.classify_port("0B00007F:zz"), "PORT_UNPARSEABLE")
        self.assertEqual([probe.classify_uid(v, SELF_UID) for v in ("0", "1001", "7", "-1", "x")],
                         ["UID_ZERO", "UID_SELF", "UID_OTHER", "UID_UNPARSEABLE", "UID_UNPARSEABLE"])
        self.assertEqual(probe.classify_remote("0100007F:D431", "V4"), "REMOTE_LOOPBACK")
        self.assertEqual(probe.classify_remote("08080808:0035", "V4"), "REMOTE_NONLOOPBACK")

    def test_udp_sockets_are_refused_by_unchanged_predicate(self):
        for kwargs, detail in (({"udp": [sock("0B00007F:D431", "07")]}, "UDP_V4_SOCKET"),
                               ({"udp6": [sock("00000000000000000000000001000000:D431", "07")]}, "UDP_V6_SOCKET")):
            snap = snapshot(facts(**kwargs))
            self.assertEqual(snap["production_predicate"]["detail"], detail)
            self.assertEqual(snap["sockets"]["rows"][0]["state"], "UDP_UNCONNECTED")

    def test_every_tcp_state_matches_production_and_only_time_wait_passes(self):
        expected_detail = {"LISTEN": "LISTEN", "ACTIVE": "ACTIVE_STATE", "CLOSING": "CLOSING_STATE"}
        for table, local, fam in (("tcp", "0100007F:1F90", "V4"),
                                  ("tcp6", "00000000000000000000000001000000:1F90", "V6")):
            for value in range(256):
                state = f"{value:02X}"
                snap = snapshot(facts(**{table: [sock(local, state, uid="1001")]}))
                verdict, category = snap["production_predicate"], snap["sockets"]["rows"][0]["state"]
                if state == "06":
                    self.assertEqual((verdict["result"], category), ("WOULD_PASS", "TIME_WAIT"))
                    continue
                self.assertEqual((verdict["result"], verdict["code"]), ("REFUSED", "ISOLATION_SOCKET_PRESENT"), state)
                want = ("TCP_OTHER_STATE" if category == "TCP_OTHER"
                        else f"TCP_{fam}_{expected_detail[category]}")
                self.assertEqual(verdict["detail"], want, (table, state))

    def test_malformed_and_bounds_fail_closed(self):
        snap = snapshot(facts(tcp=["   0: 0B00007F:9C41 00000000:0000 0A"]))
        self.assertEqual(snap["production_predicate"]["detail"], "SOCKET_ROW_MALFORMED")
        self.assertEqual((snap["sockets"]["malformed_rows"], snap["sockets"]["rows"]), ("1", []))
        interfaces, tables = facts()
        cases = (("tcp", b"x" * (probe.MAX_PROC_BYTES + 1), "OVER_BOUND", "ISOLATION_METADATA_BOUND"),
                 ("udp", UDP_HEADER.encode() + b"\n\xff\n", "NON_ASCII", "ISOLATION_METADATA_FORMAT"),
                 ("tcp6", b"", "HEADER_MISMATCH", "ISOLATION_SOCKET_FORMAT"))
        for name, body, status, code in cases:
            bad = dict(tables, **{name: body})
            snap = snapshot((interfaces, bad))
            self.assertEqual(snap["tables"][name], status)
            self.assertEqual(snap["production_predicate"]["code"], code)
        snap = snapshot(facts(drop=("udp6",)))
        self.assertEqual((snap["tables"]["udp6"], snap["production_predicate"]["code"]),
                         ("UNAVAILABLE", "ISOLATION_METADATA_UNAVAILABLE"))
        snap = snapshot(facts(interfaces=None))
        self.assertEqual((snap["interfaces"]["read"], snap["production_predicate"]["code"]),
                         ("UNAVAILABLE", "ISOLATION_METADATA_UNAVAILABLE"))

    def test_interfaces_and_routes(self):
        snap = snapshot(facts(interfaces=("eth0", "lo")))
        self.assertEqual((snap["interfaces"]["non_lo"], snap["production_predicate"]["detail"]),
                         ("1", "NON_LO_INTERFACE_PRESENT"))
        snap = snapshot(facts(route=["eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0"]))
        self.assertEqual((snap["routes"]["v4_non_lo"], snap["production_predicate"]["detail"]), ("1", "IPV4_NON_LO_ROUTE"))
        snap = snapshot(facts(v6route=[V6_LO_ROUTE.replace(" lo", " eth0")]))
        self.assertEqual((snap["routes"]["v6_non_lo"], snap["production_predicate"]["detail"]), ("1", "IPV6_NON_LO_ROUTE"))

    def test_category_overflow_and_worst_case_line_bound(self):
        rows = [sock(f"0100007F:{port:04X}", state, uid=uid, remote=remote) for port, (state, uid, remote) in enumerate(
            [(s, u, r) for s in ("0A", "01", "04", "0E") for u in ("0", "1001", "5", "x")
             for r in ("00000000:0000", "0200A8C0:0050")])]
        snap = snapshot(facts(tcp=rows))
        self.assertEqual(len(snap["sockets"]["rows"]), probe.MAX_SOCKET_CATEGORIES)
        self.assertTrue(snap["sockets"]["category_overflow"])
        worst = json.loads(json.dumps(snap))
        worst["sockets"]["rows"] = [{"proto": "TCP", "family": "V4", "state": "UDP_UNCONNECTED",
                                     "local": "V6_V4MAPPED_LOOPBACK_OTHER", "port": "PORT_UNPARSEABLE",
                                     "remote": "REMOTE_UNPARSEABLE", "uid": "UID_UNPARSEABLE", "count": "10_OR_MORE"}
                                    ] * probe.MAX_SOCKET_CATEGORIES
        worst["tables"] = {k: "HEADER_MISMATCH" for k in probe.TABLES}
        worst["production_predicate"] = {"result": "REFUSED", "code": "ISOLATION_METADATA_UNAVAILABLE",
                                         "detail": "NON_LO_INTERFACE_PRESENT"}
        self.assertLess(len(probe.encode_line("result", NONCE, worst)), probe.MAX_LINE_BYTES)

    def test_other_byte_order_reports_unknown(self):
        snap = snapshot(facts(tcp=[DNS_LISTEN]), little_endian=False)
        self.assertEqual(snap["sockets"]["rows"][0]["local"], "UNPARSEABLE")
        self.assertEqual(snap["production_predicate"]["detail"], "TCP_V4_LISTEN")

    def test_probe_read_shape_equals_production_predicate(self):
        probe.require_predicate_shape(iso)
        with self.assertRaises(probe.ProbeRefusal) as ctx:
            probe.require_predicate_shape(SimpleNamespace(_TABLES=("tcp",), MAX_PROC_BYTES=probe.MAX_PROC_BYTES,
                                                          _TCP_CLOSING_STATES=iso._TCP_CLOSING_STATES,
                                                          _TCP_ACTIVE_STATES=iso._TCP_ACTIVE_STATES,
                                                          require_isolated_facts=iso.require_isolated_facts))
        self.assertEqual(ctx.exception.code, "PRODUCTION_PREDICATE_SHAPE")


class NoRawRetention(unittest.TestCase):
    RAW = ("987654", "9C41", "40001", "0B00007F", "eth7xyz", "1001", "127.0.0.11", "inode", "192.168")

    def test_lines_and_result_never_contain_raw_metadata(self):
        snap = snapshot(facts(tcp=[DNS_LISTEN, sock("0200A8C0:9C41", "01", uid="1001", remote="0B00007F:9C41")],
                              interfaces=("eth7xyz", "lo")))
        text = probe.encode_line("ready", NONCE, snap).decode() + json.dumps(snap)
        for raw in self.RAW:
            self.assertNotIn(raw, text)

    def test_validate_snapshot_rejects_injected_or_unbounded_values(self):
        good = snapshot(facts(tcp=[DNS_LISTEN]))
        mutations = [lambda s: s.update(raw="x"), lambda s: s["sockets"]["rows"][0].update(local="127.0.0.11:40001"),
                     lambda s: s["interfaces"].update(lo_present="true"),
                     lambda s: s["sockets"]["rows"].extend([s["sockets"]["rows"][0]] * 16),
                     lambda s: s["production_predicate"].update(detail="ss -ltnp output"),
                     lambda s: s["routes"].update(v4_lo=3)]
        for mutate in mutations:
            bad = json.loads(json.dumps(good))
            mutate(bad)
            with self.assertRaises(probe.ProbeRefusal):
                probe.validate_snapshot(bad)


class LineProtocol(unittest.TestCase):
    def test_parse_line_is_closed(self):
        snap = snapshot(facts())
        good = probe.encode_line("ready", NONCE, snap)
        self.assertEqual(probe.parse_line(good, "ready", NONCE, "READY_INVALID"), snap)
        bad_lines = [good.replace(NONCE.encode(), b"d" * 64), good[:-1], good + b"\n", good[:-1] + b"\r\n",
                     b"{" + b" " * 5000 + b"}\n", good.replace(b'"kind":"ready"', b'"kind":"ready","kind":"ready"'),
                     good.replace(b'"kind":"ready"', b'"extra":1,"kind":"ready"'), b"",
                     gate.encode_message("ready", gate.SourceBinding("a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 64, 1),
                                         NONCE, worker_pid=7)]
        for line in bad_lines:
            with self.assertRaises(probe.ProbeRefusal):
                probe.parse_line(line, "ready", NONCE, "READY_INVALID")

    def test_observer_flow_two_fixed_snapshots(self):
        sequence = [facts(tcp=[DNS_LISTEN], interfaces=("eth0", "lo")), facts(tcp=[DNS_LISTEN])]
        reads, written = [], []

        def reader():
            reads.append(1)
            interfaces, tables = sequence[len(reads) - 1]
            return interfaces, dict(tables)
        probe.run_observer(NONCE, iso, reader=reader, read_line=lambda: probe.encode_line("challenge", NONCE),
                           write=written.append, self_uid=SELF_UID, little_endian=True)
        self.assertEqual(len(reads), 2)  # Exactly two snapshots; no polling.
        attached = probe.parse_line(written[0], "ready", NONCE, "READY_INVALID")
        detached = probe.parse_line(written[1], "result", NONCE, "RESULT_INVALID")
        self.assertEqual(attached["interfaces"]["non_lo"], "1")
        self.assertEqual(detached["production_predicate"]["detail"], "TCP_V4_LISTEN")

    def test_observer_refuses_wrong_challenge_without_second_snapshot(self):
        reads, written = [], []
        with self.assertRaises(probe.ProbeRefusal) as ctx:
            probe.run_observer(NONCE, iso, reader=lambda: (reads.append(1), facts())[1],
                               read_line=lambda: probe.encode_line("challenge", "e" * 64),
                               write=written.append, self_uid=SELF_UID, little_endian=True)
        self.assertEqual((ctx.exception.code, len(reads), len(written)), ("CHALLENGE_INVALID", 1, 1))

    def test_observer_environment_must_be_credential_free(self):
        probe.require_clean_observer_env({"PATH": "/usr/bin", "HOME": "/work/workspace", "HOSTNAME": "x"})
        for key in ("GH_TOKEN", "PACKAGE_SIGNING_KEY", "GNUPG_PASSPHRASE", "AWS_SECRET"):
            with self.assertRaises(probe.ProbeRefusal):
                probe.require_clean_observer_env({key: "v"})


class FakeRunner:
    def __init__(self, overrides=None):
        self.calls, self.overrides = [], dict(overrides or {})

    def __call__(self, argv, timeout):
        self.calls.append(tuple(argv))
        for prefix, response in self.overrides.items():
            if tuple(argv[1:1 + len(prefix)]) == prefix:
                return response
        if tuple(argv[1:3]) == ("network", "create"):
            return 0, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", b""
        if tuple(argv[1:3]) == ("container", "inspect"):
            return 0, b"{}\n", b""
        return 0, b"", b""

    def kinds(self):
        return [" ".join(call[1:3]) for call in self.calls]


class FakeSession:
    def __init__(self, lines, *, exit_code=0, stderr=b"", read_error=None):
        self.lines, self.exit_code, self.read_error = list(lines), exit_code, read_error
        self.stderr_buf, self.writes = bytearray(stderr), []
        self.cleanup_uncertain, self.terminated, self.deadline = False, False, 0.0

    def read_protocol_line(self):
        if self.read_error is not None:
            raise self.read_error
        return self.lines.pop(0) if self.lines else b""

    def write_stdin(self, payload, *, close_after=False):
        self.writes.append((bytes(payload), close_after))

    def wait_for_exit(self):
        return self.exit_code

    def require_stdout_clean_eof(self):
        if self.lines:
            raise probe.ProbeRefusal("PROTOCOL_EXTRA_STDOUT")

    def terminate_and_close(self):
        self.terminated = True


def lifecycle(session, runner=None, spawned=None):
    runner = runner or FakeRunner()
    spawned = spawned if spawned is not None else []
    out = probe.run_lifecycle(
        run_suffix="41728995205", image_id="sha256:" + "ab" * 32, container_python="/usr/bin/python3",
        p_dir=Path("/home/runner/work/p"), mods=PROD, runner=runner,
        spawner=lambda argv, env: spawned.append((argv, env)) or object(),
        session_factory=lambda proc, deadline, err: session, nonce=NONCE, uid=1001, gid=118)
    return out, runner, spawned


READY = probe.encode_line("ready", NONCE, snapshot(facts(tcp=[DNS_LISTEN], interfaces=("eth0", "lo"))))
RESULT = probe.encode_line("result", NONCE, snapshot(facts(tcp=[DNS_LISTEN])))


class HostLifecycle(unittest.TestCase):
    def test_happy_path_production_shaped_and_key_free(self):
        session = FakeSession([READY, RESULT])
        out, runner, spawned = lifecycle(session)
        self.assertEqual((out["refusal"], out["custody_retained"]), ("NONE", False))
        self.assertEqual(runner.kinds(), ["network create", "network disconnect", "container inspect",
                                          "container ls", "network rm"])
        argv, env = spawned[0]
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        self.assertFalse({"-e", "--env", "GH_TOKEN", "-v"} & set(argv))
        self.assertEqual(session.writes, [(probe.encode_line("challenge", NONCE), True)])
        self.assertEqual(out["after_disconnect"]["production_predicate"]["detail"], "TCP_V4_LISTEN")
        self.assertEqual(out["detached_readback"], "EMPTY_OBJECT")
        self.assertTrue(session.terminated)

    def test_detach_not_confirmed_stops_before_challenge(self):
        session = FakeSession([READY, RESULT])
        out, runner, _ = lifecycle(session, FakeRunner({("container", "inspect"): (0, b'{"n":{}}', b"")}))
        self.assertEqual((out["refusal"], out["detached_readback"]), ("DETACH_NOT_CONFIRMED", "NETWORK_ATTACHED"))
        self.assertEqual((session.writes, out["after_disconnect"]), ([], None))
        self.assertNotIn("rm -f", runner.kinds())

    def test_failures_map_to_fixed_labels_and_force_teardown(self):
        cases = [
            (FakeSession([READY, RESULT]), FakeRunner({("network", "disconnect"): (1, b"", b"raw")}), "DISCONNECT_FAILED"),
            (FakeSession([READY, RESULT]), FakeRunner({("container", "inspect"): (1, b"", b"")}), "INSPECT_FAILED"),
            (FakeSession([READY, RESULT], exit_code=3), None, "OBSERVER_NONZERO_EXIT"),
            (FakeSession([READY, RESULT, b"x\n"]), None, "OBSERVER_STDOUT_UNCLEAN"),
            (FakeSession([], read_error=probe.ProbeRefusal("HOST_CONTROLLER_TIMEOUT")), None, "SESSION_TIMEOUT"),
            (FakeSession([READY, RESULT.replace(b'"kind":"result"', b'"kind":"result","raw":"0B00007F"')]),
             None, "RESULT_INVALID"),
        ]
        for session, runner, label in cases:
            out, runner, _ = lifecycle(session, runner)
            self.assertEqual(out["refusal"], label)
            self.assertNotIn("rm -f", runner.kinds(), label)
            self.assertIn("network rm", runner.kinds(), label)

    def test_empty_ready_records_framing_and_closed_observer_refusal(self):
        out, runner, _ = lifecycle(FakeSession([], stderr=b"PRODUCTION_LEAF_DIGEST\n"))
        self.assertEqual((out["refusal"], out["ready_framing"], out["observer_stderr"]),
                         ("READY_INVALID", "EMPTY_EOF", "PRODUCTION_LEAF_DIGEST"))
        self.assertNotIn("network disconnect", runner.kinds())
        out, _, _ = lifecycle(FakeSession([], stderr=b"Traceback /home/runner secret\n"))
        self.assertEqual(out["observer_stderr"], "UNRECOGNIZED")

    def test_teardown_uncertainty_retains_custody(self):
        out, _, _ = lifecycle(FakeSession([READY, RESULT]), FakeRunner({("network", "rm"): (1, b"", b"")}))
        self.assertEqual((out["refusal"], out["custody_retained"]), ("TEARDOWN_UNCONFIRMED", True))
        out, _, _ = lifecycle(FakeSession([READY, RESULT]), FakeRunner({("container", "ls"): (0, b"abc\n", b"")}))
        self.assertTrue(out["custody_retained"])

    def test_network_create_failure_never_spawns(self):
        out, runner, spawned = lifecycle(FakeSession([READY]), FakeRunner({("network", "create"): (1, b"", b"")}))
        self.assertEqual((out["refusal"], spawned), ("NETWORK_CREATE_FAILED", []))
        self.assertEqual(runner.kinds(), ["network create"])
        self.assertTrue(out["custody_retained"])

    def test_network_cleanup_uses_only_created_immutable_id(self):
        out, runner, _ = lifecycle(FakeSession([READY, RESULT]))
        removals = [call for call in runner.calls if call[1:3] == ("network", "rm")]
        self.assertEqual(removals, [(probe.DOCKER, "network", "rm", "a" * 64)])
        self.assertFalse(out["teardown"]["container_force_remove_attempted"])

    def test_ambiguous_network_create_never_deletes_by_name(self):
        for stdout in (b"", b"unknown", b"a" * 63, b"a" * 64 + b"\nextra"):
            runner = FakeRunner({("network", "create"): (0, stdout, b"")})
            out, runner, spawned = lifecycle(FakeSession([READY]), runner)
            self.assertEqual(out["refusal"], "NETWORK_CREATE_FAILED")
            self.assertEqual((runner.kinds(), spawned), (["network create"], []))
            self.assertTrue(out["custody_retained"])

    def test_foreign_or_remaining_container_is_never_force_removed(self):
        for session in (FakeSession([], stderr=b"OBSERVER_INTERNAL\n"), FakeSession([READY, RESULT])):
            runner = FakeRunner({("container", "ls"): (0, b"remaining-or-foreign\n", b"")})
            out, runner, _ = lifecycle(session, runner)
            self.assertNotIn("rm -f", runner.kinds())
            self.assertFalse(out["teardown"]["container_absence_confirmed"])
            self.assertTrue(out["custody_retained"])

    def test_observer_argv_validator_refuses_widening(self):
        kw = dict(image_id="sha256:" + "ab" * 32, container_python="/usr/bin/python3", network="tf-current-signer-1-1",
                  container="tf-current-signer-1-2", p_dir=Path("/home/runner/work/p"), uid=1001, gid=118, nonce=NONCE, hc=hc)
        argv = probe.build_observer_argv(**kw)
        i = argv.index("--rm") + 1
        mutations = [argv[:i] + ("-e", "GH_TOKEN") + argv[i:], argv[:i] + ("--privileged",) + argv[i:],
                     argv[:i] + ("--cap-add", "NET_ADMIN") + argv[i:], argv[:i] + ("-v", "/:/host") + argv[i:],
                     argv[:i] + ("--mount", "type=bind,src=/var/run/docker.sock,dst=/s") + argv[i:],
                     tuple("host" if t == "tf-current-signer-1-1" else t for t in argv),
                     tuple("tf-signing-runtime-build:1" if t == kw["image_id"] else t for t in argv),
                     tuple("0:0" if t == "1001:118" else t for t in argv)]
        for bad in mutations:
            with self.assertRaises(probe.ProbeRefusal):
                probe.validate_observer_argv(bad, hc)


GOOD_ENV = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": probe.REPOSITORY, "GITHUB_REPOSITORY_OWNER": probe.REPOSITORY_OWNER,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "41728995205",
            "GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_REF": probe.EXPECTED_PROBE_WORKFLOW_REF,
            "PATH": "/usr/bin:/bin", "GH_TOKEN": "ghs_fixture_not_a_secret"}


class HostEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.p = self.tmp / "p"
        shutil.copytree(P_ROOT, self.p, ignore=shutil.ignore_patterns(".git"))
        target = self.p / probe.PROBE_REL_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROBE_FILE, target)
        (self.p / ".git").mkdir()
        self.events, self.env = [], dict(GOOD_ENV)
        q_body = b'{"quarantine":true}\n'
        root_sha = hashlib.sha256((self.p / bridge.BASE_ROOT_PROOF_REL_PATH).read_bytes()).hexdigest()
        self.sib = SimpleNamespace(
            CLASS_ADMISSION_GATE_OPEN=True, ADMITTED_MANIFEST_SHA256="11" * 32, _admitted_pin_matches=lambda v: True,
            authenticate_admission_manifest=lambda p, expected_manifest_sha256: self.events.append("admission"),
            held_unaliased_bytes=lambda p, max_bytes: Path(p).read_bytes(), MAX_SMALL_SOURCE_BYTES=1 << 20,
            verify_selected_fedora_certificate_bytes=lambda b: None, BASE_ROOT_PROOF_SHA256=root_sha,
            sha256_hex=lambda b: hashlib.sha256(b).hexdigest(), _verify_physical_base_metadata_proof=lambda b: None,
            _verify_physical_supplemental_notices=lambda b, d: None, QUARANTINE_SHA256=hashlib.sha256(q_body).hexdigest(),
            execute_signing_image_build=self._build, to_host_controller_image_kwargs=lambda r: {
                "container_image": "sha256:" + "ab" * 32, "container_python": "/usr/bin/python3"},
            dispose_built_image=self._dispose)

        def intake(transport, destination, *, environ):
            self.events.append(("intake", "GH_TOKEN" in environ, transport))
            os.mkdir(destination, 0o700)
            (Path(destination) / "QUARANTINE.json").write_bytes(q_body)
            (Path(destination) / "runtime.rpm").write_bytes(b"rpm")
        self.rii = SimpleNamespace(prepare_pinned_runtime_inputs=intake)
        self.build_error = self.dispose_error = None
        self.session = FakeSession([READY, RESULT])
        self.runner = FakeRunner()
        self.spawned = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build(self, **kw):
        self.events.append(("build", kw["run_id_suffix"]))
        if self.build_error is not None:
            raise self.build_error
        return SimpleNamespace(manifest_sha256="22" * 32, recipe_sha256="33" * 32)

    def _dispose(self, result, engine):
        self.events.append("dispose")
        if self.dispose_error is not None:
            raise self.dispose_error
        return {"tag_removed": True, "image_id_removed": True, "custody_retained": False}

    def git(self, argv, cwd, env):
        if argv[1:3] == ("rev-parse", "HEAD"):
            return 0, ("1" * 40 + "\n").encode(), b""
        if argv[1] == "rev-parse":
            return 0, ("2" * 40 + "\n").encode(), b""
        return 0, b"", b""

    def run_host(self, network_profile=None, **overrides):
        if network_profile is not None:
            overrides["_network_profile"] = network_profile
        profile = overrides.pop("_network_profile", None)
        mods = dict(PROD, signing_image_build=self.sib, runtime_input_intake=self.rii)
        hooks = {"require_flags": False, "uname": lambda: SimpleNamespace(sysname="Linux", machine="x86_64"),
                 "mods": mods, "git_runner": self.git, "leaf_importer": lambda p: (self.sib, self.rii),
                 "transport_factory": lambda token, tdir: ("transport", len(token) > 0),
                 "engine_factory": lambda: "engine", "runner": self.runner,
                 "spawner": lambda argv, env: self.spawned.append((argv, env)) or object(),
                 "session_factory": lambda proc, deadline, err: self.session, "nonce_fn": lambda: NONCE}
        hooks.update(overrides)
        return probe.execute_host(p_root=str(self.p), p_commit="1" * 40, work_root=str(self.tmp / "image-work"),
                                  environ=self.env, hooks=hooks,
                                  **({} if profile is None else {"network_profile": profile}))

    def test_happy_path_closed_result_and_cleanup(self):
        result = self.run_host()
        self.assertEqual((result["status"], result["refusal"], result["custody_retained"]),
                         ("diagnostic-complete", "NONE", False))
        clean = probe.validate_result(result)
        self.assertEqual(clean["source"]["descriptor_sha256"],
                         "1870d44f3df5447be273be348fcb94f9a6ea3ed1e4b93a0533ccd9196335ca31")
        self.assertEqual(clean["source"]["probe_source_sha256"], hashlib.sha256(PROBE_FILE.read_bytes()).hexdigest())
        self.assertEqual(self.events.count("dispose"), 1)
        self.assertFalse((self.tmp / "image-work").exists())
        self.assertNotIn("GH_TOKEN", self.env)
        argv, env = self.spawned[0]
        self.assertFalse(any("ghs_fixture" in token or "TOKEN" in token.upper() for token in argv + tuple(env.values())))
        out = self.tmp / "out" / "RESULT.json"
        probe.write_result(out, result)
        text = out.read_text()
        self.assertEqual(oct(out.stat().st_mode & 0o777), "0o600")
        for raw in ("ghs_fixture", "0B00007F", "987654", str(self.tmp), "tf-current-signer-"):
            self.assertNotIn(raw, text)
        for key in probe._CONSTANT_FALSE:
            self.assertIs(json.loads(text)[key], False)

    def test_complete_result_refuses_inconsistent_cleanup_or_ordering(self):
        result = self.run_host()
        for path, value in (
            (("lifecycle", "teardown", "container_absence_confirmed"), False),
            (("lifecycle", "teardown", "network_removed"), False),
            (("lifecycle", "teardown", "session_cleanup_uncertain"), True),
            (("lifecycle", "steps", "disconnect"), "NOT_REACHED"),
            (("lifecycle", "detached_readback"), "NETWORK_ATTACHED"),
            (("image", "tag_removed"), False),
            (("image", "disposal_attempted"), False),
        ):
            changed = json.loads(json.dumps(result))
            cursor = changed
            for name in path[:-1]:
                cursor = cursor[name]
            cursor[path[-1]] = value
            with self.assertRaises(probe.ProbeRefusal):
                probe.validate_result(changed)

    def test_signing_or_gpg_environment_refused_before_any_docker(self):
        for key in ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "GPG_AGENT_INFO", "DOCKER_HOST"):
            self.env = dict(GOOD_ENV, **{key: "x"})
            result = self.run_host()
            self.assertEqual(result["refusal"], "CREDENTIAL_ENVIRONMENT", key)
            self.assertEqual((self.runner.calls, self.events), ([], []))

    def test_workflow_ref_binding_and_production_barrier(self):
        self.env = dict(GOOD_ENV, GITHUB_WORKFLOW_REF=bridge.EXPECTED_WORKFLOW_REF)
        self.assertEqual(self.run_host()["refusal"], "CALLER_CONTEXT")
        with self.assertRaises(bridge.RuntimeBridgeError) as ctx:  # Barrier B1: production bridge refuses the probe.
            bridge.authenticate_workflow_context(dict(GOOD_ENV))
        self.assertEqual(ctx.exception.code, "CALLER_WORKFLOW_REF")
        for key, value in (("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "push"), ("GITHUB_HEAD_REF", "x"),
                           ("GITHUB_REF", "refs/heads/dev"), ("GITHUB_REPOSITORY", "fork/theme-forge-packages")):
            with self.assertRaises(probe.ProbeRefusal):
                probe.authenticate_probe_context(dict(GOOD_ENV, **{key: value}))

    def test_build_failure_cleans_work_root_and_never_starts_lifecycle(self):
        self.build_error = RuntimeError("raw engine output")
        result = self.run_host()
        self.assertEqual((result["refusal"], result["image"]["stage"]), ("IMAGE_PREPARE_FAILED", "BUILD"))
        self.assertEqual((self.runner.calls, result["lifecycle"]), ([], None))
        self.assertFalse((self.tmp / "image-work").exists())
        self.assertNotIn("dispose", self.events)
        self.assertFalse(result["image"]["disposal_confirmed"])
        self.assertTrue(result["custody_retained"])
        probe.validate_result(result)

    def test_dispose_failure_retains_custody(self):
        self.dispose_error = RuntimeError("daemon")
        result = self.run_host()
        self.assertEqual((result["status"], result["refusal"], result["custody_retained"]),
                         ("refused", "IMAGE_DISPOSAL_UNCONFIRMED", True))
        self.assertFalse(result["image"]["disposal_confirmed"])
        probe.validate_result(result)

    def test_intake_custody_and_work_root_failure_propagate(self):
        def intake(transport, destination, *, environ):
            error = RuntimeError("intake")
            error.custody_retained = True
            raise error
        self.rii.prepare_pinned_runtime_inputs = intake
        result = self.run_host()
        self.assertEqual((result["refusal"], result["image"]["stage"], result["custody_retained"]),
                         ("IMAGE_PREPARE_FAILED", "INTAKE", True))
        self.tearDown()
        self.setUp()
        original = self.sib.execute_signing_image_build

        def nested_build(**kw):
            os.mkdir(kw["work_root"] / "nested")
            return original(**kw)
        self.sib.execute_signing_image_build = nested_build
        result = self.run_host()
        self.assertEqual((result["refusal"], result["custody_retained"]), ("WORK_ROOT_CLEANUP_FAILED", True))
        self.assertEqual(self.runner.calls, [])
        self.assertIn("dispose", self.events)

    def test_production_byte_change_refused_before_any_effect(self):
        path = self.p / "tools/verification/current_import_routing.py"
        path.write_bytes(path.read_bytes() + b"\n")
        result = self.run_host()
        self.assertEqual((result["refusal"], self.runner.calls, self.events), ("PRODUCTION_PINS_CHANGED", [], []))

    def test_lifecycle_teardown_failure_is_not_diagnostic_complete(self):
        self.runner = FakeRunner({("network", "rm"): (1, b"", b"")})
        result = self.run_host()
        self.assertEqual((result["status"], result["refusal"], result["custody_retained"]),
                         ("refused", "TEARDOWN_UNCONFIRMED", True))
        self.assertIn("dispose", self.events)


class Invariants(unittest.TestCase):
    def test_only_new_paths_and_production_pins_hold(self):
        new = [".github/workflows/probe-current-signer-isolation.yml",
               "tools/verification/isolation_probe/current_signer_isolation_probe.py",
               "tools/verification/isolation_probe/test_current_signer_isolation_probe.py"]
        for relative in new:
            path = PROPOSAL_ROOT / relative
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
        if P_ROOT != PROPOSAL_ROOT:
            self.assertFalse([rel for rel in new if (P_ROOT / rel).exists()])
        for rel, digest in probe.PRODUCTION_PINS.items():
            self.assertEqual(hashlib.sha256((P_ROOT / rel).read_bytes()).hexdigest(), digest, rel)
        manifest = json.loads((P_ROOT / probe.LEAF_MANIFEST_REL_PATH).read_bytes())
        self.assertFalse([rel for rel in new if rel in manifest["files"] or rel in manifest["excluded_acyclic_roots"]])

    def test_no_signing_leaf_is_loaded_or_importable(self):
        self.assertFalse(probe.FORBIDDEN_LEAVES & set(sys.modules))
        with self.assertRaises(ImportError):
            __import__("secret_frame_transport")
        with self.assertRaises(probe.ProbeRefusal):
            probe.load_production_leaves(P_ROOT, ("owned_gpg_agent",))

    def test_probe_source_has_no_signing_secret_or_frame_operations(self):
        tree = ast.parse(PROBE_FILE.read_text())
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                    for alias in node.names} | {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse(imported & (probe.FORBIDDEN_LEAVES | {"subprocess", "socket", "urllib", "http"}))
        names = {getattr(node, "attr", None) or getattr(node, "id", None) for node in ast.walk(tree)}
        for banned in ("_default_frame_emitter", "capture_frame", "execute_live_lease", "read_secret_frame",
                       "emit_existing_frame_and_eof", "HostGate", "encode_message", "worker_acknowledgement",
                       "_run_gate_session", "execute_host_controller", "build_default_bridge_run_argv",
                       "owned_container_remove_command_by_name"):
            self.assertNotIn(banned, names)
        self.assertNotIn("PACKAGE_SIGNING", PROBE_FILE.read_text())

    def test_workflow_is_key_free_and_bounded(self):
        text = WORKFLOW_FILE.read_text()
        for banned in ("secrets.", "environment:", "PACKAGE_SIGNING", "pull_request", "id-token", "contents: write",
                       "--current-signer-host", "--current-signer-publish", "deploy-pages", "upload-pages"):
            self.assertNotIn(banned, text)
        self.assertEqual(text.count("GH_TOKEN: ${{ github.token }}"), 1)
        self.assertIn("permissions: {}", text)
        job_permissions = text.split("    permissions:\n", 1)[1].split("    defaults:", 1)[0]
        self.assertEqual([line.strip() for line in job_permissions.splitlines() if line.strip() and not line.strip().startswith("#")],
                         ["contents: read", "actions: read"])
        for line in text.splitlines():
            if "uses:" in line:
                self.assertRegex(line.strip(), r"^(- )?uses: [A-Za-z0-9_.\-/]+@[0-9a-f]{40}$")
        # The hosted run selects default-bridge explicitly, after the pure suite; bounds unchanged.
        self.assertEqual(text.count("--network-profile default-bridge"), 1)
        self.assertNotIn("custom-bridge", text)
        self.assertLess(text.index("test_current_signer_isolation_probe.py"), text.index("--network-profile default-bridge"))
        for kept in ("timeout-minutes: 90", "retention-days: 7", "runs-on: ubuntu-24.04", "github.run_attempt == 1",
                     "github.ref == 'refs/heads/main'"):
            self.assertIn(kept, text)


# --------------------------------------------------------------------------
# default-bridge profile: fakes only, real authenticated core helpers
# --------------------------------------------------------------------------
BRIDGE_ID, OWNED_ID, FOREIGN_ID = "b" * 64, "d" * 64, "e" * 64
RUN_SUFFIX = "41728995205"
CONTAINER = f"tf-current-signer-{RUN_SUFFIX}-2"
OWNER_LABEL = gate.default_bridge_owner_label(RUN_SUFFIX, NONCE)
MUTATING = {("network", "create"), ("network", "rm"), ("network", "connect"), ("network", "disconnect"),
            ("network", "prune"), ("container", "rm"), ("rm", "-f")}


class BridgeDocker:
    """Stateful fake of the built-in bridge plus one --rm worker. Records argv; no native effect."""

    def __init__(self, *, overrides=None, bridge_extra=(), late_peers=(), owner_rows=None, name_preexisting=False,
                 marker="true", changed_id=None, stays_attached=False):
        self.events, self.calls, self.spawned = [], [], []
        self.overrides, self.bridge_extra, self.late_peers = dict(overrides or {}), tuple(bridge_extra), tuple(late_peers)
        self.owner_rows, self.name_preexisting, self.marker = owner_rows, name_preexisting, marker
        self.changed_id, self.stays_attached = changed_id, stays_attached
        self.alive = self.attached = False

    def spawn(self, argv, env):
        self.events.append("spawn")
        self.spawned.append((tuple(argv), dict(env)))
        self.alive = self.attached = True
        return object()

    def exited(self):  # Natural --rm removal once the observer exits.
        self.alive = self.attached = False

    def _bridge(self):
        peers = list(self.bridge_extra) + (list(self.late_peers) if self.spawned else []) + (
            [OWNED_ID] if self.attached else [])
        network_id = self.changed_id if self.changed_id and self.spawned else BRIDGE_ID
        doc = {"id": network_id, "name": "bridge", "driver": "bridge", "scope": "local", "internal": False,
               "default_marker": self.marker, "containers": {peer: {} for peer in peers}}
        return json.dumps(doc, separators=(",", ":")).encode() + b"\n"

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        self.events.append(("docker",) + argv[1:3])
        for prefix, response in self.overrides.items():
            if argv[1:1 + len(prefix)] == prefix:
                return response
        if argv == gate.default_bridge_inspect_command():
            return 0, self._bridge(), b""
        if argv == gate.owned_container_listing_command(CONTAINER, OWNER_LABEL):
            if self.owner_rows is not None and self.alive:
                return 0, self.owner_rows, b""
            return 0, ((OWNED_ID + "\n").encode() if self.alive else b""), b""
        if argv == gate.container_name_listing_command(CONTAINER):
            row = FOREIGN_ID if self.name_preexisting else (OWNED_ID if self.alive else None)
            return 0, ((row + "\n").encode() if row else b""), b""
        if argv == gate.worker_networks_command(OWNED_ID):
            body = {"bridge": {"NetworkID": BRIDGE_ID}} if self.attached or self.stays_attached else {}
            return 0, json.dumps(body).encode() + b"\n", b""
        if argv == gate.default_bridge_gate_commands(BRIDGE_ID, OWNED_ID)[0]:
            self.attached = False
            return 0, b"", b""
        if argv == gate.owned_container_remove_command(OWNED_ID):
            self.alive = self.attached = False
            return 0, OWNED_ID.encode() + b"\n", b""
        return 1, b"", b"unexpected"


class BridgeSession(FakeSession):
    def __init__(self, docker, lines, **kw):
        super().__init__(lines, **kw)
        self.docker = docker

    def write_stdin(self, payload, *, close_after=False):
        self.docker.events.append("challenge")
        super().write_stdin(payload, close_after=close_after)

    def wait_for_exit(self):
        self.docker.exited()
        return self.exit_code


class SpyController:
    """Delegates to the real authenticated controller; records which helpers are reached."""
    TRACKED = frozenset({"_default_bridge_preflight", "_prepare_default_bridge_disconnect",
                         "_teardown_default_bridge_session", "_default_bridge_teardown_uncertain",
                         "_teardown_host_session", "_run_gate_session", "execute_host_controller",
                         "build_default_bridge_run_argv"})

    def __init__(self, events, replace=None):
        self._events, self._replace, self.teardown_seen = events, dict(replace or {}), None

    def __getattr__(self, name):
        real = self._replace[name] if name in self._replace else getattr(hc, name)
        if name not in self.TRACKED:
            return real

        def tracked(*args, **kwargs):
            self._events.append(name)
            if name == "_default_bridge_teardown_uncertain":
                self.teardown_seen = dict(args[0])
            return real(*args, **kwargs)
        return tracked


def default_lifecycle(docker, session, replace=None):
    spy = SpyController(docker.events, replace)
    out = probe.run_default_lifecycle(
        run_suffix=RUN_SUFFIX, image_id="sha256:" + "ab" * 32, container_python="/usr/bin/python3",
        p_dir=Path("/home/runner/work/p"), mods=dict(PROD, signer_host_controller=spy), runner=docker,
        spawner=lambda argv, env: docker.spawn(argv, env), session_factory=lambda proc, deadline, err: session,
        nonce=NONCE, uid=1001, gid=118)
    return out, spy


def mutations(docker):
    return [call for call in docker.calls if call[1:3] in MUTATING]


class DefaultBridgeLifecycle(unittest.TestCase):
    def run_case(self, *, replace=None, lines=(READY, RESULT), **docker_kw):
        docker = BridgeDocker(**docker_kw)
        session = BridgeSession(docker, list(lines))
        out, spy = default_lifecycle(docker, session, replace)
        return out, docker, session, spy

    def test_core_helpers_in_order_bridge_preserved_and_nothing_raw(self):
        out, docker, session, spy = self.run_case()
        self.assertEqual((out["refusal"], out["custody_retained"], out["ownership_pinned"], out["bridge_gate_code"]),
                         ("NONE", False, True, "NONE"))
        self.assertTrue(all(value == "OK" for value in out["steps"].values()))
        ev = docker.events
        order = [e for e in ev if e in ("_default_bridge_preflight", "spawn", "_prepare_default_bridge_disconnect",
                                        "challenge", "_teardown_default_bridge_session",
                                        "_default_bridge_teardown_uncertain")]
        self.assertEqual(order, ["_default_bridge_preflight", "spawn", "_prepare_default_bridge_disconnect", "challenge",
                                 "_teardown_default_bridge_session", "_default_bridge_teardown_uncertain"])
        detach = ev.index(("docker", "network", "disconnect"))
        self.assertLess(ev.index("_prepare_default_bridge_disconnect"), detach)
        self.assertLess(detach, ev.index("challenge"))
        # The only mutation is detaching the resolved owned endpoint from the captured bridge ID.
        self.assertEqual(mutations(docker), [gate.default_bridge_gate_commands(BRIDGE_ID, OWNED_ID)[0]])
        tear = out["teardown"]
        self.assertEqual((tear["network_removed"], tear["builtin_bridge_preserved"], tear["owner_custody"],
                          tear["container_force_remove_attempted"], tear["owned_worker_endpoint_mutation_attempted"]),
                         (False, True, "absent", False, True))
        self.assertIs(spy.teardown_seen["frame_capture_custody_retained"], False)
        for banned in ("_teardown_host_session", "_run_gate_session", "execute_host_controller",
                       "build_default_bridge_run_argv"):
            self.assertNotIn(banned, ev)
        self.assertEqual(session.writes, [(probe.encode_line("challenge", NONCE), True)])
        text = json.dumps(out)
        for raw in (BRIDGE_ID, OWNED_ID, OWNER_LABEL, CONTAINER):
            self.assertNotIn(raw, text)

    def test_argv_is_label_bound_secret_free_and_profile_exact(self):
        _, docker, _, _ = self.run_case()
        argv, env = docker.spawned[0]
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        self.assertEqual(argv[argv.index("--network") + 1], "bridge")
        self.assertEqual(argv[argv.index("--label") + 1], f"{gate.OWNER_LABEL_KEY}={OWNER_LABEL}")
        self.assertFalse({"-e", "--env", "--env-file", "GH_TOKEN", "-v", "--privileged"} & set(argv))
        self.assertFalse(any(m in t.upper() for t in argv for m in ("TOKEN", "GPG", "SIGNING", "SECRET", "PASSPHRASE")))
        kw = dict(container=CONTAINER, owner_label=OWNER_LABEL)
        probe.validate_observer_argv(argv, hc, **kw)
        i, lab = argv.index("--rm") + 1, argv.index("--label")
        bad_argvs = [
            tuple(f"{gate.OWNER_LABEL_KEY}={'f' * 64}" if t == argv[lab + 1] else t for t in argv),
            argv[:i] + ("--label", argv[lab + 1]) + argv[i:], argv[:lab] + argv[lab + 2:],
            tuple("tf-current-signer-1-1" if t == "bridge" else t for t in argv),
            argv[:i] + ("-e", "GH_TOKEN") + argv[i:], argv[:i] + ("--label-file", "/tmp/x") + argv[i:],
            argv[:i] + ("--network=host",) + argv[i:], tuple("other-name-2" if t == CONTAINER else t for t in argv),
        ]
        for bad in bad_argvs:
            with self.assertRaises(probe.ProbeRefusal):
                probe.validate_observer_argv(bad, hc, **kw)
        with self.assertRaises(probe.ProbeRefusal):  # custom profile never carries a label or the built-in bridge
            probe.validate_observer_argv(argv, hc)

    def test_preflight_refusal_never_spawns_mutates_or_tears_down(self):
        cases = ((dict(bridge_extra=(FOREIGN_ID,)), "BRIDGE_PEER_PRESENT"),
                 (dict(name_preexisting=True), "CONTAINER_NAME_COLLISION"),
                 (dict(marker="false"), "BRIDGE_IDENTITY_MISMATCH"),
                 (dict(overrides={("network", "inspect"): (1, b"", b"raw daemon text")}), "DOCKER_COMMAND_FAILED"))
        for kw, code in cases:
            out, docker, _, _ = self.run_case(**kw)
            self.assertEqual((out["refusal"], out["bridge_gate_code"]), ("BRIDGE_PREFLIGHT_REFUSED", code), code)
            self.assertEqual((docker.spawned, mutations(docker)), ([], []), code)
            self.assertNotIn("_teardown_default_bridge_session", docker.events, code)
            self.assertEqual((out["custody_retained"], out["teardown"]["owner_custody"]), (False, "NOT_RUN"), code)

    def test_foreign_ambiguous_or_malformed_ownership_never_detaches_or_removes_foreign(self):
        cases = ((dict(owner_rows=f"{OWNED_ID}\n{FOREIGN_ID}\n".encode()), "OWNER_LOOKUP_AMBIGUOUS", False),
                 (dict(owner_rows=b""), "OWNER_LOOKUP_EMPTY", False),
                 (dict(owner_rows=b"not-an-id\n"), "CONTAINER_LISTING_FORMAT", False),
                 (dict(late_peers=(FOREIGN_ID,)), "BRIDGE_PEER_PRESENT", True),
                 (dict(changed_id="f" * 64), "BRIDGE_IDENTITY_CHANGED", True))
        for kw, code, owned_removed in cases:
            out, docker, session, _ = self.run_case(**kw)
            self.assertEqual((out["refusal"], out["bridge_gate_code"], out["ownership_pinned"]),
                             ("OWNERSHIP_NOT_PROVEN", code, False), code)
            self.assertNotIn(("docker", "network", "disconnect"), docker.events, code)
            self.assertEqual(session.writes, [], code)
            removals = [call for call in docker.calls if call[1:3] == ("container", "rm")]
            self.assertEqual(removals, [gate.owned_container_remove_command(OWNED_ID)] if owned_removed else [], code)
            self.assertTrue(out["teardown"]["teardown_run"], code)
            self.assertFalse(out["teardown"]["network_removed"], code)
            if not owned_removed or code == "BRIDGE_IDENTITY_CHANGED":
                self.assertTrue(out["custody_retained"], code)

    def test_detach_not_confirmed_stops_before_challenge_and_removes_only_owned_id(self):
        out, docker, session, _ = self.run_case(stays_attached=True)
        self.assertEqual((out["refusal"], out["detached_readback"]), ("DETACH_NOT_CONFIRMED", "NETWORK_ATTACHED"))
        self.assertEqual((session.writes, out["after_disconnect"]), ([], None))
        self.assertEqual([call for call in docker.calls if call[1:3] == ("container", "rm")],
                         [gate.owned_container_remove_command(OWNED_ID)])
        self.assertTrue(out["teardown"]["builtin_bridge_preserved"])

    def test_spawn_failure_is_uncertain_and_still_runs_owned_teardown(self):
        docker = BridgeDocker()

        def failing(argv, env):
            docker.events.append("spawn")
            raise OSError("raw spawn text")
        docker.spawn = failing
        out, _ = default_lifecycle(docker, BridgeSession(docker, [READY, RESULT]))
        self.assertEqual((out["refusal"], out["custody_retained"]), ("CONTAINER_SPAWN_FAILED", True))
        self.assertTrue(out["teardown"]["teardown_run"] and out["teardown"]["spawn_outcome_uncertain"])
        self.assertEqual(mutations(docker), [])

    def test_unlisted_network_or_foreign_mutation_is_refused_before_the_runner(self):
        real = hc._teardown_default_bridge_session

        def widened(session, container, label, bridge_id, runner, **kw):
            runner((probe.DOCKER, "network", "rm", "bridge"), 30.0)
            runner((probe.DOCKER, "network", "connect", "bridge", OWNED_ID), 30.0)
            runner((probe.DOCKER, "container", "rm", "--force", FOREIGN_ID), 30.0)
            runner((probe.DOCKER, "rm", "-f", CONTAINER), 30.0)
            return real(session, container, label, bridge_id, runner, **kw)
        out, docker, _, _ = self.run_case(replace={"_teardown_default_bridge_session": widened})
        self.assertEqual(mutations(docker), [gate.default_bridge_gate_commands(BRIDGE_ID, OWNED_ID)[0]])
        self.assertEqual((out["refusal"], out["command_guard_refused"], out["custody_retained"]),
                         ("COMMAND_NOT_ALLOWED", True, True))

    def test_custom_profile_stays_legacy_and_never_reaches_default_helpers(self):
        events, spawned, runner = [], [], FakeRunner()
        out = probe.run_lifecycle(
            run_suffix=RUN_SUFFIX, image_id="sha256:" + "ab" * 32, container_python="/usr/bin/python3",
            p_dir=Path("/home/runner/work/p"), mods=dict(PROD, signer_host_controller=SpyController(events)),
            runner=runner, spawner=lambda argv, env: spawned.append(argv) or object(),
            session_factory=lambda proc, deadline, err: FakeSession([READY, RESULT]), nonce=NONCE, uid=1001, gid=118)
        self.assertEqual((out["refusal"], events), ("NONE", ["_teardown_host_session"]))
        self.assertFalse({"--label", "bridge"} & set(spawned[0]))
        self.assertEqual(runner.kinds()[0], "network create")

    def test_closed_local_copies_match_loaded_core_leaf(self):
        self.assertEqual(probe.DEFAULT_BRIDGE_GATE_CODES, gate.DEFAULT_BRIDGE_ERROR_CODES)
        self.assertEqual((probe.OWNER_LABEL_KEY, probe.DEFAULT_BRIDGE_NETWORK),
                         (gate.OWNER_LABEL_KEY, gate.DEFAULT_BRIDGE_NAME))


class DefaultBridgeEndToEnd(unittest.TestCase):
    setUp, tearDown, _build, _dispose = HostEndToEnd.setUp, HostEndToEnd.tearDown, HostEndToEnd._build, HostEndToEnd._dispose
    git, run_host = HostEndToEnd.git, HostEndToEnd.run_host

    def run_default(self, **docker_kw):
        docker = BridgeDocker(**docker_kw)
        self.session = BridgeSession(docker, [READY, RESULT])
        return self.run_host(network_profile="default-bridge", runner=docker,
                             spawner=lambda argv, env: docker.spawn(argv, env)), docker

    def test_end_to_end_closed_v2_result_without_raw_identifiers(self):
        result, docker = self.run_default()
        self.assertEqual((result["status"], result["refusal"], result["network_profile"]),
                         ("diagnostic-complete", "NONE", "default-bridge"))
        self.assertEqual(probe.validate_result(result)["schema"], "tf.current-signer-isolation-probe-result.v2")
        self.assertEqual(self.events.count("dispose"), 1)
        self.assertFalse((self.tmp / "image-work").exists())
        out = self.tmp / "out" / "RESULT.json"
        probe.write_result(out, result)
        text = out.read_text()
        for raw in (BRIDGE_ID, OWNED_ID, OWNER_LABEL, "tf-current-signer-", "ghs_fixture", str(self.tmp)):
            self.assertNotIn(raw, text)
        self.assertFalse(any("ghs_fixture" in token for token in docker.spawned[0][0]))

    def test_refused_preflight_result_is_valid_and_image_still_disposed(self):
        result, docker = self.run_default(bridge_extra=(FOREIGN_ID,))
        self.assertEqual((result["status"], result["refusal"], result["custody_retained"]),
                         ("refused", "BRIDGE_PREFLIGHT_REFUSED", False))
        self.assertEqual((docker.spawned, self.events.count("dispose")), ([], 1))
        probe.validate_result(result)

    def test_complete_default_result_refuses_invalid_combinations(self):
        result, _ = self.run_default()
        for path, value in (
            (("lifecycle", "teardown", "network_removed"), True),
            (("lifecycle", "teardown", "builtin_bridge_preserved"), False),
            (("lifecycle", "teardown", "frame_capture_custody_retained"), True),
            (("lifecycle", "teardown", "unexpected_bridge_peer_observed"), True),
            (("lifecycle", "teardown", "owner_custody"), "ambiguous"),
            (("lifecycle", "teardown", "owner_custody"), OWNED_ID),
            (("lifecycle", "teardown", "removal_by_immutable_id_only"), False),
            (("lifecycle", "teardown", "teardown_run"), False),
            (("lifecycle", "teardown", "container_force_removed"), "yes"),
            (("lifecycle", "ownership_pinned"), False),
            (("lifecycle", "command_guard_refused"), True),
            (("lifecycle", "bridge_gate_code"), "BRIDGE_PEER_PRESENT"),
            (("lifecycle", "bridge_gate_code"), "Error response from daemon"),
            (("lifecycle", "steps", "ownership"), "NOT_REACHED"),
            (("lifecycle", "owned_id"), OWNED_ID),
            (("network_profile",), "custom-bridge"),
            (("network_profile",), "host"),
            (("image", "image_id_removed"), False),
        ):
            changed = json.loads(json.dumps(result))
            cursor = changed
            for name in path[:-1]:
                cursor = cursor[name]
            cursor[path[-1]] = value
            with self.assertRaises(probe.ProbeRefusal, msg=str(path)):
                probe.validate_result(changed)
        # The previous run consumed its host token and observer lines.
        # Build a fresh successful custom-profile fixture before crossing profiles.
        self.env = dict(GOOD_ENV)
        self.session = FakeSession([READY, RESULT])
        self.runner = FakeRunner()
        mixed = json.loads(json.dumps(self.run_host()))
        self.assertEqual(mixed["status"], "diagnostic-complete")
        mixed["network_profile"] = "default-bridge"
        with self.assertRaises(probe.ProbeRefusal):
            probe.validate_result(mixed)


class HostArguments(unittest.TestCase):
    def test_network_profile_has_two_closed_choices_and_legacy_default(self):
        base = ["--p-root", "/p", "--p-commit", "1" * 40, "--work-root", "/w", "--result-out", "/r/RESULT.json"]
        self.assertEqual(probe.parse_host_args(base).network_profile, "custom-bridge")
        self.assertEqual(probe.parse_host_args(base + ["--network-profile", "default-bridge"]).network_profile,
                         "default-bridge")
        for bad in (["--network-profile", "host"], ["--network-profile", "none"], ["--network-profile"],
                    ["--network-prof", "default-bridge"]):
            with self.assertRaises(SystemExit):
                probe.parse_host_args(base + bad)
        with self.assertRaises(ValueError):
            probe.execute_host(p_root="/p", p_commit="1" * 40, work_root="/w", environ={}, network_profile="host")


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=1)
    outcome = runner.run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
