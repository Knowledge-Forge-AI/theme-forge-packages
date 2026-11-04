"""Built-in default-bridge production controller path: pure unittest only.

Fake Docker runners and fake sessions record every argv and event. Nothing here
starts Docker, touches a network, runs GPG/Git, or executes native tools. Pure
acceptance is not native isolation qualification.
"""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
LEAF_DIR = ROOT / "tools/verification/current_signer"
sys.path.insert(0, str(LEAF_DIR))
import signer_host_controller as host  # noqa: E402
import signer_protocol_io as protocol  # noqa: E402
import signing_network_gate as network_gate  # noqa: E402

DOCKER = "/usr/bin/docker"
NONCE = "6" * 64
SUFFIX = "123"
NAME = "tf-current-signer-123-2"
CUSTOM_NETWORK = "tf-current-signer-123-1"
BRIDGE_ID = "b" * 64
CHANGED_BRIDGE_ID = "c" * 64
OWNED_ID = "a" * 64
FOREIGN_ID = "f" * 64
PRIVATE_STDERR = b"PRIVATE_DOCKER_STDERR /private/fixture/path"
BINDING = network_gate.SourceBinding("1" * 40, "2" * 40, "3" * 40, "4" * 40, "5" * 64, 123)
READY = network_gate.encode_message("ready", BINDING, NONCE, worker_pid=77)
ACK = network_gate.encode_message("isolated", BINDING, NONCE, worker_pid=77)
EXPECTED_LABEL = hashlib.sha256(
    b"tf.current-signer.default-bridge.owner-label.v1\x00" + SUFFIX.encode("ascii") + NONCE.encode("ascii")
).hexdigest()
DETACHED = b"{}\n"
LEAK_SENTINELS = (OWNED_ID, BRIDGE_ID, CHANGED_BRIDGE_ID, FOREIGN_ID, EXPECTED_LABEL, "PRIVATE", "/fixture",
                  "fixture-signing-material", "fixture-passphrase", "fixture-online-token")


def config(**changes):
    values = dict(
        p_root=Path("/fixture/p"), r_root=Path("/fixture/r"), export_root=Path("/fixture/export"),
        p_commit="1" * 40, p_tree="2" * 40, r_commit="3" * 40, r_tree="4" * 40, source_closure_sha256="5" * 64,
        rs9_run=123, challenge_nonce=NONCE, run_id_suffix=SUFFIX, container_image="sha256:" + "7" * 64,
        container_python="/usr/bin/python3", expected_gpg_sha256="8" * 64, expected_rpm_sha256="9" * 64,
        release_date="Tue, 03 Nov 2026 00:00:00 +0000",
    )
    values.update(changes)
    return host.HostControllerConfig(**values)


def bridge(*peer_ids, **changes):
    doc = {"id": BRIDGE_ID, "name": "bridge", "driver": "bridge", "scope": "local", "internal": False,
           "default_marker": "true",
           "containers": {peer: {"Name": "peer", "EndpointID": "e" * 64} for peer in peer_ids}}
    doc.update(changes)
    return json.dumps(doc, separators=(",", ":")).encode("ascii") + b"\n"


def attached(network_id=BRIDGE_ID, name="bridge", **extra):
    networks = {name: {"NetworkID": network_id, "IPAddress": "172.17.0.2"}}
    networks.update(extra)
    return json.dumps(networks).encode("ascii") + b"\n"


def listing(*ids):
    return b"".join(value.encode("ascii") + b"\n" for value in ids)


def code_of(error):
    return getattr(error, "code", None)


class FakeDocker:
    """Scripted runner. Queue items: bytes (rc 0), int rc, or an exception. The last item repeats."""

    KINDS = ("bridge", "name", "owner", "inspect", "disconnect", "rm")

    def __init__(self, events=None, **queues):
        self.events = events if events is not None else []
        self.calls = []
        self.unexpected = []
        self.queues = {kind: list(queues.get(kind, ())) for kind in self.KINDS}
        for kind in ("disconnect", "rm"):
            if kind not in queues:
                self.queues[kind] = [0]

    @staticmethod
    def kind(argv):
        head = tuple(argv[1:3])
        if head == ("network", "inspect"):
            return "bridge"
        if head == ("container", "ls"):
            return "owner" if any(token.startswith("label=") for token in argv) else "name"
        if head == ("container", "inspect"):
            return "inspect"
        if head == ("network", "disconnect"):
            return "disconnect"
        if head == ("container", "rm"):
            return "rm"
        return "other"

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        kind = self.kind(argv)
        self.events.append(("docker", kind))
        queue = self.queues.get(kind)
        if not queue:
            self.unexpected.append(kind)
            raise AssertionError("unscripted docker call")
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, bytes):
            return 0, item, b""
        return item, b"", (PRIVATE_STDERR if item else b"")

    def kinds(self):
        return [self.kind(call) for call in self.calls]


def happy(events=None, **overrides):
    queues = dict(bridge=[bridge(), bridge(OWNED_ID), bridge()], name=[b""],
                  owner=[listing(OWNED_ID), b""], inspect=[attached(), DETACHED])
    queues.update(overrides)
    return FakeDocker(events, **queues)


class FakeSession:
    def __init__(self, lines, events, *, exit_code=0, cleanup_uncertain=False):
        self.lines = list(lines)
        self.events = events
        self.writes = []
        self.exit_code = exit_code
        self.cleanup_uncertain = cleanup_uncertain
        self.stderr_buf = b""
        self.deadline = 0.0

    def read_protocol_line(self):
        self.events.append(("read",))
        return self.lines.pop(0) if self.lines else b""

    def write_stdin(self, data, close_after):
        self.events.append(("write", close_after))
        self.writes.append(bytes(data))

    def require_no_extra_stdout(self):
        pass

    def wait_for_exit(self):
        self.events.append(("wait",))
        return self.exit_code

    def require_stdout_clean_eof(self):
        pass

    def terminate_and_close(self):
        self.events.append(("close",))


class Harness(unittest.TestCase):
    def setUp(self):
        host._RETAINED_HOST_SESSIONS.clear()

    def tearDown(self):
        host._RETAINED_HOST_SESSIONS.clear()

    def run_controller(self, fake, lines=(READY, ACK), *, spawn_error=None, frame_retained=False,
                       session_uncertain=False):
        events = fake.events
        session = FakeSession(lines, events, cleanup_uncertain=session_uncertain)
        emitted, spawned = [], []

        def emitter():
            events.append(("emit",))
            emitted.append(True)
            return bytearray(b"FIXTURE-FRAME")

        def spawner(argv, env):
            events.append(("spawn",))
            spawned.append((tuple(argv), dict(env)))
            if spawn_error is not None:
                raise spawn_error
            return object()

        hooks = host.HostControllerHooks(docker_cmd_runner=fake, worker_spawner=spawner, frame_emitter=emitter)
        host_env = {"GH_TOKEN": "fixture-online-token", "PACKAGE_SIGNING_KEY": "fixture-signing-material",
                    "PACKAGE_SIGNING_PASSPHRASE": "fixture-passphrase"}
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(host, "_authenticate_host_sources", return_value=(
                Path("/fixture/p"), Path("/fixture/r"), Path("/fixture/export"), {})))
            stack.enter_context(mock.patch.object(host, "physical_dir", side_effect=lambda path, label: Path(path)))
            stack.enter_context(mock.patch.object(host, "scoped_git_env", return_value={"PATH": "/usr/bin:/bin"}))
            stack.enter_context(mock.patch.object(
                protocol, "ForegroundContainerSession", side_effect=lambda proc, deadline, error: session))
            stack.enter_context(mock.patch.object(protocol, "validate_frame_bytes", side_effect=lambda data, error: None))
            stack.enter_context(mock.patch.object(host, "_verify_exported_artifacts", return_value={
                "c6_agent_and_private_work_cleanup_confirmed": True}))
            stack.enter_context(mock.patch.object(host, "_frame_custody_retained", return_value=frame_retained))
            stack.enter_context(mock.patch.dict(os.environ, host_env))
            try:
                result, error = host.execute_host_controller(config(), hooks=hooks), None
            except BaseException as caught:  # noqa: BLE001 - recorded for assertions
                result, error = None, caught
        return types.SimpleNamespace(result=result, error=error, events=events, emitted=emitted,
                                     spawned=spawned, session=session, fake=fake)

    def assert_no_leak(self, error):
        text = str(error)
        for sentinel in LEAK_SENTINELS:
            self.assertNotIn(sentinel, text)

    def assert_removal_only_by_owned_id(self, fake):
        for call in fake.calls:
            if FakeDocker.kind(call) == "rm":
                self.assertEqual(call, (DOCKER, "container", "rm", "--force", OWNED_ID))
            self.assertNotIn(call[1:3], {("network", "create"), ("network", "rm"), ("network", "connect")})
            if call[1:3] == ("container", "rm") or call[1:2] == ("rm",):
                self.assertNotIn(NAME, call)

    def assert_no_frame(self, run):
        self.assertEqual(run.emitted, [])
        self.assertNotIn(("write", True), run.events)


class BridgeIdentityParsingTests(unittest.TestCase):
    def test_valid_identity_is_internal_only(self):
        observation = network_gate.require_default_bridge_identity(bridge(OWNED_ID))
        self.assertEqual(observation.network_id, BRIDGE_ID)
        self.assertEqual(observation.peer_ids, frozenset({OWNED_ID}))
        self.assertNotIn(BRIDGE_ID, repr(observation))
        self.assertNotIn(OWNED_ID, repr(observation))

    def test_wrong_fields_and_types_refused(self):
        cases = [
            (dict(name="docker0"), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(name=None), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(driver="overlay"), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(scope="swarm"), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(internal=True), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(internal=0), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(internal=None), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(default_marker="false"), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(default_marker=""), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(default_marker=True), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(id="B" * 64), "BRIDGE_IDENTITY_FORMAT"),
            (dict(id="b" * 63), "BRIDGE_IDENTITY_FORMAT"),
            (dict(id="b" * 12), "BRIDGE_IDENTITY_FORMAT"),
            (dict(id=1), "BRIDGE_IDENTITY_FORMAT"),
            (dict(containers=None), "BRIDGE_IDENTITY_FORMAT"),
            (dict(containers=[]), "BRIDGE_IDENTITY_FORMAT"),
            (dict(containers={"ep-" + "e" * 61: {}}), "BRIDGE_IDENTITY_FORMAT"),
            (dict(containers={OWNED_ID: "peer"}), "BRIDGE_IDENTITY_FORMAT"),
            (dict(extra=1), "BRIDGE_IDENTITY_FORMAT"),
        ]
        for changes, expected in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.require_default_bridge_identity(bridge(**changes))
                self.assertEqual(caught.exception.code, expected)
        missing = json.loads(bridge())
        del missing["default_marker"]
        with self.assertRaises(network_gate.GateError) as caught:
            network_gate.require_default_bridge_identity(json.dumps(missing).encode() + b"\n")
        self.assertEqual(caught.exception.code, "BRIDGE_IDENTITY_FORMAT")

    def test_duplicate_keys_refused_at_every_depth(self):
        top = bridge().replace(b'"name":"bridge"', b'"name":"bridge","name":"bridge"')
        nested = bridge(OWNED_ID).replace(b'"Name":"peer"', b'"Name":"peer","Name":"other"')
        for data in (top, nested):
            with self.assertRaises(network_gate.GateError) as caught:
                network_gate.require_default_bridge_identity(data)
            self.assertEqual(caught.exception.code, "BRIDGE_IDENTITY_DUPLICATE")

    def test_size_framing_and_constants_refused(self):
        cases = [
            (b"{" + b" " * 5000 + b"}\n", "BRIDGE_IDENTITY_BOUND"),
            ("not-bytes", "BRIDGE_IDENTITY_BOUND"),
            (bridge()[:-1], "BRIDGE_IDENTITY_FORMAT"),
            (bridge() + bridge(), "BRIDGE_IDENTITY_FORMAT"),
            (bridge()[:-1] + b"\r\n", "BRIDGE_IDENTITY_FORMAT"),
            (b"", "BRIDGE_IDENTITY_FORMAT"),
            (b"null\n", "BRIDGE_IDENTITY_FORMAT"),
            (bridge().replace(b'"internal":false', b'"internal":NaN'), "BRIDGE_IDENTITY_FORMAT"),
            (bridge().replace(b'"local"', b'"l\xffcal"'), "BRIDGE_IDENTITY_FORMAT"),
        ]
        for data, expected in cases:
            with self.subTest(data=data[:40]):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.require_default_bridge_identity(data)
                self.assertEqual(caught.exception.code, expected)

    def test_captured_identity_compared_at_later_checkpoints(self):
        network_gate.require_default_bridge_identity(bridge(), expected_id=BRIDGE_ID)
        with self.assertRaises(network_gate.GateError) as caught:
            network_gate.require_default_bridge_identity(bridge(id=CHANGED_BRIDGE_ID), expected_id=BRIDGE_ID)
        self.assertEqual(caught.exception.code, "BRIDGE_IDENTITY_CHANGED")
        with self.assertRaises(network_gate.GateError) as caught:
            network_gate.require_default_bridge_identity(bridge(), expected_id="bridge")
        self.assertEqual(caught.exception.code, "BRIDGE_IDENTITY_FORMAT")

    def test_peer_requirements(self):
        network_gate.require_no_bridge_peers(network_gate.require_default_bridge_identity(bridge()))
        with self.assertRaises(network_gate.GateError) as caught:
            network_gate.require_no_bridge_peers(network_gate.require_default_bridge_identity(bridge(FOREIGN_ID)))
        self.assertEqual(caught.exception.code, "BRIDGE_PEER_PRESENT")
        cases = [((), "BRIDGE_OWNERSHIP_MISMATCH"), ((FOREIGN_ID,), "BRIDGE_OWNERSHIP_MISMATCH"),
                 ((OWNED_ID, FOREIGN_ID), "BRIDGE_PEER_PRESENT")]
        for peers, expected in cases:
            with self.subTest(peers=len(peers)):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.require_sole_owned_bridge_peer(
                        network_gate.require_default_bridge_identity(bridge(*peers)), OWNED_ID)
                self.assertEqual(caught.exception.code, expected)
        network_gate.require_sole_owned_bridge_peer(network_gate.require_default_bridge_identity(bridge(OWNED_ID)), OWNED_ID)

    def test_worker_network_readback_requires_exact_captured_bridge(self):
        network_gate.require_worker_on_default_bridge(attached(), BRIDGE_ID)
        cases = [
            (attached(CHANGED_BRIDGE_ID), "WORKER_NETWORK_MISMATCH"),
            (attached(name=CUSTOM_NETWORK), "WORKER_NETWORK_MISMATCH"),
            (attached(**{CUSTOM_NETWORK: {"NetworkID": FOREIGN_ID}}), "WORKER_NETWORK_MISMATCH"),
            (DETACHED, "WORKER_NETWORK_MISMATCH"),
            (b"null\n", "WORKER_NETWORK_MISMATCH"),
            (b'{"bridge":{}}\n', "WORKER_NETWORK_MISMATCH"),
            (attached().replace(b'"NetworkID"', b'"NetworkID": "x", "NetworkID"'), "WORKER_NETWORK_FORMAT"),
            (b"{" + b" " * 5000 + b"}\n", "WORKER_NETWORK_FORMAT"),
            (attached()[:-1], "WORKER_NETWORK_FORMAT"),
        ]
        for data, expected in cases:
            with self.subTest(data=data[:40]):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.require_worker_on_default_bridge(data, BRIDGE_ID)
                self.assertEqual(caught.exception.code, expected)


class OwnershipListingTests(unittest.TestCase):
    def test_listing_parse(self):
        self.assertEqual(network_gate.parse_container_id_listing(b""), ())
        self.assertEqual(network_gate.parse_container_id_listing(listing(OWNED_ID)), (OWNED_ID,))
        self.assertEqual(network_gate.parse_container_id_listing(listing(OWNED_ID, FOREIGN_ID)), (OWNED_ID, FOREIGN_ID))
        oversized = listing(*(format(index, "064x") for index in range(70)))
        for data in [b"\n", listing("A" * 64), OWNED_ID.encode(), listing(OWNED_ID, OWNED_ID), listing("a" * 12),
                     listing("a" * 63), listing(OWNED_ID)[:-1] + b"\r\n", oversized, "not-bytes",
                     listing(OWNED_ID) + b"\n", NAME.encode() + b"\n"]:
            with self.subTest(data=data[:40]):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.parse_container_id_listing(data)
                self.assertEqual(caught.exception.code, "CONTAINER_LISTING_FORMAT")

    def test_owner_lookup_zero_one_multiple(self):
        self.assertEqual(network_gate.require_single_owned_id((OWNED_ID,)), OWNED_ID)
        for ids, expected in [((), "OWNER_LOOKUP_EMPTY"), ((OWNED_ID, FOREIGN_ID), "OWNER_LOOKUP_AMBIGUOUS"),
                              ([OWNED_ID], "CONTAINER_LISTING_FORMAT"), (("x",), "CONTAINER_ID_FORMAT")]:
            with self.subTest(ids=ids):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.require_single_owned_id(ids)
                self.assertEqual(caught.exception.code, expected)

    def test_owner_label_is_run_and_nonce_bound(self):
        self.assertEqual(network_gate.default_bridge_owner_label(SUFFIX, NONCE), EXPECTED_LABEL)
        self.assertNotEqual(network_gate.default_bridge_owner_label("124", NONCE), EXPECTED_LABEL)
        self.assertNotEqual(network_gate.default_bridge_owner_label(SUFFIX, "7" * 64), EXPECTED_LABEL)
        for suffix, nonce in [("", NONCE), ("12a", NONCE), ("1" * 21, NONCE), (123, NONCE),
                              (SUFFIX, "A" * 64), (SUFFIX, "6" * 63), (SUFFIX, None)]:
            with self.subTest(suffix=suffix, nonce=str(nonce)[:8]):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.default_bridge_owner_label(suffix, nonce)
                self.assertEqual(caught.exception.code, "OWNER_LABEL_INPUT")

    def test_fixed_commands_bind_immutable_ids(self):
        self.assertEqual(network_gate.owned_container_listing_command(NAME, EXPECTED_LABEL), (
            DOCKER, "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", f"name=^/{NAME}$",
            "--filter", f"label=tf.current-signer.run={EXPECTED_LABEL}"))
        self.assertEqual(network_gate.container_name_listing_command(NAME), (
            DOCKER, "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", f"name=^/{NAME}$"))
        self.assertEqual(network_gate.owned_container_remove_command(OWNED_ID),
                         (DOCKER, "container", "rm", "--force", OWNED_ID))
        self.assertEqual(network_gate.default_bridge_gate_commands(BRIDGE_ID, OWNED_ID), (
            (DOCKER, "network", "disconnect", BRIDGE_ID, OWNED_ID),
            (DOCKER, "container", "inspect", "--format", "{{json .NetworkSettings.Networks}}", OWNED_ID)))
        inspect = network_gate.default_bridge_inspect_command()
        self.assertEqual(inspect[:4], (DOCKER, "network", "inspect", "--format"))
        self.assertEqual(inspect[-1], "bridge")
        self.assertIn('index .Options "com.docker.network.bridge.default_bridge"', inspect[4])
        for bad in (NAME, "A" * 64, "a" * 12, None):
            with self.subTest(bad=bad):
                with self.assertRaises(network_gate.GateError) as caught:
                    network_gate.owned_container_remove_command(bad)
                self.assertEqual(caught.exception.code, "CONTAINER_ID_FORMAT")
        for bad_bridge in ("bridge", "B" * 64):
            with self.assertRaises(network_gate.GateError):
                network_gate.default_bridge_gate_commands(bad_bridge, OWNED_ID)
        with self.assertRaises(network_gate.GateError) as caught:
            network_gate.container_name_listing_command("other-name")
        self.assertEqual(caught.exception.code, "RESOURCE_ID")
        with self.assertRaises(network_gate.GateError) as caught:
            network_gate.owned_container_listing_command(NAME, "not-a-label")
        self.assertEqual(caught.exception.code, "OWNER_LABEL_INPUT")


class ArgvTests(unittest.TestCase):
    def build(self, function, *args):
        with mock.patch.object(host, "physical_dir", side_effect=lambda path, label: Path(path)):
            return function(config(), *args)

    def test_generic_custom_network_argv_unchanged(self):
        uid, gid = os.getuid(), os.getgid()
        expected = (
            DOCKER, "run", "--rm", "-i", "--pull", "never", "--name", NAME, "--network", CUSTOM_NETWORK,
            "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", "type=bind,src=/fixture/p,dst=/work/p,readonly",
            "--mount", "type=bind,src=/fixture/r,dst=/work/r,readonly",
            "--mount", "type=bind,src=/fixture/export,dst=/work/export",
            "--tmpfs", f"/work/workspace:rw,exec,nosuid,nodev,mode=0700,uid={uid},gid={gid}",
            "-e", "GH_TOKEN", "sha256:" + "7" * 64,
            "/usr/bin/python3", "-I", "-B", "/work/p/tools/verification/current_import_routing.py",
            "--current-signer-worker",
            "--p-root", "/work/p", "--r-root", "/work/r", "--workspace-root", "/work/workspace",
            "--export-root", "/work/export",
            "--p-commit", "1" * 40, "--p-tree", "2" * 40, "--r-commit", "3" * 40, "--r-tree", "4" * 40,
            "--source-closure-sha256", "5" * 64, "--rs9-run", "123", "--challenge-nonce", NONCE,
            "--expected-gpg-sha256", "8" * 64, "--expected-rpm-sha256", "9" * 64,
            "--release-date", "Tue, 03 Nov 2026 00:00:00 +0000", "--zip-transport", "actions",
        )
        self.assertEqual(self.build(host.build_docker_run_argv, CUSTOM_NETWORK, NAME), expected)

    def test_default_argv_is_generic_plus_fixed_label_and_passes_hardening(self):
        default = self.build(host.build_default_bridge_run_argv, NAME, EXPECTED_LABEL)
        generic = self.build(host.build_docker_run_argv, "bridge", NAME)
        index = generic.index("--network")
        self.assertEqual(default, generic[:index + 2]
                         + ("--label", "tf.current-signer.run=" + EXPECTED_LABEL) + generic[index + 2:])
        host.validate_docker_run_argv(default)
        self.assertEqual(default.count("--network"), 1)
        self.assertEqual(default[default.index("--network") + 1], "bridge")
        self.assertNotIn("host", default)
        self.assertFalse(any("SIGNING" in token.upper() or "PASSPHRASE" in token.upper() for token in default))

    def test_default_argv_refuses_bad_label_and_selection_drift(self):
        with self.assertRaises(host.HostControllerError) as caught:
            self.build(host.build_default_bridge_run_argv, NAME, "A" * 64)
        self.assertEqual(caught.exception.code, "DEFAULT_BRIDGE_ARGV")
        good = self.build(host.build_default_bridge_run_argv, NAME, EXPECTED_LABEL)
        index = good.index("--label")
        drifted = [
            good[:index] + ("--network", CUSTOM_NETWORK) + good[index:],
            tuple(CUSTOM_NETWORK if position == good.index("--network") + 1 else token
                  for position, token in enumerate(good)),
            good[:index] + ("--label", "x=y") + good[index:],
            good[:index] + good[index + 2:],
            good[:index] + ("-e", "OTHER") + good[index:],
            good[:index] + ("--env-file", "/fixture/env") + good[index:],
        ]
        for argv in drifted:
            with self.subTest(argv=argv[index - 2:index + 3]):
                with self.assertRaises(host.HostControllerError) as caught:
                    host._require_default_bridge_argv(argv, NAME, EXPECTED_LABEL)
                self.assertEqual(caught.exception.code, "DEFAULT_BRIDGE_ARGV")

    def test_constants_agree_without_import_time_coupling(self):
        self.assertEqual(host._DEFAULT_BRIDGE_OWNER_LABEL_KEY, network_gate.OWNER_LABEL_KEY)
        self.assertEqual(host._DEFAULT_BRIDGE_NETWORK, network_gate.DEFAULT_BRIDGE_NAME)

    def test_worker_env_refuses_signing_secret_names(self):
        host._require_default_worker_env({"PATH": "/usr/bin", "GH_TOKEN": "fixture-online-token"})
        for key in ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE", "GPG_KEY"):
            with self.assertRaises(host.HostControllerError) as caught:
                host._require_default_worker_env({key: "x"})
            self.assertEqual(caught.exception.code, "DEFAULT_BRIDGE_WORKER_ENV")


class ControllerSuccessTests(Harness):
    def test_success_ordering_argv_and_teardown_receipt(self):
        fake = happy()
        run = self.run_controller(fake)
        self.assertIsNone(run.error)
        owner = network_gate.owned_container_listing_command(NAME, EXPECTED_LABEL)
        inspect_bridge = network_gate.default_bridge_inspect_command()
        readback = (DOCKER, "container", "inspect", "--format", "{{json .NetworkSettings.Networks}}", OWNED_ID)
        self.assertEqual(fake.calls, [
            inspect_bridge, network_gate.container_name_listing_command(NAME),
            owner, inspect_bridge, readback,
            (DOCKER, "network", "disconnect", BRIDGE_ID, OWNED_ID), readback,
            owner, owner, network_gate.container_name_listing_command(NAME), inspect_bridge,
        ])
        self.assertEqual(run.events, [
            ("docker", "bridge"), ("docker", "name"), ("spawn",), ("read",),
            ("docker", "owner"), ("docker", "bridge"), ("docker", "inspect"),
            ("docker", "disconnect"), ("docker", "inspect"),
            ("write", False), ("read",), ("emit",), ("write", True), ("wait",), ("close",),
            ("docker", "owner"), ("docker", "owner"), ("docker", "name"), ("docker", "bridge"),
        ])
        self.assertEqual(fake.unexpected, [])
        self.assert_removal_only_by_owned_id(fake)
        self.assertEqual(run.result["status"], "pass")
        teardown = run.result["host_container_and_network_teardown"]
        self.assertIs(teardown["network_removed"], False)
        self.assertIs(teardown["builtin_bridge_preserved"], True)
        self.assertIs(teardown["builtin_bridge_configuration_commands_issued"], False)
        self.assertIs(teardown["owned_worker_endpoint_mutation_attempted"], True)
        self.assertEqual(teardown["owner_custody"], "absent")
        self.assertIs(teardown["container_force_remove_attempted"], False)
        self.assertIs(teardown["container_absence_confirmed"], True)
        self.assertNotIn("network_mutation_none", json.dumps(teardown))
        self.assertEqual(host._RETAINED_HOST_SESSIONS, [])
        argv, env = run.spawned[0]
        self.assertIn(("--label", "tf.current-signer.run=" + EXPECTED_LABEL),
                      list(zip(argv, argv[1:])))
        self.assertEqual(argv[argv.index("--network") + 1], "bridge")
        self.assertEqual(env.get("GH_TOKEN"), "fixture-online-token")
        self.assertFalse(any("SIGNING" in key or "PASSPHRASE" in key for key in env))
        self.assertFalse(any("fixture-signing-material" in token or "fixture-passphrase" in token for token in argv))


class PreFrameRefusalTests(Harness):
    def check(self, fake, expected_code, *, lines=(READY, ACK), spawned=True):
        run = self.run_controller(fake, lines)
        self.assertIsNotNone(run.error)
        self.assertEqual(code_of(run.error), expected_code)
        self.assert_no_frame(run)
        self.assert_no_leak(run.error)
        self.assert_removal_only_by_owned_id(fake)
        self.assertEqual(bool(run.spawned), spawned)
        return run

    def test_preflight_refusals_never_spawn_or_delete(self):
        duplicate = bridge().replace(b'"driver":"bridge"', b'"driver":"bridge","driver":"bridge"')
        cases = [
            (dict(bridge=[bridge(name="docker0")]), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(bridge=[bridge(internal=True)]), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(bridge=[duplicate]), "BRIDGE_IDENTITY_DUPLICATE"),
            (dict(bridge=[b"{" + b" " * 5000 + b"}\n"]), "BRIDGE_IDENTITY_BOUND"),
            (dict(bridge=[bridge(FOREIGN_ID)]), "BRIDGE_PEER_PRESENT"),
            (dict(bridge=[1]), "DOCKER_BRIDGE_INSPECT"),
            (dict(name=[listing(FOREIGN_ID)]), "CONTAINER_NAME_COLLISION"),
            (dict(name=[b"junk\n"]), "CONTAINER_LISTING_FORMAT"),
            (dict(name=[1]), "DOCKER_CONTAINER_LIST"),
        ]
        for overrides, expected in cases:
            with self.subTest(expected=expected):
                fake = happy(**overrides)
                self.check(fake, expected, spawned=False)
                self.assertNotIn("rm", fake.kinds())
                self.assertNotIn("owner", fake.kinds())
                self.assertEqual(host._RETAINED_HOST_SESSIONS, [])

    def test_pre_disconnect_refusals_never_emit(self):
        cases = [
            (dict(owner=[b""]), "OWNER_LOOKUP_EMPTY"),
            (dict(owner=[listing(OWNED_ID, FOREIGN_ID)]), "OWNER_LOOKUP_AMBIGUOUS"),
            (dict(owner=[b"a" * 12 + b"\n"]), "CONTAINER_LISTING_FORMAT"),
            (dict(owner=[1]), "DOCKER_CONTAINER_LIST"),
            (dict(bridge=[bridge(), bridge(OWNED_ID, id=CHANGED_BRIDGE_ID)]), "BRIDGE_IDENTITY_CHANGED"),
            (dict(bridge=[bridge(), bridge(OWNED_ID, FOREIGN_ID), bridge()]), "BRIDGE_PEER_PRESENT"),
            (dict(bridge=[bridge(), bridge(FOREIGN_ID), bridge()]), "BRIDGE_OWNERSHIP_MISMATCH"),
            (dict(bridge=[bridge(), bridge(OWNED_ID, scope="global"), bridge()]), "BRIDGE_IDENTITY_MISMATCH"),
            (dict(inspect=[attached(CHANGED_BRIDGE_ID)]), "WORKER_NETWORK_MISMATCH"),
            (dict(inspect=[attached(name=CUSTOM_NETWORK)]), "WORKER_NETWORK_MISMATCH"),
            (dict(inspect=[1]), "DOCKER_WORKER_INSPECT"),
        ]
        for overrides, expected in cases:
            with self.subTest(expected=expected):
                host._RETAINED_HOST_SESSIONS.clear()
                fake = happy(**overrides)
                run = self.check(fake, expected)
                self.assertNotIn("disconnect", fake.kinds())
                self.assertEqual(run.error.handshake_observation["gate_phase"], "DISCONNECTING_NETWORK")

    def test_disconnect_readback_and_ack_refusals_never_emit(self):
        cases = [
            (dict(disconnect=[1]), (READY, ACK), "DOCKER_NETWORK_DISCONNECT"),
            (dict(inspect=[attached(), attached()]), (READY, ACK), "NETWORK_ATTACHED"),
            (dict(inspect=[attached(), 1]), (READY, ACK), "DOCKER_NETWORK_INSPECT"),
            ({}, (READY, b"garbage\n"), "MESSAGE_FORMAT"),
            ({}, (READY, READY), "MESSAGE_BINDING"),
        ]
        for overrides, lines, expected in cases:
            with self.subTest(expected=expected):
                host._RETAINED_HOST_SESSIONS.clear()
                self.check(happy(**overrides), expected, lines=lines)

    def test_ready_refusal_never_prepares_or_disconnects(self):
        fake = happy(owner=[b""])
        run = self.check(fake, "MESSAGE_FRAMING", lines=())
        kinds = fake.kinds()
        self.assertNotIn("disconnect", kinds)
        self.assertNotIn("inspect", kinds)
        # Only teardown queries follow the spawn: owner lookup, confirmation, name, bridge recheck.
        self.assertEqual(kinds, ["bridge", "name", "owner", "owner", "name", "bridge"])
        self.assertEqual(run.error.host_teardown["owner_custody"], "absent")


class CleanupCustodyTests(Harness):
    def test_spawn_failure_issues_zero_deletes_and_retains_uncertainty(self):
        fake = happy(owner=[b""])
        failure = OSError("fixture spawn failure")
        run = self.run_controller(fake, spawn_error=failure)
        self.assertIs(run.error, failure)
        self.assertNotIn("rm", fake.kinds())
        teardown = run.error.host_teardown
        self.assertIs(teardown["spawn_outcome_uncertain"], True)
        self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)
        self.assert_no_frame(run)

    def test_spawn_failure_with_owned_listing_deletes_only_by_id_and_still_retains(self):
        fake = happy(owner=[listing(OWNED_ID), b""])
        run = self.run_controller(fake, spawn_error=OSError("fixture spawn failure"))
        self.assertEqual([c for c in fake.calls if FakeDocker.kind(c) == "rm"],
                         [(DOCKER, "container", "rm", "--force", OWNED_ID)])
        self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)
        self.assert_removal_only_by_owned_id(fake)
        self.assertIs(run.error.host_teardown["spawn_outcome_uncertain"], True)

    def test_known_owned_cleanup_by_id_confirms_absence(self):
        # Ready refused: no pre-disconnect bridge read, so teardown sees the post-removal bridge.
        fake = happy(owner=[listing(OWNED_ID), b""], bridge=[bridge(), bridge()])
        run = self.run_controller(fake, lines=())
        self.assertEqual(code_of(run.error), "MESSAGE_FRAMING")
        teardown = run.error.host_teardown
        self.assertEqual(teardown["owner_custody"], "resolved")
        self.assertIs(teardown["container_force_removed"], True)
        self.assertIs(teardown["container_absence_confirmed"], True)
        self.assertIs(teardown["removal_by_immutable_id_only"], True)
        self.assertEqual([c for c in fake.calls if FakeDocker.kind(c) == "rm"],
                         [(DOCKER, "container", "rm", "--force", OWNED_ID)])
        self.assertEqual(host._RETAINED_HOST_SESSIONS, [])

    def test_ambiguous_malformed_unavailable_or_replaced_custody_never_deletes(self):
        cases = [
            (dict(owner=[listing(OWNED_ID, FOREIGN_ID)]), (), "ambiguous"),
            (dict(owner=[b"junk\n"]), (), "malformed"),
            (dict(owner=[1]), (), "unavailable"),
            (dict(owner=[RuntimeError("fixture runner failure")]), (), "unavailable"),
            (dict(owner=[listing(OWNED_ID), listing(FOREIGN_ID)], inspect=[attached(CHANGED_BRIDGE_ID)]),
             (READY, ACK), "mismatch"),
        ]
        for overrides, lines, custody in cases:
            with self.subTest(custody=custody):
                host._RETAINED_HOST_SESSIONS.clear()
                fake = happy(**overrides)
                run = self.run_controller(fake, lines=lines)
                self.assertIsNotNone(run.error)
                self.assertNotIn("rm", fake.kinds())
                teardown = run.error.host_teardown
                self.assertEqual(teardown["owner_custody"], custody)
                self.assertIs(teardown["container_absence_confirmed"], False)
                self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)
                self.assert_no_frame(run)

    def test_remove_failure_retains(self):
        fake = happy(owner=[listing(OWNED_ID)], rm=[1])
        run = self.run_controller(fake, lines=())
        teardown = run.error.host_teardown
        self.assertIs(teardown["container_force_remove_attempted"], True)
        self.assertIs(teardown["container_force_removed"], False)
        self.assertIs(teardown["container_absence_confirmed"], False)
        self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)
        self.assert_removal_only_by_owned_id(fake)

    def test_name_reuse_after_success_is_retained_never_deleted(self):
        fake = happy(name=[b"", listing(FOREIGN_ID)])
        run = self.run_controller(fake)
        self.assertEqual(code_of(run.error), "HOST_TEARDOWN_UNCONFIRMED")
        teardown = run.error.host_teardown
        self.assertIs(teardown["container_name_absent_confirmed"], False)
        self.assertIs(teardown["owned_container_absence_confirmed"], True)
        self.assertNotIn("rm", fake.kinds())
        self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)
        self.assertEqual(run.emitted, [True])

    def test_bridge_preserved_is_reported_separately_from_removed(self):
        cases = [
            (dict(bridge=[bridge(), bridge(OWNED_ID), 1]), "builtin_bridge_preserved"),
            (dict(bridge=[bridge(), bridge(OWNED_ID), bridge(id=CHANGED_BRIDGE_ID)]), "builtin_bridge_preserved"),
            (dict(bridge=[bridge(), bridge(OWNED_ID), bridge(OWNED_ID)]), "owned_bridge_endpoint_absent_confirmed"),
        ]
        for overrides, failed_key in cases:
            with self.subTest(failed_key=failed_key):
                host._RETAINED_HOST_SESSIONS.clear()
                fake = happy(**overrides)
                run = self.run_controller(fake)
                self.assertEqual(code_of(run.error), "HOST_TEARDOWN_UNCONFIRMED")
                teardown = run.error.host_teardown
                self.assertIs(teardown[failed_key], False)
                self.assertIs(teardown["network_removed"], False)
                self.assertIs(teardown["builtin_bridge_configuration_commands_issued"], False)
                self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)
                self.assert_removal_only_by_owned_id(fake)

    def test_unexpected_post_run_peer_refuses_without_touching_peer(self):
        fake = happy(bridge=[bridge(), bridge(OWNED_ID), bridge(FOREIGN_ID)])
        run = self.run_controller(fake)
        self.assertEqual(code_of(run.error), "HOST_TEARDOWN_UNCONFIRMED")
        teardown = run.error.host_teardown
        self.assertIs(teardown["builtin_bridge_preserved"], True)
        self.assertIs(teardown["unexpected_bridge_peer_observed"], True)
        self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)
        self.assertNotIn("rm", fake.kinds())
        self.assert_removal_only_by_owned_id(fake)

    def test_frame_custody_and_session_uncertainty_retained(self):
        for kwargs, key in [(dict(frame_retained=True), "frame_capture_custody_retained"),
                            (dict(session_uncertain=True), "session_cleanup_uncertain")]:
            with self.subTest(key=key):
                host._RETAINED_HOST_SESSIONS.clear()
                run = self.run_controller(happy(), **kwargs)
                self.assertEqual(code_of(run.error), "HOST_TEARDOWN_UNCONFIRMED")
                self.assertIs(run.error.host_teardown[key], True)
                self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)

    def test_teardown_interrupt_is_kept(self):
        fake = happy(owner=[listing(OWNED_ID), KeyboardInterrupt()])
        run = self.run_controller(fake)
        self.assertIsInstance(run.error, KeyboardInterrupt)
        self.assertIs(run.error.host_teardown["teardown_interrupted"], True)
        self.assertEqual(len(host._RETAINED_HOST_SESSIONS), 1)


class GateSessionOrderingTests(unittest.TestCase):
    def run_session(self, *, gate_cmds=None, prepare=None, lines=(READY, ACK), fake=None):
        events = []
        fake = fake or FakeDocker(events, inspect=[DETACHED])
        fake.events = events
        session = FakeSession(lines, events)
        gate = network_gate.HostGate(BINDING, NONCE)

        def emitter():
            events.append(("emit",))
            return bytearray(b"FIXTURE-FRAME")

        wrapped = None
        if prepare is not None:
            def wrapped():
                events.append(("prepare",))
                return prepare()
        with mock.patch.object(protocol, "validate_frame_bytes", side_effect=lambda data, error: None):
            try:
                state, error = host._run_gate_session(gate, session, gate_cmds, fake, emitter,
                                                      prepare_disconnect=wrapped), None
            except BaseException as caught:  # noqa: BLE001
                state, error = None, caught
        return types.SimpleNamespace(state=state, error=error, events=events, fake=fake, gate=gate)

    def test_custom_gate_ordering_unchanged(self):
        commands = network_gate.docker_gate_commands(CUSTOM_NETWORK, NAME)
        run = self.run_session(gate_cmds=commands)
        self.assertEqual(run.state, "frame-closed")
        self.assertEqual(run.fake.calls, list(commands))
        self.assertEqual(run.events, [("read",), ("docker", "disconnect"), ("docker", "inspect"),
                                      ("write", False), ("read",), ("emit",), ("write", True)])

    def test_default_gate_ordering_prepares_inside_disconnect_step(self):
        run = self.run_session(prepare=lambda: network_gate.default_bridge_gate_commands(BRIDGE_ID, OWNED_ID))
        self.assertEqual(run.state, "frame-closed")
        self.assertEqual(run.fake.calls, list(network_gate.default_bridge_gate_commands(BRIDGE_ID, OWNED_ID)))
        self.assertEqual(run.events, [("read",), ("prepare",), ("docker", "disconnect"), ("docker", "inspect"),
                                      ("write", False), ("read",), ("emit",), ("write", True)])

    def test_prepare_not_called_when_ready_refused(self):
        run = self.run_session(prepare=lambda: network_gate.default_bridge_gate_commands(BRIDGE_ID, OWNED_ID),
                               lines=(b"junk\n",))
        self.assertEqual(code_of(run.error), "MESSAGE_FORMAT")
        self.assertEqual(run.events, [("read",)])
        self.assertEqual(run.fake.calls, [])

    def test_prepare_failure_stops_before_disconnect_and_emitter(self):
        def refuse():
            raise network_gate.GateError("BRIDGE_PEER_PRESENT")
        run = self.run_session(prepare=refuse)
        self.assertEqual(code_of(run.error), "BRIDGE_PEER_PRESENT")
        self.assertEqual(run.events, [("read",), ("prepare",)])
        self.assertEqual(run.gate.failed_phase, "disconnecting")

    def test_exactly_one_command_source_required(self):
        commands = network_gate.docker_gate_commands(CUSTOM_NETWORK, NAME)
        for kwargs in (dict(), dict(gate_cmds=commands, prepare=lambda: commands)):
            with self.subTest(kwargs=sorted(kwargs)):
                run = self.run_session(**kwargs)
                self.assertEqual(code_of(run.error), "DEFAULT_BRIDGE_CUSTODY")
                self.assertEqual(run.events, [])


class ErrorLabelTests(unittest.TestCase):
    def test_gate_codes_are_in_host_allowlist(self):
        self.assertLessEqual(network_gate.DEFAULT_BRIDGE_ERROR_CODES, host._ALLOWED_HOST_ERROR_CODES)
        for code in ("DOCKER_BRIDGE_INSPECT", "DOCKER_CONTAINER_LIST", "DOCKER_WORKER_INSPECT",
                     "DEFAULT_BRIDGE_ARGV", "DEFAULT_BRIDGE_CUSTODY", "DEFAULT_BRIDGE_WORKER_ENV"):
            self.assertIn(code, host._ALLOWED_HOST_ERROR_CODES)

    def test_main_reports_only_fixed_labels(self):
        argv = ["--p-root", "/fixture/p", "--r-root", "/fixture/r", "--export-root", "/fixture/export",
                "--p-commit", "1" * 40, "--p-tree", "2" * 40, "--r-commit", "3" * 40, "--r-tree", "4" * 40,
                "--source-closure-sha256", "5" * 64, "--challenge-nonce", NONCE, "--run-id-suffix", SUFFIX,
                "--container-image", "sha256:" + "7" * 64, "--container-python", "/usr/bin/python3",
                "--expected-gpg-sha256", "8" * 64, "--expected-rpm-sha256", "9" * 64,
                "--release-date", "fixture", "--rs9-run", "123"]
        for error, expected in [(network_gate.GateError("BRIDGE_PEER_PRESENT"), "BRIDGE_PEER_PRESENT"),
                                (network_gate.GateError("OWNER_LOOKUP_AMBIGUOUS"), "OWNER_LOOKUP_AMBIGUOUS"),
                                (RuntimeError(OWNED_ID), "HOST_EXECUTION_FAILED")]:
            with self.subTest(expected=expected):
                stderr = io.StringIO()
                with mock.patch.object(host, "execute_host_controller", side_effect=error), \
                        mock.patch.object(host, "_frame_custody_retained", return_value=False), \
                        contextlib.redirect_stderr(stderr):
                    self.assertEqual(host.main(argv), 2)
                payload = json.loads(stderr.getvalue())
                self.assertEqual(payload["error_code"], expected)
                self.assertNotIn(OWNED_ID, stderr.getvalue())


def _segment(path, name):
    text = path.read_text(encoding="utf-8")
    for node in ast.parse(text).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name:
            return ast.get_source_segment(text, node)
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.get_source_segment(text, node)
    raise AssertionError("segment missing")


RESOURCE_SOURCE = '''_RESOURCE = re.compile(r"tf-current-signer-[0-9]{1,20}-[0-9]{1,4}")'''

DOCKER_GATE_COMMANDS_SOURCE = '''\
def docker_gate_commands(network: str, container: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    # The containing process owner must also prove exclusive creation/custody.
    if any(type(x) is not str or not _RESOURCE.fullmatch(x) for x in (network, container)):
        raise GateError("RESOURCE_ID")
    return ((DOCKER, "network", "disconnect", network, container),
            (DOCKER, "container", "inspect", "--format",
             "{{json .NetworkSettings.Networks}}", container))'''

REQUIRE_DETACHED_SOURCE = '''\
def require_detached_networks(data: bytes) -> None:
    if type(data) is not bytes or len(data) > MAX_LINE_BYTES:
        raise GateError("NETWORK_READBACK_BOUND")
    try:
        networks = json.loads(data.decode("ascii"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError):
        raise GateError("NETWORK_READBACK_FORMAT") from None
    if type(networks) is not dict or networks:
        raise GateError("NETWORK_ATTACHED")'''

HOST_GATE_SOURCE = '''\
class HostGate:
    """One-shot host ordering. No operation is retried after failure."""

    def __init__(self, binding: SourceBinding, nonce: str) -> None:
        binding.record()
        if type(nonce) is not str or not _HEX64.fullmatch(nonce):
            raise GateError("CHALLENGE_FORMAT")
        self.worker_pid: int | None = None
        self.binding, self.nonce = binding, nonce
        self.state = "waiting-ready"
        self.failed_phase: str | None = None
        self.frame_emitted = False
        self.retained_error: BaseException | None = None

    def release_frame(self, *, ready: bytes | Callable[[], bytes], disconnect: Callable[[], None],
                      inspect_networks: Callable[[], bytes],
                      exchange_challenge: Callable[[bytes], bytes],
                      emit_existing_frame_and_eof: Callable[[], None]) -> None:
        if self.state != "waiting-ready":
            raise GateError("GATE_REUSED")
        self.state = "checking-ready"
        try:
            ready_line = ready() if callable(ready) else ready
            self.worker_pid = require_message(ready_line, "ready", self.binding, self.nonce)
            self.state = "disconnecting"
            disconnect()
            require_detached_networks(inspect_networks())
            self.state = "checking-isolation"
            ack = exchange_challenge(encode_message("isolation-challenge", self.binding, self.nonce, worker_pid=self.worker_pid))
            require_message(ack, "isolated", self.binding, self.nonce, worker_pid=self.worker_pid)
            self.state = "emitting-frame"
            self.frame_emitted = True
            emit_existing_frame_and_eof()
            self.state = "frame-closed"
        except BaseException as error:
            # The caller owns real child/stream retention and finalization.
            self.failed_phase = self.state
            self.retained_error = error
            self.state = "failed"
            raise'''

LEGACY_TEARDOWN_SOURCE = '''\
def _teardown_host_session(
    session: Any | None, resources: tuple[str, str], remove_net_cmd: tuple[str, ...],
    runner: Callable[[tuple[str, ...], float], tuple[int, bytes, bytes]], *, succeeded: bool,
) -> tuple[dict[str, Any], BaseException | None]:
    network_name, container_name = resources
    interrupt = None
    session_uncertain = False
    if session is not None:
        try:
            session.terminate_and_close()
        except BaseException as error:
            session_uncertain = True
            if not isinstance(error, Exception):
                interrupt = error
        session_uncertain = session_uncertain or session.cleanup_uncertain
    force_remove_attempted = not succeeded or session_uncertain
    container_force_removed = network_removed = container_absent = False
    if force_remove_attempted:
        try:
            container_force_removed = runner((DOCKER_BINARY, "rm", "-f", container_name), 30.0)[0] == 0
        except BaseException as error:
            if not isinstance(error, Exception) and interrupt is None:
                interrupt = error
    try:
        rc, out, _err = runner(
            (DOCKER_BINARY, "container", "ls", "--all", "--quiet", "--filter", f"name=^/{container_name}$"), 30.0)
        container_absent = rc == 0 and not out.strip()
    except BaseException as error:
        if not isinstance(error, Exception) and interrupt is None:
            interrupt = error
    try:
        network_removed = runner(remove_net_cmd, 30.0)[0] == 0
    except BaseException as error:
        if not isinstance(error, Exception) and interrupt is None:
            interrupt = error
    return {
        "network": network_name, "container": container_name,
        "container_force_remove_attempted": force_remove_attempted,
        "container_force_removed": container_force_removed, "container_absence_confirmed": container_absent,
        "network_removed": network_removed, "session_cleanup_uncertain": bool(session_uncertain),
        "teardown_interrupted": interrupt is not None, "teardown_is_not_c6_cleanup": True,
    }, interrupt'''


class SourcePreservationTests(unittest.TestCase):
    """AST source-span checks for the preserved gate/probe code, not whole modified-module pins."""

    def test_gate_spans_byte_identical(self):
        path = LEAF_DIR / "signing_network_gate.py"
        for name, expected in [("_RESOURCE", RESOURCE_SOURCE), ("docker_gate_commands", DOCKER_GATE_COMMANDS_SOURCE),
                               ("require_detached_networks", REQUIRE_DETACHED_SOURCE), ("HostGate", HOST_GATE_SOURCE)]:
            with self.subTest(name=name):
                self.assertEqual(_segment(path, name), expected)

    def test_historical_probe_teardown_span_byte_identical(self):
        self.assertEqual(_segment(LEAF_DIR / "signer_host_controller.py", "_teardown_host_session"),
                         LEGACY_TEARDOWN_SOURCE)

    def test_isolation_module_bytes_match_parent_pin(self):
        expected = "dfe402c62927fefe722da410cdf433f933a4829e246d70ed3312a19e159b0df7"
        actual = hashlib.sha256((LEAF_DIR / "signing_linux_isolation.py").read_bytes()).hexdigest()
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
