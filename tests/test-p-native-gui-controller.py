import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "verification" / "p-native-gui-controller.py"
SPEC = importlib.util.spec_from_file_location("p_native_gui_controller", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def identity(path: str, marker: str) -> dict[str, object]:
    return {"path": path, "sha256": marker * 64, "size": 3}


def bind_message() -> dict[str, object]:
    return {
        "schema": MODULE.SCHEMA,
        "op": "bind",
        "nonce": "1" * 32,
        "nodePid": 101,
        "monitorPid": 202,
        "monitor": {"executable": identity("/nix/store/monitor/bin/bwrap", "a"), "argv": ["bwrap", "--die-with-parent"]},
        "application": identity("/nix/store/app/bin/theme-forge-nebular-fusion", "b"),
        "predicateHelper": identity("/nix/store/helper/bin/p-process-predicate-probe.py", "c"),
        "source": {"pCommit": "c" * 40, "pTree": "d" * 40, "nebularCommit": "e" * 40, "nebularTree": "f" * 40},
        "platform": "linux-x64",
        "scenario": "C-signal",
        "receiptPath": "/private/receipt.json",
        "launchBindingSha256": "9" * 64,
    }


class ControllerContractTests(unittest.TestCase):
    def test_closed_bind_contract_normalizes(self):
        value = MODULE.validate_bind_message(bind_message())
        self.assertEqual(value["monitorPid"], 202)
        self.assertEqual(value["launchBindingSha256"], "9" * 64)
        self.assertNotIn("applicationPid", value)

    def test_fresh_argv_count_matches_resolver_under_unchanged_wire_bound(self):
        for count in (129, 8192):
            message = bind_message()
            message["monitor"]["argv"] = ["x"] * count
            raw = json.dumps(message, separators=(",", ":")).encode()
            self.assertLessEqual(len(raw), MODULE.LIMIT)
            parsed = MODULE.parse_json(raw, "fixture")
            self.assertEqual(len(MODULE.validate_bind_message(parsed)["monitor"]["argv"]), count)
        message["monitor"]["argv"].append("x")
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_bind_message(message)

    def test_launch_binding_digest_is_required_and_strict(self):
        missing = bind_message()
        del missing["launchBindingSha256"]
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_bind_message(missing)
        for invalid in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, True):
            message = bind_message()
            message["launchBindingSha256"] = invalid
            with self.assertRaises(MODULE.Refusal):
                MODULE.validate_bind_message(message)

    def test_launch_binding_digest_change_is_normalized(self):
        message = bind_message()
        message["launchBindingSha256"] = "b" * 64
        self.assertEqual(MODULE.validate_bind_message(message)["launchBindingSha256"], "b" * 64)

    def test_numeric_application_pid_and_signal_overrides_refuse(self):
        message = bind_message()
        message["applicationPid"] = 303
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_bind_message(message)
        command = {"schema": MODULE.SCHEMA, "op": "terminate", "nonce": "1" * 32, "scenario": "C-signal", "signal": 15}
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_command(command, "terminate")

    def test_predicate_helper_binding_is_closed_and_digest_is_not_caller_optional(self):
        message = bind_message()
        message["predicateHelper"] = {"path": "/nix/store/helper/bin/p-process-predicate-probe.py", "sha256": "c" * 64, "size": 3}
        self.assertEqual(MODULE.validate_bind_message(message)["predicateHelper"]["size"], 3)
        message["predicateHelper"] = {"path": "/nix/store/helper/bin/p-process-predicate-probe.py", "sha256": "d" * 64, "size": 3}
        self.assertEqual(MODULE.validate_bind_message(message)["predicateHelper"]["sha256"], "d" * 64)

    def test_held_regular_digest_rejects_symlink_and_bounds_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "helper.py"
            path.write_bytes(b"helper")
            identity_value, data = MODULE._regular_digest(path)
            self.assertEqual(identity_value["size"], len(data))
            self.assertEqual(identity_value["sha256"], MODULE.hashlib.sha256(data).hexdigest())
            link = Path(directory) / "link.py"
            link.symlink_to(path)
            with self.assertRaises((OSError, MODULE.Refusal)):
                MODULE._regular_digest(link)

    def test_discovery_and_cleanup_are_bounded_to_held_handles(self):
        source = MODULE_PATH.read_text()
        self.assertIn("def _direct_children", source)
        self.assertNotIn("os.listdir(self.view.root)", source)
        self.assertIn("cleanup=(self.application_fd", source)
        self.assertNotIn("os.kill(", source)

    def test_wrong_target_and_boolean_pid_refuse(self):
        message = bind_message()
        message["nodePid"] = True
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_bind_message(message)
        message = bind_message()
        message["platform"] = "darwin-arm64"
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_bind_message(message)

    def test_duplicate_json_fields_refuse(self):
        with self.assertRaises(MODULE.Refusal):
            MODULE.parse_json(b'{"schema":"x","schema":"y"}', "duplicate")
        with self.assertRaises(MODULE.Refusal):
            MODULE.parse_json(b'{"value":NaN}', "nonfinite")

    def test_command_shapes_are_closed(self):
        self.assertEqual(
            MODULE.validate_command({"schema": MODULE.SCHEMA, "op": "terminate", "nonce": "1" * 32, "scenario": "C-signal"}, "terminate")["scenario"],
            "C-signal",
        )
        self.assertEqual(
            MODULE.validate_command({"schema": MODULE.SCHEMA, "op": "finalize", "nonce": "1" * 32, "monitorExit": {"code": 143, "signal": None}}, "finalize")["monitorExit"]["code"],
            143,
        )
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_command({"schema": MODULE.SCHEMA, "op": "terminate", "nonce": "2" * 32, "scenario": "C-signal"}, "terminate", "1" * 32)


if __name__ == "__main__":
    unittest.main()
