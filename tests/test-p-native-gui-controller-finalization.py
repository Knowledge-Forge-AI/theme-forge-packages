import importlib.util
import math
import os
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(os.environ.get(
    "P_GUI_CONTROLLER_PATH",
    Path(__file__).parents[1] / "tools" / "verification" / "p-native-gui-controller.py",
))
SPEC = importlib.util.spec_from_file_location("p_native_gui_controller_finalization", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class FakeLease:
    def __init__(self, *args, write=object(), **kwargs):
        self.write = write
        self.pulses = 0
        self.acknowledgements = [{"op": "ARMED"}]
        self.nonce = "fixture"

    def pulse(self):
        self.pulses += 1

    def disarm(self, witness, reason):
        self.write = None


class FakeStable:
    Lease = FakeLease

    @staticmethod
    def ProcView():
        return types.SimpleNamespace()

    @staticmethod
    def assert_fixed(*args):
        return {"state": "T"}

    @staticmethod
    def send(*args):
        return None

    @staticmethod
    def wait_until(predicate, deadline, pulse):
        if not predicate():
            raise AssertionError("inert fixture predicate did not become true")

    @staticmethod
    def recheck_stopped_identity(*args):
        return None

    @staticmethod
    def resumed_or_exited(*args):
        return True

    @staticmethod
    def zombie_witness(*args):
        return {"state": "zombie"}


def finalization_fixture(seconds, clock):
    stable = types.SimpleNamespace(ProcView=lambda: types.SimpleNamespace())
    session = MODULE.GuiSession({"scenario": "C-signal"}, stable)
    session.bound = True
    session.lease = FakeLease(write=None)
    session.witness = {"state": "zombie"}
    session.finalization_deadline = seconds
    session.application_fd = 17
    session._response = lambda operation, **fields: {"op": operation, **fields}
    return session


def terminated_fixture():
    stable = FakeStable()
    session = MODULE.GuiSession({
        "scenario": "C-signal",
        "nodePid": 101,
        "platform": "linux-x64",
        "predicateHelper": {"path": "/fixture/predicate"},
        "receiptPath": "/fixture/receipt.json",
        "application": {"sha256": "a" * 64},
    }, stable)
    session.bound = True
    session.monitor = {"pid": 202, "start": 1}
    session.application = {"pid": 303, "start": 2}
    session.monitor_fd = 11
    session.application_fd = 12
    session._revalidate_handles = lambda require_app=True: None
    session._response = lambda operation, **fields: {"op": operation, **fields}
    return session


@contextmanager
def terminated_at(delay):
    """Run the production terminate path, then advance only the test clock."""
    clock = [0.0]
    session = terminated_fixture()
    with patch.object(MODULE.time, "monotonic", side_effect=lambda: clock[0]):
        with patch.object(MODULE.select, "select", return_value=([17], [], [])):
            with patch.object(MODULE, "_receipt", return_value={}):
                terminated = session.terminate()
                if terminated["op"] != "TERMINATED":
                    raise AssertionError("production terminate did not return TERMINATED")
                clock[0] = delay
                yield session


class ControllerFinalizationClockTests(unittest.TestCase):
    def test_old_five_second_window_would_refuse_missing_finalized(self):
        clock = [5.1]
        session = finalization_fixture(5, clock)
        with patch.object(MODULE.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(MODULE.Refusal, "finalization deadline"):
                session.heartbeat()

    def test_delayed_finalized_is_valid_inside_finite_candidate_window(self):
        with terminated_at(6.0) as session:
            response = session.finalize({"code": 143, "signal": None})
            self.assertEqual(response["op"], "FINALIZED")
            self.assertEqual(session.finalization_deadline, 22.0)
            self.assertTrue(session.completed)

        with terminated_at(20.0) as session:
            response = session.finalize({"code": 143, "signal": None})
            self.assertEqual(response["op"], "FINALIZED")
            self.assertTrue(session.completed)

    def test_late_or_invalid_finalized_remains_fail_closed(self):
        with terminated_at(22.1) as late:
            with self.assertRaisesRegex(MODULE.Refusal, "finalization deadline"):
                late.finalize({"code": 143, "signal": None})
        self.assertFalse(late.completed)

        with terminated_at(6.0) as invalid:
            with self.assertRaisesRegex(MODULE.Refusal, "C-signal finalization"):
                invalid.finalize({"code": 0, "signal": None})
        self.assertFalse(invalid.completed)

    def test_active_watchdog_and_outer_budget_remain_bounded(self):
        self.assertTrue(math.isfinite(MODULE.SIGNAL_TRANSACTION_BUDGET_SECONDS))
        self.assertEqual(MODULE.SIGNAL_TRANSACTION_BUDGET_SECONDS, 35)
        stable = types.SimpleNamespace(ProcView=lambda: types.SimpleNamespace())
        session = MODULE.GuiSession({"scenario": "C-signal"}, stable)
        lease = FakeLease(write=object())
        session.lease = lease
        session.witness = None
        session.finalization_deadline = None
        with patch.object(MODULE.time, "monotonic", return_value=1.0):
            session.heartbeat()
        self.assertEqual(lease.pulses, 1)
        self.assertIsNone(session.finalization_deadline)


if __name__ == "__main__":
    unittest.main()
