"""Pure graph-contract cases for the P native driver.

These tests do not evaluate Nix, launch a process, inspect procfs, or exercise
the hosted native predicate.  They pin the before/after graph boundary only.
"""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = ROOT / "tools/verification/p-predicate-native-driver.py"
SPEC = importlib.util.spec_from_file_location("p_predicate_driver", DRIVER_PATH)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


CONTEXT = {
    "pythonRoot": "/nix/store/python-root",
    "probeSource": "/nix/store/probe-source",
    "surrogateInit": "/nix/store/surrogate-init",
}


def graph(runtime_paths, graph_marker="product-only"):
    return {
        "outputs": {"tfnf": "/nix/store/product"},
        "derivationGraph": {"marker": graph_marker},
        "runtimeClosure": [{"path": path} for path in runtime_paths],
    }


class GraphContractTests(unittest.TestCase):
    def test_preexisting_python_root_is_recorded_and_allowed(self):
        current = graph(["/nix/store/product", CONTEXT["pythonRoot"]])
        proof = DRIVER.compare_graphs(current, current, CONTEXT)
        self.assertTrue(proof["equal"])
        self.assertTrue(proof["pythonRootPreexistingProductRuntime"])
        self.assertFalse(proof["pythonRootAbsentProductRuntime"])
        self.assertEqual(proof["beforeGraphSha256"], proof["afterGraphSha256"])
        self.assertEqual(proof["beforeRuntimeClosureCount"], 2)

    def test_python_root_absent_in_both_graphs_remains_truthful(self):
        current = graph(["/nix/store/product"])
        proof = DRIVER.compare_graphs(current, current, CONTEXT)
        self.assertFalse(proof["pythonRootPreexistingProductRuntime"])
        self.assertTrue(proof["pythonRootAbsentProductRuntime"])

    def test_after_only_python_root_refuses(self):
        before = graph(["/nix/store/product"])
        after = graph(["/nix/store/product", CONTEXT["pythonRoot"]])
        with self.assertRaises(DRIVER.GraphComparisonRefusal) as caught:
            DRIVER.compare_graphs(before, after, CONTEXT)
        self.assertEqual(caught.exception.diagnostics["before"]["pythonRootPresent"], False)
        self.assertEqual(caught.exception.diagnostics["after"]["pythonRootPresent"], True)

    def test_removed_python_root_or_other_graph_change_refuses(self):
        before = graph(["/nix/store/product", CONTEXT["pythonRoot"]])
        after = graph(["/nix/store/product"])
        with self.assertRaises(DRIVER.GraphComparisonRefusal):
            DRIVER.compare_graphs(before, after, CONTEXT)

    def test_probe_or_surrogate_init_in_graph_still_refuses(self):
        before = graph(["/nix/store/product"], graph_marker=CONTEXT["probeSource"])
        with self.assertRaises(DRIVER.GraphComparisonRefusal):
            DRIVER.compare_graphs(before, before, CONTEXT)


if __name__ == "__main__":
    unittest.main()
