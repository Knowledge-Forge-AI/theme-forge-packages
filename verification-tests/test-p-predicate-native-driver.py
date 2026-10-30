"""Pure graph-contract cases for the P native driver.

These tests do not evaluate Nix, launch a process, inspect procfs, or exercise
the hosted native predicate.  They pin the before/after graph boundary only.
"""

import importlib.util
import hashlib
from pathlib import Path
from unittest.mock import patch
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
    def test_nix_v4_text_and_container_records_use_typed_fields(self):
        output = "/nix/store/out-tfnf"
        text_record = {
            "version": 4,
            "derivations": {
                "text.drv": {
                    "version": 4,
                    "outputs": {"out": {"path": "out-tfnf"}},
                    "structuredAttrs": {"text": "printf pinned"},
                }
            },
        }
        document, value, schema = DRIVER._normalize_derivation(text_record, "/nix/store/text.drv")
        self.assertIs(document, text_record)
        self.assertEqual(schema, 4)
        DRIVER._derivation_output(value, schema, output)
        self.assertEqual(DRIVER._derivation_field(value, schema, "text"), "printf pinned")

        source = "/nix/store/src-container-init.cc"
        container = {
            "version": 4,
            "derivations": {
                "container.drv": {
                    "version": 4,
                    "outputs": {"out": {"path": "out-container-init"}},
                    "structuredAttrs": None,
                    "env": {"buildCommand": "$CXX -static -s -o $out " + source},
                    "inputs": {"drvs": {}, "srcs": ["src-container-init.cc"]},
                }
            },
        }
        with patch.object(DRIVER, "authenticate_container_source", return_value={"kind": "fixture"}):
            proof = DRIVER.container_producer(
                container, "/nix/store/out-container-init",
                lambda path: b"authenticated" if path == source else b"wrong",
                "/nix/store/container.drv",
            )
        self.assertEqual(proof["declaredSource"], source)
        self.assertEqual(proof["kind"], "fixture")

    def test_legacy_derivation_envelope_remains_supported(self):
        path = "/nix/store/out-container-init"
        source = "/nix/store/src-container-init.cc"
        legacy = {
            "/nix/store/container.drv": {
                "outputs": {"out": {"path": path}},
                "env": {"buildCommand": "$CXX -static -s -o $out " + source},
                "inputSrcs": [source],
            }
        }
        document, value, schema = DRIVER._normalize_derivation(legacy, "/nix/store/container.drv")
        self.assertIs(document, legacy)
        self.assertEqual(schema, 3)
        DRIVER._derivation_output(value, schema, path)
        with patch.object(DRIVER, "authenticate_container_source", return_value={"kind": "fixture"}):
            proof = DRIVER.container_producer(legacy, path, lambda _: b"source")
        self.assertEqual(proof["declaredSource"], source)

    def test_v4_unknown_or_ambiguous_shapes_and_wrong_bindings_refuse(self):
        base = {
            "version": 4,
            "derivations": {
                "one.drv": {
                    "version": 4,
                    "outputs": {"out": {"path": "one"}},
                    "structuredAttrs": {"text": "text"},
                }
            },
        }
        with self.assertRaises(DRIVER.p.Refusal):
            DRIVER._normalize_derivation({"version": 3, "derivations": {}}, "/nix/store/one.drv")
        with self.assertRaises(DRIVER.p.Refusal):
            DRIVER._normalize_derivation({"version": 4, "derivations": {"one.drv": {}, "two.drv": {}}})
        document, value, schema = DRIVER._normalize_derivation(base, "/nix/store/one.drv")
        with self.assertRaises(DRIVER.p.Refusal):
            DRIVER._derivation_output(value, schema, "/nix/store/other")
        wrong_inputs = {
            "version": 4,
            "derivations": {
                "container.drv": {
                    "version": 4,
                    "outputs": {"out": {"path": "out-container-init"}},
                    "structuredAttrs": None,
                    "env": {"buildCommand": "$CXX -static -s -o $out /nix/store/src-container-init.cc"},
                    "inputs": {"drvs": {}, "srcs": ["unrelated.cc"]},
                }
            },
        }
        with self.assertRaises(DRIVER.p.Refusal):
            DRIVER.container_producer(wrong_inputs, "/nix/store/out-container-init", lambda _: b"source")

    def test_v4_and_legacy_graph_identity_joins_are_exact(self):
        v4 = {"version": 4, "derivations": {"container.drv": {"version": 4}}}
        self.assertTrue(DRIVER._derivation_graph_contains(v4, "/nix/store/container.drv"))
        self.assertFalse(DRIVER._derivation_graph_contains(v4, "/nix/store/other.drv"))
        legacy = {"/nix/store/container.drv": {"outputs": {}}}
        self.assertTrue(DRIVER._derivation_graph_contains(legacy, "/nix/store/container.drv"))
        self.assertFalse(DRIVER._derivation_graph_contains(legacy, "/nix/store/other.drv"))

    def test_receipt_preserves_observation_bytes_after_predicate_decode(self):
        predicate = {
            "mode": "native-predicate-only",
            "fixtureMode": False,
            "cases": [
                {"case": "term", "fixtureMode": False, "admitting": False,
                 "guiQualification": False, "witness": {"exit_code": 15}},
                {"case": "normal143", "fixtureMode": False, "admitting": False,
                 "guiQualification": False, "witness": {
                     "negativeRejected": True, "exit_code": 143 << 8,
                     "stableBracket": {"state": "Z"}}},
                {"case": "controller-death", "fixtureMode": False, "admitting": False,
                 "guiQualification": False, "predicateWitness": False,
                 "nodeOwnerAlive": True, "controllerStatus": {"code": 73, "signal": None},
                 "monitorWaitStatus": {"code": 137, "signal": None}},
            ],
        }
        observation = b"original-observation\0argv"
        source_authentication = {"wrapperSha256": "wrapper-fixture"}
        receipt = DRIVER.build_predicate_receipt(
            predicate, observation, {"equal": True}, "lock-fixture", {"fixture": True},
            source_authentication,
        )
        self.assertEqual(
            receipt["sourceAuthentication"]["originalArgvSha256"],
            hashlib.sha256(observation).hexdigest(),
        )
        self.assertEqual(receipt["cases"], predicate["cases"][:2])
        self.assertEqual(receipt["recovery"], predicate["cases"][2])
        self.assertNotIn("originalArgvSha256", source_authentication)

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
