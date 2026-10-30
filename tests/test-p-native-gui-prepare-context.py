import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location("gui_context_inputs",ROOT/"tools/verification/p-native-gui-prepare-context.py")
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
TEXT=(ROOT/"tests/fixtures/p-gui-qualified-wrapper-x64.bash").read_bytes()
BWRAP="/nix/store/zri6pfys37ih88s5yckr47khz5zw1rzk-bubblewrap-0.12.0/bin/bwrap"

def context():
    return {"sourceSha256":M.SOURCE_HASH,"containerInitSourceSha256":M.CONTAINER_HASH,
            "nixpkgsRevision":M.NIXPKGS_REV,"bwrapVersion":"0.12.0","bwrap":BWRAP,
            "declaredSecurityDefaults":dict(M.SECURITY_DEFAULTS)}

class ContextInputsTests(unittest.TestCase):
    def test_qualified_real_wrapper_objects_are_unambiguous(self):
        result=M.extract_wrapper_objects(TEXT,context())
        self.assertEqual(result["bwrap"],BWRAP)
        self.assertTrue(result["containerInit"].endswith("-container-init"))
        self.assertTrue(result["originalInit"].endswith("-tfnf-init"))
        self.assertTrue(result["pinnedBash"].endswith("/bin/bash"))

    def test_wrong_source_runtime_and_namespace_pins_refuse(self):
        for key,value in [("sourceSha256","0"*64),("containerInitSourceSha256","0"*64),
                          ("nixpkgsRevision","0"*40),("bwrapVersion","0.99"),("bwrap","/bin/bwrap")]:
            with self.subTest(key=key):
                candidate=context();candidate[key]=value
                with self.assertRaises(ValueError):M.extract_wrapper_objects(TEXT,candidate)
        for value in (True,0):
            candidate=context();candidate["declaredSecurityDefaults"]["unshareUser"]=value
            with self.assertRaises(ValueError):M.extract_wrapper_objects(TEXT,candidate)

    def test_opaque_or_ambiguous_interpreter_and_producer_refuse(self):
        for changed in [
            TEXT.replace(TEXT.split(b"\n",1)[0],b"#!/bin/bash",1),
            TEXT.replace(b"--symlink /nix/store/msxm3xjics0s0qmg4c4apnayb4xz4574-tfnf-init /init",
                b"--symlink /nix/store/msxm3xjics0s0qmg4c4apnayb4xz4574-tfnf-init /not-init",1),
            TEXT+TEXT,
            b"x"*131073,
        ]:
            with self.assertRaises(ValueError):M.extract_wrapper_objects(changed,context())

    def test_cli_cannot_run_in_local_unqualified_context(self):
        with self.assertRaisesRegex(ValueError,"native Linux only|public hosted P validation only"):
            M.prepare(ROOT,"x86_64-linux",Path("/fixture/context"),Path("/fixture/wrapper"),
                      Path("/fixture/closure"),Path("/fixture/output"))

if __name__=="__main__":unittest.main()
