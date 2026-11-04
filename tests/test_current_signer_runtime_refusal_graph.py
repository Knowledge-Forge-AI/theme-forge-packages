"""Pure proposed closed error-graph tests; no native tool, key, process or network."""
from pathlib import Path
import ast,copy,io,json,re,sys,types,unittest
from unittest import mock
if __name__=="__main__" and len(sys.argv)>1:
    ROOT=Path(sys.argv.pop(1))
else:
    ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/"tests"),str(ROOT/"tools/verification/current_signer"),str(ROOT/"tools/verification")]
import signer_worker as sw
import signer_host_controller as hc
import protected_signing_runtime as rt
# Compile only the unchanged wrapper class body; no live RS9 intake imports.
routing=types.ModuleType("current_import_routing")
class InertContractError(RuntimeError):
    def __init__(self,code,message):
        self.code=code
        super().__init__(message)
routing.ContractError=InertContractError
lease_tree=ast.parse((ROOT/"tools/verification/current_import_routing.py").read_text())
lease_classes=[n for n in lease_tree.body if isinstance(n,ast.ClassDef) and n.name in {"_LeasePhaseFailure","_EnumerationFailure"}]
exec(compile(ast.Module(body=lease_classes,type_ignores=[]),"<source-owned-lease-wrappers>","exec"),vars(routing))
import owned_gpg_agent as agent
import test_current_signer_post_frame_diagnostics as base

def graph(error):
    return sw._runtime_refusal_graph(error,rt,routing,agent)

def payload(g):
    return {"schema":base.WORKER_RECEIPT_SCHEMA,"status":"failed-closed","error_code":"WITHHELD_POST_FRAME",
      "custody_retained":True,"publication_authority":False,"native_client_qualification":False,
      "post_frame_diagnostic":{"schema":sw.POST_FRAME_DIAGNOSTIC_V2_SCHEMA,
       "step":"RUNTIME_RPM_METADATA_CREATE","code":"UNCLASSIFIED","runtime_refusal_graph":g}}

class GraphTests(unittest.TestCase):
    def setUp(self):
        self.routing_patch=mock.patch.dict(sys.modules,{"current_import_routing":routing})
        self.routing_patch.start()
        self.addCleanup(self.routing_patch.stop)
    def test_cleanup_wrapper_preserves_body_and_cleanup_categories(self):
        e=rt._LifecycleFailure("SIGNER_CLEANUP",rt.ProtectedSigningError("OUTPUT_INVENTORY",base.TEXT_CANARY),
          (agent.OwnedAgentError("AGENT_NOT_LIVE",base.PATH_CANARY),),resources=(base.KEY_CANARY,))
        got=graph(e)
        self.assertEqual(got["nodes"],[
          {"parent":None,"edge":"ROOT","code":"SIGNER_CLEANUP"},
          {"parent":0,"edge":"BODY","code":"OUTPUT_INVENTORY"},
          {"parent":0,"edge":"CLEANUP","code":"AGENT_NOT_LIVE"}])
        self.assertFalse(got["truncated"]);base._assert_no_canary(self,json.dumps(got))
        self.assertEqual(sw._classify_post_frame_error(e),"UNCLASSIFIED")
    def test_actual_native_policy_precondition_without_child(self):
        obj=rt.ProtectedSigningRuntime();obj._agent=types.SimpleNamespace(require_live=lambda:None)
        with mock.patch.object(rt.threading,"active_count",return_value=2),mock.patch.object(rt.subprocess,"Popen") as child:
            with self.assertRaises(rt.ProtectedSigningError) as got:
                obj._run((rt.NATIVE_CREATEREPO,),cwd=Path("."),env={},stdin=b"",phase="rpm-metadata-create")
        child.assert_not_called()
        self.assertEqual(graph(got.exception)["nodes"][0]["code"],"COMMAND_POLICY")
        self.assertEqual(obj._last_native_operation,"RUNTIME_RPM_METADATA_CREATE")
    def test_actual_lease_wrapper_has_distinct_body_postcheck_retention_edges(self):
        e=routing._LeasePhaseFailure(rt.ProtectedSigningError("COMMAND_FAILED",base.TEXT_CANARY),
          routing.ContractError("CURRENT_IMPORT_ROUTING",base.TEXT_CANARY),OSError(base.TEXT_CANARY))
        got=graph(e)
        self.assertEqual([n["edge"] for n in got["nodes"]],["ROOT","BODY","POSTCHECK","RETENTION"])
        self.assertEqual([n["code"] for n in got["nodes"]],["CURRENT_SIGNING_LEASE","COMMAND_FAILED","CURRENT_IMPORT_ROUTING","PYTHON_OS_ERROR"])
    def test_known_agent_code_is_retained_without_message(self):
        got=graph(agent.OwnedAgentError("TOOL_CHANGED",base.TEXT_CANARY))
        self.assertEqual(got["nodes"][0]["code"],"TOOL_CHANGED");base._assert_no_canary(self,json.dumps(got))
    def test_arbitrary_exception_properties_are_not_read(self):
        class Hostile(RuntimeError):
            @property
            def code(self):raise AssertionError(base.TEXT_CANARY)
            @property
            def __dict__(self):raise AssertionError(base.TEXT_CANARY)
            @property
            def original_error(self):raise AssertionError(base.TEXT_CANARY)
            def __str__(self):raise AssertionError(base.TEXT_CANARY)
        got=graph(Hostile(base.PATH_CANARY))
        self.assertEqual(got["nodes"],[{"parent":None,"edge":"ROOT","code":"PYTHON_RUNTIME_ERROR"}])
    def test_unknown_and_nonexact_codes_stay_unclassified(self):
        for code in (base.PATH_CANARY,"command_policy",type("S",(str,),{})("COMMAND_POLICY"),None,[]):
            e=rt.ProtectedSigningError("UNKNOWN",base.TEXT_CANARY);e.code=code
            self.assertEqual(graph(e)["nodes"][0]["code"],"UNCLASSIFIED")
    def test_foreign_source_error_subclass_is_not_walked(self):
        class Foreign(rt._LifecycleFailure):pass
        got=graph(Foreign("SIGNER_CLEANUP",rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY),()))
        self.assertEqual(len(got["nodes"]),1)
        self.assertNotEqual(got["nodes"][0]["code"],"SIGNER_CLEANUP")
    def test_cycles_are_bounded_and_explicit(self):
        e=rt._LifecycleFailure("SIGNER_CLEANUP",None,());e.original_error=e
        got=graph(e);self.assertEqual(len(got["nodes"]),1);self.assertTrue(got["truncated"])
    def test_depth_limit_is_bounded_and_explicit(self):
        e=rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)
        for _ in range(10):e=rt._LifecycleFailure("SIGNER_CLEANUP",e,())
        got=graph(e);self.assertEqual(len(got["nodes"]),4);self.assertTrue(got["truncated"])
    def test_node_limit_is_bounded_and_explicit(self):
        e=rt._LifecycleFailure("SIGNER_CLEANUP",None,tuple(OSError(base.TEXT_CANARY) for _ in range(20)))
        got=graph(e);self.assertEqual(len(got["nodes"]),8);self.assertTrue(got["truncated"])
    def test_graph_validators_are_equivalent_and_return_copies(self):
        g=graph(rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY))
        a=sw._validate_runtime_refusal_graph(g);b=hc._validate_runtime_refusal_graph(g)
        self.assertEqual(a,b);g["nodes"][0]["code"]="UNCLASSIFIED"
        self.assertEqual(a["nodes"][0]["code"],"COMMAND_POLICY")
    def test_closed_code_vocabulary_is_equal_at_both_boundaries(self):
        self.assertEqual(sw._RUNTIME_REFUSAL_GRAPH_CODES,hc._RUNTIME_REFUSAL_GRAPH_CODES)
        self.assertEqual(len(sw._POST_FRAME_CODES),70)
        self.assertTrue(sw._POST_FRAME_CODES<=sw._RUNTIME_REFUSAL_GRAPH_CODES)
    def test_invalid_graphs_refuse_without_serializing_inputs(self):
        good=graph(rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY))
        bad=[]
        for key,val in (("schema",None),("schema",type("S",(str,),{})(good["schema"])),("truncated",1),("nodes",[])):
            item=copy.deepcopy(good);item[key]=val;bad.append(item)
        for key,val in (("parent",False),("parent",0),("edge","BODY"),("code",base.PATH_CANARY),("code",type("S",(str,),{})("COMMAND_POLICY"))):
            item=copy.deepcopy(good);item["nodes"][0][key]=val;bad.append(item)
        item=copy.deepcopy(good);item["extra"]=base.TEXT_CANARY;bad.append(item)
        item=copy.deepcopy(good);item["nodes"][0]["extra"]=base.TEXT_CANARY;bad.append(item)
        for value in bad:
            with self.subTest(case=len(json.dumps(value))):
                self.assertIsNone(sw._validate_runtime_refusal_graph(value))
                self.assertIsNone(hc._validate_runtime_refusal_graph(value))
    def test_bool_forward_and_deep_parent_indices_refuse(self):
        good=graph(rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY))
        for parent in (True,1,-1,None,"0"):
            bad=copy.deepcopy(good);bad["nodes"].append({"parent":parent,"edge":"BODY","code":"COMMAND_POLICY"})
            self.assertIsNone(hc._validate_runtime_refusal_graph(bad))
        bad=copy.deepcopy(good)
        for i in range(4):bad["nodes"].append({"parent":i,"edge":"BODY","code":"COMMAND_POLICY"})
        self.assertIsNone(hc._validate_runtime_refusal_graph(bad))
    def test_old_three_field_record_remains_accepted(self):
        doc=payload(graph(rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)))
        del doc["post_frame_diagnostic"]["runtime_refusal_graph"]
        doc["post_frame_diagnostic"]["schema"]=sw.POST_FRAME_DIAGNOSTIC_SCHEMA
        got=hc._parse_untrusted_post_frame_worker_stderr(json.dumps(doc).encode())
        self.assertEqual(got["record"],"VALID");self.assertNotIn("runtime_refusal_graph",got)
    def test_graph_crosses_host_parser_sanitizer_and_remains_untrusted(self):
        doc=payload(graph(rt._LifecycleFailure("SIGNER_CLEANUP",rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY),())))
        got=hc._parse_untrusted_post_frame_worker_stderr(json.dumps(doc).encode())
        self.assertEqual(got["record"],"VALID");self.assertTrue(got["untrusted_worker_claim"])
        self.assertEqual(hc.sanitize_post_frame_diagnostic(got),got)
        self.assertEqual(got["runtime_refusal_graph"]["nodes"][1]["code"],"COMMAND_POLICY")
        self.assertEqual(got["code"],"UNCLASSIFIED");base._assert_no_canary(self,json.dumps(got))
    def test_invalid_nested_graph_invalidates_entire_worker_record(self):
        doc=payload({"schema":"bad","nodes":[],"truncated":False})
        got=hc._parse_untrusted_post_frame_worker_stderr(json.dumps(doc).encode())
        self.assertEqual(got["record"],"INVALID_RECORD")
        self.assertNotIn("runtime_refusal_graph",got)
    def test_unavailable_host_record_cannot_carry_graph(self):
        got=hc._post_frame_diagnostic_view("ABSENT")
        got["runtime_refusal_graph"]=graph(rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY))
        self.assertIsNone(hc.sanitize_post_frame_diagnostic(got))
    def test_versioned_graph_shape_cannot_masquerade_as_v1(self):
        doc=payload(graph(rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)))
        doc["post_frame_diagnostic"]["schema"]=sw.POST_FRAME_DIAGNOSTIC_SCHEMA
        self.assertEqual(hc._parse_untrusted_post_frame_worker_stderr(json.dumps(doc).encode())["record"],"INVALID_RECORD")
        doc["post_frame_diagnostic"]["schema"]=sw.POST_FRAME_DIAGNOSTIC_V2_SCHEMA
        del doc["post_frame_diagnostic"]["runtime_refusal_graph"]
        self.assertEqual(hc._parse_untrusted_post_frame_worker_stderr(json.dumps(doc).encode())["record"],"INVALID_RECORD")
    def test_enumeration_wrapper_preserves_known_causes_without_resources(self):
        e=routing._EnumerationFailure(rt.ProtectedSigningError("PATH_IO",base.TEXT_CANARY),
          (base.KEY_CANARY,),(OSError(base.TEXT_CANARY),),body_cause=ValueError(base.TEXT_CANARY))
        got=graph(e)
        self.assertEqual([n["edge"] for n in got["nodes"]],["ROOT","BODY","BODY_CAUSE","CLEANUP"])
        self.assertEqual([n["code"] for n in got["nodes"]],["CURRENT_IMPORT_ROUTING","PATH_IO","PYTHON_VALUE_ERROR","PYTHON_OS_ERROR"])
        base._assert_no_canary(self,json.dumps(got))
    def test_hostile_metaclass_cannot_forge_exact_class_membership(self):
        hits=[]
        class Meta(type):
            def __eq__(self,other):
                hits.append("equality")
                return True
        class Foreign(RuntimeError,metaclass=Meta):
            @property
            def __dict__(self):
                hits.append("dictionary")
                raise AssertionError(base.TEXT_CANARY)
        got=graph(Foreign(base.TEXT_CANARY))
        self.assertEqual(hits,[])
        self.assertEqual(got["nodes"],[{"parent":None,"edge":"ROOT","code":"PYTHON_RUNTIME_ERROR"}])
    def test_different_reported_error_cannot_receive_stale_runtime_graph(self):
        phase=sw._PostFramePhase()
        first=rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)
        second=ValueError(base.TEXT_CANARY)
        phase.runtime_refusal_graph=graph(first)
        phase.runtime_refusal_error=first
        self.assertIs(phase.runtime_refusal_error,first)
        self.assertNotIn("runtime_refusal_graph",sw._post_frame_diagnostic(phase,second))
        self.assertIsNone(phase.runtime_refusal_error)
        self.assertIsNone(phase.runtime_refusal_graph)
        phase.runtime_refusal_graph=graph(first)
        phase.runtime_refusal_error=first
        self.assertIn("runtime_refusal_graph",sw._post_frame_diagnostic(phase,first))
        self.assertIsNone(phase.runtime_refusal_error)
        self.assertIsNone(phase.runtime_refusal_graph)
    def test_worker_revalidation_refuses_bad_graph_and_schema_objects(self):
        g=graph(rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY))
        value=payload(g)["post_frame_diagnostic"]
        value["runtime_refusal_graph"]["nodes"][0]["code"]=base.PATH_CANARY
        self.assertEqual(sw._closed_post_frame_diagnostic(value),
          {"schema":sw.POST_FRAME_DIAGNOSTIC_SCHEMA,"step":"UNAVAILABLE","code":"UNCLASSIFIED"})
        value=payload(g)["post_frame_diagnostic"]
        class Hostile:
            def __eq__(self,other):return True
        value["schema"]=Hostile()
        self.assertEqual(sw._closed_post_frame_diagnostic(value)["step"],"UNAVAILABLE")
    def test_shared_exception_diamond_is_explicitly_incomplete(self):
        child=rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)
        got=graph(rt._LifecycleFailure("SIGNER_CLEANUP",child,(child,)))
        self.assertEqual(len(got["nodes"]),2);self.assertTrue(got["truncated"])
    def test_validators_have_identical_AST_and_bounded_index_behavior(self):
        functions=[]
        for module in (sw,hc):
            tree=ast.parse(Path(module.__file__).read_text())
            node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="_validate_runtime_refusal_graph")
            functions.append(ast.dump(node,include_attributes=False))
        self.assertEqual(*functions)
    def test_graph_literal_provenance_and_exact_union_size(self):
        expected=set()
        names=("tools/verification/current_signer/protected_signing_runtime.py",
          "tools/verification/current_signer/owned_gpg_agent.py",
          "tools/verification/current_signer/repository_metadata_assembly.py",
          "tools/verification/current_import_routing.py")
        for name in names:
            tree=ast.parse((ROOT/name).read_text())
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and node.args and isinstance(node.args[0],ast.Constant):
                    call=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ""
                    value=node.args[0].value
                    if call in {"ProtectedSigningError","OwnedAgentError","_LifecycleFailure","_ConsumerCleanupUnconfirmed","ContractError","_fail"} and isinstance(value,str) and re.fullmatch("[A-Z][A-Z0-9_]{1,63}",value):
                        expected.add(value)
                if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="READ_DESCRIPTOR_CLEANUP" for t in node.targets):
                    expected.add(ast.literal_eval(node.value))
        worker=ast.parse(Path(sw.__file__).read_text())
        assignment=next(n for n in worker.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="_RUNTIME_REFUSAL_GRAPH_CODES" for t in n.targets))
        literal=ast.literal_eval(assignment.value.right.args[0])
        self.assertEqual(literal,expected);self.assertEqual(len(literal),103)
        self.assertEqual(sw._RUNTIME_REFUSAL_GRAPH_CODES,sw._POST_FRAME_CODES|literal)
        self.assertEqual(len(sw._RUNTIME_REFUSAL_GRAPH_CODES),163)
    def test_runtime_import_names_match_source_owned_module_lookup(self):
        worker=ast.parse(Path(sw.__file__).read_text())
        runtime=ast.parse(Path(rt.__file__).read_text())
        imports={a.name for n in ast.walk(worker) if isinstance(n,ast.Import) for a in n.names}
        froms={n.module for n in ast.walk(runtime) if isinstance(n,ast.ImportFrom)}
        self.assertTrue({"protected_signing_runtime","current_import_routing"}<=imports)
        self.assertIn("owned_gpg_agent",froms)
    def test_maximum_graph_uses_longest_literals_and_actual_worker_emitter(self):
        longest=max(sw._RUNTIME_REFUSAL_GRAPH_CODES,key=len)
        g={"schema":sw._RUNTIME_REFUSAL_GRAPH_SCHEMA,"nodes":[{"parent":None,"edge":"ROOT","code":longest}]+
          [{"parent":0,"edge":"RETENTION","code":longest} for _ in range(7)],"truncated":True}
        e=RuntimeError(base.TEXT_CANARY);e.private_phase_entered=True;e.post_frame_diagnostic=payload(g)["post_frame_diagnostic"]
        rc,text=base._run_worker_main(e);self.assertEqual(rc,2)
        self.assertLess(len(text.encode()),hc._MAX_POST_FRAME_RECORD_BYTES)
        self.assertEqual(hc._parse_untrusted_post_frame_worker_stderr(text.encode())["record"],"VALID")
        base._assert_no_canary(self,text)
    def test_actual_consumer_cleanup_class_is_complete(self):
        e=rt._ConsumerCleanupUnconfirmed("COMMAND_CLEANUP",rt.ProtectedSigningError("COMMAND_FAILED",base.TEXT_CANARY),(OSError(base.TEXT_CANARY),))
        got=graph(e)
        self.assertFalse(got["truncated"])
        self.assertEqual([n["code"] for n in got["nodes"]],["COMMAND_CLEANUP","COMMAND_FAILED","PYTHON_OS_ERROR"])
    def test_explicit_module_bindings_ignore_ambient_aliases(self):
        foreign=types.ModuleType("foreign")
        with mock.patch.dict(sys.modules,{"current_import_routing":foreign,"owned_gpg_agent":foreign}):
            got=graph(routing._LeasePhaseFailure(agent.OwnedAgentError("TOOL_CHANGED",base.TEXT_CANARY)))
        self.assertEqual([n["code"] for n in got["nodes"]],["CURRENT_SIGNING_LEASE","TOOL_CHANGED"])
    def test_maximum_graph_fits_existing_worker_stderr_bound(self):
        e=rt._LifecycleFailure("SIGNER_CLEANUP",None,tuple(OSError(base.TEXT_CANARY) for _ in range(20)))
        wire=json.dumps(payload(graph(e)),sort_keys=True).encode()
        self.assertLess(len(wire),hc._MAX_POST_FRAME_RECORD_BYTES)
        self.assertEqual(hc._parse_untrusted_post_frame_worker_stderr(wire)["record"],"VALID")

class WorkerBoundaryTests(base._WorkerFixture):
    def setUp(self):
        super().setUp()
        patcher=mock.patch.dict(sys.modules,{"current_import_routing":routing})
        patcher.start()
        self.addCleanup(patcher.stop)
    def test_real_runtime_error_graph_crosses_worker_and_host_with_custody_preserved(self):
        obj=rt.ProtectedSigningRuntime(runner=lambda *a,**kw:None)
        error=rt._LifecycleFailure("SIGNER_CLEANUP",rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY),())
        def execute(this,*args,**kwargs):
            this._last_native_operation="RUNTIME_RPM_METADATA_CREATE"
            raise error
        obj.execute_live_lease=types.MethodType(execute,obj)
        out=self._flow(runtime=obj,overrides={"protected_signing_runtime":rt})
        self.assertIs(out.error,error)
        self.assertEqual(bytes(out.buffers["key"]),bytes(len(base.KEY_CANARY)))
        self.assertEqual(bytes(out.buffers["phrase"]),bytes(len(base.PHRASE_CANARY)))
        rc,text=base._run_worker_main(out.error);self.assertEqual(rc,2);base._assert_no_canary(self,text)
        parsed=hc._parse_untrusted_post_frame_worker_stderr(text.encode())
        self.assertEqual(parsed["record"],"VALID");self.assertTrue(parsed["untrusted_worker_claim"])
        self.assertEqual(parsed["runtime_refusal_graph"]["nodes"][1]["code"],"COMMAND_POLICY")
        self.assertEqual(out.lease.close_calls,0)
    def test_reported_lease_wrapper_is_captured_after_wrapping(self):
        obj=rt.ProtectedSigningRuntime()
        primary=rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)
        post=routing.ContractError("CURRENT_IMPORT_ROUTING",base.TEXT_CANARY)
        def execute(this,*a,**kw):
            this._last_native_operation="RUNTIME_RPM_METADATA_CREATE"
            try:raise primary
            except rt.ProtectedSigningError as body:
                raise routing._LeasePhaseFailure(body,post) from None
        obj.execute_live_lease=types.MethodType(execute,obj)
        out=self._flow(runtime=obj,overrides={"protected_signing_runtime":rt,"current_import_routing":routing})
        self.assertIs(type(out.error),routing._LeasePhaseFailure)
        rc,text=base._run_worker_main(out.error);self.assertEqual(rc,2)
        observed=hc._parse_untrusted_post_frame_worker_stderr(text.encode())["runtime_refusal_graph"]
        self.assertEqual([n["code"] for n in observed["nodes"]],["CURRENT_SIGNING_LEASE","COMMAND_POLICY","CURRENT_IMPORT_ROUTING"])
        self.assertEqual(out.lease.close_calls,0)
    def test_final_runtime_cleanup_wrapper_retains_nested_lease_observation(self):
        obj=rt.ProtectedSigningRuntime()
        primary=rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)
        lease_error=routing._LeasePhaseFailure(primary,routing.ContractError("CURRENT_IMPORT_ROUTING",base.TEXT_CANARY))
        final=rt._LifecycleFailure("SIGNER_CLEANUP",lease_error,())
        def execute(this,*a,**kw):
            this._last_native_operation="RUNTIME_RPM_METADATA_CREATE"
            raise final
        obj.execute_live_lease=types.MethodType(execute,obj)
        out=self._flow(runtime=obj,overrides={"protected_signing_runtime":rt,"current_import_routing":routing})
        self.assertIs(out.error,final)
        rc,text=base._run_worker_main(out.error);self.assertEqual(rc,2)
        observed=hc._parse_untrusted_post_frame_worker_stderr(text.encode())["runtime_refusal_graph"]
        self.assertEqual([n["code"] for n in observed["nodes"]],["SIGNER_CLEANUP","CURRENT_SIGNING_LEASE","COMMAND_POLICY","CURRENT_IMPORT_ROUTING"])
        self.assertEqual(out.lease.close_calls,0)
    def test_ordinary_diagnostic_error_preserves_primary_v1_and_zeroization(self):
        obj=rt.ProtectedSigningRuntime()
        primary=rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)
        def execute(this,*a,**k):raise primary
        obj.execute_live_lease=types.MethodType(execute,obj)
        with mock.patch.object(sw,"_runtime_refusal_graph",side_effect=TypeError(base.TEXT_CANARY)):
            out=self._flow(runtime=obj,overrides={"protected_signing_runtime":rt})
        self.assertIs(out.error,primary);self.assertIs(out.error.runtime,obj)
        self.assertEqual(out.error.post_frame_diagnostic["schema"],sw.POST_FRAME_DIAGNOSTIC_SCHEMA)
        self.assertNotIn("runtime_refusal_graph",out.error.post_frame_diagnostic)
        self.assertEqual(bytes(out.buffers["key"]),bytes(len(base.KEY_CANARY)))
        self.assertEqual(bytes(out.buffers["phrase"]),bytes(len(base.PHRASE_CANARY)))
        self.assertEqual(out.lease.close_calls,0)
    def test_diagnostic_interruption_retains_runtime_and_failure(self):
        obj=rt.ProtectedSigningRuntime()
        primary=rt.ProtectedSigningError("COMMAND_POLICY",base.TEXT_CANARY)
        def execute(this,*a,**k):raise primary
        obj.execute_live_lease=types.MethodType(execute,obj)
        interruption=KeyboardInterrupt()
        frame,buffers=self._frame_reader()
        lease=base.FakeLease()
        with mock.patch.object(self,"_frame_reader",return_value=(frame,buffers)),mock.patch.object(base,"FakeLease",return_value=lease),mock.patch.object(sw,"_runtime_refusal_graph",side_effect=interruption):
            with self.assertRaises(KeyboardInterrupt) as got:self._flow(runtime=obj,overrides={"protected_signing_runtime":rt})
        self.assertIs(got.exception,interruption);self.assertIs(got.exception.runtime,obj)
        self.assertIs(got.exception.__context__,primary)
        self.assertEqual(bytes(buffers["key"]),bytes(len(base.KEY_CANARY)))
        self.assertEqual(bytes(buffers["phrase"]),bytes(len(base.PHRASE_CANARY)))
        self.assertEqual(lease.close_calls,0)
        self.assertIs(sw._RETAINED_WORKER_CUSTODIES[-1]["error"],interruption)

if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result=unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    print(json.dumps({"tests":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
      "failureTestNames":[t.id().split(".")[-1] for t,_ in result.failures],
      "errorTestNames":[t.id().split(".")[-1] for t,_ in result.errors],
      "nativeExecution":False}))
    raise SystemExit(not result.wasSuccessful())
