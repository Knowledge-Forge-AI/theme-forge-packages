"""Manual, pending-policy native probe driver. Does not accept GUI/publication."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("predicate", HERE / "p-process-predicate-probe.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

PRODUCTS = ("tfsb", "tfsl", "tfss", "tfnf", "theme-forge-nebular-fusion-payload")
FINAL_EXEC = b'exec "${cmd[@]}"'
OBSERVATION = b"printf '%s\\0' \"${cmd[@]}\""
CONTAINER_SOURCE_SHA256 = "40f92dd2ca8e5161e55b5d85c2ece3a79a43b6d96dc20d6b0b05a0fcabf4c7fd"
NODE_OWNER_TIMEOUT = 3 * 52 + 14


def hosted_facts(env, system):
    repo = "Knowledge-Forge-AI/theme-forge-packages"
    p.require(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and
              env.get("GITHUB_REPOSITORY") == repo and env.get("RUNNER_OS") == "Linux", "public hosted P admission")
    p.require(env.get("RUNNER_ARCH") == {"x86_64-linux":"X64", "aarch64-linux":"ARM64"}[system], "native runner architecture")
    p.require(env.get("GITHUB_WORKFLOW_REF", "").startswith(repo+"/.github/workflows/probe-current-process-predicate.yml@refs/heads/"),
              "actual predicate workflow reference")
    for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
        p.require(re.fullmatch("[0-9a-f]{40}", env.get(key, "")), "hosted source/workflow SHA")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        p.require(re.fullmatch("[1-9][0-9]*", env.get(key, "")), "hosted run/attempt")
    return {k:env[k] for k in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID",
                              "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT")}


def command(argv, cwd=None):
    result = subprocess.run(argv, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=1800)
    p.require(len(result.stdout) <= 16 * 1024 * 1024, "tool output bound")
    return result.stdout


def json_command(argv, cwd=None):
    return json.loads(command(argv, cwd))


def observation_source(source, declared):
    p.require(source == declared and len(source) <= 128 * 1024, "realized wrapper differs from declared derivation text")
    p.require(source.count(FINAL_EXEC) == 1 and source.rstrip().endswith(FINAL_EXEC), "unsupported wrapper terminal exec")
    p.require(b"cmd=(" in source and b"${ro_mounts[@]}" in source and b"${auto_mounts[@]}" in source,
              "unsupported pinned wrapper arrays")
    first = source.split(b"\n", 1)[0]
    p.require(first.startswith(b"#!/nix/store/") and first.endswith(b"/bin/bash") and b" " not in first,
              "opaque/non-Bash wrapper interpreter")
    return source.replace(FINAL_EXEC, OBSERVATION), os.fsdecode(first[2:])


def parse_argv(raw, context):
    p.require(raw and len(raw) <= 1024 * 1024 and raw.endswith(b"\0"), "NUL argv bound/framing")
    argv = [os.fsdecode(x) for x in raw[:-1].split(b"\0")]
    p.require(all(argv) and argv[0] == context["bwrap"] and
              argv[-1].startswith("/nix/store/") and argv[-1].endswith("-container-init"),
              "unexpected bwrap/container-init object")
    # Closed arities from the reviewed buildFHSEnv source, never a shell parser.
    arity = {"--dev-bind": 2, "--proc": 1, "--chdir": 1, "--die-with-parent": 0,
             "--bind": 2, "--tmpfs": 1, "--symlink": 2, "--ro-bind": 2,
             "--remount-ro": 1, "--ro-bind-try": 2}
    options, i = [], 1
    while i < len(argv) - 1:
        flag = argv[i]
        p.require(flag in arity, "unsupported bwrap flag (namespace/security changes forbidden)")
        count = arity[flag]
        p.require(i + count < len(argv) - 1, "truncated option")
        options.append((flag, *argv[i+1:i+count+1]))
        i += count + 1
    p.require(options[:3] == [("--dev-bind", "/dev", "/dev"), ("--proc", "/proc"),
                              ("--chdir", os.getcwd())], "unexpected initial namespace/profile flags")
    p.require(options.count(("--die-with-parent",)) == 1 and options.count(("--bind", "/nix", "/nix")) == 1,
              "missing original parent or /nix policy")
    inits = [i for i, option in enumerate(options) if option[0] == "--symlink" and option[-1] == "/init"]
    p.require(len(inits) == 1, "ambiguous init mount")
    return argv, options[inits[0]][1]


def seal_surrogate(argv, original_init, surrogate_init):
    out, matches = list(argv), []
    for i in range(1, len(argv)-2):
        if argv[i:i+3] == ["--symlink", original_init, "/init"]:
            matches.append(i)
    p.require(len(matches) == 1, "init substitution not unique")
    out[matches[0] + 1] = surrogate_init
    p.require(sum(a != b for a, b in zip(argv, out)) == 1, "surrogate exceeds sealed init delta")
    return out


def declared_text(path):
    real = Path(path).resolve(strict=True)
    drv = command(["nix-store", "--query", "--deriver", str(real)]).decode().strip()
    p.require(drv.startswith("/nix/store/") and drv.endswith(".drv"), "missing script derivation")
    record = json_command(["nix", "derivation", "show", drv])
    p.require(len(record) == 1, "ambiguous derivation")
    value = next(iter(record.values()))
    p.require(value["outputs"]["out"]["path"] == str(real) and isinstance(value["env"].get("text"), str),
              "unsupported opaque script derivation")
    return real.read_bytes(), value["env"]["text"].encode(), drv, p.digest(json.dumps(record, sort_keys=True).encode())


def authenticate_container_source(source):
    # It is a static C++ ELF producer, not a writeShellScript. Its sole
    # pre-exec child is ldconfig, synchronously reaped before final execv.
    p.require(p.digest(source) == CONTAINER_SOURCE_SHA256, "container-init reviewed C++ source mismatch")
    p.require(source.count(b"posix_spawn(&pid, ldconfig_argv[0]") == 1 and
              source.count(b"waitpid(pid, &status, 0)") == 1 and
              source.count(b'argv[0] = "/init";\n  execv(argv[0], (char *const *)argv);') == 1,
              "container-init reviewed spawn/wait/final-exec chain differs")
    return {"sourceSha256":p.digest(source),"kind":"static-C++-ELF",
            "preExecChild":"only source-bound ldconfig, reaped before execv /init",
            "persistentHelperBetweenMonitorAndApplication":False}


def container_producer(record, path, source_reader):
    p.require(isinstance(record,dict) and len(record)==1,"ambiguous container-init derivation")
    value=next(iter(record.values()))
    p.require(value.get("outputs",{}).get("out",{}).get("path")==path,"container-init output differs")
    build=value.get("env",{}).get("buildCommand","")
    match=re.fullmatch(r'\s*\$CXX -static -s -o \$out (/nix/store/[A-Za-z0-9._+/-]+container-init\.cc)\s*',build)
    p.require(match is not None,"opaque container-init declared native producer")
    source=match[1]
    p.require(any(source==item or source.startswith(item+"/") for item in value.get("inputSrcs",[])),
              "container-init source missing from declared inputs")
    proof=authenticate_container_source(source_reader(source))
    return {**proof,"declaredSource":source,"producerDerivationSha256":p.digest(json.dumps(record,sort_keys=True).encode())}


def verify_profile_mount(argv, root):
    profile = root + "/etc/profile"
    p.require(any(argv[i:i+3] in (["--symlink",profile,"/etc/profile"],["--ro-bind",profile,"/etc/profile"])
                  for i in range(len(argv)-2)),"original FHS profile mount not visible")
    return profile


def predicate_scoped_pass(result):
    p.require(result.get("mode")=="native-predicate-only" and result.get("fixtureMode") is False,
              "fixture result cannot admit native predicate")
    cases=result.get("cases")
    p.require(isinstance(cases,list) and len(cases)==3 and
              [row.get("case") for row in cases]==["term","normal143","controller-death"],"native predicate case order")
    p.require(all(row.get("fixtureMode") is False and row.get("admitting") is False and
                  row.get("guiQualification") is False for row in cases),"native probe rows never admitting")
    p.exact_sigterm(cases[0].get("witness",{}).get("exit_code"))
    p.require(cases[1].get("witness",{}).get("negativeRejected") is True and
              cases[1]["witness"].get("exit_code")==143<<8 and
              cases[1]["witness"].get("stableBracket",{}).get("state")=="Z", "ordinary143 negative bracket/semantics")
    p.require(cases[2].get("predicateWitness") is False and cases[2].get("nodeOwnerAlive") is True and
              cases[2].get("controllerStatus")=={"code":73,"signal":None} and
              cases[2].get("monitorWaitStatus")=={"code":137,"signal":None},"controller-death failed transaction semantics")
    return True


def normalize_runtime_closure(closure):
    """Nix2.31 path-info keys each row by path; older lists carry explicit path.

    Identity is the complete set of paths plus required NAR hash/size/reference
    fields. Registration metadata is intentionally outside dependency identity.
    """
    if isinstance(closure, dict):
        rows = list(closure.items())
    else:
        p.require(isinstance(closure, list), "path-info JSON must be path map or explicit-path list")
        rows = [(row.get("path") if isinstance(row, dict) else None, row) for row in closure]
    p.require(bool(rows), "empty path-info closure")
    normalized, seen = [], set()
    def store_path(value):
        return isinstance(value, str) and value.startswith("/nix/store/") and len(value)>11 and not any(c in value for c in "\0\n\r")
    for path, row in rows:
        p.require(store_path(path) and path not in seen and isinstance(row, dict), "invalid/duplicate path-info row")
        p.require("path" not in row or row["path"] == path, "path-info redundant path differs from key")
        p.require(isinstance(row.get("narHash"), str) and bool(row["narHash"]) and
                  type(row.get("narSize")) is int and row["narSize"] >= 0 and
                  isinstance(row.get("references"), list) and all(store_path(ref) for ref in row["references"]),
                  "path-info missing/invalid NAR identity")
        p.require(len(row["references"]) == len(set(row["references"])), "duplicate path-info reference")
        seen.add(path)
        normalized.append({"path":path,"narHash":row["narHash"],"narSize":row["narSize"],
                           "references":sorted(row["references"])})
    return sorted(normalized,key=lambda row:row["path"])


def graph(root, system):
    outputs, drvs = {}, []
    for name in PRODUCTS:
        ref = f"path:{root}#packages.{system}.{name}"
        outputs[name] = command(["nix", "build", "--no-update-lock-file", "--no-link", "--print-out-paths", ref]).decode().strip()
        p.require(outputs[name].startswith("/nix/store/") and "\n" not in outputs[name], "ambiguous product output")
        drvs.append(command(["nix", "path-info", "--no-update-lock-file", "--derivation", ref]).decode().strip())
    dag = json_command(["nix", "derivation", "show", "--recursive", *drvs])
    closure = json_command(["nix", "path-info", "--json", "--recursive", *sorted(set(outputs.values()))])
    normalized = normalize_runtime_closure(closure)
    paths = {row["path"] for row in normalized}
    p.require(set(outputs.values()).issubset(paths) and
              all(ref in paths for row in normalized for ref in row["references"]),
              "path-info recursive closure missing output or reference")
    return {"outputs": outputs, "derivationGraph": dag, "runtimeClosure": normalized}


def compare_graphs(before, after, context):
    p.require(before == after, "product outputs/complete derivation graph/runtime closure changed")
    runtime = {r["path"] for r in after["runtimeClosure"]}
    p.require(context["pythonRoot"] not in runtime, "new Python root enters product runtime closure")
    graph_text = json.dumps(after["derivationGraph"], sort_keys=True)
    for key in ("probeSource", "surrogateInit"):
        p.require(context[key] not in graph_text and context[key] not in runtime, "test source enters product dependency graph")
    return {"equal": True, "sha256": p.digest(json.dumps(after, sort_keys=True).encode()),
            "sharedPreexistingLibrariesAllowed": True, "pythonRootAbsentProductRuntime": True}


def main(root, system, evidence, node):
    p.require(system in {"x86_64-linux", "aarch64-linux"} and sys.platform == "linux", "native Linux only")
    hosted = hosted_facts(os.environ, system)
    p.require(hasattr(os, "pidfd_open") and hasattr(signal_module(), "pidfd_send_signal"), "required pidfd API absent")
    root, evidence = Path(root).resolve(), Path(evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    work = Path(tempfile.mkdtemp(prefix="p-predicate-work-", dir=os.environ["RUNNER_TEMP"]))
    p.require(evidence not in work.parents and work not in evidence.parents, "work/evidence separation")
    lock = p.digest((root / "flake.lock").read_bytes())
    p.require(json.loads((root / "flake.lock").read_text())["nodes"]["nixpkgs"]["locked"]["rev"] ==
              "b6c8664de9b6cc07fe5666a29f91884ba81197c4", "unexpected locked nixpkgs revision")
    baseline = root / "tools/predicate/r5-product-baseline"
    before = graph(str(baseline), system)
    after = graph(str(root), system)
    context_path = command(["nix", "build", "--no-update-lock-file", "--no-link", "--print-out-paths",
                            f"path:{root}#testTools.{system}.predicateContext"]).decode().strip()
    context = json.loads(Path(context_path).read_text())
    p.require(context["bwrapVersion"] == "0.12.0", "reviewed bubblewrap version differs")
    p.require(context["sourceSha256"] == p.SOURCE_HASH and p.digest(Path(context["sourcePath"]).read_bytes()) == p.SOURCE_HASH,
              "pinned buildFHSEnv source mismatch")
    p.require(Path(sys.executable).resolve() == Path(context["python"]).resolve(), "wrong test interpreter")
    p.require(p.digest(Path(context["probeSource"]).read_bytes()) == p.digest((HERE / "p-process-predicate-probe.py").read_bytes()), "probe source mismatch")
    graph_proof = compare_graphs(before, after, context)
    python_graph = json_command(["nix", "derivation", "show", "--recursive", context["pythonDerivation"]])
    python_closure = json_command(["nix", "path-info", "--json", "--recursive", context["pythonRoot"]])
    (evidence / "test-tool-derivation-graph.json").write_text(json.dumps(python_graph, sort_keys=True)+"\n")
    (evidence / "test-tool-runtime-closure.json").write_text(json.dumps(python_closure, sort_keys=True)+"\n")
    (evidence / "product-graph.json").write_text(json.dumps(after, sort_keys=True)+"\n")
    source, declared, drv, drv_hash = declared_text(context["wrapper"])
    observed, bash = observation_source(source, declared)
    observation = work / "observe-original-cmd.bash"
    observation.write_bytes(observed)
    env = {k:v for k,v in os.environ.items() if k not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "NODE_PATH"}
           and not k.startswith(("PYTHON", "BASH_FUNC_"))}
    result = subprocess.run([bash, str(observation)], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=10)
    argv, init = parse_argv(result.stdout, context)
    profile = verify_profile_mount(argv, context["fhsRoot"])
    profile_sha = p.digest(Path(profile).read_bytes())
    container_drv = command(["nix-store", "--query", "--deriver", argv[-1]]).decode().strip()
    p.require(container_drv in after["derivationGraph"] and
              any(row["path"] == argv[-1] for row in after["runtimeClosure"]),
              "container-init is not the original product graph object")
    p.require(context["containerInitSourceSha256"]==CONTAINER_SOURCE_SHA256,
              "container-init context source pin differs")
    authenticate_container_source(Path(context["containerInitSource"]).read_bytes())
    container_proof=container_producer(json_command(["nix","derivation","show",container_drv]),argv[-1],
                                       lambda path:Path(path).read_bytes())
    container_bytes=Path(argv[-1]).read_bytes()
    p.require(container_bytes.startswith(b"\x7fELF"),"container-init is not expected native ELF")
    init_bytes, init_declared, init_drv, init_drv_hash = declared_text(init)
    p.require(init_bytes == init_declared and b"source /etc/profile" in init_bytes and
              ("exec " + context["rawLauncher"] + ' "$@"').encode() in init_bytes, "original profile/launcher differs")
    surrogate = seal_surrogate(argv, init, context["surrogateInit"])
    bwrap, bwrapfd = p.open_expected(context["bwrap"])
    python, pythonfd = p.open_expected(context["python"])
    try:
        p.require(Path(node).is_absolute() and command([node,"--version"]).startswith(b"v22."), "existing Node22 owner required")
        contract = {"argv": surrogate,"bwrap": bwrap,"pythonObject":python,
                    "python":context["python"],"script":context["probeSource"]}
        sealed = work/"sealed-node-contract.json"
        sealed.write_text(json.dumps(contract,sort_keys=True))
        launch = subprocess.run([node,str(HERE/"p-predicate-launcher.mjs"),str(sealed)],
                                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                env=env,check=True,timeout=NODE_OWNER_TIMEOUT)
        p.require(len(launch.stdout)<=65536,"Node owner result bound")
        result=json.loads(launch.stdout)
        scoped_pass=predicate_scoped_pass(result)
        cases,recovery=result["cases"][:2],result["cases"][2]
    finally:
        os.close(bwrapfd)
        os.close(pythonfd)
    receipt = {"schema": 1, "kind": "P-monitor-application-predicate", "mode": "native-predicate-only",
               "guiQualification": False, "publicationAuthority": False, "admitting":False,
               "predicateScopedPass":scoped_pass,"cases": cases, "recovery": recovery,
               "graphProof": graph_proof, "flakeLockSha256": lock, "context": context,
               "sourceAuthentication": {"wrapperSha256": p.digest(source), "declaredDerivation": drv,
                    "derivationJsonSha256": drv_hash, "observationSha256": p.digest(observed),
                    "adaptation": "unique terminal exec replaced by NUL printf; original cmd array unchanged",
                    "originalInitSha256": p.digest(init_bytes), "initDerivation": init_drv,
                    "initDerivationJsonSha256": init_drv_hash, "originalArgvSha256": p.digest(result.stdout),
                    "containerInitDerivation": container_drv,
                    "containerInitProducer":container_proof,"containerInitElfSha256":p.digest(container_bytes),
                    "fhsProfileSha256": profile_sha,
                    "surrogateArgvSha256": p.digest(b"\0".join(os.fsencode(x) for x in surrogate)),
                    "onlyInitAndCaseDelta": True, "expectedBwrapOpenedObject": bwrap, "expectedPythonOpenedObject": python},
               "hosted": hosted,
               "nixVersion": command(["nix", "--version"]).decode().strip()}
    receipt["nodeOwner"]={"path":str(Path(node).resolve()),"sha256":p.digest(Path(node).read_bytes()),
                          "model":"Node monitor owner; sibling Python controller; controller-child watchdog"}
    receipt["checkedSourceSha256"] = {name:p.digest((HERE/name).read_bytes()) for name in
        ("p-predicate-launcher.mjs", "p-predicate-native-driver.py", "p-process-predicate-probe.py")}
    receipt["workflowSha256"] = p.digest((root/".github/workflows/probe-current-process-predicate.yml").read_bytes())
    receipt["evidenceFiles"] = {name: p.digest((evidence/name).read_bytes()) for name in
                                ("test-tool-derivation-graph.json", "test-tool-runtime-closure.json", "product-graph.json")}
    (evidence / "predicate-result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


def signal_module():
    import signal
    return signal


if __name__ == "__main__":
    p.require(len(sys.argv) == 5, "expected root, system, fresh evidence directory, explicit Node22 owner")
    try:
        main(*sys.argv[1:])
    except Exception as error:
        destination = Path(sys.argv[3])
        destination.mkdir(parents=True, exist_ok=True)
        # Never emit raw stderr, environment, proc buffers, command lines or
        # exception payloads from tools/files. Refusals use closed source labels.
        label = str(error) if isinstance(error, p.Refusal) else type(error).__name__
        (destination/"predicate-failure.json").write_text(json.dumps({"kind":"predicate-failure",
            "accepted":False,"guiQualification":False,"publicationAuthority":False,"reason":label})+"\n")
        raise SystemExit(1)
