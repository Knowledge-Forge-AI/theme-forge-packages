"""Prepare source-bound inputs for the separately approved native GUI observer.

No GUI is launched here. The CLI is restricted to the public native validation
workflow and the existing locked Python/context. Its output is data, never an
admission capability.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

SOURCE_HASH = "5c642cc3eed380324d3109a9a428be020ed529774f5c4f5877bb2bb1b93ac93f"
CONTAINER_HASH = "40f92dd2ca8e5161e55b5d85c2ece3a79a43b6d96dc20d6b0b05a0fcabf4c7fd"
NIXPKGS_REV = "b6c8664de9b6cc07fe5666a29f91884ba81197c4"
STORE = r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+"
SECURITY_DEFAULTS = dict(unsharePid=False,unshareUser=False,unshareIpc=False,
    unshareNet=False,unshareUts=False,unshareCgroup=False,privateTmp=False,
    chdirToPwd=True,dieWithParent=True,additionalMountsOrCapabilities=False)

def require(condition, reason):
    if not condition: raise ValueError(reason)

def digest(data): return hashlib.sha256(data).hexdigest()

def extract_wrapper_objects(declared: bytes, context: dict) -> dict:
    require(isinstance(declared,bytes) and len(declared)<=131072,"wrapper source bound")
    text=declared.decode("utf-8")
    require(context.get("sourceSha256")==SOURCE_HASH and context.get("containerInitSourceSha256")==CONTAINER_HASH,
            "reviewed source identities differ")
    require(context.get("nixpkgsRevision")==NIXPKGS_REV and context.get("bwrapVersion")=="0.12.0","test context pin differs")
    defaults=context.get("declaredSecurityDefaults")
    require(type(defaults) is dict and defaults==SECURITY_DEFAULTS and all(type(v) is bool for v in defaults.values()),
            "declared namespace policy differs")
    bash=re.fullmatch(r"#!("+STORE+r"/bin/bash)",text.split("\n",1)[0])
    require(bash is not None,"pinned Bash interpreter required")
    init=re.findall(r"--symlink ("+STORE+r") /init\s*\\",text)
    container=re.findall(r"^  ("+STORE+r') "\$@"$',text,re.M)
    bwrap=re.findall(r"^cmd=\(\n  ("+STORE+r"/bin/bwrap)\n",text,re.M)
    require(len(init)==len(container)==len(bwrap)==1,"ambiguous wrapper objects")
    require(container[0].endswith("-container-init"),"container init output differs")
    require(bwrap[0]==context.get("bwrap"),"bubblewrap context differs")
    return {"bwrap":bwrap[0],"containerInit":container[0],"originalInit":init[0],"pinnedBash":bash.group(1)}

def _driver(root):
    path=root/"tools/verification/p-predicate-native-driver.py"
    spec=importlib.util.spec_from_file_location("p_gui_predicate_source",path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(module.p.SOURCE_HASH==SOURCE_HASH,"predicate helper source contract")
    return module

def prepare(root,system,context_path,wrapper,closure_path,output):
    repo="Knowledge-Forge-AI/theme-forge-packages"
    require(sys.platform=="linux" and system in {"x86_64-linux","aarch64-linux"},"native Linux only")
    require(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
            and os.environ.get("GITHUB_REPOSITORY")==repo and os.environ.get("RUNNER_OS")=="Linux",
            "public hosted P validation only")
    require(os.environ.get("RUNNER_ARCH")=={"x86_64-linux":"X64","aarch64-linux":"ARM64"}[system],"native architecture differs")
    require(os.environ.get("GITHUB_WORKFLOW_REF")==repo+"/.github/workflows/validate.yml@refs/heads/main",
            "actual native validation workflow required")
    require(re.fullmatch(r"[0-9a-f]{40}",os.environ.get("GITHUB_SHA","")) is not None
            and os.environ.get("GITHUB_SHA")==os.environ.get("GITHUB_WORKFLOW_SHA"),"workflow/source identity differs")
    root=root.resolve(strict=True)
    require(re.fullmatch(STORE,str(context_path)) is not None,"materialized context must be a Nix output")
    context=json.loads(context_path.read_bytes())
    require(type(context) is dict and context.get("schema")==1,"context schema differs")
    require(Path(context["wrapper"])==wrapper,"actual public wrapper differs")
    require(Path(sys.executable).resolve()==Path(context["python"]).resolve(),"locked Python required")
    require(digest(Path(context["sourcePath"]).read_bytes())==SOURCE_HASH,"actual buildFHSEnv source differs")
    require(digest(Path(context["containerInitSource"]).read_bytes())==CONTAINER_HASH,"actual container source differs")
    driver=_driver(root)
    actual,declared,derivation,derivation_hash=driver.declared_text(str(wrapper))
    require(actual==declared,"wrapper differs from its declared derivation")
    objects=extract_wrapper_objects(declared,context)
    closure=driver.normalize_runtime_closure(json.loads(closure_path.read_bytes()))
    roots={row["path"] for row in closure}
    def store_root(path):
        match=re.match("("+STORE+r")(?:/|$)",path)
        require(match is not None,"object escaped materialized store")
        return match.group(1)
    require(all(store_root(objects[name]) in roots for name in ("bwrap","containerInit","originalInit")),
            "wrapper objects absent from actual product runtime closure")
    # The existing container producer verifier handles typed v4 and legacy
    # derivation JSON and the exact C++ source; no shell-only assumption.
    container_drv=driver.command(["nix-store","--query","--deriver",objects["containerInit"]]).decode().strip()
    container_proof=driver.container_producer(driver.json_command(["nix","derivation","show",container_drv]),
        objects["containerInit"],lambda path:Path(path).read_bytes(),container_drv)
    result={"schema":"theme-forge.p-native-gui-observer-inputs.v1","declaredText":declared.decode(),
        "expectedSha256":digest(actual),"wrapperPath":str(wrapper),"expectedResolvedWrapperPath":str(wrapper.resolve(strict=True)),
        "pinnedBash":objects.pop("pinnedBash"),"context":objects,"buildFhsEnvSourceSha256":SOURCE_HASH,
        "containerSourceSha256":CONTAINER_HASH,"declaredDerivation":derivation,
        "declaredDerivationSha256":derivation_hash,"containerProducer":container_proof,
        "productClosureSha256":digest(closure_path.read_bytes()),"nixpkgsRevision":NIXPKGS_REV,
        "python":context["python"],"publicationAuthority":False}
    raw=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
    require(len(raw)<=65536,"observer input bound")
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return result

if __name__=="__main__":
    require(len(sys.argv)==7,"expected root/system/context/wrapper/closure/output")
    prepare(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]),Path(sys.argv[4]),Path(sys.argv[5]),Path(sys.argv[6]))
