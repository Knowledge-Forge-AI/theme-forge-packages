"""One key-free hosted observation with existing image custody and bounded tools."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from dataclasses import dataclass

from tf_rpm_probe_core import CONTINUABLE_CODES, held_file, strict_json, validate_result, validate_tool
from tf_rpm_probe_inputs import R_COMMIT, R_TREE, prepare_inputs

WORKFLOW_REF = ("Knowledge-Forge-AI/theme-forge-packages/"
                ".github/workflows/probe-current-rpm-metadata.yml@refs/heads/main")
ISO_SHA256 = "428b49cd76bcadf4c872fff4a00e6ff8878444e8f46788f5a9b2ddcb35da2c3a"
OWNER_LABEL = "io.themeforge.rpm-keyfree"


def require_context(env: dict, expected_commit: str) -> int:
    exact = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/theme-forge-packages",
        "GITHUB_REPOSITORY_OWNER": "Knowledge-Forge-AI", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main", "GITHUB_REF_NAME": "main", "GITHUB_REF_TYPE": "branch",
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    if (any(env.get(k) != value for k, value in exact.items())
            or env.get("GITHUB_HEAD_REF") or env.get("GITHUB_BASE_REF")
            or not re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", expected_commit)
            or expected_commit == "0" * 40 or env.get("GITHUB_SHA") != expected_commit):
        raise ValueError("CALLER_REFUSED")
    if os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        raise ValueError("PLATFORM_REFUSED")
    return int(env["GITHUB_RUN_ID"])


def load_isolation(p_root: Path):
    path = p_root / "tools/verification/isolation_probe/current_signer_isolation_probe.py"
    body = held_file(path, 2 * 1024 * 1024)
    if hashlib.sha256(body).hexdigest() != ISO_SHA256:
        raise ValueError("SOURCE_REFUSED")
    spec = importlib.util.spec_from_file_location("_rpm_existing_isolation", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(body, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def safe_mount_path(path: Path) -> str:
    raw = str(path)
    if not path.is_absolute() or any(c in raw for c in ",\r\n\x00") or path.is_symlink():
        raise ValueError("PATH_REFUSED")
    return raw


def container_argv(name: str, run_id: int, image: str, paths: dict, source_sha: str) -> tuple:
    uid, gid = os.getuid(), os.getgid()
    if min(uid, gid) <= 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("CONTAINER_REFUSED")
    return (
        "/usr/bin/docker", "create", "--name", name, "--label", OWNER_LABEL + "=" + str(run_id),
        "--pull", "never", "--network", "none", "--read-only", "--user", f"{uid}:{gid}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", f"/work/workspace:rw,noexec,nosuid,nodev,mode=0700,uid={uid},gid={gid}",
        "--mount", "type=bind,src=" + safe_mount_path(paths["p"]) + ",dst=/work/p,readonly",
        "--mount", "type=bind,src=" + safe_mount_path(paths["inputs"]) + ",dst=/work/inputs,readonly",
        "--env", "PYTHONDONTWRITEBYTECODE=1", image, "/usr/bin/python3", "-I", "-B",
        "/work/p/tools/verification/rpm_metadata_probe/entry.py", "--container",
        "--expected-entry-sha256", source_sha,
    )


class OwnedContainer:
    """Created ID is held in memory. No name removal, force removal, or retry."""

    def __init__(self, engine, *, name: str, run_id: int, image: str):
        self.engine, self.name, self.run_id, self.image = engine, name, run_id, image
        self.cid = None
        self.create_attempted = False

    def command(self, argv: tuple) -> bytes:
        code, stdout, stderr, _receipt = self.engine._run_bounded("rpm-keyfree-container", argv)
        if code != 0:
            raise ValueError("DOCKER_REFUSED")
        return stdout

    def listing(self) -> list[dict]:
        raw = self.command(("/usr/bin/docker", "container", "ls", "--all", "--no-trunc",
                            "--format", "{{json .}}"))
        rows = [strict_json(line) for line in raw.splitlines() if line]
        if (len(rows) > 128 or any(
                type(r) is not dict or type(r.get("ID")) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", r["ID"])
                or type(r.get("Names")) is not str
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", r["Names"])
                for r in rows) or len({r["ID"] for r in rows}) != len(rows)):
            raise ValueError("DOCKER_REFUSED")
        return rows

    def inspect(self) -> dict:
        records = strict_json(self.command(("/usr/bin/docker", "container", "inspect", self.cid)))
        if type(records) is not list or len(records) != 1:
            raise ValueError("DOCKER_REFUSED")
        row = records[0]
        if (row.get("Id") != self.cid or row.get("Name") != "/" + self.name
                or row.get("Image") != self.image
                or row.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) != str(self.run_id)):
            raise ValueError("CUSTODY_REFUSED")
        return row

    def create(self, argv: tuple) -> None:
        if any(r.get("Names") == self.name for r in self.listing()):
            raise ValueError("CONTAINER_PRESENT")
        self.create_attempted = True
        raw = self.command(argv).strip()
        if not re.fullmatch(rb"[0-9a-f]{64}", raw):
            raise ValueError("CUSTODY_REFUSED")
        self.cid = raw.decode("ascii")
        self.inspect()

    def observe(self) -> dict:
        self.inspect()
        raw = self.command(("/usr/bin/docker", "container", "start", "--attach", self.cid))
        if not 0 < len(raw) <= 16384:
            raise ValueError("RESULT_REFUSED")
        result = strict_json(raw)
        if (type(result) is not dict or set(result) != {"schema", "cases", "signingPerformed",
                                                     "publicationAuthority", "privateKeyAccess", "tool"}
                or result["schema"] != "tf.keyfree-rpm-metadata-observation.v1"
                or any(result[k] is not False for k in ("signingPerformed", "publicationAuthority", "privateKeyAccess"))
                or type(result["cases"]) is not list or not 0 <= len(result["cases"]) <= 4):
            raise ValueError("RESULT_REFUSED")
        validate_tool(result["tool"])
        if result["tool"]["status"] == "REFUSED":
            if result["cases"]:
                raise ValueError("RESULT_REFUSED")
            return result
        if not result["cases"]:
            raise ValueError("RESULT_REFUSED")
        for case in result["cases"]:
            validate_result(case)
        if any(case["code"] not in CONTINUABLE_CODES for case in result["cases"][:-1]):
            raise ValueError("RESULT_REFUSED")
        expected = [(arch, kind) for arch in ("x86_64", "aarch64")
                    for kind in ("unsigned", "public-fixture-signed")]
        if [(c["architecture"], c["inputClass"]) for c in result["cases"]] != expected[:len(result["cases"])]:
            raise ValueError("RESULT_REFUSED")
        if len(result["cases"]) < 4 and result["cases"][-1]["code"] in CONTINUABLE_CODES:
            raise ValueError("RESULT_REFUSED")
        return result

    def cleanup(self) -> bool:
        if not self.create_attempted:
            return True
        if self.cid is None:
            return False
        try:
            state = self.inspect().get("State", {})
            if state.get("Running") is not False or state.get("Status") not in {"created", "exited"}:
                return False
            self.command(("/usr/bin/docker", "container", "rm", self.cid))
            return all(r.get("ID") != self.cid and r.get("Names") != self.name for r in self.listing())
        except Exception:
            return False


def public_session(profile: dict, r_root: Path):
    if any(name == "rs9" or name.startswith("rs9.") for name in sys.modules):
        raise ValueError("SOURCE_REFUSED")
    sys.path.insert(0, str(r_root / "src"))
    from rs9.current_generation import CURRENT_GENERATION
    from rs9.public_release_transport import PublicReleaseTransport
    if Path(sys.modules["rs9.public_release_transport"].__file__) != r_root / "src/rs9/public_release_transport.py":
        raise ValueError("SOURCE_REFUSED")
    return PublicReleaseTransport().prepare(profile["artifacts"], commit=R_COMMIT,
                                            run_id=profile["RRun"], generation=CURRENT_GENERATION)


def run_host(args, profile: dict) -> dict:
    run_id = require_context(os.environ, args.p_commit)
    credential = {"GH_TOKEN": os.environ.pop("GH_TOKEN", None)}
    for name in tuple(os.environ):
        if name.startswith("GIT_"):
            os.environ.pop(name, None)
    p_root, r_root = Path(args.p_root), Path(args.r_root)
    work = Path(args.work_root)
    expected = [
        (p_root, Path(os.environ["GITHUB_WORKSPACE"]) / "p"),
        (r_root, Path(os.environ["GITHUB_WORKSPACE"]) / "r"),
        (work, Path(os.environ["RUNNER_TEMP"]) / ("tf-rpm-metadata-" + str(run_id))),
        (Path(args.result_out), Path(os.environ["RUNNER_TEMP"]) / ("tf-rpm-result-" + str(run_id)) / "RESULT.json"),
    ]
    if (len({given for given, _ in expected}) != 4
            or any(given != target for given, target in expected)):
        raise ValueError("PATH_REFUSED")
    iso = load_isolation(p_root)
    iso.verify_production_pins(p_root)
    mods = iso.load_production_leaves(p_root, iso.HOST_LEAVES)
    bridge = mods["runtime_workflow_bridge"]
    _, p_tree = bridge.verify_clean_p_checkout_and_resolve_tree(p_root, args.p_commit)
    _, r_tree = bridge.verify_clean_p_checkout_and_resolve_tree(r_root, R_COMMIT)
    if r_tree != R_TREE:
        raise ValueError("SOURCE_REFUSED")
    bridge._create_owned_0700_dir(work, "WORK_ROOT_CREATE_FAILED")

    context = HostContext(p_root, r_root, work, p_tree, run_id, iso, mods)
    return execute_observation(context, args, profile, credential)


@dataclass(frozen=True)
class HostContext:
    p_root: Path
    r_root: Path
    work: Path
    p_tree: str
    run_id: int
    iso: object
    mods: dict


def recheck(context: HostContext, expected_commit: str) -> None:
    bridge = context.mods["runtime_workflow_bridge"]
    if bridge.verify_clean_p_checkout_and_resolve_tree(context.p_root, expected_commit)[1] != context.p_tree:
        raise ValueError("SOURCE_REFUSED")
    context.iso.verify_production_pins(context.p_root)
    context.mods["source_closure"].authenticate_leaf_closure(
        context.p_root, expected_leaf_manifest_sha256=context.iso.PINNED_LEAF_MANIFEST_SHA256,
        require_unimported=False)


def execute_observation(context: HostContext, args, profile: dict, credential: dict) -> dict:
    iso, mods, work = context.iso, context.mods, context.work
    lease = owner = None
    result = {"schema": "tf.keyfree-rpm-metadata-host.v1", "status": "refused",
              "code": "INTERNAL", "stage": "AUTH", "source": {"pCommit": args.p_commit, "pTree": context.p_tree,
                                           "rCommit": R_COMMIT, "rTree": R_TREE, "rRun": profile["RRun"],
                                           "leafManifestSha256": iso.PINNED_LEAF_MANIFEST_SHA256},
              "observation": None, "containerAbsent": False, "workRootCleaned": False,
              "imageDisposed": False, "image": None, "signingPerformed": False, "publicationAuthority": False}
    token = ""
    try:
        token = mods["runtime_workflow_bridge"].pop_readonly_gh_token(credential)
        mods["runtime_workflow_bridge"].require_key_free_bridge_env(os.environ, allow_gh_token=False)
        recheck(context, args.p_commit)
        result["stage"] = "IMAGE"
        try:
            lease = iso.prepare_runtime_image(
                p_dir=context.p_root, work_dir=work / "image", run_suffix=str(context.run_id),
                token=token, environ=os.environ, mods=mods,
                recheck=lambda: recheck(context, args.p_commit))
        finally:
            token = ""
        if lease["container_python"] != "/usr/bin/python3":
            raise ValueError("IMAGE_PYTHON_REFUSED")
        admission_raw = held_file(context.p_root / "tools/verification/current_signer/runtime-image-admission.json",
                                  2 * 1024 * 1024)
        if hashlib.sha256(admission_raw).hexdigest() != lease["manifest_sha256"]:
            raise ValueError("SOURCE_REFUSED")
        admission = strict_json(admission_raw)
        result["image"] = {"manifestSha256": lease["manifest_sha256"],
                           "recipeSha256": lease["recipe_sha256"],
                           "createrepoRPMPin": admission["roots"]["createrepo_c"]}
        result["stage"] = "INPUTS"
        prepare_inputs(profile, work / "inputs", public_session(profile, context.r_root))
        recheck(context, args.p_commit)
        engine = mods["signing_image_build"].BoundedDockerSubprocessEngine(
            allow_native_execution=True, timeout_seconds=300)
        owner = OwnedContainer(engine, name="tf-rpm-metadata-" + str(context.run_id),
                               run_id=context.run_id, image=lease["image_id"])
        argv = container_argv(owner.name, context.run_id, lease["image_id"],
                              {"p": context.p_root, "inputs": work / "inputs"}, args.expected_entry_sha256)
        result["stage"] = "CREATE"
        owner.create(argv)
        result["stage"] = "OBSERVE"
        result["observation"] = owner.observe()
        result["stage"] = "RECHECK"
        recheck(context, args.p_commit)
        result.update(status="diagnostic-complete", code="NONE", stage="DONE")
    except Exception as error:
        lease = getattr(error, "probe_lease", lease)
    finally:
        token = ""
        credential.clear()
        result["containerAbsent"] = owner.cleanup() if owner else True
        if result["containerAbsent"]:
            disposal = iso.dispose_runtime_image(lease, mods)
            result["imageDisposed"] = disposal["confirmed"]
            result["workRootCleaned"] = mods["runtime_workflow_bridge"]._cleanup_owned_tree(work, {"inputs"})
        if not all(result[k] for k in ("containerAbsent", "imageDisposed", "workRootCleaned")):
            result.update(status="refused", code="CLEANUP_UNCONFIRMED")
    return result

