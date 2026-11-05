"""Pure tests for the PROPOSED, NOT ADMITTED ArchARM runtime probe controller.

Fake command callbacks and synthetic files only. These tests never run Docker,
GPG, pacman, makepkg, Python 3.14.9, Node, fakeroot, Xvfb, GTK or WebKit, never
touch the network and never create DB/RAW paths or real repository databases.
Passing them proves controller gate logic only; it does not prove native ARM
behaviour, signature validity on a real host, or container runtime behaviour.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
MODULE_PATH = ROOT / "tools" / "verification" / "archarm_runtime_probe" / "archarm_runtime_probe.py"
BASE_PATH = ROOT / "tools" / "verification" / "archarm_base_probe" / "archarm_base_probe.py"
ROOTFS_PIN_PATH = BASE_PATH.parent / "ROOTFS-PIN.json"
CERT_PATH = BASE_PATH.parent / "archlinuxarm-builder-public.gpg"
PACKAGE_PINS_PATH = MODULE_PATH.parent / "PACKAGE-PINS.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "probe-current-archarm-runtime.yml"
README_PATH = MODULE_PATH.parent / "README.md"


def _load_probe():
    name = "archarm_runtime_probe_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


P = _load_probe()
FPR = P.FINGERPRINT
SHA = "0123456789abcdef0123456789abcdef01234567"
RUN_ID = "987654321"
CONTEXT = {"runId": RUN_ID, "sourceSha": SHA}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


SYNTHETIC = (
    ("adwaita-fonts", "51.0-2", "any", "extra"),
    ("fakeroot", "1:2.1.4-1", "aarch64", "core"),
    ("gtk3", "1:3.24.52-2", "aarch64", "extra"),
    ("nodejs-lts-jod", "22.23.4-1", "aarch64", "extra"),
    ("python", "3.14.9-1", "aarch64", "core"),
    ("webkit2gtk-4.1", "2.54.2-1", "aarch64", "extra"),
    ("xorg-server-xvfb", "21.1.25-2", "aarch64", "extra"),
)


def synthetic_inputs(tmp):
    """Synthetic pins whose hashes are computed from synthetic in-memory bodies."""
    bodies, packages = {}, []
    for name, version, arch, repo in SYNTHETIC:
        filename = f"{name}-{version}-{arch}.pkg.tar.xz"
        url = P.PACKAGE_URL_PREFIX + repo + "/" + filename.replace(":", "%3A")
        body = ("synthetic-package:" + name).encode() * 8
        sig = ("synthetic-signature:" + name).encode()
        bodies[url], bodies[url + ".sig"] = body, sig
        packages.append({"name": name, "version": version, "architecture": arch, "url": url,
                         "filename": filename, "bytes": len(body), "sha256": sha256(body),
                         "signatureBytes": len(sig), "signatureSha256": sha256(sig),
                         "licenses": ["0BSD"]})
    total = sum(p["bytes"] for p in packages)
    pins = {"schema": P.PACKAGE_PIN_SCHEMA, "rootNames": list(P.ROOT_NAMES),
            "publicSigningFingerprint": FPR, "packages": packages,
            "packageCount": len(packages), "totalBytes": total,
            "toolPythonVersion": "3.14.9", "toolNodeVersion": "22.23.4",
            "networkDuringInstallOrProbe": False, "noBasePackageUpgrades": True}
    rootfs, rootfs_sig, cert = b"synthetic-rootfs" * 32, b"synthetic-rootfs-sig", b"synthetic-cert"
    real_pin = json.loads(ROOTFS_PIN_PATH.read_text())
    rootfs_pin = dict(real_pin, rootfsBytes=len(rootfs), rootfsSha256=sha256(rootfs),
                      signatureBytes=len(rootfs_sig), signatureSha256=sha256(rootfs_sig),
                      publicKeyBytes=len(cert), publicKeySha256=sha256(cert))
    bodies[rootfs_pin["rootfsUrl"]] = rootfs
    bodies[rootfs_pin["rootfsUrl"] + ".sig"] = rootfs_sig
    expect = {"packageCount": len(packages), "packageBytes": total,
              "rootfsUrl": rootfs_pin["rootfsUrl"], "rootfsBytes": len(rootfs),
              "rootfsSha256": sha256(rootfs), "publicKeyBytes": len(cert),
              "publicKeySha256": sha256(cert)}
    cert_path = Path(tmp) / "synthetic-cert.gpg"
    cert_path.write_bytes(cert)
    return pins, rootfs_pin, cert_path, bodies, expect


def good_status(fpr=FPR, hash_algo="8", extra=""):
    return ("[GNUPG:] NEWSIG\n"
            f"[GNUPG:] KEY_CONSIDERED {fpr} 0\n"
            f"[GNUPG:] GOODSIG {fpr[-16:]} Synthetic Signer <synthetic@invalid>\n"
            f"[GNUPG:] VALIDSIG {fpr} 2026-01-01 1767225600 0 4 0 1 {hash_algo} 00 {fpr}\n"
            + extra).encode("ascii")


def tokens(prefix, stages, failure=None):
    text = "".join(f"{prefix} {s}\n" for s in stages)
    if failure:
        text += f"{prefix} fail {failure}\n"
    return text.encode("ascii")


class FakeHost:
    """Models only the Docker/gpgv behaviour the controller relies on."""

    def __init__(self, bodies):
        self.bodies = bodies
        self.uname_value = ("Linux", "aarch64")
        self.engine_version = b"linux/arm64\n"
        self.engine_info = b"linux/aarch64\n"
        self.calls, self.downloads = [], []
        self.images, self.meta, self.containers = {}, {}, {}
        self.counter = 0
        self.corrupt_url = None
        self.gpg_status = {}
        self.mutate_doc = None
        self.outputs = {"installer": (0, tokens("TFI", P.INSTALL_STAGES)),
                        "runtime": (0, tokens("TFR", P.RUNTIME_STAGES))}
        self.timeout_role = None
        self.on_start = None
        self.inspect_calls = 0

    # host interface ------------------------------------------------------
    def uname(self):
        return self.uname_value

    def monotonic(self):
        return 0.0

    def _write(self, url, destination):
        self.downloads.append(url)
        body = self.bodies[url]
        if url == self.corrupt_url:
            body = body[:-1] + bytes([body[-1] ^ 1])
        with open(destination, "xb") as stream:
            stream.write(body)

    def download_rootfs(self, url, destination, size, sha):
        self._write(url, destination)
        P.BASE.check_file(Path(destination), size, sha)

    def download_package(self, url, destination, size, sha, deadline):
        self._write(url, destination)
        P.BASE.check_file(Path(destination), size, sha)

    def inspect_rootfs(self, path, pin):
        self.inspect_calls += 1
        return {"members": 1, "filesystemExtraction": False}

    def run(self, argv, env, *, timeout, limit):
        self.calls.append((list(argv), dict(env)))
        if argv[0] == "gpgv":
            return self.gpg_status.get(Path(argv[-1]).name, (0, good_status()))
        assert argv[0] == "docker", argv
        return self._docker(list(argv[1:]))

    # docker model ----------------------------------------------------------
    def _next(self):
        self.counter += 1
        return f"{self.counter:064x}"

    def _image(self, ref):
        if ref in self.images:
            return self.images[ref]
        return ref if ref.startswith("sha256:") and ref in self.meta else None

    def _container(self, ref):
        if ref in self.containers:
            return self.containers[ref]
        for doc in self.containers.values():
            if doc["Id"] == ref:
                return doc
        return None

    def _docker(self, args):
        cmd = args[0]
        if cmd == "version":
            return 0, self.engine_version
        if cmd == "info":
            return 0, self.engine_info
        if cmd == "import":
            assert args[1:3] == ["--platform", "linux/arm64"] and len(args) == 5
            tag = args[4]
            assert tag not in self.images, "import must never overwrite a tag"
            image_id = "sha256:" + self._next()
            self.images[tag] = image_id
            self.meta[image_id] = {"env": [], "labels": {}, "parent": None}
            return 0, (image_id + "\n").encode()
        if cmd == "image" and args[1] == "inspect":
            if args[2] == "--format":
                assert args[3] == P.IMAGE_FORMAT
                image_id = self._image(args[4])
                return (1, b"\n") if image_id is None else (0, f"{image_id}|linux|arm64\n".encode())
            assert len(args) == 3
            image_id = self._image(args[2])
            return (1, b"[]\n") if image_id is None else (0, b'[\n    {"Id":"x"}\n]\n')
        if cmd == "image" and args[1] == "rm":
            assert args[2] == "--no-prune" and len(args) == 4, args
            tag = args[3]
            image_id = self.images[tag]
            assert all(d["Image"] != image_id for d in self.containers.values())
            assert all(m["parent"] != image_id for m in self.meta.values())
            del self.images[tag]
            del self.meta[image_id]
            return 0, b"Untagged\n"
        if cmd == "container" and args[1] == "inspect":
            if args[2] == "--format":
                assert args[3] == P.CONTAINER_FORMAT
                doc = self._container(args[4])
                return (1, b"\n") if doc is None else (0, (json.dumps(doc) + "\n").encode())
            assert len(args) == 3
            return (1, b"[]\n") if self._container(args[2]) is None else (0, b'[\n    {"Id":"x"}\n]\n')
        if cmd == "container" and args[1] == "stop":
            assert args[2:4] == ["--time", "10"]
            doc = self._container(args[4])
            doc.update(Running=False, Status="exited", ExitCode=137)
            return 0, b"\n"
        if cmd == "container" and args[1] == "rm":
            assert len(args) == 3, "container rm must not be forced"
            doc = self._container(args[2])
            assert doc is not None and doc["Running"] is False
            del self.containers[doc["Name"][1:]]
            return 0, b"\n"
        if cmd == "create":
            return self._create(args)
        if cmd == "start":
            assert args[1] == "--attach" and len(args) == 3
            doc = self._container(args[2])
            role = doc["Labels"][P.LABEL_PREFIX + "role"]
            if self.on_start:
                self.on_start(role, doc)
            if self.timeout_role == role:
                doc.update(Running=True, Status="running")
                raise P.Refusal("COMMAND_TIMEOUT")
            code, out = self.outputs[role]
            doc.update(Running=False, Status="exited", ExitCode=code)
            return code, out
        if cmd == "commit":
            assert len(args) == 3
            doc = self._container(args[1])
            assert doc["Status"] == "exited" and args[2] not in self.images
            image_id = "sha256:" + self._next()
            self.images[args[2]] = image_id
            self.meta[image_id] = {"env": list(doc["Env"]), "labels": dict(doc["Labels"]),
                                   "parent": None}
            return 0, (image_id + "\n").encode()
        raise AssertionError("unexpected docker command " + repr(args))

    def _create(self, args):
        single = {"--name", "--platform", "--pull", "--network", "--ipc", "--hostname",
                  "--pids-limit", "--memory", "--memory-swap", "--cpus", "--log-driver",
                  "--user", "--workdir"}
        o = {"labels": {}, "env": [], "capadd": [], "capdrop": [], "secopt": [], "tmpfs": {},
             "mounts": [], "readonly": False}
        i = 1
        while args[i].startswith("--"):
            flag = args[i]
            if flag == "--read-only":
                o["readonly"] = True
                i += 1
                continue
            value = args[i + 1]
            i += 2
            if flag in single:
                assert flag not in o, flag
                o[flag] = value
            elif flag == "--label":
                key, val = value.split("=", 1)
                o["labels"][key] = val
            elif flag == "--env":
                o["env"].append(value)
            elif flag == "--cap-add":
                o["capadd"].append(value)
            elif flag == "--cap-drop":
                o["capdrop"].append(value)
            elif flag == "--security-opt":
                o["secopt"].append(value)
            elif flag == "--tmpfs":
                path, opts = value.split(":", 1)
                o["tmpfs"][path] = opts
            elif flag == "--mount":
                fields = {}
                for part in value.split(","):
                    key, _, val = part.partition("=")
                    fields[key] = val if val else True
                o["mounts"].append(fields)
            else:
                raise AssertionError("unexpected docker create flag " + flag)
        image, cmd = args[i], args[i + 1:]
        assert o["--pull"] == "never" and o["--platform"] == "linux/arm64"
        image_id = self._image(image)
        if image_id is None or o["--name"] in self.containers:
            return 1, b""
        meta = self.meta[image_id]
        env = {e.split("=", 1)[0]: e for e in meta["env"]}
        env.update({e.split("=", 1)[0]: e for e in o["env"]})
        top, hostm = [], []
        for m in o["mounts"]:
            ro = m.get("readonly") is True
            top.append({"Type": m["type"], "Source": m["source"], "Destination": m["target"],
                        "Mode": "", "RW": not ro, "Propagation": "rprivate"})
            hostm.append({"Type": m["type"], "Source": m["source"], "Target": m["target"],
                          "ReadOnly": ro})
        cid = self._next()
        doc = {"Id": cid, "Name": "/" + o["--name"], "Image": image_id, "ConfigImage": image,
               "User": o["--user"], "Env": list(env.values()),
               "Labels": {**meta["labels"], **o["labels"]}, "Cmd": cmd, "Entrypoint": None,
               "WorkingDir": o["--workdir"], "Hostname": o["--hostname"], "Mounts": top,
               "Host": {"NetworkMode": o["--network"], "IpcMode": o["--ipc"], "PidMode": "",
                        "UTSMode": "", "UsernsMode": "", "Privileged": False,
                        "CapAdd": ["CAP_" + c for c in o["capadd"]] or None,
                        "CapDrop": o["capdrop"], "SecurityOpt": o["secopt"],
                        "ReadonlyRootfs": o["readonly"], "Tmpfs": o["tmpfs"] or None,
                        "Binds": None, "Mounts": hostm or None, "VolumesFrom": None,
                        "Devices": [], "DeviceRequests": None, "DeviceCgroupRules": None,
                        "PortBindings": {}, "PublishAllPorts": False, "ExtraHosts": None,
                        "Links": None, "GroupAdd": None, "Sysctls": None, "VolumeDriver": "",
                        "CgroupParent": "", "Init": None, "OomKillDisable": None,
                        "Memory": int(o["--memory"]), "MemorySwap": int(o["--memory-swap"]),
                        "NanoCpus": int(o["--cpus"]) * 1000000000,
                        "PidsLimit": int(o["--pids-limit"]),
                        "LogConfig": {"Type": o["--log-driver"], "Config": {}},
                        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                        "AutoRemove": False},
               "Status": "created", "Running": False, "ExitCode": 0, "OOMKilled": False}
        if self.mutate_doc:
            self.mutate_doc(doc["Labels"][P.LABEL_PREFIX + "role"], doc)
        self.containers[o["--name"]] = doc
        return 0, (cid + "\n").encode()

    # assertions helpers ------------------------------------------------
    def docker_args(self):
        return [argv[1:] for argv, _ in self.calls if argv[0] == "docker"]


class TempCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tmp-archarm-runtime-", dir=TESTS_DIR))

    def tearDown(self):
        shutil.rmtree(self.tmp)


class BaseHelperContract(unittest.TestCase):
    def test_exact_local_module_registered(self):
        self.assertIs(sys.modules[P.BASE_MODULE_NAME], P.BASE)
        self.assertEqual(Path(P.BASE.__file__).resolve(), BASE_PATH.resolve())
        self.assertIs(P.Refusal, P.BASE.Refusal)
        for attribute in P.BASE_CONTRACT:
            self.assertTrue(callable(getattr(P.BASE, attribute)))

    def test_local_host_delegates_to_base_command(self):
        seen = []
        original = P.BASE.command
        P.BASE.command = lambda argv, env, *, timeout, limit: seen.append((argv, timeout, limit)) or (0, b"")
        try:
            P.LocalHost(P.BASE).run(["true"], {}, timeout=7, limit=9)
        finally:
            P.BASE.command = original
        self.assertEqual(seen, [(["true"], 7, 9)])

    def test_reload_refuses_foreign_module_identity(self):
        original = sys.modules[P.BASE_MODULE_NAME]
        sys.modules[P.BASE_MODULE_NAME] = type(sys)("archarm_base_probe")
        sys.modules[P.BASE_MODULE_NAME].__file__ = str(TESTS_DIR / "elsewhere.py")
        try:
            with self.assertRaises(RuntimeError):
                P.load_base_helper()
        finally:
            sys.modules[P.BASE_MODULE_NAME] = original


class RealPinClosure(unittest.TestCase):
    def test_real_package_pins_closed(self):
        raw = P.read_bounded(PACKAGE_PINS_PATH, P.MAX_PIN_FILE_BYTES)
        self.assertEqual(P.validate_package_pin_bytes(raw), raw)
        self.assertEqual(len(raw), P.PACKAGE_PINS_BYTES)
        self.assertEqual(sha256(raw), P.PACKAGE_PINS_SHA256)
        doc = P.validate_package_pins(P.load_json(raw), P.REAL_EXPECT)
        self.assertEqual(len(doc["packages"]), 139)
        self.assertEqual(sum(p["bytes"] for p in doc["packages"]), 201499452)
        self.assertTrue(set(P.ROOT_NAMES) <= {p["name"] for p in doc["packages"]})

    def test_exact_pin_file_bytes_refuse_mutation_or_truncation(self):
        raw = PACKAGE_PINS_PATH.read_bytes()
        for changed in (raw[:-1], raw[:-1] + b" "):
            with self.subTest(size=len(changed)):
                with self.assertRaises(P.Refusal) as got:
                    P.validate_package_pin_bytes(changed)
                self.assertEqual(str(got.exception), "PIN_FILE")

    def test_ptp_flag_claims_only_the_installer_check(self):
        self.assertEqual(P.INSTALL_FLAGS["ptpcaps"], "ptpHelperFileCapsSetInInstaller")
        self.assertNotIn("ptpHelperFileCapsRetained", P.FLAG_KEYS)
        text = " ".join(README_PATH.read_text().split())
        self.assertIn("installer layer before commit; it is not re-checked in the committed image.", text)

    def test_real_rootfs_pin_and_public_certificate(self):
        pin = P.validate_rootfs_pin(json.loads(ROOTFS_PIN_PATH.read_text()), P.REAL_EXPECT)
        self.assertEqual(pin["publicKeyFingerprint"], FPR)
        P.BASE.check_file(CERT_PATH, P.REAL_EXPECT["publicKeyBytes"],
                          P.REAL_EXPECT["publicKeySha256"])

    def test_scripts_embed_only_fixed_literals(self):
        s = P.INSTALL_SCRIPT
        self.assertIn('test "$#" -eq 139', s)
        self.assertIn("-eq 278", s)
        self.assertIn("comm -13", s)
        self.assertIn("FPR=" + FPR, s)
        self.assertEqual(P.REAL_EXPECT["packageCount"], 139)
        r = P.RUNTIME_SCRIPT
        for literal in ("(3, 14, 9)", "v22.23.4 arm64 linux", "[2, 54, 2]",
                        "PKGEXT=.pkg.tar.zst", "SOURCE_DATE_EPOCH=1767225600",
                        "arch=('aarch64')", "28b52ffd", "libgtk-3.so.0",
                        "libwebkit2gtk-4.1.so.0", "gtk_init_check", "DISPLAY=:99",
                        "pacman -Qip", "repo-add"):
            self.assertIn(literal, r)
        for forbidden in ("--skipinteg", "--nodeps", "--assume-installed", "--assumeinstalled",
                          "--overwrite", "--noscriptlet", "--dbonly", "gen-key", "--sign ",
                          "sudo", "curl", "wget", "docker", "SigLevel", "Never", "--keyserver",
                          "--recv", "pacman-key", "--refresh", "-Sy"):
            self.assertNotIn(forbidden, s)
            self.assertNotIn(forbidden, r)

    def test_pacman_config_closed(self):
        conf = P.PACMAN_CONF
        self.assertIn("LocalFileSigLevel = Required\n", conf)
        self.assertIn("Architecture = aarch64\n", conf)
        self.assertIn("GPGDir = /var/lib/tf-runtime-probe-gnupg/\n", conf)
        self.assertEqual([l for l in conf.splitlines() if l.startswith("[")], ["[options]"])
        for forbidden in ("Never", "Optional", "TrustAll", "Server", "Include", "XferCommand"):
            self.assertNotIn(forbidden, conf)


class PinRefusals(TempCase):
    def setUp(self):
        super().setUp()
        self.pins, self.rootfs_pin, _, _, self.expect = synthetic_inputs(self.tmp)

    def refused(self, doc, label, expect=None):
        with self.assertRaises(P.Refusal) as caught:
            P.validate_package_pins(doc, expect or self.expect)
        self.assertEqual(str(caught.exception), label)

    def test_synthetic_valid(self):
        P.validate_package_pins(self.pins, self.expect)

    def test_refusals(self):
        def mutate(fn):
            doc = copy.deepcopy(self.pins)
            fn(doc)
            return doc
        self.refused(mutate(lambda d: d.update(extra=1)), "PIN_SCHEMA")
        self.refused(mutate(lambda d: d.update(packageCount=99)), "PIN_COUNT")
        self.refused(mutate(lambda d: d.update(totalBytes=d["totalBytes"] + 1)), "PIN_BYTES")
        self.refused(mutate(lambda d: d.update(publicSigningFingerprint="0" * 40)), "PIN_FINGERPRINT")
        self.refused(mutate(lambda d: d.update(networkDuringInstallOrProbe=True)), "PIN_SCHEMA")
        self.refused(mutate(lambda d: d.update(toolPythonVersion="3.14.8")), "PIN_VERSION")
        self.refused(mutate(lambda d: d["rootNames"].pop()), "PIN_ROOTS")
        self.refused(mutate(lambda d: d["packages"][0].update(command="sh")), "PIN_PACKAGE")
        self.refused(mutate(lambda d: d["packages"][0].update(bytes=True)), "PIN_BYTES")
        self.refused(mutate(lambda d: d["packages"][0].update(bytes=P.MAX_PACKAGE_BYTES + 1)),
                     "PIN_BYTES")
        self.refused(mutate(lambda d: d["packages"][0].update(signatureBytes=0)), "PIN_BYTES")
        self.refused(mutate(lambda d: d["packages"][0].update(sha256="A" * 64)), "PIN_PACKAGE")
        self.refused(mutate(lambda d: d["packages"][0].update(architecture="x86_64")), "PIN_PACKAGE")
        self.refused(mutate(lambda d: d["packages"][0].update(filename="../evil.pkg.tar.xz")),
                     "PIN_PACKAGE")
        self.refused(mutate(lambda d: d["packages"].append(copy.deepcopy(d["packages"][0]))),
                     "PIN_COUNT")
        self.refused(mutate(lambda d: d["packages"][4].update(version="3.14.8-1")), "PIN_PACKAGE")
        mirror = lambda d: d["packages"][0].update(url=d["packages"][0]["url"].replace(
            "fl.us.mirror", "de.mirror"))
        self.refused(mutate(mirror), "PIN_URL")
        plain = lambda d: d["packages"][0].update(url=d["packages"][0]["url"].replace(
            "https://", "http://"))
        self.refused(mutate(plain), "PIN_URL")
        other_repo = lambda d: d["packages"][0].update(url=d["packages"][0]["url"].replace(
            "/extra/", "/testing/"))
        self.refused(mutate(other_repo), "PIN_URL")
        unencoded = lambda d: d["packages"][1].update(url=d["packages"][1]["url"].replace("%3A", ":"))
        self.refused(mutate(unencoded), "PIN_URL")

    def test_python_version_pin(self):
        doc = copy.deepcopy(self.pins)
        record = doc["packages"][4]
        record.update(version="3.14.8-1", filename="python-3.14.8-1-aarch64.pkg.tar.xz",
                      url=P.PACKAGE_URL_PREFIX + "core/python-3.14.8-1-aarch64.pkg.tar.xz")
        self.refused(doc, "PIN_VERSION")

    def test_json_loader_refusals(self):
        for raw in (b'{"a": 1, "a": 2}', b'{"a": NaN}', b"\xff", b"[1,"):
            with self.assertRaises(P.Refusal) as caught:
                P.load_json(raw)
            self.assertEqual(str(caught.exception), "PIN_JSON")

    def test_rootfs_pin_refusals(self):
        P.validate_rootfs_pin(self.rootfs_pin, self.expect)
        for change in ({"rootfsSha256": "0" * 64}, {"publicKeyFingerprint": "0" * 40},
                       {"rootfsUrl": "https://example.invalid/x.tar.gz"}, {"unexpected": 1},
                       {"signatureBytes": 0}):
            pin = dict(self.rootfs_pin, **change)
            with self.assertRaises(P.Refusal) as caught:
                P.validate_rootfs_pin(pin, self.expect)
            self.assertEqual(str(caught.exception), "ROOTFS_PIN")


class ContextAndPaths(TempCase):
    def test_context(self):
        self.assertEqual(P.validate_context(RUN_ID, "1", SHA), CONTEXT)
        for args, label in (((" 1", "1", SHA), "CONTEXT_RUN_ID"), (("0", "1", SHA), "CONTEXT_RUN_ID"),
                            ((RUN_ID, "2", SHA), "CONTEXT_RUN_ATTEMPT"),
                            ((RUN_ID, "1", SHA.upper()), "CONTEXT_SOURCE_SHA"),
                            ((RUN_ID, "1", SHA[:12]), "CONTEXT_SOURCE_SHA"),
                            ((RUN_ID, "1", SHA + ";x"), "CONTEXT_SOURCE_SHA")):
            with self.assertRaises(P.Refusal) as caught:
                P.validate_context(*args)
            self.assertEqual(str(caught.exception), label)

    def test_paths(self):
        result = P.validate_result_path(str(self.tmp / "result.json"))
        P.validate_work_path(str(self.tmp / "work"), result)
        (self.tmp / "exists").mkdir()
        for text in ("relative/work", str(self.tmp / "a,b"), str(self.tmp / "exists"),
                     str(self.tmp / "x" / ".." / "y"), str(self.tmp / "db"),
                     str(self.tmp / "missing-parent" / "work")):
            with self.assertRaises(P.Refusal):
                P.validate_work_path(text, result)
        with self.assertRaises(P.Refusal):
            P.validate_work_path(str(self.tmp), self.tmp / "result.json")
        with self.assertRaises(P.Refusal):
            P.validate_result_path(str(self.tmp / "result.txt"))

    def test_names_include_run_attempt_and_source(self):
        names = P.Names(CONTEXT)
        for value in (names.base_tag, names.derived_tag, names.installer, names.runtime):
            self.assertIn(f"r{RUN_ID}-a1-{SHA[:12]}", value)
        self.assertEqual(len({names.base_tag, names.derived_tag, names.installer, names.runtime}), 4)


class SignatureStatus(unittest.TestCase):
    def ok(self, status, code=0):
        return P.check_gpg_status(code, status, FPR, "PACKAGE_SIGNATURE")

    def bad(self, status, code=0):
        with self.assertRaises(P.Refusal) as caught:
            self.ok(status, code)
        self.assertEqual(str(caught.exception), "PACKAGE_SIGNATURE")

    def test_good(self):
        self.assertTrue(self.ok(good_status()))
        self.assertTrue(self.ok(good_status(hash_algo="10")))

    def test_malformed_and_wrong(self):
        self.bad(good_status(), code=1)
        self.bad(good_status(hash_algo="2"))
        self.bad(good_status(fpr="0" * 40))
        self.bad(good_status(extra="[GNUPG:] BADSIG 77193F152BDBE6A6 x\n"))
        self.bad(good_status(extra="[GNUPG:] EXPKEYSIG 77193F152BDBE6A6 x\n"))
        self.bad(good_status(extra="[GNUPG:] ERRSIG x\n"))
        self.bad(good_status() + good_status())
        self.bad(good_status().replace(b"[GNUPG:] GOODSIG", b"[GNUPG:] NOTICE"))
        self.bad(good_status() + b"plain text\n")
        self.bad(good_status() + "é\n".encode())
        primary = good_status().decode().replace(f" 00 {FPR}", " 00 " + "1" * 40).encode()
        self.bad(primary)
        cls = good_status().decode().replace(" 8 00 ", " 8 01 ").encode()
        self.bad(cls)
        rsa = good_status().decode().replace(" 0 1 8 ", " 0 22 8 ").encode()
        self.bad(rsa)


class FakeResponse:
    def __init__(self, body, url, *, status=200, length=None):
        self.body, self.url, self.status = body, url, status
        self.headers = {"Content-Length": str(len(body) if length is None else length)}
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self):
        return self.url

    def read(self, n):
        chunk = self.body[self.offset:self.offset + n]
        self.offset += len(chunk)
        return chunk


class FakeOpener:
    def __init__(self, response):
        self.response, self.opened = response, []

    def open(self, url, timeout):
        self.opened.append((url, timeout))
        return self.response


class PackageDownload(TempCase):
    URL = P.PACKAGE_URL_PREFIX + "extra/demo-1-1-aarch64.pkg.tar.xz"
    BODY = b"demo-package"

    def fetch(self, response, name="out", url=None, clock=lambda: 0.0):
        opener = FakeOpener(response)
        P.download_package(url or self.URL, self.tmp / name, len(self.BODY), sha256(self.BODY),
                           1000.0, opener_factory=lambda: opener, clock=clock)
        return opener

    def refused(self, label, *args, **kwargs):
        with self.assertRaises(P.Refusal) as caught:
            self.fetch(*args, **kwargs)
        self.assertEqual(str(caught.exception), label)

    def test_good_once(self):
        opener = self.fetch(FakeResponse(self.BODY, self.URL))
        self.assertEqual(len(opener.opened), 1)
        self.assertEqual((self.tmp / "out").read_bytes(), self.BODY)

    def test_refusals_no_retry(self):
        self.refused("INPUT_URL", FakeResponse(self.BODY, self.URL),
                     url="http://fl.us.mirror.archlinuxarm.org/aarch64/extra/demo-1-1-aarch64.pkg.tar.xz")
        self.refused("INPUT_URL", FakeResponse(self.BODY, self.URL),
                     url="https://mirror.invalid/aarch64/extra/demo-1-1-aarch64.pkg.tar.xz")
        self.refused("INPUT_TRANSPORT", FakeResponse(self.BODY, self.URL + "?moved"), name="a")
        self.refused("INPUT_TRANSPORT", FakeResponse(self.BODY, self.URL, status=203), name="b")
        self.refused("INPUT_SIZE", FakeResponse(self.BODY, self.URL, length=5), name="c")
        self.refused("INPUT_SIZE", FakeResponse(self.BODY + b"x", self.URL, length=len(self.BODY)),
                     name="d")
        rotated = b"demo-packagf"
        self.refused("INPUT_HASH", FakeResponse(rotated, self.URL), name="e")
        ticks = iter([0.0, 0.0, 99999.0])
        self.refused("INPUT_TIMEOUT", FakeResponse(self.BODY, self.URL), name="f",
                     clock=lambda: next(ticks))
        (self.tmp / "g").write_bytes(b"")
        self.refused("INPUT_TRANSPORT", FakeResponse(self.BODY, self.URL), name="g")

    def test_opener_has_no_proxy_and_refuses_redirect(self):
        opener = P.build_package_opener()
        kinds = [type(h) for h in opener.handlers]
        self.assertIn(P.BASE.NoRedirect, kinds)
        proxies = [h for h in opener.handlers if type(h).__name__ == "ProxyHandler"]
        self.assertTrue(all(h.proxies == {} for h in proxies))
        with self.assertRaises(P.Refusal) as caught:
            P.BASE.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://x.invalid/")
        self.assertEqual(str(caught.exception), "INPUT_REDIRECT")


class TokenParsing(unittest.TestCase):
    def parse(self, data):
        return P.parse_tokens(data, "TFI", P.INSTALL_STAGES, P.INSTALL_FAILURES, "INSTALL_OUTPUT")

    def test_good_and_failure(self):
        self.assertEqual(self.parse(tokens("TFI", P.INSTALL_STAGES)), (list(P.INSTALL_STAGES), None))
        self.assertEqual(self.parse(tokens("TFI", ["inputs", "keyring"], "chroot")),
                         (["inputs", "keyring"], "chroot"))
        self.assertEqual(self.parse(b""), ([], None))

    def test_refusals(self):
        for data in (b"TFI keyring\n", b"TFI inputs\nTFI inputs\n", b"TFI inputs",
                     b"TFI fail unknown\n", b"TFI fail chroot\nTFI inputs\n",
                     b"error: something raw\n", b"TFR inputs\n", b"TFI inputs extra\n",
                     b"TFI \xff\n", tokens("TFI", P.INSTALL_STAGES) + b"TFI done\n"):
            with self.assertRaises(P.Refusal) as caught:
                self.parse(data)
            self.assertEqual(str(caught.exception), "INSTALL_OUTPUT")


class ArgvGates(TempCase):
    def test_installer_argv(self):
        names = P.Names(CONTEXT)
        argv = P.installer_create_argv(names, self.tmp / "inputs")
        self.assertEqual(argv[0], "create")
        joined = " ".join(argv[:-1])
        for required in ("--network none", "--ipc none", "--cap-drop ALL",
                         "--security-opt no-new-privileges=true", "--pull never",
                         "--log-driver none", "--user 0:0", "--pids-limit 256"):
            self.assertIn(required, joined)
        caps = [argv[i + 1] for i, a in enumerate(argv) if a == "--cap-add"]
        self.assertEqual(caps, ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID",
                                "SETFCAP"])
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
        self.assertEqual(mounts, [f"type=bind,source={self.tmp / 'inputs'},target=/run/tf-inputs,readonly"])
        self.assertEqual(argv[-3:], list(P.INSTALLER_CMD))

    def test_runtime_argv(self):
        argv = P.runtime_create_argv(P.Names(CONTEXT))
        joined = " ".join(argv[:-1])
        for required in ("--read-only", "--user 65534:65534", "--cap-drop ALL", "--network none",
                         "--tmpfs /tmp:" + P.TMPFS_OPTIONS):
            self.assertIn(required, joined)
        self.assertNotIn("--cap-add", argv)
        self.assertNotIn("--mount", argv)

    def test_no_forbidden_flags_anywhere(self):
        names = P.Names(CONTEXT)
        for argv in (P.installer_create_argv(names, self.tmp / "inputs"), P.runtime_create_argv(names)):
            head = argv[:-1]
            for forbidden in ("--privileged", "-v", "--volume", "--network=host", "host",
                              "--pid", "--userns", "--device", "--rm", "-f", "--force",
                              "seccomp=unconfined", "apparmor=unconfined", "docker.sock",
                              "SYS_ADMIN", "NET_ADMIN", "SYS_CHROOT", "--env-file", "--add-host"):
                self.assertNotIn(forbidden, head)
            self.assertFalse(any("docker.sock" in a for a in head))


class ContainerReadback(TempCase):
    def make(self, role):
        pins, rootfs_pin, cert, bodies, expect = synthetic_inputs(self.tmp)
        host = FakeHost(bodies)
        names = P.Names(CONTEXT)
        _, out = host._docker(["import", "--platform", "linux/arm64", "x", names.base_tag])
        base_id = out.decode().strip()
        inputs = self.tmp / "inputs"
        if role == "installer":
            _, cid = host._create(P.installer_create_argv(names, inputs))
            exp = P.expected_container("installer", names, image_id=base_id, inputs_dir=inputs)
            doc = host.containers[names.installer]
        else:
            host.meta[base_id]["env"] = list(P.INSTALLER_ENV)
            host.meta[base_id]["labels"] = names.labels("installer")
            host.images[names.derived_tag] = base_id
            _, cid = host._create(P.runtime_create_argv(names))
            exp = P.expected_container("runtime", names, image_id=base_id)
            doc = host.containers[names.runtime]
        exp["id"] = cid.decode().strip()
        return json.loads(json.dumps(doc)), exp

    def test_good(self):
        for role in ("installer", "runtime"):
            doc, exp = self.make(role)
            self.assertTrue(P.verify_container(doc, exp, "X"))

    def test_mutations_refused(self):
        mutations = [
            lambda d: d["Host"].update(NetworkMode="bridge"),
            lambda d: d["Host"].update(NetworkMode="host"),
            lambda d: d["Host"].update(Privileged=True),
            lambda d: d["Host"].update(CapAdd=(d["Host"]["CapAdd"] or []) + ["CAP_SYS_ADMIN"]),
            lambda d: d["Host"].update(CapDrop=[]),
            lambda d: d["Host"].update(SecurityOpt=["seccomp=unconfined", "no-new-privileges"]),
            lambda d: d["Host"].update(SecurityOpt=[]),
            lambda d: d["Host"].update(Binds=["/var/run/docker.sock:/var/run/docker.sock"]),
            lambda d: d["Host"].update(PidMode="host"),
            lambda d: d["Host"].update(IpcMode="host"),
            lambda d: d["Host"].update(Memory=0),
            lambda d: d["Host"].update(PidsLimit=None),
            lambda d: d["Host"].update(Devices=[{"PathOnHost": "/dev/kvm"}]),
            lambda d: d["Host"].update(LogConfig={"Type": "json-file"}),
            lambda d: d["Host"].update(ReadonlyRootfs=not d["Host"]["ReadonlyRootfs"]),
            lambda d: d.update(Labels={}),
            lambda d: d.update(Cmd=["/bin/sh", "-c", "true"]),
            lambda d: d.update(Env=d["Env"] + ["GITHUB_TOKEN=x"]),
            lambda d: d.update(User="0:0" if d["User"] != "0:0" else "1000:1000"),
            lambda d: d.update(Id="f" * 64),
            lambda d: d.update(Image="sha256:" + "e" * 64),
            lambda d: d["Mounts"].append({"Type": "bind", "Source": "/", "Destination": "/host",
                                          "RW": True}),
        ]
        for role in ("installer", "runtime"):
            for index, mutate in enumerate(mutations):
                doc, exp = self.make(role)
                mutate(doc)
                with self.assertRaises(P.Refusal, msg=f"{role} mutation {index}"):
                    P.verify_container(doc, exp, "X")

    def test_installer_mount_must_be_readonly(self):
        doc, exp = self.make("installer")
        doc["Mounts"][0]["RW"] = True
        with self.assertRaises(P.Refusal):
            P.verify_container(doc, exp, "X")
        doc, exp = self.make("installer")
        doc["Host"]["Mounts"][0]["ReadOnly"] = False
        with self.assertRaises(P.Refusal):
            P.verify_container(doc, exp, "X")


class PresenceReadback(unittest.TestCase):
    def test_v2_schema_and_installer_labels_match_script(self):
        self.assertEqual(P.RESULT_SCHEMA, "tf.archarm-key-free-runtime-probe.v2")
        self.assertEqual(set(re.findall(r"\bfail ([a-z_]+)\b", P.INSTALL_SCRIPT)),
                         set(P.INSTALL_FAILURES))
        self.assertNotIn("INSTALL_HOOKS", P.REFUSALS)

    def check(self, code, output):
        calls = []
        def docker(args, **kwargs):
            calls.append((args, kwargs))
            return code, output
        result = P.presence(docker, "container", "owned-fixture")
        self.assertEqual(calls, [(["container", "inspect", "owned-fixture"],
                                  {"limit": P.PRESENCE_LIMIT})])
        return result

    def test_indented_and_compact_single_object(self):
        for output in (b'[{"Id":"x"}]\n', b'[\n    {"Id":"x"}\n]\n'):
            with self.subTest(output=output):
                self.assertTrue(self.check(0, output))

    def test_only_nonzero_empty_array_establishes_absence(self):
        for output in (b"[]\n", b"[ \n ]\n"):
            with self.subTest(output=output):
                self.assertFalse(self.check(1, output))
        with self.assertRaises(P.Refusal):
            self.check(0, b"[]\n")

    def test_invalid_or_ambiguous_readback_is_refused(self):
        for code, output in ((0, b"{}"), (0, b"[{}"), (0, b"[{},{}]"),
                             (0, b"[null]"), (0, b"null"), (0, b"[true]"),
                             (1, b"[{}]"), (2, b"[]"), (0, b"[{}] trailing"),
                             (0, b"\xff")):
            with self.subTest(code=code, output=output):
                with self.assertRaises(P.Refusal) as caught:
                    self.check(code, output)
                self.assertEqual(str(caught.exception), "DOCKER_READBACK")


class FlowCase(TempCase):
    def setUp(self):
        super().setUp()
        self.pins, self.rootfs_pin, self.cert, bodies, self.expect = synthetic_inputs(self.tmp)
        self.host = FakeHost(bodies)
        self.work = self.tmp / "work"
        self.names = P.Names(CONTEXT)
        self.forbid_base_entrypoints()

    def forbid_base_entrypoints(self):
        def refuse(*_args, **_kwargs):
            raise AssertionError("base native_probe/main must never be called")
        self._saved = (P.BASE.native_probe, P.BASE.main)
        P.BASE.native_probe = refuse
        P.BASE.main = refuse
        self.addCleanup(self.restore_base)

    def restore_base(self):
        P.BASE.native_probe, P.BASE.main = self._saved

    def run_probe(self):
        result = P.run_probe(context=CONTEXT, package_pins=self.pins, rootfs_pin=self.rootfs_pin,
                             certificate=self.cert, work=self.work, host=self.host,
                             digests={"rootfsSha256": self.rootfs_pin["rootfsSha256"],
                                      "rootfsPinSha256": "1" * 64, "packagePinsSha256": "2" * 64,
                                      "publicKeySha256": self.expect["publicKeySha256"]},
                             expect=self.expect)
        return P.finalize(result)

    def assert_no_forced_or_prune(self):
        for args in self.host.docker_args():
            for forbidden in ("-f", "--force", "prune", "push", "save", "export", "login",
                              "--privileged", "build", "pull"):
                self.assertNotIn(forbidden, args[:-3] if args and args[0] == "create" else args)

    def assert_clean(self, result):
        self.assertTrue(result["cleanupComplete"])
        self.assertFalse(self.work.exists())
        self.assertEqual(self.host.containers, {})
        self.assertEqual(self.host.images, {})
        self.assert_no_forced_or_prune()


class FullFlow(FlowCase):
    def test_pass(self):
        result = self.run_probe()
        self.assertEqual(result["status"], "pass", result)
        self.assertIsNone(result["refusal"])
        self.assertTrue(all(result["flags"].values()))
        self.assertEqual(result["counts"]["packageSignaturesVerified"], len(SYNTHETIC))
        self.assertTrue(all(v is False for v in result["assertions"].values()))
        self.assert_clean(result)
        text = json.dumps(result)
        self.assertNotIn(str(self.tmp), text)
        self.assertNotIn("TFI", text)
        self.assertLessEqual(len(text), P.MAX_RESULT_BYTES)
        for argv, env in self.host.calls:
            self.assertEqual(set(env), {"PATH", "HOME", "GNUPGHOME", "LANG", "LC_ALL", "TMPDIR"}
                             | ({"DOCKER_CONFIG"} if argv[0] == "docker" else set()))
            if argv[0] == "docker":
                self.assertEqual(env["HOME"], env["DOCKER_CONFIG"])
                self.assertEqual(env["DOCKER_CONFIG"], str(self.work / "docker-home"))
        order = [a[0] if a[0] not in ("image", "container") else a[0] + " " + a[1]
                 for a in self.host.docker_args()]
        self.assertLess(order.index("import"), order.index("create"))
        self.assertLess(order.index("commit"), len(order) - order[::-1].index("create") - 1)
        self.assertEqual(self.host.inspect_calls, 1)

    def test_signature_verification_precedes_import(self):
        result = self.run_probe()
        calls = [argv[0] if argv[0] == "gpgv" else argv[1] for argv, _ in self.host.calls]
        last_gpgv = len(calls) - calls[::-1].index("gpgv") - 1
        self.assertLess(last_gpgv, calls.index("import"))
        self.assertEqual(calls.count("gpgv"), len(SYNTHETIC) + 1)
        self.assertEqual(result["status"], "pass")


class FailureFlows(FlowCase):
    def test_wrong_host_before_any_command(self):
        for uname in (("Linux", "x86_64"), ("Darwin", "arm64"), ("Linux", "arm64")):
            self.host.uname_value = uname
            result = self.run_probe()
            self.assertEqual(result["refusal"], "NATIVE_ARM_HOST")
            self.assertEqual(self.host.calls, [])
            self.assertFalse(self.work.exists())
            self.assertTrue(result["cleanupComplete"])

    def test_existing_work_root_untouched(self):
        self.work.mkdir()
        (self.work / "sentinel").write_text("owner")
        result = self.run_probe()
        self.assertEqual(result["refusal"], "FRESH_WORK_ROOT")
        self.assertEqual((self.work / "sentinel").read_text(), "owner")
        self.assertEqual(self.host.calls, [])

    def test_wrong_engine(self):
        self.host.engine_version = b"linux/amd64\n"
        result = self.run_probe()
        self.assertEqual(result["refusal"], "NATIVE_ARM_ENGINE")
        self.assertEqual(self.host.downloads, [])
        self.assert_clean(result)

    def test_existing_reference_never_overwritten(self):
        self.host.images[self.names.base_tag] = "sha256:" + "a" * 64
        self.host.meta["sha256:" + "a" * 64] = {"env": [], "labels": {}, "parent": None}
        result = self.run_probe()
        self.assertEqual(result["refusal"], "OWNED_NAME_COLLISION")
        self.assertIn(self.names.base_tag, self.host.images)
        self.assertFalse(any(a[:2] == ["image", "rm"] for a in self.host.docker_args()))
        self.assertTrue(result["cleanupComplete"])
        self.assertEqual(self.host.downloads, [])

    def test_existing_container_name_refused(self):
        self.host.containers[self.names.runtime] = {"Id": "c" * 64, "Name": "/" + self.names.runtime,
                                                    "Image": "x", "Labels": {}, "Running": False}
        result = self.run_probe()
        self.assertEqual(result["refusal"], "OWNED_NAME_COLLISION")
        self.assertIn(self.names.runtime, self.host.containers)

    def test_mutable_mirror_rotation_refused_without_retry(self):
        target = self.pins["packages"][3]["url"]
        self.host.corrupt_url = target
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INPUT_HASH")
        self.assertEqual(self.host.downloads.count(target), 1)
        self.assertFalse(any(a[0] == "import" for a in self.host.docker_args()))
        self.assert_clean(result)

    def test_rootfs_rotation_refused(self):
        self.host.corrupt_url = self.rootfs_pin["rootfsUrl"]
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INPUT_HASH")
        self.assert_clean(result)

    def test_rootfs_mutation_after_verified_inspection_refuses_import(self):
        original = self.host.inspect_rootfs

        def change_rootfs(path, pin):
            result = original(path, pin)
            data = Path(path).read_bytes()
            Path(path).write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            return result

        self.host.inspect_rootfs = change_rootfs
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INPUT_HASH")
        self.assertFalse(result["flags"]["inputsReverified"])
        self.assertFalse(any(a[0] == "import" for a in self.host.docker_args()))
        self.assert_clean(result)

    def test_bad_package_signature(self):
        self.host.gpg_status["002.pkg.tar.xz"] = (0, good_status(fpr="1" * 40))
        result = self.run_probe()
        self.assertEqual(result["refusal"], "PACKAGE_SIGNATURE")
        self.assertFalse(result["flags"]["packageSignaturesVerified"])
        self.assertFalse(any(a[0] == "import" for a in self.host.docker_args()))
        self.assert_clean(result)

    def test_bad_rootfs_signature(self):
        self.host.gpg_status["rootfs.tar.gz"] = (2, b"")
        result = self.run_probe()
        self.assertEqual(result["refusal"], "ROOTFS_SIGNATURE")
        self.assertEqual(self.host.inspect_calls, 0)
        self.assert_clean(result)

    def test_installer_network_readback_refused_before_start(self):
        self.host.mutate_doc = lambda role, doc: doc["Host"].update(NetworkMode="bridge") \
            if role == "installer" else None
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INSTALLER_HOST_CONFIG")
        self.assertFalse(any(a[0] == "start" for a in self.host.docker_args()))
        self.assert_clean(result)

    def test_runtime_capability_readback_refused(self):
        self.host.mutate_doc = lambda role, doc: doc["Host"].update(CapAdd=["CAP_NET_RAW"]) \
            if role == "runtime" else None
        result = self.run_probe()
        self.assertEqual(result["refusal"], "RUNTIME_HOST_CONFIG")
        self.assertFalse(result["flags"]["runtimeHostConfigVerified"])
        self.assert_clean(result)

    def test_installer_chroot_denied(self):
        self.host.outputs["installer"] = (1, tokens("TFI", ["inputs", "keyring"], "chroot"))
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INSTALL_CHROOT")
        self.assertTrue(result["flags"]["publicKeyringReady"])
        self.assertFalse(result["flags"]["pacmanSignedInstall"])
        self.assertFalse(any(a[0] == "commit" for a in self.host.docker_args()))
        self.assert_clean(result)

    def test_installer_raw_output_refused(self):
        self.host.outputs["installer"] = (0, b"error: raw pacman text\n")
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INSTALL_OUTPUT")
        self.assertNotIn("raw pacman", json.dumps(result))
        self.assert_clean(result)

    def test_each_hook_refusal_preserves_failure_and_cleans_indented_readback(self):
        for label in ("hooks_schemas", "hooks_pixbuf", "hooks_immodules", "hooks_mime",
                      "hooks_icons", "hooks_fonts"):
            with self.subTest(label=label):
                self.host.outputs["installer"] = (
                    1, tokens("TFI", ["inputs", "keyring", "pacman", "delta"], label))
                result = self.run_probe()
                self.assertEqual(result["refusal"], "INSTALL_" + label.upper())
                self.assertEqual(result["status"], "fail")
                self.assertTrue(result["flags"]["pacmanSignedInstall"])
                self.assertTrue(result["flags"]["packageDeltaExact"])
                self.assertFalse(result["flags"]["hookStateMatchesInputs"])
                self.assertFalse(result["flags"]["derivedImageCommitted"])
                self.assertFalse(any(a[0] == "commit" for a in self.host.docker_args()))
                self.assert_clean(result)

    def test_malformed_existing_presence_preserves_owned_resources(self):
        original = self.host._docker
        def malformed(args):
            code, output = original(args)
            if (len(args) == 3 and args[:2] == ["container", "inspect"]
                    and code == 0):
                return 0, b"[{}] trailing"
            return code, output
        self.host._docker = malformed
        self.host.outputs["installer"] = (
            1, tokens("TFI", ["inputs", "keyring", "pacman", "delta"], "hooks_pixbuf"))
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INSTALL_HOOKS_PIXBUF")
        self.assertFalse(result["cleanupComplete"])
        self.assertIn(self.names.installer, self.host.containers)
        self.assertIn(self.names.base_tag, self.host.images)
        self.assertTrue(self.work.exists())
        self.assertFalse(any(a[:2] in (["container", "rm"], ["image", "rm"])
                             for a in self.host.docker_args()))

    def test_installer_nonzero_without_token(self):
        self.host.outputs["installer"] = (1, tokens("TFI", ["inputs"]))
        result = self.run_probe()
        self.assertEqual(result["refusal"], "INSTALL_INCOMPLETE")
        self.assert_clean(result)

    def test_runtime_gtk_failure(self):
        done = list(P.RUNTIME_STAGES[:P.RUNTIME_STAGES.index("gtk")])
        self.host.outputs["runtime"] = (1, tokens("TFR", done, "gtk"))
        result = self.run_probe()
        self.assertEqual(result["refusal"], "RUNTIME_GTK")
        self.assertTrue(result["flags"]["xvfbOwnProcess"])
        self.assertFalse(result["flags"]["gtkInitCheck"])
        self.assert_clean(result)

    def test_runtime_timeout_stops_then_removes_without_force(self):
        self.host.timeout_role = "runtime"
        result = self.run_probe()
        self.assertEqual(result["refusal"], "COMMAND_TIMEOUT")
        args = self.host.docker_args()
        stops = [i for i, a in enumerate(args) if a[:2] == ["container", "stop"]]
        removes = [i for i, a in enumerate(args) if a[:2] == ["container", "rm"]]
        self.assertEqual(len(stops), 1)
        self.assertTrue(removes and stops[0] < removes[0])
        self.assert_clean(result)

    def test_cleanup_identity_mismatch_preserves_and_fails(self):
        def swap(role, doc):
            if role == "runtime":
                doc["Id"] = "d" * 64  # name now resolves to an unverified identity
        self.host.on_start = swap
        result = self.run_probe()
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["cleanupComplete"])
        self.assertIn(self.names.runtime, self.host.containers)
        self.assertIn(self.names.derived_tag, self.host.images)
        self.assertIn(self.names.base_tag, self.host.images)
        self.assertTrue(self.work.exists())
        self.assertFalse(any(a[:2] == ["image", "rm"] for a in self.host.docker_args()))

    def test_cleanup_label_mismatch_preserves(self):
        def relabel(role, doc):
            if role == "installer":
                doc["Labels"] = dict(doc["Labels"], **{P.LABEL_PREFIX + "run": "1"})
        self.host.on_start = relabel
        result = self.run_probe()
        self.assertFalse(result["cleanupComplete"])
        self.assertIn(self.names.installer, self.host.containers)

    def test_unexpected_workspace_entry_preserves(self):
        def plant(role, doc):
            if role == "runtime":
                (self.work / "inputs" / "unexpected").write_text("x")
        self.host.on_start = plant
        result = self.run_probe()
        self.assertFalse(result["cleanupComplete"])
        self.assertEqual(result["refusal"], "CLEANUP_INCOMPLETE")
        self.assertTrue((self.work / "inputs" / "pkg").exists())

    def test_unexpected_docker_home_state_preserves(self):
        def plant(role, doc):
            if role == "runtime":
                # Non-JSON client state is refused by the base helper's bounded cleanup.
                (self.work / "docker-home" / "state.txt").write_text("x")
        self.host.on_start = plant
        result = self.run_probe()
        self.assertFalse(result["cleanupComplete"])
        self.assertTrue(self.work.exists())


class ResultSchema(unittest.TestCase):
    def test_closed(self):
        result = P.new_result()
        result["refusal"] = "NATIVE_ARM_HOST"
        P.validate_result(result)
        for mutate in (lambda r: r.update(extra=1), lambda r: r.update(refusal="raw text"),
                       lambda r: r["flags"].update(extra=True),
                       lambda r: r["assertions"].update(publicationAuthority=True),
                       lambda r: r["digests"].update(rootfsSha256="/home/runner/x"),
                       lambda r: r["counts"].update(packagesPinned=-1),
                       lambda r: r.update(status="pass")):
            bad = copy.deepcopy(result)
            mutate(bad)
            with self.assertRaises(P.Refusal):
                P.validate_result(bad)

    def test_unknown_refusal_closed(self):
        self.assertEqual(P.closed_label("something raw"), "UNCLASSIFIED_PROBE_FAILURE")
        self.assertEqual(P.closed_label("INSTALL_CHROOT"), "INSTALL_CHROOT")


class MainEntry(TempCase):
    def test_bad_attempt_writes_fixed_failure_only(self):
        result_path = self.tmp / "result.json"
        code = P.main(["--work", str(self.tmp / "work"), "--result", str(result_path),
                       "--run-id", RUN_ID, "--run-attempt", "2", "--source-sha", SHA])
        self.assertEqual(code, 1)
        result = json.loads(result_path.read_text())
        self.assertEqual(result["refusal"], "CONTEXT_RUN_ATTEMPT")
        self.assertTrue(result["cleanupComplete"])
        self.assertFalse((self.tmp / "work").exists())

    def test_main_refuses_result_with_another_pin_digest(self):
        result_path = self.tmp / "pin-result.json"
        original = P.run_probe

        def altered_result(**kwargs):
            result = P.new_result()
            result.update(sourceSha=SHA, runId=RUN_ID, runAttempt=1, stage="complete",
                          cleanupComplete=True)
            result["digests"].update(kwargs["digests"])
            result["digests"]["packagePinsSha256"] = "f" * 64
            result["flags"].update({key: True for key in P.FLAG_KEYS})
            result["counts"].update(packagesPinned=139, packageBytesPinned=201499452,
                                    packagesDownloaded=139, packageSignaturesVerified=139)
            return result

        P.run_probe = altered_result
        try:
            code = P.main(["--work", str(self.tmp / "work"), "--result", str(result_path),
                           "--run-id", RUN_ID, "--run-attempt", "1", "--source-sha", SHA])
        finally:
            P.run_probe = original
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(result_path.read_text())["refusal"], "PIN_FILE")
        self.assertFalse((self.tmp / "work").exists())

    def test_existing_result_not_overwritten(self):
        result_path = self.tmp / "result.json"
        result_path.write_text("owner")
        code = P.main(["--work", str(self.tmp / "work"), "--result", str(result_path),
                       "--run-id", RUN_ID, "--run-attempt", "1", "--source-sha", SHA])
        self.assertEqual(code, 2)
        self.assertEqual(result_path.read_text(), "owner")


class WorkflowText(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW_PATH.read_text()

    def test_trigger_and_scope(self):
        t = self.text
        self.assertIn("workflow_dispatch:", t)
        for forbidden in ("push:", "pull_request", "schedule:", "workflow_run", "secrets.",
                          "environment:", "id-token", "contents: write", "packages: write",
                          "docker push", "gh release", "upload-release", "self-hosted"):
            self.assertNotIn(forbidden, t)
        for required in ("contents: read", "runs-on: ubuntu-24.04-arm", "timeout-minutes: 90",
                         "retention-days: 7", "github.ref == 'refs/heads/main'",
                         "github.run_attempt == '1'", "/theme-forge-packages'",
                         "persist-credentials: false", "test_archarm_runtime_probe.py",
                         "archarm_runtime_probe.py", "${{ github.run_id }}", "${{ github.sha }}"):
            self.assertIn(required, t)

    def test_action_refs_match_the_qualified_base_workflow(self):
        uses = [line.split("uses:", 1)[1].strip() for line in self.text.splitlines()
                if "uses:" in line]
        self.assertEqual(len(uses), 2)
        for ref in uses:
            name, _, rev = ref.partition("@")
            self.assertIn(name, ("actions/checkout", "actions/upload-artifact"))
            expected = {
                "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
                "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
            }
            self.assertEqual(rev, expected[name])
        self.assertNotIn("REPLACE_WITH_", self.text)
        self.assertIn("github.repository == 'Knowledge-Forge-AI/theme-forge-packages'", self.text)
        self.assertIn("ref: ${{ github.sha }}", self.text)

    def test_context_passed_through_env_not_script(self):
        run_blocks = self.text.split("run: |")[1:]
        for block in run_blocks:
            body = block.split("\n      - ", 1)[0]
            self.assertNotIn("${{", body)

    def test_readme_scope(self):
        text = README_PATH.read_text()
        self.assertIn("NOT ADMITTED", text)
        self.assertIn("Rollback", text)


if __name__ == "__main__":
    unittest.main()
