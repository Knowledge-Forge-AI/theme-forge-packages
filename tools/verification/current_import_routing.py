"""Current-only unsigned import and APT indexing. No signing/deployment API."""
import sys
if __name__ == "__main__" and (not sys.flags.isolated or not sys.flags.dont_write_bytecode):
    raise SystemExit("SIGNER_BOOTSTRAP_FLAGS")
from dataclasses import dataclass
from contextlib import contextmanager
import gzip
import hashlib
import lzma
import zlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import weakref
from types import MappingProxyType

# Acyclic root bootstrap: this importer is directly pinned by RS9.
LEAF_MANIFEST_SHA256 = "be9f081a98b10a5c8b554d799e66ffa3bff6f8ab92817d73da773378559311fd"


def _bootstrap_source_bytes(path, limit=2 * 1024 * 1024):
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise SystemExit("SIGNER_BOOTSTRAP_SYMLINK")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise SystemExit("SIGNER_BOOTSTRAP_FILE") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise SystemExit("SIGNER_BOOTSTRAP_FILE")
        chunks, left = [], limit + 1
        while left:
            block = os.read(fd, min(left, 65536))
            if not block:
                break
            chunks.append(block)
            left -= len(block)
        body = b"".join(chunks)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(body) > limit or len(body) != before.st_size or identity(before) != identity(after):
            raise SystemExit("SIGNER_BOOTSTRAP_CHANGED")
        return body
    finally:
        os.close(fd)


def _bootstrap_leaf_bytes(root):
    manifest = _bootstrap_source_bytes(root / "tools/verification/current_signer/leaf-manifest.json",65536)
    if hashlib.sha256(manifest).hexdigest() != LEAF_MANIFEST_SHA256:
        raise SystemExit("SIGNER_BOOTSTRAP_MANIFEST_PIN")
    def closed_pairs(pairs):
        result = {}
        for key,value in pairs:
            if key in result:
                raise SystemExit("SIGNER_BOOTSTRAP_DUPLICATE")
            result[key] = value
        return result
    try:
        doc = json.loads(manifest,object_pairs_hook=closed_pairs)
    except (ValueError,UnicodeError):
        raise SystemExit("SIGNER_BOOTSTRAP_SCHEMA") from None
    if not isinstance(doc,dict) or doc.get("schema") != "tf.current-signer-leaf-manifest.v1":
        raise SystemExit("SIGNER_BOOTSTRAP_SCHEMA")
    files = doc.get("files")
    if not isinstance(files,dict) or not 1 <= len(files) <= 64:
        raise SystemExit("SIGNER_BOOTSTRAP_INVENTORY")
    held = {}
    for rel,expected in files.items():
        if not isinstance(rel,str) or not (rel in {"tools/verification/p-current-nix-contract.json","tools/verification/current-command-contracts.json"} or re.fullmatch(r"tools/verification/(?:current_signer/[A-Za-z0-9_]+\.py|b3/(?:inputs/)?[A-Za-z0-9_]+\.py)",rel)):
            raise SystemExit("SIGNER_BOOTSTRAP_PATH")
        if not isinstance(expected,str) or not re.fullmatch("[0-9a-f]{64}",expected):
            raise SystemExit("SIGNER_BOOTSTRAP_HASH")
        body = _bootstrap_source_bytes(root / rel)
        if hashlib.sha256(body).hexdigest() != expected:
            raise SystemExit("SIGNER_BOOTSTRAP_LEAF_PIN")
        if rel.startswith("tools/verification/current_signer/"):
            if Path(rel).stem in sys.stdlib_module_names or Path(rel).stem in {"current_import_routing","rs9","b3"}:
                raise SystemExit("SIGNER_BOOTSTRAP_MODULE_IDENTITY")
            held[Path(rel).stem] = (root / rel,body)
    return held


def _bootstrap_current_signer():
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise SystemExit("SIGNER_BOOTSTRAP_FLAGS")
    import importlib.abc
    import importlib.util
    entries = {"--current-signer-host":"signer_host_controller","--current-signer-worker":"signer_worker","--current-signer-publish":"retained_publication","--current-signer-client":"package_client_qualification","--current-signer-runtime":"runtime_workflow_bridge"}
    if len(sys.argv) < 2 or sys.argv[1] not in entries:
        raise SystemExit("CURRENT_SIGNER_MODE_REQUIRED")
    root = Path(os.path.abspath(__file__)).parents[2]
    held = _bootstrap_leaf_bytes(root)
    held["current_import_routing"] = (Path(os.path.abspath(__file__)),_bootstrap_source_bytes(Path(os.path.abspath(__file__))))
    entry = entries[sys.argv[1]]
    if entry not in held or any(name in sys.modules for name in held):
        raise SystemExit("SIGNER_BOOTSTRAP_MODULE_IDENTITY")
    class HeldLoader(importlib.abc.Loader):
        def __init__(self,name):
            self.name = name
        def create_module(self,spec):
            return None
        def exec_module(self,module):
            path,body = held[self.name]
            module.__file__ = str(path)
            exec(compile(body,str(path),"exec",dont_inherit=True),module.__dict__)
    class HeldFinder(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname in held:
                return importlib.util.spec_from_loader(fullname,HeldLoader(fullname),origin=str(held[fullname][0]))
            return None
    sys.meta_path.insert(0,HeldFinder())
    module = importlib.import_module(entry)
    raise SystemExit(module.main(sys.argv[2:]))


if __name__ == "__main__":
    _bootstrap_current_signer()

from rs9.errors import ContractError
from rs9.hosted_custody import source_tree_identity
from rs9.qualified_distribution_inputs import SourceBoundConfiguration, qualified_theme_forge_packages_inputs
from rs9.repo_apt import AptRepositoryCandidate, parse_deb_control, validate_apt_repository
from rs9.scratch import canonical, physical_directory

VERSIONS = {"theme-forge-stellar-burst": "0.7.0", "theme-forge-stellar-loom": "0.5.0",
            "theme-forge-solar-sail": "0.3.0", "theme-forge-nebular-fusion": "0.7.1"}
KEY_SHA256 = "6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95"
SOURCE_FILES = frozenset({"release-lock.json", "flake.nix", "flake.lock", "package-matrix.json",
    "keys/knowledge-forge-ai-packages.asc", ".github/workflows/publish.yml",
    "tools/verification/generate-publication-provenance.mjs",
    "tools/verification/verify-publication-provenance.mjs",
    "tools/verification/current_import_routing.py", "tools/verification/current-rs9-inputs.json"})
SYSTEMS = {"deb": {"amd64", "arm64"}, "rpm": {"x86_64-linux", "aarch64-linux"},
           "pacman": {"x86_64-linux"}}
MODULE_ENTRY = "tools/verification/current_import_routing.py"
ARCH_SYSTEM = {"deb": {"amd64": "amd64", "arm64": "arm64"},
               "rpm": {"x86_64": "x86_64-linux", "aarch64": "aarch64-linux"},
               "pacman": {"x86_64": "x86_64-linux"}}
MAX_PACKAGE = 512 * 1024 * 1024
APT_DISTRIBUTION = "resolute"
APT_COMPONENTS = ("main",)
APT_INDEX_NAMES = ("Packages", "Packages.gz", "Packages.xz")
APT_RELEASE = f"dists/{APT_DISTRIBUTION}/Release"
MAX_APT_MEMBERS = 128
MAX_APT_DEPTH = 6
MAX_APT_METADATA = 16 * 1024 * 1024
_SHA256_TEXT = re.compile(r"[0-9a-f]{64}")
_APT_RELEASE_ROW = re.compile(r" ([0-9a-f]{64}) (0|[1-9][0-9]{0,11}) (\S+)")
_APT_FIELD = re.compile(r"([A-Za-z][A-Za-z0-9-]*): ?(.*)")


def fail(message):
    raise ContractError("CURRENT_IMPORT_ROUTING", message)


def _stable(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode


def held_bytes(path, maximum=MAX_PACKAGE):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        fail("Aliased input forbidden")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        import stat
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail("Bounded regular input required")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(data) != before.st_size or len(data) > maximum or _stable(before) != _stable(after) or _stable(path.stat()) != _stable(after) or any(p.is_symlink() for p in (path, *path.parents)):
        fail("Input changed during read")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _apt_release_entries(release_bytes):
    """Strictly parse the RS9 ``build_indices`` Release shape.

    Returns ``(entries, architectures)`` where ``entries`` maps each SHA256
    index path to ``(sha256, size)``.  The index set is derived from the
    Release Architectures/Components fields, which must equal the routed DEB
    systems; no count is assumed.
    """
    from rs9.security import validate_safe_relative_posix_path
    if not isinstance(release_bytes, bytes) or not 0 < len(release_bytes) <= MAX_APT_METADATA:
        fail("Bounded APT Release required")
    try:
        text = release_bytes.decode("utf-8")
    except UnicodeDecodeError:
        fail("APT Release encoding differs")
    if "\r" in text or not text.endswith("\n"):
        fail("APT Release framing differs")
    lines = text[:-1].split("\n")
    if lines.count("SHA256:") != 1:
        fail("APT Release SHA256 block differs")
    marker = lines.index("SHA256:")
    header = {}
    for line in lines[:marker]:
        match = _APT_FIELD.fullmatch(line)
        if match is None or match.group(1) in header:
            fail("APT Release header differs")
        header[match.group(1)] = match.group(2)
    entries = {}
    for line in lines[marker + 1:]:
        match = _APT_RELEASE_ROW.fullmatch(line)
        if match is None:
            fail("APT Release SHA256 row differs")
        path = match.group(3)
        validate_safe_relative_posix_path(path)
        if path in entries:
            fail("Duplicate APT Release SHA256 row")
        entries[path] = (match.group(1), int(match.group(2)))
    architectures = tuple(header.get("Architectures", "").split(" "))
    components = tuple(header.get("Components", "").split(" "))
    if (header.get("Suite") != APT_DISTRIBUTION or header.get("Codename") != APT_DISTRIBUTION
            or header.get("Acquire-By-Hash") != "yes" or components != APT_COMPONENTS
            or len(set(architectures)) != len(architectures) or set(architectures) != SYSTEMS["deb"]):
        fail("APT Release scope differs from routed DEB systems")
    expected = {f"{component}/binary-{arch}/{name}" for component in components
                for arch in architectures for name in APT_INDEX_NAMES}
    if set(entries) != expected:
        fail("APT Release index set differs")
    return entries, architectures


def _apt_member_map(release_sha256, release_size, entries, pool):
    """Derive the exact APT member map relative to the APT root.

    Members are Release and its by-hash copy, every Release SHA256 index and
    its by-hash copy, and every pool DEB.  ``pool`` is ``(filename, sha, size)``.
    """
    from rs9.security import validate_safe_relative_posix_path
    members = {}

    def add(path, digest, size):
        validate_safe_relative_posix_path(path)
        if (not isinstance(digest, str) or _SHA256_TEXT.fullmatch(digest) is None
                or type(size) is not int or not 0 < size <= MAX_PACKAGE):
            fail("APT member identity is not bounded")
        if members.setdefault(path, (digest, size)) != (digest, size):
            fail("APT member identity conflicts")

    base = f"dists/{APT_DISTRIBUTION}"
    add(APT_RELEASE, release_sha256, release_size)
    add(f"{base}/by-hash/SHA256/{release_sha256}", release_sha256, release_size)
    for path, (digest, size) in sorted(entries.items()):
        add(f"{base}/{path}", digest, size)
        add(f"{base}/{path.rsplit('/', 1)[0]}/by-hash/SHA256/{digest}", digest, size)
    for filename, digest, size in pool:
        if (not isinstance(filename, str) or not filename.startswith("pool/")
                or not filename.endswith(".deb") or filename in members):
            fail("APT pool member differs")
        add(filename, digest, size)
    if len(members) > MAX_APT_MEMBERS:
        fail("Too many APT members")
    return members


def _apt_tree_entries(paths):
    """Exact walker view: member files plus every ancestor directory as ``dir/``."""
    entries = set(paths)
    for path in paths:
        parts = path.split("/")
        for index in range(1, len(parts)):
            entries.add("/".join(parts[:index]) + "/")
    return frozenset(entries)


def _bounded_decompress(data, kind):
    if kind == "Packages.gz":
        engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            body = engine.decompress(data, MAX_APT_METADATA + 1)
        except zlib.error:
            fail("APT compressed index is not decodable")
        if not engine.eof or engine.unused_data or engine.unconsumed_tail:
            fail("APT compressed index framing differs")
    else:
        engine = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        try:
            body = engine.decompress(data, max_length=MAX_APT_METADATA + 1)
        except lzma.LZMAError:
            fail("APT compressed index is not decodable")
        if not engine.eof or engine.unused_data:
            fail("APT compressed index framing differs")
    if len(body) > MAX_APT_METADATA:
        fail("APT compressed index exceeds bound")
    return body


def _apt_package_stanzas(data):
    """Strict bounded Packages parser; continuation lines belong to one field."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail("APT Packages encoding differs")
    if "\r" in text or not text.endswith("\n") or text == "\n":
        fail("APT Packages framing differs")
    stanzas = []
    for block in text[:-1].split("\n\n"):
        fields, current = {}, None
        for line in block.split("\n"):
            if line.startswith((" ", "\t")) and current is not None:
                fields[current] += "\n" + line
                continue
            match = _APT_FIELD.fullmatch(line)
            if match is None or match.group(1) in fields:
                fail("APT Packages stanza differs")
            current = match.group(1)
            fields[current] = match.group(2)
        if (any(key not in fields for key in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256"))
                or re.fullmatch(r"[1-9][0-9]{0,11}", fields["Size"]) is None
                or _SHA256_TEXT.fullmatch(fields["SHA256"]) is None):
            fail("APT Packages stanza differs")
        stanzas.append(fields)
        if len(stanzas) > MAX_SIGNING_MEMBERS:
            fail("Too many APT Packages stanzas")
    return stanzas


@dataclass(frozen=True)
class ProductionSource:
    root: Path
    commit: str
    tree: str
    files: dict

    def verify(self):
        root = physical_directory(self.root)
        if any(not re.fullmatch(r"[0-9a-f]{40}", x or "") for x in (self.commit, self.tree)):
            fail("Exact P source coordinates required")
        if set(self.files) != SOURCE_FILES or any(not re.fullmatch(r"[0-9a-f]{64}", h or "") for h in self.files.values()):
            fail("Source-owned P file inventory required")
        if source_tree_identity(root, self.commit) != self.tree:
            fail("P source tree differs")
        bodies = {}
        for name, expected in self.files.items():
            from rs9.security import validate_safe_relative_posix_path
            validate_safe_relative_posix_path(name)
            data = held_bytes(root / name, 2 * 1024 * 1024)
            if sha(data) != expected:
                fail("P source file differs")
            bodies[name] = data
        if sha(held_bytes(Path(__file__), 2 * 1024 * 1024)) != self.files[MODULE_ENTRY]:
            fail("Executing routing module differs from P inventory")
        lock = json.loads(bodies["release-lock.json"])
        if {p: v.get("version") for p, v in lock.get("products", {}).items()} != VERSIONS:
            fail("P lock is not the exact current four")
        if sha(bodies["keys/knowledge-forge-ai-packages.asc"]) != KEY_SHA256:
            fail("P public key continuity differs")
        return {"repository": "Knowledge-Forge-AI/theme-forge-packages", "commit": self.commit,
                "tree": self.tree, "files": self.files, "inventory_sha256": sha(canonical(self.files))}


def _plan_inputs(inventory, collection):
    """Physical routing only; caller must obtain inventory freshly from facade."""
    plan, names, coverage, independent, architectures = [], {}, {f: {p: set() for p in VERSIONS} for f in SYSTEMS}, {}, {}
    for row in inventory["binaries"]:
        family, product, name = row["family"], row["product"], row["name"]
        if family not in SYSTEMS or product not in VERSIONS or row["version"] != VERSIONS[product] or Path(name).name != name:
            fail("Unexpected binary identity")
        separator = "_" if family == "deb" else "-"
        if not name.startswith(product + separator + VERSIONS[product] + "-"):
            fail("Binary basename version differs")
        prior = names.setdefault(name, (family, row["sha256"], row["size"]))
        if prior != (family, row["sha256"], row["size"]):
            fail("Same basename differs")
        if any(item[0]["family"] == family and item[0]["name"] == name for item in plan):
            fail("Duplicate binary row")
        bodies, seen_origins = [], set()
        for origin in row["origins"]:
            if (not isinstance(origin, dict) or set(origin) != {"artifact", "system", "path"}
                    or origin["system"] not in SYSTEMS[family]):
                fail("Unsupported native system")
            from rs9.security import validate_safe_relative_posix_path
            for field in ("artifact", "path"):
                validate_safe_relative_posix_path(origin[field])
            origin_key = (origin["artifact"], origin["system"], origin["path"])
            if origin_key in seen_origins:
                fail("Duplicate origin identity")
            seen_origins.add(origin_key)
            body = held_bytes(collection / origin["artifact"] / origin["path"])
            if len(body) != row["size"] or sha(body) != row["sha256"]:
                fail("Original unsigned package changed")
            bodies.append(body)
            coverage[family][product].add(origin["system"])
        if not bodies or any(body != bodies[0] for body in bodies):
            fail("Duplicate origins differ")
        arch = row["architecture"]
        allowed = {"deb": {"all", "amd64", "arm64"}, "rpm": {"noarch", "x86_64", "aarch64"}, "pacman": {"any", "x86_64"}}
        if architectures.setdefault((family, product, arch), name) != name:
            fail("Same product architecture has differing package versions/revisions")
        if arch not in allowed[family]:
            fail("Unsupported package architecture")
        origins = [origin["system"] for origin in row["origins"]]
        is_independent = arch in {"all", "any", "noarch"}
        expected_systems = SYSTEMS[family] if is_independent else {ARCH_SYSTEM[family][arch]}
        if set(origins) != expected_systems:
            fail("Package architecture disagrees with exact origin systems")
        product_architectures = {a for f, p, a in architectures if (f, p) == (family, product)}
        if product_architectures & {"all", "any", "noarch"} and product_architectures - {"all", "any", "noarch"}:
            fail("Independent and specific packages cannot mix")
        if is_independent:
            identity = (name, row["sha256"], row["size"])
            if independent.setdefault((family, product), identity) != identity:
                fail("Architecture-independent package differs")
        if family == "deb":
            control = parse_deb_control(bodies[0])
            if (control["Package"], control["Version"], control["Architecture"]) != (product, name.split("_")[1], arch):
                fail("DEB control disagrees with routing identity")
        destinations = ([f"unsigned/rpm/{destination_arch}/{name}" for destination_arch in (sorted(ARCH_SYSTEM[family]) if is_independent else [arch])]
                        if family == "rpm" else [f"unsigned/{family}/{name}"])
        plan.append((row, bodies[0], destinations))
    if any(systems != SYSTEMS[family] for family, products in coverage.items() for systems in products.values()):
        fail("All four products and native systems required")
    return plan


def _write_unsigned(plan, stage, release_date):
    apt = AptRepositoryCandidate(stage / "apt", distribution="resolute",
                                 origin="Knowledge Forge AI", label="Knowledge Forge AI")
    objects = []
    packages = []
    for row, data, destinations in plan:
        for relative in destinations:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
            if sha(held_bytes(target)) != row["sha256"]:
                fail("Staged unsigned bytes differ")
        if row["family"] == "deb":
            package = apt.add_package(deb_bytes=data)
            if (package.sha256 != row["sha256"] or package.size != row["size"]
                    or Path(package.filename).name != row["name"]):
                fail("APT pool changed DEB bytes")
            packages.append(package)
        objects.append({**row, "destinations": destinations})
    indices = apt.build_indices(release_date=release_date)
    validate_apt_repository(stage / "apt", APT_DISTRIBUTION)
    # The member inventory is derived only from the actual RS9 DebPackage
    # rows and the Release bytes build_indices wrote; Release bytes are not
    # serialized, only their size and digest.
    release_bytes = indices.get("release_bytes")
    if (indices.get("distribution") != APT_DISTRIBUTION or not isinstance(release_bytes, bytes)
            or sha(release_bytes) != indices.get("release_sha256")):
        fail("APT Release anchor differs")
    entries, _ = _apt_release_entries(release_bytes)
    if {path: digest for path, (digest, _) in entries.items()} != indices.get("indices"):
        fail("APT Release SHA256 rows differ from built indices")
    members = _apt_member_map(indices["release_sha256"], len(release_bytes), entries,
                              [(package.filename, package.sha256, package.size) for package in packages])
    return objects, {
        "distribution": APT_DISTRIBUTION, "release_sha256": indices["release_sha256"],
        "release_size": len(release_bytes), "indices": dict(indices["indices"]),
        "members": [{"path": path, "sha256": digest, "size": size}
                    for path, (digest, size) in sorted(members.items())],
    }


def prepare_unsigned(config, production, collection, stage, *, release_date, zip_transport="actions", timeout=7200):
    """Fresh original-run admission precedes selection; no saved-result input."""
    if type(config) is not SourceBoundConfiguration or type(production) is not ProductionSource:
        fail("Explicit source-bound RS9 and P configurations required")
    collection, stage = physical_directory(collection), physical_directory(stage)
    if any(collection.iterdir()) or any(stage.iterdir()) or collection == stage or collection in stage.parents or stage in collection.parents:
        fail("Distinct empty collection and stage roots required")
    try:
        source_roots = (physical_directory(production.root), physical_directory(config.repository))
    except (TypeError, ValueError, OSError) as error:
        fail("Physical source directories required")
    if any(target == root or root in target.parents for target in (stage, collection)
           for root in source_roots):
        fail("Staging cannot mutate either source checkout")
    p_source = production.verify()
    inventory = qualified_theme_forge_packages_inputs(config, collection, consumer_repository=production.root,
        consumer_commit=production.commit, consumer_tree=production.tree, zip_transport=zip_transport, timeout=timeout)
    if production.verify() != p_source:
        fail("P source changed during original-run admission")
    plan = _plan_inputs(inventory, collection)
    objects, apt_indices = _write_unsigned(plan, stage, release_date)
    if production.verify() != p_source:
        fail("P source changed during unsigned routing")
    original = {key: inventory[key] for key in config.expected()}
    result = {"schema": "theme-forge.current-unsigned-routing.v1", "p_source": p_source, "rs9_original": original,
              "own_repository_admission": inventory["own_repository_admission"],
              "objects": objects, "apt_indices": apt_indices, "signed": False, "assembly_ready": False,
              "production_enabled": False, "publication_authority": False,
              "pending": ["Gate3-P-native-three", "APT4-real-GPG-and-SignedStore", "RPM-signature-preservation",
                          "protected-signing", "production-client-checks", "signed-assembly-and-provenance"]}
    with (stage / "unsigned-routing.json").open("xb") as stream:
        stream.write(canonical(result))
    return result


# Same-process custody only. This registry is authenticated-module discipline,
# not confinement against hostile Python code in this interpreter.
_SIGNING_LIVE = weakref.WeakKeyDictionary()
_SIGNING_LOCK = threading.RLock()
_SIGNING_SENTINEL = object()
MAX_SIGNING_MEMBERS = 64
_SIGNING_STATES = weakref.WeakKeyDictionary()
_SIGNING_RETENTION = {}
_LEASE_SENTINEL = object()
_LEASE_MINT_TOKEN = object()
# Weak live-input handles are intentionally paired with strong owner records.
# The lease registry is strong: a transferred lease cannot lose its descriptor
# custody merely because a caller drops its last reference.
_LEASE_REGISTRY = {}
_LEASE_RETENTION = {}
# Closed leases retain only a weak observational tombstone.  No descriptor or
# routing record is kept here, and operational admission still requires the
# active strong registry above.
_LEASE_CLOSED = weakref.WeakKeyDictionary()
_OWNER_RETENTION = {}
_PREHANDLE_RETENTION = {}
_NATIVE_PHASES = frozenset({
    "public-key-import", "private-key-import", "rpm-public-key-import",
    "rpm-package-sign", "rpm-package-verify", "pacman-package-sign",
    "pacman-package-verify",
    # Closed later-runtime names; admitting a name executes nothing here.
    "apt-release-clearsign", "apt-release-detach-sign",
    "rpm-metadata-create", "rpm-metadata-sign", "rpm-metadata-verify",
    "pacman-database-create", "pacman-database-sign", "pacman-database-verify",
})
_ASSEMBLY_PHASES = frozenset({
    "apt-output", "rpm-output", "noarch-output", "pacman-output",
    "signature-output", "final-output-inventory",
    "apt-release-output", "apt-inrelease-output", "apt-release-gpg-output",
    "apt-tree-output", "rpm-metadata-output", "pacman-database-output",
})


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


class _DirectoryHold:
    def __init__(self, path, *, provisional=None):
        self.path = None
        self.ancestors = []
        self.fd = None
        self.fd_status = "unopened"
        self.close_ledger = []
        self.close_errors = []
        if provisional is not None:
            provisional.append(self)
        self.path = physical_directory(path)
        self.ancestors = [(p, _directory_identity(os.lstat(p))) for p in (*reversed(self.path.parents), self.path)]
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.fd_status = "open"
        try:
            self.identity = _directory_identity(os.fstat(self.fd))
            if self.identity != self.ancestors[-1][1]:
                fail("Signing root changed during open")
            self.check()
        except BaseException as error:
            try:
                self.close()
            except BaseException as close_error:
                error.cleanup_errors = (close_error,)
            raise

    def check(self):
        if self.fd_status != "open" or self.fd is None or _directory_identity(os.fstat(self.fd)) != self.identity:
            fail("Held signing root changed")
        for path, expected in self.ancestors:
            actual = os.lstat(path)
            if not stat.S_ISDIR(actual.st_mode) or _directory_identity(actual) != expected:
                fail("Signing root ancestor changed")

    def close(self):
        if self.fd_status in {"closed", "unopened"}:
            return
        if self.fd_status == "uncertain":
            error = ContractError("CURRENT_IMPORT_ROUTING", "Directory descriptor close is uncertain")
            error.close_ledger = tuple(self.close_ledger)
            raise error
        number = self.fd
        try:
            os.close(number)
        except BaseException as error:
            self.fd_status = "uncertain"
            self.fd = None
            self.close_ledger.append({"kind": "directory", "fd": number, "status": "uncertain"})
            self.close_errors.append(error)
            wrapped = ContractError("CURRENT_IMPORT_ROUTING", "Directory descriptor close failed")
            wrapped.close_ledger = tuple(self.close_ledger)
            wrapped.close_errors = tuple(self.close_errors)
            raise wrapped from error
        self.fd_status = "closed"
        self.fd = None
        self.close_ledger.append({"kind": "directory", "fd": number, "status": "closed"})


class _SigningFile:
    def __init__(self, root, relative, expected_sha, expected_size, *, provisional=None):
        from rs9.security import validate_safe_relative_posix_path
        validate_safe_relative_posix_path(relative)
        if type(expected_size) is not int or not 0 < expected_size <= MAX_PACKAGE:
            fail("Bounded signing input required")
        self.root, self.relative = root, relative
        self.expected_sha, self.expected_size = expected_sha, expected_size
        self.parents = []
        self._parent_status = []
        self.fd = None
        self.fd_status = "unopened"
        self.close_ledger = []
        self.close_errors = []
        if provisional is not None:
            provisional.append(self)
        try:
            parent = root.fd
            for component in Path(relative).parts[:-1]:
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                # Enroll the acquired descriptor before any fstat/identity
                # operation can fail; close() can then account for it.
                self.parents.append((component, fd, None))
                self._parent_status.append("open")
                info = os.fstat(fd)
                self.parents[-1] = (component, fd, _directory_identity(info))
                parent = fd
            self.fd = os.open(Path(relative).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            self.fd_status = "open"
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("Unaliased regular signing input required")
            self.identity = _stable(info)
            self.read()
        except BaseException as error:
            try:
                self.close()
            except BaseException as close_error:
                error.cleanup_errors = (close_error,)
            raise

    def check(self):
        if self.fd_status != "open" or any(status != "open" for status in self._parent_status):
            fail("Held signing input descriptor is no longer open")
        self.root.check()
        parent = self.root.fd
        for index, (name, fd, expected) in enumerate(self.parents):
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (_directory_identity(named) != expected
                    or _directory_identity(os.fstat(fd)) != expected):
                fail("Signing input ancestor changed")
            parent = fd
        named = os.stat(Path(self.relative).name, dir_fd=parent, follow_symlinks=False)
        if (self.fd is None or _stable(named) != self.identity
                or _stable(os.fstat(self.fd)) != self.identity or named.st_nlink != 1):
            fail("Held signing input changed")

    def read(self):
        self.check()
        chunks, offset = [], 0
        while offset < self.expected_size + 1:
            block = os.pread(self.fd, min(1024 * 1024, self.expected_size + 1 - offset), offset)
            if not block:
                break
            chunks.append(block)
            offset += len(block)
        data = b"".join(chunks)
        self.check()
        if len(data) != self.expected_size or sha(data) != self.expected_sha:
            fail("Held signing input bytes differ")
        return data

    def close(self):
        if self.fd_status == "uncertain" or any(status == "uncertain" for status in self._parent_status):
            error = ContractError("CURRENT_IMPORT_ROUTING", "Signing input descriptor close is uncertain")
            error.close_ledger = tuple(self.close_ledger)
            error.close_errors = tuple(self.close_errors)
            raise error
        if self.fd_status == "open":
            number = self.fd
            try:
                os.close(number)
            except BaseException as error:
                self.fd_status = "uncertain"
                self.fd = None
                self.close_ledger.append({"kind": "file", "fd": number, "status": "uncertain"})
                self.close_errors.append(error)
            else:
                self.fd_status = "closed"
                self.fd = None
                self.close_ledger.append({"kind": "file", "fd": number, "status": "closed"})
        for index in range(len(self.parents) - 1, -1, -1):
            if self._parent_status[index] != "open":
                continue
            _, number, _ = self.parents[index]
            try:
                os.close(number)
            except BaseException as error:
                self._parent_status[index] = "uncertain"
                self.close_ledger.append({"kind": "parent", "fd": number, "status": "uncertain"})
                self.close_errors.append(error)
            else:
                self._parent_status[index] = "closed"
                self.close_ledger.append({"kind": "parent", "fd": number, "status": "closed"})
        if self.close_errors:
            error = ContractError("CURRENT_IMPORT_ROUTING", "Signing input descriptor close failed")
            error.close_ledger = tuple(self.close_ledger)
            error.close_errors = tuple(self.close_errors)
            raise error from self.close_errors[0]
        self.parents = []


def _freeze(value):
    """Deep-freeze routing metadata before it crosses the transfer boundary."""
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze(item) for item in value)
    return value


def _destination_members(destination):
    """Return the exact flat regular-file set held by a fresh destination."""
    destination.check()
    members = set()
    for name in os.listdir(destination.fd):
        if Path(name).name != name or name in {"", ".", ".."}:
            fail("Unexpected signing destination member")
        info = os.stat(name, dir_fd=destination.fd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail("Signing destination contains an unsafe member")
        members.add(name)
        if len(members) > MAX_SIGNING_MEMBERS:
            fail("Too many signing destination members")
    return members


class _LeasePhaseFailure(ContractError):
    """A private dual-failure container; neither error is public evidence."""

    def __init__(self, body_error=None, post_error=None, retention_error=None):
        super().__init__("CURRENT_SIGNING_LEASE", "Lease phase custody check failed")
        self.body_error = body_error
        self.post_error = post_error
        self.retention_error = retention_error


def _lease_record(lease):
    if type(lease) is not _LiveSigningLease:
        fail("Module-owned live lease required")
    with _SIGNING_LOCK:
        try:
            record = _LEASE_REGISTRY.get(lease)
            record_ref = getattr(lease, "_record")
            marker = getattr(lease, "_marker")
            pid = getattr(lease, "_pid")
        except BaseException:
            fail("Live lease was not minted by this owner")
    if (record is None or record_ref is not record or marker is not _LEASE_SENTINEL
            or pid != os.getpid() or record.get("pid") != os.getpid()):
        fail("Live lease was not minted by this owner")
    return record


class _LiveSigningLease:
    """Module-owned descriptor lease transferred from one fresh import."""

    __slots__ = ("__weakref__", "_record", "_marker", "_pid", "_state", "_lock", "_frozen", "_rows", "_held", "_roots",
                 "_destination_parent", "_destination", "_copies", "_members", "_stage_members", "_routing",
                 "_origin", "_source_roots", "_object_cache", "_apt_tree", "_apt_held", "_apt_release",
                 "_apt_anchor")

    def __init__(self, mint_token, record):
        if mint_token is not _LEASE_MINT_TOKEN or not isinstance(record, dict) or record.get("minted") is not True:
            raise TypeError("Live signing leases can only be minted by transfer_signing_inputs")
        self._record = record
        self._marker = _LEASE_SENTINEL
        self._pid = record["pid"]
        self._state = "active"
        self._lock = threading.RLock()
        self._frozen = record["frozen"]
        self._rows = tuple(record["rows"])
        self._held = tuple(record["held"])
        self._roots = tuple(record["roots"])
        self._destination_parent = record["destination_parent"]
        self._destination = record["destination"]
        self._copies = tuple(record["copies"])
        self._members = frozenset(record["members"])
        self._stage_members = frozenset(record["stage_members"])
        self._routing = record["routing"]
        self._origin = record["origin"]
        self._source_roots = tuple(record["source_roots"])
        self._object_cache = None
        self._apt_tree = frozenset(record["apt_members"])
        self._apt_held = MappingProxyType(dict(record["apt_held"]))
        self._apt_release = record["apt_release"]
        self._apt_anchor = tuple(record["apt_anchor"])

    @property
    def state(self):
        with _SIGNING_LOCK:
            if (getattr(self, "_state", None) == "closed"
                    and _LEASE_CLOSED.get(self) == os.getpid()):
                return "closed"
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            return self._state

    @property
    def origin(self):
        return self._origin

    @property
    def destination(self):
        return self._destination.path

    def _set_state(self, value):
        self._state = value
        self._record["state"] = value

    def _require(self, allowed=("active", "running")):
        record = _lease_record(self)
        if self._pid != os.getpid() or self._state not in allowed or record.get("state") != self._state:
            fail("Live signing lease is not usable in its current process/state")
        for root in self._roots:
            root.check()
        if self._destination_parent is not None:
            self._destination_parent.check()
        self._destination.check()
        for item in self._held:
            item.read()
        if self._routing is None or self._routing.read() != self._record["routing_bytes"]:
            fail("Live routing file differs from retained custody")
        if _package_members(self._roots[1]) != self._stage_members:
            fail("Live unsigned package membership differs")
        if _apt_members(self._roots[1]) != self._apt_tree:
            fail("Live APT tree membership differs")
        for item in self._copies:
            item.read()
        if _destination_members(self._destination) != self._members:
            fail("Live copied member set differs")
        if len(self._copies) != len(self._members):
            fail("Live copied member set differs")

    def check(self):
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            try:
                self._require()
            except BaseException as error:
                self._retain((error,))
                raise

    def _check_output_location(self, path):
        """Reject runtime output/work roots inside any retained input root."""
        candidate = Path(path).absolute()
        physical = (physical_directory(candidate) if candidate.exists()
                    else physical_directory(candidate.parent) / candidate.name)
        roots = (*self._source_roots, *(root.path for root in self._roots), self._destination.path)
        for root in roots:
            root = Path(root)
            if candidate == root or root in candidate.parents or physical == root or root in physical.parents:
                fail("Protected output must be outside retained signing inputs")
        return candidate

    def _begin(self):
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            try:
                self._require(("active",))
            except BaseException as error:
                self._retain((error,))
                raise
            self._set_state("running")

    # Compatibility alias retained for the parent runtime's current seam.
    _enter_runtime = _begin

    def _retain(self, errors=()):
        if errors is None:
            errors = ()
        if not isinstance(errors, tuple) or any(not isinstance(error, BaseException) or callable(error) for error in errors):
            fail("Lease retention accepts only private error references")
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            record = _lease_record(self)
            resources = list(record.get("resources", ()))
            for error in errors:
                for resource in getattr(error, "resources", ()):
                    if not any(resource is retained for retained in resources):
                        resources.append(resource)
            if resources:
                record["resources"] = tuple(resources)
            if self._state == "closed":
                fail("Closed live lease cannot be retained")
            if self._state == "retained":
                record["errors"] = tuple(record.get("errors", ())) + tuple(errors)
                _LEASE_RETENTION[self] = record
                return
            self._set_state("retained")
            record["errors"] = tuple(errors)
            _LEASE_RETENTION[self] = record

    def _close_confirmed(self):
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            if self._state == "closed":
                return
            if self._state not in {"active", "running"}:
                fail("Live lease cannot be closed from its current state")
            try:
                self._require()
            except BaseException as error:
                self._retain((error,))
                raise
            errors = []
            for item in reversed(self._copies):
                try:
                    item.close()
                except BaseException as error:
                    errors.append(error)
            for item in reversed(self._held):
                try:
                    item.close()
                except BaseException as error:
                    errors.append(error)
            for root in reversed(self._roots):
                try:
                    root.close()
                except BaseException as error:
                    errors.append(error)
            for item in (self._destination, self._destination_parent):
                if item is not None:
                    try:
                        item.close()
                    except BaseException as error:
                        errors.append(error)
            if errors:
                self._set_state("retained")
                self._record["errors"] = tuple(errors)
                self._record["close_ledger"] = tuple(
                    entry for item in (*self._copies, *self._held, *self._roots, self._destination, self._destination_parent)
                    if item is not None for entry in getattr(item, "close_ledger", ())
                )
                _LEASE_RETENTION[self] = self._record
                error = ContractError("CURRENT_SIGNING_LEASE", "Live lease descriptor cleanup is uncertain")
                error.cleanup_errors = tuple(errors)
                raise error
            self._set_state("closed")
            with _SIGNING_LOCK:
                _LEASE_CLOSED[self] = os.getpid()
                _LEASE_REGISTRY.pop(self, None)
                _LEASE_RETENTION.pop(self, None)

    def _relative_for_object(self, obj):
        _lease_record(self)
        if self._object_cache is None:
            self.unsigned_objects()
        if id(obj) not in self._record.get("object_ids", {}):
            fail("Lease object identity is not admitted")
        return self._record["object_ids"][id(obj)]

    def read_unsigned(self, obj):
        _lease_record(self)
        if self._object_cache is None:
            self.unsigned_objects()
        relative = self._record.get("object_ids", {}).get(id(obj))
        if relative is None:
            fail("Lease reads require an admitted unsigned object")
        with _SIGNING_LOCK, self._lock:
            try:
                self._require()
            except BaseException as error:
                self._retain((error,))
                raise
            item = next((item for item in self._copies if item.relative == relative), None)
            if item is None:
                fail("Lease member is not retained")
            return item.read()

    def unsigned_objects(self):
        from current_protected_signing import UnsignedObject
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            try:
                self._require()
            except BaseException as error:
                self._retain((error,))
                raise
            if self._object_cache is None:
                values = []
                object_ids = {}
                for row, _ in self._rows:
                    family = {"deb": "apt", "rpm": "rpm", "pacman": "pacman"}[row["family"]]
                    value = UnsignedObject(
                        channel=family, product=row["product"], version=row["version"],
                        architecture=row["architecture"], origin=self._origin,
                        path=self._destination.path / row["name"], sha256=row["sha256"], size=row["size"],
                    )
                    object.__setattr__(value, "_live_name", row["name"])
                    values.append(value)
                    object_ids[id(value)] = row["name"]
                self._object_cache = tuple(values)
                self._record["object_ids"] = object_ids
            return self._object_cache

    def _read_apt_held(self, item, anchor=None):
        """Full custody check, then one held-descriptor read; never a path."""
        with _SIGNING_LOCK, self._lock:
            try:
                self._require()
                data = item.read()
                if anchor is not None:
                    digest, size = anchor
                    if (len(data) != size or sha(data) != digest
                            or digest != self._frozen["apt_indices"]["release_sha256"]
                            or size != self._frozen["apt_indices"]["release_size"]):
                        fail("Held APT Release differs from frozen anchor")
            except BaseException as error:
                self._retain((error,))
                raise
            return data

    def read_apt_release(self):
        """Exact held Release bytes bound to the frozen routing anchor."""
        _lease_record(self)
        return self._read_apt_held(self._apt_release, self._apt_anchor)

    def apt_tree_members(self):
        """Sorted held APT member paths relative to the APT root."""
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            try:
                self._require()
            except BaseException as error:
                self._retain((error,))
                raise
            return tuple(sorted(self._apt_held))

    def read_apt_member(self, relative):
        """Read one exact minted APT member; no normalization or filesystem path."""
        _lease_record(self)
        if type(relative) is not str or relative not in self._apt_held:
            fail("Lease APT reads require an exact held member")
        item = self._apt_held[relative]
        return self._read_apt_held(item, self._apt_anchor if relative == APT_RELEASE else None)

    @contextmanager
    def _phase(self, name, allowed):
        if name not in allowed:
            fail("Unsupported live lease phase")
        _lease_record(self)
        body_error = post_error = None
        try:
            with _SIGNING_LOCK, self._lock:
                self._require()
        except BaseException as error:
            self._retain((error,))
            raise
        try:
            yield
        except BaseException as error:
            body_error = error
        try:
            with _SIGNING_LOCK, self._lock:
                self._require()
        except BaseException as error:
            post_error = error
            retention_error = None
            try:
                self._retain(tuple(error for error in (body_error, post_error) if error is not None))
            except BaseException as retain_error:
                retention_error = retain_error
        if body_error is not None and post_error is not None:
            raise _LeasePhaseFailure(body_error, post_error, retention_error) from None
        if body_error is not None:
            raise body_error
        if post_error is not None:
            raise _LeasePhaseFailure(None, post_error, retention_error) from None

    def native_phase(self, name):
        return self._phase(name, _NATIVE_PHASES)

    def assembly_phase(self, name):
        return self._phase(name, _ASSEMBLY_PHASES)

    def __enter__(self):
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            try:
                self._require()
            except BaseException as error:
                self._retain((error,))
                raise
        return self

    def __getstate__(self):
        raise TypeError("Live signing leases cannot be serialized")

    def __reduce__(self):
        raise TypeError("Live signing leases cannot be pickled")

    def __exit__(self, exc_type, exc, tb):
        with _SIGNING_LOCK:
            if (getattr(self, "_state", None) == "closed"
                    and _LEASE_CLOSED.get(self) == os.getpid()):
                return False
        _lease_record(self)
        with _SIGNING_LOCK, self._lock:
            if self._state in {"active", "running"}:
                error = ContractError("CURRENT_SIGNING_LEASE", "Unresolved live lease custody retained")
                self._retain((error,))
                raise error
            return False


@dataclass(frozen=True, eq=False)
class _LiveSigningInputs:
    _marker: object


class _EnumerationResource:
    """One temporary package-walk descriptor with one-shot close custody."""

    __slots__ = ("fd", "expected", "kind", "status", "close_ledger", "close_errors", "close_error")

    def __init__(self, fd, expected, kind):
        self.fd = fd
        self.expected = expected
        self.kind = kind
        self.status = "open"
        self.close_ledger = []
        self.close_errors = []
        self.close_error = None

    def close(self):
        if self.status == "closed":
            return
        if self.status == "uncertain":
            raise self.close_error
        number = self.fd
        try:
            os.close(number)
        except BaseException as error:
            self.status = "uncertain"
            self.close_ledger.append({"kind": self.kind, "fd": number, "status": "uncertain"})
            self.close_errors.append(error)
            wrapped = ContractError("CURRENT_IMPORT_ROUTING", "Enumeration descriptor close failed")
            wrapped.close_ledger = tuple(self.close_ledger)
            wrapped.close_errors = tuple(self.close_errors)
            self.close_error = wrapped
            raise wrapped from error
        self.status = "closed"
        self.close_ledger.append({"kind": self.kind, "fd": number, "status": "closed"})


class _EnumerationFailure(ContractError):
    """Enumeration body/cleanup failure retaining its temporary resources."""

    def __init__(self, body_error, resources, cleanup_errors, *, body_cause=None,
                 message="Unsigned package enumeration failed"):
        super().__init__("CURRENT_IMPORT_ROUTING", message)
        self.body_error = body_error
        self.body_cause = body_cause
        self.resources = tuple(resources)
        self.cleanup_errors = tuple(cleanup_errors)


def _package_members(stage, *, resource_sink=None):
    """Only the owned unsigned-package subtree; APT indices/pool are separate."""
    found = set()
    entries = 0
    root_fd = None
    root_identity = None
    expected_directories = {}
    visited = set()
    walked_fds = []
    owned_resources = []
    close_errors = []
    body_error = None
    body_cause = None

    def enroll(fd, expected, kind):
        resource = _EnumerationResource(fd, expected, kind)
        owned_resources.append(resource)
        if resource_sink is not None:
            resource_sink.append(resource)
        return resource

    def refuse_walk_error(error):
        raise error
    try:
        root_fd = os.open("unsigned", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage.fd)
        # The root descriptor is enrolled before fstat and every duplicate is
        # enrolled immediately after dup; cleanup never retries an uncertain fd.
        root_entry = enroll(root_fd, None, "package-root")
        root_info = os.fstat(root_fd)
        root_identity = _directory_identity(root_info)
        root_entry.expected = _stable(root_info)
        expected_directories = {".": _stable(root_info)}
        for directory, children, files, fd in os.fwalk(".", follow_symlinks=False, dir_fd=root_fd, onerror=refuse_walk_error):
            relative = Path(directory).as_posix()
            if (relative in visited or relative not in expected_directories
                    or _stable(os.fstat(fd)) != expected_directories[relative]):
                fail("Unsigned package directory changed during enumeration")
            visited.add(relative)
            duplicate = os.dup(fd)
            walked_fds.append(enroll(duplicate, expected_directories[relative], "package-walk"))
            if len(Path(directory).parts) > 2:
                fail("Unexpected unsigned package directory depth")
            entries += len(children) + len(files)
            if entries > MAX_SIGNING_MEMBERS + 16:
                fail("Too many unsigned package entries")
            for name in children:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    fail("Aliased unsigned package directory")
                child = (Path(directory) / name).as_posix()
                if child in expected_directories:
                    fail("Duplicate unsigned package directory")
                expected_directories[child] = _stable(info)
            for name in files:
                if not stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                    fail("Unexpected unsigned package member")
                found.add((Path("unsigned") / directory / name).as_posix())
        if visited != set(expected_directories):
            fail("Unsigned package directory was skipped")
        if any(_stable(os.fstat(entry.fd)) != entry.expected for entry in walked_fds):
            fail("Unsigned package directory entries changed during enumeration")
        if _directory_identity(os.stat("unsigned", dir_fd=stage.fd, follow_symlinks=False)) != root_identity:
            fail("Unsigned package root changed")
    except OSError as error:
        body_cause = error
        body_error = ContractError("CURRENT_IMPORT_ROUTING", "Unsigned package directory enumeration failed")
        body_error.original_error = error
    except BaseException as error:
        body_cause = error
        body_error = error
    finally:
        for entry in reversed(owned_resources):
            if entry.status != "open":
                continue
            try:
                entry.close()
            except BaseException as error:
                close_errors.append(error)
        if close_errors:
            if body_error is None:
                body_error = ContractError("CURRENT_IMPORT_ROUTING", "Unsigned package enumeration cleanup failed")
            raise _EnumerationFailure(body_error, owned_resources, close_errors,
                                      body_cause=body_cause) from body_error
    if body_error is not None:
        raise body_error
    stage.check()
    return found


def _apt_members(stage, *, resource_sink=None):
    """Exact held stage APT subtree: member files plus ``dir/`` entries.

    Same enrollment, close-once and typed-failure discipline as
    ``_package_members``; it opens only ``apt`` and never the unsigned tree.
    """
    found = set()
    entries = 0
    root_fd = None
    root_identity = None
    expected_directories = {}
    visited = set()
    walked_fds = []
    owned_resources = []
    close_errors = []
    body_error = None
    body_cause = None

    def enroll(fd, expected, kind):
        resource = _EnumerationResource(fd, expected, kind)
        owned_resources.append(resource)
        if resource_sink is not None:
            resource_sink.append(resource)
        return resource

    def refuse_walk_error(error):
        raise error
    try:
        root_fd = os.open("apt", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage.fd)
        root_entry = enroll(root_fd, None, "apt-root")
        root_info = os.fstat(root_fd)
        root_identity = _directory_identity(root_info)
        root_entry.expected = _stable(root_info)
        expected_directories = {".": _stable(root_info)}
        for directory, children, files, fd in os.fwalk(".", follow_symlinks=False, dir_fd=root_fd, onerror=refuse_walk_error):
            relative = Path(directory).as_posix()
            if (relative in visited or relative not in expected_directories
                    or _stable(os.fstat(fd)) != expected_directories[relative]):
                fail("APT tree directory changed during enumeration")
            visited.add(relative)
            duplicate = os.dup(fd)
            walked_fds.append(enroll(duplicate, expected_directories[relative], "apt-walk"))
            if len(Path(directory).parts) > MAX_APT_DEPTH:
                fail("Unexpected APT tree directory depth")
            entries += len(children) + len(files)
            if entries > 2 * MAX_APT_MEMBERS:
                fail("Too many APT tree entries")
            for name in children:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode):
                    fail("Aliased APT tree directory")
                child = (Path(directory) / name).as_posix()
                if child in expected_directories:
                    fail("Duplicate APT tree directory")
                expected_directories[child] = _stable(info)
                found.add(child + "/")
            for name in files:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    fail("Unexpected or aliased APT tree member")
                found.add((Path(directory) / name).as_posix())
        if visited != set(expected_directories):
            fail("APT tree directory was skipped")
        if any(_stable(os.fstat(entry.fd)) != entry.expected for entry in walked_fds):
            fail("APT tree directory entries changed during enumeration")
        if _directory_identity(os.stat("apt", dir_fd=stage.fd, follow_symlinks=False)) != root_identity:
            fail("APT tree root changed")
    except OSError as error:
        body_cause = error
        body_error = ContractError("CURRENT_IMPORT_ROUTING", "APT tree directory enumeration failed")
        body_error.original_error = error
    except BaseException as error:
        body_cause = error
        body_error = error
    finally:
        for entry in reversed(owned_resources):
            if entry.status != "open":
                continue
            try:
                entry.close()
            except BaseException as error:
                close_errors.append(error)
        if close_errors:
            if body_error is None:
                body_error = ContractError("CURRENT_IMPORT_ROUTING", "APT tree enumeration cleanup failed")
            raise _EnumerationFailure(body_error, owned_resources, close_errors, body_cause=body_cause,
                                      message="APT tree enumeration failed") from body_error
    if body_error is not None:
        raise body_error
    stage.check()
    return found


def _hold_apt_tree(stage, apt_indices, rows, held, provisional):
    """Hold every APT member and bind the held bytes to frozen routing rows.

    The frozen member inventory is never trusted alone: the map is re-derived
    from held Release/Packages bytes and the authenticated DEB routing rows,
    then must equal the frozen inventory exactly.
    """
    if (not isinstance(apt_indices, dict)
            or set(apt_indices) != {"distribution", "release_sha256", "release_size", "indices", "members"}
            or apt_indices["distribution"] != APT_DISTRIBUTION
            or not isinstance(apt_indices["release_sha256"], str)
            or _SHA256_TEXT.fullmatch(apt_indices["release_sha256"]) is None
            or type(apt_indices["release_size"]) is not int
            or not 0 < apt_indices["release_size"] <= MAX_APT_METADATA
            or not isinstance(apt_indices["indices"], dict)
            or not isinstance(apt_indices["members"], list)
            or not 0 < len(apt_indices["members"]) <= MAX_APT_MEMBERS):
        fail("Live APT anchor differs")
    frozen_members = {}
    for item in apt_indices["members"]:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}
                or not isinstance(item["path"], str) or not isinstance(item["sha256"], str)
                or type(item["size"]) is not int or item["path"] in frozen_members):
            fail("Live APT member inventory differs")
        frozen_members[item["path"]] = (item["sha256"], item["size"])
    if [item["path"] for item in apt_indices["members"]] != sorted(frozen_members):
        fail("Live APT member inventory is not canonical")
    holds = {}

    def hold(path, digest, size):
        if path in holds:
            fail("Duplicate APT member hold")
        current = _SigningFile(stage, "apt/" + path, digest, size, provisional=provisional)
        held.append(current)
        holds[path] = current
        return current.read()

    release_sha, release_size = apt_indices["release_sha256"], apt_indices["release_size"]
    entries, architectures = _apt_release_entries(hold(APT_RELEASE, release_sha, release_size))
    if {path: digest for path, (digest, _) in entries.items()} != apt_indices["indices"]:
        fail("Held APT Release differs from frozen indices")
    base = f"dists/{APT_DISTRIBUTION}"
    index_bytes = {}
    for path, (digest, size) in sorted(entries.items()):
        if size > MAX_APT_METADATA:
            fail("APT index exceeds bound")
        index_bytes[path] = hold(f"{base}/{path}", digest, size)
    deb_rows = {row["name"]: row for row in rows if row["family"] == "deb"}
    pool = {}
    for arch in architectures:
        prefix = f"{APT_COMPONENTS[0]}/binary-{arch}/"
        plain = index_bytes[prefix + "Packages"]
        for name in APT_INDEX_NAMES[1:]:
            if _bounded_decompress(index_bytes[prefix + name], name) != plain:
                fail("APT compressed index differs from Packages")
        listed = set()
        for stanza in _apt_package_stanzas(plain):
            filename = stanza["Filename"]
            name = Path(filename).name
            row = deb_rows.get(name)
            if (row is None or name in listed
                    or (stanza["SHA256"], int(stanza["Size"])) != (row["sha256"], row["size"])
                    or stanza["Package"] != row["product"] or stanza["Version"] != name.split("_")[1]
                    or stanza["Architecture"] != row["architecture"]
                    or row["architecture"] not in (arch, "all")):
                fail("APT index package row differs from routing")
            if pool.setdefault(name, filename) != filename:
                fail("APT index package filename differs between architectures")
            listed.add(name)
        if listed != {name for name, row in deb_rows.items() if row["architecture"] in (arch, "all")}:
            fail("APT index package set differs from routing")
    if set(pool) != set(deb_rows):
        fail("APT pool set differs from routing")
    derived = _apt_member_map(release_sha, release_size, entries,
                              [(pool[name], deb_rows[name]["sha256"], deb_rows[name]["size"]) for name in sorted(pool)])
    if derived != frozen_members:
        fail("Held APT tree differs from frozen member inventory")
    for path, (digest, size) in sorted(derived.items()):
        if path not in holds:
            hold(path, digest, size)
    if set(holds) != set(frozen_members):
        fail("Held APT members differ from frozen inventory")
    return holds


def _apt_holds(held, frozen):
    """Recover the held APT map and exact tree view from one fresh owner value."""
    holds = {item.relative[len("apt/"):]: item for item in held if item.relative.startswith("apt/")}
    expected = {item["path"] for item in frozen["apt_indices"]["members"]}
    if set(holds) != expected or APT_RELEASE not in holds:
        fail("Held APT members differ from frozen inventory")
    return holds, _apt_tree_entries(holds)


@contextmanager
def fresh_signing_inputs(config, production, collection, stage, *, release_date,
                         zip_transport="actions", timeout=7200):
    """Fresh import to expiring mechanical handle; saved records are not inputs."""
    roots, held, handle = [], [], None
    pre_token = object()
    pre_state = {"state": "preparing", "resources": [], "errors": [], "cleanup_errors": ()}
    _PREHANDLE_RETENTION[pre_token] = pre_state
    try:
        for path in (collection, stage):
            roots.append(_DirectoryHold(path, provisional=pre_state["resources"]))
        result = prepare_unsigned(config, production, collection, stage, release_date=release_date,
                                  zip_transport=zip_transport, timeout=timeout)
        for root in roots:
            root.check()
        if (not isinstance(result, dict) or set(result) != {"schema", "p_source", "rs9_original", "own_repository_admission",
                            "objects", "apt_indices", "signed", "assembly_ready",
                            "production_enabled", "publication_authority", "pending"}
                or result["schema"] != "theme-forge.current-unsigned-routing.v1"
                or any(result[key] is not False for key in
                       ("signed", "assembly_ready", "production_enabled", "publication_authority"))
                or result["p_source"] != production.verify()
                or result["rs9_original"] != config.expected()):
            fail("Live unsigned routing source or status differs")
        frozen = json.loads(canonical(result))
        routing_bytes = canonical(frozen)
        routing_file = _SigningFile(roots[1], "unsigned-routing.json", sha(routing_bytes), len(routing_bytes),
                                     provisional=pre_state["resources"])
        held.append(routing_file)
        if routing_file.read() != routing_bytes:
            fail("Live routing file differs")
        rows, members = [], set()
        if not isinstance(frozen["objects"], list) or not 0 < len(frozen["objects"]) <= MAX_SIGNING_MEMBERS:
            fail("Closed live object list required")
        for row in frozen["objects"]:
            if (not isinstance(row, dict) or set(row) != {"family", "product", "name", "version",
                    "architecture", "sha256", "size", "origins", "destinations"}
                    or any(not isinstance(row[key], str) for key in
                           ("family", "product", "name", "version", "architecture", "sha256"))
                    or row["family"] not in SYSTEMS or row["product"] not in VERSIONS
                    or row["version"] != VERSIONS[row["product"]]
                    or not isinstance(row["name"], str) or Path(row["name"]).name != row["name"]
                    or not isinstance(row["destinations"], list) or not 1 <= len(row["destinations"]) <= 2):
                fail("Live signing object differs")
            family, arch, name = row["family"], row["architecture"], row["name"]
            allowed = {"deb": {"all", "amd64", "arm64"}, "rpm": {"noarch", "x86_64", "aarch64"}, "pacman": {"any", "x86_64"}}
            if arch not in allowed[family]:
                fail("Live package architecture differs")
            pure = row["product"] in {"theme-forge-stellar-loom", "theme-forge-solar-sail"}
            marker = {"deb": "all", "rpm": "noarch", "pacman": "any"}[family]
            if (pure and arch != marker) or (not pure and arch == marker):
                fail("Live package architecture-independent marker differs from product scope")
            expected = ([f"unsigned/rpm/{a}/{name}" for a in (sorted(ARCH_SYSTEM[family]) if arch == "noarch" else [arch])]
                        if family == "rpm" else [f"unsigned/{family}/{name}"])
            if row["destinations"] != expected:
                fail("Live package destination set differs")
            copies = []
            for relative in row["destinations"]:
                if relative in members or Path(relative).name != row["name"] or not relative.startswith("unsigned/" + row["family"] + "/"):
                    fail("Live package destination differs")
                members.add(relative)
                current = _SigningFile(roots[1], relative, row["sha256"], row["size"],
                                       provisional=pre_state["resources"])
                held.append(current)
                copies.append(current)
            rows.append((row, tuple(copies)))
        if _package_members(roots[1], resource_sink=pre_state["resources"]) != members:
            fail("Extra or missing unsigned package member")
        apt_holds = _hold_apt_tree(roots[1], frozen["apt_indices"], [row for row, _ in rows], held,
                                   pre_state["resources"])
        apt_tree = _apt_tree_entries(apt_holds)
        if _apt_members(roots[1], resource_sink=pre_state["resources"]) != apt_tree:
            fail("Extra or missing APT tree member")
        source_roots = (physical_directory(production.root), physical_directory(config.repository))
        handle = _LiveSigningInputs(_SIGNING_SENTINEL)
        with _SIGNING_LOCK:
            _SIGNING_LIVE[handle] = (os.getpid(), frozen, tuple(rows), tuple(held), tuple(roots), source_roots)
            _SIGNING_STATES[handle] = {"state": "fresh", "value": _SIGNING_LIVE[handle]}
            pre_state["state"] = "fresh"
            pre_state["handle"] = handle
            _PREHANDLE_RETENTION.pop(pre_token, None)
        yield handle
        with _SIGNING_LOCK:
            owner_state = _SIGNING_STATES.get(handle)
            if owner_state is None or owner_state.get("state") not in {"transferred", "retained"}:
                for item in held:
                    item.read()
                if _package_members(roots[1], resource_sink=pre_state["resources"]) != members:
                    fail("Unsigned package membership changed")
                if _apt_members(roots[1], resource_sink=pre_state["resources"]) != apt_tree:
                    fail("APT tree membership changed")
    except OSError:
        raise ContractError("CURRENT_IMPORT_ROUTING", "Physical signing custody unavailable") from None
    finally:
        moved = False
        if handle is not None:
            with _SIGNING_LOCK:
                owner_state = _SIGNING_STATES.pop(handle, None)
                _SIGNING_LIVE.pop(handle, None)
                moved = owner_state is not None and owner_state.get("state") in {"transferred", "retained", "materializing"}
                if owner_state is not None and owner_state.get("state") in {"retained", "materializing"}:
                    _OWNER_RETENTION[handle] = owner_state
                    _SIGNING_RETENTION[handle] = owner_state
        if not moved:
            close_errors = []
            for item in reversed(pre_state["resources"]):
                try:
                    item.close()
                except BaseException as error:
                    close_errors.append(error)
            if close_errors:
                pre_state["state"] = "retained"
                pre_state["errors"] = tuple(close_errors)
                pre_state["cleanup_errors"] = tuple(close_errors)
                _PREHANDLE_RETENTION[pre_token] = pre_state
                if handle is not None:
                    owner_state = {"state": "retained", "value": (os.getpid(), frozen if 'frozen' in locals() else None,
                        tuple(), tuple(held), tuple(roots), tuple()), "errors": tuple(close_errors),
                                  "resources": tuple(pre_state["resources"])}
                    _OWNER_RETENTION[handle] = owner_state
                    _SIGNING_RETENTION[handle] = owner_state
                active_error = sys.exc_info()[1]
                if active_error is not None:
                    active_error.cleanup_errors = tuple(close_errors)
                else:
                    raise ContractError("CURRENT_IMPORT_ROUTING", "Fresh signing custody close is uncertain") from close_errors[0]
            else:
                _PREHANDLE_RETENTION.pop(pre_token, None)


def _close_provisional_fd(entry, errors):
    """Close an enrolled write/inspection fd once; never retry its number."""
    if entry is None or entry.get("status") != "open":
        return
    number = entry["fd"]
    try:
        os.close(number)
    except BaseException as error:
        entry["status"] = "uncertain"
        entry["error"] = error
        errors.append(error)
    else:
        entry["status"] = "closed"


def _transfer_destination(value, destination, owner_state=None):
    """Materialize one lease from held descriptors; caller owns the RLock."""
    _, frozen, rows, held, roots, source_roots = value
    target = Path(destination)
    parent = destination_hold = None
    created_fd = None
    created_identity = None
    created_names = []
    copies = []
    lease = None
    provisional = {"resources": [], "fds": [], "created": False, "identity": None,
                   "target": target, "errors": [], "cleanup_errors": [],
                   "created_records": {}, "deletion_ledger": {}}
    if owner_state is not None:
        owner_state["provisional"] = provisional
    try:
        # Recheck all source custody before creating any destination entry.
        for item in held:
            item.read()
        expected_stage_members = {relative for row, _ in rows for relative in row["destinations"]}
        if _package_members(roots[1], resource_sink=provisional["resources"]) != expected_stage_members:
            fail("Unsigned package membership changed before lease transfer")
        apt_held, apt_tree = _apt_holds(held, frozen)
        if _apt_members(roots[1], resource_sink=provisional["resources"]) != apt_tree:
            fail("APT tree membership changed before lease transfer")
        parent = _DirectoryHold(target.parent, provisional=provisional["resources"])
        parent_info = os.fstat(parent.fd)
        if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
            fail("Signing lease parent must be owned and deny foreign writes")
        if target.name in {"", ".", ".."} or target.parent != parent.path:
            fail("Physical signing lease destination required")
        if any(target == path or path in target.parents for path in (*source_roots, *(root.path for root in roots))):
            fail("Signing lease destination must be outside source and import roots")
        os.mkdir(target.name, 0o700, dir_fd=parent.fd)
        provisional["created"] = True
        provisional["created_identity"] = None
        created_fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd)
        provisional["fds"].append({"kind": "created-directory", "fd": created_fd, "status": "open"})
        info = os.fstat(created_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or os.listdir(created_fd)):
            fail("Fresh signing lease directory custody differs")
        created_identity = _directory_identity(info)
        provisional["identity"] = created_identity
        provisional["created_identity"] = created_identity
        destination_hold = _DirectoryHold(target, provisional=provisional["resources"])
        if destination_hold.identity != created_identity:
            fail("Fresh signing lease directory was replaced")
        for row, sources in rows:
            data = sources[0].read()
            if any(source.read() != data for source in sources[1:]):
                fail("Repeated package copies differ during lease transfer")
            relative = row["name"]
            fd = os.open(relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=destination_hold.fd)
            write_entry = {"kind": "write", "fd": fd, "status": "open", "name": relative}
            provisional["fds"].append(write_entry)
            created_names.append(relative)
            body_error = None
            try:
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        fail("Signing lease write made no progress")
                    view = view[count:]
                os.fsync(fd)
            except BaseException as error:
                body_error = error
                raise
            finally:
                _close_provisional_fd(write_entry, provisional["cleanup_errors"])
                if body_error is None and write_entry["status"] != "closed":
                    fail("Signing lease write descriptor close was not confirmed")
            created_info = os.stat(relative, dir_fd=destination_hold.fd, follow_symlinks=False)
            if not stat.S_ISREG(created_info.st_mode) or created_info.st_nlink != 1:
                fail("Signing lease created member is not a regular file")
            provisional["created_records"][relative] = {
                "identity": _stable(created_info), "sha256": row["sha256"], "size": row["size"], "copy": None,
            }
            copy = _SigningFile(destination_hold, relative, row["sha256"], row["size"],
                                 provisional=provisional["resources"])
            copies.append(copy)
            provisional["created_records"][relative]["copy"] = copy
            if copy.read() != data:
                fail("Signing lease copy readback differs")
            destination_hold.check()
        parent.check()
        if _directory_identity(os.stat(target.name, dir_fd=parent.fd, follow_symlinks=False)) != created_identity:
            fail("Signing lease destination changed during transfer")
        for item in held:
            item.read()
        if _package_members(roots[1], resource_sink=provisional["resources"]) != expected_stage_members:
            fail("Unsigned package membership changed during lease transfer")
        if _apt_members(roots[1], resource_sink=provisional["resources"]) != apt_tree:
            fail("APT tree membership changed during lease transfer")
        if _destination_members(destination_hold) != {row["name"] for row, _ in rows}:
            fail("Signing lease copied member set differs during transfer")
        created_entry = provisional["fds"][0]
        _close_provisional_fd(created_entry, provisional["cleanup_errors"])
        created_fd = None
        if provisional["cleanup_errors"]:
            raise provisional["cleanup_errors"][0]
        frozen_immutable = _freeze(json.loads(canonical(frozen)))
        immutable_rows = tuple((_freeze(row), tuple(copies_for_row)) for row, copies_for_row in rows)
        record = {"minted": True, "pid": os.getpid(), "state": "active", "frozen": frozen_immutable,
                  "rows": immutable_rows, "held": tuple(held), "roots": tuple(roots),
                  "destination_parent": parent, "destination": destination_hold, "copies": tuple(copies),
                  "members": frozenset(row["name"] for row, _ in rows),
                  "stage_members": frozenset(expected_stage_members),
                  "routing": next((item for item in held if item.relative == "unsigned-routing.json"), None),
                  "routing_bytes": canonical(frozen),
                  "origin": frozen_immutable.get("p_source", {}).get("repository", ""),
                  "source_roots": tuple(source_roots),
                  "apt_members": apt_tree, "apt_held": MappingProxyType(dict(apt_held)),
                  "apt_release": apt_held[APT_RELEASE],
                  "apt_anchor": (frozen_immutable["apt_indices"]["release_sha256"],
                                 frozen_immutable["apt_indices"]["release_size"]),
                  "errors": (), "provisional": provisional}
        lease = _LiveSigningLease(_LEASE_MINT_TOKEN, record)
        _LEASE_REGISTRY[lease] = record
        lease._require()
        return lease
    except BaseException as original_error:
        provisional["errors"].append(original_error)
        cleanup_errors = list(provisional["cleanup_errors"])
        # A typed package-walk failure already owns its temporary descriptor
        # ledger.  Propagate that ledger and its close failures before the
        # created-destination deletion barrier; otherwise a post-copy walk
        # close failure would be noticed only after pathname cleanup.
        enumeration_resources = getattr(original_error, "resources", ())
        for resource in enumeration_resources:
            if resource not in provisional["resources"]:
                provisional["resources"].append(resource)
        for cleanup_error in getattr(original_error, "cleanup_errors", ()):
            if cleanup_error not in cleanup_errors:
                cleanup_errors.append(cleanup_error)
        if enumeration_resources:
            provisional["enumeration_error"] = original_error
        if lease is not None and _LEASE_REGISTRY.get(lease) is not None:
            # The lease is already strongly registered.  A final mint check
            # failure must retain it, never close the descriptors and then
            # leave an active registry entry pointing at closed resources.
            try:
                lease._retain((original_error,))
            except BaseException as retention_error:
                cleanup_errors.append(retention_error)
                record = _LEASE_REGISTRY.get(lease)
                if record is not None:
                    record["errors"] = tuple(record.get("errors", ())) + (original_error, retention_error)
                    _LEASE_RETENTION[lease] = record
            error = ContractError("CURRENT_IMPORT_ROUTING", "Live lease mint verification failed")
            error.original_error = original_error
            error.cleanup_errors = tuple(cleanup_errors)
            error.cleanup_confirmed = False
            error.retained = True
            error.retained_resources = (lease, provisional)
            raise error from original_error
        cleanup_ok = not provisional["created"]
        # Prove every enrolled destination file is still the exact inode/body
        # written by this transfer before closing its held copy or unlinking it.
        if provisional["created"]:
            try:
                if parent is None or created_fd is None or created_identity is None:
                    raise RuntimeError("fresh destination custody is unavailable")
                parent.check()
                named = os.stat(target.name, dir_fd=parent.fd, follow_symlinks=False)
                if _directory_identity(named) != created_identity:
                    raise RuntimeError("fresh destination identity changed")
                if _destination_members(destination_hold) != set(created_names):
                    raise RuntimeError("fresh destination membership is uncertain")
                for name in created_names:
                    record = provisional["created_records"].get(name)
                    if record is None:
                        raise RuntimeError("fresh destination file record is missing")
                    info = os.stat(name, dir_fd=created_fd, follow_symlinks=False)
                    if _stable(info) != record["identity"]:
                        raise RuntimeError("fresh destination file identity changed")
                    if record.get("copy") is not None:
                        record["copy"].read()
                    else:
                        body = held_bytes(target / name, record["size"])
                        if len(body) != record["size"] or sha(body) != record["sha256"]:
                            raise RuntimeError("fresh destination file body changed")
            except BaseException as error:
                cleanup_errors.append(error)
        # Close enrolled leaf/copy and write resources.  An uncertain live
        # descriptor is never followed by deletion of its pathname.
        for item in reversed(provisional["resources"]):
            if isinstance(item, _SigningFile):
                try:
                    item.close()
                except BaseException as error:
                    cleanup_errors.append(error)
        for entry in provisional["fds"]:
            if entry.get("kind") == "write":
                _close_provisional_fd(entry, cleanup_errors)
        if cleanup_errors:
            cleanup_ok = False
        # Delete only after all body/identity checks and descriptor closes have
        # succeeded.  Each confirmed unlink is recorded; uncertainty stops the
        # ledger and retains the remaining names/resources.
        if provisional["created"] and not cleanup_errors:
            try:
                if parent is None or created_fd is None or created_identity is None:
                    raise RuntimeError("fresh destination custody is unavailable")
                for name in created_names:
                    os.unlink(name, dir_fd=created_fd)
                    provisional["deletion_ledger"][name] = "removed"
                if os.listdir(created_fd):
                    raise RuntimeError("fresh destination cleanup is incomplete")
                os.rmdir(target.name, dir_fd=parent.fd)
                provisional["deletion_ledger"]["directory"] = "removed"
                cleanup_ok = True
            except BaseException as error:
                provisional["deletion_error"] = error
                cleanup_errors.append(error)
        for item in reversed(provisional["resources"]):
            if isinstance(item, _SigningFile):
                continue
            try:
                item.close()
            except BaseException as error:
                cleanup_errors.append(error)
        for entry in reversed(provisional["fds"]):
            if entry.get("kind") == "write":
                continue
            _close_provisional_fd(entry, cleanup_errors)
        provisional["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            cleanup_ok = False
        error = ContractError("CURRENT_IMPORT_ROUTING", "Live lease transfer failed")
        error.original_error = original_error
        error.cleanup_errors = tuple(cleanup_errors)
        error.cleanup_confirmed = cleanup_ok
        error.retained = not cleanup_ok
        if not cleanup_ok:
            error.retained_resources = (owner_state, provisional, parent, destination_hold, tuple(copies), created_fd, target)
        raise error from original_error


def transfer_signing_inputs(handle, destination):
    """Atomically transfer a fresh owner to module-owned descriptor custody."""
    if type(handle) is not _LiveSigningInputs or handle._marker is not _SIGNING_SENTINEL:
        fail("Fresh live signing input handle required")
    with _SIGNING_LOCK:
        value = _SIGNING_LIVE.get(handle)
        state_record = _SIGNING_STATES.get(handle)
        if (value is None or state_record is None or state_record.get("state") != "fresh"
                or value[0] != os.getpid()):
            fail("Fresh live signing input handle required")
        state_record["state"] = "materializing"
        try:
            lease = _transfer_destination(value, destination, owner_state=state_record)
        except BaseException as error:
            state_record["state"] = "retained" if getattr(error, "retained", False) else "aborted"
            state_record["error"] = error
            _SIGNING_LIVE.pop(handle, None)
            if getattr(error, "retained", False):
                state_record["value"] = value
                _OWNER_RETENTION[handle] = state_record
                _SIGNING_RETENTION[handle] = state_record
            raise
        # The lease is registered before the owner can be marked transferred;
        # an outer context therefore never observes a moved state without a
        # strong owner for every held descriptor.
        if _LEASE_REGISTRY.get(lease) is None or state_record.get("state") != "materializing":
            state_record["state"] = "retained"
            state_record["error"] = ContractError("CURRENT_IMPORT_ROUTING", "Live lease commit was interrupted")
            _OWNER_RETENTION[handle] = state_record
            _SIGNING_RETENTION[handle] = state_record
            lease._retain((state_record["error"],))
            raise state_record["error"]
        state_record["state"] = "transferred"
        state_record["lease"] = lease
        state_record["value"] = value
        _SIGNING_LIVE.pop(handle, None)
        return lease


def copy_signing_inputs(handle, destination):
    """Consume once; copy from held FDs, never reopen original package paths."""
    with _SIGNING_LOCK:
        value = _SIGNING_LIVE.pop(handle, None) if type(handle) is _LiveSigningInputs else None
    if value is None or handle._marker is not _SIGNING_SENTINEL or value[0] != os.getpid():
        fail("Live signing input handle required")
    _, frozen, rows, held, roots, source_roots = value
    expected_members = {relative for row, _ in rows for relative in row["destinations"]}
    if _package_members(roots[1]) != expected_members:
        fail("Unsigned package membership differs before intake")
    _, apt_tree = _apt_holds(held, frozen)
    if _apt_members(roots[1]) != apt_tree:
        fail("APT tree membership differs before intake")
    for item in held:
        item.read()
    target = Path(destination)
    parent, destination_hold, created_fd, created_identity, created = None, None, None, None, []
    try:
        parent = _DirectoryHold(target.parent)
        parent_info = os.fstat(parent.fd)
        if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
            fail("Signing-copy parent must be owned and deny foreign writes")
        if target.name in {"", ".", ".."} or target.parent != parent.path:
            fail("Physical signing-copy destination required")
        if any(target == path or path in target.parents for path in (*source_roots, *(root.path for root in roots))):
            fail("Signing copies must be outside source checkouts and import roots")
        os.mkdir(target.name, 0o700, dir_fd=parent.fd)
        try:
            created_fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd)
        except OSError:
            # No copy has been written. Capture only a verified empty owned
            # directory for guarded cleanup if opening it failed.
            info = os.stat(target.name, dir_fd=parent.fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700:
                created_identity = _directory_identity(info)
            raise
        info = os.fstat(created_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            fail("Private signing-copy directory ownership or shape differs")
        created_identity = _directory_identity(info)
        if os.listdir(created_fd):
            fail("Private signing-copy directory is not empty")
        destination_hold = _DirectoryHold(target)
        if destination_hold.identity != created_identity:
            fail("Private signing-copy directory was replaced")
        copied = []
        for row, sources in rows:
            data = sources[0].read()
            if any(source.read() != data for source in sources[1:]):
                fail("Repeated package copies differ")
            name = row["name"]
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=destination_hold.fd)
            created.append(name)
            try:
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        fail("Signing copy write made no progress")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            check = _SigningFile(destination_hold, name, row["sha256"], row["size"])
            try:
                if check.read() != data:
                    fail("Signing copy readback differs")
            finally:
                check.close()
            destination_hold.check()
            copied.append({**row, "path": target / name})
        for root in roots:
            root.check()
        if _package_members(roots[1]) != expected_members:
            fail("Unsigned package membership changed during intake")
        if _apt_members(roots[1]) != apt_tree:
            fail("APT tree membership changed during intake")
    except BaseException as error:
        if created_identity is not None:
            parent.check()
            named = os.stat(target.name, dir_fd=parent.fd, follow_symlinks=False)
            if _directory_identity(named) != created_identity:
                fail("Signing-copy cleanup identity differs")
            if destination_hold is not None:
                destination_hold.check()
            for name in created:
                os.unlink(name, dir_fd=created_fd)
            os.rmdir(target.name, dir_fd=parent.fd)
        if isinstance(error, OSError):
            raise ContractError("CURRENT_IMPORT_ROUTING", "Signing copy I/O failed") from None
        raise
    finally:
        if created_fd is not None:
            os.close(created_fd)
        if destination_hold is not None:
            destination_hold.close()
        if parent is not None:
            parent.close()
    # Caller may pass these owned copies to the mechanical signer only. Neither
    # this result nor its serialized metadata admits production/publication.
    return {"objects": tuple(copied), "p_source": frozen["p_source"],
            "rs9_original": frozen["rs9_original"], "routing_sha256": sha(canonical(frozen)),
            "production_enabled": False, "publication_authority": False}
