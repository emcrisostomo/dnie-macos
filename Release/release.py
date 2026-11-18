#!/usr/bin/env python3
"""Build and verify the pinned arm64 macOS component package."""

import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import uuid
import xml.etree.ElementTree as ET


class ReleaseError(Exception):
    pass


TOOLCHAIN = {"architecture": "arm64", "xcode": "27.2", "xcode_build": "27B52",
             "macos_sdk": "27.2", "sdk_build": "26B118", "swift": "6.4.2",
             "macos": "27.2.1", "macos_build": "26B131"}
CONFIG = {"configuration": "Release", "deployment": "26.0", "version": "0.1.0",
          "build": "1", "app_id": "org.dniemacos.dnietoken",
          "extension_id": "org.dniemacos.dnietoken.tokenextension",
          "package_id": "org.dniemacos.dnietoken.installer",
          "install_location": "/Applications"}
PACKAGE_VERSION = f"{CONFIG['version']}.{CONFIG['build']}"
HOST = Path("DNIeTokenHost.app")
EXTENSION = HOST / "Contents/PlugIns/DNIeTokenExtension.appex"
RESOURCES = EXTENSION / "Contents/Resources/DNIeCore_DNIeCore.bundle"
ASSETS = RESOURCES / "Contents/Resources/Assets"
HOST_RESOURCES = HOST / "Contents/Resources"
SOURCE_REFERENCE = HOST_RESOURCES / "SOURCE.json"
NOTICE_HASHES = {
    Path("LICENSE"): "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
    Path("LICENSES/README.md"): "5217a4b4d17dfc3fd3243fdbc53d2af19e4ecd1d770725b79e1d98429c4e85c2",
}
PUBLIC_REPOSITORY = "https://github.com/emcrisostomo/dnie-macos"
STAGE_SCRIPT = Path("Validation/Scripts/stage-production-credential-asset.sh")
CREDENTIAL_SOURCE = Path("Validation/private/SecureChannel/generation2.json")
CREDENTIAL_CODE = Path("Packages/DNIeCore/Sources/DNIeCore/Evidence/Credentials")
CREDENTIAL_ASSET = CREDENTIAL_CODE / "Assets/generation2.json"
BUILD_INPUTS = ("DNIeToken.xcodeproj", "HostApp", "TokenExtension",
                "Packages/DNIeCore/Package.swift", "Packages/DNIeCore/Sources", str(STAGE_SCRIPT),
                *(str(path) for path in NOTICE_HASHES))
# Reviewed public runtime tree. Change only after source and generated payload review.
BUILD_INPUT_TREE_SHA256 = "3755f807c084d223fcab88b8c1e8f3fa4e5bdb0afad2d89e95fb9ba0ca2dd34b"
MANIFEST = "manifest.json"
NOTARY_STATE = "notary-state.json"
SUBMISSION = "submission.pkg"
SIGNED_PACKAGE = "DNIeToken.pkg"
DIAGNOSTIC_PACKAGE = "DNIeToken-diagnostic-unsigned.pkg"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def hash_file(path):
    with path.open("rb") as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            hasher.update(chunk)
        return hasher.hexdigest()


def command(args, *, label, env=None, cwd=None, binary=False, stderr=False, input_bytes=None):
    # Deliberately suppress raw output from Apple tools, including identity and account names,
    # credential-bearing build paths and notary service diagnostics.
    try:
        completed = subprocess.run(args, cwd=cwd,
                                   env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                                        "LC_ALL": "C", **(env or {})},
                                   stdin=subprocess.DEVNULL if input_bytes is None else None,
                                   input=input_bytes, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT if stderr else subprocess.PIPE,
                                   check=False)
    except (OSError, ValueError):
        raise ReleaseError(f"{label} could not start.") from None
    if completed.returncode:
        raise ReleaseError(f"{label} failed (status {completed.returncode}).")
    return completed.stdout if binary else completed.stdout.decode("utf-8", errors="replace")


def git(root, *args, binary=False):
    return command(("/usr/bin/git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", root, *args),
                   label="Git source inspection", binary=binary)


def source_identity(root, revision):
    if not re.fullmatch("[0-9a-f]{40}", revision or ""):
        raise ReleaseError("Provide the full 40-character Git revision.")
    if Path(git(root, "rev-parse", "--show-toplevel").strip()).resolve() != root:
        raise ReleaseError("Source must be the checkout root.")
    if git(root, "rev-parse", "HEAD").strip() != revision:
        raise ReleaseError("Source HEAD differs from the pinned revision.")
    if git(root, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"):
        raise ReleaseError("Source checkout is dirty.")
    if any(line[:1] in ("S", "h", "s") for line in git(root, "ls-files", "-v").splitlines()):
        raise ReleaseError("Source index contains hidden worktree changes.")
    return {"revision": revision, "tree": git(root, "rev-parse", f"{revision}^{{tree}}").strip()}


def check_running_program(root, revision):
    literal = git(root, "show", f"{revision}:Release/release.py", binary=True)
    if Path(__file__).resolve().read_bytes() != literal:
        raise ReleaseError("Running release program differs from the pinned source revision.")


def source_tree(root, revision):
    tree = git(root, "ls-tree", "-rz", revision, "--", *BUILD_INPUTS, binary=True)
    if sha256(tree) != BUILD_INPUT_TREE_SHA256:
        raise ReleaseError("Build inputs differ from the reviewed runtime tree.")
    return tree


def export_source(root, revision, tree, destination):
    destination.mkdir(mode=0o700)
    expected = {}
    for entry in tree.rstrip(b"\0").split(b"\0"):
        info, name = entry.decode("utf-8").split("\t", 1)
        mode, kind, object_id = info.split()
        relative = PurePosixPath(name)
        if kind != "blob" or mode not in ("100644", "100755") or (
                relative.is_absolute() or ".." in relative.parts):
            raise ReleaseError("Source contains an unsupported path or node.")
        expected[name] = object_id, int(mode[-3:], 8)
    archive = git(root, "archive", "--format=tar", revision, "--", *BUILD_INPUTS, binary=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as contents:
        extracted = set()
        for entry in contents:
            if entry.isdir():
                continue
            if not entry.isfile() or entry.name not in expected or entry.name in extracted:
                raise ReleaseError("Source export contains an unexpected node.")
            stream = contents.extractfile(entry)
            data = stream.read()
            object_id, mode = expected[entry.name]
            git_blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
            if git_blob != object_id:
                raise ReleaseError("Source export bytes do not match the committed blob.")
            path = destination / entry.name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
            extracted.add(entry.name)
    if extracted != set(expected):
        raise ReleaseError("Source export is missing committed build inputs.")


def check_toolchain(run=command, architecture=None):
    xcode = run(("/usr/bin/xcodebuild", "-version"), label="Xcode version").splitlines()
    sdk = run(("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"),
              label="macOS SDK version").strip()
    swift = run(("/usr/bin/xcrun", "swift", "--version"), label="Swift version")
    if (architecture or platform.machine()) != TOOLCHAIN["architecture"]:
        raise ReleaseError("Release requires a native arm64 process.")
    if xcode != [f"Xcode {TOOLCHAIN['xcode']}", f"Build version {TOOLCHAIN['xcode_build']}"]:
        raise ReleaseError("Xcode version or build disagrees with the release pin.")
    if sdk != TOOLCHAIN["macos_sdk"]:
        raise ReleaseError("macOS SDK version disagrees with the release pin.")
    if not re.search(rf"Apple Swift version {re.escape(TOOLCHAIN['swift'])}(?:\s|$)", swift):
        raise ReleaseError("Swift version disagrees with the release pin.")
    sdk_build = run(("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-build-version"),
                    label="SDK build version").strip()
    host_version = run(("/usr/bin/sw_vers", "-productVersion"), label="macOS version").strip()
    host_build = run(("/usr/bin/sw_vers", "-buildVersion"), label="macOS build").strip()
    if (sdk_build, host_version, host_build) != (TOOLCHAIN["sdk_build"], TOOLCHAIN["macos"], TOOLCHAIN["macos_build"]):
        raise ReleaseError("macOS host or SDK build differs from the release pin.")
    return dict(TOOLCHAIN)


def canonical(path):
    # Keep symlink and '..' rejection ahead of file reads.
    if not path.is_absolute():
        path = Path.cwd() / path
    if ".." in path.parts or path.resolve() != path:
        raise ReleaseError("Path is linked or noncanonical.")
    return path


def open_safe_directory(path):
    path = canonical(path)
    directory_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
    directory = os.open("/", directory_flags)
    try:
        for part in path.parts[1:]:
            next_directory = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
            info = os.fstat(directory)
            if (info.st_uid not in (0, os.getuid())
                    or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
                raise ReleaseError("Private path has an untrusted directory ancestor.")
        return directory
    except BaseException:
        os.close(directory)
        raise


def validate_output_parent(output):
    directory = open_safe_directory(output.parent)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise ReleaseError("Output parent must be operator-owned or a trusted temporary directory.")
    finally:
        os.close(directory)


def open_regular(path, mode):
    path = canonical(path)
    directory = open_safe_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    stream = os.fdopen(fd, "rb")
    info = os.fstat(stream.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode):
        stream.close()
        raise ReleaseError("Private file must be owned by the invoking user, mode 0600 and unlinked.")
    return stream

def read_private(path):
    try:
        path = canonical(path)
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise ReleaseError("Private input directory is writable by another account.")
        with open_regular(path, 0o600) as stream:
            data = stream.read(65_537)
    except OSError:
        raise ReleaseError("Private input could not be read safely.") from None
    if not data or len(data) > 65_536:
        raise ReleaseError("Private input size is outside the supported range.")
    return data


def decode_record(data, label):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError()
        return result

    try:
        value = json.loads(data, object_pairs_hook=unique)
    except (ValueError, TypeError, UnicodeError):
        raise ReleaseError(f"{label} is malformed.") from None
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be a JSON object.")
    return value


def authorize(path, expected_hash, source, fixture_hash=None):
    if path is None or not re.fullmatch("[0-9a-f]{64}", expected_hash or ""):
        raise ReleaseError("Release requires the independently approved authorization record digest.")
    data = read_private(path)
    if sha256(data) != expected_hash:
        raise ReleaseError("Authorization record digest does not match the approved input.")
    record = decode_record(data, "Authorization record")
    expected = {"schema": 1, **source, "scope": "public-binary-release",
                "version": CONFIG["version"], "build": CONFIG["build"],
                "source_rights": True, "credential_redistribution": True,
                "apple_notarization_submission": True}
    format_checks = {"fixture_sha256": "[0-9a-f]{64}", "team_id": "[A-Z0-9]{10}",
                     "application_identity_sha1": "[0-9A-F]{40}",
                     "installer_identity_sha1": "[0-9A-F]{40}",
                     "installer_certificate_sha256": "[0-9a-f]{64}",
                     "notary_profile": "[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}"}
    if (record.keys() != expected.keys() | format_checks.keys()
            or any(type(record[key]) is not type(value) or record[key] != value
                   for key, value in expected.items())
            or any(not isinstance(record[key], str) or not re.fullmatch(pattern, record[key])
                   for key, pattern in format_checks.items())):
        raise ReleaseError("Authorization does not grant the required exact release scope.")
    if fixture_hash is not None and record["fixture_sha256"] != fixture_hash:
        raise ReleaseError("Authorized credential input digest does not match.")
    return record


def write_bytes(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pending-", delete=False) as tmp:
        pending = Path(tmp.name)
        try:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            os.replace(pending, path)
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            pending.unlink(missing_ok=True)


def write_record(path, data):
    write_bytes(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())


def inventory(root):
    items = {}
    for node in sorted(root.rglob("*")):
        info = node.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o7022:
            raise ReleaseError("Payload contains an unsafe mode.")
        if stat.S_ISDIR(info.st_mode):
            entry = {"type": "directory", "mode": f"{mode:04o}"}
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            entry = {"type": "file", "mode": f"{mode:04o}", "sha256": hash_file(node)}
        else:
            raise ReleaseError("Payload contains a link or unsupported node.")
        items[node.relative_to(root).as_posix()] = entry
    return items


def first_difference(left, right):
    for name in sorted(left.keys() | right.keys()):
        if name not in left or name not in right:
            return {"path": name, "field": "presence"}
        for key in ("type", "mode", "sha256"):
            if left[name].get(key) != right[name].get(key):
                return {"path": name, "field": key}
    return None


def inventory_digest(items):
    return sha256(json.dumps(items, sort_keys=True, separators=(",", ":")).encode())


def plist(path):
    try:
        with path.open("rb") as stream:
            value = plistlib.load(stream)
    except (OSError, ValueError, plistlib.InvalidFileException):
        raise ReleaseError("Payload property list is malformed.") from None
    if not isinstance(value, dict):
        raise ReleaseError("Payload property list is malformed.")
    return value


def check_entitlements(entitlements, *, extension):
    expected = ({"com.apple.security.app-sandbox": True, "com.apple.security.smartcard": True}
                if extension else {})
    if (entitlements.keys() != expected.keys()
            or any(entitlements[key] is not value for key, value in expected.items())):
        raise ReleaseError("Executable entitlement profile is unexpected.")


def corresponding_source(identity):
    return {**identity, "url": f"{PUBLIC_REPOSITORY}/tree/{identity['revision']}"}


def add_notices(source, payload, identity):
    for relative in NOTICE_HASHES:
        target = payload / HOST_RESOURCES / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
        target.chmod(0o644)
    reference = payload / SOURCE_REFERENCE
    write_record(reference, corresponding_source(identity))
    reference.chmod(0o644)


def verify_notices(root, contents, identity):
    for relative, digest in NOTICE_HASHES.items():
        if contents[(HOST_RESOURCES / relative).as_posix()]["sha256"] != digest:
            raise ReleaseError("Packaged licence or provenance notice differs from reviewed source.")
    reference = decode_record((root / SOURCE_REFERENCE).read_bytes(), "Corresponding source reference")
    if reference != corresponding_source(identity):
        raise ReleaseError("Corresponding source reference differs from the pinned source.")


def payload_paths(credential, signed):
    files = {
        HOST / "Contents/Info.plist", HOST / "Contents/PkgInfo",
        HOST / "Contents/MacOS/DNIeTokenHost",
        EXTENSION / "Contents/Info.plist", EXTENSION / "Contents/MacOS/DNIeTokenExtension",
        RESOURCES / "Contents/Info.plist", ASSETS / "README.md", SOURCE_REFERENCE,
        *(HOST_RESOURCES / relative for relative in NOTICE_HASHES),
    }
    if credential:
        files.add(ASSETS / "generation2.json")
    if signed:
        files.update(bundle / "Contents/_CodeSignature/CodeResources"
                     for bundle in (HOST, EXTENSION))
    dirs = {parent for node in files for parent in node.parents if parent != Path(".")}
    return {path.as_posix(): "file" for path in files} | {
        path.as_posix(): "directory" for path in dirs
    }


def expected_payload_mode(name, kind):
    executables = (HOST / "Contents/MacOS/DNIeTokenHost",
                   EXTENSION / "Contents/MacOS/DNIeTokenExtension")
    return "0755" if kind == "directory" or Path(name) in executables else "0644"


def check_layout(root, *, credential, signed):
    contents = inventory(root)
    if {path: item["type"] for path, item in contents.items()} != payload_paths(credential, signed):
        raise ReleaseError("Payload file allowlist differs. Extra code or undeclared content is forbidden.")
    return contents


def normalize_unsigned_modes(root, *, credential):
    for name, item in check_layout(root, credential=credential, signed=False).items():
        (root / name).chmod(int(expected_payload_mode(name, item["type"]), 8))


def check_payload(root, identity, *, fixture_hash=None, signed=False, run=command):
    contents = check_layout(root, credential=fixture_hash is not None, signed=signed)
    if any(item["mode"] != expected_payload_mode(name, item["type"])
           for name, item in contents.items()):
        raise ReleaseError("Payload node mode does not match release policy.")
    verify_notices(root, contents, identity)
    for bundle, identifier, executable, package_type in (
            (HOST, CONFIG["app_id"], "DNIeTokenHost", "APPL"),
            (EXTENSION, CONFIG["extension_id"], "DNIeTokenExtension", "XPC!")):
        info = plist(root / bundle / "Contents/Info.plist")
        expected = {"CFBundleExecutable": executable, "CFBundleIdentifier": identifier,
                    "CFBundlePackageType": package_type,
                    "CFBundleShortVersionString": CONFIG["version"], "CFBundleVersion": CONFIG["build"],
                    "LSMinimumSystemVersion": CONFIG["deployment"],
                    "DTXcodeBuild": TOOLCHAIN["xcode_build"],
                    "DTSDKName": f"macosx{TOOLCHAIN['macos_sdk']}", "DTSDKBuild": TOOLCHAIN["sdk_build"],
                    "BuildMachineOSBuild": TOOLCHAIN["macos_build"]}
        if any(info.get(key) != value for key, value in expected.items()):
            raise ReleaseError("Host or extension metadata differs from the release configuration.")
        if bundle == HOST and info.get("LSUIElement") is not True:
            raise ReleaseError("Host interface metadata is unexpected.")
        if bundle == EXTENSION and info.get("NSExtension") != {
                "NSExtensionPointIdentifier": "com.apple.ctk-tokens",
                "NSExtensionAttributes": {"com.apple.ctk.aid": "A000000063504B43532D3135",
                                          "com.apple.ctk.class-id": "org.dniemacos.dnietoken.token",
                                          "com.apple.ctk.driver-class": "DNIeTokenExtension.TokenDriver",
                                          "com.apple.ctk.token-type": "smartcard"}}:
            raise ReleaseError("Smart Card Token Extension metadata is unexpected.")
        binary_path = root / bundle / "Contents/MacOS" / executable
        arch = run(("/usr/bin/lipo", "-archs", binary_path), label="Executable architecture")
        if arch.strip() != TOOLCHAIN["architecture"]:
            raise ReleaseError("Payload executable architecture is unexpected.")
        build = run(("/usr/bin/vtool", "-show-build", binary_path), label="Mach-O deployment metadata")
        for key, value in (("platform", "MACOS"), ("minos", CONFIG["deployment"]),
                           ("sdk", TOOLCHAIN["macos_sdk"])):
            if re.findall(rf"^\s*{key}\s+(\S+)\s*$", build, re.M) != [value]:
                raise ReleaseError("Mach-O deployment metadata differs from the release configuration.")
        linked = run(("/usr/bin/otool", "-L", binary_path), label="Linked libraries").splitlines()[1:]
        if not linked or any(not line.strip().startswith(("/System/Library/Frameworks/", "/usr/lib/"))
                             for line in linked):
            raise ReleaseError("Executable has an unreviewed external library linkage.")
    resource_info = plist(root / RESOURCES / "Contents/Info.plist")
    if (resource_info.get("CFBundleIdentifier") != "dniecore.DNIeCore.resources"
            or "CFBundleExecutable" in resource_info):
        raise ReleaseError("Swift package resource bundle metadata is unexpected.")
    if fixture_hash is not None and contents[(ASSETS / "generation2.json").as_posix()]["sha256"] != fixture_hash:
        raise ReleaseError("Packaged credential bytes differ from the approved input.")
    return contents


def build_environment(work):
    cache_home = work / "cache-home"
    (cache_home / "Library/Caches").mkdir(parents=True)
    temporary = work / "tmp"
    temporary.mkdir()
    return {"CFFIXED_USER_HOME": str(cache_home), "TMPDIR": str(temporary),
            "CLANG_MODULE_CACHE_PATH": str(work / "clang-cache"),
            "SWIFTPM_MODULECACHE_OVERRIDE": str(work / "swift-cache")}


def stage_credential(source, work, data, env):
    # Copy only authorized bytes into the ephemeral input slot consumed by the existing stager.
    private_slot = source / CREDENTIAL_SOURCE
    private_slot.parent.mkdir(parents=True, mode=0o700)
    write_bytes(private_slot, data)
    command(("/bin/zsh", source / STAGE_SCRIPT), label="Credential staging", cwd=source, env=env)
    staged = source / CREDENTIAL_ASSET
    if read_private(staged) != data:
        raise ReleaseError("Staged credential bytes do not match the authorization input.")
    verifier = work / "main.swift"
    verifier.write_text(
        "import Foundation\n"
        "do {\n"
        "    let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))\n"
        "    _ = try CredentialFixtureVerifier.verifyGeneration2(data)\n"
        "} catch { exit(1) }\n"
    )
    executable = work / "validate-fixture"
    command(("/usr/bin/xcrun", "--sdk", "macosx", "swiftc", "-module-name", "DNIeFixtureValidation",
             "-target", "arm64-apple-macos26.0", "-o", executable, verifier,
             source / CREDENTIAL_CODE / "CredentialFixture.swift",
             source / "Packages/DNIeCore/Sources/DNIeCore/SecureChannel/CryptoPrimitives.swift"),
            label="Credential verifier build", cwd=source, env=env)
    command((executable, staged), label="Credential content verification", cwd=source, env=env)


def build_payload(root, identity, tree, work, credential_data=None):
    source = work / "source"
    export_source(root, identity["revision"], tree, source)
    env = build_environment(work)
    if credential_data is not None:
        stage_credential(source, work, credential_data, env)
    derived = work / "derived"
    command(("/usr/bin/xcodebuild", "-project", source / "DNIeToken.xcodeproj",
             "-scheme", "DNIeTokenHost", "-configuration", CONFIG["configuration"], "-sdk", "macosx",
             "-destination", "generic/platform=macOS", "-derivedDataPath", derived,
             "-packageCachePath", work / "package-cache", "-disableAutomaticPackageResolution",
             "-disablePackageRepositoryCache", "-skipPackageUpdates", "CODE_SIGNING_ALLOWED=NO",
             "CODE_SIGNING_REQUIRED=NO", "ARCHS=arm64", "ONLY_ACTIVE_ARCH=NO",
             "COMPILER_INDEX_STORE_ENABLE=NO", "GCC_GENERATE_DEBUGGING_SYMBOLS=NO", "build"),
            label="Unsigned Xcode build", cwd=source, env=env)
    payload = work / "payload"
    payload.mkdir()
    command(("/usr/bin/ditto", "--noqtn", derived / "Build/Products/Release" / HOST, payload / HOST),
            label="Payload staging")
    add_notices(source, payload, identity)
    normalize_unsigned_modes(payload, credential=credential_data is not None)
    return payload


def component_plist(path):
    components = [{
        "RootRelativeBundlePath": HOST.as_posix(),
        "BundleHasStrictIdentifier": True,
        "BundleIsRelocatable": False,
        "BundleIsVersionChecked": True,
        "BundleOverwriteAction": "upgrade",
        "ChildBundles": [{
            "RootRelativeBundlePath": EXTENSION.as_posix(),
            "BundleOverwriteAction": "",
            "ChildBundles": [{
                "RootRelativeBundlePath": RESOURCES.as_posix(),
                "BundleOverwriteAction": "",
            }],
        }],
    }]
    with path.open("wb") as stream:
        plistlib.dump(components, stream)

def package(payload, work, dest, installer=None):
    components = work / "components.plist"
    component_plist(components)
    sign_args = () if installer is None else ("--sign", installer, "--timestamp")
    command(("/usr/bin/pkgbuild", "--root", payload, "--component-plist", components,
             "--identifier", CONFIG["package_id"], "--version", PACKAGE_VERSION,
             "--install-location", CONFIG["install_location"], "--ownership", "recommended", *sign_args, dest),
            label="Flat component package creation")
    dest.chmod(0o600)


def check_package_metadata(expanded):
    if {path.name for path in expanded.iterdir()} != {"Bom", "PackageInfo", "Payload"}:
        raise ReleaseError("Package contains scripts or unexpected components.")
    try:
        info = ET.parse(expanded / "PackageInfo").getroot()
    except (OSError, ET.ParseError):
        raise ReleaseError("Package metadata could not be parsed.") from None
    expected_attrs = {"identifier": CONFIG["package_id"], "version": PACKAGE_VERSION,
                      "install-location": CONFIG["install_location"], "relocatable": "false",
                      "auth": "root", "postinstall-action": "none", "overwrite-permissions": "true",
                      "format-version": "2"}
    if (info.tag != "pkg-info" or info.attrib.keys() != expected_attrs.keys() | {"generator-version"}
            or not info.get("generator-version")
            or any(info.get(key) != value for key, value in expected_attrs.items())):
        raise ReleaseError("Package installation metadata is unexpected.")
    expected_nodes = {"payload", "bundle", "bundle-version", "upgrade-bundle", "strict-identifier",
                      "update-bundle", "atomic-update-bundle", "relocate"}
    if {node.tag for node in info} != expected_nodes or len(info) != len(expected_nodes) + 2:
        raise ReleaseError("Package includes unexpected installer metadata.")
    for tag in ("bundle-version", "upgrade-bundle", "strict-identifier"):
        nodes = info.findall(tag)
        if (len(nodes) != 1 or nodes[0].attrib or len(nodes[0]) != 1
                or nodes[0][0].tag != "bundle" or nodes[0][0].attrib != {"id": CONFIG["app_id"]}
                or len(nodes[0][0]) != 0):
            raise ReleaseError("Package bundle replacement policy is unexpected.")
    for tag in ("update-bundle", "atomic-update-bundle", "relocate"):
        nodes = info.findall(tag)
        if len(nodes) != 1 or nodes[0].attrib or len(nodes[0]) != 0:
            raise ReleaseError("Package update or relocation policy is unexpected.")
    version = {"CFBundleShortVersionString": CONFIG["version"], "CFBundleVersion": CONFIG["build"]}
    expected_bundles = {
        "./" + HOST.as_posix(): {"id": CONFIG["app_id"], **version},
        "./" + EXTENSION.as_posix(): {"id": CONFIG["extension_id"], **version},
        "./" + RESOURCES.as_posix(): {"id": "dniecore.DNIeCore.resources"},
    }
    actual = {}
    for bundle in info.findall("bundle"):
        attributes = dict(bundle.attrib)
        path = attributes.pop("path", None)
        if path in actual or len(bundle) != 0:
            raise ReleaseError("Package bundle membership is ambiguous.")
        actual[path] = attributes
    if actual != expected_bundles:
        raise ReleaseError("Package bundle identifiers or versions are unexpected.")
    summary = info.find("payload")
    if (summary.attrib.keys() != {"numberOfFiles", "installKBytes"} or len(summary) != 0
            or any(not re.fullmatch("[0-9]{1,8}", value) for value in summary.attrib.values())):
        raise ReleaseError("Package payload summary is malformed.")
    return int(summary.get("numberOfFiles"))


PROVENANCE_ATTRIBUTE = "com.apple.provenance"
# Pinned pkgbuild AppleDouble layout: empty FinderInfo and resource fork, one 11-byte attribute.
PROVENANCE_PREFIX = (
    struct.pack(">II16sHIIIIII", 0x51607, 0x20000, b"Mac OS X        ", 2, 9, 50, 113, 2, 163, 0)
    + bytes(34)
    + struct.pack(">8I2HIIHB", 0x41545452, 0, 163, 152, 11, 0, 0, 0, 0, 1, 152, 11, 0, 21)
    + PROVENANCE_ATTRIBUTE.encode() + b"\0"
)


def read_odc_record(stream):
    header = stream.read(76)
    if len(header) != 76 or header[:6] != b"070707" or not re.fullmatch(rb"[0-7]+", header[6:]):
        raise ReleaseError("Raw payload has an unsupported ODC archive record.")
    mode, uid, gid, links = (int(header[pos:pos + 6], 8) for pos in (18, 24, 30, 36))
    name_size, data_size = int(header[59:65], 8), int(header[65:76], 8)
    if not 1 < name_size <= 512 or data_size > 16 * 1024 * 1024:
        raise ReleaseError("Raw payload archive record exceeds its bounds.")
    name_bytes = stream.read(name_size)
    if len(name_bytes) != name_size or name_bytes[-1:] != b"\0" or b"\0" in name_bytes[:-1]:
        raise ReleaseError("Raw payload archive name is malformed.")
    try:
        name = name_bytes[:-1].decode("ascii")
    except UnicodeError:
        raise ReleaseError("Raw payload archive name is unsupported.") from None
    data = stream.read(data_size)
    if len(data) != data_size:
        raise ReleaseError("Raw payload archive record is truncated.")
    return name, mode, uid, gid, links, data


def check_raw_payload(payload, bom, layout, declared_count):
    modes = {f"./{name}": (stat.S_IFDIR if kind == "directory" else stat.S_IFREG)
             | int(expected_payload_mode(name, kind), 8) for name, kind in layout.items()}
    companions = {}
    for name in modes:
        path = PurePosixPath(name)
        companion = "./" + path.with_name("._" + path.name).as_posix()
        companions[companion] = name
    modes["."] = stat.S_IFDIR | 0o755

    archive_modes, digests, attrs = {}, {}, {}
    node_links, companion_links = {}, {}
    total = 0
    with gzip.open(payload, "rb") as stream:
        for _ in range(len(modes) + len(companions) + 1):
            name, mode, uid, gid, links, data = read_odc_record(stream)
            if name == "TRAILER!!!":
                padding = stream.read(513)
                if data or len(padding) > 512 or any(padding):
                    raise ReleaseError("Raw payload has unexpected archive trailer data.")
                break
            total += len(data)
            if total > 64 * 1024 * 1024 or name in archive_modes or uid != 0 or gid != 0:
                raise ReleaseError("Raw payload archive has invalid ownership, size or duplicate nodes.")
            if name in companions:
                counterpart = companions[name]
                if (mode != (stat.S_IFREG | 0o644) or links < 1
                        or len(data) != len(PROVENANCE_PREFIX) + 11
                        or not data.startswith(PROVENANCE_PREFIX)):
                    raise ReleaseError("Raw payload contains unsupported AppleDouble metadata.")
                archive_modes[name] = modes[counterpart]
                attrs[counterpart[2:]] = data[len(PROVENANCE_PREFIX):]
                companion_links[counterpart] = links
            elif name in modes and mode == modes[name]:
                archive_modes[name] = mode
                node_links[name] = links
                if stat.S_ISREG(mode):
                    if links != 1:
                        raise ReleaseError("Raw payload contains a hard-linked file.")
                    digests[name[2:]] = sha256(data)
                elif data:
                    raise ReleaseError("Raw payload directory record contains data.")
            else:
                raise ReleaseError("Raw payload contains an unexpected archive path or mode.")
        else:
            raise ReleaseError("Raw payload is missing its archive trailer.")
    if any(node_links.get(name) != links for name, links in companion_links.items()):
        raise ReleaseError("Raw AppleDouble link metadata differs from its counterpart.")
    if modes.keys() - archive_modes.keys() or len(archive_modes) != declared_count:
        raise ReleaseError("Raw payload differs from its reviewed paths or declared file count.")

    bom_modes = {}
    for row in bom.splitlines():
        fields = row.split("\t")
        if (len(fields) != 4 or fields[0] in bom_modes or fields[2:] != ["0", "0"]
                or not re.fullmatch("[0-7]+", fields[1])):
            raise ReleaseError("Installer BOM contains an invalid or duplicate entry.")
        bom_modes[fields[0]] = int(fields[1], 8)
    if bom_modes != archive_modes:
        raise ReleaseError("Installer BOM differs from the inspected raw payload.")
    return digests, attrs


def check_expanded_archive(root, contents, digests, attrs, run=command):
    if digests != {name: entry["sha256"] for name, entry in contents.items() if entry["type"] == "file"}:
        raise ReleaseError("Expanded file contents differ from the raw package payload.")
    for name in (".", *contents):
        path = root / name
        names = run(("/usr/bin/xattr", path), label="Expanded payload attribute names").splitlines()
        # pkgutil creates the extraction root locally. No archive companion is allowed for it.
        if name == "." and names == [PROVENANCE_ATTRIBUTE]:
            continue
        expected = [PROVENANCE_ATTRIBUTE] if name in attrs else []
        if names != expected:
            raise ReleaseError("Expanded payload has an unexpected extended attribute set.")
        if expected:
            value = run(("/usr/bin/xattr", "-px", PROVENANCE_ATTRIBUTE, path),
                        label="Expanded payload provenance")
            try:
                observed = bytes.fromhex(value)
            except ValueError:
                raise ReleaseError("Expanded provenance is malformed.") from None
            if observed != attrs[name]:
                raise ReleaseError("Expanded provenance differs from the raw archive metadata.")


def inspect_package(path, work, identity, *, fixture_hash=None, auth=None):
    if auth is not None:
        verify_installer_signature(path, auth)
    raw = work / "raw-package"
    command(("/usr/sbin/pkgutil", "--expand", path, raw), label="Raw component package expansion")
    declared_count = check_package_metadata(raw)
    bom = command(("/usr/bin/lsbom", "-p", "fmug", raw / "Bom"), label="Installer BOM inspection")
    layout = payload_paths(fixture_hash is not None, auth is not None)
    digests, attrs = check_raw_payload(raw / "Payload", bom, layout, declared_count)
    expanded = work / "expanded"
    command(("/usr/sbin/pkgutil", "--expand-full", path, expanded), label="Flat package expansion")
    check_package_metadata(expanded)
    contents = check_payload(expanded / "Payload", identity, fixture_hash=fixture_hash, signed=auth is not None)
    check_expanded_archive(expanded / "Payload", contents, digests, attrs)
    if auth is not None:
        verify_application_signature(expanded / "Payload", auth)
    return contents


def select_identity(listing, fingerprint, kind, team):
    matches = re.findall(r'^\s*\d+\) ([0-9A-F]{40}) "([^"\r\n]+)"\s*$', listing, re.M)
    candidates = [name for digest, name in matches if digest == fingerprint
                  and name.startswith(kind + ": ") and name.endswith(f" ({team})")]
    if len(candidates) != 1:
        raise ReleaseError("Required valid Developer ID identity does not match the authorized team and fingerprint.")
    name = candidates[0]
    if sum(other == name for _, other in matches) != 1:
        raise ReleaseError("Developer ID identity name is ambiguous in the local Keychain.")
    return name


def signing_identities(auth):
    listing = command(("/usr/bin/security", "find-identity", "-v", "-p", "codesigning"),
                      label="Developer ID Application identity lookup")
    select_identity(listing, auth["application_identity_sha1"], "Developer ID Application", auth["team_id"])
    installer_listing = command(("/usr/bin/security", "find-identity", "-v", "-p", "basic"),
                                label="Developer ID Installer identity lookup")
    installer = select_identity(installer_listing, auth["installer_identity_sha1"],
                                "Developer ID Installer", auth["team_id"])
    return auth["application_identity_sha1"], installer


def sign_application(payload, identity):
    # Explicit outside-in verification follows. The resource bundle has no executable.
    with tempfile.NamedTemporaryFile(dir=payload.parent, suffix=".plist") as entitlements:
        plistlib.dump({"com.apple.security.app-sandbox": True, "com.apple.security.smartcard": True},
                      entitlements)
        entitlements.flush()
        command(("/usr/bin/codesign", "--force", "--sign", identity, "--timestamp",
                 "--options", "runtime", "--entitlements", entitlements.name, payload / EXTENSION),
                label="Developer ID extension signing")
    command(("/usr/bin/codesign", "--force", "--sign", identity, "--timestamp",
             "--options", "runtime", payload / HOST), label="Developer ID host signing")


def verify_application_signature(payload, auth, run=command):
    run(("/usr/bin/codesign", "--verify", "--strict", "--deep", "--all-architectures", payload / HOST),
        label="Nested signature validation")
    for bundle in (HOST, EXTENSION):
        identifier = CONFIG["app_id"] if bundle == HOST else CONFIG["extension_id"]
        requirement = (f'=identifier "{identifier}" and anchor apple generic and '
                       'certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
                       'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
                       f'certificate leaf[subject.OU] = "{auth["team_id"]}" and '
                       f'certificate leaf = H"{auth["application_identity_sha1"]}"')
        run(("/usr/bin/codesign", "--verify", "--strict", "-R", requirement, payload / bundle),
            label="Developer ID signature policy")
        detail = run(("/usr/bin/codesign", "--display", "--verbose=4", payload / bundle),
                     label="Hardened runtime and secure timestamp inspection", stderr=True)
        if not re.search(r"^CodeDirectory .*\bflags=0x[0-9a-f]+\([^\n)]*\bruntime\b",
                         detail, re.M) or not re.search(r"^Timestamp=.+$", detail, re.M):
            raise ReleaseError("Code signature lacks hardened runtime or a secure timestamp.")
        data = run(("/usr/bin/codesign", "--display", "--xml", "--entitlements", "-", payload / bundle),
                   label="Signed entitlement extraction", binary=True)
        try:
            entitlements = plistlib.loads(data) if data else {}
        except (ValueError, plistlib.InvalidFileException):
            raise ReleaseError("Signed entitlements are malformed.") from None
        if not isinstance(entitlements, dict):
            raise ReleaseError("Signed entitlements are malformed.")
        check_entitlements(entitlements, extension=bundle == EXTENSION)


def verify_installer_signature(path, auth, run=command):
    status = run(("/usr/sbin/pkgutil", "--check-signature", path),
                 label="Developer ID Installer signature validation")
    cert = re.search(r"^\s*1\. Developer ID Installer: [^\n]+ \(([A-Z0-9]{10})\)\s*\n"
                     r"\s*SHA256 Fingerprint:\s*((?:[0-9A-F]{2}[ \n]+){31}[0-9A-F]{2})",
                     status, re.M)
    if (not cert or "signed by a developer certificate issued by Apple for distribution" not in status
            or not re.search(r"^ +Signed with a trusted timestamp on: +[^\s].*$", status, re.M)
            or cert.group(1) != auth["team_id"]
            or "".join(cert.group(2).split()).lower() != auth["installer_certificate_sha256"]):
        raise ReleaseError("Package signature has unexpected Developer ID Installer trust metadata.")


def submission_id(value):
    try:
        canonical_id = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ReleaseError("Notary service did not provide a valid submission ID.") from None
    if canonical_id != value:
        raise ReleaseError("Notary submission ID is noncanonical.")
    return canonical_id


def read_notary_state(path):
    state = decode_record(read_private(path), "Notary state")
    status = state.get("status")
    if (status not in ("upload-started", "uploaded", "accepted", "rejected")
            or not is_digest(state.get("sha256"))):
        raise ReleaseError("Notary state contains an invalid submission binding.")
    expected_keys = {"sha256", "status"}
    if status != "upload-started":
        expected_keys.add("id")
        submission_id(state.get("id"))
    if state.keys() != expected_keys:
        raise ReleaseError("Notary state has unexpected fields.")
    return state


def is_digest(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def notarize(output, artifact, profile, run=command, *, resume=False):
    state_path = output / NOTARY_STATE
    artifact_digest = private_artifact_hash(artifact)
    if state_path.exists() or state_path.is_symlink():
        state = read_notary_state(state_path)
        if state.get("sha256") != artifact_digest:
            raise ReleaseError("Submission package differs from the recorded upload.")
    else:
        if resume:
            raise ReleaseError("A recorded notary submission is required to resume.")
        # Persist intent before making the request. A transport failure may mean Apple already
        # received it. An unknown submission ID requires investigation; never blindly upload again.
        state = {"sha256": artifact_digest, "status": "upload-started"}
        write_record(state_path, state)
        response = decode_record(run(("/usr/bin/xcrun", "notarytool", "submit", artifact,
                                      "--keychain-profile", profile, "--output-format", "json"),
                                     label="Apple notarization upload"), "Notary upload response")
        state.update(id=submission_id(response.get("id")), status="uploaded")
        write_record(state_path, state)

    if state.get("status") == "upload-started":
        raise ReleaseError("Previous upload outcome is unknown. No automatic resubmission is allowed.")
    if state.get("status") not in ("uploaded", "accepted"):
        raise ReleaseError("Previous notarization is terminal. No automatic resubmission is allowed.")
    identifier = submission_id(state.get("id"))
    if state["status"] == "accepted":
        return identifier

    response = decode_record(run(("/usr/bin/xcrun", "notarytool", "wait", identifier,
                                  "--keychain-profile", profile, "--timeout", "30m",
                                  "--output-format", "json"), label="Apple notarization wait"),
                             "Notary result")
    if response.get("id") != identifier:
        raise ReleaseError("Notary result does not match the submitted ID.")
    status = response.get("status")
    if status == "Accepted":
        state["status"] = "accepted"
    elif status in ("Invalid", "Rejected"):
        state["status"] = "rejected"
    else:
        raise ReleaseError("Notarization is pending or returned an unknown status. Resume later.")
    write_record(state_path, state)
    if status != "Accepted":
        raise ReleaseError("Apple rejected the submission. No automatic resubmission is allowed.")
    return identifier


def private_artifact_hash(path):
    try:
        with open_regular(path, 0o600) as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(128 * 1024), b""):
                digest.update(chunk)
            return digest.hexdigest()
    except OSError:
        raise ReleaseError("Release artifact cannot be opened safely.") from None


def check_ticket(path):
    command(("/usr/bin/xcrun", "stapler", "validate", path), label="Stapled ticket verification")
    result = command(("/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=4", path),
                     label="Gatekeeper installation assessment", stderr=True)
    if not re.search(r"^source=Notarized Developer ID\s*$", result, re.M):
        raise ReleaseError("Gatekeeper did not identify a notarized Developer ID package.")


def diagnostic_build(root, identity, tree, output, repeat):
    with tempfile.TemporaryDirectory(prefix="dnie-unsigned-", dir="/private/tmp") as temp:
        work = Path(temp).resolve()
        first = work / "run-a"
        first.mkdir()
        payload = build_payload(root, identity, tree, first)
        built = check_payload(payload, identity)
        artifact = output / DIAGNOSTIC_PACKAGE
        package(payload, first, artifact)
        installed = inspect_package(artifact, first, identity)
        if first_difference(built, installed):
            raise ReleaseError("Installer payload differs from the unsigned build.")
        manifest = {"schema": 1, "kind": "credential-free-diagnostic",
                    "source": identity, "toolchain": TOOLCHAIN, "configuration": CONFIG,
                    "package_sha256": private_artifact_hash(artifact),
                    "payload_sha256": inventory_digest(installed),
                    "validation": {"credential": "absent", "build": "unsigned",
                                   "package": "inspected", "notarization": "not attempted",
                                   "runtime": "unverified", "repeatability": "not attempted"}}
        if repeat:
            # Swift 6.4.2 emits the absolute source-path length in a generated diagnostic
            # check even with debug information disabled. Keep run directory lengths equal.
            second = work / "run-b"
            second.mkdir()
            other = build_payload(root, identity, tree, second)
            comparison = check_payload(other, identity)
            difference = first_difference(built, comparison)
            manifest.update(second_payload_sha256=inventory_digest(comparison),
                            first_payload_difference=difference)
            manifest["validation"]["repeatability"] = "different" if difference else "identical"
            write_record(output / MANIFEST, manifest)
            if difference:
                raise ReleaseError(f"Unsigned payloads differ at {difference['path']} ({difference['field']}).")
        else:
            write_record(output / MANIFEST, manifest)


def start_release(root, identity, tree, output, auth, auth_digest, fixture):
    fixture_digest = auth["fixture_sha256"]
    app_identity, installer = signing_identities(auth)
    with tempfile.TemporaryDirectory(prefix="dnie-authorized-release-", dir="/private/tmp") as temp:
        work = Path(temp).resolve()
        first, second = work / "run-a", work / "run-b"
        first.mkdir()
        second.mkdir()
        payload = build_payload(root, identity, tree, first, fixture)
        unsigned = check_payload(payload, identity, fixture_hash=fixture_digest)
        other = build_payload(root, identity, tree, second, fixture)
        comparison = check_payload(other, identity, fixture_hash=fixture_digest)
        if difference := first_difference(unsigned, comparison):
            write_record(output / "repeatability-failure.json",
                         {"source": identity, "first_payload_difference": difference})
            raise ReleaseError(f"Unsigned release payloads differ at {difference['path']} ({difference['field']}).")
        sign_application(payload, app_identity)
        built = check_payload(payload, identity, fixture_hash=fixture_digest, signed=True)
        verify_application_signature(payload, auth)
        artifact = output / SUBMISSION
        package(payload, work, artifact, installer)
        packaged = inspect_package(artifact, work, identity, fixture_hash=fixture_digest, auth=auth)
        if first_difference(built, packaged):
            raise ReleaseError("Installer payload differs from the signed application.")
        # Bind resume to the privately approved scope and immutable upload artifact.
        write_record(output / "release-binding.json",
                     {"source": identity, "authorization_sha256": auth_digest,
                      "submission_sha256": private_artifact_hash(artifact),
                      "payload_sha256": inventory_digest(packaged),
                      "unsigned_payload_sha256": inventory_digest(unsigned)})


def load_binding(output, identity, auth_digest):
    binding = decode_record(read_private(output / "release-binding.json"), "Release binding")
    if binding.get("source") != identity or binding.get("authorization_sha256") != auth_digest:
        raise ReleaseError("Existing output is not bound to this source and approval.")
    digest_keys = {"submission_sha256", "payload_sha256", "unsigned_payload_sha256"}
    if "package_sha256" in binding:
        digest_keys.add("package_sha256")
    if (binding.keys() != digest_keys | {"source", "authorization_sha256"}
            or any(not is_digest(binding[key]) for key in digest_keys)):
        raise ReleaseError("Release binding contains malformed digest fields.")
    if private_artifact_hash(output / SUBMISSION) != binding["submission_sha256"]:
        raise ReleaseError("Signed package is no longer identical to the approved upload artifact.")
    return binding


def finalize_release(identity, output, auth, auth_digest, *, resume=False):
    binding = load_binding(output, identity, auth_digest)
    artifact = output / SUBMISSION
    # Require signature and exact contents again before a first upload or interrupted resume.
    with tempfile.TemporaryDirectory(prefix="dnie-release-preflight-", dir="/private/tmp") as temp:
        work = Path(temp).resolve()
        contents = inspect_package(artifact, work, identity, fixture_hash=auth["fixture_sha256"], auth=auth)
        if inventory_digest(contents) != binding.get("payload_sha256"):
            raise ReleaseError("Signed package payload differs from the inspected submission.")
    notarize(output, artifact, auth["notary_profile"], resume=resume)
    with tempfile.TemporaryDirectory(prefix=".staple-", dir=output) as temp:
        work = Path(temp).resolve()
        candidate = work / SIGNED_PACKAGE
        shutil.copyfile(artifact, candidate)
        candidate.chmod(0o600)
        command(("/usr/bin/xcrun", "stapler", "staple", candidate), label="Notary ticket stapling")
        check_ticket(candidate)
        contents = inspect_package(candidate, work, identity, fixture_hash=auth["fixture_sha256"], auth=auth)
        if inventory_digest(contents) != binding.get("payload_sha256"):
            raise ReleaseError("Stapled package payload differs from the inspected submission.")
        digest = private_artifact_hash(candidate)
        os.replace(candidate, output / SIGNED_PACKAGE)
    binding["package_sha256"] = digest
    write_record(output / "release-binding.json", binding)
    write_record(output / MANIFEST,
                 {"schema": 1, "kind": "developer-id-release",
                  "source": identity, "toolchain": TOOLCHAIN, "configuration": CONFIG,
                  "package_sha256": digest, "submission_sha256": binding["submission_sha256"],
                  "payload_sha256": binding["payload_sha256"],
                  "unsigned_payload_sha256": binding["unsigned_payload_sha256"],
                  "validation": {"credential": "verified", "build": "Developer ID",
                                 "package": "inspected", "notarization": "accepted",
                                 "stapled_ticket": "validated", "gatekeeper": "accepted",
                                 "runtime": "unverified", "repeatability": "identical"}})


def read_manifest(path, identity):
    manifest = decode_record(read_private(path), "Release manifest")
    if (manifest.get("source") != identity or manifest.get("configuration") != CONFIG
            or manifest.get("toolchain") != TOOLCHAIN or type(manifest.get("schema")) is not int
            or manifest["schema"] != 1):
        raise ReleaseError("Output manifest does not match the pinned source and configuration.")
    kind = manifest.get("kind")
    validation = manifest.get("validation")
    digests = {"package_sha256", "payload_sha256"}
    keys = {"schema", "kind", "source", "configuration", "toolchain", "validation"}
    if kind == "developer-id-release":
        digests |= {"submission_sha256", "unsigned_payload_sha256"}
        expected = {"credential": "verified", "build": "Developer ID", "package": "inspected",
                    "notarization": "accepted", "stapled_ticket": "validated", "gatekeeper": "accepted",
                    "runtime": "unverified", "repeatability": "identical"}
    elif kind == "credential-free-diagnostic":
        repeatability = validation.get("repeatability") if isinstance(validation, dict) else None
        if repeatability not in ("not attempted", "identical", "different"):
            raise ReleaseError("Diagnostic manifest repeatability status is invalid.")
        if repeatability != "not attempted":
            keys.add("first_payload_difference")
            digests.add("second_payload_sha256")
            difference = manifest.get("first_payload_difference")
            if repeatability == "identical":
                if difference is not None or manifest.get("payload_sha256") != manifest.get("second_payload_sha256"):
                    raise ReleaseError("Diagnostic repeatability record is inconsistent.")
            else:
                paths = payload_paths(False, False)
                if (not isinstance(difference, dict) or difference.keys() != {"path", "field"}
                        or not isinstance(difference["path"], str) or difference["path"] not in paths
                        or difference["field"] not in ("presence", "type", "mode", "sha256")
                        or manifest.get("payload_sha256") == manifest.get("second_payload_sha256")):
                    raise ReleaseError("Diagnostic repeatability record contains invalid evidence.")
        expected = {"credential": "absent", "build": "unsigned", "package": "inspected",
                    "notarization": "not attempted", "runtime": "unverified", "repeatability": repeatability}
    else:
        raise ReleaseError("Output manifest kind is unknown.")
    if (validation != expected or manifest.keys() != keys | digests
            or any(not is_digest(manifest[key]) for key in digests)):
        raise ReleaseError("Output manifest contains unexpected validation or digest fields.")
    return manifest


def verify_output(output, identity, args):
    manifest = read_manifest(output / MANIFEST, identity)
    auth = None
    fixture_hash = None
    if manifest.get("kind") == "credential-free-diagnostic":
        artifact = output / DIAGNOSTIC_PACKAGE
    elif manifest.get("kind") == "developer-id-release":
        auth = authorize(args.authorization, args.authorization_sha256, identity)
        fixture_hash = auth["fixture_sha256"]
        binding = load_binding(output, identity, args.authorization_sha256)
        state = read_notary_state(output / NOTARY_STATE)
        if (state.get("status") != "accepted" or state.get("sha256") != binding["submission_sha256"]
                or manifest.get("submission_sha256") != binding["submission_sha256"]):
            raise ReleaseError("Notarization acceptance is missing for this signed artifact.")
        submission_id(state.get("id"))
        if any(manifest.get(key) != binding.get(key) for key in ("payload_sha256", "package_sha256", "unsigned_payload_sha256")):
            raise ReleaseError("Final manifest differs from the inspected release binding.")
        artifact = output / SIGNED_PACKAGE
    else:
        raise ReleaseError("Output manifest kind is unknown.")
    if private_artifact_hash(artifact) != manifest.get("package_sha256"):
        raise ReleaseError("Package digest differs from the output manifest.")
    with tempfile.TemporaryDirectory(prefix="dnie-verify-", dir="/private/tmp") as temp:
        contents = inspect_package(artifact, Path(temp).resolve(), identity, fixture_hash=fixture_hash, auth=auth)
        if inventory_digest(contents) != manifest.get("payload_sha256"):
            raise ReleaseError("Package payload digest differs from the output manifest.")
    if auth is not None:
        check_ticket(artifact)
    if manifest["validation"]["repeatability"] == "different":
        raise ReleaseError("Diagnostic package checks pass, but unsigned build repeatability failed.")


HELP = """Release packaging
  make release-check          Check the exact checkout and pinned toolchain
  make release-unsigned       Build and inspect a credential-free diagnostic package
  make release-repeatability  Compare two clean unsigned payloads and record the first difference
  make release                Run the authorized Developer ID and notarization workflow
  make release-verify         Re-inspect an existing diagnostic or stapled package
  make release-test           Run offline packaging tests

Set DNIERELEASE_REVISION to the full current commit and DNIERELEASE_OUTPUT to a
canonical path outside the checkout. See Release/README.md for exact inputs.
"""


class ReleaseArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ReleaseError("Invalid release arguments. See the command help for accepted inputs.")


def arguments():
    parser = ReleaseArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("help", "check", "unsigned", "repeatability", "release", "verify"))
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--revision", default=os.getenv("DNIERELEASE_REVISION"))
    parser.add_argument("--output", type=Path, default=os.getenv("DNIERELEASE_OUTPUT"))
    parser.add_argument("--authorization", type=Path, default=os.getenv("DNIERELEASE_AUTHORIZATION"))
    parser.add_argument("--authorization-sha256", default=os.getenv("DNIERELEASE_AUTHORIZATION_SHA256"))
    parser.add_argument("--fixture", type=Path, default=os.getenv("DNIERELEASE_FIXTURE"))
    parser.add_argument("--resume", action="store_true", default=os.getenv("DNIERELEASE_RESUME") == "1")
    return parser.parse_args()


def interrupt(_signal, _frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, interrupt)
    args = arguments()
    if args.operation == "help":
        print(HELP.rstrip())
        return
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise ReleaseError("Run on macOS as the invoking user without sudo.")
    os.umask(0o022)
    root = canonical(args.source)
    identity = source_identity(root, args.revision)
    tree = source_tree(root, identity["revision"])
    check_running_program(root, identity["revision"])
    check_toolchain()
    if args.operation == "check":
        print(json.dumps({"source": identity, "toolchain": TOOLCHAIN, "configuration": CONFIG}, indent=2))
        return
    if args.output is None:
        raise ReleaseError("Provide an output path outside the source checkout.")
    output = canonical(args.output)
    if output == root or root in output.parents:
        raise ReleaseError("Output must be outside the source checkout.")
    validate_output_parent(output)
    existing = args.operation == "verify" or (args.operation == "release" and args.resume)
    auth, fixture = None, None
    if args.operation == "release":
        auth = authorize(args.authorization, args.authorization_sha256, identity)
        if not args.resume:
            if args.fixture is None:
                raise ReleaseError("Provide the externally authorized credential input file.")
            fixture = read_private(args.fixture)
            if sha256(fixture) != auth["fixture_sha256"]:
                raise ReleaseError("Authorized credential input digest does not match.")
    if not existing:
        try:
            output.mkdir(mode=0o700)
        except FileExistsError:
            raise ReleaseError("Output already exists. Choose a new path or explicitly resume an existing release.") from None
    info = output.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ReleaseError("Output directory must be unlinked, owner-controlled and mode 0700.")
    lock_fd = os.open(output / ".lock", os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    try:
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1
                or lock_info.st_uid != os.getuid() or stat.S_IMODE(lock_info.st_mode) != 0o600):
            raise ReleaseError("Output lock must be owned by the invoking user, mode 0600 and unlinked.")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.operation in ("unsigned", "repeatability"):
            diagnostic_build(root, identity, tree, output, args.operation == "repeatability")
        elif args.operation == "verify":
            verify_output(output, identity, args)
        else:
            if not args.resume:
                start_release(root, identity, tree, output, auth, args.authorization_sha256, fixture)
            finalize_release(identity, output, auth, args.authorization_sha256, resume=args.resume)
    finally:
        os.close(lock_fd)
    print("Release step completed. See the output manifest for verified results.")


if __name__ == "__main__":
    try:
        main()
    except ReleaseError as error:
        print(f"Release stopped. {error}", file=sys.stderr)
        sys.exit(1)
    except BlockingIOError:
        print("Release stopped. Another process owns the output directory lock.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Release stopped. A local file or metadata input could not be processed safely.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Release interrupted. A recorded upload can be resumed with the same inputs.", file=sys.stderr)
        sys.exit(130)
