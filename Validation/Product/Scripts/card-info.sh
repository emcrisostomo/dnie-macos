#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
exec /usr/bin/python3 -I -B - "${script_dir:h:h:h}" "$@" <<'PY'
import os
import pathlib
import plistlib
import re
import runpy
import signal
import stat
import subprocess
import sys

XCRUN = "/usr/bin/xcrun"
CODESIGN = "/usr/bin/codesign"
SCRATCH_ROOT = "/private/tmp"
BUILD_TIMEOUT = 120
SIGN_TIMEOUT = 10
RUNTIME_TIMEOUT = 10

REPORT = re.compile(
    rb"reader_count=(?:unknown|[0-9]{1,2})\n"
    rb"valid_card_count=(?:unknown|[0-9]{1,2})\n"
    rb"card=(?:no_reader|empty|probing|unresponsive_or_unknown|responsive|inventory_unavailable|inventory_changed)\n"
    rb"dnie_publication=(?:not_checked|observed|not_observed|indeterminate)\n"
    rb"authentication=(?:not_checked|visible|not_observed|indeterminate)\n"
    rb"signature=(?:not_checked|visible|not_observed|indeterminate)\n"
)


class CardInfoError(Exception):
    pass


def fail(category, status=1):
    print(f"card_info_error={category}", file=sys.stderr)
    return status


def run(command, timeout, category, *, workspace, accepted=(0,), capture=False):
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
            env={**os.environ, "TMPDIR": str(workspace)},
        )
    except OSError:
        raise CardInfoError(category)
    try:
        output, _ = process.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        # Each child starts its own process group. Terminate that group only.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if isinstance(error, subprocess.TimeoutExpired):
            raise CardInfoError("timeout")
        raise
    if process.returncode not in accepted:
        raise CardInfoError(category)
    return process.returncode, output


def build(source, workspace):
    binary = workspace / "card-info"
    entitlement = source / "CardInfo.entitlements"
    run([
        XCRUN, "--sdk", "macosx", "swiftc", "-swift-version", "6", "-parse-as-library",
        "-module-cache-path", str(workspace / "modules"),
        "-framework", "Foundation", "-framework", "CryptoTokenKit",
        "-framework", "Security", "-framework", "LocalAuthentication",
        str(source / "CardInfoSnapshot.swift"), str(source / "CardInfo.swift"), "-o", str(binary),
    ], BUILD_TIMEOUT, "build", workspace=workspace)
    run([CODESIGN, "--sign", "-", "--entitlements", str(entitlement), str(binary)],
        SIGN_TIMEOUT, "sign", workspace=workspace)
    run([CODESIGN, "--verify", "--strict", str(binary)],
        SIGN_TIMEOUT, "signature", workspace=workspace)
    # The colon requests XML; the plain dash prints a human-readable listing.
    _, raw = run(
        [CODESIGN, "--display", "--entitlements", ":-", str(binary)],
        SIGN_TIMEOUT, "entitlements", workspace=workspace, capture=True,
    )
    try:
        entitlements = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError):
        raise CardInfoError("entitlements")
    if not (isinstance(entitlements, dict) and len(entitlements) == 1
            and entitlements.get("com.apple.security.smartcard") is True):
        raise CardInfoError("entitlements")
    return binary


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main():
    args = sys.argv[2:]
    if args not in ([], ["--build-only"]):
        return fail("usage", 64)
    if os.geteuid() == 0:
        return fail("root")
    signal.signal(signal.SIGHUP, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    os.umask(0o077)
    repo = pathlib.Path(sys.argv[1])
    try:
        release = runpy.run_path(str(repo / "Release/release.py"))
    except (OSError, ImportError):
        return fail("scratch")
    try:
        with release["private_work_directory"]("dnie-card-info.", parent=pathlib.Path(SCRATCH_ROOT)) as workspace:
            # Reopen through the audited FD/ACL helper and bind the path used
            # for child output to the checked directory before spawning.
            descriptor = release["open_safe_directory"](workspace)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o700
                        or not os.path.samestat(opened, workspace.lstat())):
                    raise CardInfoError("scratch")
            finally:
                os.close(descriptor)
            binary = build(repo / "Tools/DNIeCardInfo", workspace)
            if args:
                print("card_info_build=pass")
                return 0
            status, output = run(
                [str(binary)], RUNTIME_TIMEOUT, "runtime", workspace=workspace,
                accepted=(0, 1), capture=True,
            )
            if REPORT.fullmatch(output) is None:
                raise CardInfoError("runtime")
            sys.stdout.buffer.write(output)
            return status
    except CardInfoError as error:
        return fail(error.args[0])
    except KeyboardInterrupt:
        return fail("interrupted")
    except (OSError, release["ReleaseError"]):
        return fail("scratch")


sys.exit(main())
PY
