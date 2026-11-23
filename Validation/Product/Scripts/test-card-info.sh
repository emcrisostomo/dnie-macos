#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
exec /usr/bin/python3 -I -B - "${script_dir:h:h:h}" <<'PYTHON'
import os
import pathlib
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
from textwrap import dedent


def tests(root, repo):
    source_dir = repo / "Tools/DNIeCardInfo"
    test_binary = root / "snapshot-tests"
    subprocess.run([
        "/usr/bin/xcrun", "--sdk", "macosx", "swiftc",
        "-swift-version", "6", "-parse-as-library", "-D", "CARD_INFO_TESTING",
        "-module-cache-path", str(root / "modules"),
        str(source_dir / "CardInfoSnapshot.swift"), str(source_dir / "CardInfo.swift"),
        str(source_dir / "CardInfoTests.swift"), "-o", str(test_binary),
    ], check=True, timeout=120, stdin=subprocess.DEVNULL)
    subprocess.run([str(test_binary)], check=True, timeout=10, stdin=subprocess.DEVNULL)
    source = (repo / "Validation/Product/Scripts/card-info.sh").read_text()
    fixture = root / "fixture"
    wrapper = fixture / "Validation/Product/Scripts/card-info.sh"
    wrapper.parent.mkdir(parents=True)
    (fixture / "Release").mkdir()
    shutil.copyfile(repo / "Release/release.py",
                    fixture / "Release/release.py")
    scratch = root / "wrapper-scratch"
    scratch.mkdir()
    compiler = root / "compiler"
    signer = root / "signer"
    result = root / "result"
    transcript = root / "transcript"
    entitlements = root / "entitlements"

    def fixture_tool(path, script):
        python = shlex.quote(sys.executable)
        path.write_text(f'#!/bin/sh\nexec {python} -I -B -c {shlex.quote(dedent(script))} "$@"\n')
        path.chmod(0o700)

    fixture_tool(compiler, f"""
    import os, pathlib, stat, sys
    if sys.argv[1:4] != ['--sdk', 'macosx', 'swiftc'] or '-module-cache-path' not in sys.argv:
        sys.exit(1)
    out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
    modules = pathlib.Path(sys.argv[sys.argv.index('-module-cache-path') + 1])
    if stat.S_IMODE(out.parent.stat().st_mode) != 0o700 or modules.parent != out.parent:
        sys.exit(1)
    if pathlib.Path(os.environ.get('TMPDIR', '')) != out.parent:
        sys.exit(1)
    out.write_bytes(pathlib.Path({str(result)!r}).read_bytes())
    out.chmod(0o700)
    with pathlib.Path({str(transcript)!r}).open('a') as log:
        log.write('compile\\n')
    """)
    fixture_tool(signer, f"""
    import os, pathlib, sys
    if pathlib.Path(os.environ.get('TMPDIR', '')) != pathlib.Path(sys.argv[-1]).parent:
        sys.exit(1)
    with pathlib.Path({str(transcript)!r}).open('a') as log:
        log.write(sys.argv[1] + '\\n')
    if sys.argv[1] == '--display':
        if sys.argv[2:4] != ['--entitlements', ':-']:
            sys.exit(1)
        sys.stdout.buffer.write(pathlib.Path({str(entitlements)!r}).read_bytes())
    elif sys.argv[1] == '--sign' and sys.argv[2] != '-':
        sys.exit(1)
    elif sys.argv[1] == '--verify' and '--strict' not in sys.argv:
        sys.exit(1)
    """)
    for literal, replacement in [
        ('/usr/bin/python3 -I -B -', f'{shlex.quote(sys.executable)} -I -B -'),
        ('"/usr/bin/xcrun"', repr(str(compiler))),
        ('"/usr/bin/codesign"', repr(str(signer))),
        ('SCRATCH_ROOT = "/private/tmp"', f'SCRATCH_ROOT = {str(scratch)!r}'),
        ('RUNTIME_TIMEOUT = 10', "RUNTIME_TIMEOUT = 0.25"),
    ]:
        assert source.count(literal) == 1, literal
        source = source.replace(literal, replacement)
    wrapper.write_text(source)
    wrapper.chmod(0o700)
    good_plist = b'<plist version="1.0"><dict><key>com.apple.security.smartcard</key><true/></dict></plist>'
    entitlements.write_bytes(good_plist)
    expected = (
        "reader_count=0\nvalid_card_count=0\ncard=no_reader\n"
        "dnie_publication=not_checked\nauthentication=not_checked\nsignature=not_checked\n"
    )

    inherited = root / "unused-inherited-temp"
    inherited.mkdir()

    def check(args, program, status, output="", error="", expect_build=True):
        result.write_text('#!/bin/sh\n[ "$TMPDIR" = "${0%/*}" ] || exit 88\n' + program)
        transcript.unlink(missing_ok=True)
        completed = subprocess.run([str(wrapper), *args], capture_output=True, text=True, timeout=7,
                                   env={**os.environ, "TMPDIR": str(inherited)})
        assert completed.returncode == status, (completed.returncode, completed.stderr)
        assert completed.stdout == output, completed.stdout
        assert completed.stderr == error, completed.stderr
        assert not list(scratch.iterdir()), "wrapper retained generated files"
        assert not list(inherited.iterdir()), "inherited temporary directory received output"
        if status != 64 and expect_build:
            assert transcript.read_text() == "compile\n--sign\n--verify\n--display\n"
        else:
            assert not transcript.exists(), "rejected invocation reached build"

    check(["invalid"], "", 64, error="card_info_error=usage\n")
    check(["--build-only"], "exit 99\n", 0, "card_info_build=pass\n")
    check([], f"printf '%s' '{expected}'\n", 0, expected)
    check([], f"printf '%s' '{expected}reader_name=PRIVATE_READER\n'\n", 1,
          error="card_info_error=runtime\n")
    check([], "echo PRIVATE_CHILD_ERROR >&2\nexit 70\n", 1, error="card_info_error=runtime\n")
    check([], "echo PRIVATE_CHILD_OUTPUT\n/bin/sleep 5\n", 1, error="card_info_error=timeout\n")
    entitlements.write_bytes(good_plist.replace(b"<true/>", b"<integer>1</integer>"))
    check([], "exit 90\n", 1, error="card_info_error=entitlements\n")
    entitlements.write_bytes(good_plist)
    acl = "everyone allow list,search,file_inherit,directory_inherit"
    subprocess.run(["/bin/chmod", "+a", acl, str(scratch)], check=True)
    try:
        inheriting_child = scratch / "inherits_acl"
        inheriting_child.mkdir(mode=0o700)
        observed_acl = subprocess.run(["/bin/ls", "-lde", str(inheriting_child)],
                                      check=True, capture_output=True, text=True).stdout
        assert "inherited" in observed_acl and "allow" in observed_acl
        inheriting_child.rmdir()
        check(["--build-only"], "exit 89\n", 1, error="card_info_error=scratch\n", expect_build=False)
    finally:
        subprocess.run(["/bin/chmod", "-a", acl, str(scratch)], check=True)
    print("card_info_wrapper_tests=pass")


def main():
    if os.geteuid() == 0:
        return 1
    os.umask(0o077)
    repo = pathlib.Path(sys.argv[1])
    release = runpy.run_path(str(repo / "Release/release.py"))
    with release["private_work_directory"]("dnie-card-info-tests.", parent=pathlib.Path("/private/tmp")) as workspace:
        descriptor = release["open_safe_directory"](workspace)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o700
                    or not os.path.samestat(opened, workspace.lstat())):
                raise release["ReleaseError"]("Card-info test workspace changed.")
        finally:
            os.close(descriptor)
        os.environ["TMPDIR"] = str(workspace)
        tests(workspace, repo)
    return 0


sys.exit(main())
PYTHON
