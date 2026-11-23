#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
repository_root="${script_dir:h:h:h}"
fixture_root="$(mktemp -d /private/tmp/dnie-clean-development-test.XXXXXX)"
cleanup() {
  for process in "${hold_pid:-}" "${build_pid:-}" "${build_child:-}"; do
    if [[ -n "${process}" ]]; then
      kill "${process}" 2>/dev/null || true
      wait "${process}" 2>/dev/null || true
    fi
  done
  rm -rf -- "${fixture_root}"
}
trap cleanup EXIT
fixture_repository="${fixture_root}/repository"
fixture_bin="${fixture_root}/bin"
derived_data="${fixture_repository}/DerivedData"
slot="${derived_data}/T067"
mkdir -p "${slot}/Build/Products/Release/DNIeTokenHost.app" \
  "${derived_data}/T083CleanIncremental" "${fixture_bin}" \
  "${fixture_repository}/Validation/private" "${fixture_repository}/Packages"
touch "${slot}/Build/Products/Release/DNIeTokenHost.app/build-output" \
  "${fixture_repository}/Validation/private/credential-input" \
  "${fixture_repository}/Packages/staged-input" "${fixture_root}/installed-app" \
  "${derived_data}/T083CleanIncremental/other-output"
print -rl -- '#!/bin/zsh' 'exit 0' > "${fixture_bin}/pluginkit"
chmod 700 "${fixture_bin}/pluginkit"

clean_fixture() {
  env -u DNIE_DEVELOPMENT_BUILD_SLOT DNIE_WORKFLOW_TEST_MODE=1 DNIE_WORKFLOW_REPOSITORY_ROOT="${fixture_repository}" \
    DNIE_WORKFLOW_BIN_DIR="${fixture_bin}" \
    "$@" /usr/bin/make -s -f "${repository_root}/Makefile" clean
}

clean_fixture
[[ ! -e "${slot}" && -f "${derived_data}/T083CleanIncremental/other-output" &&
   -f "${fixture_repository}/Validation/private/credential-input" &&
   -f "${fixture_repository}/Packages/staged-input" && -f "${fixture_root}/installed-app" ]]
clean_fixture


clean_fixture DNIE_DEVELOPMENT_BUILD_SLOT=T083CleanIncremental
[[ ! -e "${derived_data}/T083CleanIncremental" ]]
mkdir -p "${derived_data}/T083Upgrade"
clean_fixture DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade
[[ ! -e "${derived_data}/T083Upgrade" ]]

refuses() {
  local reason="$1"
  shift
  if "$@" >"${fixture_root}/failure-out" 2>"${fixture_root}/failure-err"; then
    print -u2 -- "Unexpected clean acceptance: ${reason}"
    exit 1
  fi
  /usr/bin/grep -q -- "${reason}" "${fixture_root}/failure-err"
}

refuses 'must be T067' clean_fixture DNIE_DEVELOPMENT_BUILD_SLOT=../T067
refuses 'must be T067' clean_fixture DNIE_DEVELOPMENT_BUILD_SLOT=
mkdir "${slot}"
touch "${slot}/preserve"
ln -s "${fixture_root}/installed-app" "${slot}/link"
refuses 'link or unsupported file type' clean_fixture
[[ -L "${slot}/link" && -f "${slot}/preserve" ]]
rm "${slot}/link"

ln "${slot}/preserve" "${fixture_root}/outside-link"
refuses 'link or unsupported file type' clean_fixture
[[ -f "${fixture_root}/outside-link" && -f "${slot}/preserve" ]]
rm "${fixture_root}/outside-link"

mkfifo "${slot}/fifo"
refuses 'unsupported file type' clean_fixture
[[ -p "${slot}/fifo" && -f "${slot}/preserve" ]]
rm "${slot}/fifo"

chmod 0777 "${slot}"
refuses 'unsafe owner, mode' clean_fixture
[[ -f "${slot}/preserve" ]]
chmod 0755 "${slot}"

chmod +a 'everyone allow write' "${slot}/preserve"
refuses 'extended ACL' clean_fixture
[[ -f "${slot}/preserve" ]]
chmod -N "${slot}/preserve"

chflags uchg "${slot}/preserve"
refuses 'unsafe owner, mode, flag' clean_fixture
chflags nouchg "${slot}/preserve"

exec {fixture_lock}<"${fixture_repository}"
cleanup_tool="${script_dir}/clean-development.py"
fixture_helper() {
  /usr/bin/python3 -B "${cleanup_tool}" --fixture "${fixture_repository}" "${fixture_bin}" "$@"
}
fixture_helper --lock "${fixture_lock}"
refuses 'already running' clean_fixture
[[ -f "${slot}/preserve" ]]
for route in install uninstall; do
  refuses 'already running' env DNIE_WORKFLOW_TEST_MODE=1 \
    DNIE_WORKFLOW_REPOSITORY_ROOT="${fixture_repository}" \
    DNIE_WORKFLOW_BIN_DIR="${fixture_bin}" "${script_dir}/developer-workflow.sh" "${route}"
done
exec {fixture_lock}<&-

# Decline a foreign owner or filesystem without mounting a volume or changing
# any file ownership in this normal-user test.
 /usr/bin/python3 -B - "${cleanup_tool}" "${slot}/preserve" <<'PYTHON'
import os
import runpy
from types import SimpleNamespace
import sys

script = runpy.run_path(sys.argv[1])
validate = script["validate_slot_entry"]
info = os.stat(sys.argv[2])
for owner, device in ((os.geteuid() + 1, info.st_dev), (os.geteuid(), info.st_dev + 1)):
    simulated = SimpleNamespace(st_uid=owner, st_dev=device, st_mode=info.st_mode,
                                st_flags=info.st_flags, st_nlink=info.st_nlink)
    try:
        validate(simulated, info.st_dev, directory=False)
    except script["CleanError"]:
        continue
    raise SystemExit("Clean accepted a foreign owner or filesystem.")
PYTHON

/usr/bin/python3 -B -c 'import sys,time; f=open(sys.argv[1]); open(sys.argv[2], "x").close(); time.sleep(30)' \
  "${slot}/preserve" "${fixture_root}/file-open" &
hold_pid=$!
for _ in {1..100}; do
  [[ -f "${fixture_root}/file-open" ]] && break
  /bin/sleep 0.05
done
[[ -f "${fixture_root}/file-open" ]]
refuses 'process is using' clean_fixture
kill "${hold_pid}"
wait "${hold_pid}" 2>/dev/null || true
hold_pid=""

printf '#!/bin/zsh\nprint -rl -- %q %q\n' \
  '- org.dniemacos.dnietoken.tokenextension (0.1.1)' "    Path = ${slot}/registered.appex" \
  > "${fixture_bin}/pluginkit"
# The status prefix is disabled, but the row still retains an explicit path.
refuses 'still refers to' clean_fixture
[[ -f "${slot}/preserve" ]]

print -rl -- '#!/bin/zsh' 'exit 99' > "${fixture_bin}/pluginkit"
refuses 'Unable to inspect PlugInKit' clean_fixture
[[ -f "${slot}/preserve" ]]

printf '#!/bin/zsh\n/bin/mv %q %q\n/bin/mkdir %q\n/usr/bin/touch %q\n' \
  "${slot}" "${fixture_root}/relocated-slot" "${slot}" "${slot}/replacement" > "${fixture_bin}/pluginkit"
refuses 'changed' clean_fixture
[[ -f "${slot}/replacement" && -f "${fixture_root}/relocated-slot/preserve" ]]
print -rl -- '#!/bin/zsh' 'exit 0' > "${fixture_bin}/pluginkit"
clean_fixture

ln -s "${fixture_root}/relocated-slot" "${slot}"
refuses 'not a modifiable, unlinked directory' clean_fixture
[[ -L "${slot}" && -f "${fixture_root}/relocated-slot/preserve" ]]
rm "${slot}"

# Root lifecycle visibility is simulated locally. Real ad-hoc signatures prove
# the copying and strict reinspection boundary without Apple keys or card data.
/usr/bin/git -C "${fixture_repository}" init --quiet
print 'Validation/private/' > "${fixture_repository}/.gitignore"
mkdir "${fixture_root}/fixture-lifecycle"
app="${slot}/Build/Products/Release/DNIeTokenHost.app"
mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
/bin/cp /usr/bin/true "${app}/Contents/MacOS/DNIeTokenHost"
print -r -- 'local fixture bytes' > "${app}/Contents/Resources/payload"
cat > "${app}/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>org.dniemacos.clean-fixture</string>
  <key>CFBundleExecutable</key><string>DNIeTokenHost</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
</dict>
</plist>
PLIST
/usr/bin/codesign --force --sign - "${app}" >/dev/null 2>&1
cat > "${fixture_bin}/artifact-inspector" <<'INSPECT'
#!/bin/zsh
set -euo pipefail
/usr/bin/codesign --verify --deep --strict "$1" >/dev/null 2>&1
/usr/bin/codesign --display --verbose=4 "$1" 2>&1 | /usr/bin/sed -n 's/^CDHash=/artifact_cdhash=/p'
INSPECT
chmod 0700 "${fixture_bin}/artifact-inspector"
expected="$("${fixture_bin}/artifact-inspector" "${app}")"
expected="${expected#artifact_cdhash=}"
[[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]]
cache="${fixture_repository}/Validation/private/DevelopmentRecovery"
archived="${cache}/${expected}/DNIeTokenHost.app"

clean_fixture | /usr/bin/grep -q '^development_recovery_source=retained$'
[[ ! -e "${slot}" && -f "${archived}/Contents/Resources/payload" ]]
[[ "$(/usr/bin/stat -f %Lp "${cache}")" == 700 && "$(/usr/bin/stat -f %Lp "${cache}/${expected}")" == 700 ]]
[[ "$("${fixture_bin}/artifact-inspector" "${archived}")" == "artifact_cdhash=${expected}" ]]
/usr/bin/grep -qx 'local fixture bytes' "${archived}/Contents/Resources/payload"

run_locked() {
  local descriptor
  exec {descriptor}<"${fixture_repository}"
  local result=0
  fixture_helper "$1" "${descriptor}" "$2" || result=$?
  exec {descriptor}<&-
  return "${result}"
}
wrong=0000000000000000000000000000000000000000
refuses 'No complete exact signed app' run_locked --restore "${wrong}"
run_locked --restore "${expected}" | /usr/bin/grep -q '^development_recovery_source=restored$'
[[ "$("${fixture_bin}/artifact-inspector" "${app}")" == "artifact_cdhash=${expected}" ]]
refuses 'already occupies' run_locked --restore "${expected}"
[[ "$("${fixture_bin}/artifact-inspector" "${app}")" == "artifact_cdhash=${expected}" ]]

# Refuse deletion if an existing expected archive is a collision.
mv "${cache}/${expected}" "${cache}/saved-archive"
mkdir -m 700 "${cache}/${expected}"
refuses 'contains unrelated data' clean_fixture
[[ -f "${app}/Contents/Resources/payload" ]]
rmdir "${cache}/${expected}"
mv "${cache}/saved-archive" "${cache}/${expected}"
clean_fixture
[[ ! -e "${slot}" && -f "${archived}/Contents/Resources/payload" ]]
refuses 'original source is missing' run_locked --prune "${expected}"
[[ -f "${archived}/Contents/Resources/payload" ]]

mkdir "${cache}/${wrong}"
touch "${cache}/${wrong}/unrelated"
cat > "${fixture_bin}/pluginkit" <<'PLUGINKIT'
#!/bin/zsh
set -euo pipefail
case "$1" in
  -m)
    if [[ -f "${CLEAN_TEST_REGISTRATION}" ]]; then
      print -rl -- '+ org.dniemacos.dnietoken.tokenextension (0.1.1)' "    Path = ${CLEAN_TEST_EXTENSION}"
    fi
    ;;
  -a)
    [[ "$2" == "${CLEAN_TEST_EXTENSION}" ]]
    /usr/bin/touch "${CLEAN_TEST_REGISTRATION}"
    ;;
  *) exit 99 ;;
esac
PLUGINKIT
print -rl -- '#!/bin/zsh' 'exit 1' > "${fixture_bin}/pgrep"
chmod 700 "${fixture_bin}/pgrep"
workflow="${script_dir}/developer-workflow.sh"
env DNIE_WORKFLOW_TEST_MODE=1 DNIE_WORKFLOW_REPOSITORY_ROOT="${fixture_repository}" \
  DNIE_WORKFLOW_BIN_DIR="${fixture_bin}" DNIE_WORKFLOW_DESTINATION_APP="${fixture_root}/unused-destination.app" \
  DNIE_WORKFLOW_ARTIFACT_INSPECTOR="${fixture_bin}/artifact-inspector" \
  CLEAN_TEST_REGISTRATION="${fixture_root}/fixture-registration" \
  CLEAN_TEST_EXTENSION="${app}/Contents/PlugIns/DNIeTokenExtension.appex" \
  "${workflow}" finish-source-restoration "${expected}" >"${fixture_root}/restore-out"
/usr/bin/grep -q '^development_source_registration_restoration=pass$' "${fixture_root}/restore-out"
/usr/bin/grep -q '^development_recovery_source=disposed$' "${fixture_root}/restore-out"
[[ ! -e "${cache}/${expected}" && -f "${cache}/${wrong}/unrelated" &&
   -f "${fixture_root}/fixture-registration" ]]
[[ "$("${fixture_bin}/artifact-inspector" "${app}")" == "artifact_cdhash=${expected}" ]]
print -rl -- '#!/bin/zsh' 'exit 0' > "${fixture_bin}/pluginkit"

# The production signature inspector must be bypassed for output missing a
# required executable. The test app has a host executable but no extension.
/usr/bin/python3 -B - "${cleanup_tool}" "${fixture_repository}" <<'PYTHON'
from contextlib import ExitStack
from pathlib import Path
import runpy
import sys

support = runpy.run_path(sys.argv[1])
recovery = runpy.run_path(str(Path(sys.argv[1]).with_name("development-recovery.py")))
root = Path(sys.argv[2])
with ExitStack() as stack:
    slot = support["BuildSlot"](root, "T067", lambda fd: None, lambda fd: None)
    root_fd = slot.open_root(stack)
    source = ("DerivedData", "T067", *support["SOURCE_HOST"])
    app_fd = slot.open_directories(stack, root_fd, source)
    assert recovery["preserve"](
        slot, stack, app_fd, root.joinpath(*source), root_fd, Path("inspect-pilot-artifact.sh"),
    ) is False
PYTHON

# A deliberately interrupted wrapper must leave the actual writing process
# holding the lock. Only the exact test-owned wrapper PID is killed.
copied_scripts="${fixture_repository}/Validation/Product/Scripts"
mkdir -p "${copied_scripts}" "${fixture_repository}/Release" "${fixture_repository}/Validation/Scripts"
for name in build-development.sh clean-development.py development-recovery.py; do
  cp "${script_dir}/${name}" "${copied_scripts}/${name}"
done
cp "${repository_root}/Release/release.py" "${fixture_repository}/Release/"
print 'Packages/' >>"${fixture_repository}/.gitignore"
print -rl -- '#!/bin/zsh' 'exit 0' > "${fixture_repository}/Validation/Scripts/stage-production-credential-asset.sh"
chmod 700 "${fixture_repository}/Validation/Scripts/stage-production-credential-asset.sh"
print -rl -- '#!/bin/zsh' \
  'print "1) 0123456789ABCDEF0123456789ABCDEF01234567 Apple Development: synthetic"' > "${fixture_bin}/security"
cat > "${fixture_bin}/mktemp" <<'STUB'
#!/bin/zsh
exec /usr/bin/mktemp "${CLEAN_TEST_SCRATCH}/${1:t}"
STUB
cat > "${fixture_bin}/xcodebuild" <<'STUB'
#!/bin/zsh
exec /usr/bin/python3 -B -c 'import os,sys,time; open(sys.argv[1], "x").write(str(os.getpid())); time.sleep(30)' "${CLEAN_TEST_CHILD}"
STUB
chmod 700 "${fixture_bin}"/{security,mktemp,xcodebuild}
mkdir "${derived_data}/T083Upgrade"
env PATH="${fixture_bin}:/usr/bin:/bin:/usr/sbin:/sbin" DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade \
  CLEAN_TEST_SCRATCH="${fixture_root}" CLEAN_TEST_CHILD="${fixture_root}/child-pid" \
  "${copied_scripts}/build-development.sh" >"${fixture_root}/interrupted-build.out" 2>&1 &
build_pid=$!
for _ in {1..100}; do
  [[ -s "${fixture_root}/child-pid" ]] && break
  /bin/sleep 0.05
done
[[ -s "${fixture_root}/child-pid" ]]
build_child="$(<"${fixture_root}/child-pid")"
kill -KILL "${build_pid}"
wait "${build_pid}" 2>/dev/null || true
build_pid=""
refuses 'already running' clean_fixture DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade
kill "${build_child}"
build_child=""
for _ in {1..100}; do
  if clean_fixture DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade >/dev/null 2>"${fixture_root}/retry-clean.err"; then
    break
  fi
  /bin/sleep 0.05
done
[[ ! -e "${derived_data}/T083Upgrade" ]]
# An interrupted disposal must not corrupt the authoritative slot/cache name.
/usr/bin/python3 -B - "${script_dir}/clean-development.py" <<'PYTHON'
from contextlib import ExitStack
from pathlib import Path
import os
import runpy
import tempfile
support = runpy.run_path(__import__('sys').argv[1])
recovery = runpy.run_path(str(Path(__import__('sys').argv[1]).with_name('development-recovery.py')))
with tempfile.TemporaryDirectory(prefix='/private/tmp/dnie-clean-retirement-test.') as temp:
    root = Path(temp)
    target = root / 'T067'
    target.mkdir()
    (target / 'first').write_text('disposable')
    (target / 'second').write_text('retained')
    with ExitStack() as stack:
        slot = support['BuildSlot'](root, 'T067', lambda fd: None, lambda fd: None)
        parent = slot.open_root(stack)
        fd = slot.open_directories(stack, parent, ('T067',))
        entries = slot.snapshot(fd)
        def interrupted(fd, entries, check):
            check()
            os.unlink('first', dir_fd=fd)
            raise support['CleanError']('injected interruption')
        slot.dispose_contents = interrupted
        try:
            slot.retire_and_dispose(parent, 'T067', fd, entries, 'T067', recovery['publish'])
        except support['CleanError']:
            pass
        else:
            raise AssertionError('injected failure accepted')
    assert not target.exists()
    retired = list(root.glob('.retired-T067-*'))
    assert len(retired) == 1 and (retired[0] / 'second').is_file()
    assert retired[0].stat().st_mode & 0o777 == 0o700
    # A fresh build namespace remains available, independent of retained output.
    target.mkdir()
    (target / 'fresh').write_text('fresh output')
    with ExitStack() as stack:
        slot = support['BuildSlot'](root, 'T067', lambda fd: None, lambda fd: None)
        parent = slot.open_root(stack)
        fd = slot.open_directories(stack, parent, ('T067',))
        slot.retire_and_dispose(parent, 'T067', fd, slot.snapshot(fd), 'T067', recovery['publish'])
    assert not target.exists() and retired[0].exists()
PYTHON
print 'test_clean_development=pass'
