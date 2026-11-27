#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
repository_root="${script_dir:h:h:h}"
workflow="${script_dir}/developer-workflow.sh"
makefile="${repository_root}/Makefile"

[[ -x "${workflow}" && -f "${makefile}" ]] || {
  print -u2 "developer_workflow_missing=true"
  exit 1
}
grep -q 'require_normal_user' "${workflow}"
grep -q 'EUID == 0' "${script_dir}/build-development.sh"
grep -q 'Do not run the development build through sudo/root' "${script_dir}/build-development.sh"

fixture_root="$(mktemp -d /private/tmp/dnie-developer-workflow-test.XXXXXX)"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM
stub_bin="${fixture_root}/bin"
test_repository="${fixture_root}/repository"
mkdir -p "${stub_bin}" "${test_repository}/Validation/private/SecureChannel"
touch "${test_repository}/Validation/private/SecureChannel/generation2.json"
chmod 600 "${test_repository}/Validation/private/SecureChannel/generation2.json"

write_stub() {
  local name="$1"
  shift
  {
    print '#!/bin/zsh'
    print 'set -euo pipefail'
    print -r -- "$*"
  } > "${stub_bin}/${name}"
  chmod 700 "${stub_bin}/${name}"
}

write_stub uname 'print arm64'
write_stub sw_vers 'case "$1" in -productVersion) print 26.6.2;; -buildVersion) print 25G83;; *) exit 64;; esac'
write_stub xcodebuild 'print "Xcode 26.6"; print "Build version 17F113"'
write_stub xcrun 'if [[ "$1" == --show-sdk-version ]]; then print 26.5; else print "Apple Swift version 6.3.3"; fi'
write_stub stat 'if [[ "$1" == -f && "$2" == %Lp ]]; then print 600; else exit 64; fi'
write_stub git '[[ "$1" == -C && "$3" == check-ignore && "$4" == --quiet ]]'
write_stub security 'print "  1) 0123456789ABCDEF0123456789ABCDEF01234567 \"Apple Development: redacted\""'
write_stub pluginkit 'exit 0'

common_env=(
  DNIE_WORKFLOW_TEST_MODE=1
  DNIE_WORKFLOW_REPOSITORY_ROOT="${test_repository}"
  DNIE_WORKFLOW_BIN_DIR="${stub_bin}"
)

write_stub sudo 'print -u2 unexpected_privileged_side_effect=true; exit 99'
env "${common_env[@]}" "${workflow}" check > "${fixture_root}/check.out"
grep -q '^environment_evidence_match=pass$' "${fixture_root}/check.out"
grep -q '^credential_fixture_inspected=false$' "${fixture_root}/check.out"
grep -q '^signing_keychain_inspected=false$' "${fixture_root}/check.out"
! grep -q '0123456789ABCDEF' "${fixture_root}/check.out"
env "${common_env[@]}" DNIE_WORKFLOW_DESTINATION_APP="${fixture_root}/absent.app" \
  "${workflow}" status > "${fixture_root}/status.out"
grep -qx 'installed_app=absent' "${fixture_root}/status.out"
grep -qx 'provider_registration=absent' "${fixture_root}/status.out"
write_stub pluginkit 'print "+ org.dniemacos.dnietoken.tokenextension (0.1.0)"; print "    Path = /private/tmp/stale.appex"'
if env "${common_env[@]}" DNIE_WORKFLOW_DESTINATION_APP="${fixture_root}/absent.app" \
  "${workflow}" status >"${fixture_root}/stale-status.out" 2>"${fixture_root}/stale-status.err"; then
  print -u2 "stale_registration_status_accepted=true"
  exit 2
fi
grep -qx 'installed_app=absent' "${fixture_root}/stale-status.out"
grep -qx 'provider_registration=unexpected' "${fixture_root}/stale-status.out"
write_stub pluginkit 'exit 0'

write_stub build-stub '
if [[ "${1:-}" == --check-build-slot ]]; then
  [[ "$#" -eq 1 ]]; print development_build_slot=T067; print development_build_slot_state=absent; exit 0
fi
[[ "$#" -eq 0 ]]; print development_build=pass'

# The documented Make build route must reject the selected slot before environment, fixture,
# signing-keychain, credential-staging, or Xcode access.
rm -f -- "${test_repository}/Validation/private/SecureChannel/generation2.json"
preflight_sentinel="${fixture_root}/slot-preflight-external-command"
write_stub security 'print security >> "'"${preflight_sentinel}"'"; exit 99'
write_stub xcodebuild 'print xcodebuild >> "'"${preflight_sentinel}"'"; exit 99'
if env "${common_env[@]}" DNIE_DEVELOPMENT_BUILD_SLOT=../T067 \
    make -s -f "${makefile}" build >"${fixture_root}/slot-refusal.out" 2>"${fixture_root}/slot-refusal.err"; then
  print -u2 "unsafe_make_build_slot_accepted=true"
  exit 2
fi
grep -q 'must be T067 or T083CleanIncremental' "${fixture_root}/slot-refusal.err"
[[ ! -e "${preflight_sentinel}" ]]
write_stub xcodebuild 'print "Xcode 26.6"; print "Build version 17F113"'
write_stub security 'print "  1) 0123456789ABCDEF0123456789ABCDEF01234567 \"Apple Development: redacted\""'

if env "${common_env[@]}" DNIE_WORKFLOW_BUILD_SCRIPT="${stub_bin}/build-stub" \
  "${workflow}" build >"${fixture_root}/missing.out" 2>"${fixture_root}/missing.err"; then
  print -u2 "missing_fixture_accepted=true"
  exit 2
fi
grep -q 'fixture is missing' "${fixture_root}/missing.err"
touch "${test_repository}/Validation/private/SecureChannel/generation2.json"
chmod 600 "${test_repository}/Validation/private/SecureChannel/generation2.json"

write_stub security 'exit 31'
if env "${common_env[@]}" DNIE_WORKFLOW_BUILD_SCRIPT="${stub_bin}/build-stub" \
  "${workflow}" build >"${fixture_root}/security-failure.out" 2>"${fixture_root}/security-failure.err"; then
  print -u2 "signing_inspection_failure_hidden=true"
  exit 2
fi
grep -q 'Unable to inspect code-signing identities' "${fixture_root}/security-failure.err"

write_stub security 'print "  1) 0123456789ABCDEF0123456789ABCDEF01234567 \"Apple Development: redacted one\""; print "  2) 89ABCDEF0123456789ABCDEF0123456789ABCDEF \"Apple Development: redacted two\""'
if env "${common_env[@]}" DNIE_WORKFLOW_BUILD_SCRIPT="${stub_bin}/build-stub" \
  "${workflow}" build >"${fixture_root}/ambiguous.out" 2>"${fixture_root}/ambiguous.err"; then
  print -u2 "ambiguous_signing_identity_accepted=true"
  exit 2
fi
grep -q 'multiple valid Apple Development identities' "${fixture_root}/ambiguous.err"
! grep -q '0123456789ABCDEF' "${fixture_root}/ambiguous.err"
env "${common_env[@]}" DNIE_SIGNING_IDENTITY_SHA1=89ABCDEF0123456789ABCDEF0123456789ABCDEF \
  DNIE_WORKFLOW_BUILD_SCRIPT="${stub_bin}/build-stub" "${workflow}" build > "${fixture_root}/explicit.out"
! grep -q '89ABCDEF' "${fixture_root}/explicit.out"

env PATH="${stub_bin}:/usr/bin:/bin:/usr/sbin:/sbin" \
  DNIE_SIGNING_IDENTITY_SHA1=89ABCDEF0123456789ABCDEF0123456789ABCDEF \
  "${script_dir}/build-development.sh" --check-signing > "${fixture_root}/build-signing.out"
grep -q '^signing_selection=pass$' "${fixture_root}/build-signing.out"
! grep -q '89ABCDEF' "${fixture_root}/build-signing.out"

write_stub sw_vers 'case "$1" in -productVersion) print 27.0.1;; -buildVersion) print 26A434;; *) exit 64;; esac'
env "${common_env[@]}" "${workflow}" check >"${fixture_root}/mismatch.out" 2>"${fixture_root}/mismatch.err"
grep -q '^environment_evidence_match=unknown$' "${fixture_root}/mismatch.out"
grep -q 'recorded product evidence environment' "${fixture_root}/mismatch.err"
grep -q 'observed_macos_version=27.0.1' "${fixture_root}/mismatch.err"

for command in upgrade disable enable; do
  if env "${common_env[@]}" "${workflow}" "${command}" >"${fixture_root}/${command}.out" 2>"${fixture_root}/${command}.err"; then
    print -u2 "unsupported_command_accepted=${command}"
    exit 4
  fi
  grep -q 'not accepted' "${fixture_root}/${command}.err"
done
if env "${common_env[@]}" "${workflow}" finish-source-restoration invalid \
    >"${fixture_root}/finish-invalid.out" 2>"${fixture_root}/finish-invalid.err"; then
  print -u2 'malformed_source_finish_identity_accepted=true'
  exit 5
fi
grep -q 'requires one exact artifact identity' "${fixture_root}/finish-invalid.err"

! grep -q 'production root mutation remains stopped' "${workflow}"
grep -q 'Verify and publish a fresh exact-owned local pilot app' "${workflow}"
grep -q 'finish-source-restoration CDHASH' "${workflow}"

make -s -f "${makefile}" help > "${fixture_root}/help.out"
grep -q '^  check' "${fixture_root}/help.out"
grep -q '^  install' "${fixture_root}/help.out"
if make -s -f "${makefile}" build install >"${fixture_root}/combined.out" 2>"${fixture_root}/combined.err"; then
  print -u2 "combined_make_operations_accepted=true"
  exit 8
fi
grep -q 'one operational target' "${fixture_root}/combined.err"

# Native GUI and terminal transports receive one fixed, shell-quoted bootstrap command.
write_stub osascript '
[[ "$#" -eq 4 && "$1" == -l && "$2" == AppleScript && "$3" == -e ]] || exit 64
script_text="$4"
print -r -- "${script_text}" > "'"${fixture_root}"'/osascript.command"
if [[ "${AUTHORIZATION_STUB_MULTILINE:-0}" == 1 ]]; then
  if [[ "${script_text}" == *" without altering line endings" ]]; then
    /usr/bin/printf "%s\n" transport_line_one transport_line_two transport_line_three
  else
    /usr/bin/printf "transport_line_one\rtransport_line_two\rtransport_line_three\n"
  fi
  exit 0
fi
if [[ "${AUTHORIZATION_STUB_EXECUTE:-0}" == 1 ]]; then
  command_text="${script_text#do shell script \"}"; command_text="${command_text%\" with administrator privileges without altering line endings}"
  command_text="${command_text//\\\\/\\}"; command_text="${command_text//\\\"/\"}"
  /bin/zsh -f -c "${command_text}" >/dev/null 2>&1 || true
fi
exit "${AUTHORIZATION_STUB_EXIT:-0}"'
authorization_env=("${common_env[@]}" DNIE_WORKFLOW_TEST_EXERCISE_AUTHORIZATION_TRANSPORT=1)
injection_token='authorization.test;touch /private/tmp/dnie-authorization-injected'
rm -f /private/tmp/dnie-authorization-injected
env "${authorization_env[@]}" DNIE_WORKFLOW_TEST_AUTHORIZATION_TRANSPORT=native-gui \
  DNIE_WORKFLOW_TEST_AUTHORIZATION_TOKEN="${injection_token}" AUTHORIZATION_STUB_EXECUTE=1 \
  "${workflow}" test-authorization >/dev/null
grep -q '^do shell script "' "${fixture_root}/osascript.command"
grep -q 'with administrator privileges without altering line endings$' "${fixture_root}/osascript.command"
grep -q '/bin/zsh' "${fixture_root}/osascript.command"
grep -q 'pilot-lifecycle-root.sh' "${fixture_root}/osascript.command"
grep -q "$(/usr/bin/id -u)" "${fixture_root}/osascript.command"
[[ ! -e /private/tmp/dnie-authorization-injected ]]
multiline_output="$(env "${authorization_env[@]}" DNIE_WORKFLOW_TEST_AUTHORIZATION_TRANSPORT=native-gui \
  AUTHORIZATION_STUB_MULTILINE=1 "${workflow}" test-authorization)"
[[ "${multiline_output}" == $'transport_line_one\ntransport_line_two\ntransport_line_three' ]]
if env "${authorization_env[@]}" DNIE_WORKFLOW_TEST_AUTHORIZATION_TRANSPORT=native-gui \
    AUTHORIZATION_STUB_EXIT=128 "${workflow}" test-authorization >/dev/null 2>"${fixture_root}/authorization-cancel.err"; then
  print -u2 'native_authorization_cancellation_accepted=true'; exit 9
fi

write_stub sudo '/usr/bin/printf "%s\n" "$@" > "'"${fixture_root}"'/sudo.command"; exit 0'
env "${authorization_env[@]}" DNIE_WORKFLOW_TEST_AUTHORIZATION_TRANSPORT=sudo \
  "${workflow}" test-authorization >/dev/null
grep -q '^/usr/bin/env$' "${fixture_root}/sudo.command"
grep -q '^/bin/zsh$' "${fixture_root}/sudo.command"
grep -q '^-f$' "${fixture_root}/sudo.command"
grep -q '^pilot-lifecycle-root.sh$' <(/usr/bin/sed 's#^.*/##' "${fixture_root}/sudo.command")
grep -q "^$(/usr/bin/id -u)$" "${fixture_root}/sudo.command"

# A foreground lifecycle uses the same terminal transport even when a phase
# discards stdout or captures a proof. A detached invocation uses native GUI.
fixture_cdhash=0123456789abcdef0123456789abcdef01234567
mkdir "${fixture_root}/source.app"
write_stub inspect-artifact '[[ "$#" -eq 1 && -d "$1" ]]; print "artifact_cdhash='"${fixture_cdhash}"'"; print "extension_marketing_version=0.1.0"'
write_stub pgrep 'exit 1'
write_stub sleep 'exit 0'
write_stub pluginkit '
[[ "$1" == -m ]] || exit 99
if [[ -e "'"${fixture_root}"'/registered" ]]; then
  print "+ org.dniemacos.dnietoken.tokenextension (0.1.0)"
  print "    Path = ${DNIE_WORKFLOW_DESTINATION_APP}/Contents/PlugIns/DNIeTokenExtension.appex"
fi'
write_stub sudo '
[[ "$1" == /usr/bin/env && "$8" == -- && "${13}" == "$(/usr/bin/id -u)" ]] || exit 99
shift 13
phase="$1"
print -r -- "sudo:${phase}" >> "'"${fixture_root}"'/transport-trace"
case "${phase}" in
  publish-pilot)
    mkdir "${DNIE_WORKFLOW_DESTINATION_APP}"
    print pilot_publication=pending-install
    ;;
  confirm-pilot) print pilot_installation=committed ;;
  register-securityagent) /usr/bin/touch "'"${fixture_root}"'/registered" ;;
  probe-pending-install)
    print -rl -- pending_install_recoverable=true "pending_install_token=$2" "pending_install_cdhash=$3"
    ;;
  rollback-pending-install) exit 77 ;;
  *) exit 99 ;;
esac'
write_stub osascript '
print -r -- native-gui >> "'"${fixture_root}"'/transport-trace"
if [[ "$4" == *" register-securityagent "* ]]; then /usr/bin/touch "'"${fixture_root}"'/registered"; fi
print -r -- detached-proof'
env "${authorization_env[@]}" DNIE_WORKFLOW_TEST_AUTHORIZATION_TRANSPORT='' \
  DNIE_WORKFLOW_SOURCE_APP="${fixture_root}/source.app" \
  DNIE_WORKFLOW_DESTINATION_APP="${fixture_root}/installed.app" \
  DNIE_WORKFLOW_ARTIFACT_INSPECTOR="${stub_bin}/inspect-artifact" \
  /usr/bin/python3 -I - "${workflow}" "${fixture_root}" "${fixture_cdhash}" <<'PY'
from pathlib import Path
import subprocess
import sys

workflow, fixture, cdhash = sys.argv[1:]
trace = Path(fixture, "transport-trace")
terminal = ["/usr/bin/script", "-q", "/dev/null"]

def run(args, expected_trace, *, detached=False):
    trace.write_text("")
    result = subprocess.run(
        args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=20, start_new_session=detached,
    )
    observed = trace.read_text().splitlines()
    if observed != expected_trace:
        raise SystemExit(
            f"Expected transport calls {expected_trace}, received {observed}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result

install = run(terminal + [workflow, "install"], [
    "sudo:publish-pilot", "sudo:register-securityagent", "sudo:confirm-pilot",
])
if install.returncode or "pilot_install=pass" not in install.stdout:
    raise SystemExit(f"Terminal fixture install failed: {install.stdout}{install.stderr}")
Path(fixture, "registered").unlink()

recovery = run(terminal + [
    "/bin/zsh", "-fc", 'exec "$@" </dev/null > /dev/null', "--", workflow,
    "recover-pending-install", "install.20261120000000.100.200", cdhash,
], ["sudo:probe-pending-install", "sudo:rollback-pending-install"])
if recovery.returncode != 1 or "rollback was not authorized" not in recovery.stdout:
    raise SystemExit(f"Captured recovery proof did not reach guarded rollback: {recovery.stdout}{recovery.stderr}")

gui = run([workflow, "test-authorization"], ["native-gui"], detached=True)
if gui.returncode or gui.stdout != "detached-proof\n":
    raise SystemExit("Detached invocation did not preserve native GUI output")
PY

print "developer_workflow_offline=pass"
