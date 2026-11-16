#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
workflow="${script_dir}/developer-workflow.sh"
root_helper="${script_dir}/pilot-lifecycle-root.sh"
inspector="${script_dir}/inspect-pilot-artifact.sh"
fixture_root="$(mktemp -d /private/tmp/dnie-pilot-lifecycle-test.XXXXXX)"
trap '/bin/rm -rf -- "${fixture_root}"' EXIT INT TERM
mkdir -p "${fixture_root}/bin" "${fixture_root}/repository" "${fixture_root}/Applications" "${fixture_root}/Library/Application Support"
stub_bin="${fixture_root}/bin"
source_app="${fixture_root}/repository/DNIeTokenHost.app"
destination_app="${fixture_root}/Applications/DNIeTokenHost.app"
cdhash=0123456789abcdef0123456789abcdef01234567
extension_cdhash=89abcdef0123456789abcdef0123456789abcdef

make_app() {
  local app="$1" hash="${2:-${cdhash}}" version="${3:-0.1.0}" build="${4:-1}" extension_hash="${5:-${extension_cdhash}}"
  local team="${6:-TEAM000001}"
  mkdir -p "${app}/Contents/Resources" "${app}/Contents/MacOS" "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS" \
    "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets"
  print '#!/bin/zsh' > "${app}/Contents/MacOS/DNIeTokenHost"
  chmod 755 "${app}/Contents/MacOS/DNIeTokenHost"
  print '#!/bin/zsh' > "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension"
  chmod 755 "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension"
  {
    print 'host_id=org.dniemacos.dnietoken'
    print 'extension_id=org.dniemacos.dnietoken.tokenextension'
    print "host_version=${version}"
    print "host_build=${build}"
    print "extension_version=${version}"
    print "extension_build=${build}"
    print 'extension_point=com.apple.ctk-tokens'
    print 'token_type=smartcard'
    print 'aid=A000000063504B43532D3135'
    print 'class_id=org.dniemacos.dnietoken.token'
    print 'driver_class=DNIeTokenExtension.TokenDriver'
    print 'host_sandbox_entitlement=absent'
    print 'host_smartcard_entitlement=absent'
    print 'host_keychain_groups=absent'
    print 'extension_sandbox_entitlement=true'
    print 'extension_smartcard_entitlement=true'
    print 'extension_keychain_groups=absent'
    print 'credential_asset_count=1'
    print "host_cdhash=${hash}"
    print "extension_cdhash=${extension_hash}"
    print "cdhash=${hash}"
    print 'team_pairing=pass'
    print "host_team=${team}"
    print "extension_team=${team}"
  } > "${app}/Contents/Resources/pilot-artifact-metadata"
  print '{"ordered_field_names":["alpha","beta"],"fields_hex":{"alpha":"00ff","beta":"010203"}}' > "${app}/Contents/Resources/generation2.synthetic.json"
  print fixture > "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets/generation2.json"
}
set_fixture_host_hash() {
  local app="$1" hash="$2" metadata
  metadata="${app}/Contents/Resources/pilot-artifact-metadata"
  sed -i '' -e "s/^host_cdhash=.*/host_cdhash=${hash}/" -e "s/^cdhash=.*/cdhash=${hash}/" "${metadata}"
}
make_app "${source_app}"
# Reproduce the restrictive signed source modes that caused the live root-owned copy to become
# unreadable/unexecutable by the target runtime identities.
while IFS= read -r entry; do chmod 700 "${entry}"; done < <(find "${source_app}" -type d -print)
while IFS= read -r entry; do chmod 600 "${entry}"; done < <(find "${source_app}" -type f -print)
chmod 700 "${source_app}/Contents/MacOS/DNIeTokenHost" \
  "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension"
source_mode_snapshot() {
  local entry
  local -a entries
  entries=("${(@0)$(find "${source_app}" -print0)}")
  entries=("${(@)entries:#}")
  for entry in "${entries[@]}"; do
    print -r -- "${entry#${source_app}/}|$(stat -f %Lp "${entry}")"
  done
}
source_modes_restrictive() {
  local entry mode
  local -a entries
  entries=("${(@0)$(find "${source_app}" -print0)}")
  entries=("${(@)entries:#}")
  for entry in "${entries[@]}"; do
    mode="$(stat -f %Lp "${entry}")"
    if [[ -d "${entry}" || "${entry}" == "${source_app}/Contents/MacOS/DNIeTokenHost" ||
          "${entry}" == "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension" ]]; then
      [[ "${mode}" == 700 ]] || return 1
    else
      [[ -f "${entry}" && "${mode}" == 600 ]] || return 1
    fi
  done
}
source_modes_restrictive
source_modes_before="$(source_mode_snapshot)"
print keep > "${fixture_root}/unrelated-sentinel"

write_stub() {
  local name="$1"; shift
  { print '#!/bin/zsh'; print 'set -euo pipefail'; print -r -- "$*"; } > "${stub_bin}/${name}"
  chmod 700 "${stub_bin}/${name}"
}
write_stub pgrep '
[[ ! -f "'"${fixture_root}"'/pgrep.fail" ]] || exit 71
pattern="${2:-}"
if [[ -f "'"${fixture_root}"'/host.active" && "$pattern" == *"/Contents/MacOS/DNIeTokenHost"* ]]; then exit 0; fi
if [[ -f "'"${fixture_root}"'/provider.active" && "$pattern" == *"DNIeTokenExtension"* ]]; then exit 0; fi
exit 1'
write_stub sleep 'exit 0'
write_stub pluginkit '
state="'"${fixture_root}"'/registration"
[[ ! -f "'"${fixture_root}"'/registration-query.fail" ]] || exit 71
if [[ "${1:-}" == -r ]]; then print -r -- "remove=${2:-}" >> "'"${fixture_root}"'/events"; /bin/rm -f -- "$state"; [[ ! -f "'"${fixture_root}"'/fail-query-after-remove" ]] || touch "'"${fixture_root}"'/registration-query.fail"; exit 0; fi
if [[ "${1:-}" == -a ]]; then
  print -r -- "add=${2:-}" >> "'"${fixture_root}"'/events"
  [[ ! -f "'"${fixture_root}"'/add.fail" ]] || exit 72
  print -r -- "${2:-}" > "$state"
  exit 0
fi
print -r -- registration-query >> "'"${fixture_root}"'/events"
[[ -f "$state" ]] || exit 0
lines=("${(@f)$(<"$state")}")
if [[ ! -f "'"${fixture_root}"'/retain-stale-registration" ]]; then
  any_present=0
  for path in "${lines[@]}"; do app="${path%%/Contents/PlugIns/*}"; [[ -d "$app" ]] && any_present=1; done
  (( any_present )) || { /bin/rm -f -- "$state"; exit 0; }
fi
for path in "${lines[@]}"; do
  version=0.1.0
  [[ ! -f "'"${fixture_root}"'/registration-version" ]] || version="$(<"'"${fixture_root}"'/registration-version")"
  if [[ -f "'"${fixture_root}"'/registration-malformed" ]]; then
    print "+ org.dniemacos.dnietoken.tokenextension (${version}) trailing"
  else
    print "+ org.dniemacos.dnietoken.tokenextension (${version})"
  fi
  print "    Path = $path"
done'
write_stub open '
[[ ! -f "'"${fixture_root}"'/open.fail" ]] || exit 77
app="${@: -1}"
if [[ "$app" == "'"${destination_app}"'" ]]; then print -r -- "open-destination" >> "'"${fixture_root}"'/events"
else print -r -- "open-source" >> "'"${fixture_root}"'/events"
fi
print -r -- "$app/Contents/PlugIns/DNIeTokenExtension.appex" > "'"${fixture_root}"'/registration"'
write_stub securityagent 'exit 0'
write_stub root-helper-wrapper '
actual="'"${root_helper}"'"
"$actual" "$@"
helper_status=$?
if [[ "$helper_status" == 0 && "${1:-}" == register-securityagent ]]; then
  print -r -- securityagent >> "'"${fixture_root}"'/events"
  print -r -- "'"${destination_app}"'/Contents/PlugIns/DNIeTokenExtension.appex" > "'"${fixture_root}"'/registration"
  [[ "${DNIE_WORKFLOW_TEST_FAIL_POST_SECURITYAGENT_QUERY:-0}" != 1 ]] || touch "'"${fixture_root}"'/registration-query.fail"
fi
if [[ "$helper_status" == 0 && "${1:-}" == probe-pending-install && "${DNIE_WORKFLOW_TEST_CHANGE_ROW_AFTER_PROBE:-0}" == 1 ]]; then
  print -r -- "/private/tmp/changed/DNIeTokenExtension.appex" > "'"${fixture_root}"'/registration"
fi
exit "$helper_status"'

common_env=(
  DNIE_WORKFLOW_TEST_MODE=1
  DNIE_WORKFLOW_REPOSITORY_ROOT="${fixture_root}/repository"
  DNIE_WORKFLOW_BIN_DIR="${stub_bin}"
  DNIE_WORKFLOW_SOURCE_APP="${source_app}"
  DNIE_WORKFLOW_DESTINATION_APP="${destination_app}"
  DNIE_WORKFLOW_ROOT_HELPER="${stub_bin}/root-helper-wrapper"
  DNIE_WORKFLOW_ARTIFACT_INSPECTOR="${inspector}"
  DNIE_LIFECYCLE_TEST_MODE=1
  DNIE_LIFECYCLE_TEST_ROOT="${fixture_root}"
)
state_root="${fixture_root}/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle"

# Fixed fixture descendants may not be symlinks, even when they resolve inside the fixture.
mv "${fixture_root}/Applications" "${fixture_root}/Applications.real"
ln -s "${fixture_root}/Applications.real" "${fixture_root}/Applications"
if env "${common_env[@]}" "${root_helper}" probe-absent descend01 >/dev/null 2>&1; then exit 9; fi
rm "${fixture_root}/Applications"; mv "${fixture_root}/Applications.real" "${fixture_root}/Applications"
mv "${fixture_root}/Library" "${fixture_root}/Library.real"
ln -s "${fixture_root}/Library.real" "${fixture_root}/Library"
if env "${common_env[@]}" "${root_helper}" probe-absent descend02 >/dev/null 2>&1; then exit 10; fi
rm "${fixture_root}/Library"; mv "${fixture_root}/Library.real" "${fixture_root}/Library"

# Synthetic artifact inspection enforces opposite host/extension entitlement polarity.
sed -i '' 's/^host_sandbox_entitlement=absent$/host_sandbox_entitlement=true/' "${source_app}/Contents/Resources/pilot-artifact-metadata"
if env "${common_env[@]}" "${inspector}" "${source_app}" >/dev/null 2>&1; then exit 92; fi
sed -i '' 's/^host_sandbox_entitlement=true$/host_sandbox_entitlement=absent/' "${source_app}/Contents/Resources/pilot-artifact-metadata"
sed -i '' 's/^extension_sandbox_entitlement=true$/extension_sandbox_entitlement=absent/' "${source_app}/Contents/Resources/pilot-artifact-metadata"
if env "${common_env[@]}" "${inspector}" "${source_app}" >/dev/null 2>&1; then exit 93; fi
sed -i '' 's/^extension_sandbox_entitlement=absent$/extension_sandbox_entitlement=true/' "${source_app}/Contents/Resources/pilot-artifact-metadata"

# The trusted synthetic inspector emits the complete bounded tuple and rejects ambiguity/mismatch.
env "${common_env[@]}" "${inspector}" "${source_app}" > "${fixture_root}/artifact-tuple.out"
grep -q '^host_marketing_version=0.1.0$' "${fixture_root}/artifact-tuple.out"
grep -q '^extension_build_version=1$' "${fixture_root}/artifact-tuple.out"
grep -q "^host_cdhash=${cdhash}$" "${fixture_root}/artifact-tuple.out"
grep -q "^extension_cdhash=${extension_cdhash}$" "${fixture_root}/artifact-tuple.out"
grep -q '^artifact_team_pairing=pass$' "${fixture_root}/artifact-tuple.out"
! grep -Eqi 'authority|apple development:|teamidentifier|account' "${fixture_root}/artifact-tuple.out"

# The separately isolated first-pilot candidate emits and registers as the exact 0.1.1/build 2 tuple.
candidate_app="${fixture_root}/repository/candidate/DNIeTokenHost.app"
candidate_cdhash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
candidate_extension_cdhash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
make_app "${candidate_app}" "${candidate_cdhash}" 0.1.1 2 "${candidate_extension_cdhash}"
env "${common_env[@]}" "${inspector}" "${candidate_app}" > "${fixture_root}/candidate-tuple.out"
grep -q '^host_marketing_version=0.1.1$' "${fixture_root}/candidate-tuple.out"
grep -q '^host_build_version=2$' "${fixture_root}/candidate-tuple.out"
grep -q '^extension_marketing_version=0.1.1$' "${fixture_root}/candidate-tuple.out"
grep -q '^extension_build_version=2$' "${fixture_root}/candidate-tuple.out"
grep -q "^host_cdhash=${candidate_cdhash}$" "${fixture_root}/candidate-tuple.out"
grep -q "^extension_cdhash=${candidate_extension_cdhash}$" "${fixture_root}/candidate-tuple.out"
grep -q "^artifact_cdhash=${candidate_cdhash}$" "${fixture_root}/candidate-tuple.out"
grep -q '^artifact_team_pairing=pass$' "${fixture_root}/candidate-tuple.out"
! grep -Eqi 'authority|apple development:|teamidentifier|account' "${fixture_root}/candidate-tuple.out"

# Trusted pair inspection independently validates fixed old/new tuples and privately compares teams.
env "${common_env[@]}" "${inspector}" --upgrade-pair "${source_app}" "${candidate_app}" > "${fixture_root}/pair-tuple.out"
for expected in \
  'old_host_marketing_version=0.1.0' 'old_host_build_version=1' \
  'old_extension_marketing_version=0.1.0' 'old_extension_build_version=1' \
  "old_host_cdhash=${cdhash}" "old_extension_cdhash=${extension_cdhash}" \
  'new_host_marketing_version=0.1.1' 'new_host_build_version=2' \
  'new_extension_marketing_version=0.1.1' 'new_extension_build_version=2' \
  "new_host_cdhash=${candidate_cdhash}" "new_extension_cdhash=${candidate_extension_cdhash}" \
  'upgrade_pair_verification=pass' 'upgrade_pair_team_match=pass'; do
  grep -qx "${expected}" "${fixture_root}/pair-tuple.out"
done
! grep -Eqi 'authority|apple development:|teamidentifier|account|TEAM000001' "${fixture_root}/pair-tuple.out"

pair_must_fail_privately() {
  local label="$1" old="$2" new="$3" output
  output="${fixture_root}/pair-${label}.out"
  if env "${common_env[@]}" "${inspector}" --upgrade-pair "${old}" "${new}" >"${output}" 2>&1; then
    exit 934
  fi
  ! grep -Eq 'TEAM[[:alnum:]]*' "${output}"
}

pair_must_fail_privately reversed "${candidate_app}" "${source_app}"
pair_must_fail_privately same-tuple "${source_app}" "${source_app}"

pair_wrong_app="${fixture_root}/repository/pair-wrong/DNIeTokenHost.app"
make_app "${pair_wrong_app}" cccccccccccccccccccccccccccccccccccccccc 0.1.0 1 dddddddddddddddddddddddddddddddddddddddd
pair_must_fail_privately wrong-candidate "${source_app}" "${pair_wrong_app}"

sed -i '' 's/^extension_build=2$/extension_build=3/' "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
pair_must_fail_privately nested-mismatch "${source_app}" "${candidate_app}"
sed -i '' 's/^extension_build=3$/extension_build=2/' "${candidate_app}/Contents/Resources/pilot-artifact-metadata"

print 'host_team=TEAM000001' >> "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
pair_must_fail_privately duplicate-team "${source_app}" "${candidate_app}"
sed -i '' '$d' "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
sed -i '' '/^extension_team=/d' "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
pair_must_fail_privately missing-team "${source_app}" "${candidate_app}"
print 'extension_team=TEAM000001' >> "${candidate_app}/Contents/Resources/pilot-artifact-metadata"

sed -i '' 's/^extension_team=TEAM000001$/extension_team=TEAM000002/' \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
pair_must_fail_privately nested-team-mismatch "${source_app}" "${candidate_app}"
sed -i '' 's/^extension_team=TEAM000002$/extension_team=TEAM000001/' \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"

sed -i '' 's/^host_team=TEAM000001$/host_team=TEAM000002/; s/^extension_team=TEAM000001$/extension_team=TEAM000002/' \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
pair_must_fail_privately cross-team "${source_app}" "${candidate_app}"
sed -i '' 's/^host_team=TEAM000002$/host_team=TEAM000001/; s/^extension_team=TEAM000002$/extension_team=TEAM000001/' \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"

sed -i '' "s/^host_cdhash=${candidate_cdhash}$/host_cdhash=${cdhash}/; s/^cdhash=${candidate_cdhash}$/cdhash=${cdhash}/" \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
pair_must_fail_privately same-host-identity "${source_app}" "${candidate_app}"
sed -i '' "s/^host_cdhash=${cdhash}$/host_cdhash=${candidate_cdhash}/; s/^cdhash=${cdhash}$/cdhash=${candidate_cdhash}/" \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
sed -i '' "s/^extension_cdhash=${candidate_extension_cdhash}$/extension_cdhash=${extension_cdhash}/" \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"
pair_must_fail_privately same-extension-identity "${source_app}" "${candidate_app}"
sed -i '' "s/^extension_cdhash=${extension_cdhash}$/extension_cdhash=${candidate_extension_cdhash}/" \
  "${candidate_app}/Contents/Resources/pilot-artifact-metadata"

print -r -- "${candidate_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
print 0.1.1 > "${fixture_root}/registration-version"
env "${common_env[@]}" "${workflow}" test-registration-version \
  "${candidate_app}/Contents/PlugIns/DNIeTokenExtension.appex" 0.1.1 >/dev/null
rm "${fixture_root}/registration-version"
print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"

for mutation in \
  'host_version=0.1.0|host_version=1.0' \
  'host_build=1|host_build=01' \
  'extension_id=org.dniemacos.dnietoken.tokenextension|extension_id=wrong' \
  "extension_cdhash=${extension_cdhash}|extension_cdhash=invalid" \
  'team_pairing=pass|team_pairing=fail'; do
  before="${mutation%%|*}"; after="${mutation#*|}"
  sed -i '' "s/^${before}$/${after}/" "${source_app}/Contents/Resources/pilot-artifact-metadata"
  if env "${common_env[@]}" "${inspector}" "${source_app}" >/dev/null 2>&1; then exit 931; fi
  sed -i '' "s/^${after}$/${before}/" "${source_app}/Contents/Resources/pilot-artifact-metadata"
done
print 'host_version=0.1.0' >> "${source_app}/Contents/Resources/pilot-artifact-metadata"
if env "${common_env[@]}" "${inspector}" "${source_app}" >/dev/null 2>&1; then exit 932; fi
sed -i '' '$d' "${source_app}/Contents/Resources/pilot-artifact-metadata"

# Registration comparison includes the reported version and rejects wrong, duplicate and malformed rows.
print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
env "${common_env[@]}" "${workflow}" test-registration-version \
  "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" 0.1.0 >/dev/null
for registration_case in wrong-version duplicate malformed; do
  case "${registration_case}" in
    wrong-version) print 0.1.1 > "${fixture_root}/registration-version" ;;
    duplicate) print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" >> "${fixture_root}/registration" ;;
    malformed) touch "${fixture_root}/registration-malformed" ;;
  esac
  if env "${common_env[@]}" DNIE_WORKFLOW_TEST_REGISTRATION_CASE="${registration_case}" "${workflow}" \
      test-registration-version "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" 0.1.0 >/dev/null 2>&1; then exit 933; fi
  rm -f "${fixture_root}/registration-version" "${fixture_root}/registration-malformed"
  print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
done

# Fresh install accepts and isolates only the exact verified build-tree registration.
: > "${fixture_root}/events"
print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
install_registration_before="$(<"${fixture_root}/registration")"
for inactivity_case in host.active provider.active pgrep.fail; do
  touch "${fixture_root}/${inactivity_case}"
  if env "${common_env[@]}" "${workflow}" install >/dev/null 2>"${fixture_root}/install-${inactivity_case}.err"; then exit 801; fi
  if [[ "${inactivity_case}" == pgrep.fail ]]; then
    grep -q 'Unable to establish' "${fixture_root}/install-${inactivity_case}.err"
  else
    grep -q 'host or provider is active' "${fixture_root}/install-${inactivity_case}.err"
  fi
  rm "${fixture_root}/${inactivity_case}"
  [[ "$(<"${fixture_root}/registration")" == "${install_registration_before}" &&
     ! -e "${destination_app}" && ! -e "${state_root}" && ! -s "${fixture_root}/events" ]] || exit 802
done
if env "${common_env[@]}" DNIE_WORKFLOW_TEST_REFUSE_ROOT_COMMAND=authorize "${workflow}" install \
    >/dev/null 2>"${fixture_root}/authorization-refused.err"; then exit 81; fi
grep -q 'source registration was not changed' "${fixture_root}/authorization-refused.err"
[[ "$(<"${fixture_root}/registration")" == "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" &&
   ! -e "${destination_app}" && ! -e "${state_root}" ]]
env "${common_env[@]}" "${workflow}" install > "${fixture_root}/install.out"
grep -q '^pilot_install=pass$' "${fixture_root}/install.out"
grep -q '^source_registration_isolated=1$' "${fixture_root}/install.out"
grep -q '^actor=_securityagent$' "${fixture_root}/securityagent-invocation"
grep -qx "host=${destination_app}/Contents/MacOS/DNIeTokenHost" "${fixture_root}/securityagent-invocation"
/usr/bin/awk '$0=="securityagent"{seen=1;next} seen&&$0=="registration-query"{found=1} END{exit !found}' "${fixture_root}/events"
! grep -q '^open-destination$' "${fixture_root}/events"
[[ -d "${destination_app}" && -d "${source_app}" ]]
[[ "$(stat -f %Lp "${destination_app}")" == 755 && "$(stat -f %u "${destination_app}")" == "${EUID}" ]]
[[ "$(stat -f %Lp "${destination_app}/Contents/MacOS/DNIeTokenHost")" == 755 ]]
[[ "$(stat -f %Lp "${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension")" == 755 ]]
[[ "$(stat -f %Lp "${destination_app}/Contents/Resources/pilot-artifact-metadata")" == 644 ]]
[[ "$(stat -f %Lp "${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets/generation2.json")" == 444 ]]
grep -q '^phase=committed$' "${fixture_root}/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle/installed.state"

# The pending-only recovery entry points refuse a committed install and commit-intent topology.
committed_token="$(sed -n 's/^token=//p' "${state_root}/installed.state")"
if env "${common_env[@]}" "${root_helper}" probe-pending-install "${committed_token}" "${cdhash}" >/dev/null 2>&1; then exit 84; fi
if env "${common_env[@]}" "${root_helper}" rollback-pending-install "${committed_token}" "${cdhash}" >/dev/null 2>&1; then exit 85; fi
[[ -d "${destination_app}" ]] && grep -q '^phase=committed$' "${state_root}/installed.state"
print 'phase=commit-install-intent' > "${state_root}/transactions/${committed_token}/transaction.state"
chmod 600 "${state_root}/transactions/${committed_token}/transaction.state"
if env "${common_env[@]}" "${root_helper}" probe-pending-install "${committed_token}" "${cdhash}" >/dev/null 2>&1; then exit 87; fi
if env "${common_env[@]}" "${root_helper}" rollback-pending-install "${committed_token}" "${cdhash}" >/dev/null 2>&1; then exit 88; fi
print 'phase=installed' > "${state_root}/transactions/${committed_token}/transaction.state"
chmod 600 "${state_root}/transactions/${committed_token}/transaction.state"

# Host activity, extension activity, and process-query errors fail before withdrawal or any
# root, registration, or launch mutation.
uninstall_registration_before="$(<"${fixture_root}/registration")"
uninstall_state_before="$(/usr/bin/shasum -a 256 "${state_root}/installed.state")"
uninstall_mutations_before="$(grep -Ec '^(remove=|add=|open-|securityagent$)' "${fixture_root}/events" || true)"
uninstall_transactions_before="$(find "${state_root}/transactions" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
for inactivity_case in host.active provider.active pgrep.fail; do
  touch "${fixture_root}/${inactivity_case}"
  if env "${common_env[@]}" "${workflow}" uninstall >/dev/null 2>"${fixture_root}/uninstall-${inactivity_case}.err"; then exit 11; fi
  if [[ "${inactivity_case}" == pgrep.fail ]]; then
    grep -q 'Unable to establish' "${fixture_root}/uninstall-${inactivity_case}.err"
  else
    grep -q 'host or provider is active' "${fixture_root}/uninstall-${inactivity_case}.err"
  fi
  rm "${fixture_root}/${inactivity_case}"
  [[ -d "${destination_app}" && "$(<"${fixture_root}/registration")" == "${uninstall_registration_before}" &&
     "$(/usr/bin/shasum -a 256 "${state_root}/installed.state")" == "${uninstall_state_before}" &&
     "$(grep -Ec '^(remove=|add=|open-|securityagent$)' "${fixture_root}/events" || true)" == "${uninstall_mutations_before}" &&
     "$(find "${state_root}/transactions" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" == "${uninstall_transactions_before}" ]] || exit 12
done

# Failed post-withdrawal registration absence restores the exact app.
touch "${fixture_root}/retain-stale-registration"
if env "${common_env[@]}" "${workflow}" uninstall >"${fixture_root}/uninstall-rollback.out" 2>"${fixture_root}/uninstall-rollback.err"; then
  cat "${fixture_root}/uninstall-rollback.out" >&2
  exit 12
fi
grep -q 'exact owned app was restored' "${fixture_root}/uninstall-rollback.err" || { cat "${fixture_root}/uninstall-rollback.err" >&2; exit 12; }
[[ -d "${destination_app}" ]]
rm "${fixture_root}/retain-stale-registration"

# Uninstall succeeds, retains its archive, and leaves unrelated state alone.
env "${common_env[@]}" "${workflow}" uninstall > "${fixture_root}/uninstall.out"
grep -q '^pilot_uninstall=pass$' "${fixture_root}/uninstall.out"
[[ ! -e "${destination_app}" && "$(<"${fixture_root}/unrelated-sentinel")" == keep ]]
find "${fixture_root}/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle/transactions" -type d -name DNIeTokenHost.app | grep -q .

# A denied rollback authorization preserves the exact pending topology for reviewed recovery.
if env "${common_env[@]}" DNIE_WORKFLOW_TEST_FAIL_POST_SECURITYAGENT_QUERY=1 \
    DNIE_WORKFLOW_TEST_REFUSE_ROOT_COMMAND=rollback-install "${workflow}" install \
    >/dev/null 2>"${fixture_root}/rollback-authorization.err"; then exit 82; fi
grep -q 'retained pending state requires reviewed recovery' "${fixture_root}/rollback-authorization.err"
[[ -d "${destination_app}" ]] && grep -q '^phase=pending-install$' "${state_root}/installed.state"
pending_token="$(sed -n 's/^token=//p' "${state_root}/installed.state")"
env "${common_env[@]}" "${root_helper}" rollback-install "${pending_token}" "${cdhash}" >/dev/null
rm "${fixture_root}/registration-query.fail"
[[ ! -e "${destination_app}" && ! -e "${state_root}/installed.state" ]]

# Refused native registration authorization leaves the exact pending install recoverable.
if env "${common_env[@]}" DNIE_WORKFLOW_TEST_REFUSE_ROOT_COMMAND=register-securityagent "${workflow}" install \
    >/dev/null 2>"${fixture_root}/securityagent-authorization.err"; then exit 83; fi
grep -q 'retained pending state requires reviewed recovery' "${fixture_root}/securityagent-authorization.err"
[[ -d "${destination_app}" ]] && grep -q '^phase=pending-install$' "${state_root}/installed.state"
pending_token="$(sed -n 's/^token=//p' "${state_root}/installed.state")"

# A root-proven pending artifact remains recoverable when its restrictive app mode blocks the
# normal-user inspector and no provider row was ever created.
write_stub inaccessible-inspector '
if [[ "$1" == "'"${destination_app}"'" ]]; then exit 77; fi
exec "'"${inspector}"'" "$@"'
absent_remove_count_before="$(grep -c '^remove=' "${fixture_root}/events" || true)"
env "${common_env[@]}" DNIE_WORKFLOW_ARTIFACT_INSPECTOR="${stub_bin}/inaccessible-inspector" \
  "${workflow}" recover-pending-install "${pending_token}" "${cdhash}" > "${fixture_root}/absent-row-recovery.out"
absent_remove_count_after="$(grep -c '^remove=' "${fixture_root}/events" || true)"
grep -q '^pending_install_recovery=pass$' "${fixture_root}/absent-row-recovery.out"
grep -q '^initial_registration=absent$' "${fixture_root}/absent-row-recovery.out"
[[ "${absent_remove_count_after}" == "${absent_remove_count_before}" && ! -e "${destination_app}" ]]
source_modes_restrictive
[[ "$(source_mode_snapshot)" == "${source_modes_before}" ]]

# Recreate a pending install for exact-row and topology-change recovery coverage.
if env "${common_env[@]}" DNIE_WORKFLOW_TEST_REFUSE_ROOT_COMMAND=register-securityagent "${workflow}" install \
    >/dev/null 2>"${fixture_root}/securityagent-authorization-second.err"; then exit 94; fi
pending_token="$(sed -n 's/^token=//p' "${state_root}/installed.state")"
print -r -- "${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"

# A row classification change after the privileged proof stops before app withdrawal.
if env "${common_env[@]}" DNIE_WORKFLOW_TEST_CHANGE_ROW_AFTER_PROBE=1 \
    "${workflow}" recover-pending-install "${pending_token}" "${cdhash}" >/dev/null 2>"${fixture_root}/pending-row-change.err"; then exit 95; fi
grep -Eq 'registration topology became ambiguous|registration classification changed' "${fixture_root}/pending-row-change.err"
[[ -d "${destination_app}" ]]
print -r -- "${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"

# Changed artifacts, active providers, and non-installed rows fail before the root probe.
set_fixture_host_hash "${source_app}" ffffffffffffffffffffffffffffffffffffffff
if env "${common_env[@]}" "${workflow}" recover-pending-install "${pending_token}" "${cdhash}" >/dev/null 2>"${fixture_root}/pending-source-change.err"; then exit 89; fi
grep -q 'source artifact identity differs' "${fixture_root}/pending-source-change.err"
set_fixture_host_hash "${source_app}" "${cdhash}"
touch "${fixture_root}/provider.active"
if env "${common_env[@]}" "${workflow}" recover-pending-install "${pending_token}" "${cdhash}" >/dev/null 2>"${fixture_root}/pending-active.err"; then exit 90; fi
grep -q 'provider is active' "${fixture_root}/pending-active.err"
rm "${fixture_root}/provider.active"
print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
if env "${common_env[@]}" "${workflow}" recover-pending-install "${pending_token}" "${cdhash}" >/dev/null 2>"${fixture_root}/pending-row.err"; then exit 91; fi
grep -q 'either zero provider rows or one exact installed row' "${fixture_root}/pending-row.err"
print -r -- "${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"

# Approval refusal happens after exact unregistration but leaves attributable pending state.
if env "${common_env[@]}" DNIE_WORKFLOW_TEST_REFUSE_ROOT_COMMAND=rollback-pending-install \
    "${workflow}" recover-pending-install "${pending_token}" "${cdhash}" \
    >/dev/null 2>"${fixture_root}/pending-recovery-refused.err"; then exit 86; fi
grep -q 'registration is absent' "${fixture_root}/pending-recovery-refused.err"
[[ -d "${destination_app}" && ! -e "${fixture_root}/registration" ]] && grep -q '^phase=pending-install$' "${state_root}/installed.state"

# Re-establish the observed installed row and perform the exact guarded recovery.
print -r -- "${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
exact_remove_count_before="$(grep -c '^remove=' "${fixture_root}/events" || true)"
env "${common_env[@]}" "${workflow}" recover-pending-install "${pending_token}" "${cdhash}" > "${fixture_root}/pending-recovery.out"
exact_remove_count_after="$(grep -c '^remove=' "${fixture_root}/events" || true)"
grep -q '^pending_install_recovery=pass$' "${fixture_root}/pending-recovery.out"
grep -q '^installed_registration=absent$' "${fixture_root}/pending-recovery.out"
grep -q '^source_registration=exact-singleton$' "${fixture_root}/pending-recovery.out"
grep -qx "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" "${fixture_root}/registration"
[[ "${exact_remove_count_after}" -eq $(( exact_remove_count_before + 1 )) ]]
grep -qx "remove=${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex" <(grep '^remove=' "${fixture_root}/events" | tail -n 1)
[[ "$(grep -c '^add=' "${fixture_root}/events")" -eq 2 ]]
grep -qx "add=${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" <(grep '^add=' "${fixture_root}/events" | tail -n 1)
! grep -q '^open-source$' "${fixture_root}/events"
[[ ! -e "${destination_app}" && ! -e "${state_root}/installed.state" &&
   -d "${state_root}/transactions/${pending_token}/DNIeTokenHost.app.failed-install" ]]
source_modes_restrictive
[[ "$(source_mode_snapshot)" == "${source_modes_before}" ]]
/bin/rm -f -- "${fixture_root}/registration"

# Consumed-root partial recovery can finish only the exact absent-installed, zero-row source
# restoration. It performs one development add, never launches the host or calls the root helper.
finish_add_count_before="$(grep -c '^add=' "${fixture_root}/events")"
finish_root_count_before="$(find "${state_root}/transactions" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" > "${fixture_root}/finish-source.out"
grep -q '^development_source_registration_restoration=pass$' "${fixture_root}/finish-source.out"
[[ "$(grep -c '^add=' "${fixture_root}/events")" -eq $(( finish_add_count_before + 1 )) ]]
grep -qx "add=${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" <(grep '^add=' "${fixture_root}/events" | tail -n 1)
[[ "$(find "${state_root}/transactions" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" == "${finish_root_count_before}" ]]
! grep -q '^open-source$' "${fixture_root}/events"
source_modes_restrictive
[[ "$(source_mode_snapshot)" == "${source_modes_before}" ]]

# Source-only restoration fails closed before -a for changed identity, active provider,
# nonzero/foreign topology, and any installed-path presence.
rm "${fixture_root}/registration"
finish_add_count_before="$(grep -c '^add=' "${fixture_root}/events")"
set_fixture_host_hash "${source_app}" ffffffffffffffffffffffffffffffffffffffff
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-changed.err"; then exit 96; fi
grep -q 'identity differs' "${fixture_root}/finish-changed.err"
set_fixture_host_hash "${source_app}" "${cdhash}"
touch "${fixture_root}/provider.active"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-active.err"; then exit 97; fi
grep -q 'provider is active' "${fixture_root}/finish-active.err"
rm "${fixture_root}/provider.active"
touch "${fixture_root}/host.active"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-host-active.err"; then exit 971; fi
grep -q 'host or provider is active' "${fixture_root}/finish-host-active.err"
rm "${fixture_root}/host.active"
touch "${fixture_root}/pgrep.fail"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-pgrep.err"; then exit 972; fi
grep -q 'Unable to establish' "${fixture_root}/finish-pgrep.err"
rm "${fixture_root}/pgrep.fail"
touch "${fixture_root}/retain-stale-registration"
print /private/tmp/foreign.appex > "${fixture_root}/registration"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-foreign.err"; then exit 98; fi
grep -q 'stale or competing' "${fixture_root}/finish-foreign.err"
print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
print -r -- /private/tmp/duplicate.appex >> "${fixture_root}/registration"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-duplicate.err"; then exit 981; fi
grep -q 'stale or competing' "${fixture_root}/finish-duplicate.err"
print -r -- '+ org.dniemacos.dnietoken.tokenextension malformed' > "${fixture_root}/registration"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-malformed.err"; then exit 982; fi
grep -q 'stale or competing' "${fixture_root}/finish-malformed.err"
rm "${fixture_root}/registration"
rm "${fixture_root}/retain-stale-registration"
mkdir -p "${destination_app}"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-installed.err"; then exit 99; fi
grep -q 'installed production path to remain absent' "${fixture_root}/finish-installed.err"
rm -rf "${destination_app}"
[[ "$(grep -c '^add=' "${fixture_root}/events")" == "${finish_add_count_before}" ]]

# A failed explicit add is attempted exactly once and is never retried automatically.
touch "${fixture_root}/add.fail"
if env "${common_env[@]}" "${workflow}" finish-source-restoration "${cdhash}" >/dev/null 2>"${fixture_root}/finish-add.err"; then exit 991; fi
grep -q 'could not be added' "${fixture_root}/finish-add.err"
rm "${fixture_root}/add.fail"
[[ "$(grep -c '^add=' "${fixture_root}/events")" -eq $(( finish_add_count_before + 1 )) ]]

# Already absent is accepted only with absent registration and ownership.
env "${common_env[@]}" "${workflow}" uninstall | grep -q '^pilot_uninstall=already-absent$'
print '/private/tmp/stale/DNIeTokenExtension.appex' > "${fixture_root}/registration"
touch "${fixture_root}/retain-stale-registration"
if env "${common_env[@]}" "${workflow}" uninstall >/dev/null 2>"${fixture_root}/stale.err"; then exit 13; fi
grep -q 'stale or competing' "${fixture_root}/stale.err"
rm "${fixture_root}/registration" "${fixture_root}/retain-stale-registration"

# Duplicate source/unknown registration and altered credential content fail before mutation.
print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
print -r -- '/private/tmp/competing/DNIeTokenExtension.appex' >> "${fixture_root}/registration"
if env "${common_env[@]}" "${workflow}" install >/dev/null 2>"${fixture_root}/duplicate.err"; then exit 131; fi
grep -q 'stale, duplicated' "${fixture_root}/duplicate.err"
rm "${fixture_root}/registration"
sed -i '' 's/00ff/00fe/' "${source_app}/Contents/Resources/generation2.synthetic.json"
if env "${common_env[@]}" "${workflow}" install >/dev/null 2>"${fixture_root}/credential.err"; then exit 132; fi
grep -q 'artifact preflight' "${fixture_root}/credential.err"
sed -i '' 's/00fe/00ff/' "${source_app}/Contents/Resources/generation2.synthetic.json"

# Query failure after exact source unregistration is not mistaken for absence.
print -r -- "${source_app}/Contents/PlugIns/DNIeTokenExtension.appex" > "${fixture_root}/registration"
touch "${fixture_root}/fail-query-after-remove"
if env "${common_env[@]}" "${workflow}" install >/dev/null 2>"${fixture_root}/query-fail.err"; then exit 133; fi
grep -q 'isolation result is uncertain' "${fixture_root}/query-fail.err"
rm -f "${fixture_root}/fail-query-after-remove" "${fixture_root}/registration-query.fail" "${fixture_root}/registration"

# Canonical traversal and symlinked source ancestors are rejected in fixture mode.
escaped_root="${fixture_root}/../${fixture_root:t}"
if env DNIE_LIFECYCLE_TEST_MODE=1 DNIE_LIFECYCLE_TEST_ROOT="${escaped_root}" "${root_helper}" probe-absent escape001 >/dev/null 2>&1; then exit 134; fi
ln -s "${fixture_root}/repository" "${fixture_root}/linked-repository"
if env "${common_env[@]}" "${root_helper}" install symlink1 "${fixture_root}/linked-repository/DNIeTokenHost.app" "${cdhash}" >/dev/null 2>&1; then exit 135; fi
rm "${fixture_root}/linked-repository"

# Commit failures drive the paired rollback rather than leaving a published or withdrawn app.
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_FAIL_AT=commit-install-before-write "${workflow}" install >/dev/null 2>"${fixture_root}/commit-install.err"; then exit 136; fi
grep -q 'Install commit failed' "${fixture_root}/commit-install.err"
[[ ! -e "${destination_app}" ]]
env "${common_env[@]}" "${workflow}" install >/dev/null
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_FAIL_AT=commit-uninstall-before-write "${workflow}" uninstall >/dev/null 2>"${fixture_root}/commit-uninstall.err"; then exit 137; fi
grep -q 'Uninstall commit failed' "${fixture_root}/commit-uninstall.err"
[[ -d "${destination_app}" ]]
env "${common_env[@]}" "${root_helper}" uninstall hardcleanup1 "${cdhash}" >/dev/null
env "${common_env[@]}" "${root_helper}" commit-uninstall hardcleanup1 "${cdhash}" >/dev/null

# Failures and hard kills after the first commit mutation remain exactly rollback-recoverable.
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_FAIL_AT=commit-install-after-state "${workflow}" install >/dev/null 2>"${fixture_root}/commit-install-after.err"; then exit 138; fi
grep -q 'Install commit failed' "${fixture_root}/commit-install-after.err"
[[ ! -e "${destination_app}" && ! -e "${state_root}/installed.state" ]]
env "${common_env[@]}" "${workflow}" install >/dev/null
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_FAIL_AT=commit-uninstall-after-state "${workflow}" uninstall >/dev/null 2>"${fixture_root}/commit-uninstall-after.err"; then exit 139; fi
grep -q 'Uninstall commit failed' "${fixture_root}/commit-uninstall-after.err"
[[ -d "${destination_app}" ]] && grep -q '^phase=committed$' "${state_root}/installed.state"
env "${common_env[@]}" "${workflow}" uninstall >/dev/null

if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_KILL_AT=commit-install-after-state "${workflow}" install >/dev/null 2>"${fixture_root}/commit-install-kill.err"; then exit 140; fi
grep -q 'Install commit failed' "${fixture_root}/commit-install-kill.err"
[[ ! -e "${destination_app}" && ! -e "${state_root}/installed.state" && ! -e "${state_root}/operation.lock" ]]
env "${common_env[@]}" "${workflow}" install >/dev/null
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_KILL_AT=commit-uninstall-after-state "${workflow}" uninstall >/dev/null 2>"${fixture_root}/commit-uninstall-kill.err"; then exit 141; fi
grep -q 'Uninstall commit failed' "${fixture_root}/commit-uninstall-kill.err"
[[ -d "${destination_app}" && ! -e "${state_root}/operation.lock" ]] && grep -q '^phase=committed$' "${state_root}/installed.state"
env "${common_env[@]}" "${workflow}" uninstall >/dev/null

# Reinstall works; destination collisions, malformed artifacts, and locks fail closed.
env "${common_env[@]}" "${workflow}" install >/dev/null
env "${common_env[@]}" "${workflow}" uninstall >/dev/null

# Permission normalization never chmods through aliases, multiply linked files, or specials.
ln -s pilot-artifact-metadata "${source_app}/Contents/Resources/mode-alias"
if env "${common_env[@]}" "${root_helper}" install modealias1 "${source_app}" "${cdhash}" >/dev/null 2>"${fixture_root}/mode-alias.err"; then exit 142; fi
grep -q 'contains a symlink' "${fixture_root}/mode-alias.err"
rm "${source_app}/Contents/Resources/mode-alias"
ln "${source_app}/Contents/Resources/pilot-artifact-metadata" "${source_app}/Contents/Resources/mode-hardlink"
if env "${common_env[@]}" "${root_helper}" install modehard1 "${source_app}" "${cdhash}" >/dev/null 2>"${fixture_root}/mode-hardlink.err"; then exit 143; fi
grep -q 'multiply linked regular file' "${fixture_root}/mode-hardlink.err"
rm "${source_app}/Contents/Resources/mode-hardlink"
mkfifo "${source_app}/Contents/Resources/mode-special"
if env "${common_env[@]}" "${root_helper}" install modespecial1 "${source_app}" "${cdhash}" >/dev/null 2>"${fixture_root}/mode-special.err"; then exit 144; fi
grep -q 'special filesystem entry' "${fixture_root}/mode-special.err"
rm "${source_app}/Contents/Resources/mode-special"

sed -i '' 's/^aid=.*/aid=wrong/' "${source_app}/Contents/Resources/pilot-artifact-metadata"
if env "${common_env[@]}" "${workflow}" install >/dev/null 2>"${fixture_root}/metadata.err"; then exit 14; fi
grep -q 'artifact preflight' "${fixture_root}/metadata.err"
sed -i '' 's/^aid=.*/aid=A000000063504B43532D3135/' "${source_app}/Contents/Resources/pilot-artifact-metadata"
mkdir -p "${destination_app}"
if env "${common_env[@]}" "${root_helper}" install collision1 "${source_app}" "${cdhash}" >/dev/null 2>"${fixture_root}/collision.err"; then exit 15; fi
grep -q 'existing destination' "${fixture_root}/collision.err"
rm -rf "${destination_app}"
ln -s "${source_app}" "${destination_app}"
if env "${common_env[@]}" "${root_helper}" install collision2 "${source_app}" "${cdhash}" >/dev/null 2>&1; then exit 16; fi
rm "${destination_app}"
mkdir -p "${state_root}/operation.lock"
if env "${common_env[@]}" "${root_helper}" install locked001 "${source_app}" "${cdhash}" >/dev/null 2>"${fixture_root}/lock.err"; then exit 17; fi
grep -q 'Another lifecycle transaction' "${fixture_root}/lock.err"
rm -rf "${state_root}/operation.lock"

# Source mutation is detected after staging without publishing.
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_MUTATE_SOURCE_AFTER_COPY=1 "${root_helper}" install mutation1 "${source_app}" "${cdhash}" >/dev/null 2>"${fixture_root}/mutation.err"; then exit 18; fi
grep -q 'changed during publication' "${fixture_root}/mutation.err"
[[ ! -e "${destination_app}" ]]
set_fixture_host_hash "${source_app}" "${cdhash}"

# Signals after each filesystem mutation leave a recoverable explicit pending state.
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_INTERRUPT_AT=install-after-publish "${root_helper}" install signalinst "${source_app}" "${cdhash}" >/dev/null 2>&1; then exit 19; fi
grep -q '^phase=pending-install$' "${state_root}/installed.state"
# Archive collision refuses without moving the installed app.
mkdir "${state_root}/transactions/signalinst/DNIeTokenHost.app.failed-install"
if env "${common_env[@]}" "${root_helper}" rollback-install signalinst "${cdhash}" >/dev/null 2>&1; then exit 191; fi
[[ -d "${destination_app}" ]]
rmdir "${state_root}/transactions/signalinst/DNIeTokenHost.app.failed-install"
# A validated stale lock is adopted only by the exact pending rollback.
mkdir -m 700 "${state_root}/operation.lock"
live_start="fixture-process-$$"
{ print 'operation=interrupted-install'; print 'token=signalinst'; print "pid=$$"; print "process_start=${live_start}"; } > "${state_root}/operation.lock/owner"
chmod 600 "${state_root}/operation.lock/owner"
if env "${common_env[@]}" "${root_helper}" probe-rollback-install signalinst "${cdhash}" >/dev/null 2>&1; then exit 190; fi
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_PROCESS_LOOKUP_FAIL_PID=$$ "${root_helper}" probe-rollback-install signalinst "${cdhash}" >/dev/null 2>"${fixture_root}/live-lock-lookup.err"; then exit 189; fi
grep -q "start identity could not be established" "${fixture_root}/live-lock-lookup.err"
if env "${common_env[@]}" "${root_helper}" rollback-install signalinst "${cdhash}" >/dev/null 2>"${fixture_root}/live-lock.err"; then exit 192; fi
grep -q 'lock owner is still running' "${fixture_root}/live-lock.err"
{ print 'operation=interrupted-install'; print 'token=signalinst'; print 'pid=999999'; print 'process_start=dead-owner'; } > "${state_root}/operation.lock/owner"
chmod 600 "${state_root}/operation.lock/owner"
env "${common_env[@]}" "${root_helper}" rollback-install signalinst "${cdhash}" >/dev/null
[[ ! -e "${destination_app}" ]]
env "${common_env[@]}" "${root_helper}" install signalprep "${source_app}" "${cdhash}" >/dev/null
env "${common_env[@]}" "${root_helper}" commit-install signalprep "${cdhash}"
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_INTERRUPT_AT=uninstall-after-withdrawal "${root_helper}" uninstall signaluninst "${cdhash}" >/dev/null 2>&1; then exit 20; fi
grep -q '^phase=pending-uninstall$' "${state_root}/installed.state"
mkdir "${destination_app}"
print keep > "${destination_app}/foreign-sentinel"
if env "${common_env[@]}" "${root_helper}" rollback-uninstall signaluninst "${cdhash}" >/dev/null 2>&1; then exit 201; fi
[[ "$(<"${destination_app}/foreign-sentinel")" == keep && -d "${state_root}/transactions/signaluninst/DNIeTokenHost.app" ]]
rm -rf "${destination_app}"
mkdir -m 700 "${state_root}/operation.lock"
{ print 'operation=interrupted-uninstall'; print 'token=signaluninst'; print 'pid=999999'; print 'process_start=dead-owner'; } > "${state_root}/operation.lock/owner"
chmod 600 "${state_root}/operation.lock/owner"
env "${common_env[@]}" "${root_helper}" rollback-uninstall signaluninst "${cdhash}"
[[ -d "${destination_app}" && "$(stat -f %Lp "${destination_app}")" == 755 && "$(<"${fixture_root}/unrelated-sentinel")" == keep ]]

# SIGKILL before ownership-state transitions leaves an attributable lock and phase for bounded recovery.
env "${common_env[@]}" "${root_helper}" uninstall hardcleanup2 "${cdhash}" >/dev/null
env "${common_env[@]}" "${root_helper}" commit-uninstall hardcleanup2 "${cdhash}" >/dev/null
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_KILL_AT=install-after-claim "${root_helper}" install hardinst1 "${source_app}" "${cdhash}" >/dev/null 2>&1; then exit 202; fi
grep -q '^phase=publishing$' "${state_root}/transactions/hardinst1/transaction.state"
[[ -d "${state_root}/operation.lock" && -d "${destination_app}" ]]
env "${common_env[@]}" "${root_helper}" recover-interrupted hardinst1 "${cdhash}" | grep -q '^interrupted_recovery=publishing$'
[[ ! -e "${destination_app}" && ! -e "${state_root}/operation.lock" && -d "${state_root}/transactions/hardinst1/DNIeTokenHost.app.failed-interrupted" ]]

env "${common_env[@]}" "${root_helper}" install hardprep1 "${source_app}" "${cdhash}" >/dev/null
env "${common_env[@]}" "${root_helper}" commit-install hardprep1 "${cdhash}"
if env "${common_env[@]}" DNIE_LIFECYCLE_TEST_KILL_AT=uninstall-after-withdrawal "${root_helper}" uninstall harduninst1 "${cdhash}" >/dev/null 2>&1; then exit 203; fi
grep -q '^phase=withdrawing$' "${state_root}/transactions/harduninst1/transaction.state"
[[ -d "${state_root}/operation.lock" && ! -e "${destination_app}" && -d "${state_root}/transactions/harduninst1/DNIeTokenHost.app" ]]
env "${common_env[@]}" "${root_helper}" recover-interrupted harduninst1 "${cdhash}" | grep -q '^interrupted_recovery=withdrawing$'
grep -q '^phase=committed$' "${state_root}/installed.state"
[[ -d "${destination_app}" && "$(stat -f %Lp "${destination_app}")" == 755 && ! -e "${state_root}/operation.lock" ]]

print 'pilot_lifecycle_offline=pass'
