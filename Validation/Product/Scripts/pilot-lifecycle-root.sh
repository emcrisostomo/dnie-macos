#!/bin/zsh
set -euo pipefail

umask 077

fail() { print -u2 -- "$1"; exit "${2:-1}"; }

test_mode="${DNIE_LIFECYCLE_TEST_MODE:-0}"
if [[ "${test_mode}" == 1 ]]; then
  test_root="${DNIE_LIFECYCLE_TEST_ROOT:-}"
  (( EUID != 0 )) || fail "Lifecycle fixture mode must never run as root." 64
  [[ "${test_root}" == /private/tmp/dnie-pilot-lifecycle-test.* && -d "${test_root}" && ! -L "${test_root}" ]] ||
    fail "The lifecycle test root must be an isolated /private/tmp directory." 64
  [[ "${test_root:A}" == "${test_root}" && "${test_root}" != *'/../'* && "${test_root}" != *'/./'* &&
     "$(/usr/bin/stat -f %u "${test_root}")" == "${EUID}" ]] ||
    fail "The lifecycle fixture root is not canonical and owned by the invoking user." 64
  for test_directory in "${test_root}/Applications" "${test_root}/Library" "${test_root}/Library/Application Support"; do
    [[ -d "${test_directory}" && ! -L "${test_directory}" && "${test_directory:A}" == "${test_directory}" &&
       "$(/usr/bin/stat -f %u "${test_directory}")" == "${EUID}" ]] ||
      fail "A lifecycle fixture descendant is symlinked, noncanonical, or not owned by the invoking user." 64
  done
  destination="${test_root}/Applications/DNIeTokenHost.app"
  state_root="${test_root}/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle"
else
  (( EUID == 0 )) || fail "The lifecycle transaction helper must run as root."
  for variable in ${(k)parameters}; do
    [[ "${variable}" == DNIE_LIFECYCLE_* ]] || continue
    fail "Test-only lifecycle overrides are not accepted by the production transaction helper." 64
  done
  trusted_tools="/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle/trusted-tools"
  [[ "${0:A}" == "${trusted_tools}/pilot-lifecycle-root.sh" && "${0}" == "${0:A}" &&
     -f "${0}" && ! -L "${0}" && "$(/usr/bin/stat -f %u "${0}")" == 0 &&
     "$(/usr/bin/stat -f %Lp "${0}")" == 700 && "$(/usr/bin/stat -f %l "${0}")" == 1 &&
     -d "${trusted_tools}" && ! -L "${trusted_tools}" && "$(/usr/bin/stat -f %u "${trusted_tools}")" == 0 &&
     "$(/usr/bin/stat -f %Lp "${trusted_tools}")" == 700 ]] ||
    fail "Production lifecycle execution requires the exact root-owned digest-staged helper path." 77
  destination="/Applications/DNIeTokenHost.app"
  state_root="/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle"
  [[ -d /Applications && ! -L /Applications && -d '/Library/Application Support' && ! -L '/Library/Application Support' ]] ||
    fail "A production lifecycle parent is missing or is a symlink."
fi

script_dir="${0:A:h}"
inspector="${script_dir}/inspect-pilot-artifact.sh"
state_file="${state_root}/installed.state"
lock="${state_root}/operation.lock"
transactions="${state_root}/transactions"

state_value() { /usr/bin/awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$2"; }
process_start_identity() {
  local pid="$1"
  if [[ "${test_mode}" == 1 ]]; then
    [[ "${DNIE_LIFECYCLE_TEST_PROCESS_LOOKUP_FAIL_PID:-}" != "${pid}" ]] || return 1
    print -r -- "fixture-process-${pid}"
  else /bin/ps -p "${pid}" -o lstart= 2>/dev/null | /usr/bin/sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; fi
}
inspect_cdhash() {
  if [[ "${test_mode}" == 1 ]]; then
    local output
    output="$("${inspector}" "$1")" || return 1
    print -r -- "${output}" | /usr/bin/sed -n 's/^artifact_cdhash=//p'
  else
    /usr/bin/codesign --verify --deep --strict "$1" >/dev/null 2>&1 || return 1
    { /usr/bin/codesign --display --verbose=4 "$1" 2>&1 || return 1; } | /usr/bin/sed -n 's/^CDHash=//p' | /usr/bin/head -n 1
  fi
}
require_exact_field_order() {
  local file="$1"; shift
  local -a expected actual
  local line
  [[ -f "${file}" && ! -L "${file}" ]] || return 1
  [[ "$(/usr/bin/tail -c 1 "${file}" | /usr/bin/od -An -tuC | /usr/bin/tr -d ' ')" == 10 ]] || return 1
  expected=("$@")
  actual=()
  while IFS= read -r line; do
    [[ "${line}" == [a-z0-9_]*=* && "${line#*=}" != "" ]] || return 1
    actual+=("${line%%=*}")
  done < "${file}"
  [[ ${#actual} -eq ${#expected} ]] || return 1
  local index
  for (( index = 1; index <= ${#expected}; index++ )); do
    [[ "${actual[index]}" == "${expected[index]}" ]] || return 1
  done
}
require_strict_committed_state() {
  require_exact_field_order "${state_file}" host_id extension_id cdhash phase token ||
    fail "The committed ownership state does not have the exact five-field shape."
  [[ "$(/usr/bin/stat -f %u "${state_file}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${state_file}")" == 600 && "$(/usr/bin/stat -f %l "${state_file}")" == 1 &&
     "$(state_value host_id "${state_file}")" == org.dniemacos.dnietoken &&
     "$(state_value extension_id "${state_file}")" == org.dniemacos.dnietoken.tokenextension &&
     "$(state_value cdhash "${state_file}")" =~ '^[[:xdigit:]]{40}$' &&
     "$(state_value phase "${state_file}")" == committed ]] ||
    fail "The committed ownership state is malformed or unsafe."
  valid_token "$(state_value token "${state_file}")" || fail "The committed ownership token is malformed."
}
upgrade_pair_fields=(
  old_artifact_verification old_host_bundle_identifier old_extension_bundle_identifier
  old_host_marketing_version old_host_build_version old_extension_marketing_version
  old_extension_build_version old_host_cdhash old_extension_cdhash old_artifact_cdhash
  old_artifact_team_pairing old_credential_asset_count old_credential_private_key_binding
  old_credential_asset_value_logged new_artifact_verification new_host_bundle_identifier
  new_extension_bundle_identifier new_host_marketing_version new_host_build_version
  new_extension_marketing_version new_extension_build_version new_host_cdhash
  new_extension_cdhash new_artifact_cdhash new_artifact_team_pairing
  new_credential_asset_count new_credential_private_key_binding
  new_credential_asset_value_logged upgrade_pair_verification upgrade_pair_team_match
)
journal_fields=(
  journal_version token phase old_state_host_id old_state_extension_id old_state_cdhash
  old_state_phase old_state_token old_state_sha256 saved_state_path saved_state_inode destination_path candidate_path
  transaction_path archive_path staging_path release_receipt_path destination_inode
  candidate_inode state_inode staging_inode staging_verification archive_retention_dependency archive_retention_owner
  archive_retention_scope archive_disposition_trigger rollback_predecessor_phase
  rollback_predecessor_topology rollback_predecessor_operation "${upgrade_pair_fields[@]}"
)
require_upgrade_pair_output() {
  local output="$1"
  require_exact_field_order "${output}" "${upgrade_pair_fields[@]}" ||
    fail "Trusted upgrade-pair inspection returned a missing, duplicate, unknown, or reordered field."
  [[ "$(state_value old_artifact_verification "${output}")" == pass &&
     "$(state_value old_host_bundle_identifier "${output}")" == org.dniemacos.dnietoken &&
     "$(state_value old_extension_bundle_identifier "${output}")" == org.dniemacos.dnietoken.tokenextension &&
     "$(state_value old_host_marketing_version "${output}")" == 0.1.0 &&
     "$(state_value old_host_build_version "${output}")" == 1 &&
     "$(state_value old_extension_marketing_version "${output}")" == 0.1.0 &&
     "$(state_value old_extension_build_version "${output}")" == 1 &&
     "$(state_value old_artifact_team_pairing "${output}")" == pass &&
     "$(state_value new_artifact_verification "${output}")" == pass &&
     "$(state_value new_host_bundle_identifier "${output}")" == org.dniemacos.dnietoken &&
     "$(state_value new_extension_bundle_identifier "${output}")" == org.dniemacos.dnietoken.tokenextension &&
     "$(state_value new_host_marketing_version "${output}")" == 0.1.1 &&
     "$(state_value new_host_build_version "${output}")" == 2 &&
     "$(state_value new_extension_marketing_version "${output}")" == 0.1.1 &&
     "$(state_value new_extension_build_version "${output}")" == 2 &&
     "$(state_value new_artifact_team_pairing "${output}")" == pass &&
     "$(state_value upgrade_pair_verification "${output}")" == pass &&
     "$(state_value upgrade_pair_team_match "${output}")" == pass ]] ||
    fail "Trusted upgrade-pair inspection did not return the fixed accepted tuple."
  local field
  for field in old_host_cdhash old_extension_cdhash old_artifact_cdhash new_host_cdhash new_extension_cdhash new_artifact_cdhash; do
    [[ "$(state_value "${field}" "${output}")" =~ '^[[:xdigit:]]{40}$' ]] ||
      fail "Trusted upgrade-pair inspection returned a malformed artifact identity."
  done
}
require_upgrade_journal() {
  local journal="${transaction}/upgrade.journal" pair_field
  [[ -d "${state_root}" && ! -L "${state_root}" && "${state_root:A}" == "${state_root}" &&
     "$(/usr/bin/stat -f %u "${state_root}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${state_root}")" == 700 &&
     -d "${transactions}" && ! -L "${transactions}" && "${transactions:A}" == "${transactions}" &&
     "$(/usr/bin/stat -f %u "${transactions}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${transactions}")" == 700 &&
     -d "${transaction}" && ! -L "${transaction}" && "${transaction:A}" == "${transaction}" &&
     "$(/usr/bin/stat -f %u "${transaction}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${transaction}")" == 700 &&
     -f "${journal}" && ! -L "${journal}" && "$(/usr/bin/stat -f %u "${journal}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${journal}")" == 600 && "$(/usr/bin/stat -f %l "${journal}")" == 1 ]] ||
    fail "The retained upgrade journal topology is unsafe."
  require_exact_field_order "${journal}" "${journal_fields[@]}" ||
    fail "The retained upgrade journal has a missing, duplicate, unknown, or reordered field."
  [[ "$(state_value journal_version "${journal}")" == 1 &&
     "$(state_value token "${journal}")" == "${token}" &&
     ( "$(state_value phase "${journal}")" == copying || "$(state_value phase "${journal}")" == old-retained ||
       "$(state_value phase "${journal}")" == rollback-armed ) &&
     "$(state_value old_state_host_id "${journal}")" == org.dniemacos.dnietoken &&
     "$(state_value old_state_extension_id "${journal}")" == org.dniemacos.dnietoken.tokenextension &&
     "$(state_value old_state_phase "${journal}")" == committed &&
     "$(state_value saved_state_path "${journal}")" == "${transaction}/old-installed.state" &&
     "$(state_value destination_path "${journal}")" == "${destination}" &&
     "$(state_value transaction_path "${journal}")" == "${transaction}" &&
     "$(state_value archive_path "${journal}")" == "${transaction}/DNIeTokenHost.app.old" &&
     "$(state_value staging_path "${journal}")" == "${transaction}/DNIeTokenHost.app.staging" &&
     "$(state_value release_receipt_path "${journal}")" == "${transaction}/operation.lock.released" &&
     "$(state_value archive_retention_dependency "${journal}")" == upgrade-recovery &&
     "$(state_value archive_retention_owner "${journal}")" == pilot-lifecycle-root &&
     "$(state_value archive_retention_scope "${journal}")" == local-fixture-only &&
     "$(state_value archive_disposition_trigger "${journal}")" == terminal-review ]] ||
    fail "The retained upgrade journal contains an invalid fixed field."
  if [[ "$(state_value phase "${journal}")" == rollback-armed ]]; then
    case "$(state_value rollback_predecessor_phase "${journal}"):$(state_value rollback_predecessor_topology "${journal}"):$(state_value rollback_predecessor_operation "${journal}")" in
      copying:copying-before-move:upgrade-old-retention-armed|\
      copying:copying-after-move:upgrade-old-retention-armed|\
      old-retained:old-retained-armed:upgrade-old-retention-armed|\
      old-retained:old-retained-terminal:upgrade-old-retained) ;;
      *) fail "The retained upgrade journal has invalid rollback ancestry." ;;
    esac
  else
    [[ "$(state_value rollback_predecessor_phase "${journal}")" == none &&
       "$(state_value rollback_predecessor_topology "${journal}")" == none &&
       "$(state_value rollback_predecessor_operation "${journal}")" == none ]] ||
      fail "The retained upgrade journal has unexpected rollback ancestry."
  fi
  case "$(state_value staging_verification "${journal}")" in
    absent)
      [[ "$(state_value staging_inode "${journal}")" == absent ]] ||
        fail "The retained upgrade journal has an inconsistent staging substate."
      ;;
    copying-unverified|verified)
      [[ "$(state_value staging_inode "${journal}")" == <-> &&
         "$(state_value staging_inode "${journal}")" -gt 0 ]] ||
        fail "The retained upgrade journal has an inconsistent staging substate."
      ;;
    *) fail "The retained upgrade journal has an invalid staging substate." ;;
  esac
  valid_token "$(state_value old_state_token "${journal}")" || fail "The saved ownership token is malformed."
  [[ "$(state_value old_state_cdhash "${journal}")" =~ '^[[:xdigit:]]{40}$' &&
     "$(state_value old_state_sha256 "${journal}")" =~ '^[[:xdigit:]]{64}$' ]] ||
    fail "The saved ownership identity or fingerprint is malformed."
  for pair_field in "${upgrade_pair_fields[@]}"; do
    [[ -n "$(state_value "${pair_field}" "${journal}")" ]] || fail "The retained inspection tuple is incomplete."
  done
}
require_retained_upgrade_lock() {
  local expected_operation="${1:-}" allow_current="${2:-0}" owner="${lock}/owner" owner_pid owner_start current_start operation
  local claim="${lock}/upgrade-adoption.claim" claim_owner="${lock}/upgrade-adoption.claim/owner"
  [[ -d "${lock}" && ! -L "${lock}" && "$(/usr/bin/stat -f %u "${lock}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${lock}")" == 700 &&
     -f "${owner}" && ! -L "${owner}" && "$(/usr/bin/stat -f %u "${owner}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${owner}")" == 600 && "$(/usr/bin/stat -f %l "${owner}")" == 1 ]] ||
    fail "The retained upgrade lock topology is unsafe."
  require_exact_field_order "${owner}" operation token pid process_start retained ||
    fail "The retained upgrade lock owner is missing, duplicated, unknown, or ownerless."
  operation="$(state_value operation "${owner}")"
  [[ ( "${operation}" == upgrade-copying-prepared || "${operation}" == upgrade-copying-staging ||
       "${operation}" == upgrade-copying-verified ) &&
     ( -z "${expected_operation}" || "${operation}" == "${expected_operation}" ) &&
     "$(state_value token "${owner}")" == "${token}" && "$(state_value retained "${owner}")" == true ]] ||
    fail "The retained upgrade lock is foreign or malformed."
  if [[ "${operation}" == upgrade-copying-prepared ]]; then
    [[ ! -e "${claim}" && ! -L "${claim}" ]] || fail "The upgrade staging adoption claim already exists."
  else
    [[ -d "${claim}" && ! -L "${claim}" && "$(/usr/bin/stat -f %u "${claim}")" == "${EUID}" &&
       "$(/usr/bin/stat -f %Lp "${claim}")" == 700 && -f "${claim_owner}" && ! -L "${claim_owner}" &&
       "$(/usr/bin/stat -f %u "${claim_owner}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${claim_owner}")" == 600 &&
       "$(/usr/bin/stat -f %l "${claim_owner}")" == 1 ]] || fail "The upgrade staging adoption claim is unsafe."
    require_exact_field_order "${claim_owner}" token pid process_start predecessor_operation retained ||
      fail "The upgrade staging adoption claim is malformed."
    [[ "$(state_value token "${claim_owner}")" == "${token}" &&
       "$(state_value pid "${claim_owner}")" == "$(state_value pid "${owner}")" &&
       "$(state_value process_start "${claim_owner}")" == "$(state_value process_start "${owner}")" &&
       "$(state_value predecessor_operation "${claim_owner}")" == upgrade-copying-prepared &&
       "$(state_value retained "${claim_owner}")" == true ]] || fail "The upgrade staging adoption claim is foreign or inconsistent."
  fi
  owner_pid="$(state_value pid "${owner}")"; owner_start="$(state_value process_start "${owner}")"
  [[ "${owner_pid}" == <-> && "${owner_pid}" -gt 0 && -n "${owner_start}" ]] ||
    fail "The retained upgrade lock has no exact owner identity."
  if kill -0 "${owner_pid}" 2>/dev/null; then
    current_start="$(process_start_identity "${owner_pid}" || true)"
    [[ -n "${current_start}" ]] || fail "The retained upgrade lock owner's start identity could not be established."
    [[ "${current_start}" != "${owner_start}" || ( "${allow_current}" == 1 && "${owner_pid}" == $$ ) ]] ||
      fail "The retained upgrade lock owner is still running."
  fi
}
retain_upgrade_lock_as() {
  local operation="$1" owner_start owner_new="${lock}/owner.new" owner="${lock}/owner"
  local claim="${lock}/upgrade-adoption.claim" claim_owner="${lock}/upgrade-adoption.claim/owner"
  local prior_inode prior_sha
  owner_start="$(process_start_identity $$)"
  if [[ "${operation}" == upgrade-copying-staging ]]; then
    prior_inode="$(/usr/bin/stat -f %i "${owner}")"
    prior_sha="$(/usr/bin/shasum -a 256 "${owner}" | /usr/bin/awk '{print $1}')"
    /bin/mkdir -m 700 "${claim}" 2>/dev/null || fail "The upgrade staging adoption claim already exists."
    { print -r -- "token=${token}"; print -r -- "pid=$$"; print -r -- "process_start=${owner_start}";
      print 'predecessor_operation=upgrade-copying-prepared'; print 'retained=true'; } > "${claim_owner}"
    /bin/chmod 600 "${claim_owner}"
    [[ "$(/usr/bin/stat -f %i "${owner}")" == "${prior_inode}" &&
       "$(/usr/bin/shasum -a 256 "${owner}" | /usr/bin/awk '{print $1}')" == "${prior_sha}" ]] ||
      fail "The retained upgrade lock changed while claiming adoption."
    require_exact_field_order "${owner}" operation token pid process_start retained ||
      fail "The retained upgrade lock changed while claiming adoption."
    [[ "$(state_value operation "${owner}")" == upgrade-copying-prepared &&
       "$(state_value token "${owner}")" == "${token}" ]] ||
      fail "The retained upgrade lock changed while claiming adoption."
    require_upgrade_journal
  else
    require_retained_upgrade_lock upgrade-copying-staging 1
    [[ "$(state_value pid "${claim_owner}")" == $$ &&
       "$(state_value process_start "${claim_owner}")" == "${owner_start}" ]] ||
      fail "The upgrade staging adoption claim is not owned by this exact executor."
  fi
  [[ -n "${owner_start}" && ! -e "${owner_new}" && ! -L "${owner_new}" ]] ||
    fail "The retained upgrade lock adoption target is unsafe."
  { print -r -- "operation=${operation}"; print -r -- "token=${token}"; print -r -- "pid=$$";
    print -r -- "process_start=${owner_start}"; print 'retained=true'; } > "${owner_new}"
  /bin/chmod 600 "${owner_new}"
  /bin/mv "${owner_new}" "${lock}/owner"
  lock_retained=1
}
require_fixture_artifacts_inactive() {
  local activity
  for activity in "${DNIE_LIFECYCLE_TEST_OLD_ACTIVITY:-unknown}" \
    "${DNIE_LIFECYCLE_TEST_CANDIDATE_ACTIVITY:-unknown}" \
    "${DNIE_LIFECYCLE_TEST_STAGING_ACTIVITY:-unknown}"; do
    [[ "${activity}" == inactive ]] || fail "Fixture artifact activity is active or unknown; old retention is forbidden."
  done
}
claim_old_retention_transition() {
  local owner="${lock}/owner" claim="${lock}/upgrade-old-retention.claim"
  local claim_owner="${lock}/upgrade-old-retention.claim/owner" owner_start prior_inode prior_sha
  require_retained_upgrade_lock upgrade-copying-verified
  require_upgrade_journal
  [[ "$(state_value phase "${transaction}/upgrade.journal")" == copying ]] ||
    fail "Old retention requires the exact copying-phase journal."
  prior_inode="$(/usr/bin/stat -f %i "${owner}")"
  prior_sha="$(/usr/bin/shasum -a 256 "${owner}" | /usr/bin/awk '{print $1}')"
  owner_start="$(process_start_identity $$)"
  [[ -n "${owner_start}" ]] || fail "The old-retention executor identity is unavailable."
  /bin/mkdir -m 700 "${claim}" 2>/dev/null || fail "The old-retention transition claim already exists."
  {
    print -r -- "token=${token}"
    print -r -- "pid=$$"
    print -r -- "process_start=${owner_start}"
    print 'predecessor_operation=upgrade-copying-verified'
    print -r -- "predecessor_owner_pid=$(state_value pid "${owner}")"
    print -r -- "predecessor_owner_start=$(state_value process_start "${owner}")"
    print -r -- "predecessor_owner_inode=${prior_inode}"
    print -r -- "predecessor_owner_sha256=${prior_sha}"
    print -r -- "destination_inode=$(state_value destination_inode "${transaction}/upgrade.journal")"
    print -r -- "archive_path=${transaction}/DNIeTokenHost.app.old"
    print 'retained=true'
  } > "${claim_owner}"
  /bin/chmod 600 "${claim_owner}"
  [[ "$(/usr/bin/stat -f %i "${owner}")" == "${prior_inode}" &&
     "$(/usr/bin/shasum -a 256 "${owner}" | /usr/bin/awk '{print $1}')" == "${prior_sha}" ]] ||
    fail "The verified staging reservation changed while claiming old retention."
  require_retained_upgrade_lock upgrade-copying-verified
  [[ ! -e "${lock}/owner.new" && ! -L "${lock}/owner.new" ]] ||
    fail "The old-retention owner target is unsafe."
  { print 'operation=upgrade-old-retention-armed'; print -r -- "token=${token}"; print -r -- "pid=$$";
    print -r -- "process_start=${owner_start}"; print 'retained=true'; } > "${lock}/owner.new"
  /bin/chmod 600 "${lock}/owner.new"
  /bin/mv "${lock}/owner.new" "${owner}"
  lock_retained=1
}
require_old_retention_claim() {
  local expected_operation="$1" allow_current="${2:-0}" owner="${lock}/owner" claim="${lock}/upgrade-old-retention.claim"
  local claim_owner="${claim}/owner" staging_claim_owner="${lock}/upgrade-adoption.claim/owner"
  local staging_claim="${lock}/upgrade-adoption.claim"
  local owner_pid owner_start current_start
  [[ -d "${lock}" && ! -L "${lock}" && "$(/usr/bin/stat -f %u "${lock}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${lock}")" == 700 && -f "${owner}" && ! -L "${owner}" &&
     "$(/usr/bin/stat -f %u "${owner}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${owner}")" == 600 &&
     "$(/usr/bin/stat -f %l "${owner}")" == 1 && -d "${claim}" && ! -L "${claim}" &&
     "${claim:A}" == "${claim}" &&
     "$(/usr/bin/stat -f %u "${claim}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${claim}")" == 700 &&
     -f "${claim_owner}" && ! -L "${claim_owner}" && "$(/usr/bin/stat -f %u "${claim_owner}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${claim_owner}")" == 600 && "$(/usr/bin/stat -f %l "${claim_owner}")" == 1 ]] ||
    fail "The retained old-retention claim topology is unsafe."
  require_exact_field_order "${owner}" operation token pid process_start retained ||
    fail "The retained old-retention owner is malformed."
  require_exact_field_order "${claim_owner}" token pid process_start predecessor_operation predecessor_owner_pid \
    predecessor_owner_start predecessor_owner_inode predecessor_owner_sha256 destination_inode archive_path retained ||
    fail "The retained old-retention transition claim is malformed."
  [[ "$(state_value operation "${owner}")" == "${expected_operation}" &&
     "$(state_value token "${owner}")" == "${token}" && "$(state_value retained "${owner}")" == true &&
     "$(state_value token "${claim_owner}")" == "${token}" &&
     "$(state_value pid "${claim_owner}")" == "$(state_value pid "${owner}")" &&
     "$(state_value process_start "${claim_owner}")" == "$(state_value process_start "${owner}")" &&
     "$(state_value predecessor_operation "${claim_owner}")" == upgrade-copying-verified &&
     "$(state_value predecessor_owner_pid "${claim_owner}")" == <-> &&
     -n "$(state_value predecessor_owner_start "${claim_owner}")" &&
     "$(state_value predecessor_owner_inode "${claim_owner}")" == <-> &&
     "$(state_value predecessor_owner_sha256 "${claim_owner}")" =~ '^[[:xdigit:]]{64}$' &&
     "$(state_value destination_inode "${claim_owner}")" == "$(state_value destination_inode "${transaction}/upgrade.journal")" &&
     "$(state_value archive_path "${claim_owner}")" == "${transaction}/DNIeTokenHost.app.old" &&
     "$(state_value retained "${claim_owner}")" == true ]] ||
    fail "The retained old-retention claim is foreign or inconsistent."
  [[ -d "${staging_claim}" && ! -L "${staging_claim}" && "${staging_claim:A}" == "${staging_claim}" &&
     "$(/usr/bin/stat -f %u "${staging_claim}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${staging_claim}")" == 700 &&
     -f "${staging_claim_owner}" && ! -L "${staging_claim_owner}" &&
     "$(/usr/bin/stat -f %u "${staging_claim_owner}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${staging_claim_owner}")" == 600 &&
     "$(/usr/bin/stat -f %l "${staging_claim_owner}")" == 1 ]] ||
    fail "The predecessor staging claim topology is unsafe."
  [[ "$(/usr/bin/find "${claim}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 &&
     "$(/usr/bin/find "${staging_claim}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] ||
    fail "The old-retention claim ancestry contains an unexpected entry."
  require_exact_field_order "${staging_claim_owner}" token pid process_start predecessor_operation retained ||
    fail "The predecessor staging claim is malformed."
  [[ "$(state_value token "${staging_claim_owner}")" == "${token}" &&
     "$(state_value pid "${staging_claim_owner}")" == "$(state_value predecessor_owner_pid "${claim_owner}")" &&
     "$(state_value process_start "${staging_claim_owner}")" == "$(state_value predecessor_owner_start "${claim_owner}")" &&
     "$(state_value predecessor_operation "${staging_claim_owner}")" == upgrade-copying-prepared &&
     "$(state_value retained "${staging_claim_owner}")" == true ]] ||
    fail "The predecessor staging claim is foreign or inconsistent."
  owner_pid="$(state_value pid "${owner}")"; owner_start="$(state_value process_start "${owner}")"
  [[ "${owner_pid}" == <-> && "${owner_pid}" -gt 0 && -n "${owner_start}" ]] ||
    fail "The retained old-retention owner identity is incomplete."
  if kill -0 "${owner_pid}" 2>/dev/null; then
    current_start="$(process_start_identity "${owner_pid}" || true)"
    [[ -n "${current_start}" ]] || fail "The retained old-retention owner start identity is unavailable."
    [[ "${current_start}" != "${owner_start}" || ( "${allow_current}" == 1 && "${owner_pid}" == $$ ) ]] ||
      fail "The retained old-retention owner is still running."
  fi
}
write_upgrade_phase() {
  local phase="$1" journal="${transaction}/upgrade.journal" temporary="${transaction}/upgrade.journal.phase.$$"
  local field value
  require_upgrade_journal
  [[ "$(state_value phase "${journal}")" == copying ]] ||
    fail "Old retention can transition only from the exact copying phase."
  [[ "${phase}" == old-retained && ! -e "${temporary}" && ! -L "${temporary}" ]] ||
    fail "The upgrade phase transition target is unsafe."
  {
    for field in "${journal_fields[@]}"; do
      if [[ "${field}" == phase ]]; then value="${phase}"; else value="$(state_value "${field}" "${journal}")"; fi
      print -r -- "${field}=${value}"
    done
  } > "${temporary}"
  /bin/chmod 600 "${temporary}"
  require_exact_field_order "${temporary}" "${journal_fields[@]}" ||
    fail "The upgrade phase transition failed strict journal validation."
  /bin/mv "${temporary}" "${journal}"
  require_upgrade_journal
}
retain_old_retention_owner() {
  local owner_start="$(process_start_identity $$)"
  require_old_retention_claim upgrade-old-retention-armed 1
  [[ "$(state_value pid "${lock}/owner")" == $$ &&
     "$(state_value process_start "${lock}/owner")" == "${owner_start}" &&
     ! -e "${lock}/owner.new" && ! -L "${lock}/owner.new" ]] ||
    fail "The old-retention executor no longer owns the exact transition."
  { print 'operation=upgrade-old-retained'; print -r -- "token=${token}"; print -r -- "pid=$$";
    print -r -- "process_start=${owner_start}"; print 'retained=true'; } > "${lock}/owner.new"
  /bin/chmod 600 "${lock}/owner.new"
  /bin/mv "${lock}/owner.new" "${lock}/owner"
  lock_retained=1
}
require_upgrade_recovery_artifacts() {
  local topology="$1" candidate="$2" expected_state="$3" journal="${transaction}/upgrade.journal"
  local archive="${transaction}/DNIeTokenHost.app.old" staging="${transaction}/DNIeTokenHost.app.staging"
  local saved_state="${transaction}/old-installed.state" old_path field saved_sha
  require_upgrade_journal
  require_exact_field_order "${saved_state}" host_id extension_id cdhash phase token ||
    fail "The exact saved ownership-state bytes are malformed."
  [[ -f "${saved_state}" && ! -L "${saved_state}" && "$(/usr/bin/stat -f %u "${saved_state}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${saved_state}")" == 600 && "$(/usr/bin/stat -f %l "${saved_state}")" == 1 &&
     "$(/usr/bin/stat -f %i "${saved_state}")" == "$(state_value saved_state_inode "${journal}")" &&
     "$(state_value saved_state_path "${journal}")" == "${saved_state}" &&
     "$(state_value host_id "${saved_state}")" == "$(state_value old_state_host_id "${journal}")" &&
     "$(state_value extension_id "${saved_state}")" == "$(state_value old_state_extension_id "${journal}")" &&
     "$(state_value cdhash "${saved_state}")" == "$(state_value old_state_cdhash "${journal}")" &&
     "$(state_value phase "${saved_state}")" == "$(state_value old_state_phase "${journal}")" &&
     "$(state_value token "${saved_state}")" == "$(state_value old_state_token "${journal}")" ]] ||
    fail "The saved upgrade authority changed or is unsafe."
  saved_sha="$(/usr/bin/shasum -a 256 "${saved_state}" | /usr/bin/awk '{print $1}')"
  [[ "${saved_sha}" == "$(state_value old_state_sha256 "${journal}")" ]] ||
    fail "The saved upgrade fingerprint changed."
  case "${expected_state}" in
    committed)
      require_strict_committed_state
      /usr/bin/cmp -s "${state_file}" "${saved_state}" || fail "The committed state no longer matches the saved authority."
      [[ "$(/usr/bin/stat -f %i "${state_file}")" == "$(state_value state_inode "${journal}")" ]] ||
        fail "The committed ownership-state inode changed."
      ;;
    pending)
      require_exact_field_order "${state_file}" host_id extension_id cdhash phase token ||
        fail "The rollback-pending ownership state does not have the exact five-field shape."
      [[ "$(/usr/bin/stat -f %u "${state_file}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${state_file}")" == 600 &&
         "$(/usr/bin/stat -f %l "${state_file}")" == 1 ]] || fail "The rollback-pending ownership state is unsafe."
      owned_state_matches pending-upgrade-rollback "$(state_value old_state_cdhash "${journal}")" "${token}" ||
        fail "The rollback-pending ownership state is foreign or malformed."
      ;;
    *) fail "The recovery artifact state expectation is invalid." ;;
  esac
  [[ "$(state_value candidate_path "${journal}")" == "${candidate}" &&
     -d "${candidate}" && ! -L "${candidate}" && "$(/usr/bin/stat -f %i "${candidate}")" == "$(state_value candidate_inode "${journal}")" &&
     -d "${staging}" && ! -L "${staging}" && "$(/usr/bin/stat -f %i "${staging}")" == "$(state_value staging_inode "${journal}")" &&
     "$(state_value staging_verification "${journal}")" == verified &&
     ! -e "${transaction}/operation.lock.released" && ! -L "${transaction}/operation.lock.released" &&
     ! -e "${transaction}/transaction.state" && ! -L "${transaction}/transaction.state" ]] ||
    fail "The recovery candidate, staging, or retained path topology changed."
  case "${topology}" in
    copying-before-move)
      old_path="${destination}"
      [[ -d "${destination}" && ! -L "${destination}" && ! -e "${archive}" && ! -L "${archive}" ]] ||
        fail "The pre-move recovery joint topology is not eligible."
      ;;
    copying-after-move|old-retained-armed|old-retained-terminal)
      old_path="${archive}"
      [[ ! -e "${destination}" && ! -L "${destination}" && -d "${archive}" && ! -L "${archive}" ]] ||
        fail "The post-move recovery joint topology is not eligible."
      ;;
    *) fail "The recovery joint topology is not eligible." ;;
  esac
  [[ "$(/usr/bin/stat -f %u "${old_path}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${old_path}")" == 755 &&
     "$(/usr/bin/stat -f %i "${old_path}")" == "$(state_value destination_inode "${journal}")" ]] ||
    fail "The exact old artifact ownership or inode changed."
  require_normalizable_app_topology "${old_path}"
  require_normalizable_app_topology "${candidate}"
  require_normalizable_app_topology "${staging}"
  upgrade_probe_tmp="${transaction}/upgrade-pair.rollback-source.${upgrade_temp_suffix}"
  claim_upgrade_temp "${upgrade_probe_tmp}" "The rollback source inspection temporary collided."
  "${inspector}" --upgrade-pair "${old_path}" "${candidate}" > "${upgrade_probe_tmp}"
  /bin/chmod 600 "${upgrade_probe_tmp}"; require_upgrade_pair_output "${upgrade_probe_tmp}"
  for field in "${upgrade_pair_fields[@]}"; do
    [[ "$(state_value "${field}" "${journal}")" == "$(state_value "${field}" "${upgrade_probe_tmp}")" ]] ||
      fail "The recovery old/candidate tuple changed."
  done
  dispose_upgrade_temp
  upgrade_probe_tmp="${transaction}/upgrade-pair.rollback-staged.${upgrade_temp_suffix}"
  claim_upgrade_temp "${upgrade_probe_tmp}" "The rollback staged inspection temporary collided."
  "${inspector}" --upgrade-pair "${old_path}" "${staging}" > "${upgrade_probe_tmp}"
  /bin/chmod 600 "${upgrade_probe_tmp}"; require_upgrade_pair_output "${upgrade_probe_tmp}"
  for field in "${upgrade_pair_fields[@]}"; do
    [[ "$(state_value "${field}" "${journal}")" == "$(state_value "${field}" "${upgrade_probe_tmp}")" ]] ||
      fail "The recovery old/staged tuple changed."
  done
  dispose_upgrade_temp
}
classify_upgrade_recovery_entry() {
  local phase operation
  require_upgrade_journal
  phase="$(state_value phase "${transaction}/upgrade.journal")"
  operation="$(state_value operation "${lock}/owner" 2>/dev/null || true)"
  case "${phase}:${operation}" in
    copying:upgrade-old-retention-armed)
      require_old_retention_claim upgrade-old-retention-armed
      if [[ -d "${destination}" && ! -L "${destination}" && ! -e "${transaction}/DNIeTokenHost.app.old" && ! -L "${transaction}/DNIeTokenHost.app.old" ]]; then
        rollback_predecessor_topology=copying-before-move
      elif [[ ! -e "${destination}" && ! -L "${destination}" && -d "${transaction}/DNIeTokenHost.app.old" && ! -L "${transaction}/DNIeTokenHost.app.old" ]]; then
        rollback_predecessor_topology=copying-after-move
      else fail "The recovery joint topology is not eligible."
      fi
      ;;
    old-retained:upgrade-old-retention-armed)
      require_old_retention_claim upgrade-old-retention-armed
      rollback_predecessor_topology=old-retained-armed
      ;;
    old-retained:upgrade-old-retained)
      require_old_retention_claim upgrade-old-retained
      rollback_predecessor_topology=old-retained-terminal
      ;;
    *) fail "The retained upgrade phase and owner are not eligible for rollback arming." ;;
  esac
  rollback_predecessor_phase="${phase}"
  rollback_predecessor_operation="${operation}"
}
claim_upgrade_rollback_transition() {
  local owner="${lock}/owner" claim="${lock}/upgrade-rollback.claim" claim_owner
  local owner_inode owner_sha owner_start old_claim staging_claim old_claim_inode old_claim_sha staging_claim_inode staging_claim_sha
  local journal_tmp="${transaction}/upgrade.journal.rollback.${upgrade_temp_suffix}"
  local state_tmp="${state_file}.rollback.${upgrade_temp_suffix}" owner_tmp="${lock}/owner.rollback.${upgrade_temp_suffix}"
  claim_owner="${claim}/owner"
  old_claim="${lock}/upgrade-old-retention.claim/owner"; staging_claim="${lock}/upgrade-adoption.claim/owner"
  [[ ! -e "${journal_tmp}" && ! -L "${journal_tmp}" && ! -e "${state_tmp}" && ! -L "${state_tmp}" &&
     ! -e "${owner_tmp}" && ! -L "${owner_tmp}" && ! -e "${claim}" && ! -L "${claim}" ]] ||
    fail "The rollback metadata target is unsafe or already claimed."
  owner_inode="$(/usr/bin/stat -f %i "${owner}")"; owner_sha="$(/usr/bin/shasum -a 256 "${owner}" | /usr/bin/awk '{print $1}')"
  old_claim_inode="$(/usr/bin/stat -f %i "${old_claim}")"; old_claim_sha="$(/usr/bin/shasum -a 256 "${old_claim}" | /usr/bin/awk '{print $1}')"
  staging_claim_inode="$(/usr/bin/stat -f %i "${staging_claim}")"; staging_claim_sha="$(/usr/bin/shasum -a 256 "${staging_claim}" | /usr/bin/awk '{print $1}')"
  owner_start="$(process_start_identity $$)"; [[ -n "${owner_start}" ]] || fail "The rollback arming identity is unavailable."
  /bin/mkdir -m 700 "${claim}" 2>/dev/null || fail "The rollback transition intent is already claimed."
  {
    print -r -- "token=${token}"; print -r -- "pid=$$"; print -r -- "process_start=${owner_start}"
    print -r -- "predecessor_operation=${rollback_predecessor_operation}"
    print -r -- "predecessor_phase=${rollback_predecessor_phase}"
    print -r -- "predecessor_topology=${rollback_predecessor_topology}"
    print -r -- "predecessor_owner_pid=$(state_value pid "${owner}")"
    print -r -- "predecessor_owner_start=$(state_value process_start "${owner}")"
    print -r -- "predecessor_owner_inode=${owner_inode}"; print -r -- "predecessor_owner_sha256=${owner_sha}"
    print -r -- "old_claim_inode=${old_claim_inode}"; print -r -- "old_claim_sha256=${old_claim_sha}"
    print -r -- "staging_claim_inode=${staging_claim_inode}"; print -r -- "staging_claim_sha256=${staging_claim_sha}"
    print 'retained=true'
  } > "${claim_owner}"
  /bin/chmod 600 "${claim_owner}"
  [[ "$(/usr/bin/stat -f %i "${owner}")" == "${owner_inode}" &&
     "$(/usr/bin/shasum -a 256 "${owner}" | /usr/bin/awk '{print $1}')" == "${owner_sha}" ]] ||
    fail "The rollback predecessor owner changed while claiming intent."
  rollback_journal_tmp="${journal_tmp}"; rollback_state_tmp="${state_tmp}"; rollback_owner_tmp="${owner_tmp}"
}
require_upgrade_rollback_intent_pins() {
  local claim_dir="${lock}/upgrade-rollback.claim" claim="${lock}/upgrade-rollback.claim/owner"
  local old_claim="${lock}/upgrade-old-retention.claim/owner"
  local staging_claim="${lock}/upgrade-adoption.claim/owner"
  [[ -d "${claim_dir}" && ! -L "${claim_dir}" && "${claim_dir:A}" == "${claim_dir}" &&
     "$(/usr/bin/stat -f %u "${claim_dir}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${claim_dir}")" == 700 &&
     "$(/usr/bin/stat -f %l "${claim_dir}")" -ge 2 &&
     -f "${claim}" && ! -L "${claim}" && "$(/usr/bin/stat -f %u "${claim}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${claim}")" == 600 && "$(/usr/bin/stat -f %l "${claim}")" == 1 &&
     "$(/usr/bin/find "${claim_dir}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] ||
    fail "The rollback transition intent topology is unsafe."
  require_exact_field_order "${claim}" token pid process_start predecessor_operation predecessor_phase predecessor_topology \
    predecessor_owner_pid predecessor_owner_start predecessor_owner_inode predecessor_owner_sha256 old_claim_inode \
    old_claim_sha256 staging_claim_inode staging_claim_sha256 retained || fail "The rollback transition intent is malformed."
  [[ "$(/usr/bin/stat -f %i "${old_claim}")" == "$(state_value old_claim_inode "${claim}")" &&
     "$(/usr/bin/shasum -a 256 "${old_claim}" | /usr/bin/awk '{print $1}')" == "$(state_value old_claim_sha256 "${claim}")" &&
     "$(/usr/bin/stat -f %i "${staging_claim}")" == "$(state_value staging_claim_inode "${claim}")" &&
     "$(/usr/bin/shasum -a 256 "${staging_claim}" | /usr/bin/awk '{print $1}')" == "$(state_value staging_claim_sha256 "${claim}")" &&
     "$(state_value destination_inode "${old_claim}")" == "$(state_value destination_inode "${transaction}/upgrade.journal")" &&
     "$(state_value archive_path "${old_claim}")" == "${transaction}/DNIeTokenHost.app.old" &&
     "$(state_value predecessor_operation "${staging_claim}")" == upgrade-copying-prepared ]] ||
    fail "The pinned predecessor claim changed or is semantically inconsistent."
}
require_internal_rollback_executor() {
  local claim="${lock}/upgrade-rollback.claim/owner" executor_start
  executor_start="$(process_start_identity $$)"
  [[ -n "${executor_start}" && "$(state_value token "${claim}")" == "${token}" &&
     "$(state_value pid "${claim}")" == $$ && "$(state_value process_start "${claim}")" == "${executor_start}" &&
     "$(state_value predecessor_phase "${claim}")" == "${rollback_predecessor_phase}" &&
     "$(state_value predecessor_topology "${claim}")" == "${rollback_predecessor_topology}" &&
     "$(state_value predecessor_operation "${claim}")" == "${rollback_predecessor_operation}" ]] ||
    fail "The rollback transition intent is not bound to this exact executor and captured predecessor."
}
test_mutate_rollback_authority() {
  [[ "${test_mode}" == 1 && "${DNIE_LIFECYCLE_TEST_MUTATE_ROLLBACK_AT:-}" == "$1" ]] || return 0
  case "${DNIE_LIFECYCLE_TEST_ROLLBACK_MUTATION_KIND:-bytes}" in
    bytes) /usr/bin/perl -pi -e 's#^archive_path=.*#archive_path=/private/tmp/controlled-foreign-old.app#' \
      "${lock}/upgrade-old-retention.claim/owner" ;;
    intent-mode) /bin/chmod 755 "${lock}/upgrade-rollback.claim" ;;
    intent-extra) print preserve > "${lock}/upgrade-rollback.claim/unexpected" ;;
    intent-triple) /usr/bin/sed -i '' \
      -e 's/^predecessor_phase=copying$/predecessor_phase=old-retained/' \
      -e 's/^predecessor_topology=copying-before-move$/predecessor_topology=old-retained-terminal/' \
      -e 's/^predecessor_operation=upgrade-old-retention-armed$/predecessor_operation=upgrade-old-retained/' \
      "${lock}/upgrade-rollback.claim/owner" ;;
    journal-triple) /usr/bin/sed -i '' \
      -e 's/^rollback_predecessor_phase=copying$/rollback_predecessor_phase=old-retained/' \
      -e 's/^rollback_predecessor_topology=copying-before-move$/rollback_predecessor_topology=old-retained-terminal/' \
      -e 's/^rollback_predecessor_operation=upgrade-old-retention-armed$/rollback_predecessor_operation=upgrade-old-retained/' \
      "${transaction}/upgrade.journal" ;;
    old-mode) /bin/chmod 755 "${lock}/upgrade-old-retention.claim" ;;
    *) fail "The rollback authority mutation selector is invalid." ;;
  esac
}
inject_late_rollback_temp_collision() {
  local boundary="$1" path="$2"
  [[ "${test_mode}" == 1 && "${DNIE_LIFECYCLE_TEST_LATE_COLLISION_AT:-}" == "${boundary}" ]] || return 0
  case "${DNIE_LIFECYCLE_TEST_LATE_COLLISION_KIND:-regular}" in
    regular) print preserve > "${path}" ;;
    dangling) /bin/ln -s "${test_root}/late-collision-target-must-stay-absent" "${path}" ;;
    *) fail "The rollback late-collision selector is invalid." ;;
  esac
}
claim_rollback_metadata_temp() {
  local path="$1" message="$2"
  if ! ( setopt noclobber; : > "${path}" ) 2>/dev/null; then fail "${message}"; fi
  rollback_metadata_inode="$(/usr/bin/stat -f %i "${path}")"
  require_rollback_metadata_temp "${path}" "${rollback_metadata_inode}" "${message}"
}
require_rollback_metadata_temp() {
  local path="$1" expected_inode="$2" message="$3"
  [[ -f "${path}" && ! -L "${path}" && "$(/usr/bin/stat -f %u "${path}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${path}")" == 600 && "$(/usr/bin/stat -f %l "${path}")" == 1 &&
     "$(/usr/bin/stat -f %i "${path}")" == "${expected_inode}" ]] || fail "${message}"
}
test_mutate_rollback_temp_mode() {
  [[ "${test_mode}" == 1 && "${DNIE_LIFECYCLE_TEST_MUTATE_TEMP_MODE_AT:-}" == "$1" ]] || return 0
  /bin/chmod 644 "$2"
}
require_upgrade_rollback_prewrite() {
  local expected_phase="$1" expected_state="$2" expected_owner="$3" candidate="$4"
  local owner="${lock}/owner" claim="${lock}/upgrade-rollback.claim/owner"
  require_old_retention_claim "${expected_owner}"
  require_upgrade_rollback_intent_pins
  require_internal_rollback_executor
  [[ "$(state_value phase "${transaction}/upgrade.journal")" == "${expected_phase}" &&
     "$(state_value operation "${owner}")" == "${expected_owner}" && "$(state_value token "${owner}")" == "${token}" &&
     "$(/usr/bin/stat -f %i "${owner}")" == "$(state_value predecessor_owner_inode "${claim}")" &&
     "$(/usr/bin/shasum -a 256 "${owner}" | /usr/bin/awk '{print $1}')" == "$(state_value predecessor_owner_sha256 "${claim}")" ]] ||
    fail "The rollback metadata predecessor substate changed."
  if [[ "${expected_phase}" == rollback-armed ]]; then
    [[ "$(state_value rollback_predecessor_phase "${transaction}/upgrade.journal")" == "${rollback_predecessor_phase}" &&
       "$(state_value rollback_predecessor_topology "${transaction}/upgrade.journal")" == "${rollback_predecessor_topology}" &&
       "$(state_value rollback_predecessor_operation "${transaction}/upgrade.journal")" == "${rollback_predecessor_operation}" ]] ||
      fail "The advanced rollback journal ancestry is not bound to the captured predecessor."
  fi
  require_upgrade_recovery_artifacts "$(state_value predecessor_topology "${claim}")" "${candidate}" "${expected_state}"
}
write_upgrade_rollback_journal() {
  local journal="${transaction}/upgrade.journal" field value
  inject_late_rollback_temp_collision journal "${rollback_journal_tmp}"
  claim_rollback_metadata_temp "${rollback_journal_tmp}" "The rollback journal temporary is not exclusively claimable."
  {
    for field in "${journal_fields[@]}"; do
      case "${field}" in
        phase) value=rollback-armed ;;
        rollback_predecessor_phase) value="${rollback_predecessor_phase}" ;;
        rollback_predecessor_topology) value="${rollback_predecessor_topology}" ;;
        rollback_predecessor_operation) value="${rollback_predecessor_operation}" ;;
        *) value="$(state_value "${field}" "${journal}")" ;;
      esac
      print -r -- "${field}=${value}"
    done
  } >> "${rollback_journal_tmp}"
  /bin/chmod 600 "${rollback_journal_tmp}"
  test_mutate_rollback_temp_mode journal "${rollback_journal_tmp}"
  require_rollback_metadata_temp "${rollback_journal_tmp}" "${rollback_metadata_inode}" \
    "The rollback journal temporary identity or topology changed."
  require_exact_field_order "${rollback_journal_tmp}" "${journal_fields[@]}" || fail "The rollback journal update failed strict validation."
  /bin/mv "${rollback_journal_tmp}" "${journal}"
  require_upgrade_journal
}
write_upgrade_rollback_state() {
  inject_late_rollback_temp_collision state "${rollback_state_tmp}"
  claim_rollback_metadata_temp "${rollback_state_tmp}" "The rollback state temporary is not exclusively claimable."
  { print 'host_id=org.dniemacos.dnietoken'; print 'extension_id=org.dniemacos.dnietoken.tokenextension';
    print -r -- "cdhash=$(state_value old_state_cdhash "${transaction}/upgrade.journal")"
    print 'phase=pending-upgrade-rollback'; print -r -- "token=${token}"; } >> "${rollback_state_tmp}"
  /bin/chmod 600 "${rollback_state_tmp}"
  test_mutate_rollback_temp_mode state "${rollback_state_tmp}"
  require_rollback_metadata_temp "${rollback_state_tmp}" "${rollback_metadata_inode}" \
    "The rollback state temporary identity or topology changed."
  require_exact_field_order "${rollback_state_tmp}" host_id extension_id cdhash phase token ||
    fail "The rollback-pending ownership state failed strict validation."
  /bin/sync; /bin/mv "${rollback_state_tmp}" "${state_file}"; /bin/sync
}
write_upgrade_rollback_owner() {
  local owner_start="$(process_start_identity $$)"
  inject_late_rollback_temp_collision owner "${rollback_owner_tmp}"
  claim_rollback_metadata_temp "${rollback_owner_tmp}" "The rollback owner temporary is not exclusively claimable."
  { print 'operation=upgrade-rollback-armed'; print -r -- "token=${token}"; print -r -- "pid=$$";
    print -r -- "process_start=${owner_start}"; print 'retained=true'; } >> "${rollback_owner_tmp}"
  /bin/chmod 600 "${rollback_owner_tmp}"
  test_mutate_rollback_temp_mode owner "${rollback_owner_tmp}"
  require_rollback_metadata_temp "${rollback_owner_tmp}" "${rollback_metadata_inode}" \
    "The rollback owner temporary identity or topology changed."
  /bin/mv "${rollback_owner_tmp}" "${lock}/owner"
  lock_retained=1
}
require_upgrade_rollback_claim() {
  local owner="${lock}/owner" rollback_claim_dir="${lock}/upgrade-rollback.claim"
  local old_claim_dir="${lock}/upgrade-old-retention.claim" staging_claim_dir="${lock}/upgrade-adoption.claim"
  local claim="${lock}/upgrade-rollback.claim/owner"
  local old_claim="${lock}/upgrade-old-retention.claim/owner" staging_claim="${lock}/upgrade-adoption.claim/owner"
  local pid start current_start
  [[ -d "${lock}" && ! -L "${lock}" && "${lock:A}" == "${lock}" &&
     "$(/usr/bin/stat -f %u "${lock}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${lock}")" == 700 &&
     "$(/usr/bin/stat -f %l "${lock}")" -ge 2 &&
     -d "${rollback_claim_dir}" && ! -L "${rollback_claim_dir}" && "${rollback_claim_dir:A}" == "${rollback_claim_dir}" &&
     "$(/usr/bin/stat -f %u "${rollback_claim_dir}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${rollback_claim_dir}")" == 700 &&
     "$(/usr/bin/stat -f %l "${rollback_claim_dir}")" -ge 2 &&
     -d "${old_claim_dir}" && ! -L "${old_claim_dir}" && "${old_claim_dir:A}" == "${old_claim_dir}" &&
     "$(/usr/bin/stat -f %u "${old_claim_dir}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${old_claim_dir}")" == 700 &&
     "$(/usr/bin/stat -f %l "${old_claim_dir}")" -ge 2 &&
     -d "${staging_claim_dir}" && ! -L "${staging_claim_dir}" && "${staging_claim_dir:A}" == "${staging_claim_dir}" &&
     "$(/usr/bin/stat -f %u "${staging_claim_dir}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${staging_claim_dir}")" == 700 &&
     "$(/usr/bin/stat -f %l "${staging_claim_dir}")" -ge 2 &&
     -f "${owner}" && ! -L "${owner}" && "$(/usr/bin/stat -f %u "${owner}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${owner}")" == 600 && "$(/usr/bin/stat -f %l "${owner}")" == 1 &&
     -f "${claim}" && ! -L "${claim}" && "$(/usr/bin/stat -f %u "${claim}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${claim}")" == 600 && "$(/usr/bin/stat -f %l "${claim}")" == 1 &&
     -f "${old_claim}" && ! -L "${old_claim}" && "$(/usr/bin/stat -f %u "${old_claim}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${old_claim}")" == 600 && "$(/usr/bin/stat -f %l "${old_claim}")" == 1 &&
     -f "${staging_claim}" && ! -L "${staging_claim}" && "$(/usr/bin/stat -f %u "${staging_claim}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${staging_claim}")" == 600 && "$(/usr/bin/stat -f %l "${staging_claim}")" == 1 ]] ||
    fail "The rollback claim ancestry topology is unsafe."
  [[ "$(/usr/bin/find "${rollback_claim_dir}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 &&
     "$(/usr/bin/find "${old_claim_dir}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 &&
     "$(/usr/bin/find "${staging_claim_dir}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] ||
    fail "The rollback claim ancestry contains an unexpected entry."
  require_exact_field_order "${owner}" operation token pid process_start retained || fail "The rollback owner is malformed."
  require_exact_field_order "${claim}" token pid process_start predecessor_operation predecessor_phase predecessor_topology \
    predecessor_owner_pid predecessor_owner_start predecessor_owner_inode predecessor_owner_sha256 old_claim_inode \
    old_claim_sha256 staging_claim_inode staging_claim_sha256 retained ||
    fail "The rollback transition intent is malformed."
  require_exact_field_order "${old_claim}" token pid process_start predecessor_operation predecessor_owner_pid \
    predecessor_owner_start predecessor_owner_inode predecessor_owner_sha256 destination_inode archive_path retained ||
    fail "The retained old-transition ancestry is malformed."
  require_exact_field_order "${staging_claim}" token pid process_start predecessor_operation retained ||
    fail "The retained staging ancestry is malformed."
  [[ "$(state_value operation "${owner}")" == upgrade-rollback-armed && "$(state_value token "${owner}")" == "${token}" &&
     "$(state_value retained "${owner}")" == true && "$(state_value token "${claim}")" == "${token}" &&
     "$(state_value pid "${claim}")" == "$(state_value pid "${owner}")" &&
     "$(state_value process_start "${claim}")" == "$(state_value process_start "${owner}")" &&
     "$(state_value predecessor_phase "${claim}")" == "$(state_value rollback_predecessor_phase "${transaction}/upgrade.journal")" &&
     "$(state_value predecessor_topology "${claim}")" == "$(state_value rollback_predecessor_topology "${transaction}/upgrade.journal")" &&
     "$(state_value predecessor_operation "${claim}")" == "$(state_value rollback_predecessor_operation "${transaction}/upgrade.journal")" &&
     "$(state_value predecessor_owner_pid "${claim}")" == "$(state_value pid "${old_claim}")" &&
     "$(state_value predecessor_owner_start "${claim}")" == "$(state_value process_start "${old_claim}")" &&
     "$(state_value predecessor_owner_inode "${claim}")" == <-> &&
     "$(state_value predecessor_owner_sha256 "${claim}")" =~ '^[[:xdigit:]]{64}$' &&
     "$(state_value predecessor_operation "${old_claim}")" == upgrade-copying-verified &&
     "$(state_value destination_inode "${old_claim}")" == "$(state_value destination_inode "${transaction}/upgrade.journal")" &&
     "$(state_value archive_path "${old_claim}")" == "${transaction}/DNIeTokenHost.app.old" &&
     "$(state_value predecessor_owner_pid "${old_claim}")" == "$(state_value pid "${staging_claim}")" &&
     "$(state_value predecessor_owner_start "${old_claim}")" == "$(state_value process_start "${staging_claim}")" &&
     "$(state_value predecessor_operation "${staging_claim}")" == upgrade-copying-prepared &&
     "$(state_value token "${old_claim}")" == "${token}" && "$(state_value token "${staging_claim}")" == "${token}" &&
     "$(state_value retained "${claim}")" == true && "$(state_value retained "${old_claim}")" == true &&
     "$(state_value retained "${staging_claim}")" == true ]] || fail "The rollback claim ancestry is foreign or inconsistent."
  require_upgrade_rollback_intent_pins
  for pid_start in "$(state_value predecessor_owner_pid "${claim}"):$(state_value predecessor_owner_start "${claim}")" \
    "$(state_value pid "${owner}"):$(state_value process_start "${owner}")"; do
    pid="${pid_start%%:*}"; start="${pid_start#*:}"
    [[ "${pid}" == <-> && "${pid}" -gt 0 && -n "${start}" ]] || fail "The rollback claim has an incomplete owner identity."
    if kill -0 "${pid}" 2>/dev/null; then
      current_start="$(process_start_identity "${pid}" || true)"; [[ -n "${current_start}" ]] || fail "A rollback owner start identity is unavailable."
      [[ "${current_start}" != "${start}" ]] || fail "A rollback owner is still running."
    fi
  done
}
acquire_lock() {
  [[ ! -e "${state_root}" || ( -d "${state_root}" && ! -L "${state_root}" ) ]] || fail "The lifecycle state root is unsafe."
  state_parent="${state_root:h}"
  if [[ ! -e "${state_parent}" ]]; then /bin/mkdir "${state_parent}"; fi
  [[ -d "${state_parent}" && ! -L "${state_parent}" ]] || fail "The lifecycle state parent is unsafe."
  if [[ ! -e "${state_root}" ]]; then /bin/mkdir "${state_root}"; fi
  [[ -d "${state_root}" && ! -L "${state_root}" ]] || fail "The lifecycle state root is unsafe."
  if [[ "${2:-}" == direct ]]; then
    require_direct_state_scope
  else
    if [[ ! -e "${transactions}" ]]; then /bin/mkdir "${transactions}"; fi
    /bin/chmod 700 "${state_root}" "${transactions}"
    [[ "$(/usr/bin/stat -f %u "${state_parent}")" == "${EUID}" && "$(/usr/bin/stat -f %u "${state_root}")" == "${EUID}" &&
       "$(/usr/bin/stat -f %u "${transactions}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${state_root}")" == 700 &&
       "$(/usr/bin/stat -f %Lp "${transactions}")" == 700 ]] || fail "Lifecycle state ownership or modes are unsafe."
  fi
  /bin/mkdir "${lock}" 2>/dev/null || fail "Another lifecycle transaction or retained recovery lock exists. Use only the bounded recovery command after inspection."
  [[ "${2:-}" != direct ]] || lock_held=1
  owner_start="$(process_start_identity $$)"
  [[ -n "${owner_start}" ]] || fail "Unable to record lifecycle lock owner identity."
  { print -r -- "operation=$1"; print -r -- "token=${token}"; print -r -- "pid=$$"; print -r -- "process_start=${owner_start}"; } > "${lock}/owner"
  /bin/chmod 600 "${lock}/owner"
  lock_held=1
}
release_lock() { /bin/rm -f -- "${lock}/owner"; /bin/rmdir "${lock}"; lock_held=0; }
valid_token() { [[ "$1" =~ '^[0-9A-Za-z._-]{8,96}$' ]]; }
require_fixture_ancestors() {
  local path="$1" cursor="${1:h}"
  [[ "${path:A}" == "${path}" && "${path}" == "${test_root}"/* ]] || return 1
  while [[ "${cursor}" == "${test_root}"/* ]]; do
    [[ -d "${cursor}" && ! -L "${cursor}" && "${cursor:A}" == "${cursor}" && "$(/usr/bin/stat -f %u "${cursor}")" == "${EUID}" ]] || return 1
    cursor="${cursor:h}"
  done
}
test_hook() {
  [[ "${test_mode}" == 1 && "${DNIE_LIFECYCLE_TEST_INTERRUPT_AT:-}" == "$1" ]] || return 0
  kill -TERM $$
}
test_fail() {
  [[ "${test_mode}" == 1 && "${DNIE_LIFECYCLE_TEST_FAIL_AT:-}" == "$1" ]] || return 0
  fail "Injected isolated lifecycle failure at $1."
}
test_kill() {
  [[ "${test_mode}" == 1 && "${DNIE_LIFECYCLE_TEST_KILL_AT:-}" == "$1" ]] || return 0
  kill -KILL $$
}
claim_upgrade_temp() {
  local path="$1" message="$2"
  [[ ! -e "${path}" && ! -L "${path}" ]] || fail "${message}"
  if ! ( setopt noclobber; : > "${path}" ) 2>/dev/null; then fail "${message}"; fi
  upgrade_probe_tmp="${path}"
  upgrade_probe_tmp_owned=1
  [[ -f "${path}" && ! -L "${path}" && "$(/usr/bin/stat -f %u "${path}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %l "${path}")" == 1 ]] || fail "The claimed upgrade inspection temporary is unsafe."
  /bin/chmod 600 "${path}"
}
dispose_upgrade_temp() {
  (( upgrade_probe_tmp_owned == 1 )) || return 0
  /bin/rm -f -- "${upgrade_probe_tmp}"
  upgrade_probe_tmp=""
  upgrade_probe_tmp_owned=0
}
write_transaction_state() {
  local phase="$1" inode="${2:-}" state="${transaction}/transaction.state" temporary="${transaction}/transaction.state.new.$$"
  [[ -d "${transaction}" && ! -L "${transaction}" && ! -e "${temporary}" && ! -L "${temporary}" ]] || fail "The transaction state target is unsafe."
  { print "phase=${phase}"; [[ -z "${inode}" ]] || print "destination_inode=${inode}"; } > "${temporary}"
  /bin/chmod 600 "${temporary}"; /bin/mv -f "${temporary}" "${state}"
}
write_state() {
  local phase="$1" cdhash="$2" token="$3"
  local state_tmp="${state_file}.new.$$"
  [[ ! -e "${state_tmp}" && ! -L "${state_tmp}" ]] || fail "A lifecycle state temporary collision exists."
  { print 'host_id=org.dniemacos.dnietoken'; print 'extension_id=org.dniemacos.dnietoken.tokenextension';
    print "cdhash=${cdhash}"; print "phase=${phase}"; print "token=${token}"; } > "${state_tmp}"
  /bin/chmod 600 "${state_tmp}"
  [[ "$(/usr/bin/stat -f %u "${state_tmp}")" == "${EUID}" && "$(/usr/bin/stat -f %Lp "${state_tmp}")" == 600 &&
     "$(/usr/bin/stat -f %l "${state_tmp}")" == 1 ]] || fail "The lifecycle state temporary is unsafe."
  /bin/sync
  /bin/mv -f "${state_tmp}" "${state_file}"
  /bin/sync
}
owned_state_matches() {
  local phase="$1" cdhash="$2" token="${3:-}"
  [[ -f "${state_file}" && ! -L "${state_file}" && "$(/usr/bin/stat -f %u "${state_file}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${state_file}")" == 600 && "$(/usr/bin/stat -f %l "${state_file}")" == 1 &&
     "$(state_value host_id "${state_file}")" == org.dniemacos.dnietoken &&
     "$(state_value extension_id "${state_file}")" == org.dniemacos.dnietoken.tokenextension &&
     "$(state_value cdhash "${state_file}")" == "${cdhash}" && "$(state_value phase "${state_file}")" == "${phase}" &&
     ( -z "${token}" || "$(state_value token "${state_file}")" == "${token}" ) ]]
}
require_owned_state() {
  owned_state_matches "$@" || fail "The installed app is not proven to be owned by this pilot lifecycle."
}
require_stale_lock() {
  local owner_pid owner_start current_start
  [[ -d "${lock}" && ! -L "${lock}" && "$(/usr/bin/stat -f %u "${lock}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${lock}")" == 700 &&
     -f "${lock}/owner" && ! -L "${lock}/owner" && "$(/usr/bin/stat -f %u "${lock}/owner")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${lock}/owner")" == 600 && "$(/usr/bin/stat -f %l "${lock}/owner")" == 1 &&
     "$(state_value token "${lock}/owner")" == "${token}" ]] || fail "The retained lifecycle lock is not safely attributable to this transaction."
  owner_pid="$(state_value pid "${lock}/owner")"; owner_start="$(state_value process_start "${lock}/owner")"
  [[ "${owner_pid}" == <-> && "${owner_pid}" -gt 0 && -n "${owner_start}" ]] || fail "The retained lock has no exact process identity."
  if kill -0 "${owner_pid}" 2>/dev/null; then
    current_start="$(process_start_identity "${owner_pid}" || true)"
    [[ -n "${current_start}" ]] || fail "The live lifecycle lock owner's start identity could not be established; adoption is forbidden."
    [[ "${current_start}" != "${owner_start}" ]] || fail "The exact lifecycle lock owner is still running; adoption is forbidden."
  fi
}
adopt_stale_lock() {
  local operation="$1" phase="$2" expected="$3"
  require_stale_lock
  require_owned_state "${phase}" "${expected}" "${token}"
  owner_start="$(process_start_identity $$)"
  { print -r -- "operation=${operation}"; print -r -- "token=${token}"; print -r -- "pid=$$"; print -r -- "process_start=${owner_start}"; print 'adopted=true'; } > "${lock}/owner.new"
  /bin/chmod 600 "${lock}/owner.new"; /bin/mv -f "${lock}/owner.new" "${lock}/owner"
  lock_held=1
}
adopt_stale_lock_for_commit_recovery() {
  local operation="$1"
  require_stale_lock; require_transaction_state
  owner_start="$(process_start_identity $$)"
  { print -r -- "operation=${operation}"; print -r -- "token=${token}"; print -r -- "pid=$$"; print -r -- "process_start=${owner_start}"; print 'adopted=true'; } > "${lock}/owner.new"
  /bin/chmod 600 "${lock}/owner.new"; /bin/mv -f "${lock}/owner.new" "${lock}/owner"; lock_held=1
}
require_transaction_state() {
  [[ -d "${transaction}" && ! -L "${transaction}" && "$(/usr/bin/stat -f %u "${transaction}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${transaction}")" == 700 && -f "${transaction}/transaction.state" &&
     ! -L "${transaction}/transaction.state" && "$(/usr/bin/stat -f %u "${transaction}/transaction.state")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${transaction}/transaction.state")" == 600 &&
     "$(/usr/bin/stat -f %l "${transaction}/transaction.state")" == 1 ]] || fail "The retained transaction state is unsafe."
}
install_rollback_state_valid() {
  local expected="$1" phase=""
  owned_state_matches pending-install "${expected}" "${token}" && return 0
  [[ -f "${transaction}/transaction.state" ]] || return 1
  phase="$(state_value phase "${transaction}/transaction.state")"
  owned_state_matches committed "${expected}" "${token}" && [[ "${phase}" == commit-install-intent ]]
}
pending_install_state_valid() {
  local expected="$1"
  owned_state_matches pending-install "${expected}" "${token}" &&
    [[ "$(state_value phase "${transaction}/transaction.state")" == pending-install ]]
}
uninstall_rollback_state_valid() {
  local expected="$1" phase=""
  owned_state_matches pending-uninstall "${expected}" "${token}" && return 0
  [[ -f "${transaction}/transaction.state" ]] || return 1
  phase="$(state_value phase "${transaction}/transaction.state")"
  [[ "${phase}" == commit-uninstall-intent && ! -e "${state_file}" && ! -L "${state_file}" ]]
}
require_normalizable_app_topology() {
  local app="$1" asset entry
  local -a entries
  asset="${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets/generation2.json"
  [[ -d "${app}" && ! -L "${app}" && -f "${asset}" && ! -L "${asset}" ]] ||
    fail "The published app or exact credential asset is missing, linked, or unsafe."
  entries=("${(@0)$(/usr/bin/find "${app}" -print0)}")
  entries=("${(@)entries:#}")
  (( ${#entries} > 0 )) || fail "The published app topology could not be enumerated."
  for entry in "${entries[@]}"; do
    [[ ! -L "${entry}" ]] || fail "The published app contains a symlink; permission normalization is forbidden."
    if [[ -f "${entry}" ]]; then
      [[ "$(/usr/bin/stat -f %l "${entry}")" == 1 ]] ||
        fail "The published app contains a multiply linked regular file; permission normalization is forbidden."
    elif [[ ! -d "${entry}" ]]; then
      fail "The published app contains a special filesystem entry; permission normalization is forbidden."
    fi
  done
}
normalize_published_app() {
  local app="$1" expected="$2" expected_uid entry mode normalized asset
  local -a entries
  require_normalizable_app_topology "${app}"
  asset="${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets/generation2.json"
  entries=("${(@0)$(/usr/bin/find "${app}" -print0)}")
  entries=("${(@)entries:#}")
  if [[ "${test_mode}" == 1 ]]; then expected_uid="${EUID}"; else /usr/sbin/chown -R root:wheel "${app}"; expected_uid=0; fi
  for entry in "${entries[@]}"; do
    if [[ -d "${entry}" ]]; then
      /bin/chmod 755 "${entry}"
    else
      mode="$(/usr/bin/stat -f %Lp "${entry}")"
      [[ "${mode}" == <-> ]] || fail "A published regular-file mode is invalid."
      if (( (8#${mode} & 8#100) == 8#100 )); then normalized=755; else normalized=644; fi
      /bin/chmod "${normalized}" "${entry}"
    fi
  done
  /bin/chmod 444 "${asset}"
  for entry in "${entries[@]}"; do
    [[ "$(/usr/bin/stat -f %u "${entry}")" == "${expected_uid}" ]] ||
      fail "The published app contains an unexpectedly owned entry."
    if [[ -d "${entry}" ]]; then normalized=755
    elif [[ "${entry}" == "${asset}" ]]; then normalized=444
    else
      mode="$(/usr/bin/stat -f %Lp "${entry}")"
      if (( (8#${mode} & 8#100) == 8#100 )); then normalized=755; else normalized=644; fi
    fi
    [[ "$(/usr/bin/stat -f %Lp "${entry}")" == "${normalized}" ]] ||
      fail "The published app permission normalization did not produce the exact required mode."
  done
  [[ "$(inspect_cdhash "${app}")" == "${expected}" ]] ||
    fail "Permission normalization changed or invalidated the strict signed artifact boundary."
}
direct_token() { [[ "$1" =~ '^direct-[0-9A-Za-z._-]{8,89}$' ]]; }
require_direct_state_scope() {
  local directory
  for directory in "${state_root:h}" "${state_root}"; do
    [[ -d "${directory}" && ! -L "${directory}" && "${directory:A}" == "${directory}" &&
       "$(/usr/bin/stat -f %u "${directory}")" == "${EUID}" &&
       "$(/usr/bin/stat -f %Lp "${directory}")" == 700 ]] || fail "The direct pilot ownership directory is unsafe."
  done
}
require_direct_transaction_free() {
  local owner="$1"
  direct_token "${owner}" || fail "Ownership belongs to a historical or unknown operation."
  if [[ -e "${transactions}" || -L "${transactions}" ]]; then
    [[ -d "${transactions}" && ! -L "${transactions}" &&
       "$(/usr/bin/stat -f %u "${transactions}")" == "${EUID}" &&
       "$(/usr/bin/stat -f %Lp "${transactions}")" == 700 &&
       ! -e "${transactions}/${owner}" && ! -L "${transactions}/${owner}" ]] ||
      fail "The direct ownership token collides with historical lifecycle state."
  fi
}
require_direct_ownership_state() {
  local phase="$1" cdhash="$2" owner="$3"
  require_direct_transaction_free "${owner}"
  require_exact_field_order "${state_file}" host_id extension_id cdhash phase token ||
    fail "The direct ownership state does not have the exact five-field shape."
  [[ "${cdhash}" =~ '^[[:xdigit:]]{40}$' ]] || fail "The direct ownership identity is malformed."
  require_owned_state "${phase}" "${cdhash}" "${owner}"
}
require_direct_installed_app() {
  local cdhash="$1" observed_identity="${2:-}" ownership_phase before
  [[ -d "${destination}" && ! -L "${destination}" && "${destination:A}" == "${destination}" &&
     "$(/usr/bin/stat -f %u "${destination}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${destination}")" == 755 ]] || fail "The exact installed app is absent or unsafe."
  [[ -f "${state_file}" && ! -L "${state_file}" ]] || fail "No exact ownership binding exists for the installed app."
  ownership_phase="$(state_value phase "${state_file}")"
  case "${ownership_phase}" in
    committed)
      require_strict_committed_state
      require_owned_state committed "${cdhash}"
      ;;
    pending-install)
      require_direct_ownership_state pending-install "${cdhash}" "$(state_value token "${state_file}")"
      ;;
    *) fail "The installed app has unknown or historical pending ownership." ;;
  esac
  before="$(/usr/bin/stat -f '%d:%i' "${destination}")"
  [[ -z "${observed_identity}" || "${before}" == "${observed_identity}" ]] ||
    fail "The installed app identity changed since it was observed."
  [[ "$(inspect_cdhash "${destination}")" == "${cdhash}" &&
     "$(/usr/bin/stat -f '%d:%i' "${destination}")" == "${before}" ]] ||
    fail "The installed app differs from the exact signed ownership binding."
}
require_direct_python() {
  local directory mode list
  direct_python="/Library/Developer/CommandLineTools/usr/bin/python3"
  direct_python="${direct_python:A}"
  [[ "${direct_python}" == /Library/Developer/CommandLineTools/* && -f "${direct_python}" && -x "${direct_python}" &&
     "$(/usr/bin/stat -f '%u:%Lp' "${direct_python}")" == 0:755 ]] ||
    fail "The fixed Apple Command Line Tools Python is required for the atomic app move."
  list="$(/bin/ls -lde "${direct_python}")"
  [[ "${list}" != *$'\n'* ]] || fail "The fixed Apple Command Line Tools Python has an unexpected ACL."
  directory="${direct_python:h}"
  while [[ "${directory}" == /Library || "${directory}" == /Library/* ]]; do
    [[ -d "${directory}" && ! -L "${directory}" && "$(/usr/bin/stat -f %u "${directory}")" == 0 ]] ||
      fail "The fixed Apple Command Line Tools Python ancestry is unsafe."
    mode="$(/usr/bin/stat -f %Lp "${directory}")"
    list="$(/bin/ls -lde "${directory}")"
    [[ "${mode}" == <-> && "${list}" != *$'\n'* ]] && (( (8#${mode} & 8#022) == 0 )) ||
      fail "The fixed Apple Command Line Tools Python ancestry has unsafe write permissions."
    directory="${directory:h}"
  done
}
move_direct_app_exclusive() {
  # Callers use only the fixed pilot destination and generated private app paths.
  "${direct_python}" -I -B - "$1" "$2" <<'PYTHON'
import ctypes
import os
import sys

source, destination = map(os.fsencode, sys.argv[1:])
source_parent, source_name = os.path.split(source)
destination_parent, destination_name = os.path.split(destination)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
try:
    source_fd = os.open(source_parent, flags)
    destination_fd = os.open(destination_parent, flags)
    rename = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).renameatx_np
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    # Darwin RENAME_EXCL refuses any pre-existing destination entry.
    if rename(source_fd, source_name, destination_fd, destination_name, 0x4) != 0:
        raise OSError(ctypes.get_errno(), "exclusive rename failed")
except OSError as error:
    sys.exit(f"Atomic pilot app move failed: {error}")
PYTHON
}
require_no_direct_custody() {
  local -a retained
  retained=("${state_root}"/remove.*(N))
  (( ${#retained} == 0 )) ||
    fail "A prior removal left an unresolved private directory at ${retained[1]}."
}
require_direct_app_inactive() {
  local pattern
  if [[ "${test_mode}" == 1 ]]; then
    [[ ! -e "${test_root}/pgrep.fail" ]] ||
      fail "Unable to establish that the exact installed host and provider are inactive."
    [[ ! -e "${test_root}/host.active" && ! -e "${test_root}/provider.active" ]] ||
      fail "The exact installed host or provider is active."
    return
  fi
  for pattern in \
    '^/Applications/DNIeTokenHost\.app/Contents/MacOS/DNIeTokenHost([[:space:]]|$)' \
    '^/Applications/DNIeTokenHost\.app/Contents/PlugIns/DNIeTokenExtension\.appex/Contents/MacOS/DNIeTokenExtension([[:space:]]|$)'; do
    if /usr/bin/pgrep -f "${pattern}" >/dev/null 2>&1; then
      fail "The exact installed host or provider is active."
    elif (( $? != 1 )); then
      fail "Unable to establish that the exact installed host and provider are inactive."
    fi
  done
}
remove_direct_app() {
  local expected="$1" observed_identity="$2" custody_app
  require_direct_python
  direct_custody="$(/usr/bin/mktemp -d "${state_root}/remove.XXXXXXXX")"
  custody_app="${direct_custody}/DNIeTokenHost.app"
  [[ ! -L "${destination}" && "$(/usr/bin/stat -f '%d:%i' "${destination}")" == "${observed_identity}" ]] ||
    fail "The exact installed app changed before removal."
  require_direct_app_inactive
  move_direct_app_exclusive "${destination}" "${custody_app}" ||
    fail "The app could not be moved into private removal custody."
  test_fail remove-pilot-after-move
  if [[ ! -d "${custody_app}" || -L "${custody_app}" ||
        "$(/usr/bin/stat -f '%d:%i' "${custody_app}")" != "${observed_identity}" ]] ||
     ! ( require_normalizable_app_topology "${custody_app}" ) ||
     [[ "$(inspect_cdhash "${custody_app}")" != "${expected}" ||
        "$(/usr/bin/stat -f '%d:%i' "${custody_app}")" != "${observed_identity}" ]]; then
    if move_direct_app_exclusive "${custody_app}" "${destination}"; then
      fail "The moved app differed from the exact ownership proof and was returned without deleting it."
    fi
    fail "The moved app differed from the exact ownership proof and could not be returned safely."
  fi
  /bin/rm -rfx -- "${custody_app}" ||
    fail "App removal failed. The ownership binding remains. Inspect make status before retrying."
  cleanup_direct_custody
}
cleanup_direct_custody() {
  [[ -n "${direct_custody}" ]] || return 0
  if ! /bin/rmdir -- "${direct_custody}" 2>/dev/null; then
    print -u2 -- "The private removal directory was left at ${direct_custody}."
    direct_custody=""
    return 1
  fi
  direct_custody=""
}
cleanup_direct_staging() {
  [[ -n "${direct_stage}" ]] || return 0
  [[ -d "${direct_stage}" && ! -L "${direct_stage}" &&
     "$(/usr/bin/stat -f '%u:%Lp:%i' "${direct_stage}")" == "${EUID}:700:${direct_stage_inode}" ]] ||
    fail "The generated pilot staging directory changed and was left at ${direct_stage}."
  /bin/rm -rf -- "${direct_stage}" || fail "Unable to remove generated pilot staging at ${direct_stage}."
  direct_stage=""
}
claim_and_restore_app() {
  local archive="$1" expected="$2"
  [[ -d "${archive}" && ! -L "${archive}" && ! -e "${destination}" && ! -L "${destination}" ]] ||
    fail "Restoration requires an exact archive and absent destination."
  /bin/mkdir -m 700 "${destination}" || fail "Exclusive restoration claim failed."
  publication_inode="$(/usr/bin/stat -f %i "${destination}")"
  /usr/bin/ditto "${archive}" "${destination}"
  [[ "$(/usr/bin/stat -f %i "${destination}")" == "${publication_inode}" && "$(inspect_cdhash "${destination}")" == "${expected}" ]] ||
    fail "The restored app failed inode-bound artifact verification."
  normalize_published_app "${destination}" "${expected}"
  /bin/rm -rf -- "${archive}"
  publication_inode=""
}

write_upgrade_journal() {
  local candidate="$1" pair_output="$2" journal="${transaction}/upgrade.journal"
  local temporary="${transaction}/upgrade.journal.new.$$" field
  local saved_state="${transaction}/old-installed.state"
  local state_sha saved_state_inode destination_inode candidate_inode state_inode
  [[ ! -e "${journal}" && ! -L "${journal}" && ! -e "${temporary}" && ! -L "${temporary}" ]] ||
    fail "The upgrade journal target already exists or is unsafe."
  state_sha="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
  [[ -f "${saved_state}" && ! -L "${saved_state}" && "$(/usr/bin/stat -f %u "${saved_state}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${saved_state}")" == 600 && "$(/usr/bin/stat -f %l "${saved_state}")" == 1 ]] ||
    fail "The exact saved ownership-state bytes are unsafe."
  /usr/bin/cmp -s "${state_file}" "${saved_state}" || fail "The saved ownership-state bytes do not match the committed state."
  saved_state_inode="$(/usr/bin/stat -f %i "${saved_state}")"
  destination_inode="$(/usr/bin/stat -f %i "${destination}")"
  candidate_inode="$(/usr/bin/stat -f %i "${candidate}")"
  state_inode="$(/usr/bin/stat -f %i "${state_file}")"
  [[ "${saved_state_inode}" == <-> && "${destination_inode}" == <-> && "${candidate_inode}" == <-> && "${state_inode}" == <-> &&
     "${saved_state_inode}" != "${state_inode}" &&
     "${destination_inode}" != "${candidate_inode}" && "${destination_inode}" != "${state_inode}" &&
     "${candidate_inode}" != "${state_inode}" ]] || fail "The upgrade preparation inode claims collide or are malformed."
  {
    print 'journal_version=1'
    print -r -- "token=${token}"
    print 'phase=copying'
    print -r -- "old_state_host_id=$(state_value host_id "${state_file}")"
    print -r -- "old_state_extension_id=$(state_value extension_id "${state_file}")"
    print -r -- "old_state_cdhash=$(state_value cdhash "${state_file}")"
    print -r -- "old_state_phase=$(state_value phase "${state_file}")"
    print -r -- "old_state_token=$(state_value token "${state_file}")"
    print -r -- "old_state_sha256=${state_sha}"
    print -r -- "saved_state_path=${saved_state}"
    print -r -- "saved_state_inode=${saved_state_inode}"
    print -r -- "destination_path=${destination}"
    print -r -- "candidate_path=${candidate}"
    print -r -- "transaction_path=${transaction}"
    print -r -- "archive_path=${transaction}/DNIeTokenHost.app.old"
    print -r -- "staging_path=${transaction}/DNIeTokenHost.app.staging"
    print -r -- "release_receipt_path=${transaction}/operation.lock.released"
    print -r -- "destination_inode=${destination_inode}"
    print -r -- "candidate_inode=${candidate_inode}"
    print -r -- "state_inode=${state_inode}"
    print 'staging_inode=absent'
    print 'staging_verification=absent'
    print 'archive_retention_dependency=upgrade-recovery'
    print 'archive_retention_owner=pilot-lifecycle-root'
    print 'archive_retention_scope=local-fixture-only'
    print 'archive_disposition_trigger=terminal-review'
    print 'rollback_predecessor_phase=none'
    print 'rollback_predecessor_topology=none'
    print 'rollback_predecessor_operation=none'
    for field in "${upgrade_pair_fields[@]}"; do
      print -r -- "${field}=$(state_value "${field}" "${pair_output}")"
    done
  } > "${temporary}"
  /bin/chmod 600 "${temporary}"
  require_exact_field_order "${temporary}" "${journal_fields[@]}" || fail "The new upgrade journal failed strict shape validation."
  owner_start="$(process_start_identity $$)"
  [[ -n "${owner_start}" && ! -e "${lock}/owner.new" && ! -L "${lock}/owner.new" ]] ||
    fail "The retained upgrade lock owner cannot be recorded safely."
  { print 'operation=upgrade-copying-prepared'; print -r -- "token=${token}"; print -r -- "pid=$$";
    print -r -- "process_start=${owner_start}"; print 'retained=true'; } > "${lock}/owner.new"
  /bin/chmod 600 "${lock}/owner.new"
  /bin/mv "${lock}/owner.new" "${lock}/owner"
  lock_retained=1
  test_hook upgrade-prepare-before-journal
  /bin/mv "${temporary}" "${journal}"
  test_hook upgrade-prepare-after-journal
}

write_upgrade_staging_substate() {
  local staging_inode="$1" verification="$2" journal="${transaction}/upgrade.journal"
  local temporary="${transaction}/upgrade.journal.stage.$$" field value
  [[ ( "${verification}" == copying-unverified || "${verification}" == verified ) &&
     "${staging_inode}" == <-> && "${staging_inode}" -gt 0 &&
     ! -e "${temporary}" && ! -L "${temporary}" ]] ||
    fail "The upgrade staging journal update is unsafe."
  {
    for field in "${journal_fields[@]}"; do
      case "${field}" in
        staging_inode) value="${staging_inode}" ;;
        staging_verification) value="${verification}" ;;
        *) value="$(state_value "${field}" "${journal}")" ;;
      esac
      print -r -- "${field}=${value}"
    done
  } > "${temporary}"
  /bin/chmod 600 "${temporary}"
  require_exact_field_order "${temporary}" "${journal_fields[@]}" ||
    fail "The upgrade staging journal update failed strict shape validation."
  /bin/mv "${temporary}" "${journal}"
  require_upgrade_journal
}

require_upgrade_preparation_relationships() {
  local candidate="$1" journal="${transaction}/upgrade.journal" pair_output="$2" expected_staging="${3:-absent}"
  local field current_sha staging="${transaction}/DNIeTokenHost.app.staging"
  require_strict_committed_state
  require_upgrade_journal
  [[ "$(state_value phase "${journal}")" == copying ]] ||
    fail "The upgrade is no longer in the copying phase."
  local saved_state="${transaction}/old-installed.state"
  [[ "$(state_value candidate_path "${journal}")" == "${candidate}" &&
     "$(state_value old_state_host_id "${journal}")" == "$(state_value host_id "${state_file}")" &&
     "$(state_value old_state_extension_id "${journal}")" == "$(state_value extension_id "${state_file}")" &&
     "$(state_value old_state_cdhash "${journal}")" == "$(state_value cdhash "${state_file}")" &&
     "$(state_value old_state_phase "${journal}")" == "$(state_value phase "${state_file}")" &&
     "$(state_value old_state_token "${journal}")" == "$(state_value token "${state_file}")" ]] ||
    fail "The committed ownership state no longer matches the saved upgrade authority."
  current_sha="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
  [[ "${current_sha}" == "$(state_value old_state_sha256 "${journal}")" &&
     -f "${saved_state}" && ! -L "${saved_state}" && "$(/usr/bin/stat -f %u "${saved_state}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${saved_state}")" == 600 && "$(/usr/bin/stat -f %l "${saved_state}")" == 1 &&
     "$(/usr/bin/stat -f %i "${saved_state}")" == "$(state_value saved_state_inode "${journal}")" &&
     "$(/usr/bin/shasum -a 256 "${saved_state}" | /usr/bin/awk '{print $1}')" == "${current_sha}" &&
     "$(state_value saved_state_path "${journal}")" == "${saved_state}" &&
     "$(/usr/bin/stat -f %i "${destination}")" == "$(state_value destination_inode "${journal}")" &&
     "$(/usr/bin/stat -f %i "${candidate}")" == "$(state_value candidate_inode "${journal}")" &&
     "$(/usr/bin/stat -f %i "${state_file}")" == "$(state_value state_inode "${journal}")" ]] ||
    fail "The saved upgrade fingerprint or inode claim changed."
  [[ ! -e "${transaction}/DNIeTokenHost.app.old" && ! -L "${transaction}/DNIeTokenHost.app.old" &&
     ! -e "${transaction}/operation.lock.released" && ! -L "${transaction}/operation.lock.released" &&
     ! -e "${transaction}/transaction.state" && ! -L "${transaction}/transaction.state" ]] ||
    fail "The prepared upgrade paths collide with an existing or legacy lifecycle artifact."
  case "${expected_staging}" in
    absent)
      [[ "$(state_value staging_verification "${journal}")" == absent &&
         "$(state_value staging_inode "${journal}")" == absent && ! -e "${staging}" && ! -L "${staging}" ]] ||
        fail "The prepared upgrade staging path is not absent."
      ;;
    copying-unverified|verified)
      [[ "$(state_value staging_verification "${journal}")" == "${expected_staging}" &&
         -d "${staging}" && ! -L "${staging}" && "${staging:A}" == "${staging}" &&
         "$(/usr/bin/stat -f %u "${staging}")" == "${EUID}" &&
         "$(/usr/bin/stat -f %i "${staging}")" == "$(state_value staging_inode "${journal}")" ]] ||
        fail "The upgrade staging inode or verification substate changed."
      ;;
    *) fail "The requested upgrade staging relationship is invalid." ;;
  esac
  [[ "$(state_value old_state_cdhash "${journal}")" == "$(state_value old_host_cdhash "${journal}")" &&
     "$(state_value old_artifact_cdhash "${journal}")" == "$(state_value old_host_cdhash "${journal}")" &&
     "$(state_value new_artifact_cdhash "${journal}")" == "$(state_value new_host_cdhash "${journal}")" &&
     "$(state_value old_host_cdhash "${journal}")" != "$(state_value new_host_cdhash "${journal}")" &&
     "$(state_value old_extension_cdhash "${journal}")" != "$(state_value new_extension_cdhash "${journal}")" ]] ||
    fail "The journaled ownership and inspection tuples are inconsistent."
  require_upgrade_pair_output "${pair_output}"
  for field in "${upgrade_pair_fields[@]}"; do
    [[ "$(state_value "${field}" "${journal}")" == "$(state_value "${field}" "${pair_output}")" ]] ||
      fail "The inspected artifact pair changed after preparation."
  done
}
require_old_retained_relationships() {
  local candidate="$1" source_pair="$2" staged_pair="$3" journal="${transaction}/upgrade.journal"
  local expected_phase="${4:-old-retained}"
  local archive="${transaction}/DNIeTokenHost.app.old" staging="${transaction}/DNIeTokenHost.app.staging"
  local saved_state="${transaction}/old-installed.state" current_sha field
  require_strict_committed_state
  require_upgrade_journal
  [[ ( "${expected_phase}" == copying || "${expected_phase}" == old-retained ) &&
     "$(state_value phase "${journal}")" == "${expected_phase}" ]] ||
    fail "The upgrade journal is not at the required old-retention phase."
  current_sha="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
  [[ "$(state_value candidate_path "${journal}")" == "${candidate}" &&
     "$(state_value old_state_host_id "${journal}")" == "$(state_value host_id "${state_file}")" &&
     "$(state_value old_state_extension_id "${journal}")" == "$(state_value extension_id "${state_file}")" &&
     "$(state_value old_state_cdhash "${journal}")" == "$(state_value cdhash "${state_file}")" &&
     "$(state_value old_state_phase "${journal}")" == "$(state_value phase "${state_file}")" &&
     "$(state_value old_state_token "${journal}")" == "$(state_value token "${state_file}")" &&
     "${current_sha}" == "$(state_value old_state_sha256 "${journal}")" &&
     -f "${saved_state}" && ! -L "${saved_state}" && "$(/usr/bin/stat -f %u "${saved_state}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${saved_state}")" == 600 && "$(/usr/bin/stat -f %l "${saved_state}")" == 1 &&
     "$(/usr/bin/stat -f %i "${saved_state}")" == "$(state_value saved_state_inode "${journal}")" &&
     "$(/usr/bin/shasum -a 256 "${saved_state}" | /usr/bin/awk '{print $1}')" == "${current_sha}" &&
     -d "${archive}" && ! -L "${archive}" && "${archive:A}" == "${archive}" &&
     "$(/usr/bin/stat -f %u "${archive}")" == "${EUID}" &&
     "$(/usr/bin/stat -f %Lp "${archive}")" == 755 &&
     "$(/usr/bin/stat -f %i "${archive}")" == "$(state_value destination_inode "${journal}")" &&
     ! -e "${destination}" && ! -L "${destination}" &&
     -d "${candidate}" && ! -L "${candidate}" &&
     "$(/usr/bin/stat -f %i "${candidate}")" == "$(state_value candidate_inode "${journal}")" &&
     -d "${staging}" && ! -L "${staging}" &&
     "$(/usr/bin/stat -f %i "${staging}")" == "$(state_value staging_inode "${journal}")" &&
     "$(state_value staging_verification "${journal}")" == verified &&
     "$(/usr/bin/stat -f %i "${state_file}")" == "$(state_value state_inode "${journal}")" &&
     ! -e "${transaction}/operation.lock.released" && ! -L "${transaction}/operation.lock.released" &&
     ! -e "${transaction}/transaction.state" && ! -L "${transaction}/transaction.state" ]] ||
    fail "The exact old-retained archive, state, or inode topology changed."
  require_upgrade_pair_output "${source_pair}"
  require_upgrade_pair_output "${staged_pair}"
  for field in "${upgrade_pair_fields[@]}"; do
    [[ "$(state_value "${field}" "${journal}")" == "$(state_value "${field}" "${source_pair}")" &&
       "$(state_value "${field}" "${journal}")" == "$(state_value "${field}" "${staged_pair}")" ]] ||
      fail "The old archive, candidate, or staged inspection tuple changed."
  done
}

command_name="${1:-}"
case "${command_name}" in
  prepare-upgrade-fixture|probe-upgrade-fixture|stage-upgrade-fixture|probe-staged-upgrade-fixture|retain-old-upgrade-fixture|probe-old-retained-upgrade-fixture|arm-upgrade-rollback-fixture|probe-armed-upgrade-rollback-fixture)
    [[ "${test_mode}" == 1 ]] || fail "Upgrade preparation commands are fixture-only until coordinator and transaction integration review." 64
    ;;
esac
token="${2:-}"
valid_token "${token}" || fail "A bounded lifecycle transaction token is required." 64
transaction="${transactions}/${token}"
lock_held=0
lock_retained=0
publication_inode=""
direct_stage=""
direct_stage_inode=""
direct_custody=""
upgrade_probe_tmp=""
upgrade_probe_tmp_owned=0
upgrade_temp_suffix="${DNIE_LIFECYCLE_TEST_TEMP_SUFFIX:-$$}"
rollback_journal_tmp=""
rollback_state_tmp=""
rollback_owner_tmp=""
rollback_predecessor_phase=""
rollback_predecessor_topology=""
rollback_predecessor_operation=""
rollback_metadata_inode=""
[[ "${upgrade_temp_suffix}" == <-> ]] || fail "The fixture temporary suffix is invalid." 64
trap 'exit_status=$?; [[ -z "${direct_stage}" ]] || ( cleanup_direct_staging ) || exit_status=1; cleanup_direct_custody || exit_status=1; (( upgrade_probe_tmp_owned == 0 )) || /bin/rm -f -- "${upgrade_probe_tmp}" 2>/dev/null || true; if (( exit_status != 0 )) && [[ -n "${publication_inode}" && -d "${destination}" && ! -L "${destination}" && "$(/usr/bin/stat -f %i "${destination}" 2>/dev/null)" == "${publication_inode}" ]]; then /bin/mv "${destination}" "${transaction}/DNIeTokenHost.app.failed-install" 2>/dev/null || true; print "phase=failed-install-retained" > "${transaction}/transaction.state" 2>/dev/null || true; fi; if (( lock_held && ! lock_retained )); then release_lock || true; fi; exit ${exit_status}' EXIT
trap 'exit 130' INT TERM HUP

case "${command_name}" in
  authorize)
    print 'pilot_authorization=pass'
    ;;
  publish-pilot)
    [[ $# == 4 ]] && direct_token "${token}" || fail "Publication requires a direct token, source app, and artifact identity." 64
    source_app="$3"; expected="${4:l}"
    require_direct_python
    [[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]] || fail "The expected artifact identity is invalid." 64
    [[ "${source_app}" == /*/DNIeTokenHost.app && "${source_app:A}" == "${source_app}" &&
       "${source_app}" != "${destination}" ]] || fail "The source path is outside the authorized canonical scope."
    if [[ "${test_mode}" == 1 ]]; then
      require_fixture_ancestors "${source_app}" || fail "The source app escaped the canonical fixture scope."
    fi
    acquire_lock publish-pilot direct
    require_no_direct_custody
    [[ ! -e "${destination}" && ! -L "${destination}" && ! -e "${state_file}" && ! -L "${state_file}" ]] ||
      fail "Publication requires an absent destination and ownership state. Inspect make status or make uninstall."
    require_direct_transaction_free "${token}"
    [[ "$(/usr/bin/stat -f %d "${state_root}")" == "$(/usr/bin/stat -f %d "${destination:h}")" ]] ||
      fail "The private staging and installation directories are on different devices."
    require_normalizable_app_topology "${source_app}"
    [[ "$(inspect_cdhash "${source_app}")" == "${expected}" ]] || fail "The source artifact identity changed before staging."
    direct_stage="$(/usr/bin/mktemp -d "${state_root}/publish.XXXXXXXX")"
    direct_stage_inode="$(/usr/bin/stat -f %i "${direct_stage}")"
    staging="${direct_stage}/DNIeTokenHost.app"
    /usr/bin/ditto -X --noacl --nopersistRootless "${source_app}" "${staging}" || fail "The source app could not be staged."
    normalize_published_app "${staging}" "${expected}"
    staged_verification="$("${inspector}" "${staging}")" || fail "The staged app failed the strict product verification."
    [[ "${staged_verification}" == *$'\n'"artifact_cdhash=${expected}"$'\n'* &&
       "$(inspect_cdhash "${source_app}")" == "${expected}" ]] || fail "The source or staged artifact changed before publication."
    stage_app_identity="$(/usr/bin/stat -f '%d:%i' "${staging}")"
    write_state pending-install "${expected}" "${token}"
    test_fail publish-pilot-after-binding
    move_direct_app_exclusive "${staging}" "${destination}" ||
      fail "Publication did not complete. A pending ownership binding remains. Inspect make status before retrying."
    test_fail publish-pilot-after-rename
    require_direct_installed_app "${expected}" "${stage_app_identity}"
    cleanup_direct_staging
    release_lock
    print 'pilot_publication=pending-install'
    ;;
  confirm-pilot)
    [[ $# == 3 && "${3:-}" =~ '^[[:xdigit:]]{40}$' ]] || fail "Confirmation requires one exact artifact identity." 64
    expected="${3:l}"
    acquire_lock confirm-pilot direct
    require_direct_ownership_state pending-install "${expected}" "${token}"
    require_direct_installed_app "${expected}"
    write_state committed "${expected}" "${token}"
    release_lock
    print 'pilot_installation=committed'
    ;;
  probe-pilot-removal)
    [[ $# == 4 && "${3:-}" =~ '^[[:xdigit:]]{40}$' && "${4:-}" =~ '^[0-9]+:[0-9]+$' ]] ||
      fail "Removal proof requires the exact artifact identity and observed device:inode." 64
    require_direct_state_scope
    [[ ! -e "${lock}" && ! -L "${lock}" ]] || fail "The lifecycle lock exists. Removal ownership cannot be observed safely."
    require_no_direct_custody
    require_direct_installed_app "${3:l}" "$4"
    [[ ! -e "${lock}" && ! -L "${lock}" ]] || fail "A lifecycle operation started during removal ownership inspection."
    print 'pilot_removal_probe=pass'
    ;;
  remove-pilot)
    [[ ( $# == 3 && "${3:-}" == absent ) ||
       ( $# == 4 && "${3:-}" =~ '^[[:xdigit:]]{40}$' && "${4:-}" =~ '^[0-9]+:[0-9]+$' ) ]] ||
      fail "Removal requires the exact artifact identity and observed device:inode, or the absent classification." 64
    acquire_lock remove-pilot direct
    require_no_direct_custody
    if [[ "$3" == absent ]]; then
      [[ ! -e "${destination}" && ! -L "${destination}" ]] || fail "The destination exists; absent removal was refused."
      if [[ -e "${state_file}" || -L "${state_file}" ]]; then
        [[ -f "${state_file}" && ! -L "${state_file}" ]] || fail "The absent app has an unsafe ownership binding."
        ownership_phase="$(state_value phase "${state_file}")"
        [[ "${ownership_phase}" == pending-install || "${ownership_phase}" == committed ]] ||
          fail "The absent app has unknown or historical pending ownership."
        require_direct_ownership_state "${ownership_phase}" "$(state_value cdhash "${state_file}")" "$(state_value token "${state_file}")"
      fi
    else
      observed_identity="$4"
      require_normalizable_app_topology "${destination}"
      require_direct_installed_app "${3:l}" "${observed_identity}"
      [[ "$(/usr/bin/stat -f %d "${destination:h}")" == "${observed_identity%%:*}" ]] ||
        fail "The installed app is on a different device from its parent."
      remove_direct_app "${3:l}" "${observed_identity}"
    fi
    [[ ! -e "${destination}" && ! -L "${destination}" ]] ||
      fail "The destination is still present. The ownership binding remains."
    /bin/rm -f -- "${state_file}" || fail "The app is absent but its ownership binding could not be removed."
    release_lock
    print 'pilot_installation=absent'
    ;;
  prepare-upgrade-fixture)
    candidate="${3:-}"
    [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    [[ "${candidate}" != "${destination}" && -d "${destination}" && ! -L "${destination}" &&
       -d "${candidate}" && ! -L "${candidate}" && ! -e "${transaction}" && ! -L "${transaction}" ]] ||
      fail "Upgrade preparation requires distinct old/candidate artifacts and a collision-free transaction path."
    require_strict_committed_state
    require_normalizable_app_topology "${destination}"
    require_normalizable_app_topology "${candidate}"
    acquire_lock prepare-upgrade-fixture
    /bin/mkdir "${transaction}"
    /bin/chmod 700 "${transaction}"
    pair_output="${transaction}/upgrade-pair.new.${upgrade_temp_suffix}"
    claim_upgrade_temp "${pair_output}" "The upgrade-pair inspection temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${candidate}" > "${pair_output}"
    /bin/chmod 600 "${pair_output}"
    require_upgrade_pair_output "${pair_output}"
    [[ "$(state_value cdhash "${state_file}")" == "$(state_value old_host_cdhash "${pair_output}")" ]] ||
      fail "The exact committed owner does not match the inspected installed artifact."
    [[ ! -e "${transaction}/old-installed.state" && ! -L "${transaction}/old-installed.state" ]] ||
      fail "The saved ownership-state target collided."
    /bin/cp "${state_file}" "${transaction}/old-installed.state"
    /bin/chmod 600 "${transaction}/old-installed.state"
    write_upgrade_journal "${candidate}" "${pair_output}"
    require_upgrade_preparation_relationships "${candidate}" "${pair_output}"
    dispose_upgrade_temp
    print 'upgrade_preparation=fixture-only-pass'
    print -r -- "upgrade_journal=${transaction}/upgrade.journal"
    ;;
  probe-upgrade-fixture)
    candidate="${3:-}"
    [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    require_retained_upgrade_lock upgrade-copying-prepared
    require_upgrade_journal
    [[ -d "${destination}" && ! -L "${destination}" && -d "${candidate}" && ! -L "${candidate}" ]] ||
      fail "The prepared old or candidate artifact is missing or unsafe."
    require_normalizable_app_topology "${destination}"
    require_normalizable_app_topology "${candidate}"
    upgrade_probe_tmp="${transaction}/upgrade-pair.probe.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The upgrade probe temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${candidate}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}"
    dispose_upgrade_temp
    print 'upgrade_preparation_probe=fixture-only-pass'
    print 'upgrade_phase=copying'
    ;;
  stage-upgrade-fixture)
    candidate="${3:-}"
    [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    require_retained_upgrade_lock upgrade-copying-prepared
    require_upgrade_journal
    require_normalizable_app_topology "${destination}"
    require_normalizable_app_topology "${candidate}"
    upgrade_probe_tmp="${transaction}/upgrade-pair.source-before.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The source inspection temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${candidate}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}" absent
    dispose_upgrade_temp
    retain_upgrade_lock_as upgrade-copying-staging
    staging="${transaction}/DNIeTokenHost.app.staging"
    [[ ! -e "${staging}" && ! -L "${staging}" ]] || fail "The upgrade staging path is not exclusively claimable."
    /bin/mkdir -m 700 "${staging}" || fail "The upgrade staging path could not be exclusively claimed."
    staging_inode="$(/usr/bin/stat -f %i "${staging}")"
    write_upgrade_staging_substate "${staging_inode}" copying-unverified
    test_hook upgrade-stage-before-copy; test_fail upgrade-stage-before-copy
    if [[ "${test_mode}" == 1 && ( "${DNIE_LIFECYCLE_TEST_INTERRUPT_AT:-}" == upgrade-stage-during-copy ||
       "${DNIE_LIFECYCLE_TEST_FAIL_AT:-}" == upgrade-stage-during-copy ) ]]; then
      /bin/mkdir -p "${staging}/Contents"
      /usr/bin/ditto "${candidate}/Contents/Resources" "${staging}/Contents/Resources"
      test_hook upgrade-stage-during-copy; test_fail upgrade-stage-during-copy
    fi
    /usr/bin/ditto "${candidate}" "${staging}"
    [[ "$(/usr/bin/stat -f %i "${staging}")" == "${staging_inode}" ]] ||
      fail "The upgrade staging inode changed during candidate copy."
    normalize_published_app "${staging}" "$(state_value new_host_cdhash "${transaction}/upgrade.journal")"
    upgrade_probe_tmp="${transaction}/upgrade-pair.source-after.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The source reinspection temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${candidate}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}" copying-unverified
    dispose_upgrade_temp
    upgrade_probe_tmp="${transaction}/upgrade-pair.staged.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The staged inspection temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${staging}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}" copying-unverified
    dispose_upgrade_temp
    write_upgrade_staging_substate "${staging_inode}" verified
    retain_upgrade_lock_as upgrade-copying-verified
    test_hook upgrade-stage-after-copy; test_fail upgrade-stage-after-copy
    print 'upgrade_staging=fixture-only-pass'
    print 'upgrade_phase=copying'
    print 'staging_verification=verified'
    ;;
  probe-staged-upgrade-fixture)
    candidate="${3:-}"; [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    require_retained_upgrade_lock upgrade-copying-verified
    require_upgrade_journal
    staging="${transaction}/DNIeTokenHost.app.staging"
    require_normalizable_app_topology "${destination}"
    require_normalizable_app_topology "${candidate}"
    require_normalizable_app_topology "${staging}"
    upgrade_probe_tmp="${transaction}/upgrade-pair.source-probe.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The source probe temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${candidate}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}" verified
    dispose_upgrade_temp
    upgrade_probe_tmp="${transaction}/upgrade-pair.staged-probe.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The staged probe temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${staging}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}" verified
    dispose_upgrade_temp
    print 'upgrade_staging_probe=fixture-only-pass'
    print 'upgrade_phase=copying'
    ;;
  retain-old-upgrade-fixture)
    candidate="${3:-}"; [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    require_retained_upgrade_lock upgrade-copying-verified
    require_upgrade_journal
    [[ "$(state_value phase "${transaction}/upgrade.journal")" == copying ]] ||
      fail "Old retention requires the exact copying-phase journal."
    require_fixture_artifacts_inactive
    staging="${transaction}/DNIeTokenHost.app.staging"
    require_normalizable_app_topology "${destination}"
    require_normalizable_app_topology "${candidate}"
    require_normalizable_app_topology "${staging}"
    upgrade_probe_tmp="${transaction}/upgrade-pair.old-retain-source-before.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The old-retention source inspection temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${candidate}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}" verified
    dispose_upgrade_temp
    upgrade_probe_tmp="${transaction}/upgrade-pair.old-retain-staged-before.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The old-retention staged inspection temporary collided."
    "${inspector}" --upgrade-pair "${destination}" "${staging}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_upgrade_preparation_relationships "${candidate}" "${upgrade_probe_tmp}" verified
    dispose_upgrade_temp
    claim_old_retention_transition
    require_old_retention_claim upgrade-old-retention-armed 1
    archive="${transaction}/DNIeTokenHost.app.old"
    [[ -d "${destination}" && ! -L "${destination}" &&
       "$(/usr/bin/stat -f %u "${destination}")" == "${EUID}" &&
       "$(/usr/bin/stat -f %Lp "${destination}")" == 755 &&
       "$(/usr/bin/stat -f %i "${destination}")" == "$(state_value destination_inode "${transaction}/upgrade.journal")" &&
       ! -e "${archive}" && ! -L "${archive}" ]] ||
      fail "The exact old destination cannot be retained into the collision-free archive."
    test_hook upgrade-old-retention-before-move; test_fail upgrade-old-retention-before-move
    /bin/mv "${destination}" "${archive}"
    [[ -d "${archive}" && ! -L "${archive}" &&
       "$(/usr/bin/stat -f %u "${archive}")" == "${EUID}" &&
       "$(/usr/bin/stat -f %Lp "${archive}")" == 755 &&
       "$(/usr/bin/stat -f %i "${archive}")" == "$(state_value destination_inode "${transaction}/upgrade.journal")" &&
       ! -e "${destination}" && ! -L "${destination}" ]] ||
      fail "The old-app archive move did not preserve the exact inode and absent destination."
    test_hook upgrade-old-retention-after-move; test_fail upgrade-old-retention-after-move
    upgrade_probe_tmp="${transaction}/upgrade-pair.old-retain-source-after.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The retained source inspection temporary collided."
    "${inspector}" --upgrade-pair "${archive}" "${candidate}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_old_retained_relationships "${candidate}" "${upgrade_probe_tmp}" "${upgrade_probe_tmp}" copying
    dispose_upgrade_temp
    upgrade_probe_tmp="${transaction}/upgrade-pair.old-retain-staged-after.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The retained staged inspection temporary collided."
    "${inspector}" --upgrade-pair "${archive}" "${staging}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_old_retained_relationships "${candidate}" "${upgrade_probe_tmp}" "${upgrade_probe_tmp}" copying
    dispose_upgrade_temp
    write_upgrade_phase old-retained
    test_hook upgrade-old-retention-after-phase; test_fail upgrade-old-retention-after-phase
    retain_old_retention_owner
    print 'upgrade_old_retention=fixture-only-pass'
    print 'upgrade_phase=old-retained'
    ;;
  arm-upgrade-rollback-fixture)
    candidate="${3:-}"; [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    require_fixture_artifacts_inactive
    classify_upgrade_recovery_entry
    require_upgrade_recovery_artifacts "${rollback_predecessor_topology}" "${candidate}" committed
    claim_upgrade_rollback_transition
    test_hook upgrade-rollback-before-journal; test_fail upgrade-rollback-before-journal
    test_mutate_rollback_authority before-journal
    require_upgrade_rollback_prewrite "${rollback_predecessor_phase}" committed "${rollback_predecessor_operation}" "${candidate}"
    write_upgrade_rollback_journal
    test_hook upgrade-rollback-after-journal; test_fail upgrade-rollback-after-journal
    test_hook upgrade-rollback-before-state; test_fail upgrade-rollback-before-state
    test_mutate_rollback_authority before-state
    require_upgrade_rollback_prewrite rollback-armed committed "${rollback_predecessor_operation}" "${candidate}"
    write_upgrade_rollback_state
    test_hook upgrade-rollback-after-state; test_fail upgrade-rollback-after-state
    test_hook upgrade-rollback-before-owner; test_fail upgrade-rollback-before-owner
    test_mutate_rollback_authority before-owner
    require_upgrade_rollback_prewrite rollback-armed pending "${rollback_predecessor_operation}" "${candidate}"
    write_upgrade_rollback_owner
    test_hook upgrade-rollback-after-owner; test_fail upgrade-rollback-after-owner
    print 'upgrade_rollback_arming=fixture-only-pass'
    print 'upgrade_phase=rollback-armed'
    ;;
  probe-armed-upgrade-rollback-fixture)
    candidate="${3:-}"; [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    require_upgrade_journal
    [[ "$(state_value phase "${transaction}/upgrade.journal")" == rollback-armed ]] ||
      fail "The upgrade journal is not at the exact rollback-armed phase."
    require_upgrade_rollback_claim
    require_fixture_artifacts_inactive
    require_upgrade_recovery_artifacts "$(state_value rollback_predecessor_topology "${transaction}/upgrade.journal")" "${candidate}" pending
    print 'upgrade_rollback_arming_probe=fixture-only-pass'
    print 'upgrade_phase=rollback-armed'
    ;;
  probe-old-retained-upgrade-fixture)
    candidate="${3:-}"; [[ -n "${candidate}" ]] || fail "A fixed candidate artifact path is required." 64
    require_fixture_ancestors "${candidate}" || fail "The candidate path is outside the canonical fixture scope."
    require_upgrade_journal
    [[ "$(state_value phase "${transaction}/upgrade.journal")" == old-retained ]] ||
      fail "The upgrade journal is not at the exact old-retained phase."
    require_old_retention_claim upgrade-old-retained
    require_fixture_artifacts_inactive
    archive="${transaction}/DNIeTokenHost.app.old"
    staging="${transaction}/DNIeTokenHost.app.staging"
    require_normalizable_app_topology "${archive}"
    require_normalizable_app_topology "${candidate}"
    require_normalizable_app_topology "${staging}"
    upgrade_probe_tmp="${transaction}/upgrade-pair.old-retained-source-probe.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The old-retained source probe temporary collided."
    "${inspector}" --upgrade-pair "${archive}" "${candidate}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_old_retained_relationships "${candidate}" "${upgrade_probe_tmp}" "${upgrade_probe_tmp}"
    dispose_upgrade_temp
    upgrade_probe_tmp="${transaction}/upgrade-pair.old-retained-staged-probe.${upgrade_temp_suffix}"
    claim_upgrade_temp "${upgrade_probe_tmp}" "The old-retained staged probe temporary collided."
    "${inspector}" --upgrade-pair "${archive}" "${staging}" > "${upgrade_probe_tmp}"
    /bin/chmod 600 "${upgrade_probe_tmp}"
    require_old_retained_relationships "${candidate}" "${upgrade_probe_tmp}" "${upgrade_probe_tmp}"
    dispose_upgrade_temp
    print 'upgrade_old_retention_probe=fixture-only-pass'
    print 'upgrade_phase=old-retained'
    ;;
  register-securityagent)
    expected="${3:-}"; [[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]] || fail "The expected artifact identity is invalid." 64
    if direct_token "${token}" && [[ ! -e "${transaction}" && ! -L "${transaction}" ]]; then
      acquire_lock register-securityagent direct
      require_direct_ownership_state pending-install "${expected:l}" "${token}"
    else
      acquire_lock register-securityagent
    fi
    require_owned_state pending-install "${expected:l}" "${token}"
    [[ "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] || fail "The pending installed artifact changed before _securityagent registration."
    host_executable="${destination}/Contents/MacOS/DNIeTokenHost"
    expected_uid=0; [[ "${test_mode}" == 1 ]] && expected_uid="${EUID}"
    host_mode="$(/usr/bin/stat -f %Lp "${host_executable}" 2>/dev/null || true)"
    [[ -f "${host_executable}" && ! -L "${host_executable}" && -x "${host_executable}" &&
       "$(/usr/bin/stat -f %u "${host_executable}")" == "${expected_uid}" && "${host_mode}" == <-> ]] &&
      [[ "$(/usr/bin/stat -f %l "${host_executable}")" == 1 ]] &&
      (( (8#${host_mode} & 8#111) == 8#111 && (8#${host_mode} & 8#022) == 0 )) ||
      fail "The exact pending installed host executable is unsafe."
    if [[ "${test_mode}" == 1 ]]; then
      print -r -- "actor=_securityagent" > "${test_root}/securityagent-invocation"
      print -r -- "host=${host_executable}" >> "${test_root}/securityagent-invocation"
      [[ "${DNIE_LIFECYCLE_TEST_SECURITYAGENT_FAIL:-0}" != 1 ]] || fail "Injected _securityagent registration failure."
    else
      /usr/bin/sudo -n -u _securityagent "${host_executable}" >/dev/null 2>&1 ||
        fail "The fixed _securityagent host invocation failed."
    fi
    release_lock
    print 'securityagent_registration=pass'
    ;;
  install)
    source_app="${3:-}"; expected="${4:-}"
    [[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]] || fail "The expected artifact identity is invalid." 64
    if [[ "${test_mode}" == 1 ]]; then
      require_fixture_ancestors "${source_app}"
    else
      [[ "${source_app}" == /* ]]
    fi || fail "The source path is outside the authorized canonical scope."
    [[ ! -e "${destination}" && ! -L "${destination}" && ! -e "${state_file}" ]] || fail "Fresh install refuses an existing destination or ownership state."
    acquire_lock install
    /bin/mkdir "${transaction}"
    write_transaction_state copying
    before="$(inspect_cdhash "${source_app}")"; [[ "${before}" == "${expected:l}" ]] || fail "The source artifact identity changed before publication."
    require_normalizable_app_topology "${source_app}"
    staging="${transaction}/DNIeTokenHost.app.staging"
    /usr/bin/ditto "${source_app}" "${staging}"
    if [[ "${test_mode}" == 1 && "${DNIE_LIFECYCLE_TEST_MUTATE_SOURCE_AFTER_COPY:-0}" == 1 ]]; then
      /usr/bin/sed -i '' \
        -e 's/^host_cdhash=.*/host_cdhash=ffffffffffffffffffffffffffffffffffffffff/' \
        -e 's/^cdhash=.*/cdhash=ffffffffffffffffffffffffffffffffffffffff/' \
        "${source_app}/Contents/Resources/pilot-artifact-metadata"
    fi
    staged="$(inspect_cdhash "${staging}")"; after="$(inspect_cdhash "${source_app}")"
    [[ "${staged}" == "${expected:l}" && "${after}" == "${expected:l}" ]] || fail "The source or staged artifact changed during publication."
    normalize_published_app "${staging}" "${expected:l}"
    [[ ! -e "${destination}" && ! -L "${destination}" ]] || fail "The destination appeared during publication; staging was retained."
    /bin/mkdir -m 700 "${destination}" || fail "The no-overwrite destination claim failed; staging was retained."
    publication_inode="$(/usr/bin/stat -f %i "${destination}")"
    write_transaction_state publishing "${publication_inode}"
    test_kill install-after-claim
    /usr/bin/ditto "${staging}" "${destination}"
    [[ -d "${destination}" && ! -L "${destination}" && "$(/usr/bin/stat -f %i "${destination}")" == "${publication_inode}" ]] ||
      fail "The claimed destination changed during publication."
    /bin/rm -rf -- "${staging}"
    [[ "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] || fail "The published app failed exact artifact verification."
    normalize_published_app "${destination}" "${expected:l}"
    write_state pending-install "${expected:l}" "${token}"
    write_transaction_state pending-install
    publication_inode=""
    test_hook install-after-publish
    release_lock
    print "lifecycle_transaction=${transaction}"
    ;;
  commit-install)
    expected="${3:-}"; acquire_lock commit-install; require_owned_state pending-install "${expected:l}" "${token}"
    [[ "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] || fail "The installed artifact changed before commit."
    test_fail commit-install-before-write
    write_transaction_state commit-install-intent
    write_state committed "${expected:l}" "${token}"
    test_fail commit-install-after-state; test_kill commit-install-after-state
    write_transaction_state installed; release_lock
    ;;
  rollback-install)
    expected="${3:-}"
    if [[ -d "${lock}" ]]; then adopt_stale_lock_for_commit_recovery rollback-install; else acquire_lock rollback-install; fi
    install_rollback_state_valid "${expected:l}" || fail "Install rollback is not an exact recoverable pending/commit-intent topology."
    [[ "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] || fail "Rollback refuses an unrecognized installed artifact."
    [[ ! -e "${transaction}/DNIeTokenHost.app.failed-install" && ! -L "${transaction}/DNIeTokenHost.app.failed-install" ]] || fail "The failed-install archive target already exists."
    /bin/mv "${destination}" "${transaction}/DNIeTokenHost.app.failed-install"
    [[ ! -e "${destination}" ]] || fail "Install rollback did not withdraw the exact app."
    /bin/rm -f -- "${state_file}"; write_transaction_state failed-install-retained; release_lock
    print "retained_recovery=${transaction}/DNIeTokenHost.app.failed-install"
    ;;
  rollback-pending-install)
    expected="${3:-}"
    [[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]] || fail "The pending recovery artifact identity is invalid." 64
    if [[ -d "${lock}" ]]; then
      require_stale_lock
      require_transaction_state
      pending_install_state_valid "${expected:l}" || fail "Pending-install rollback requires the exact uncommitted pending topology."
      adopt_stale_lock rollback-pending-install pending-install "${expected:l}"
    else
      acquire_lock rollback-pending-install
    fi
    require_transaction_state
    pending_install_state_valid "${expected:l}" || fail "Pending-install rollback requires the exact uncommitted pending topology."
    [[ "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] || fail "Pending-install rollback refuses an unrecognized installed artifact."
    [[ ! -e "${transaction}/DNIeTokenHost.app.failed-install" && ! -L "${transaction}/DNIeTokenHost.app.failed-install" ]] || fail "The failed-install archive target already exists."
    /bin/mv "${destination}" "${transaction}/DNIeTokenHost.app.failed-install"
    [[ ! -e "${destination}" ]] || fail "Pending-install rollback did not withdraw the exact app."
    /bin/rm -f -- "${state_file}"
    write_transaction_state failed-install-retained
    release_lock
    print "retained_recovery=${transaction}/DNIeTokenHost.app.failed-install"
    ;;
  uninstall)
    expected="${3:-}"; [[ -d "${destination}" && ! -L "${destination}" ]] || fail "The owned install destination is missing or unsafe."
    acquire_lock uninstall; require_owned_state committed "${expected:l}"
    [[ "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] || fail "Uninstall refuses an app that differs from recorded ownership."
    /bin/mkdir "${transaction}"; write_transaction_state withdrawing
    [[ ! -e "${transaction}/DNIeTokenHost.app" && ! -L "${transaction}/DNIeTokenHost.app" ]] || fail "The uninstall archive target already exists."
    /bin/mv "${destination}" "${transaction}/DNIeTokenHost.app"
    [[ ! -e "${destination}" && -d "${transaction}/DNIeTokenHost.app" ]] || fail "Recoverable withdrawal did not complete."
    test_kill uninstall-after-withdrawal
    write_state pending-uninstall "${expected:l}" "${token}"; write_transaction_state pending-uninstall; release_lock
    test_hook uninstall-after-withdrawal
    print "retained_recovery=${transaction}/DNIeTokenHost.app"
    ;;
  commit-uninstall)
    expected="${3:-}"; acquire_lock commit-uninstall; require_owned_state pending-uninstall "${expected:l}" "${token}"
    [[ ! -e "${destination}" && -d "${transaction}/DNIeTokenHost.app" ]] || fail "Uninstall commit found ambiguous filesystem state."
    test_fail commit-uninstall-before-write
    write_transaction_state commit-uninstall-intent
    /bin/rm -f -- "${state_file}"
    test_fail commit-uninstall-after-state; test_kill commit-uninstall-after-state
    write_transaction_state uninstalled-retained; release_lock
    print "retained_uninstall_archive=${transaction}/DNIeTokenHost.app"
    ;;
  rollback-uninstall)
    expected="${3:-}"
    if [[ -d "${lock}" ]]; then adopt_stale_lock_for_commit_recovery rollback-uninstall; else acquire_lock rollback-uninstall; fi
    uninstall_rollback_state_valid "${expected:l}" || fail "Uninstall rollback is not an exact recoverable pending/commit-intent topology."
    [[ ! -e "${destination}" && -d "${transaction}/DNIeTokenHost.app" ]] || fail "Uninstall rollback found ambiguous filesystem state."
    claim_and_restore_app "${transaction}/DNIeTokenHost.app" "${expected:l}"
    write_state committed "${expected:l}" "${token}"; write_transaction_state uninstall-rolled-back; release_lock
    ;;
  probe-rollback-install)
    expected="${3:-}"; [[ ! -d "${lock}" ]] || require_stale_lock; require_transaction_state
    install_rollback_state_valid "${expected:l}" || fail "Install rollback probe rejected a valid committed or unknown topology."
    print 'install_rollback_recoverable=true'
    ;;
  probe-pending-install)
    expected="${3:-}"
    [[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]] || fail "The pending recovery artifact identity is invalid." 64
    [[ ! -d "${lock}" ]] || require_stale_lock
    require_transaction_state
    pending_install_state_valid "${expected:l}" || fail "Pending-install probe rejected a committed or unknown topology."
    [[ -d "${destination}" && ! -L "${destination}" && "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] ||
      fail "Pending-install probe rejected the exact installed artifact identity."
    print 'pending_install_recoverable=true'
    print "pending_install_token=${token}"
    print "pending_install_cdhash=${expected:l}"
    ;;
  probe-rollback-uninstall)
    expected="${3:-}"; [[ ! -d "${lock}" ]] || require_stale_lock; require_transaction_state
    uninstall_rollback_state_valid "${expected:l}" || fail "Uninstall rollback probe rejected an unknown topology."
    print 'uninstall_rollback_recoverable=true'
    ;;
  recover-interrupted)
    expected="${3:-}"; [[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]] || fail "The recovery artifact identity is invalid." 64
    require_stale_lock; require_transaction_state
    phase="$(state_value phase "${transaction}/transaction.state")"
    lock_held=1
    case "${phase}" in
      copying)
        [[ ! -e "${destination}" && ! -L "${destination}" && ! -e "${state_file}" ]] || fail "Interrupted copy recovery found ambiguous installed state."
        write_transaction_state interrupted-copy-retained
        ;;
      publishing)
        recorded_inode="$(state_value destination_inode "${transaction}/transaction.state")"
        [[ "${recorded_inode}" == <-> && ! -e "${state_file}" ]] || fail "Interrupted publication recovery lacks exact inode ownership."
        if [[ -e "${destination}" || -L "${destination}" ]]; then
          [[ -d "${destination}" && ! -L "${destination}" && "$(/usr/bin/stat -f %i "${destination}")" == "${recorded_inode}" &&
             ! -e "${transaction}/DNIeTokenHost.app.failed-interrupted" && ! -L "${transaction}/DNIeTokenHost.app.failed-interrupted" ]] ||
            fail "Interrupted publication recovery found a destination ownership collision."
          /bin/mv "${destination}" "${transaction}/DNIeTokenHost.app.failed-interrupted"
        fi
        write_transaction_state interrupted-publication-retained
        ;;
      withdrawing)
        require_owned_state committed "${expected:l}"
        archive="${transaction}/DNIeTokenHost.app"
        if [[ -d "${destination}" && ! -L "${destination}" && ! -e "${archive}" ]]; then
          [[ "$(inspect_cdhash "${destination}")" == "${expected:l}" ]] || fail "Interrupted withdrawal left an unrecognized destination."
        elif [[ ! -e "${destination}" && ! -L "${destination}" && -d "${archive}" && ! -L "${archive}" ]]; then
          claim_and_restore_app "${archive}" "${expected:l}"
        else
          fail "Interrupted withdrawal recovery found ambiguous app/archive topology."
        fi
        write_transaction_state interrupted-withdrawal-restored
        ;;
      *) fail "The retained transaction phase is not eligible for bounded interruption recovery." ;;
    esac
    release_lock
    print "interrupted_recovery=${phase}"
    ;;
  probe-absent)
    acquire_lock probe-absent
    [[ ! -e "${destination}" && ! -L "${destination}" && ! -e "${state_file}" ]] || fail "Absent uninstall state is not clean; recovery is required."
    release_lock
    print 'pilot_installation=absent'
    ;;
  *) fail "usage: ${0:t} {authorize|publish-pilot|confirm-pilot|probe-pilot-removal|remove-pilot|prepare-upgrade-fixture|probe-upgrade-fixture|stage-upgrade-fixture|probe-staged-upgrade-fixture|retain-old-upgrade-fixture|probe-old-retained-upgrade-fixture|arm-upgrade-rollback-fixture|probe-armed-upgrade-rollback-fixture|register-securityagent|install|commit-install|rollback-install|rollback-pending-install|probe-pending-install|uninstall|commit-uninstall|rollback-uninstall|probe-rollback-uninstall|recover-interrupted} TOKEN [SOURCE] [CDHASH|absent] [DEVICE:INODE]" 64 ;;
esac
