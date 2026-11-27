#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
default_repository_root="${script_dir:h:h:h}"
test_mode="${DNIE_WORKFLOW_TEST_MODE:-0}"

if [[ "${test_mode}" == 1 ]]; then
  repository_root="${DNIE_WORKFLOW_REPOSITORY_ROOT:?test repository root is required}"
  bin_dir="${DNIE_WORKFLOW_BIN_DIR:?test binary directory is required}"
  [[ "${repository_root}" == /private/tmp/* && "${bin_dir}" == /private/tmp/* ]]
else
  repository_root="${default_repository_root}"
  bin_dir=""
  for variable in ${(k)parameters}; do
    [[ "${variable}" == DNIE_WORKFLOW_* ]] || continue
    [[ "${variable}" == DNIE_WORKFLOW_TEST_MODE ]] && continue
    print -u2 "Test-only workflow overrides are not accepted outside offline test mode."
    exit 64
  done
fi

tool() {
  local name="$1"
  if [[ -n "${bin_dir}" ]]; then
    print -r -- "${bin_dir}/${name}"
  else
    command -v "${name}"
  fi
}

fail() {
  print -u2 -- "$1"
  exit "${2:-1}"
}

require_normal_user() {
  (( EUID != 0 )) || fail "Do not run the development workflow through sudo/root; signing, private-fixture staging, DerivedData, and registration inspection belong to the invoking user."
}

resolve_signing_identity() {
  local security_command="$(tool security)"
  local requested="${DNIE_SIGNING_IDENTITY_SHA1:-}"
  local output=""
  local hashes=()
  output="$(${security_command} find-identity -v -p codesigning)" ||
    fail "Unable to inspect code-signing identities."
  hashes=("${(@f)$(print -r -- "${output}" | awk '
    /Apple Development/ {
      for (i = 1; i <= NF; i++) {
        value = $i
        gsub(/[^[:xdigit:]]/, "", value)
        if (length(value) == 40) { print toupper(value); break }
      }
    }
  ')}")
  hashes=("${(@)hashes:#}")

  if [[ -n "${requested}" ]]; then
    [[ "${requested}" =~ '^[[:xdigit:]]{40}$' ]] ||
      fail "DNIE_SIGNING_IDENTITY_SHA1 must be exactly one 40-hex Apple Development identity hash." 64
    requested="${requested:u}"
    (( ${hashes[(I)${requested}]} > 0 )) ||
      fail "The explicitly selected Apple Development identity is not currently valid."
    signing_identity="${requested}"
    return
  fi

  if (( ${#hashes} == 0 )); then
    fail "No valid Apple Development code-signing identity was found."
  fi
  if (( ${#hashes} != 1 )); then
    fail "There are multiple valid Apple Development identities; select one with DNIE_SIGNING_IDENTITY_SHA1 without printing it in logs."
  fi
  signing_identity="${hashes[1]}"
}

check_environment() {
  local uname_command="$(tool uname)"
  local sw_vers_command="$(tool sw_vers)"
  local xcodebuild_command="$(tool xcodebuild)"
  local xcrun_command="$(tool xcrun)"
  local observed_arch observed_version observed_build observed_xcode observed_xcode_build observed_sdk observed_swift
  observed_arch="$(${uname_command} -m)"
  observed_version="$(${sw_vers_command} -productVersion)"
  observed_build="$(${sw_vers_command} -buildVersion)"
  observed_xcode="$(${xcodebuild_command} -version 2>/dev/null | sed -n '1p')"
  observed_xcode_build="$(${xcodebuild_command} -version 2>/dev/null | sed -n '2p')"
  observed_sdk="$(${xcrun_command} --show-sdk-version 2>/dev/null)"
  observed_swift="$(${xcrun_command} swift --version 2>&1)"

  if [[ "${observed_arch}" != arm64 || "${observed_version}" != 26.6.2 ||
        "${observed_build}" != 25G83 || "${observed_xcode}" != 'Xcode 26.6' ||
        "${observed_xcode_build}" != 'Build version 17F113' || "${observed_sdk}" != 26.5 ||
        "${observed_swift}" != *'Apple Swift version 6.3.3'* ]]; then
    print -u2 "The machine does not match the recorded product evidence environment; current runtime/build support remains UNKNOWN, not unsupported."
    print -u2 "observed_arch=${observed_arch}"
    print -u2 "observed_macos_version=${observed_version}"
    print -u2 "observed_macos_build=${observed_build}"
    print -u2 "observed_xcode=${observed_xcode}"
    print -u2 "observed_xcode_build=${observed_xcode_build}"
    print -u2 "observed_sdk=${observed_sdk}"
    print "environment_evidence_match=unknown"
    return
  fi
  print "environment_evidence_match=pass"
}

check_fixture_metadata() {
  local fixture="${repository_root}/Validation/private/SecureChannel/generation2.json"
  local stat_command="$(tool stat)"
  local git_command="$(tool git)"
  [[ -f "${fixture}" && ! -L "${fixture}" ]] ||
    fail "The authorized local generation-2 fixture is missing or is a symlink."
  [[ "$(${stat_command} -f '%Lp' "${fixture}")" == 600 ]] ||
    fail "The authorized local generation-2 fixture must have mode 0600."
  ${git_command} -C "${repository_root}" check-ignore --quiet "${fixture}" ||
    fail "The authorized local generation-2 fixture is not ignored by Git."
  print "credential_fixture_metadata=pass"
  print "credential_fixture_bytes_read=false"
}

run_build_preflight() {
  check_environment
  check_fixture_metadata
  resolve_signing_identity
  print "signing_selection=pass"
  print "signing_identity_logged=false"
}

run_check() {
  check_environment
  zsh -n "${script_dir}/developer-workflow.sh" "${script_dir}/build-development.sh" \
    "${script_dir}/prepare-installed-path.sh" "${script_dir}/inspect-registration.sh" \
    "${default_repository_root}/Validation/Scripts/stage-production-credential-asset.sh" \
    "${default_repository_root}/Validation/Scripts/test-stage-production-credential-asset.sh"
  "${default_repository_root}/Validation/Scripts/test-stage-production-credential-asset.sh"
  print "developer_workflow_syntax=pass"
  print "credential_fixture_inspected=false"
  print "signing_keychain_inspected=false"
  print "card_private_operation=false"
}

test_override() {
  local variable="$1"
  local fallback="$2"
  if [[ "${test_mode}" == 1 ]]; then
    print -r -- "${(P)variable:-${fallback}}"
  else
    print -r -- "${fallback}"
  fi
}

run_build() {
  require_normal_user
  local build_script="$(test_override DNIE_WORKFLOW_BUILD_SCRIPT "${script_dir}/build-development.sh")"
  "${build_script}" --check-build-slot >/dev/null
  run_build_preflight
  DNIE_SIGNING_IDENTITY_SHA1="${signing_identity}" "${build_script}"
}

development_cleanup_tool() {
  local -a arguments=()
  if [[ "${test_mode}" == 1 ]]; then
    arguments=(--fixture "${repository_root}" "${bin_dir}")
  fi
  /usr/bin/python3 -B "${script_dir}/clean-development.py" "${arguments[@]}" "$@"
}

run_clean() {
  require_normal_user
  development_cleanup_tool
}

hold_development_lock() {
  require_normal_user
  # The helper validates the inherited directory and locks its shared open file
  # description. This shell keeps the descriptor through lifecycle postflight.
  exec {development_lock_fd}<"${repository_root}"
  development_cleanup_tool --lock "${development_lock_fd}"
}

restore_missing_development_app() {
  local app="$1" expected="$2"
  [[ ! -e "${app}" && ! -L "${app}" ]] || return 0
  [[ "${app}" == "${repository_root}/DerivedData/T067/Build/Products/Release/DNIeTokenHost.app" ]] || return 0
  development_cleanup_tool --restore "${development_lock_fd}" "${expected}"
}

prune_completed_development_app() {
  development_cleanup_tool --prune "${development_lock_fd}" "${1:l}" ||
    print -u2 'The exact recovery cache entry was retained for explicit review.'
}

inspect_artifact() {
  local inspector_script="$(test_override DNIE_WORKFLOW_ARTIFACT_INSPECTOR "${script_dir}/inspect-pilot-artifact.sh")"
  "${inspector_script}" "$1"
}

artifact_field() {
  print -r -- "$1" | sed -n "s/^$2=//p"
}

artifact_cdhash() {
  local output
  output="$(inspect_artifact "$1")" || return 1
  artifact_field "${output}" artifact_cdhash
}

registration_snapshot() {
  local pluginkit_command="$(tool pluginkit)"
  "${pluginkit_command}" -m -A -D -vvv -i org.dniemacos.dnietoken.tokenextension 2>/dev/null
}

active_paths_for_identifier() {
  active_registrations_for_identifier "$1" "$2" | /usr/bin/cut -f 2-
}

active_registrations_for_identifier() {
  print -r -- "$1" | awk -v id="$2" '
    function finish_record() {
      if (!in_record) return
      if (target) { if (!usable || path == "" || version == "") invalid=1; else records[++count]=version "\t" path }
      in_record=0; target=0; usable=0; path=""; version=""
    }
    function start_header(line, raw, status, header_id) {
      raw=line; status=substr(raw,1,1)
      if (status ~ /[+!\-=\?]/) raw=substr(raw,2); else status=""
      sub(/^[[:space:]]*/, "", raw)
      if (raw !~ /^[^[:space:]]+[[:space:]]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/) return 0
      header_id=raw; sub(/[[:space:]]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/, "", header_id)
      finish_record(); version=raw; sub(/^.*\(/, "", version); sub(/\)$/, "", version)
      in_record=1; target=(header_id==id); usable=(status=="" || status=="+" || status=="!"); path=""; return 1
    }
    function shaped(line, raw, status) {
      raw=line; status=substr(raw,1,1); if (status ~ /[+!\-=\?]/) raw=substr(raw,2)
      sub(/^[[:space:]]*/, "", raw); return raw ~ /^[^[:space:]]+[[:space:]]*\([^)]*\)$/
    }
    function malformed_target(line, raw, status, boundary) {
      raw=line; status=substr(raw,1,1); if (status ~ /[+!\-=\?]/) raw=substr(raw,2)
      sub(/^[[:space:]]*/, "", raw); boundary=substr(raw,length(id)+1,1)
      return index(raw,id)==1 && (boundary=="" || boundary ~ /[[:space:]\(]/)
    }
    { if (start_header($0)) next
      if (in_record && target && shaped($0)) { invalid=1; finish_record(); next }
      if (malformed_target($0)) { invalid=1; next }
      if (in_record && target && $0 ~ /^[[:space:]]*Path = /) {
        if (path!="") invalid=1; else { path=$0; sub(/^[[:space:]]*Path = /,"",path) }
      }
    }
    END { finish_record(); if (invalid) exit 1; for (i=1;i<=count;i++) print records[i] }'
}

registration_is_exact_path_version() {
  local expected_path="$1" expected_version="$2" snapshot="$3" records
  [[ "${expected_version}" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || return 1
  records="$(active_registrations_for_identifier "${snapshot}" org.dniemacos.dnietoken.tokenextension)" || return 1
  [[ "${records}" == "${expected_version}"$'\t'"${expected_path}" &&
     "$(print -r -- "${records}" | sed '/^$/d' | wc -l | tr -d ' ')" == 1 ]]
}

registration_is_exact_path() {
  local expected="$1" snapshot="$2" paths
  paths="$(active_paths_for_identifier "${snapshot}" org.dniemacos.dnietoken.tokenextension)" || return 1
  [[ "${paths}" == "${expected}" && "$(print -r -- "${paths}" | sed '/^$/d' | wc -l | tr -d ' ')" == 1 ]]
}

require_registration_path() {
  registration_is_exact_path "$1" "$2" ||
    fail "The production provider registration is stale, duplicated, or points outside the exact accepted path."
}

registration_is_absent() {
  local snapshot="$1" paths
  paths="$(active_paths_for_identifier "${snapshot}" org.dniemacos.dnietoken.tokenextension)" || return 1
  [[ -z "${paths}" ]]
}

registration_classification() {
  local expected="$1" snapshot="$2"
  if registration_is_exact_path "${expected}" "${snapshot}"; then print exact-installed
  elif registration_is_absent "${snapshot}"; then print absent
  else return 1
  fi
}

require_no_registration() {
  registration_is_absent "$1" || fail "A stale or competing production-provider registration remains visible."
}

require_app_inactive() {
  local app="$1" pgrep_command="$(tool pgrep)" pattern observed_status
  for pattern in \
    "^${app}/Contents/MacOS/DNIeTokenHost([[:space:]]|$)" \
    "^${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension([[:space:]]|$)"; do
    if "${pgrep_command}" -f "${pattern}" >/dev/null 2>&1; then
      fail "The exact host or provider is active; lifecycle mutation is forbidden."
    else
      observed_status=$?
      (( observed_status == 1 )) || fail "Unable to establish that the exact host and provider are inactive; lifecycle mutation is forbidden."
    fi
  done
}

run_with_lifecycle_transport() {
  local lifecycle_transport
  # sudo can use the controlling terminal even when a phase captures or redirects output.
  if [[ "${test_mode}" == 1 && -n "${DNIE_WORKFLOW_TEST_AUTHORIZATION_TRANSPORT:-}" ]]; then
    lifecycle_transport="${DNIE_WORKFLOW_TEST_AUTHORIZATION_TRANSPORT}"
  elif ( : </dev/tty ) 2>/dev/null; then
    lifecycle_transport=sudo
  else
    lifecycle_transport=native-gui
  fi
  "$@"
}

run_root_lifecycle() {
  local root_helper="$(test_override DNIE_WORKFLOW_ROOT_HELPER "${script_dir}/pilot-lifecycle-root.sh")"
  if [[ "${test_mode}" == 1 && "${DNIE_WORKFLOW_TEST_EXERCISE_AUTHORIZATION_TRANSPORT:-0}" != 1 ]]; then
    if [[ "${DNIE_WORKFLOW_TEST_REFUSE_ROOT_COMMAND:-}" == "${1:-}" ]]; then return 77; fi
    "${root_helper}" "$@"
  else
    local inspector_source="${script_dir}/inspect-pilot-artifact.sh" helper_digest inspector_digest invoking_uid
    local bootstrap_payload privileged_command apple_command argument
    local -a privileged_arguments
    helper_digest="$(/usr/bin/shasum -a 256 "${root_helper}" | /usr/bin/cut -d ' ' -f 1)"
    inspector_digest="$(/usr/bin/shasum -a 256 "${inspector_source}" | /usr/bin/cut -d ' ' -f 1)"
    invoking_uid="$(/usr/bin/id -u)"
    [[ "${invoking_uid}" == <-> && "${invoking_uid}" -ne 0 ]] || fail "The lifecycle caller must be an identified normal user."
    # BOOTSTRAP_PAYLOAD_BEGIN: extracted by the isolated executable bootstrap test.
    bootstrap_payload='
      set -euo pipefail; umask 077
      helper_source="$1"; inspector_source="$2"; helper_digest="$3"; inspector_digest="$4"; caller_uid="$5"; shift 5
      bootstrap_test_root="${DNIE_BOOTSTRAP_TEST_ROOT:-}"; bootstrap_test_only="${DNIE_BOOTSTRAP_TEST_ONLY:-0}"
      if (( EUID == 0 )); then
        [[ -z "${bootstrap_test_root}" && "${bootstrap_test_only}" == 0 && "${caller_uid}" == <-> && "${caller_uid}" -ne 0 ]] || exit 70
        [[ -z "${SUDO_UID:-}" || "${SUDO_UID}" == "${caller_uid}" ]] || exit 70
        source_uid="${caller_uid}"; target_uid=0; base="/Library/Application Support/org.dniemacos.dnietoken"
      else
        [[ "${bootstrap_test_only}" == 1 && "${bootstrap_test_root}" == /private/tmp/dnie-pilot-bootstrap-test.* &&
           "${bootstrap_test_root:A}" == "${bootstrap_test_root}" && -d "${bootstrap_test_root}" && ! -L "${bootstrap_test_root}" &&
           "$(/usr/bin/stat -f %u "${bootstrap_test_root}")" == "${EUID}" ]] || exit 70
        source_uid="${EUID}"; target_uid="${EUID}"; base="${bootstrap_test_root}/Library/Application Support/org.dniemacos.dnietoken"
      fi
      for source expected in "${helper_source}" "${helper_digest}" "${inspector_source}" "${inspector_digest}"; do
        [[ "${source:A}" == "${source}" && -f "${source}" && ! -L "${source}" &&
           "$(/usr/bin/stat -f %u "${source}")" == "${source_uid}" && "$(/usr/bin/stat -f %l "${source}")" == 1 ]] || exit 71
        mode="$(/usr/bin/stat -f %Lp "${source}")"; (( (8#${mode} & 8#022) == 0 )) || exit 72
        [[ "$(/usr/bin/shasum -a 256 "${source}" | /usr/bin/cut -d " " -f 1)" == "${expected}" ]] || exit 73
      done
      trusted="${base}/pilot-lifecycle/trusted-tools"
      if (( EUID == 0 )); then
        [[ -d /Library && ! -L /Library && "$(/usr/bin/stat -f %u /Library)" == 0 &&
           $(( 8#$(/usr/bin/stat -f %Lp /Library) & 8#022 )) == 0 &&
           -d "/Library/Application Support" && ! -L "/Library/Application Support" && "$(/usr/bin/stat -f %u "/Library/Application Support")" == 0 &&
           $(( 8#$(/usr/bin/stat -f %Lp "/Library/Application Support") & 8#022 )) == 0 ]] || exit 74
      else
        for test_directory in "${bootstrap_test_root}/Library" "${bootstrap_test_root}/Library/Application Support"; do
          [[ ! -e "${test_directory}" || ( -d "${test_directory}" && ! -L "${test_directory}" &&
             "${test_directory:A}" == "${test_directory}" && "$(/usr/bin/stat -f %u "${test_directory}")" == "${EUID}" &&
             $(( 8#$(/usr/bin/stat -f %Lp "${test_directory}") & 8#022 )) == 0 ) ]] || exit 74
          if [[ ! -d "${test_directory}" ]]; then /bin/mkdir "${test_directory}"; /bin/chmod 700 "${test_directory}"; fi
        done
      fi
      lifecycle="${base}/pilot-lifecycle"
      for directory in "${base}" "${lifecycle}" "${trusted}"; do
        [[ ! -e "${directory}" || ( -d "${directory}" && ! -L "${directory}" && "$(/usr/bin/stat -f %u "${directory}")" == "${target_uid}" && "$(/usr/bin/stat -f %Lp "${directory}")" == 700 ) ]] || exit 75
        if [[ ! -d "${directory}" ]]; then /bin/mkdir "${directory}"; (( EUID != 0 )) || /usr/sbin/chown root:wheel "${directory}"; /bin/chmod 700 "${directory}"; fi
      done
      for source expected target in "${helper_source}" "${helper_digest}" "${trusted}/pilot-lifecycle-root.sh" "${inspector_source}" "${inspector_digest}" "${trusted}/inspect-pilot-artifact.sh"; do
        temporary="${target}.new.$$"; /bin/cp -p "${source}" "${temporary}"; (( EUID != 0 )) || /usr/sbin/chown root:wheel "${temporary}"; /bin/chmod 700 "${temporary}"
        [[ "$(/usr/bin/shasum -a 256 "${temporary}" | /usr/bin/cut -d " " -f 1)" == "${expected}" ]] || exit 76
        /bin/mv -f "${temporary}" "${target}"
      done
      if (( EUID != 0 )); then print "bootstrap_staging_test=pass"; exit 0; fi
      exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "${trusted}/pilot-lifecycle-root.sh" "$@"
    '
    # BOOTSTRAP_PAYLOAD_END
    privileged_arguments=(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/zsh -f -c "${bootstrap_payload}" -- "${root_helper}" "${inspector_source}" \
      "${helper_digest}" "${inspector_digest}" "${invoking_uid}" "$@")
    case "${lifecycle_transport}" in
      sudo)
        if [[ "${test_mode}" == 1 ]]; then "$(tool sudo)" "${privileged_arguments[@]}"
        else /usr/bin/sudo "${privileged_arguments[@]}"; fi
        ;;
      native-gui)
        if [[ "${test_mode}" != 1 ]]; then
          local console_uid console_user
          console_uid="$(/usr/bin/stat -f %u /dev/console)"; console_user="$(/usr/bin/stat -f %Su /dev/console)"
          [[ "${console_uid}" == "${invoking_uid}" && "${console_user}" != root && "${console_user}" != loginwindow ]] &&
            /bin/launchctl print "gui/${console_uid}" >/dev/null ||
            fail "Native administrator authorization requires the active nonroot console GUI user."
        fi
        privileged_command=""
        for argument in "${privileged_arguments[@]}"; do privileged_command+="${(q)argument} "; done
        apple_command="${privileged_command//\\/\\\\}"; apple_command="${apple_command//\"/\\\"}"
        if [[ "${test_mode}" == 1 ]]; then
          "$(tool osascript)" -l AppleScript -e "do shell script \"${apple_command}\" with administrator privileges without altering line endings"
        else
          /usr/bin/osascript -l AppleScript -e "do shell script \"${apple_command}\" with administrator privileges without altering line endings"
        fi
        ;;
      *) fail "The lifecycle authorization transport is invalid." 64 ;;
    esac
  fi
}

wait_for_registration_path() {
  local expected="$1" snapshot
  for _ in {1..20}; do
    snapshot="$(registration_snapshot)" || return 1
    if registration_is_exact_path "${expected}" "${snapshot}"; then return 0; fi
    "$(tool sleep)" 0.25
  done
  return 1
}

wait_for_registration_absence() {
  local snapshot
  for _ in {1..20}; do
    snapshot="$(registration_snapshot)" || return 1
    if registration_is_absent "${snapshot}"; then return 0; fi
    "$(tool sleep)" 0.25
  done
  return 1
}

restore_development_source_registration() {
  local expected="${1:l}"
  local source_app destination_app source_extension observed snapshot
  [[ "${expected}" =~ '^[[:xdigit:]]{40}$' ]] ||
    fail "Source registration restoration requires one exact artifact identity." 64
  source_app="$(test_override DNIE_WORKFLOW_SOURCE_APP "${repository_root}/DerivedData/T067/Build/Products/Release/DNIeTokenHost.app")"
  destination_app="$(test_override DNIE_WORKFLOW_DESTINATION_APP /Applications/DNIeTokenHost.app)"
  source_extension="${source_app}/Contents/PlugIns/DNIeTokenExtension.appex"

  [[ ! -e "${destination_app}" && ! -L "${destination_app}" ]] ||
    fail "Source registration restoration requires the installed production path to remain absent."
  require_app_inactive "${source_app}"
  require_app_inactive "${destination_app}"
  snapshot="$(registration_snapshot)" ||
    fail "Unable to inspect registration before source restoration."
  require_no_registration "${snapshot}"
  restore_missing_development_app "${source_app}" "${expected}" ||
    fail "The exact cached development source could not be restored."
  observed="$(artifact_cdhash "${source_app}")" ||
    fail "The retained development source failed exact restoration inspection."
  [[ "${observed:l}" == "${expected}" ]] ||
    fail "The retained development source identity differs from the authorized identity."

  # Recheck every mutable boundary immediately before the documented development-only add.
  [[ "$(artifact_cdhash "${source_app}")" == "${expected}" ]] ||
    fail "The retained development source changed before source restoration."
  [[ ! -e "${destination_app}" && ! -L "${destination_app}" ]] ||
    fail "The installed production path appeared before source restoration."
  require_app_inactive "${source_app}"
  require_app_inactive "${destination_app}"
  snapshot="$(registration_snapshot)" ||
    fail "Unable to recheck registration immediately before source restoration."
  require_no_registration "${snapshot}"

  "$(tool pluginkit)" -a "${source_extension}" >/dev/null 2>&1 ||
    fail "The exact development source registration could not be added."
  wait_for_registration_path "${source_extension}" ||
    fail "The development add did not establish one exact source registration."

  [[ "$(artifact_cdhash "${source_app}")" == "${expected}" ]] ||
    fail "The retained development source changed after source restoration."
  [[ ! -e "${destination_app}" && ! -L "${destination_app}" ]] ||
    fail "The installed production path appeared during source restoration."
  require_app_inactive "${source_app}"
  require_app_inactive "${destination_app}"
  snapshot="$(registration_snapshot)" ||
    fail "Unable to inspect the final source registration state."
  require_registration_path "${source_extension}" "${snapshot}"
}

run_finish_source_restoration() {
  require_normal_user
  restore_development_source_registration "$1"
  prune_completed_development_app "$1"
  print 'development_source_registration_restoration=pass'
  print 'installed_registration=absent'
  print 'source_registration=exact-singleton'
}

lifecycle_paths() {
  source_app="$(test_override DNIE_WORKFLOW_SOURCE_APP "${repository_root}/DerivedData/T067/Build/Products/Release/DNIeTokenHost.app")"
  destination_app="$(test_override DNIE_WORKFLOW_DESTINATION_APP /Applications/DNIeTokenHost.app)"
  source_extension="${source_app}/Contents/PlugIns/DNIeTokenExtension.appex"
  installed_extension="${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex"
}

observe_lifecycle() {
  local source_app destination_app source_extension installed_extension
  lifecycle_paths
  local snapshot inspection version paths installed_row="" source_row=""
  local app_state=absent registration_state=unavailable
  if [[ -L "${destination_app}" || ( -e "${destination_app}" && ! -d "${destination_app}" ) ]]; then
    app_state=unexpected
  elif [[ -d "${destination_app}" ]]; then
    app_state=present
    if inspection="$(inspect_artifact "${destination_app}" 2>/dev/null)" &&
       version="$(artifact_field "${inspection}" extension_marketing_version)" &&
       [[ "${version}" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
      installed_row="${version}"$'\t'"${installed_extension}"
      print "installed_artifact=verified"
    else
      print "installed_artifact=unverified"
    fi
  fi
  if snapshot="$(registration_snapshot)"; then
    if paths="$(active_paths_for_identifier "${snapshot}" org.dniemacos.dnietoken.tokenextension)" &&
       [[ $'\n'"${paths}"$'\n' == *$'\n'"${source_extension}"$'\n'* ]] &&
       inspection="$(inspect_artifact "${source_app}" 2>/dev/null)" &&
       version="$(artifact_field "${inspection}" extension_marketing_version)" &&
       [[ "${version}" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
      source_row="${version}"$'\t'"${source_extension}"
    fi
    registration_state="$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" || registration_state=unexpected
  fi
  print "installed_app=${app_state}"
  print "provider_registration=${registration_state}"
  [[ "${app_state}" != unexpected && ( "${app_state}" != present || -n "${installed_row}" ) &&
     "${registration_state}" != unexpected && "${registration_state}" != unavailable &&
     "${registration_state}" != exact-both ]]
}

lifecycle_fail() {
  print -u2 -- "$1"
  observe_lifecycle >&2 || true
  exit 1
}

published_registration() {
  local snapshot="$1" source_row="$2" installed_row="$3" records
  records="$(active_registrations_for_identifier "${snapshot}" org.dniemacos.dnietoken.tokenextension)" || return 1
  case "${records}" in
    "") print absent ;;
    "${source_row}") print exact-source ;;
    "${installed_row}") print exact-installed ;;
    "${source_row}"$'\n'"${installed_row}"|"${installed_row}"$'\n'"${source_row}") print exact-both ;;
    *) return 1 ;;
  esac
}

wait_for_registration_set() {
  local source_row="$1" installed_row="$2" expected="$3" allow_absence="${4:-no}" snapshot registration
  for _ in {1..20}; do
    snapshot="$(registration_snapshot)" &&
      registration="$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" || return 1
    [[ "${registration}" == "${expected}" ||
       ( "${allow_absence}" == yes && "${registration}" == absent ) ]] && return 0
    "$(tool sleep)" 0.25
  done
  return 1
}

run_install() {
  require_normal_user
  local source_app destination_app source_extension installed_extension
  local snapshot inspection cdhash version token publication confirmation source_isolated=0
  local source_row installed_row registration
  lifecycle_paths
  [[ ! -e "${destination_app}" && ! -L "${destination_app}" ]] ||
    lifecycle_fail "Install requires an absent application destination."
  inspection="$(inspect_artifact "${source_app}")" ||
    lifecycle_fail "The development product failed the exact pilot artifact preflight."
  cdhash="$(artifact_field "${inspection}" artifact_cdhash)"
  version="$(artifact_field "${inspection}" extension_marketing_version)"
  [[ "${cdhash}" =~ '^[[:xdigit:]]{40}$' && "${version}" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] ||
    lifecycle_fail "The artifact preflight returned an invalid signed identity or extension version."
  (require_app_inactive "${source_app}"; require_app_inactive "${destination_app}") ||
    lifecycle_fail "The source and installed paths must be inactive before publication."
  snapshot="$(registration_snapshot)" || lifecycle_fail "Unable to inspect the pre-install registration state."
  if ! registration_is_absent "${snapshot}" &&
     ! registration_is_exact_path_version "${source_extension}" "${version}" "${snapshot}"; then
    lifecycle_fail "Install found a stale, duplicated, or competing provider registration."
  fi

  token="direct-install.$(/bin/date +%Y%m%d%H%M%S).$$.${RANDOM}"
  publication="$(run_root_lifecycle publish-pilot "${token}" "${source_app}" "${cdhash}")" &&
    [[ "${publication}" == pilot_publication=pending-install ]] ||
    lifecycle_fail "The authorized app publication did not complete."
  [[ "$(inspect_artifact "${destination_app}")" == "${inspection}" ]] ||
    lifecycle_fail "The published app does not match the inspected build."
  source_row="${version}"$'\t'"${source_extension}"
  installed_row="${version}"$'\t'"${installed_extension}"
  snapshot="$(registration_snapshot)" || lifecycle_fail "Unable to inspect registration after app publication."
  registration="$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" ||
    lifecycle_fail "Registration is unexpected after app publication."
  if [[ "${registration}" == exact-source || "${registration}" == exact-both ]]; then
    [[ "$(inspect_artifact "${source_app}")" == "${inspection}" ]] ||
      lifecycle_fail "The build-tree artifact changed before withdrawing its registration."
    (require_app_inactive "${source_app}") ||
      lifecycle_fail "The build-tree registration could not be withdrawn safely."
    snapshot="$(registration_snapshot)" &&
      registration="$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" &&
      [[ "${registration}" == exact-source || "${registration}" == exact-both ]] ||
      lifecycle_fail "The exact build-tree row did not remain visible before withdrawal."
    "$(tool pluginkit)" -r "${source_extension}" >/dev/null ||
      lifecycle_fail "The exact build-tree registration could not be withdrawn."
    wait_for_registration_set "${source_row}" "${installed_row}" exact-installed yes ||
      lifecycle_fail "The exact build-tree registration withdrawal could not be verified."
    source_isolated=1
  fi

  run_root_lifecycle register-securityagent "${token}" "${cdhash}" >/dev/null ||
    lifecycle_fail "The _securityagent registration did not complete."
  wait_for_registration_set "" "${installed_row}" exact-installed ||
    lifecycle_fail "Registration did not establish one exact installed provider row."
  [[ "$(inspect_artifact "${destination_app}")" == "${inspection}" ]] ||
    lifecycle_fail "The installed app changed after registration."
  confirmation="$(run_root_lifecycle confirm-pilot "${token}" "${cdhash}")" &&
    [[ "${confirmation}" == pilot_installation=committed ]] ||
    lifecycle_fail "The installed app ownership could not be confirmed."
  snapshot="$(registration_snapshot)" &&
    registration_is_exact_path_version "${installed_extension}" "${version}" "${snapshot}" ||
    lifecycle_fail "The exact installed provider row did not remain visible after confirmation."
  print "pilot_install=pass"
  print "source_registration_isolated=${source_isolated}"
}

run_recover_pending_install() {
  require_normal_user
  local token="$1" expected="${2:l}"
  local source_app destination_app source_extension installed_extension snapshot observed rollback_output expected_archive
  local initial_registration current_registration probe_output expected_probe installed_user_inspectable=1
  [[ "${token}" =~ '^install\.[0-9]{14}\.[0-9]+\.[0-9]+$' && "${expected}" =~ '^[[:xdigit:]]{40}$' ]] ||
    fail "Pending-install recovery requires one exact install token and artifact identity." 64
  source_app="$(test_override DNIE_WORKFLOW_SOURCE_APP "${repository_root}/DerivedData/T067/Build/Products/Release/DNIeTokenHost.app")"
  destination_app="$(test_override DNIE_WORKFLOW_DESTINATION_APP /Applications/DNIeTokenHost.app)"
  source_extension="${source_app}/Contents/PlugIns/DNIeTokenExtension.appex"
  installed_extension="${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex"
  restore_missing_development_app "${source_app}" "${expected}" ||
    fail "The exact cached development source could not be restored."
  observed="$(artifact_cdhash "${source_app}")" || fail "The retained source artifact failed exact recovery inspection."
  [[ "${observed:l}" == "${expected}" ]] || fail "The retained source artifact identity differs from the authorized recovery identity."
  if observed="$(artifact_cdhash "${destination_app}")"; then
    [[ "${observed:l}" == "${expected}" ]] || fail "The pending installed artifact identity differs from the authorized recovery identity."
  else
    installed_user_inspectable=0
  fi
  require_app_inactive "${source_app}"
  require_app_inactive "${destination_app}"
  snapshot="$(registration_snapshot)" || fail "Unable to inspect the pending recovery registration state."
  initial_registration="$(registration_classification "${installed_extension}" "${snapshot}")" ||
    fail "Pending recovery requires either zero provider rows or one exact installed row."

  probe_output="$(run_root_lifecycle probe-pending-install "${token}" "${expected}")" ||
    fail "The root-owned state is not an exact uncommitted pending install; nothing was unregistered."
  expected_probe=$'pending_install_recoverable=true\n'"pending_install_token=${token}"$'\n'"pending_install_cdhash=${expected}"
  [[ "${probe_output}" == "${expected_probe}" ]] ||
    fail "The privileged pending probe did not return the exact authorized token and artifact identity."

  # Recheck every normal-user boundary after authorization and immediately before withdrawal.
  [[ "$(artifact_cdhash "${source_app}")" == "${expected}" ]] ||
    fail "The source artifact changed after the pending-install probe; nothing was unregistered."
  if (( installed_user_inspectable )); then
    [[ "$(artifact_cdhash "${destination_app}")" == "${expected}" ]] ||
      fail "The installed artifact changed after the pending-install probe; nothing was unregistered."
  fi
  require_app_inactive "${source_app}"
  require_app_inactive "${destination_app}"
  snapshot="$(registration_snapshot)" || fail "Unable to recheck registration after the pending-install probe."
  current_registration="$(registration_classification "${installed_extension}" "${snapshot}")" ||
    fail "The provider registration topology became ambiguous after the pending-install probe."
  [[ "${current_registration}" == "${initial_registration}" ]] ||
    fail "The provider registration classification changed after the pending-install probe."

  if [[ "${initial_registration}" == exact-installed ]]; then
    "$(tool pluginkit)" -r "${installed_extension}" >/dev/null 2>&1 ||
      fail "The exact installed registration could not be withdrawn; root state and app remain pending."
    wait_for_registration_absence ||
      fail "Installed registration withdrawal could not be proven; root state and app remain pending."
  fi
  require_app_inactive "${source_app}"
  require_app_inactive "${destination_app}"
  snapshot="$(registration_snapshot)" || fail "Unable to recheck registration immediately before pending rollback."
  require_no_registration "${snapshot}"

  rollback_output="$(run_root_lifecycle rollback-pending-install "${token}" "${expected}")" ||
    fail "Pending-install rollback was not authorized or failed; the exact app remains attributable and registration is absent."
  if [[ "${test_mode}" == 1 ]]; then
    expected_archive="${DNIE_LIFECYCLE_TEST_ROOT}/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle/transactions/${token}/DNIeTokenHost.app.failed-install"
  else
    expected_archive="/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle/transactions/${token}/DNIeTokenHost.app.failed-install"
  fi
  [[ "${rollback_output}" == "retained_recovery=${expected_archive}" && ! -e "${destination_app}" && ! -L "${destination_app}" ]] ||
    fail "The guarded rollback did not report the exact retained archive and absent destination."

  [[ "$(artifact_cdhash "${source_app}")" == "${expected}" ]] ||
    fail "The app was retained in the exact recovery archive, but the source artifact changed before restoration."
  require_app_inactive "${source_app}"
  snapshot="$(registration_snapshot)" || fail "Unable to confirm registration absence before source restoration."
  require_no_registration "${snapshot}"
  restore_development_source_registration "${expected}"
  snapshot="$(registration_snapshot)" || fail "Unable to inspect the final recovery registration state."
  require_registration_path "${source_extension}" "${snapshot}"
  [[ ! -e "${destination_app}" && ! -L "${destination_app}" &&
     "$(artifact_cdhash "${source_app}")" == "${expected}" ]] ||
    fail "The final pending-install recovery topology changed unexpectedly."
  prune_completed_development_app "${expected}"
  print 'pending_install_recovery=pass'
  print "retained_recovery=${expected_archive}"
  print 'installed_registration=absent'
  print "initial_registration=${initial_registration}"
  print 'source_registration=exact-singleton'
}

run_uninstall() {
  require_normal_user
  local source_app destination_app source_extension installed_extension
  local snapshot installed_inspection source_inspection cdhash=absent version token proof result
  local source_row="" installed_row="" expected_after=absent registration paths installed_identity
  local -a removal_arguments
  lifecycle_paths
  snapshot="$(registration_snapshot)" || lifecycle_fail "Unable to inspect the pre-uninstall registration state."
  if [[ -e "${destination_app}" || -L "${destination_app}" ]]; then
    [[ -d "${destination_app}" && ! -L "${destination_app}" ]] ||
      lifecycle_fail "The install destination is not an exact application directory."
    installed_identity="$(/usr/bin/stat -f '%d:%i' "${destination_app}")" &&
      installed_inspection="$(inspect_artifact "${destination_app}")" ||
      lifecycle_fail "The installed app failed exact product verification."
    cdhash="$(artifact_field "${installed_inspection}" artifact_cdhash)"
    version="$(artifact_field "${installed_inspection}" extension_marketing_version)"
    [[ "${cdhash}" =~ '^[[:xdigit:]]{40}$' && "${version}" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] ||
      lifecycle_fail "The installed app returned an invalid signed identity or extension version."
    installed_row="${version}"$'\t'"${installed_extension}"
    (require_app_inactive "${destination_app}") ||
      lifecycle_fail "The installed path must be inactive before removal."
  fi

  # A failed install can leave the original development row beside or without
  # the installed row. Verify this source independently and leave it in place.
  paths="$(active_paths_for_identifier "${snapshot}" org.dniemacos.dnietoken.tokenextension)" ||
    lifecycle_fail "Uninstall found a stale or competing provider registration."
  if [[ $'\n'"${paths}"$'\n' == *$'\n'"${source_extension}"$'\n'* ]]; then
    source_inspection="$(inspect_artifact "${source_app}")" ||
      lifecycle_fail "The visible build-tree row could not be matched to the signed source."
    version="$(artifact_field "${source_inspection}" extension_marketing_version)"
    [[ "${version}" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] ||
      lifecycle_fail "The signed source returned an invalid extension version."
    source_row="${version}"$'\t'"${source_extension}"
    expected_after=exact-source
  fi

  registration="$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" ||
    lifecycle_fail "Uninstall found a stale or competing provider registration."
  token="direct-remove.$(/bin/date +%Y%m%d%H%M%S).$$.${RANDOM}"
  if [[ "${registration}" == exact-installed || "${registration}" == exact-both ]]; then
    proof="$(run_root_lifecycle probe-pilot-removal "${token}" "${cdhash}" "${installed_identity}")" &&
      [[ "${proof}" == pilot_removal_probe=pass ]] ||
      lifecycle_fail "Exact app ownership could not be proven before withdrawing the registration."
    [[ "$(inspect_artifact "${destination_app}")" == "${installed_inspection}" &&
       "$(/usr/bin/stat -f '%d:%i' "${destination_app}")" == "${installed_identity}" ]] ||
      lifecycle_fail "The installed app changed after the removal ownership check."
    (require_app_inactive "${destination_app}") ||
      lifecycle_fail "The installed path must remain inactive before withdrawing registration."
    if [[ -n "${source_row}" ]]; then
      [[ "$(inspect_artifact "${source_app}")" == "${source_inspection}" ]] ||
        lifecycle_fail "The build-tree artifact changed before withdrawing the installed registration."
    fi
    snapshot="$(registration_snapshot)" &&
      [[ "$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" == "${registration}" ]] ||
      lifecycle_fail "The registration changed after the removal ownership check."
    "$(tool pluginkit)" -r "${installed_extension}" >/dev/null ||
      lifecycle_fail "The exact installed provider registration could not be withdrawn."
    wait_for_registration_set "${source_row}" "${installed_row}" "${expected_after}" ||
      lifecycle_fail "The installed provider registration withdrawal could not be verified."
  fi

  if [[ -n "${source_row}" ]]; then
    [[ "$(inspect_artifact "${source_app}")" == "${source_inspection}" ]] ||
      lifecycle_fail "The build-tree artifact changed before app removal."
  fi
  if [[ "${cdhash}" != absent ]]; then
    [[ "$(/usr/bin/stat -f '%d:%i' "${destination_app}")" == "${installed_identity}" ]] ||
      lifecycle_fail "The installed app changed immediately before removal."
    (require_app_inactive "${destination_app}") ||
      lifecycle_fail "The installed path must remain inactive before app removal."
  fi
  snapshot="$(registration_snapshot)" &&
    [[ "$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" == "${expected_after}" ]] ||
    lifecycle_fail "The expected registration state could not be verified before app removal."
  removal_arguments=(remove-pilot "${token}" "${cdhash}")
  if [[ "${cdhash}" != absent ]]; then
    removal_arguments+=("${installed_identity}")
  fi
  result="$(run_root_lifecycle "${removal_arguments[@]}")" &&
    [[ "${result}" == pilot_installation=absent ]] ||
    lifecycle_fail "Exact app and ownership removal did not complete."
  [[ ! -e "${destination_app}" && ! -L "${destination_app}" ]] ||
    lifecycle_fail "The final app absence could not be verified."
  if [[ -n "${source_row}" ]]; then
    [[ "$(inspect_artifact "${source_app}")" == "${source_inspection}" ]] ||
      lifecycle_fail "The build-tree artifact changed during removal."
  fi
  snapshot="$(registration_snapshot)" &&
    [[ "$(published_registration "${snapshot}" "${source_row}" "${installed_row}")" == "${expected_after}" ]] ||
    lifecycle_fail "The final registration state could not be verified."
  print "provider_registration=${expected_after}"
  if [[ "${cdhash}" == absent ]]; then
    print "pilot_uninstall=already-absent"
  else
    print "pilot_uninstall=pass"
  fi
}

run_status() {
  require_normal_user
  local observation observed=0
  observation="$(observe_lifecycle)" || observed=$?
  print -r -- "${observation}"
  if [[ "${observation}" == *provider_registration=exact-installed ]]; then
    local source_app destination_app source_extension installed_extension
    lifecycle_paths
    print "installed_provider_visibility=pass"
    print "installed_extension=${installed_extension}"
  elif [[ "${observation}" == *provider_registration=absent ]]; then
    print "installed_provider_visibility=absent"
  fi
  print "status_private_operation=false"
  return "${observed}"
}

print_help() {
  print 'DNIe local-beta developer workflow (Xcode remains the build system)'
  print ''
  print '  help      Show this non-mutating help (the default target)'
  print '  check     Run non-mutating syntax/offline safety checks; report evidence mismatch as UNKNOWN'
  print '  build     Build and inspect the private Apple Development beta'
  print '  install   Verify and publish a fresh exact-owned local pilot app'
  print '  status    Inspect installed-path and registration state without card/private operations'
  print '  test      Run offline dispatch and safety fixtures'
  print '  clean     Remove the selected development build slot when its safety checks pass'
  print ''
  print 'Set DNIE_SIGNING_IDENTITY_SHA1 to one valid Apple Development SHA-1 when auto-selection is ambiguous.'
  print '  uninstall Remove the exact-owned pilot app and its matching registration'
  print '  finish-source-restoration CDHASH  Restore only the exact development row after an independently audited consumed recovery'
  print 'upgrade, disable, and enable remain intentionally unsupported.'
}

command_name="${1:-help}"
if [[ "${command_name}" == recover-pending-install ]]; then
  [[ "$#" == 3 ]] || fail "usage: ${0:t} recover-pending-install INSTALL_TOKEN CDHASH" 64
elif [[ "${command_name}" == finish-source-restoration ]]; then
  [[ "$#" == 2 ]] || fail "usage: ${0:t} finish-source-restoration CDHASH" 64
elif [[ "${command_name}" == test-registration-version && "${test_mode}" == 1 ]]; then
  [[ "$#" == 3 ]] || fail "unknown developer workflow command: ${command_name}" 64
else
  [[ "$#" -le 1 ]] || fail "usage: ${0:t} [help|check|build|install|status|upgrade|uninstall|disable|enable|clean]" 64
fi
case "${command_name}" in
  install|uninstall|recover-pending-install|finish-source-restoration) hold_development_lock ;;
esac
case "${command_name}" in
  help) print_help ;;
  check) run_check ;;
  build) run_build ;;
  install) run_with_lifecycle_transport run_install ;;
  status) run_status ;;
  uninstall) run_with_lifecycle_transport run_uninstall ;;
  recover-pending-install) run_with_lifecycle_transport run_recover_pending_install "$2" "$3" ;;
  finish-source-restoration) run_finish_source_restoration "$2" ;;
  test-authorization)
    [[ "${test_mode}" == 1 ]] || fail "unknown developer workflow command: ${command_name}" 64
    run_with_lifecycle_transport run_root_lifecycle authorize "${DNIE_WORKFLOW_TEST_AUTHORIZATION_TOKEN:-authorization.test}"
    ;;
  test-registration-version)
    [[ "${test_mode}" == 1 && "$#" == 3 ]] || fail "unknown developer workflow command: ${command_name}" 64
    test_snapshot="$(registration_snapshot)" || fail "Unable to inspect the test registration state."
    registration_is_exact_path_version "$2" "$3" "${test_snapshot}" ||
      fail "The registration is not one exact path/version row."
    print 'registration_path_version=pass'
    ;;
  clean) run_clean ;;
  upgrade|disable|enable)
    fail "${command_name} is not accepted: the generic lifecycle procedure has not passed T030/U-12. Use no evidence-specific cleanup helper as a product command." 2
    ;;
  *) fail "unknown developer workflow command: ${command_name}" 64 ;;
esac
