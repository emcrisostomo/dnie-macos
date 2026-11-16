#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
workflow="${script_dir}/developer-workflow.sh"
root_helper="${script_dir}/pilot-lifecycle-root.sh"
inspector="${script_dir}/inspect-pilot-artifact.sh"
build_script="${script_dir}/build-development.sh"
repository_root="${script_dir:h:h:h}"
project="${repository_root}/DNIeToken.xcodeproj/project.pbxproj"
host_entitlements="${repository_root}/HostApp/HostApp.entitlements"
extension_entitlements="${repository_root}/TokenExtension/TokenExtension.entitlements"
host_entry="${repository_root}/HostApp/AppDelegate.swift"

require() { local pattern="$1" file="$2"; grep -Fq -- "${pattern}" "${file}" || { print -u2 "missing_static_boundary=${pattern}"; exit 1; }; }
reject() { local pattern="$1" file="$2"; ! grep -Fq -- "${pattern}" "${file}" || { print -u2 "rejected_static_boundary=${pattern}"; exit 1; }; }

reject 'Production lifecycle mutation remains stopped until the independent safety review is accepted.' "${root_helper}"
reject 'production root mutation remains stopped until independent safety review is accepted.' "${workflow}"
require 'Production lifecycle execution requires the exact root-owned digest-staged helper path.' "${root_helper}"
require 'trusted_tools="/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle/trusted-tools"' "${root_helper}"
require 'transport=sudo' "${workflow}"
require 'transport=native-gui' "${workflow}"
require 'with administrator privileges' "${workflow}"
require 'privileged_arguments=(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/zsh -f -c' "${workflow}"
require 'else /usr/bin/sudo "${privileged_arguments[@]}"' "${workflow}"
require '/usr/bin/osascript -l AppleScript -e "do shell script' "${workflow}"
require 'with administrator privileges without altering line endings' "${workflow}"
reject '/usr/bin/sudo -u _securityagent' "${workflow}"
require 'run_root_lifecycle register-securityagent' "${workflow}"
require '"$(tool pluginkit)" -a "${source_extension}"' "${workflow}"
require 'restore_development_source_registration "${expected}"' "${workflow}"
require 'require_app_inactive()' "${workflow}"
reject 'require_provider_inactive()' "${workflow}"
reject 'require_app_inactive_for_source_restoration()' "${workflow}"
require 'finish-source-restoration) run_finish_source_restoration "$2"' "${workflow}"
require 'caller_uid="$5"; shift 5' "${workflow}"
require '[[ -z "${SUDO_UID:-}" || "${SUDO_UID}" == "${caller_uid}" ]]' "${workflow}"
require 'helper_digest="$(/usr/bin/shasum -a 256' "${workflow}"
require '/usr/bin/cut -d " " -f 1' "${workflow}"
reject '/usr/bin/awk "{print \\$1}"' "${workflow}"
require '"$(/usr/bin/stat -f %u "${source}")" == "${source_uid}"' "${workflow}"
require 'for directory in "${base}" "${lifecycle}" "${trusted}"' "${workflow}"
require 'exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin' "${workflow}"

require "com.apple.ctk.class-id'" "${inspector}"
require "com.apple.ctk.driver-class'" "${inspector}"
require 'DNIeCore_DNIeCore.bundle/Contents/Resources/Assets/generation2.json' "${inspector}"
require 'extension_signature=' "${inspector}"
require '"${host_team}" == "${extension_team}"' "${inspector}"
require '/usr/bin/openssl rsa -inform DER -check -noout' "${inspector}"
require "Print :com.apple.security.app-sandbox' \"\${host_entitlement_file}\"" "${inspector}"
require "Print :com.apple.security.app-sandbox' \"\${extension_entitlement_file}\"" "${inspector}"
reject 'dnie-pilot-manifest.' "${inspector}"

require '@main' "${host_entry}"
require '@MainActor' "${host_entry}"
require 'private static var retainedDelegate: AppDelegate?' "${host_entry}"
require 'let delegate = AppDelegate()' "${host_entry}"
require 'retainedDelegate = delegate' "${host_entry}"
require 'application.delegate = delegate' "${host_entry}"
require 'application.run()' "${host_entry}"
require 'func applicationDidFinishLaunching' "${host_entry}"
require 'NSApp.terminate(nil)' "${host_entry}"
main_line="$(grep -n '^@main$' "${host_entry}" | cut -d: -f1)"
entry_line="$(grep -n '^enum DNIeTokenHostMain {$' "${host_entry}" | cut -d: -f1)"
retain_line="$(grep -n 'retainedDelegate = delegate' "${host_entry}" | cut -d: -f1)"
assign_line="$(grep -n 'application.delegate = delegate' "${host_entry}" | cut -d: -f1)"
run_line="$(grep -n 'application.run()' "${host_entry}" | cut -d: -f1)"
[[ "${main_line}" == <-> && "${entry_line}" == <-> && "${entry_line}" -eq $(( main_line + 2 )) &&
   "${retain_line}" == <-> && "${assign_line}" == <-> && "${run_line}" == <-> &&
   "${retain_line}" -lt "${assign_line}" && "${assign_line}" -lt "${run_line}" ]]

[[ "$(grep -c 'ENABLE_APP_SANDBOX = NO;' "${project}")" == 2 &&
   "$(grep -c 'ENABLE_APP_SANDBOX = YES;' "${project}")" == 2 ]]
! /usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "${host_entitlements}" >/dev/null 2>&1
! /usr/libexec/PlistBuddy -c 'Print :com.apple.security.smartcard' "${host_entitlements}" >/dev/null 2>&1
! /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups' "${host_entitlements}" >/dev/null 2>&1
[[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.smartcard' "${extension_entitlements}")" == true ]]
require 'host_entitlements_file=' "${build_script}"
require 'extension_entitlements_file=' "${build_script}"
require 'The signed delivery host has a sandbox, Smart Card, or keychain capability.' "${build_script}"
require 'The host and extension are not paired to the same Apple Development team.' "${build_script}"
require '[[ ! -s "${host_entitlements_file}" ]] || /usr/bin/plutil -lint "${host_entitlements_file}"' "${build_script}"
require '[[ ! -s "${host_entitlement_file}" ]] || /usr/bin/plutil -lint "${host_entitlement_file}"' "${inspector}"

# A failed key lookup establishes absence only after validating a nonempty export.
host_parser_fixture="$(mktemp /private/tmp/dnie-host-entitlement-parser.XXXXXX)"
host_export_accepts() {
  [[ ! -s "$1" ]] || /usr/bin/plutil -lint "$1" >/dev/null 2>&1 || return 1
  local key
  for key in com.apple.security.app-sandbox com.apple.security.smartcard keychain-access-groups; do
    if /usr/libexec/PlistBuddy -c "Print :${key}" "$1" >/dev/null 2>&1; then return 1; fi
  done
}
host_export_accepts "${host_parser_fixture}"
print -r -- '<?xml version="1.0"?><plist version="1.0"><dict/></plist>' > "${host_parser_fixture}"
host_export_accepts "${host_parser_fixture}"
print -r -- 'not a property list' > "${host_parser_fixture}"
if host_export_accepts "${host_parser_fixture}"; then print -u2 'malformed_host_export_accepted=true'; exit 1; fi
for forbidden_key in com.apple.security.app-sandbox com.apple.security.smartcard keychain-access-groups; do
  print -r -- "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>${forbidden_key}</key><true/></dict></plist>" > "${host_parser_fixture}"
  if host_export_accepts "${host_parser_fixture}"; then print -u2 'forbidden_host_capability_accepted=true'; exit 1; fi
done
/bin/rm -f -- "${host_parser_fixture}"

register_line="$(grep -n 'run_root_lifecycle register-securityagent' "${workflow}" | head -n 1 | cut -d: -f1)"
observation_line="$(grep -n 'wait_for_registration_path "${destination_app}/Contents/PlugIns/DNIeTokenExtension.appex"' "${workflow}" | head -n 1 | cut -d: -f1)"
[[ "${register_line}" == <-> && "${observation_line}" == <-> && "${register_line}" -lt "${observation_line}" ]]
if /usr/bin/awk '/^run_install\(\)/{capture=1} capture{print} /^run_recover_pending_install\(\)/{exit}' "${workflow}" |
   grep -Fq '"$(tool open)" -g "${destination_app}"'; then
  print -u2 'ordinary_user_open_remains_in_install_path=true'; exit 1
fi
install_body="$(/usr/bin/awk '/^run_install\(\)/{capture=1} capture{print} /^run_recover_pending_install\(\)/{exit}' "${workflow}")"
[[ "$(print -r -- "${install_body}" | grep -c 'run_root_lifecycle register-securityagent')" == 1 ]]
! print -r -- "${install_body}" | grep -Fq '"$(tool pluginkit)" -a "${destination_app}'

require 'normalize_published_app "${destination}"' "${root_helper}"
require '/usr/bin/sudo -n -u _securityagent "${host_executable}"' "${root_helper}"
require 'require_owned_state pending-install "${expected:l}" "${token}"' "${root_helper}"
require '/bin/chmod 755 "${entry}"' "${root_helper}"
require '/bin/chmod 444 "${asset}"' "${root_helper}"
require 'multiply linked regular file' "${root_helper}"
require 'special filesystem entry' "${root_helper}"
require 'Permission normalization changed or invalidated the strict signed artifact boundary.' "${root_helper}"
reject '/bin/chmod -R' "${root_helper}"
require 'pending_install_token=${token}' "${root_helper}"
require 'pending_install_cdhash=${expected:l}' "${root_helper}"
require 'registration_classification' "${workflow}"
require '[[ "${probe_output}" == "${expected_probe}" ]]' "${workflow}"
require 'provider registration classification changed after the pending-install probe' "${workflow}"
require 'adopt_stale_lock_for_commit_recovery rollback-install' "${root_helper}"
require 'adopt_stale_lock_for_commit_recovery rollback-uninstall' "${root_helper}"
require 'The exact lifecycle lock owner is still running; adoption is forbidden.' "${root_helper}"
require 'The failed-install archive target already exists.' "${root_helper}"
require 'claim_and_restore_app "${transaction}/DNIeTokenHost.app"' "${root_helper}"
require 'A lifecycle fixture descendant is symlinked, noncanonical, or not owned' "${root_helper}"
reject '/bin/mv -n' "${root_helper}"

# Exercise the exact digest expression with positional parameters that previously corrupted awk quoting.
digest_source="$(mktemp /private/tmp/dnie-bootstrap-digest.XXXXXX)"
trap '/bin/rm -f -- "${digest_source}"' EXIT INT TERM
print reviewed > "${digest_source}"
digest_expected="$(/usr/bin/shasum -a 256 "${digest_source}" | /usr/bin/cut -d ' ' -f 1)"
/bin/zsh -c 'source="$1"; expected="$2"; [[ "$(/usr/bin/shasum -a 256 "${source}" | /usr/bin/cut -d " " -f 1)" == "${expected}" ]]' -- "${digest_source}" "${digest_expected}"

bootstrap_root="$(mktemp -d /private/tmp/dnie-pilot-bootstrap-test.XXXXXX)"
trap '/bin/rm -f -- "${digest_source}"; /bin/rm -rf -- "${bootstrap_root}"' EXIT INT TERM
bootstrap_payload="$(/usr/bin/awk '
  /bootstrap_payload='\''$/ { capture=1; next }
  capture && /^    '\''$/ { exit }
  capture { sub(/^      /, ""); print }
' "${workflow}")"
helper_digest="$(/usr/bin/shasum -a 256 "${root_helper}" | /usr/bin/cut -d ' ' -f 1)"
inspector_digest="$(/usr/bin/shasum -a 256 "${inspector}" | /usr/bin/cut -d ' ' -f 1)"
env DNIE_BOOTSTRAP_TEST_ROOT="${bootstrap_root}" DNIE_BOOTSTRAP_TEST_ONLY=1 \
  /bin/zsh -c "${bootstrap_payload}" -- "${root_helper}" "${inspector}" "${helper_digest}" "${inspector_digest}" "${EUID}" | \
  grep -q '^bootstrap_staging_test=pass$'
trusted="${bootstrap_root}/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle/trusted-tools"
[[ "$(/usr/bin/shasum -a 256 "${trusted}/pilot-lifecycle-root.sh" | /usr/bin/cut -d ' ' -f 1)" == "${helper_digest}" &&
   "$(/usr/bin/shasum -a 256 "${trusted}/inspect-pilot-artifact.sh" | /usr/bin/cut -d ' ' -f 1)" == "${inspector_digest}" &&
   "$(/usr/bin/stat -f %Lp "${trusted}")" == 700 ]]

escape_root="$(mktemp -d /private/tmp/dnie-pilot-bootstrap-test.XXXXXX)"
escape_target="$(mktemp -d /private/tmp/dnie-pilot-bootstrap-escape.XXXXXX)"
ln -s "${escape_target}" "${escape_root}/Library"
if env DNIE_BOOTSTRAP_TEST_ROOT="${escape_root}" DNIE_BOOTSTRAP_TEST_ONLY=1 \
  /bin/zsh -c "${bootstrap_payload}" -- "${root_helper}" "${inspector}" "${helper_digest}" "${inspector_digest}" "${EUID}" >/dev/null 2>&1; then
  print -u2 'bootstrap_symlink_escape_accepted=true'; exit 1
fi
/bin/rm -rf -- "${escape_root}" "${escape_target}"

print 'pilot_lifecycle_privileged_static=pass'
