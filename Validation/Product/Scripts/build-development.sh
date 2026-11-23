#!/bin/zsh
set -euo pipefail

if (( EUID == 0 )); then
  print -u2 "Do not run the development build through sudo/root; signing, private-fixture staging, and DerivedData belong to the invoking user."
  exit 1
fi

script_dir="${0:A:h}"
repository_root="${script_dir:h:h:h}"
build_slot="T067"
if (( ${+DNIE_DEVELOPMENT_BUILD_SLOT} )); then
  build_slot="${DNIE_DEVELOPMENT_BUILD_SLOT}"
  [[ -n "${build_slot}" ]] || {
    print -u2 "DNIE_DEVELOPMENT_BUILD_SLOT must not be empty when explicitly set."
    exit 64
  }
fi
case "${build_slot}" in
  T067|T083CleanIncremental)
    marketing_version="0.1.1"
    build_number="2"
    ;;
  T083Upgrade)
    marketing_version="0.1.2"
    build_number="3"
    ;;
  *)
    print -u2 "DNIE_DEVELOPMENT_BUILD_SLOT must be T067 or T083CleanIncremental, or T083Upgrade."
    exit 64
    ;;
esac

derived_data_root="${repository_root}/DerivedData"
derived_data="${derived_data_root}/${build_slot}"

require_invoking_user_directory_or_absence() {
  local candidate_path="$1"
  local label="$2"
  if [[ -L "${candidate_path}" || ( -e "${candidate_path}" && ! -d "${candidate_path}" ) ]]; then
    print -u2 "The ${label} path is a symlink or nondirectory collision; refusing the build."
    exit 1
  fi
  if [[ -d "${candidate_path}" && "$(/usr/bin/stat -f %u "${candidate_path}")" != "${EUID}" ]]; then
    print -u2 "The ${label} directory is not owned by the invoking user; refusing the build."
    exit 1
  fi
}

require_invoking_user_directory_or_absence "${repository_root}" "repository root"
require_invoking_user_directory_or_absence "${derived_data_root}" "DerivedData root"
require_invoking_user_directory_or_absence "${derived_data}" "development build slot"

validate_existing_build_slot_tree() {
  [[ -d "${derived_data}" ]] || return 0
  local repository_device
  repository_device="$(/usr/bin/stat -f %d "${repository_root}")"
  if ! /usr/bin/find "${derived_data}" -xdev -exec /usr/bin/stat -f $'%d\t%u\t%l\t%HT' {} + |
      /usr/bin/awk -F '\t' -v expected_device="${repository_device}" -v expected_uid="${EUID}" '
        $1 != expected_device || $2 != expected_uid { unsafe = 1 }
        $4 == "Regular File" && $3 != 1 { unsafe = 1 }
        $4 != "Directory" && $4 != "Regular File" { unsafe = 1 }
        END { exit unsafe }
      '; then
    print -u2 "The existing development build slot contains an unsafe link, owner, filesystem boundary, file type, or multiply linked file; refusing the build."
    exit 1
  fi

  if [[ "${build_slot}" != T067 && -d "${derived_data_root}/T067" &&
        "$(/usr/bin/stat -f '%d:%i' "${derived_data}")" == "$(/usr/bin/stat -f '%d:%i' "${derived_data_root}/T067")" ]]; then
    print -u2 "The validation build slot aliases the accepted T067 slot; refusing the build."
    exit 1
  fi
}

validate_existing_build_slot_tree

if [[ "${1:-}" == --check-build-slot ]]; then
  [[ "$#" -eq 1 ]] || exit 64
  print "development_build_slot=${build_slot}"
  if [[ -d "${derived_data}" ]]; then
    print "development_build_slot_state=reusable"
  else
    print "development_build_slot_state=absent"
  fi
  print "marketing_version=${marketing_version}"
  print "build_number=${build_number}"
  print "xcodebuild_marketing_version_argument=MARKETING_VERSION=${marketing_version}"
  print "xcodebuild_build_number_argument=CURRENT_PROJECT_VERSION=${build_number}"
  print "credential_staging_performed=false"
  print "signing_keychain_inspected=false"
  print "xcodebuild_invoked=false"
  exit 0
fi

configuration="Release"
products="${derived_data}/Build/Products/${configuration}"
host_app="${products}/DNIeTokenHost.app"
extension="${host_app}/Contents/PlugIns/DNIeTokenExtension.appex"
credential_asset="${repository_root}/Packages/DNIeCore/Sources/DNIeCore/Evidence/Credentials/Assets/generation2.json"

requested_signing_identity="${DNIE_SIGNING_IDENTITY_SHA1:-}"
signing_identities=("${(@f)$(security find-identity -v -p codesigning | awk '
  /Apple Development/ {
    for (i = 1; i <= NF; i++) {
      value = $i
      gsub(/[^[:xdigit:]]/, "", value)
      if (length(value) == 40) { print toupper(value); break }
    }
  }
')}")
signing_identities=("${(@)signing_identities:#}")
if [[ -n "${requested_signing_identity}" ]]; then
  if [[ ! "${requested_signing_identity}" =~ '^[[:xdigit:]]{40}$' ]]; then
    print -u2 "DNIE_SIGNING_IDENTITY_SHA1 must be exactly one 40-hex Apple Development identity hash."
    exit 64
  fi
  requested_signing_identity="${requested_signing_identity:u}"
  if (( ${signing_identities[(I)${requested_signing_identity}]} == 0 )); then
    print -u2 "The explicitly selected Apple Development identity is not currently valid."
    exit 1
  fi
  signing_identity="${requested_signing_identity}"
elif [[ "${#signing_identities}" -eq 0 ]]; then
  print -u2 "No valid Apple Development code-signing identity was found."
  exit 1
elif [[ "${#signing_identities}" -ne 1 ]]; then
  print -u2 "Multiple valid Apple Development identities were found; set DNIE_SIGNING_IDENTITY_SHA1 explicitly."
  exit 1
else
  signing_identity="${signing_identities[1]}"
fi

if [[ "${1:-}" == --check-signing ]]; then
  [[ "$#" -eq 1 ]] || exit 64
  print "signing_selection=pass"
  print "signing_identity_logged=false"
  exit 0
fi
[[ "$#" -eq 0 ]] || exit 64

"${repository_root}/Validation/Scripts/stage-production-credential-asset.sh"
if ! git -C "${repository_root}" check-ignore --quiet "${credential_asset}"; then
  print -u2 "The development credential asset is not ignored; refusing the build."
  exit 1
fi

build_log="$(mktemp /private/tmp/dnie-development-build.XXXXXX)"
host_entitlements_file="$(mktemp /private/tmp/dnie-development-host-entitlements.XXXXXX)"
extension_entitlements_file="$(mktemp /private/tmp/dnie-development-extension-entitlements.XXXXXX)"
chmod 600 "${build_log}" "${host_entitlements_file}" "${extension_entitlements_file}"
cleanup() {
  rm -f "${build_log}" "${host_entitlements_file}" "${extension_entitlements_file}"
}
trap cleanup EXIT INT TERM

set +e
xcodebuild \
  -project "${repository_root}/DNIeToken.xcodeproj" \
  -scheme DNIeTokenHost \
  -configuration "${configuration}" \
  -destination 'generic/platform=macOS' \
  -derivedDataPath "${derived_data}" \
  build \
  -quiet \
  ARCHS=arm64 \
  ONLY_ACTIVE_ARCH=YES \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="${signing_identity}" \
  DEVELOPMENT_TEAM= \
  PROVISIONING_PROFILE_SPECIFIER= \
  MARKETING_VERSION="${marketing_version}" \
  CURRENT_PROJECT_VERSION="${build_number}" \
  >"${build_log}" 2>&1
build_status="$?"
set -e
if [[ "${build_status}" -ne 0 ]]; then
  sed -E \
    -e 's/[[:xdigit:]]{40}/[REDACTED_SIGNING_ID]/g' \
    -e 's/Apple Development: [^)]*/Apple Development: [REDACTED]/g' \
    "${build_log}" >&2
  exit "${build_status}"
fi

test -d "${host_app}"
test -d "${extension}"
codesign --verify --deep --strict --verbose=4 "${host_app}"
codesign --verify --strict --verbose=4 "${extension}"

host_identifier="$(plutil -extract CFBundleIdentifier raw "${host_app}/Contents/Info.plist")"
extension_identifier="$(plutil -extract CFBundleIdentifier raw "${extension}/Contents/Info.plist")"
aid="$(/usr/libexec/PlistBuddy \
  -c 'Print :NSExtension:NSExtensionAttributes:com.apple.ctk.aid' \
  "${extension}/Contents/Info.plist")"
if [[ "${host_identifier}" != "org.dniemacos.dnietoken" ||
      "${extension_identifier}" != "org.dniemacos.dnietoken.tokenextension" ||
      "${aid}" != "A000000063504B43532D3135" ]]; then
  print -u2 "The signed product metadata does not match the production identifiers."
  exit 1
fi

embedded_assets=("${(@f)$(find "${host_app}" -type f -name generation2.json -print)}")
if [[ "${#embedded_assets[@]}" -ne 1 ]]; then
  print -u2 "Expected exactly one embedded generation-2 credential asset."
  exit 1
fi
if ! jq -e '
  .fixture_version == 2 and
  .set_id == "generation_2" and
  .manifest_sha256 == "3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d"
' "${embedded_assets[1]}" >/dev/null; then
  print -u2 "The embedded credential asset failed its public integrity metadata gate."
  exit 1
fi

codesign --display --entitlements :- "${host_app}" >"${host_entitlements_file}" 2>/dev/null ||
  { print -u2 "Unable to inspect signed host entitlements."; exit 1; }
codesign --display --entitlements :- "${extension}" >"${extension_entitlements_file}" 2>/dev/null ||
  { print -u2 "Unable to inspect signed extension entitlements."; exit 1; }
[[ ! -s "${host_entitlements_file}" ]] || /usr/bin/plutil -lint "${host_entitlements_file}" >/dev/null 2>&1 ||
  { print -u2 "The signed host entitlement export is malformed."; exit 1; }
if /usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "${host_entitlements_file}" >/dev/null 2>&1 ||
   /usr/libexec/PlistBuddy -c 'Print :com.apple.security.smartcard' "${host_entitlements_file}" >/dev/null 2>&1 ||
   /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups' "${host_entitlements_file}" >/dev/null 2>&1; then
  print -u2 "The signed delivery host has a sandbox, Smart Card, or keychain capability."
  exit 1
fi
if [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "${extension_entitlements_file}" 2>/dev/null)" != true ||
      "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.smartcard' "${extension_entitlements_file}" 2>/dev/null)" != true ]] ||
   /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups' "${extension_entitlements_file}" >/dev/null 2>&1; then
  print -u2 "The signed extension entitlement boundary is not the expected sandboxed Smart Card subset."
  exit 1
fi

host_signature="$({ codesign --display --verbose=4 "${host_app}"; } 2>&1)" || { print -u2 "Unable to read the signed host identity."; exit 1; }
extension_signature="$({ codesign --display --verbose=4 "${extension}"; } 2>&1)" || { print -u2 "Unable to read the signed extension identity."; exit 1; }
host_team="$(print -r -- "${host_signature}" | sed -n 's/^TeamIdentifier=//p' | head -n 1)"
extension_team="$(print -r -- "${extension_signature}" | sed -n 's/^TeamIdentifier=//p' | head -n 1)"
if [[ "${host_signature}" != *$'Authority=Apple Development:'* || "${extension_signature}" != *$'Authority=Apple Development:'* ||
      "${host_signature}" != *'(runtime)'* || "${extension_signature}" != *'(runtime)'* ||
      ! "${host_team}" =~ '^[[:alnum:]]{10}$' || "${host_team}" != "${extension_team}" ]]; then
  print -u2 "The host and extension are not paired to the same Apple Development team."
  exit 1
fi

print "development_build=pass"
print "signing_class=apple_development"
print "host_app=${host_app}"
print "host_bundle_identifier=${host_identifier}"
print "extension_bundle_identifier=${extension_identifier}"
print "credential_asset_count=1"
print "credential_asset_value_logged=false"
