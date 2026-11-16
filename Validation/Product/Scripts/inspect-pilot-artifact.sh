#!/bin/zsh
set -euo pipefail

fail() { print -u2 -- "$1"; exit "${2:-1}"; }

mode=single
typeset -a sensitive_temporaries
sensitive_temporaries=()
cleanup_sensitive_temporaries() {
  (( ${#sensitive_temporaries} == 0 )) || /bin/rm -f -- "${sensitive_temporaries[@]}"
}
case "${1:-}" in
  --upgrade-pair)
    [[ "$#" -eq 3 && -n "${2:-}" && -n "${3:-}" ]] ||
      fail "usage: ${0:t} --upgrade-pair OLD_APP CANDIDATE_APP" 64
    mode=pair
    old_app="$2"
    candidate_app="$3"
    ;;
  *)
    [[ "$#" -eq 1 && -n "${1:-}" ]] || fail "usage: ${0:t} APP" 64
    app="$1"
    ;;
esac

inspect_artifact() {
local app="$1"

if [[ "${DNIE_LIFECYCLE_TEST_MODE:-0}" == 1 ]]; then
  [[ "${DNIE_LIFECYCLE_TEST_ROOT:-}" == /private/tmp/dnie-pilot-lifecycle-test.* ]] ||
    fail "The lifecycle test root must be an isolated /private/tmp fixture." 64
  cursor="${app:h}"
  [[ "${DNIE_LIFECYCLE_TEST_ROOT:A}" == "${DNIE_LIFECYCLE_TEST_ROOT}" && "${app:A}" == "${app}" &&
     "${app}" == "${DNIE_LIFECYCLE_TEST_ROOT}"/* ]] || fail "The test artifact escaped its canonical fixture root." 64
  while [[ "${cursor}" == "${DNIE_LIFECYCLE_TEST_ROOT}"/* ]]; do
    [[ -d "${cursor}" && ! -L "${cursor}" && "${cursor:A}" == "${cursor}" &&
       "$(/usr/bin/stat -f %u "${cursor}")" == "${EUID}" ]] || fail "A test artifact ancestor is unsafe." 64
    cursor="${cursor:h}"
  done
  metadata="${app}/Contents/Resources/pilot-artifact-metadata"
  [[ -d "${app}" && ! -L "${app}" && -f "${metadata}" && ! -L "${metadata}" ]] ||
    fail "The synthetic artifact is missing or unsafe."
  metadata_value() {
    local key="$1" values
    values="$(/usr/bin/sed -n "s/^${key}=//p" "${metadata}")"
    [[ -n "${values}" && "$(print -r -- "${values}" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] ||
      fail "The synthetic artifact metadata is missing or ambiguous."
    print -r -- "${values}"
  }
  host_id="$(metadata_value host_id)"
  extension_id="$(metadata_value extension_id)"
  host_version="$(metadata_value host_version)"
  host_build="$(metadata_value host_build)"
  extension_version="$(metadata_value extension_version)"
  extension_build="$(metadata_value extension_build)"
  host_cdhash="$(metadata_value host_cdhash)"
  extension_cdhash="$(metadata_value extension_cdhash)"
  legacy_cdhash="$(metadata_value cdhash)"
  team_pairing="$(metadata_value team_pairing)"
  [[ "${host_id}" == org.dniemacos.dnietoken ]] || fail "The host identifier is incorrect."
  [[ "${extension_id}" == org.dniemacos.dnietoken.tokenextension ]] || fail "The extension identifier is incorrect."
  grep -qx 'extension_point=com.apple.ctk-tokens' "${metadata}" || fail "The extension point is incorrect."
  grep -qx 'token_type=smartcard' "${metadata}" || fail "The token type is incorrect."
  grep -qx 'aid=A000000063504B43532D3135' "${metadata}" || fail "The production AID is incorrect."
  grep -qx 'class_id=org.dniemacos.dnietoken.token' "${metadata}" || fail "The token class identifier is incorrect."
  grep -qx 'driver_class=DNIeTokenExtension.TokenDriver' "${metadata}" || fail "The token driver class is incorrect."
  grep -qx 'host_sandbox_entitlement=absent' "${metadata}" || fail "The delivery host must not be sandboxed."
  grep -qx 'host_smartcard_entitlement=absent' "${metadata}" || fail "The delivery host must not have the Smart Card entitlement."
  grep -qx 'host_keychain_groups=absent' "${metadata}" || fail "The delivery host has unexpected keychain access groups."
  grep -qx 'extension_sandbox_entitlement=true' "${metadata}" || fail "The extension App Sandbox entitlement is missing."
  grep -qx 'extension_smartcard_entitlement=true' "${metadata}" || fail "The extension Smart Card entitlement is missing."
  grep -qx 'extension_keychain_groups=absent' "${metadata}" || fail "The extension has unexpected keychain access groups."
  grep -qx 'credential_asset_count=1' "${metadata}" || fail "The credential asset count is incorrect."
  synthetic_asset="${app}/Contents/Resources/generation2.synthetic.json"
  [[ -f "${synthetic_asset}" && ! -L "${synthetic_asset}" ]] || fail "The synthetic credential fixture is missing."
  ordered_names=("${(@f)$(/usr/bin/jq -r '.ordered_field_names[]' "${synthetic_asset}")}")
  synthetic_hash="$({
    for name in "${ordered_names[@]}"; do
      field_hex="$(/usr/bin/jq -er --arg name "${name}" '.fields_hex[$name]' "${synthetic_asset}")"
      [[ "${field_hex}" =~ '^[[:xdigit:]]+$' && $(( ${#field_hex} % 2 )) == 0 ]] || exit 1
      print -rn -- "${name}"; printf '\0'; printf '%08x' "$(( ${#field_hex} / 2 ))" | /usr/bin/xxd -r -p
      print -rn -- "${field_hex}" | /usr/bin/xxd -r -p
    done
  } | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')" || fail "The synthetic credential field is malformed."
  [[ "${synthetic_hash}" == e53e237646482b2d405f2ce104dc31e2a34f28aeabb79127be429cbc2206b76a ]] ||
    fail "The synthetic credential field content failed manifest recomputation."
  [[ "${host_version}" == "${extension_version}" && "${host_build}" == "${extension_build}" ]] ||
    fail "The host and extension versions do not match."
  [[ ( "${host_version}" == 0.1.0 && "${host_build}" == 1 ) ||
     ( "${host_version}" == 0.1.1 && "${host_build}" == 2 ) ]] ||
    fail "The artifact version is outside the first pilot upgrade contract."
  [[ "${host_cdhash}" =~ '^[[:xdigit:]]{40}$' && "${extension_cdhash}" =~ '^[[:xdigit:]]{40}$' ]] ||
    fail "A signed artifact identity is missing or malformed."
  [[ "${legacy_cdhash:l}" == "${host_cdhash:l}" ]] || fail "The compatibility artifact identity does not match the host identity."
  [[ "${host_cdhash:l}" != "${extension_cdhash:l}" ]] || fail "The host and extension identities must be distinct."
  [[ "${team_pairing}" == pass ]] || fail "The host and extension are not paired to the same Apple Development team."
  if [[ "${mode}" == pair ]]; then
    host_team="$(metadata_value host_team)"
    extension_team="$(metadata_value extension_team)"
    [[ "${host_team}" =~ '^[[:alnum:]]{10}$' && "${host_team}" == "${extension_team}" ]] ||
      fail "The host and extension are not paired to the same Apple Development team."
  else
    host_team=""
    extension_team=""
  fi
  credential_binding="synthetic-not-applicable"
else
  for variable in ${(k)parameters}; do
    [[ "${variable}" == DNIE_LIFECYCLE_* ]] || continue
    fail "Test-only lifecycle overrides are not accepted for production artifact inspection." 64
  done
  [[ -x /usr/bin/jq ]] || fail "The fixed system jq prerequisite is unavailable; artifact inspection cannot proceed." 69
  [[ -d "${app}" && ! -L "${app}" ]] || fail "The product app is missing or is a symlink."
  [[ -z "$(/usr/bin/find "${app}" -type l -print -quit)" ]] || fail "The product bundle contains a symlink."
  extension="${app}/Contents/PlugIns/DNIeTokenExtension.appex"
  [[ -d "${extension}" && ! -L "${extension}" ]] || fail "The embedded extension is missing or is a symlink."
  /usr/bin/codesign --verify --deep --strict "${app}" >/dev/null 2>&1 || fail "Strict product signature verification failed."
  /usr/bin/codesign --verify --strict "${extension}" >/dev/null 2>&1 || fail "Strict extension signature verification failed."
  host_id="$(/usr/bin/plutil -extract CFBundleIdentifier raw "${app}/Contents/Info.plist")"
  host_version="$(/usr/bin/plutil -extract CFBundleShortVersionString raw "${app}/Contents/Info.plist")"
  host_build="$(/usr/bin/plutil -extract CFBundleVersion raw "${app}/Contents/Info.plist")"
  extension_id="$(/usr/bin/plutil -extract CFBundleIdentifier raw "${extension}/Contents/Info.plist")"
  extension_version="$(/usr/bin/plutil -extract CFBundleShortVersionString raw "${extension}/Contents/Info.plist")"
  extension_build="$(/usr/bin/plutil -extract CFBundleVersion raw "${extension}/Contents/Info.plist")"
  point="$(/usr/bin/plutil -extract NSExtension.NSExtensionPointIdentifier raw "${extension}/Contents/Info.plist")"
  token_type="$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionAttributes:com.apple.ctk.token-type' "${extension}/Contents/Info.plist")"
  aid="$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionAttributes:com.apple.ctk.aid' "${extension}/Contents/Info.plist")"
  class_id="$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionAttributes:com.apple.ctk.class-id' "${extension}/Contents/Info.plist")"
  driver_class="$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionAttributes:com.apple.ctk.driver-class' "${extension}/Contents/Info.plist")"
  [[ "${host_id}" == org.dniemacos.dnietoken && "${extension_id}" == org.dniemacos.dnietoken.tokenextension &&
     "${point}" == com.apple.ctk-tokens && "${token_type}" == smartcard && "${aid}" == A000000063504B43532D3135 &&
     "${class_id}" == org.dniemacos.dnietoken.token && "${driver_class}" == DNIeTokenExtension.TokenDriver ]] ||
    fail "The signed product metadata does not match the production boundary."
  [[ "${host_version}" == "${extension_version}" && "${host_build}" == "${extension_build}" ]] ||
    fail "The host and extension versions do not match."
  [[ ( "${host_version}" == 0.1.0 && "${host_build}" == 1 ) ||
     ( "${host_version}" == 0.1.1 && "${host_build}" == 2 ) ]] ||
    fail "The artifact version is outside the first pilot upgrade contract."

  host_entitlement_file="$(mktemp /private/tmp/dnie-pilot-host-entitlements.XXXXXX)"
  sensitive_temporaries+=("${host_entitlement_file}")
  trap cleanup_sensitive_temporaries EXIT INT TERM
  extension_entitlement_file="$(mktemp /private/tmp/dnie-pilot-extension-entitlements.XXXXXX)"
  sensitive_temporaries+=("${extension_entitlement_file}")
  chmod 600 "${host_entitlement_file}" "${extension_entitlement_file}"
  /usr/bin/codesign --display --entitlements :- "${app}" >"${host_entitlement_file}" 2>/dev/null ||
    fail "Unable to inspect signed host entitlements."
  /usr/bin/codesign --display --entitlements :- "${extension}" >"${extension_entitlement_file}" 2>/dev/null ||
    fail "Unable to inspect signed extension entitlements."
  [[ ! -s "${host_entitlement_file}" ]] || /usr/bin/plutil -lint "${host_entitlement_file}" >/dev/null 2>&1 ||
    fail "The signed host entitlement export is malformed."
  ! /usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "${host_entitlement_file}" >/dev/null 2>&1 &&
    ! /usr/libexec/PlistBuddy -c 'Print :com.apple.security.smartcard' "${host_entitlement_file}" >/dev/null 2>&1 &&
    ! /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups' "${host_entitlement_file}" >/dev/null 2>&1 ||
    fail "The signed delivery host has a sandbox, Smart Card, or keychain capability."
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.app-sandbox' "${extension_entitlement_file}" 2>/dev/null)" == true &&
     "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.smartcard' "${extension_entitlement_file}" 2>/dev/null)" == true ]] ||
    fail "The signed extension entitlement boundary is incomplete."
  ! /usr/libexec/PlistBuddy -c 'Print :keychain-access-groups' "${extension_entitlement_file}" >/dev/null 2>&1 ||
    fail "The signed extension has unexpected keychain access groups."

  asset="${extension}/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets/generation2.json"
  [[ -f "${asset}" && ! -L "${asset}" ]] || fail "The exact runtime generation-2 credential asset is missing or unsafe."
  found_assets=("${(@f)$(/usr/bin/find "${app}" -type f -name generation2.json -print)}"); found_assets=("${(@)found_assets:#}")
  (( ${#found_assets} == 1 )) && [[ "${found_assets[1]}" == "${asset}" ]] || fail "The runtime credential asset location is duplicated or ambiguous."
  assets=("${asset}")
  expected_names='["icc_root_ca_modulus_1","ifd_modulus_1","ifd_pin_modulus_1","ifd_private_exponent_1","ifd_pin_private_exponent_1","C_CV_CA_CS_AUT_cert_1","C_CV_IFDUser_AUT_cert_1","C_CV_IFDUser_AUT_pin_cert_1","cvc_intca_keyref_1","cvc_ifd_keyref_1","cvc_ifd_keyref_pin_1","sn_ifd_1","sn_ifd_pin_1","icc_root_ca_public_exponent","ifd_public_exponent","ifd_pin_public_exponent","root_ca_keyref","icc_priv_keyref"]'
  /usr/bin/jq -e --argjson names "${expected_names}" '
    .fixture_version == 2 and .set_id == "generation_2" and
    .manifest_sha256 == "3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d" and
    .source_sha256 == "6528a9662523362f53479440c6611a241cda1940a2b5a05fa5deb4c8bf3cba4a" and
    .official_binary_sha256 == "d2de4308190433a22683ef7fa85637b446f2a9420e35e50b86314a5590c46bc2" and
    .ordered_field_names == $names and (.fields_hex | keys | sort) == ($names | sort) and
    (.local_private_keys_pkcs1_hex | keys | sort) == ["pin", "user"] and
    (.local_private_keys_pkcs1_hex.pin | type == "string" and length > 0 and length <= 8192) and
    (.local_private_keys_pkcs1_hex.user | type == "string" and length > 0 and length <= 8192)
  ' "${assets[1]}" >/dev/null || fail "The embedded credential asset failed its manifest integrity gate."
  ordered_names=("${(@f)$(/usr/bin/jq -r '.ordered_field_names[]' "${assets[1]}")}")
  computed_manifest="$({
    for name in "${ordered_names[@]}"; do
      field_hex="$(/usr/bin/jq -er --arg name "${name}" '.fields_hex[$name]' "${assets[1]}")"
      [[ "${field_hex}" =~ '^[[:xdigit:]]+$' && $(( ${#field_hex} % 2 )) == 0 && ${#field_hex} -le 8192 ]] || exit 1
      print -rn -- "${name}"; printf '\0'; printf '%08x' "$(( ${#field_hex} / 2 ))" | /usr/bin/xxd -r -p
      print -rn -- "${field_hex}" | /usr/bin/xxd -r -p
    done
  } | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')" || fail "The embedded credential asset contains a malformed field."
  [[ "${computed_manifest}" == 3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d ]] ||
    fail "The embedded credential field content failed the computed manifest gate."
  for binding in 'user:ifd_modulus_1' 'pin:ifd_pin_modulus_1'; do
    role="${binding%%:*}"; modulus_name="${binding#*:}"
    key_hex="$(/usr/bin/jq -er --arg role "${role}" '.local_private_keys_pkcs1_hex[$role]' "${assets[1]}")"
    expected_modulus="$(/usr/bin/jq -er --arg name "${modulus_name}" '.fields_hex[$name]' "${assets[1]}")"
    [[ "${key_hex}" =~ '^[[:xdigit:]]+$' && $(( ${#key_hex} % 2 )) == 0 && ${#key_hex} -le 8192 ]] ||
      fail "The embedded credential private-key encoding is malformed."
    print -rn -- "${key_hex}" | /usr/bin/xxd -r -p | /usr/bin/openssl rsa -inform DER -check -noout >/dev/null 2>&1 ||
      fail "The embedded credential private-key structure is invalid."
    observed_modulus="$(print -rn -- "${key_hex}" | /usr/bin/xxd -r -p | /usr/bin/openssl rsa -inform DER -modulus -noout 2>/dev/null)" ||
      fail "The embedded credential private-key binding could not be inspected."
    observed_modulus="${observed_modulus#Modulus=}"
    expected_modulus="$(print -rn -- "${expected_modulus}" | /usr/bin/sed 's/^0*//')"
    [[ "${observed_modulus:l}" == "${expected_modulus:l}" ]] || fail "The embedded credential private key does not match its public modulus."
  done
  host_signature="$({ /usr/bin/codesign --display --verbose=4 "${app}"; } 2>&1)" || fail "Unable to read the signed host identity."
  extension_signature="$({ /usr/bin/codesign --display --verbose=4 "${extension}"; } 2>&1)" || fail "Unable to read the signed extension identity."
  host_teams="$(print -r -- "${host_signature}" | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  extension_teams="$(print -r -- "${extension_signature}" | /usr/bin/sed -n 's/^TeamIdentifier=//p')"
  [[ -n "${host_teams}" && "$(print -r -- "${host_teams}" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 &&
     -n "${extension_teams}" && "$(print -r -- "${extension_teams}" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" == 1 ]] ||
    fail "The signed team identity is missing or ambiguous."
  host_team="${host_teams}"
  extension_team="${extension_teams}"
  [[ "${host_signature}" == *$'Authority=Apple Development:'* && "${extension_signature}" == *$'Authority=Apple Development:'* &&
     "${host_signature}" == *'(runtime)'* && "${extension_signature}" == *'(runtime)'* &&
     "${host_team}" =~ '^[[:alnum:]]{10}$' && "${host_team}" == "${extension_team}" ]] ||
    fail "The host and extension are not paired to the same Apple Development team."
  host_cdhash="$(print -r -- "${host_signature}" | sed -n 's/^CDHash=//p' | head -n 1)"
  extension_cdhash="$(print -r -- "${extension_signature}" | sed -n 's/^CDHash=//p' | head -n 1)"
  [[ "${host_cdhash}" =~ '^[[:xdigit:]]{40}$' && "${extension_cdhash}" =~ '^[[:xdigit:]]{40}$' ]] ||
    fail "A signed artifact identity is missing or malformed."
  [[ "${host_cdhash:l}" != "${extension_cdhash:l}" ]] || fail "The host and extension identities must be distinct."
  credential_binding="pass"
fi
}

print_tuple() {
local prefix="$1"

print "${prefix}artifact_verification=pass"
print "${prefix}host_bundle_identifier=org.dniemacos.dnietoken"
print "${prefix}extension_bundle_identifier=org.dniemacos.dnietoken.tokenextension"
print "${prefix}host_marketing_version=${host_version}"
print "${prefix}host_build_version=${host_build}"
print "${prefix}extension_marketing_version=${extension_version}"
print "${prefix}extension_build_version=${extension_build}"
print "${prefix}host_cdhash=${host_cdhash:l}"
print "${prefix}extension_cdhash=${extension_cdhash:l}"
print "${prefix}artifact_cdhash=${host_cdhash:l}"
print "${prefix}artifact_team_pairing=pass"
print "${prefix}credential_asset_count=1"
print "${prefix}credential_private_key_binding=${credential_binding}"
print "${prefix}credential_asset_value_logged=false"
}

if [[ "${mode}" == single ]]; then
  inspect_artifact "${app}"
  print_tuple ""
  exit 0
fi

inspect_artifact "${old_app}"
[[ "${host_version}" == 0.1.0 && "${host_build}" == 1 &&
   "${extension_version}" == 0.1.0 && "${extension_build}" == 1 ]] ||
  fail "The old artifact is not the fixed 0.1.0 build 1 tuple."
old_host_cdhash="${host_cdhash:l}"
old_extension_cdhash="${extension_cdhash:l}"
old_team="${host_team}"
old_tuple="$(print_tuple old_)"

inspect_artifact "${candidate_app}"
[[ "${host_version}" == 0.1.1 && "${host_build}" == 2 &&
   "${extension_version}" == 0.1.1 && "${extension_build}" == 2 ]] ||
  fail "The candidate artifact is not the fixed 0.1.1 build 2 tuple."
[[ "${old_host_cdhash}" != "${host_cdhash:l}" &&
   "${old_extension_cdhash}" != "${extension_cdhash:l}" ]] ||
  fail "The old and candidate signed artifact identities are not distinct."
[[ "${old_team}" == "${host_team}" ]] || fail "The old and candidate artifacts are signed by different teams."

print -r -- "${old_tuple}"
print_tuple new_
print "upgrade_pair_verification=pass"
print "upgrade_pair_team_match=pass"
