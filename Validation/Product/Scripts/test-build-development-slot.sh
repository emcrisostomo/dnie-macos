#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
source_script="${script_dir}/build-development.sh"
repository_root="${script_dir:h:h:h}"
fixture_root="$(mktemp -d /private/tmp/dnie-build-slot-test.XXXXXX)"
trap 'rm -rf -- "${fixture_root}"' EXIT INT TERM

test_repository="${fixture_root}/repository"
test_scripts="${test_repository}/Validation/Product/Scripts"
stub_bin="${fixture_root}/bin"
sentinel="${fixture_root}/external-command-called"
mkdir -p "${test_scripts}" "${stub_bin}"
cp "${source_script}" "${test_scripts}/build-development.sh"
chmod 700 "${test_scripts}/build-development.sh"

for command in security xcodebuild codesign jq git; do
  {
    print '#!/bin/zsh'
    print 'print -r -- "$0" >> "'"${sentinel}"'"'
    print 'exit 99'
  } > "${stub_bin}/${command}"
  chmod 700 "${stub_bin}/${command}"
done

run_check() {
  env PATH="${stub_bin}:/usr/bin:/bin:/usr/sbin:/sbin" "$@" \
    "${test_scripts}/build-development.sh" --check-build-slot
}

default_output="$(run_check)"
[[ "${default_output}" == *$'development_build_slot=T067\n'* ]]
[[ "${default_output}" == *$'marketing_version=0.1.0\n'* ]]
[[ "${default_output}" == *$'build_number=1\n'* ]]
[[ "${default_output}" == *$'xcodebuild_marketing_version_argument=MARKETING_VERSION=0.1.0\n'* ]]
[[ "${default_output}" == *$'xcodebuild_build_number_argument=CURRENT_PROJECT_VERSION=1\n'* ]]
[[ "${default_output}" == *$'development_build_slot_state=absent\n'* ]]
[[ "${default_output}" == *$'credential_staging_performed=false\n'* ]]
[[ "${default_output}" == *$'signing_keychain_inspected=false\n'* ]]
[[ "${default_output}" == *$'xcodebuild_invoked=false'* ]]
[[ ! -e "${sentinel}" ]]

mkdir "${test_repository}/DerivedData"
validation_absent_output="$(run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083CleanIncremental)"
[[ "${validation_absent_output}" == *$'development_build_slot=T083CleanIncremental\n'* ]]
[[ "${validation_absent_output}" == *$'marketing_version=0.1.0\n'* ]]
[[ "${validation_absent_output}" == *$'build_number=1\n'* ]]
[[ "${validation_absent_output}" == *$'development_build_slot_state=absent\n'* ]]
[[ ! -e "${sentinel}" ]]

upgrade_absent_output="$(run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade)"
[[ "${upgrade_absent_output}" == *$'development_build_slot=T083Upgrade\n'* ]]
[[ "${upgrade_absent_output}" == *$'development_build_slot_state=absent\n'* ]]
[[ "${upgrade_absent_output}" == *$'marketing_version=0.1.1\n'* ]]
[[ "${upgrade_absent_output}" == *$'build_number=2\n'* ]]
[[ "${upgrade_absent_output}" == *$'xcodebuild_marketing_version_argument=MARKETING_VERSION=0.1.1\n'* ]]
[[ "${upgrade_absent_output}" == *$'xcodebuild_build_number_argument=CURRENT_PROJECT_VERSION=2\n'* ]]
[[ ! -e "${sentinel}" ]]

mkdir -p "${test_repository}/DerivedData/T083Upgrade/Build/Products"
touch "${test_repository}/DerivedData/T083Upgrade/Build/Products/safe-product"
upgrade_output="$(run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade)"
[[ "${upgrade_output}" == *$'development_build_slot_state=reusable\n'* ]]
[[ ! -e "${sentinel}" ]]

mkdir "${fixture_root}/outside-upgrade-slot"
ln -s "${fixture_root}/outside-upgrade-slot" \
  "${test_repository}/DerivedData/T083Upgrade/Build/escaped-output"
if run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade \
    >"${fixture_root}/upgrade-nested-symlink.out" 2>"${fixture_root}/upgrade-nested-symlink.err"; then
  print -u2 "upgrade_nested_build_slot_symlink_accepted=true"
  exit 2
fi
grep -q 'contains an unsafe link' "${fixture_root}/upgrade-nested-symlink.err"
[[ ! -e "${sentinel}" ]]
rm "${test_repository}/DerivedData/T083Upgrade/Build/escaped-output"

mkdir -p "${test_repository}/DerivedData/T083CleanIncremental"
validation_output="$(run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083CleanIncremental)"
[[ "${validation_output}" == *$'development_build_slot=T083CleanIncremental\n'* ]]
[[ "${validation_output}" == *$'development_build_slot_state=reusable\n'* ]]
[[ ! -e "${sentinel}" ]]

mkdir -p "${test_repository}/DerivedData/T083CleanIncremental/Build/Products"
touch "${test_repository}/DerivedData/T083CleanIncremental/Build/Products/safe-product"
safe_tree_output="$(run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083CleanIncremental)"
[[ "${safe_tree_output}" == *$'development_build_slot_state=reusable\n'* ]]

mkdir "${fixture_root}/outside-slot"
ln -s "${fixture_root}/outside-slot" \
  "${test_repository}/DerivedData/T083CleanIncremental/Build/escaped-output"
if run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083CleanIncremental \
    >"${fixture_root}/nested-symlink.out" 2>"${fixture_root}/nested-symlink.err"; then
  print -u2 "nested_build_slot_symlink_accepted=true"
  exit 2
fi
grep -q 'contains an unsafe link' "${fixture_root}/nested-symlink.err"
[[ ! -e "${sentinel}" ]]
rm "${test_repository}/DerivedData/T083CleanIncremental/Build/escaped-output"

mkdir "${test_repository}/DerivedData/T067"
touch "${test_repository}/DerivedData/T067/accepted-slot-file"
ln "${test_repository}/DerivedData/T067/accepted-slot-file" \
  "${test_repository}/DerivedData/T083CleanIncremental/Build/aliased-t067-file"
if run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083CleanIncremental \
    >"${fixture_root}/hardlink-alias.out" 2>"${fixture_root}/hardlink-alias.err"; then
  print -u2 "multiply_linked_t067_alias_accepted=true"
  exit 2
fi
grep -q 'multiply linked file' "${fixture_root}/hardlink-alias.err"
[[ ! -e "${sentinel}" ]]

ln "${test_repository}/DerivedData/T067/accepted-slot-file" \
  "${test_repository}/DerivedData/T083Upgrade/Build/aliased-t067-file"
if run_check DNIE_DEVELOPMENT_BUILD_SLOT=T083Upgrade \
    >"${fixture_root}/upgrade-hardlink-alias.out" 2>"${fixture_root}/upgrade-hardlink-alias.err"; then
  print -u2 "upgrade_multiply_linked_t067_alias_accepted=true"
  exit 2
fi
grep -q 'multiply linked file' "${fixture_root}/upgrade-hardlink-alias.err"
[[ ! -e "${sentinel}" ]]

for rejected in '' arbitrary ../T067 /private/tmp/T067 'T083CleanIncremental/child' 'T083Upgrade/child'; do
  if run_check DNIE_DEVELOPMENT_BUILD_SLOT="${rejected}" \
      >"${fixture_root}/rejected.out" 2>"${fixture_root}/rejected.err"; then
    print -u2 "unsafe_build_slot_accepted=true"
    exit 2
  fi
  [[ ! -e "${sentinel}" ]]
done

rm -rf -- "${test_repository}/DerivedData"
touch "${test_repository}/DerivedData"
if run_check >"${fixture_root}/collision.out" 2>"${fixture_root}/collision.err"; then
  print -u2 "derived_data_collision_accepted=true"
  exit 3
fi
grep -q 'symlink or nondirectory collision' "${fixture_root}/collision.err"
[[ ! -e "${sentinel}" ]]

rm -f -- "${test_repository}/DerivedData"
mkdir "${fixture_root}/outside-derived-data"
ln -s "${fixture_root}/outside-derived-data" "${test_repository}/DerivedData"
if run_check >"${fixture_root}/derived-symlink.out" 2>"${fixture_root}/derived-symlink.err"; then
  print -u2 "derived_data_symlink_accepted=true"
  exit 4
fi
grep -q 'symlink or nondirectory collision' "${fixture_root}/derived-symlink.err"
[[ ! -e "${sentinel}" ]]

rm "${test_repository}/DerivedData"
mkdir "${test_repository}/DerivedData"
ln -s "${fixture_root}/outside-derived-data" "${test_repository}/DerivedData/T067"
if run_check >"${fixture_root}/slot-symlink.out" 2>"${fixture_root}/slot-symlink.err"; then
  print -u2 "build_slot_symlink_accepted=true"
  exit 5
fi
grep -q 'symlink or nondirectory collision' "${fixture_root}/slot-symlink.err"
[[ ! -e "${sentinel}" ]]

# Three parents above this copied script resolve to root-owned /private.
root_owner_case="${fixture_root}/root-owner"
mkdir -p "${root_owner_case}"
cp "${source_script}" "${root_owner_case}/build-development.sh"
chmod 700 "${root_owner_case}/build-development.sh"
if env PATH="${stub_bin}:/usr/bin:/bin:/usr/sbin:/sbin" \
    "${root_owner_case}/build-development.sh" --check-build-slot \
    >"${fixture_root}/root-owner.out" 2>"${fixture_root}/root-owner.err"; then
  print -u2 "root_owned_repository_accepted=true"
  exit 6
fi
grep -q 'not owned by the invoking user' "${fixture_root}/root-owner.err"
[[ ! -e "${sentinel}" ]]

for plist in "${repository_root}/HostApp/Info.plist" "${repository_root}/TokenExtension/Info.plist"; do
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${plist}")" == '$(MARKETING_VERSION)' ]]
  [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "${plist}")" == '$(CURRENT_PROJECT_VERSION)' ]]
done
[[ "$(grep -c 'MARKETING_VERSION = 0.1.0;' "${repository_root}/DNIeToken.xcodeproj/project.pbxproj")" -eq 4 ]]
[[ "$(grep -c 'CURRENT_PROJECT_VERSION = 1;' "${repository_root}/DNIeToken.xcodeproj/project.pbxproj")" -eq 4 ]]
grep -q 'MARKETING_VERSION="${marketing_version}"' "${source_script}"
grep -q 'CURRENT_PROJECT_VERSION="${build_number}"' "${source_script}"
! grep -q "PlistBuddy.*Set.*CFBundle\(ShortVersionString\|Version\)" "${source_script}"

print "development_build_slot_offline=pass"
