#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
repository_root="${script_dir:h:h:h}"
derived_data="${repository_root}/DerivedData/T067"
installed_app="/Applications/DNIeTokenHost.app"

if [[ ! -d "${installed_app}" ]]; then
  print -u2 "The development provider is not installed."
  exit 1
fi

# Remove the competing build-tree registration before accepting installed-path evidence.
xcodebuild \
  -project "${repository_root}/DNIeToken.xcodeproj" \
  -scheme DNIeTokenHost \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -derivedDataPath "${derived_data}" \
  clean \
  -quiet

/usr/bin/open -g "${installed_app}"
for _ in {1..20}; do
  if "${script_dir}/inspect-registration.sh" >/dev/null 2>&1; then
    "${script_dir}/inspect-registration.sh"
    print "build_tree_registration_removed=true"
    exit 0
  fi
  sleep 0.25
done

print -u2 "The installed production provider did not become uniquely visible within five seconds."
exit 1
