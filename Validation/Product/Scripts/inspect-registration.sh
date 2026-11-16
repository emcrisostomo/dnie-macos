#!/bin/zsh
set -euo pipefail

bundle_identifier="org.dniemacos.dnietoken.tokenextension"
installed_extension="/Applications/DNIeTokenHost.app/Contents/PlugIns/DNIeTokenExtension.appex"

registration="$(pluginkit -m -A -D -vvv -i "${bundle_identifier}")"
if [[ "${registration}" != *"${bundle_identifier}"* ||
      "${registration}" != *"Path = ${installed_extension}"* ]]; then
  print -u2 "The production provider is not uniquely visible from its installed path."
  exit 1
fi
if [[ "$(print -r -- "${registration}" | grep -c "${bundle_identifier}")" -ne 1 ]]; then
  print -u2 "More than one production-provider registration is visible."
  exit 1
fi

print "installed_provider_visibility=pass"
print "installed_extension=${installed_extension}"
