#!/bin/zsh
set -euo pipefail

fixture_root="$(mktemp -d /private/tmp/dnie-asset-stage-test.XXXXXX)"
cleanup() { /bin/rm -rf -- "${fixture_root}"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

repository="${fixture_root}/repository"
helper="${repository}/Validation/Scripts/stage-production-credential-asset.sh"
source_fixture="${repository}/Validation/private/SecureChannel/generation2.json"
asset_directory="${repository}/Packages/DNIeCore/Sources/DNIeCore/Evidence/Credentials/Assets"
destination="${asset_directory}/generation2.json"
external="${fixture_root}/external"

/bin/mkdir -p "${helper:h}" "${source_fixture:h}" "${asset_directory}" "${external}"
/bin/cp "${0:A:h}/stage-production-credential-asset.sh" "${helper}"
/bin/chmod 755 "${helper}"

write_fixture() {
  local changed="$1"
  print -r -- "{
    \"fixture_version\": 2,
    \"set_id\": \"generation_2\",
    \"manifest_sha256\": \"3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d\",
    \"source_sha256\": \"6528a9662523362f53479440c6611a241cda1940a2b5a05fa5deb4c8bf3cba4a\",
    \"official_binary_sha256\": \"d2de4308190433a22683ef7fa85637b446f2a9420e35e50b86314a5590c46bc2\",
    \"ordered_field_names\": [\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\",\"j\",\"k\",\"l\",\"m\",\"n\",\"o\",\"p\",\"q\",\"r\"],
    \"fields_hex\": {\"a\":\"${changed}\",\"b\":\"02\",\"c\":\"03\",\"d\":\"04\",\"e\":\"05\",\"f\":\"06\",\"g\":\"07\",\"h\":\"08\",\"i\":\"09\",\"j\":\"0a\",\"k\":\"0b\",\"l\":\"0c\",\"m\":\"0d\",\"n\":\"0e\",\"o\":\"0f\",\"p\":\"10\",\"q\":\"11\",\"r\":\"12\"},
    \"local_private_keys_pkcs1_hex\": {\"pin\":\"00\",\"user\":\"00\"}
  }" > "${source_fixture}"
  /bin/chmod 600 "${source_fixture}"
}

write_fixture 01
"${helper}" >/dev/null
[[ -f "${destination}" && ! -L "${destination}" &&
   "$(/usr/bin/stat -f '%u' "${destination}")" == "${EUID}" &&
   "$(/usr/bin/stat -f '%Lp' "${destination}")" == 600 ]]
/usr/bin/cmp -s "${source_fixture}" "${destination}"

/usr/bin/touch -t 202001010000 "${destination}"
inode_before="$(/usr/bin/stat -f '%i' "${destination}")"
mtime_before="$(/usr/bin/stat -f '%m' "${destination}")"
hash_before="$(/usr/bin/shasum -a 256 "${destination}" | /usr/bin/cut -d ' ' -f 1)"
"${helper}" >/dev/null
[[ "$(/usr/bin/stat -f '%i' "${destination}")" == "${inode_before}" &&
   "$(/usr/bin/stat -f '%m' "${destination}")" == "${mtime_before}" &&
   "$(/usr/bin/shasum -a 256 "${destination}" | /usr/bin/cut -d ' ' -f 1)" == "${hash_before}" ]]

write_fixture 19
"${helper}" >/dev/null
[[ "$(/usr/bin/stat -f '%i' "${destination}")" != "${inode_before}" ]]
/usr/bin/cmp -s "${source_fixture}" "${destination}"
[[ -z "$(/usr/bin/find "${asset_directory}" -maxdepth 1 -name '.generation2.json.stage.*' -print -quit)" ]]

/bin/mv "${destination}" "${destination}.safe"
print -r -- sentinel > "${external}/collision"
/bin/ln -s "${external}/collision" "${destination}"
if "${helper}" >/dev/null 2>&1; then exit 91; fi
[[ "$(<"${external}/collision")" == sentinel ]]
/bin/rm "${destination}"
/bin/mv "${destination}.safe" "${destination}"

/bin/chmod 644 "${destination}"
if "${helper}" >/dev/null 2>&1; then exit 92; fi
/bin/chmod 600 "${destination}"

/bin/ln "${destination}" "${external}/hardlink"
if "${helper}" >/dev/null 2>&1; then exit 95; fi
/bin/rm "${external}/hardlink"

/bin/mv "${source_fixture}" "${source_fixture}.safe"
/bin/ln -s "${source_fixture}.safe" "${source_fixture}"
if "${helper}" >/dev/null 2>&1; then exit 96; fi
/bin/rm "${source_fixture}"
/bin/mv "${source_fixture}.safe" "${source_fixture}"

/bin/mv "${asset_directory}" "${asset_directory}.safe"
/bin/ln -s "${external}" "${asset_directory}"
if "${helper}" >/dev/null 2>&1; then exit 93; fi
/bin/rm "${asset_directory}"
/bin/mv "${asset_directory}.safe" "${asset_directory}"

/bin/chmod 777 "${asset_directory:h}"
if "${helper}" >/dev/null 2>&1; then exit 94; fi
/bin/chmod 755 "${asset_directory:h}"

grep -Fq 'destination changed during staging' "${helper}"
grep -Fq "stat -f '%d:%i'" "${helper}"
grep -Fq '(( EUID != 0 ))' "${helper}"

print 'stage_production_credential_asset=pass'
