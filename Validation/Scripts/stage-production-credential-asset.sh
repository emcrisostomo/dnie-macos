#!/bin/zsh

set -euo pipefail

fail() {
  print -u2 -- "$1"
  exit "${2:-1}"
}

(( EUID != 0 )) || fail "Do not stage the development credential as root."

script_dir=${0:A:h}
repository=${script_dir:h:h}
source_fixture="${repository}/Validation/private/SecureChannel/generation2.json"
asset_directory="${repository}/Packages/DNIeCore/Sources/DNIeCore/Evidence/Credentials/Assets"
destination="${asset_directory}/generation2.json"
temporary=""
destination_identity=""

cleanup() {
  [[ -z "${temporary}" ]] || /bin/rm -f -- "${temporary}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_safe_directory() {
  local directory="$1"
  local mode
  [[ -d "${directory}" && ! -L "${directory}" && "${directory:A}" == "${directory}" ]] ||
    fail "A credential staging directory is missing, linked, or noncanonical."
  [[ "$(/usr/bin/stat -f '%u' "${directory}")" == "${EUID}" ]] ||
    fail "A credential staging directory is not owned by the invoking user."
  mode="$(/usr/bin/stat -f '%Lp' "${directory}")"
  (( (8#${mode} & 8#22) == 0 )) ||
    fail "A credential staging directory is writable by another account."
}

require_safe_ancestors() {
  local target="$1"
  local relative component cursor
  require_safe_directory "${repository}"
  [[ "${target}" == "${repository}"/* ]] || fail "The credential staging path escaped the repository."
  relative="${target#${repository}/}"
  cursor="${repository}"
  for component in ${(s:/:)relative}; do
    [[ -n "${component}" && "${component}" != . && "${component}" != .. ]] ||
      fail "The credential staging path contains an unsafe component."
    cursor="${cursor}/${component}"
    require_safe_directory "${cursor}"
  done
}

require_safe_file() {
  local file="$1"
  [[ -f "${file}" && ! -L "${file}" && "${file:A}" == "${file}" ]] ||
    fail "A credential staging file is missing, linked, or noncanonical."
  [[ "$(/usr/bin/stat -f '%u' "${file}")" == "${EUID}" &&
     "$(/usr/bin/stat -f '%Lp' "${file}")" == 600 &&
     "$(/usr/bin/stat -f '%l' "${file}")" == 1 ]] ||
    fail "A credential staging file has unsafe ownership, mode, or link count."
}

require_safe_ancestors "${source_fixture:h}"
require_safe_file "${source_fixture}"
[[ "$(/usr/bin/stat -f '%z' "${source_fixture}")" -le 65536 ]] ||
  fail "The authorized local generation-2 fixture is too large."

/usr/bin/jq -e '
  .fixture_version == 2 and
  .set_id == "generation_2" and
  .manifest_sha256 == "3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d" and
  .source_sha256 == "6528a9662523362f53479440c6611a241cda1940a2b5a05fa5deb4c8bf3cba4a" and
  .official_binary_sha256 == "d2de4308190433a22683ef7fa85637b446f2a9420e35e50b86314a5590c46bc2" and
  (.ordered_field_names | length) == 18 and
  (.fields_hex | length) == 18 and
  (.local_private_keys_pkcs1_hex | keys | sort) == ["pin", "user"]
' "${source_fixture}" >/dev/null || fail "The authorized local generation-2 fixture failed its metadata gate."

require_safe_ancestors "${asset_directory}"
if [[ -e "${destination}" || -L "${destination}" ]]; then
  require_safe_file "${destination}"
  if /usr/bin/cmp -s -- "${source_fixture}" "${destination}"; then
    print 'production credential asset: unchanged local generation-2 fixture; runtime verification required'
    exit 0
  fi
  destination_identity="$(/usr/bin/stat -f '%d:%i' "${destination}")"
fi

umask 077
temporary="$(/usr/bin/mktemp "${asset_directory}/.generation2.json.stage.XXXXXX")" ||
  fail "Unable to claim a private credential staging file."
require_safe_file "${temporary}"
/bin/cp -- "${source_fixture}" "${temporary}"
/bin/chmod 600 "${temporary}"
require_safe_file "${temporary}"
/usr/bin/cmp -s -- "${source_fixture}" "${temporary}" ||
  fail "The private credential staging copy does not match its source."

require_safe_ancestors "${asset_directory}"
if [[ -e "${destination}" || -L "${destination}" ]]; then
  require_safe_file "${destination}"
  [[ -n "${destination_identity}" &&
     "$(/usr/bin/stat -f '%d:%i' "${destination}")" == "${destination_identity}" ]] ||
    fail "The credential destination changed during staging."
  /bin/mv -f -- "${temporary}" "${destination}"
else
  [[ -z "${destination_identity}" ]] || fail "The credential destination changed during staging."
  /bin/mv -n -- "${temporary}" "${destination}"
  [[ ! -e "${temporary}" ]] || fail "The credential destination appeared during publication."
fi
temporary=""
require_safe_file "${destination}"
/usr/bin/cmp -s -- "${source_fixture}" "${destination}" ||
  fail "The published credential asset does not match its source."

print 'production credential asset: staged local generation-2 fixture; runtime verification required'
