#!/bin/zsh
set -euo pipefail

lookback="${1:-20m}"
if [[ "${lookback}" != <->(s|m|h) ]]; then
  print -u2 "usage: $0 [integer{s|m|h}]"
  exit 64
fi

scan_file="$(mktemp /private/tmp/dnie-provider-log-scan.XXXXXX)"
chmod 600 "${scan_file}"
cleanup() {
  rm -f "${scan_file}"
}
trap cleanup EXIT INT TERM

test_mode="${DNIE_SECRET_LOG_TEST_MODE:-false}"
if [[ "${test_mode}" != true && "${test_mode}" != false ]]; then
  print -u2 "Invalid provider log test mode."
  exit 64
fi
if [[ "${test_mode}" == true ]]; then
  scan_scope="synthetic_fixture"
  test_input="${DNIE_SECRET_LOG_TEST_INPUT:-}"
  test_query_status="${DNIE_SECRET_LOG_TEST_QUERY_STATUS:-0}"
  test_input_resolved="${test_input:A}"
  test_root="${test_input_resolved:h}"
  if [[ -z "${test_input}" || "${test_query_status}" != <0-255> ||
        "${test_root:t}" != dnie-secret-log-test.* || "${test_root:h}" != /private/tmp ||
        ! -d "${test_root}" || -L "${test_root}" ||
        "$(/usr/bin/stat -f '%u:%Lp' "${test_root}" 2>/dev/null)" != "${EUID}:700" ||
        ! -f "${test_input_resolved}" || -L "${test_input_resolved}" ||
        "$(/usr/bin/stat -f '%u:%Lp' "${test_input_resolved}" 2>/dev/null)" != "${EUID}:600" ]]; then
    print -u2 "Invalid provider log test fixture."
    exit 64
  fi
  if [[ "${test_query_status}" -ne 0 ]]; then
    print -u2 "Provider log query failed."
    exit 65
  fi
  /bin/cat "${test_input_resolved}" > "${scan_file}"
elif (( ${+DNIE_SECRET_LOG_TEST_INPUT} || ${+DNIE_SECRET_LOG_TEST_QUERY_STATUS} )); then
  print -u2 "Provider log test controls require explicit test mode."
  exit 64
else
  scan_scope="subsystem_only"
  if ! /usr/bin/log show \
      --style compact \
      --last "${lookback}" \
      --predicate 'subsystem == "org.dniemacos.dnietoken"' \
      > "${scan_file}"; then
    print -u2 "Provider log query failed."
    exit 65
  fi
fi

for forbidden in \
  'password_(value|length)=' \
  'pin_(value|length)=' \
  'master[-_ ]key' \
  'session[-_ ]key' \
  'protected[-_ ]apdu' \
  'cka[-_ ]id' \
  'certificate_(der|pem|subject|holder|serial|fingerprint)=' \
  'data[-_ ]to[-_ ]sign=' \
  'signature_(value|bytes)=' \
  '[[:xdigit:]]{32,}'; do
  if rg --ignore-case --quiet "${forbidden}" "${scan_file}"; then
    print -u2 "Provider log scan found a forbidden value class."
    exit 1
  fi
done

line_count="$(wc -l < "${scan_file}" | tr -d ' ')"
event_count="$(/usr/bin/awk '
  /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9][.,][0-9]/ { count += 1 }
  END { print count + 0 }
' "${scan_file}")"
print "provider_log_line_count=${line_count}"
print "provider_log_event_count=${event_count}"
print "provider_log_scope=${scan_scope}"
if [[ "${event_count}" -eq 0 ]]; then
  print "secret_log_scan=inconclusive"
  print "retained_log_file=false"
  print -u2 "Provider log scan found no substantive events."
  exit 3
fi
print "secret_log_scan=pass"
print "retained_log_file=false"
