#!/bin/zsh
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  print -u2 "usage: ${0:t}"
  exit 64
fi

script_dir="${0:A:h}"
scanner="${script_dir}/scan-secret-logs.sh"
[[ -x "${scanner}" ]] || exit 10

fixture_root="$(/usr/bin/mktemp -d /private/tmp/dnie-secret-log-test.XXXXXX)"
/bin/chmod 700 "${fixture_root}"
cleanup() {
  /bin/rm -rf -- "${fixture_root}"
}
trap cleanup EXIT HUP INT TERM

header='Timestamp                       Thread     Type        Activity             PID    TTL'
print -rn -- '' > "${fixture_root}/empty"
print -r -- "${header}" > "${fixture_root}/header-only"
{
  print -r -- "${header}"
  print -r -- '2026-10-15 12:00:00.123456+0200 0x123 Default 0x0 123 0 DNIeToken: milestone.extension.loaded'
} > "${fixture_root}/safe-event"
{
  print -r -- "${header}"
  print -r -- '2026-10-15 12:00:00.123456+0200 0x123 Default 0x0 123 0 DNIeToken: pin_length=redacted'
} > "${fixture_root}/forbidden-event"
/bin/chmod 600 "${fixture_root}"/*

run_case() {
  local fixture="$1" query_status="$2" output="$3" expected_status="$4" rc
  if DNIE_SECRET_LOG_TEST_MODE=true \
      DNIE_SECRET_LOG_TEST_INPUT="${fixture_root}/${fixture}" \
      DNIE_SECRET_LOG_TEST_QUERY_STATUS="${query_status}" \
      "${scanner}" 20m > "${output}" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  [[ "${rc}" -eq "${expected_status}" ]]
}

before_temps="$(find /private/tmp -maxdepth 1 -name 'dnie-provider-log-scan.*' -print | /usr/bin/sort)"
run_case empty 0 "${fixture_root}/empty.out" 3
/usr/bin/grep -Fxq 'provider_log_event_count=0' "${fixture_root}/empty.out"
/usr/bin/grep -Fxq 'secret_log_scan=inconclusive' "${fixture_root}/empty.out"
run_case header-only 0 "${fixture_root}/header-only.out" 3
/usr/bin/grep -Fxq 'provider_log_line_count=1' "${fixture_root}/header-only.out"
/usr/bin/grep -Fxq 'provider_log_event_count=0' "${fixture_root}/header-only.out"
run_case safe-event 0 "${fixture_root}/safe-event.out" 0
/usr/bin/grep -Fxq 'provider_log_event_count=1' "${fixture_root}/safe-event.out"
/usr/bin/grep -Fxq 'provider_log_scope=synthetic_fixture' "${fixture_root}/safe-event.out"
/usr/bin/grep -Fxq 'secret_log_scan=pass' "${fixture_root}/safe-event.out"
run_case forbidden-event 0 "${fixture_root}/forbidden-event.out" 1
/usr/bin/grep -Fxq 'Provider log scan found a forbidden value class.' "${fixture_root}/forbidden-event.out"
if /usr/bin/grep -Fq 'pin_length=redacted' "${fixture_root}/forbidden-event.out"; then
  print -u2 'forbidden_match_was_printed=true'
  exit 11
fi
run_case safe-event 23 "${fixture_root}/query-failure.out" 65
/usr/bin/grep -Fxq 'Provider log query failed.' "${fixture_root}/query-failure.out"
if DNIE_SECRET_LOG_TEST_INPUT="${fixture_root}/safe-event" \
    "${scanner}" 20m > "${fixture_root}/ungated-test-control.out" 2>&1; then
  exit 13
else
  rc=$?
fi
[[ "${rc}" -eq 64 ]]
/usr/bin/grep -Fxq 'Provider log test controls require explicit test mode.' "${fixture_root}/ungated-test-control.out"
if DNIE_SECRET_LOG_TEST_MODE=inherited-invalid \
    "${scanner}" 20m > "${fixture_root}/invalid-test-mode.out" 2>&1; then
  exit 14
else
  rc=$?
fi
[[ "${rc}" -eq 64 ]]
/usr/bin/grep -Fxq 'Invalid provider log test mode.' "${fixture_root}/invalid-test-mode.out"
after_temps="$(find /private/tmp -maxdepth 1 -name 'dnie-provider-log-scan.*' -print | /usr/bin/sort)"
[[ "${before_temps}" == "${after_temps}" ]]

# Test controls must not influence the ordinary execution path.
/usr/bin/grep -Fq 'DNIE_SECRET_LOG_TEST_MODE' "${scanner}"
/usr/bin/grep -Fq '/usr/bin/log show' "${scanner}"
if /usr/bin/grep -Eq '(^|[[:space:]])(eval|source)[[:space:]]' "${scanner}"; then
  print -u2 'arbitrary_command_seam=true'
  exit 12
fi

trap - EXIT HUP INT TERM
cleanup
print 'scan_secret_logs_synthetic=true'
print 'scan_secret_logs_temp_cleanup=true'
