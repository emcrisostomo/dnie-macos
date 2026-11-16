#!/bin/zsh
set -euo pipefail

script_dir="${0:A:h}"
root_helper="${script_dir}/pilot-lifecycle-root.sh"
inspector="${script_dir}/inspect-pilot-artifact.sh"
typeset -a fixture_roots
cleanup() {
  local root
  for root in "${fixture_roots[@]}"; do
    [[ "${root}" == /private/tmp/dnie-pilot-lifecycle-test.* ]] && /bin/rm -rf -- "${root}"
  done
  return 0
}
trap 'cleanup || true' EXIT INT TERM

rollback_only=0
case "${1:-}" in
  '') ;;
  --rollback-arming-only) rollback_only=1 ;;
  *) print -u2 -- "usage: ${0:t} [--rollback-arming-only]"; exit 64 ;;
esac
(( $# <= 1 )) || { print -u2 -- "usage: ${0:t} [--rollback-arming-only]"; exit 64; }

old_hash=0123456789abcdef0123456789abcdef01234567
old_extension_hash=89abcdef0123456789abcdef0123456789abcdef
new_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
new_extension_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

make_app() {
  local app="$1" hash="$2" version="$3" build="$4" extension_hash="$5"
  /bin/mkdir -p "${app}/Contents/Resources" "${app}/Contents/MacOS" \
    "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS" \
    "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets"
  print '#!/bin/zsh' > "${app}/Contents/MacOS/DNIeTokenHost"
  print '#!/bin/zsh' > "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension"
  /bin/chmod 755 "${app}/Contents/MacOS/DNIeTokenHost" \
    "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/MacOS/DNIeTokenExtension"
  {
    print 'host_id=org.dniemacos.dnietoken'
    print 'extension_id=org.dniemacos.dnietoken.tokenextension'
    print "host_version=${version}"
    print "host_build=${build}"
    print "extension_version=${version}"
    print "extension_build=${build}"
    print 'extension_point=com.apple.ctk-tokens'
    print 'token_type=smartcard'
    print 'aid=A000000063504B43532D3135'
    print 'class_id=org.dniemacos.dnietoken.token'
    print 'driver_class=DNIeTokenExtension.TokenDriver'
    print 'host_sandbox_entitlement=absent'
    print 'host_smartcard_entitlement=absent'
    print 'host_keychain_groups=absent'
    print 'extension_sandbox_entitlement=true'
    print 'extension_smartcard_entitlement=true'
    print 'extension_keychain_groups=absent'
    print 'credential_asset_count=1'
    print "host_cdhash=${hash}"
    print "extension_cdhash=${extension_hash}"
    print "cdhash=${hash}"
    print 'team_pairing=pass'
    print 'host_team=TEAM000001'
    print 'extension_team=TEAM000001'
  } > "${app}/Contents/Resources/pilot-artifact-metadata"
  print '{"ordered_field_names":["alpha","beta"],"fields_hex":{"alpha":"00ff","beta":"010203"}}' \
    > "${app}/Contents/Resources/generation2.synthetic.json"
  print fixture > "${app}/Contents/PlugIns/DNIeTokenExtension.appex/Contents/Resources/DNIeCore_DNIeCore.bundle/Contents/Resources/Assets/generation2.json"
  /bin/chmod 755 "${app}"
}

new_fixture() {
  fixture_root="$(mktemp -d /private/tmp/dnie-pilot-lifecycle-test.XXXXXX)"
  fixture_roots+=("${fixture_root}")
  /bin/mkdir -p "${fixture_root}/Applications" "${fixture_root}/Library/Application Support" "${fixture_root}/candidate"
  destination="${fixture_root}/Applications/DNIeTokenHost.app"
  candidate="${fixture_root}/candidate/DNIeTokenHost.app"
  state_root="${fixture_root}/Library/Application Support/org.dniemacos.dnietoken/pilot-lifecycle"
  state_file="${state_root}/installed.state"
  lock="${state_root}/operation.lock"
  transaction="${state_root}/transactions/upgrade001"
  make_app "${destination}" "${old_hash}" 0.1.0 1 "${old_extension_hash}"
  make_app "${candidate}" "${new_hash}" 0.1.1 2 "${new_extension_hash}"
  /bin/mkdir -p "${state_root}/transactions"
  /bin/chmod 700 "${state_root}" "${state_root}/transactions"
  { print 'host_id=org.dniemacos.dnietoken'; print 'extension_id=org.dniemacos.dnietoken.tokenextension';
    print "cdhash=${old_hash}"; print 'phase=committed'; print 'token=installed01'; } > "${state_file}"
  /bin/chmod 600 "${state_file}"
  common_env=(DNIE_LIFECYCLE_TEST_MODE=1 DNIE_LIFECYCLE_TEST_ROOT="${fixture_root}"
    DNIE_LIFECYCLE_TEST_OLD_ACTIVITY=inactive DNIE_LIFECYCLE_TEST_CANDIDATE_ACTIVITY=inactive
    DNIE_LIFECYCLE_TEST_STAGING_ACTIVITY=inactive)
}

prepare() {
  env "${common_env[@]}" "${root_helper}" prepare-upgrade-fixture upgrade001 "${candidate}"
}
probe() {
  env "${common_env[@]}" "${root_helper}" probe-upgrade-fixture upgrade001 "${candidate}"
}
stage() {
  env "${common_env[@]}" "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}"
}
probe_staged() {
  env "${common_env[@]}" "${root_helper}" probe-staged-upgrade-fixture upgrade001 "${candidate}"
}
retain_old() {
  env "${common_env[@]}" "${root_helper}" retain-old-upgrade-fixture upgrade001 "${candidate}"
}
probe_old_retained() {
  env "${common_env[@]}" "${root_helper}" probe-old-retained-upgrade-fixture upgrade001 "${candidate}"
}
arm_rollback() {
  env "${common_env[@]}" "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
}
probe_armed_rollback() {
  env "${common_env[@]}" "${root_helper}" probe-armed-upgrade-rollback-fixture upgrade001 "${candidate}"
}
must_fail() {
  local label="$1"; shift
  if "$@" >"${fixture_root}/${label}.out" 2>&1; then
    print -u2 -- "unexpected_success=${label}"
    exit 1
  fi
}
expect_error() {
  local label="$1" pattern="$2"
  /usr/bin/grep -Eq -- "${pattern}" "${fixture_root}/${label}.out" || {
    print -u2 -- "unexpected_error_class=${label}"
    exit 1
  }
}

# The positive fixture pins exact old bytes and both artifact tuples while retaining the lock.
if (( rollback_only == 0 )); then
new_fixture
state_before="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
destination_inode="$(/usr/bin/stat -f %i "${destination}")"
candidate_inode="$(/usr/bin/stat -f %i "${candidate}")"
prepare_output="$(prepare)"
/usr/bin/grep -q '^upgrade_preparation=fixture-only-pass$' <<< "${prepare_output}"
journal="${transaction}/upgrade.journal"
[[ -f "${journal}" && ! -L "${journal}" && "$(/usr/bin/stat -f %Lp "${journal}")" == 600 &&
   -f "${transaction}/old-installed.state" && "$(/usr/bin/stat -f %Lp "${transaction}/old-installed.state")" == 600 &&
   -d "${lock}" && ! -e "${transaction}/transaction.state" ]]
/usr/bin/cmp -s "${state_file}" "${transaction}/old-installed.state"
[[ "$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')" == "${state_before}" &&
   "$(/usr/bin/stat -f %i "${destination}")" == "${destination_inode}" &&
   "$(/usr/bin/stat -f %i "${candidate}")" == "${candidate_inode}" ]]
/usr/bin/grep -qx 'phase=copying' "${journal}"
/usr/bin/grep -qx 'old_host_marketing_version=0.1.0' "${journal}"
/usr/bin/grep -qx 'new_host_marketing_version=0.1.1' "${journal}"
if /usr/bin/grep -Eqi 'authority|apple development:|teamidentifier|account|TEAM000001' "${journal}"; then
  print -u2 'private_team_or_signer_label_leaked=true'
  exit 1
fi
probe_output="$(probe)"
/usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"

# Ordinary and legacy recovery commands cannot adopt, mutate, or release the retained upgrade lock.
lock_before="$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')"
journal_before="$(/usr/bin/shasum -a 256 "${journal}" | /usr/bin/awk '{print $1}')"
must_fail legacy-uninstall env "${common_env[@]}" "${root_helper}" uninstall legacyun1 "${old_hash}"
expect_error legacy-uninstall 'Another lifecycle transaction or retained recovery lock exists'
must_fail legacy-recover env "${common_env[@]}" "${root_helper}" recover-interrupted upgrade001 "${old_hash}"
expect_error legacy-recover 'retained transaction state is unsafe'
must_fail legacy-rollback env "${common_env[@]}" "${root_helper}" rollback-uninstall upgrade001 "${old_hash}"
expect_error legacy-rollback 'retained transaction state is unsafe'
[[ "$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')" == "${state_before}" &&
   "$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')" == "${lock_before}" &&
   "$(/usr/bin/shasum -a 256 "${journal}" | /usr/bin/awk '{print $1}')" == "${journal_before}" &&
   "$(/usr/bin/stat -f %i "${destination}")" == "${destination_inode}" ]]
must_fail foreign-token env "${common_env[@]}" "${root_helper}" probe-upgrade-fixture foreign01 "${candidate}"
expect_error foreign-token 'retained upgrade lock is foreign or malformed'

# Strict journal/state/tuple parsing rejects changed bytes, malformed fields, and unsafe modes.
/bin/cp "${journal}" "${fixture_root}/journal.backup"
for mutation in unknown duplicate bad-phase bad-version bad-hash bad-token no-newline; do
  /bin/cp "${fixture_root}/journal.backup" "${journal}"
  /bin/chmod 600 "${journal}"
  probe_output="$(probe)"
  /usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"
  case "${mutation}" in
    unknown) print 'unexpected=value' >> "${journal}" ;;
    duplicate) print 'phase=copying' >> "${journal}" ;;
    bad-phase) /usr/bin/sed -i '' 's/^phase=copying$/phase=prepared/' "${journal}" ;;
    bad-version) /usr/bin/sed -i '' 's/^new_host_marketing_version=0.1.1$/new_host_marketing_version=0.1.2/' "${journal}" ;;
    bad-hash) /usr/bin/sed -i '' 's/^new_host_cdhash=.*/new_host_cdhash=bad/' "${journal}" ;;
    bad-token) /usr/bin/sed -i '' 's/^token=upgrade001$/token=bad!/' "${journal}" ;;
    no-newline) /usr/bin/perl -pi -e 'chomp if eof' "${journal}" ;;
  esac
  must_fail "journal-${mutation}" probe
  case "${mutation}" in
    unknown|duplicate|no-newline) expect_error "journal-${mutation}" 'missing, duplicate, unknown, or reordered field' ;;
    bad-phase|bad-token) expect_error "journal-${mutation}" 'invalid fixed field' ;;
    bad-version) expect_error "journal-${mutation}" 'inspected artifact pair changed after preparation' ;;
    bad-hash) expect_error "journal-${mutation}" 'journaled ownership and inspection tuples are inconsistent|inspected artifact pair changed after preparation' ;;
  esac
done
/bin/cp "${fixture_root}/journal.backup" "${journal}"
/bin/chmod 600 "${journal}"
probe_output="$(probe)"
/usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"
/bin/chmod 644 "${journal}"
must_fail journal-mode probe
expect_error journal-mode 'retained upgrade journal topology is unsafe'
/bin/chmod 600 "${journal}"
probe_output="$(probe)"
/usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"

# State mutation replaces the pinned inode on macOS; use a fresh fixture for every later family.
/usr/bin/sed -i '' 's/^token=installed01$/token=changed001/' "${state_file}"
must_fail changed-state probe
expect_error changed-state 'committed ownership state no longer matches|saved upgrade fingerprint or inode claim changed'

new_fixture
prepare_output="$(prepare)"
/usr/bin/grep -q '^upgrade_preparation=fixture-only-pass$' <<< "${prepare_output}"
probe_output="$(probe)"
/usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"
/usr/bin/sed -i '' "s/^host_cdhash=${new_hash}$/host_cdhash=cccccccccccccccccccccccccccccccccccccccc/; s/^cdhash=${new_hash}$/cdhash=cccccccccccccccccccccccccccccccccccccccc/" \
  "${candidate}/Contents/Resources/pilot-artifact-metadata"
must_fail changed-candidate probe
expect_error changed-candidate 'inspected artifact pair changed after preparation'

new_fixture
prepare_output="$(prepare)"
/usr/bin/grep -q '^upgrade_preparation=fixture-only-pass$' <<< "${prepare_output}"
probe_output="$(probe)"
/usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"
/usr/bin/sed -i '' 's/^token=installed01$/token=savedbad01/' "${transaction}/old-installed.state"
must_fail changed-saved-state probe
expect_error changed-saved-state 'saved upgrade fingerprint or inode claim changed'

# Retained lock parsing rejects live, missing, duplicate, unknown, and unsafe owner topology.
new_fixture
prepare_output="$(prepare)"
/usr/bin/grep -q '^upgrade_preparation=fixture-only-pass$' <<< "${prepare_output}"
probe_output="$(probe)"
/usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"
/bin/cp "${lock}/owner" "${fixture_root}/owner.backup"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/owner"
must_fail live-owner probe
expect_error live-owner 'retained upgrade lock owner is still running'
for mutation in duplicate unknown mode ownerless; do
  /bin/cp "${fixture_root}/owner.backup" "${lock}/owner"
  /bin/chmod 600 "${lock}/owner"
  probe_output="$(probe)"
  /usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"
  case "${mutation}" in
    duplicate) print 'token=upgrade001' >> "${lock}/owner" ;;
    unknown) print 'extra=value' >> "${lock}/owner" ;;
    mode) /bin/chmod 644 "${lock}/owner" ;;
    ownerless) /bin/rm -f -- "${lock}/owner" ;;
  esac
  must_fail "lock-${mutation}" probe
  case "${mutation}" in
    duplicate|unknown) expect_error "lock-${mutation}" 'missing, duplicated, unknown, or ownerless' ;;
    mode|ownerless) expect_error "lock-${mutation}" 'retained upgrade lock topology is unsafe' ;;
  esac
done

# Canonical/link/collision failures stop before preparation can change the app or committed state.
new_fixture
state_before="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
/bin/mkdir "${transaction}"
must_fail transaction-collision prepare
[[ ! -e "${lock}" && "$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')" == "${state_before}" ]]
/bin/rmdir "${transaction}"
/bin/mv "${candidate}" "${candidate}.real"
/bin/ln -s "${candidate}.real" "${candidate}"
must_fail candidate-link prepare
/bin/rm "${candidate}"
/bin/mv "${candidate}.real" "${candidate}"
/bin/ln "${candidate}/Contents/Resources/pilot-artifact-metadata" "${candidate}/Contents/Resources/metadata.alias"
must_fail candidate-hardlink prepare
/bin/rm "${candidate}/Contents/Resources/metadata.alias"
must_fail same-path env "${common_env[@]}" "${root_helper}" prepare-upgrade-fixture upgrade001 "${destination}"
[[ ! -e "${lock}" && "$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')" == "${state_before}" ]]

# Both interruption hooks retain a phase-attributable lock; post-journal state is probeable.
new_fixture
must_fail interrupt-before env "${common_env[@]}" DNIE_LIFECYCLE_TEST_INTERRUPT_AT=upgrade-prepare-before-journal \
  "${root_helper}" prepare-upgrade-fixture upgrade001 "${candidate}"
[[ -d "${lock}" && ! -e "${transaction}/upgrade.journal" ]]
/usr/bin/grep -q '^phase=copying$' "${transaction}"/upgrade.journal.new.*
must_fail interrupt-before-uninstall env "${common_env[@]}" "${root_helper}" uninstall interrupt1 "${old_hash}"

new_fixture
must_fail interrupt-after env "${common_env[@]}" DNIE_LIFECYCLE_TEST_INTERRUPT_AT=upgrade-prepare-after-journal \
  "${root_helper}" prepare-upgrade-fixture upgrade001 "${candidate}"
[[ -d "${lock}" && -f "${transaction}/upgrade.journal" ]]
probe_output="$(probe)"
/usr/bin/grep -q '^upgrade_preparation_probe=fixture-only-pass$' <<< "${probe_output}"

# Candidate staging is an inode-bound copy that leaves the installed app, state, and saved bytes untouched.
new_fixture
state_before="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
destination_inode="$(/usr/bin/stat -f %i "${destination}")"
candidate_inode="$(/usr/bin/stat -f %i "${candidate}")"
prepare_output="$(prepare)"
/usr/bin/grep -q '^upgrade_preparation=fixture-only-pass$' <<< "${prepare_output}"
stage_output="$(stage)"
/usr/bin/grep -q '^upgrade_staging=fixture-only-pass$' <<< "${stage_output}"
staging="${transaction}/DNIeTokenHost.app.staging"
staging_inode="$(/usr/bin/stat -f %i "${staging}")"
[[ -d "${staging}" && ! -L "${staging}" && "${staging_inode}" == <-> &&
   "$(/usr/bin/stat -f %i "${destination}")" == "${destination_inode}" &&
   "$(/usr/bin/stat -f %i "${candidate}")" == "${candidate_inode}" &&
   "$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')" == "${state_before}" ]]
/usr/bin/cmp -s "${state_file}" "${transaction}/old-installed.state"
/usr/bin/grep -qx "staging_inode=${staging_inode}" "${transaction}/upgrade.journal"
/usr/bin/grep -qx 'staging_verification=verified' "${transaction}/upgrade.journal"
/usr/bin/grep -qx 'operation=upgrade-copying-verified' "${lock}/owner"
probe_output="$(probe_staged)"
/usr/bin/grep -q '^upgrade_staging_probe=fixture-only-pass$' <<< "${probe_output}"
must_fail no-preparation-probe probe
expect_error no-preparation-probe 'retained upgrade lock is foreign or malformed'
must_fail no-staging-retry stage
expect_error no-staging-retry 'retained upgrade lock is foreign or malformed'
[[ ! -e "${transaction}/DNIeTokenHost.app.failed-install" && ! -e "${transaction}/transaction.state" ]]

# Source, staged bytes, staging inode, and verified tuple changes fail closed without touching the old owner.
new_fixture
prepare_output="$(prepare)"
/usr/bin/grep -q '^upgrade_preparation=fixture-only-pass$' <<< "${prepare_output}"
/usr/bin/sed -i '' "s/^host_cdhash=${new_hash}$/host_cdhash=cccccccccccccccccccccccccccccccccccccccc/; s/^cdhash=${new_hash}$/cdhash=cccccccccccccccccccccccccccccccccccccccc/" \
  "${candidate}/Contents/Resources/pilot-artifact-metadata"
must_fail source-mutated-before-copy stage
expect_error source-mutated-before-copy 'inspected artifact pair changed after preparation'
[[ ! -e "${transaction}/DNIeTokenHost.app.staging" && ! -e "${transaction}/DNIeTokenHost.app.failed-install" ]]

new_fixture
prepare_output="$(prepare)"; stage_output="$(stage)"
/usr/bin/grep -q '^upgrade_staging=fixture-only-pass$' <<< "${stage_output}"
staging="${transaction}/DNIeTokenHost.app.staging"
/usr/bin/sed -i '' "s/^host_cdhash=${new_hash}$/host_cdhash=cccccccccccccccccccccccccccccccccccccccc/; s/^cdhash=${new_hash}$/cdhash=cccccccccccccccccccccccccccccccccccccccc/" \
  "${candidate}/Contents/Resources/pilot-artifact-metadata"
must_fail source-mutated-after-copy probe_staged
expect_error source-mutated-after-copy 'inspected artifact pair changed after preparation'

new_fixture
prepare_output="$(prepare)"; stage_output="$(stage)"
staging="${transaction}/DNIeTokenHost.app.staging"
/usr/bin/sed -i '' "s/^host_cdhash=${new_hash}$/host_cdhash=dddddddddddddddddddddddddddddddddddddddd/; s/^cdhash=${new_hash}$/cdhash=dddddddddddddddddddddddddddddddddddddddd/" \
  "${staging}/Contents/Resources/pilot-artifact-metadata"
must_fail staged-tuple-mutated probe_staged
expect_error staged-tuple-mutated 'inspected artifact pair changed after preparation'

new_fixture
prepare_output="$(prepare)"; stage_output="$(stage)"
staging="${transaction}/DNIeTokenHost.app.staging"
/bin/mv "${staging}" "${staging}.replaced"
/bin/mkdir "${staging}"
must_fail staging-inode-replaced probe_staged
expect_error staging-inode-replaced 'staging inode or verification substate changed|published app or exact credential asset is missing'

# Staging target collisions and links are rejected while the exact prepared reservation remains retained.
new_fixture
prepare_output="$(prepare)"
/bin/mkdir "${transaction}/DNIeTokenHost.app.staging"
must_fail staging-collision stage
expect_error staging-collision 'staging path is not exclusively claimable|prepared upgrade staging path is not absent'
/usr/bin/grep -qx 'operation=upgrade-copying-prepared' "${lock}/owner"
[[ ! -e "${transaction}/DNIeTokenHost.app.failed-install" ]]

new_fixture
prepare_output="$(prepare)"
/bin/ln -s "${candidate}" "${transaction}/DNIeTokenHost.app.staging"
must_fail staging-link stage
expect_error staging-link 'staging path is not exclusively claimable|prepared upgrade staging path is not absent'
/usr/bin/grep -qx 'operation=upgrade-copying-prepared' "${lock}/owner"

# Foreign or live preparation reservations cannot be adopted for staging.
new_fixture
prepare_output="$(prepare)"
/usr/bin/sed -i '' 's/^operation=upgrade-copying-prepared$/operation=foreign-copy/' "${lock}/owner"
must_fail staging-foreign-lock stage
expect_error staging-foreign-lock 'retained upgrade lock is foreign or malformed'

new_fixture
prepare_output="$(prepare)"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/owner"
must_fail staging-live-lock stage
expect_error staging-live-lock 'retained upgrade lock owner is still running'

new_fixture
prepare_output="$(prepare)"
/bin/mkdir -m 700 "${lock}/upgrade-adoption.claim"
print sentinel > "${lock}/upgrade-adoption.claim/keep"
must_fail staging-claim-collision stage
expect_error staging-claim-collision 'upgrade staging adoption claim already exists'
/usr/bin/grep -qx sentinel "${lock}/upgrade-adoption.claim/keep"
/usr/bin/grep -qx 'operation=upgrade-copying-prepared' "${lock}/owner"

new_fixture
prepare_output="$(prepare)"
sentinel="${transaction}/upgrade-pair.source-before.424242"
print 'preserve-this-collision' > "${sentinel}"
must_fail staging-temp-collision env "${common_env[@]}" DNIE_LIFECYCLE_TEST_TEMP_SUFFIX=424242 \
  "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}"
expect_error staging-temp-collision 'source inspection temporary collided'
/usr/bin/grep -qx 'preserve-this-collision' "${sentinel}"
/usr/bin/grep -qx 'operation=upgrade-copying-prepared' "${lock}/owner"

new_fixture
prepare_output="$(prepare)"
sentinel="${transaction}/upgrade-pair.source-before.424243"
dangling_target="${fixture_root}/must-not-be-created"
/bin/ln -s "${dangling_target}" "${sentinel}"
must_fail staging-temp-dangling-link env "${common_env[@]}" DNIE_LIFECYCLE_TEST_TEMP_SUFFIX=424243 \
  "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}"
expect_error staging-temp-dangling-link 'source inspection temporary collided'
[[ -L "${sentinel}" && "$(/usr/bin/readlink "${sentinel}")" == "${dangling_target}" && ! -e "${dangling_target}" ]]
/usr/bin/grep -qx 'operation=upgrade-copying-prepared' "${lock}/owner"

new_fixture
prepare_output="$(prepare)"
env "${common_env[@]}" "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}" >"${fixture_root}/concurrent-a.out" 2>&1 &
concurrent_a=$!
env "${common_env[@]}" "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}" >"${fixture_root}/concurrent-b.out" 2>&1 &
concurrent_b=$!
if wait "${concurrent_a}"; then concurrent_a_status=0; else concurrent_a_status=$?; fi
if wait "${concurrent_b}"; then concurrent_b_status=0; else concurrent_b_status=$?; fi
if [[ ( "${concurrent_a_status}" == 0 && "${concurrent_b_status}" == 0 ) ||
      ( "${concurrent_a_status}" != 0 && "${concurrent_b_status}" != 0 ) ]]; then
  print -u2 'concurrent_staging_did_not_have_exactly_one_winner=true'
  exit 1
fi
if [[ "${concurrent_a_status}" == 0 ]]; then concurrent_failure="${fixture_root}/concurrent-b.out"
else concurrent_failure="${fixture_root}/concurrent-a.out"; fi
/usr/bin/grep -Eq 'adoption claim already exists|retained upgrade lock is foreign or malformed|retained upgrade lock owner is still running|prepared upgrade staging path is not absent' "${concurrent_failure}"
probe_output="$(probe_staged)"
/usr/bin/grep -q '^upgrade_staging_probe=fixture-only-pass$' <<< "${probe_output}"

# Signals and injected failures preserve the exact copying substate and never invoke legacy publication recovery.
for boundary in before-copy during-copy; do
  new_fixture
  prepare_output="$(prepare)"
  hook="upgrade-stage-${boundary}"
  must_fail "term-${boundary}" env "${common_env[@]}" DNIE_LIFECYCLE_TEST_INTERRUPT_AT="${hook}" \
    "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}"
  /usr/bin/grep -qx 'staging_verification=copying-unverified' "${transaction}/upgrade.journal"
  /usr/bin/grep -qx 'operation=upgrade-copying-staging' "${lock}/owner"
  [[ -d "${transaction}/DNIeTokenHost.app.staging" && ! -e "${transaction}/DNIeTokenHost.app.failed-install" &&
     ! -e "${transaction}/transaction.state" ]]
  must_fail "retry-${boundary}" stage
  expect_error "retry-${boundary}" 'retained upgrade lock is foreign or malformed'
done

new_fixture
prepare_output="$(prepare)"
must_fail term-after-copy env "${common_env[@]}" DNIE_LIFECYCLE_TEST_INTERRUPT_AT=upgrade-stage-after-copy \
  "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}"
/usr/bin/grep -qx 'staging_verification=verified' "${transaction}/upgrade.journal"
/usr/bin/grep -qx 'operation=upgrade-copying-verified' "${lock}/owner"
probe_output="$(probe_staged)"
/usr/bin/grep -q '^upgrade_staging_probe=fixture-only-pass$' <<< "${probe_output}"
[[ ! -e "${transaction}/DNIeTokenHost.app.failed-install" && ! -e "${transaction}/transaction.state" ]]

for boundary in before-copy during-copy after-copy; do
  new_fixture
  prepare_output="$(prepare)"
  hook="upgrade-stage-${boundary}"
  must_fail "failure-${boundary}" env "${common_env[@]}" DNIE_LIFECYCLE_TEST_FAIL_AT="${hook}" \
    "${root_helper}" stage-upgrade-fixture upgrade001 "${candidate}"
  [[ ! -e "${transaction}/DNIeTokenHost.app.failed-install" && ! -e "${transaction}/transaction.state" ]]
  if [[ "${boundary}" == after-copy ]]; then
    /usr/bin/grep -qx 'staging_verification=verified' "${transaction}/upgrade.journal"
    probe_output="$(probe_staged)"
    /usr/bin/grep -q '^upgrade_staging_probe=fixture-only-pass$' <<< "${probe_output}"
  else
    /usr/bin/grep -qx 'staging_verification=copying-unverified' "${transaction}/upgrade.journal"
    must_fail "failure-retry-${boundary}" stage
    expect_error "failure-retry-${boundary}" 'retained upgrade lock is foreign or malformed'
  fi
done

# Verified staging transitions to one exact retained-old archive without publishing the candidate.
new_fixture
prepare_output="$(prepare)"; stage_output="$(stage)"
state_before="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
saved_before="$(/usr/bin/shasum -a 256 "${transaction}/old-installed.state" | /usr/bin/awk '{print $1}')"
old_inode="$(/usr/bin/stat -f %i "${destination}")"
candidate_inode="$(/usr/bin/stat -f %i "${candidate}")"
staging_inode="$(/usr/bin/stat -f %i "${transaction}/DNIeTokenHost.app.staging")"
retain_output="$(retain_old)"
/usr/bin/grep -q '^upgrade_old_retention=fixture-only-pass$' <<< "${retain_output}"
archive="${transaction}/DNIeTokenHost.app.old"
[[ -d "${archive}" && ! -L "${archive}" && ! -e "${destination}" && ! -L "${destination}" &&
   "$(/usr/bin/stat -f %i "${archive}")" == "${old_inode}" &&
   "$(/usr/bin/stat -f %i "${candidate}")" == "${candidate_inode}" &&
   "$(/usr/bin/stat -f %i "${transaction}/DNIeTokenHost.app.staging")" == "${staging_inode}" &&
   "$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')" == "${state_before}" &&
   "$(/usr/bin/shasum -a 256 "${transaction}/old-installed.state" | /usr/bin/awk '{print $1}')" == "${saved_before}" ]]
/usr/bin/grep -qx 'phase=old-retained' "${transaction}/upgrade.journal"
/usr/bin/grep -qx 'operation=upgrade-old-retained' "${lock}/owner"
[[ -d "${lock}/upgrade-old-retention.claim" && ! -L "${lock}/upgrade-old-retention.claim" &&
   ! -e "${transaction}/DNIeTokenHost.app.failed-install" && ! -e "${transaction}/transaction.state" ]]
probe_output="$(probe_old_retained)"
/usr/bin/grep -q '^upgrade_old_retention_probe=fixture-only-pass$' <<< "${probe_output}"
must_fail old-retained-legacy-recover env "${common_env[@]}" "${root_helper}" recover-interrupted upgrade001 "${old_hash}"
expect_error old-retained-legacy-recover 'retained transaction state is unsafe'
[[ -d "${archive}" && ! -e "${destination}" && ! -e "${transaction}/DNIeTokenHost.app.failed-install" ]]

# The fixture activity model is closed: active and unknown artifacts stop before a transition claim.
for activity in OLD CANDIDATE STAGING; do
  for value in active unknown; do
    new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
    old_inode="$(/usr/bin/stat -f %i "${destination}")"
    must_fail "activity-${activity:l}-${value}" env "${common_env[@]}" \
      "DNIE_LIFECYCLE_TEST_${activity}_ACTIVITY=${value}" \
      "${root_helper}" retain-old-upgrade-fixture upgrade001 "${candidate}"
    expect_error "activity-${activity:l}-${value}" 'activity is active or unknown'
    [[ "$(/usr/bin/stat -f %i "${destination}")" == "${old_inode}" &&
       ! -e "${transaction}/DNIeTokenHost.app.old" && ! -e "${lock}/upgrade-old-retention.claim" ]]
  done
done

# Archive, destination, and transition-claim collisions preserve the verified-staging predecessor.
new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/bin/mkdir "${transaction}/DNIeTokenHost.app.old"
must_fail old-archive-collision retain_old
expect_error old-archive-collision 'prepared upgrade paths collide|collision-free archive'
/usr/bin/grep -qx 'operation=upgrade-copying-verified' "${lock}/owner"

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/bin/mv "${destination}" "${destination}.real"; /bin/ln -s "${destination}.real" "${destination}"
must_fail old-destination-link retain_old
expect_error old-destination-link 'published app or exact credential asset is missing|saved upgrade fingerprint or inode claim changed'
[[ -L "${destination}" && ! -e "${transaction}/DNIeTokenHost.app.old" ]]

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/bin/chmod 700 "${destination}"
must_fail old-destination-mode retain_old
expect_error old-destination-mode 'exact old destination cannot be retained'
[[ -d "${destination}" && ! -e "${transaction}/DNIeTokenHost.app.old" ]]

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/bin/mkdir -m 700 "${lock}/upgrade-old-retention.claim"; print sentinel > "${lock}/upgrade-old-retention.claim/keep"
must_fail old-claim-collision retain_old
expect_error old-claim-collision 'old-retention transition claim already exists'
/usr/bin/grep -qx sentinel "${lock}/upgrade-old-retention.claim/keep"
/usr/bin/grep -qx 'operation=upgrade-copying-verified' "${lock}/owner"

# Foreign, live, ownerless, altered, and incomplete staging reservations are never adopted.
new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/usr/bin/sed -i '' 's/^operation=upgrade-copying-verified$/operation=foreign-retention/' "${lock}/owner"
must_fail old-foreign-owner retain_old
expect_error old-foreign-owner 'retained upgrade lock is foreign or malformed'

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/owner"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/upgrade-adoption.claim/owner"
must_fail old-live-owner retain_old
expect_error old-live-owner 'retained upgrade lock owner is still running'

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"; /bin/rm "${lock}/owner"
must_fail old-ownerless retain_old
expect_error old-ownerless 'retained upgrade lock topology is unsafe'

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/bin/chmod 644 "${lock}/upgrade-adoption.claim/owner"
must_fail old-predecessor-claim-mode retain_old
expect_error old-predecessor-claim-mode 'upgrade staging adoption claim is unsafe|predecessor staging claim topology is unsafe'
[[ -d "${destination}" && ! -e "${lock}/upgrade-old-retention.claim" ]]

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/usr/bin/sed -i '' 's/^phase=copying$/phase=old-retained/' "${transaction}/upgrade.journal"
must_fail old-wrong-entry-phase retain_old
expect_error old-wrong-entry-phase 'exact copying-phase journal'
[[ ! -e "${lock}/upgrade-old-retention.claim" &&
   -z "$(/usr/bin/find "${transaction}" -maxdepth 1 -name 'upgrade-pair.old-retain-*' -print -quit)" ]]

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/usr/bin/sed -i '' "s/^host_cdhash=${new_hash}$/host_cdhash=cccccccccccccccccccccccccccccccccccccccc/; s/^cdhash=${new_hash}$/cdhash=cccccccccccccccccccccccccccccccccccccccc/" \
  "${transaction}/DNIeTokenHost.app.staging/Contents/Resources/pilot-artifact-metadata"
must_fail old-staging-altered retain_old
expect_error old-staging-altered 'inspected artifact pair changed after preparation'

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/bin/mv "${transaction}/DNIeTokenHost.app.staging" "${transaction}/DNIeTokenHost.app.staging.replaced"
/bin/mkdir "${transaction}/DNIeTokenHost.app.staging"
must_fail old-staging-incomplete retain_old
expect_error old-staging-incomplete 'published app or exact credential asset is missing|staging inode or verification substate changed'

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
/usr/bin/sed -i '' 's/^token=installed01$/token=changed001/' "${state_file}"
must_fail old-state-altered retain_old
expect_error old-state-altered 'committed ownership state no longer matches|saved upgrade fingerprint or inode claim changed'

# Before/after-move TERM and injected failures retain attributable STOP topologies with no legacy trap.
for kind in INTERRUPT FAIL; do
  for boundary in before-move after-move; do
    new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
    hook="upgrade-old-retention-${boundary}"
    must_fail "old-${kind:l}-${boundary}" env "${common_env[@]}" "DNIE_LIFECYCLE_TEST_${kind}_AT=${hook}" \
      "${root_helper}" retain-old-upgrade-fixture upgrade001 "${candidate}"
    /usr/bin/grep -qx 'operation=upgrade-old-retention-armed' "${lock}/owner"
    /usr/bin/grep -qx 'phase=copying' "${transaction}/upgrade.journal"
    [[ -d "${lock}/upgrade-old-retention.claim" && ! -e "${transaction}/DNIeTokenHost.app.failed-install" &&
       ! -e "${transaction}/transaction.state" ]]
    if [[ "${boundary}" == before-move ]]; then
      [[ -d "${destination}" && ! -e "${transaction}/DNIeTokenHost.app.old" ]]
    else
      [[ ! -e "${destination}" && -d "${transaction}/DNIeTokenHost.app.old" ]]
    fi
    must_fail "old-${kind:l}-${boundary}-retry" retain_old
    expect_error "old-${kind:l}-${boundary}-retry" 'retained upgrade lock is foreign or malformed'
    must_fail "old-${kind:l}-${boundary}-probe" probe_old_retained
    expect_error "old-${kind:l}-${boundary}-probe" 'old-retention claim is foreign|journal is not at the exact|owner is malformed'
  done
done

# Terminal probes require stale ownership and exact claim/journal topology before creating temporaries.
new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"; retain_output="$(retain_old)"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/owner"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" \
  "${lock}/upgrade-old-retention.claim/owner"
must_fail old-terminal-live-owner probe_old_retained
expect_error old-terminal-live-owner 'old-retention owner is still running'

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"; retain_output="$(retain_old)"
/bin/chmod 644 "${lock}/upgrade-adoption.claim/owner"
must_fail old-terminal-predecessor-mode probe_old_retained
expect_error old-terminal-predecessor-mode 'predecessor staging claim topology is unsafe'

new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"; retain_output="$(retain_old)"
/usr/bin/sed -i '' 's/^phase=old-retained$/phase=copying/' "${transaction}/upgrade.journal"
must_fail old-terminal-wrong-phase probe_old_retained
expect_error old-terminal-wrong-phase 'exact old-retained phase'
[[ -z "$(/usr/bin/find "${transaction}" -maxdepth 1 -name 'upgrade-pair.old-retained-*' -print -quit)" ]]
fi

# Recovery arming accepts exactly the four pre-publication joint topologies and mutates metadata only.
make_recovery_entry() {
  local topology="$1"
  new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
  case "${topology}" in
    copying-before-move)
      must_fail entry-before-move env "${common_env[@]}" \
        DNIE_LIFECYCLE_TEST_INTERRUPT_AT=upgrade-old-retention-before-move \
        "${root_helper}" retain-old-upgrade-fixture upgrade001 "${candidate}"
      ;;
    copying-after-move)
      must_fail entry-after-move env "${common_env[@]}" \
        DNIE_LIFECYCLE_TEST_INTERRUPT_AT=upgrade-old-retention-after-move \
        "${root_helper}" retain-old-upgrade-fixture upgrade001 "${candidate}"
      ;;
    old-retained-armed)
      must_fail entry-after-phase env "${common_env[@]}" \
        DNIE_LIFECYCLE_TEST_INTERRUPT_AT=upgrade-old-retention-after-phase \
        "${root_helper}" retain-old-upgrade-fixture upgrade001 "${candidate}"
      ;;
    old-retained-terminal) retain_output="$(retain_old)" ;;
    *) print -u2 -- "unknown_recovery_entry=${topology}"; exit 1 ;;
  esac
}

for topology in copying-before-move copying-after-move old-retained-armed old-retained-terminal; do
  make_recovery_entry "${topology}"
  journal="${transaction}/upgrade.journal"
  saved_inode="$(/usr/bin/stat -f %i "${transaction}/old-installed.state")"
  saved_hash="$(/usr/bin/shasum -a 256 "${transaction}/old-installed.state" | /usr/bin/awk '{print $1}')"
  candidate_inode="$(/usr/bin/stat -f %i "${candidate}")"
  staging_inode="$(/usr/bin/stat -f %i "${transaction}/DNIeTokenHost.app.staging")"
  old_path="${destination}"
  [[ "${topology}" == copying-before-move ]] || old_path="${transaction}/DNIeTokenHost.app.old"
  old_inode="$(/usr/bin/stat -f %i "${old_path}")"
  old_metadata_hash="$(/usr/bin/shasum -a 256 "${old_path}/Contents/Resources/pilot-artifact-metadata" | /usr/bin/awk '{print $1}')"
  candidate_metadata_hash="$(/usr/bin/shasum -a 256 "${candidate}/Contents/Resources/pilot-artifact-metadata" | /usr/bin/awk '{print $1}')"
  staging_metadata_hash="$(/usr/bin/shasum -a 256 "${transaction}/DNIeTokenHost.app.staging/Contents/Resources/pilot-artifact-metadata" | /usr/bin/awk '{print $1}')"
  arm_output="$(arm_rollback)"
  /usr/bin/grep -q '^upgrade_rollback_arming=fixture-only-pass$' <<< "${arm_output}"
  /usr/bin/grep -qx 'phase=rollback-armed' "${journal}"
  /usr/bin/grep -qx "rollback_predecessor_topology=${topology}" "${journal}"
  /usr/bin/grep -qx 'operation=upgrade-rollback-armed' "${lock}/owner"
  /usr/bin/grep -qx 'host_id=org.dniemacos.dnietoken' "${state_file}"
  /usr/bin/grep -qx 'extension_id=org.dniemacos.dnietoken.tokenextension' "${state_file}"
  /usr/bin/grep -qx "cdhash=${old_hash}" "${state_file}"
  /usr/bin/grep -qx 'phase=pending-upgrade-rollback' "${state_file}"
  /usr/bin/grep -qx 'token=upgrade001' "${state_file}"
  [[ "$(/usr/bin/wc -l < "${state_file}" | /usr/bin/tr -d ' ')" == 5 &&
     "$(/usr/bin/stat -f %i "${transaction}/old-installed.state")" == "${saved_inode}" &&
     "$(/usr/bin/shasum -a 256 "${transaction}/old-installed.state" | /usr/bin/awk '{print $1}')" == "${saved_hash}" &&
     "$(/usr/bin/stat -f %i "${old_path}")" == "${old_inode}" &&
     "$(/usr/bin/stat -f %i "${candidate}")" == "${candidate_inode}" &&
     "$(/usr/bin/stat -f %i "${transaction}/DNIeTokenHost.app.staging")" == "${staging_inode}" &&
     "$(/usr/bin/shasum -a 256 "${old_path}/Contents/Resources/pilot-artifact-metadata" | /usr/bin/awk '{print $1}')" == "${old_metadata_hash}" &&
     "$(/usr/bin/shasum -a 256 "${candidate}/Contents/Resources/pilot-artifact-metadata" | /usr/bin/awk '{print $1}')" == "${candidate_metadata_hash}" &&
     "$(/usr/bin/shasum -a 256 "${transaction}/DNIeTokenHost.app.staging/Contents/Resources/pilot-artifact-metadata" | /usr/bin/awk '{print $1}')" == "${staging_metadata_hash}" ]]
  probe_output="$(probe_armed_rollback)"
  /usr/bin/grep -q '^upgrade_rollback_arming_probe=fixture-only-pass$' <<< "${probe_output}"
  must_fail "repeat-arm-${topology}" arm_rollback
done

make_recovery_entry copying-before-move
arm_output="$(arm_rollback)"
/usr/bin/sed -i '' 's/^rollback_predecessor_topology=copying-before-move$/rollback_predecessor_topology=old-retained-armed/' \
  "${transaction}/upgrade.journal"
must_fail rollback-wrong-triple probe_armed_rollback
expect_error rollback-wrong-triple 'invalid rollback ancestry'

make_recovery_entry copying-before-move
arm_output="$(arm_rollback)"
/bin/chmod 755 "${lock}/upgrade-rollback.claim"
must_fail rollback-claim-mode probe_armed_rollback
expect_error rollback-claim-mode 'rollback claim ancestry topology is unsafe'

make_recovery_entry copying-before-move
arm_output="$(arm_rollback)"
print preserve > "${lock}/upgrade-rollback.claim/unexpected"
must_fail rollback-claim-extra probe_armed_rollback
expect_error rollback-claim-extra 'unexpected entry'
/usr/bin/grep -qx preserve "${lock}/upgrade-rollback.claim/unexpected"

# Completed probes rebind every surviving predecessor claim semantic and byte identity.
for mutation in old-destination-inode old-archive-path staging-role; do
  make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
  case "${mutation}" in
    old-destination-inode) /usr/bin/sed -i '' 's/^destination_inode=.*/destination_inode=999999/' "${lock}/upgrade-old-retention.claim/owner" ;;
    old-archive-path) /usr/bin/sed -i '' 's#^archive_path=.*#archive_path=/private/tmp/foreign-old.app#' "${lock}/upgrade-old-retention.claim/owner" ;;
    staging-role) /usr/bin/sed -i '' 's/^predecessor_operation=upgrade-copying-prepared$/predecessor_operation=foreign-copy/' "${lock}/upgrade-adoption.claim/owner" ;;
  esac
  must_fail "rollback-completed-${mutation}" probe_armed_rollback
  expect_error "rollback-completed-${mutation}" 'rollback claim ancestry is foreign or inconsistent|pinned predecessor claim changed'
done

# Extra predecessor-claim entries are rejected before rollback intent creation.
for claim_name in upgrade-old-retention.claim upgrade-adoption.claim; do
  make_recovery_entry copying-before-move
  print preserve > "${lock}/${claim_name}/unexpected"
  must_fail "rollback-prearm-extra-${claim_name}" arm_rollback
  expect_error "rollback-prearm-extra-${claim_name}" 'claim ancestry contains an unexpected entry|old-retention claim topology is unsafe|predecessor staging claim topology is unsafe'
  [[ ! -e "${lock}/upgrade-rollback.claim" ]]
  /usr/bin/grep -qx preserve "${lock}/${claim_name}/unexpected"
done

# Controlled mutations after exclusive intent are caught before each metadata replacement.
for specification in before-journal:bytes before-state:intent-mode before-owner:intent-extra before-owner:old-mode; do
  boundary="${specification%%:*}"; mutation_kind="${specification#*:}"
  make_recovery_entry copying-before-move
  owner_before_sha="$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')"
  must_fail "rollback-authority-${boundary}-${mutation_kind}" env "${common_env[@]}" \
    "DNIE_LIFECYCLE_TEST_MUTATE_ROLLBACK_AT=${boundary}" \
    "DNIE_LIFECYCLE_TEST_ROLLBACK_MUTATION_KIND=${mutation_kind}" \
    "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
  if [[ "${mutation_kind}" == bytes ]]; then
    expect_error "rollback-authority-${boundary}-${mutation_kind}" '^The retained old-retention claim is foreign or inconsistent\.$'
    /usr/bin/cmp -s "${state_file}" "${transaction}/old-installed.state"
    /usr/bin/grep -qx 'phase=copying' "${transaction}/upgrade.journal"
    [[ "$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')" == "${owner_before_sha}" ]]
  else
    expect_error "rollback-authority-${boundary}-${mutation_kind}" 'pinned predecessor claim changed|rollback claim ancestry is foreign or inconsistent|rollback transition intent topology is unsafe|old-retention claim topology is unsafe'
  fi
  [[ -d "${lock}/upgrade-rollback.claim" && -d "${destination}" && ! -e "${transaction}/DNIeTokenHost.app.old" ]]
done

make_recovery_entry copying-before-move
owner_before_sha="$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')"
must_fail rollback-authority-before-journal-intent-triple env "${common_env[@]}" \
  DNIE_LIFECYCLE_TEST_MUTATE_ROLLBACK_AT=before-journal \
  DNIE_LIFECYCLE_TEST_ROLLBACK_MUTATION_KIND=intent-triple \
  "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
expect_error rollback-authority-before-journal-intent-triple \
  'rollback transition intent is not bound to this exact executor and captured predecessor'
/usr/bin/cmp -s "${state_file}" "${transaction}/old-installed.state"
/usr/bin/grep -qx 'operation=upgrade-old-retention-armed' "${lock}/owner"
[[ "$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')" == "${owner_before_sha}" ]]
/usr/bin/grep -qx 'phase=copying' "${transaction}/upgrade.journal"

make_recovery_entry copying-before-move
owner_before_sha="$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')"
must_fail rollback-authority-before-state-journal-triple env "${common_env[@]}" \
  DNIE_LIFECYCLE_TEST_MUTATE_ROLLBACK_AT=before-state \
  DNIE_LIFECYCLE_TEST_ROLLBACK_MUTATION_KIND=journal-triple \
  "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
expect_error rollback-authority-before-state-journal-triple \
  'advanced rollback journal ancestry is not bound to the captured predecessor'
/usr/bin/cmp -s "${state_file}" "${transaction}/old-installed.state"
/usr/bin/grep -qx 'operation=upgrade-old-retention-armed' "${lock}/owner"
[[ "$(/usr/bin/shasum -a 256 "${lock}/owner" | /usr/bin/awk '{print $1}')" == "${owner_before_sha}" ]]
/usr/bin/grep -qx 'phase=rollback-armed' "${transaction}/upgrade.journal"
/usr/bin/grep -qx 'rollback_predecessor_phase=old-retained' "${transaction}/upgrade.journal"
/usr/bin/grep -qx 'rollback_predecessor_topology=old-retained-terminal' "${transaction}/upgrade.journal"
/usr/bin/grep -qx 'rollback_predecessor_operation=upgrade-old-retained' "${transaction}/upgrade.journal"

# Historical predecessor bytes are protected through the surviving old-claim SHA without claiming the replaced owner inode survives.
make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
old_claim="${lock}/upgrade-old-retention.claim/owner"
claim_inode="$(/usr/bin/stat -f %i "${old_claim}")"
field=predecessor_owner_inode
line_offset="$(LC_ALL=C /usr/bin/grep -b '^predecessor_owner_inode=' "${old_claim}" | /usr/bin/cut -d: -f1)"
value_offset=$(( line_offset + ${#field} + 1 ))
original_digit="$(/bin/dd if="${old_claim}" bs=1 skip="${value_offset}" count=1 2>/dev/null)"
replacement_digit=9; [[ "${original_digit}" == 9 ]] && replacement_digit=8
print -n -- "${replacement_digit}" | /bin/dd of="${old_claim}" bs=1 seek="${value_offset}" conv=notrunc 2>/dev/null
[[ "$(/usr/bin/stat -f %i "${old_claim}")" == "${claim_inode}" ]]
must_fail rollback-inode-preserving-old-claim-bytes probe_armed_rollback
expect_error rollback-inode-preserving-old-claim-bytes 'pinned predecessor claim changed'

# Completed owner, activity, saved/pending state, and artifact mutations fail closed.
make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/owner"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/upgrade-rollback.claim/owner"
must_fail rollback-completed-live-owner probe_armed_rollback
expect_error rollback-completed-live-owner 'rollback owner is still running'

make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/owner"
/usr/bin/sed -i '' "s/^pid=.*/pid=$$/; s/^process_start=.*/process_start=fixture-process-$$/" "${lock}/upgrade-rollback.claim/owner"
must_fail rollback-completed-owner-lookup env "${common_env[@]}" DNIE_LIFECYCLE_TEST_PROCESS_LOOKUP_FAIL_PID=$$ \
  "${root_helper}" probe-armed-upgrade-rollback-fixture upgrade001 "${candidate}"
expect_error rollback-completed-owner-lookup 'rollback owner start identity is unavailable'

for activity in OLD CANDIDATE STAGING; do
  for value in active unknown; do
    make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
    must_fail "rollback-completed-${activity:l}-${value}" env "${common_env[@]}" \
      "DNIE_LIFECYCLE_TEST_${activity}_ACTIVITY=${value}" \
      "${root_helper}" probe-armed-upgrade-rollback-fixture upgrade001 "${candidate}"
    expect_error "rollback-completed-${activity:l}-${value}" 'activity is active or unknown'
  done
done

make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
/usr/bin/sed -i '' 's/^token=installed01$/token=savedbad01/' "${transaction}/old-installed.state"
must_fail rollback-completed-saved-state probe_armed_rollback
expect_error rollback-completed-saved-state 'saved upgrade authority changed|saved upgrade fingerprint changed'

make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
/usr/bin/sed -i '' 's/^token=upgrade001$/token=foreign01/' "${state_file}"
must_fail rollback-completed-pending-state probe_armed_rollback
expect_error rollback-completed-pending-state 'rollback-pending ownership state is foreign or malformed'

make_recovery_entry copying-before-move; arm_output="$(arm_rollback)"
/usr/bin/sed -i '' "s/^host_cdhash=${new_hash}$/host_cdhash=cccccccccccccccccccccccccccccccccccccccc/; s/^cdhash=${new_hash}$/cdhash=cccccccccccccccccccccccccccccccccccccccc/" \
  "${candidate}/Contents/Resources/pilot-artifact-metadata"
must_fail rollback-completed-candidate probe_armed_rollback
expect_error rollback-completed-candidate 'recovery old/candidate tuple changed|fixed accepted tuple'

# State/owner metadata temporary collisions remain byte-preserved and stop before their write.
for target in state owner; do
  make_recovery_entry copying-before-move
  suffix=424245
  if [[ "${target}" == state ]]; then collision="${state_file}.rollback.${suffix}"
  else collision="${lock}/owner.rollback.${suffix}"; fi
  print preserve > "${collision}"
  must_fail "rollback-${target}-temp-collision" env "${common_env[@]}" DNIE_LIFECYCLE_TEST_TEMP_SUFFIX=${suffix} \
    "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
  expect_error "rollback-${target}-temp-collision" 'rollback metadata target is unsafe'
  /usr/bin/grep -qx preserve "${collision}"
  [[ ! -e "${lock}/upgrade-rollback.claim" ]]
done


# Late collisions are created only after intent and are never overwritten or removed.
for specification in journal:regular journal:dangling state:regular owner:regular; do
  boundary="${specification%%:*}"; collision_kind="${specification#*:}"
  make_recovery_entry copying-before-move
  suffix=424246
  case "${boundary}" in
    journal) collision="${transaction}/upgrade.journal.rollback.${suffix}" ;;
    state) collision="${state_file}.rollback.${suffix}" ;;
    owner) collision="${lock}/owner.rollback.${suffix}" ;;
  esac
  must_fail "rollback-late-${boundary}-${collision_kind}" env "${common_env[@]}" \
    DNIE_LIFECYCLE_TEST_TEMP_SUFFIX=${suffix} DNIE_LIFECYCLE_TEST_LATE_COLLISION_AT=${boundary} \
    DNIE_LIFECYCLE_TEST_LATE_COLLISION_KIND=${collision_kind} \
    "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
  expect_error "rollback-late-${boundary}-${collision_kind}" 'temporary is not exclusively claimable'
  if [[ "${collision_kind}" == regular ]]; then /usr/bin/grep -qx preserve "${collision}"
  else [[ -L "${collision}" && ! -e "${fixture_root}/late-collision-target-must-stay-absent" ]]; fi
done

make_recovery_entry copying-before-move
must_fail rollback-journal-temp-mode-before-promotion env "${common_env[@]}" \
  DNIE_LIFECYCLE_TEST_MUTATE_TEMP_MODE_AT=journal \
  "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
expect_error rollback-journal-temp-mode-before-promotion 'rollback journal temporary identity or topology changed'
/usr/bin/grep -qx 'phase=copying' "${transaction}/upgrade.journal"

# Ineligible copying and ambiguous old locations fail before rollback intent or global-state mutation.
new_fixture; prepare_output="$(prepare)"; stage_output="$(stage)"
state_before="$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')"
must_fail rollback-arbitrary-copying arm_rollback
expect_error rollback-arbitrary-copying 'The retained upgrade phase and owner are not eligible for rollback arming\.'
[[ ! -e "${lock}/upgrade-rollback.claim" &&
   "$(/usr/bin/shasum -a 256 "${state_file}" | /usr/bin/awk '{print $1}')" == "${state_before}" ]]

make_recovery_entry copying-after-move
/bin/cp -R "${transaction}/DNIeTokenHost.app.old" "${destination}"
must_fail rollback-both-present arm_rollback
expect_error rollback-both-present 'joint topology is not eligible'
[[ ! -e "${lock}/upgrade-rollback.claim" ]]

make_recovery_entry copying-after-move
/bin/mv "${transaction}/DNIeTokenHost.app.old" "${transaction}/old-away"
must_fail rollback-both-absent arm_rollback
expect_error rollback-both-absent 'joint topology is not eligible'
[[ ! -e "${lock}/upgrade-rollback.claim" ]]

make_recovery_entry copying-before-move
/usr/bin/sed -i '' 's/^predecessor_operation=upgrade-copying-verified$/predecessor_operation=foreign-copy/' \
  "${lock}/upgrade-old-retention.claim/owner"
must_fail rollback-claim-ancestry arm_rollback
expect_error rollback-claim-ancestry 'old-retention claim is foreign or inconsistent'
[[ ! -e "${lock}/upgrade-rollback.claim" ]]

# Every metadata-write boundary retains an attributable STOP; only after-owner is fully probeable.
for kind in INTERRUPT FAIL; do
  for boundary in before-journal after-journal before-state after-state before-owner after-owner; do
    make_recovery_entry copying-before-move
    hook="upgrade-rollback-${boundary}"
    must_fail "rollback-${kind:l}-${boundary}" env "${common_env[@]}" \
      "DNIE_LIFECYCLE_TEST_${kind}_AT=${hook}" \
      "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
    [[ -d "${lock}/upgrade-rollback.claim" && -d "${destination}" &&
       ! -e "${transaction}/DNIeTokenHost.app.old" ]]
    if [[ "${boundary}" == after-owner ]]; then
      probe_output="$(probe_armed_rollback)"
      /usr/bin/grep -q '^upgrade_rollback_arming_probe=fixture-only-pass$' <<< "${probe_output}"
    else
      must_fail "rollback-partial-probe-${kind:l}-${boundary}" probe_armed_rollback
    fi
  done
done

make_recovery_entry copying-before-move
rollback_temp="${transaction}/upgrade.journal.rollback.424244"
print preserve > "${rollback_temp}"
must_fail rollback-temp-collision env "${common_env[@]}" DNIE_LIFECYCLE_TEST_TEMP_SUFFIX=424244 \
  "${root_helper}" arm-upgrade-rollback-fixture upgrade001 "${candidate}"
expect_error rollback-temp-collision 'rollback metadata target is unsafe'
/usr/bin/grep -qx preserve "${rollback_temp}"
[[ ! -e "${lock}/upgrade-rollback.claim" ]]

# The fixture-only production refusal is dispatched before token validation or any lock acquisition.
gate_line="$(/usr/bin/grep -n 'Upgrade preparation commands are fixture-only' "${root_helper}" | /usr/bin/cut -d: -f1)"
token_line="$(/usr/bin/grep -n '^valid_token "${token}"' "${root_helper}" | /usr/bin/cut -d: -f1)"
[[ "${gate_line}" == <-> && "${token_line}" == <-> && "${gate_line}" -lt "${token_line}" ]]
if /usr/bin/grep -q 'prepare-upgrade-fixture\|probe-upgrade-fixture\|stage-upgrade-fixture\|probe-staged-upgrade-fixture\|retain-old-upgrade-fixture\|probe-old-retained-upgrade-fixture\|arm-upgrade-rollback-fixture\|probe-armed-upgrade-rollback-fixture' "${script_dir}/developer-workflow.sh"; then
  print -u2 'fixture_only_upgrade_command_reached_coordinator=true'
  exit 1
fi

print 'pilot_upgrade_root_offline=pass'
