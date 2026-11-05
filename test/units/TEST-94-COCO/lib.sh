# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
#
# Host-side helpers for the confidential computing integration test (TEST-94-COCO).
# Sourced by the TEST-94-COCO.sh driver.

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

# util.sh (assert_*, vmspawn_images_dir) lives one level up in the shared units dir.
# shellcheck source=test/units/util.sh
. "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")/util.sh"
# shellcheck source=test/units/TEST-94-COCO/fixtures.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/fixtures.sh"

# Exit status the guest test runner reports on success (its unit's SuccessActionExitStatus=). vmspawn
# forwards the guest PID1's EXIT_STATUS over the vsock notify socket and exits with it.
_COCO_GUEST_PASS=123
# vsock port the host listens on for the guest's per-check result records, distinct from vmspawn's own
# (kernel-assigned) notify port. The host binds CID_ANY:PORT; the guest connects to CID 2 (host):PORT.
_COCO_RESULT_PORT=4321

# _coco_guest_unit COCO_TYPE UNITS_DIR TESTCASES
# Emit the one-shot unit that runs the guest test runner: passes the coco type, result port and
# the requested checks via the environment, and relays the aggregate verdict via
# SuccessAction/EXIT_STATUS. Its output, including the trace and why an assertion failed, goes to
# the console as well, which the host dumps when the guest fails.
_coco_guest_unit() {
    local coco_type="${1:?}" units_dir="${2:?}" testcases="${3:?}"
    cat <<EOF
[Unit]
Description=coco guest self-check
After=basic.target
SuccessAction=exit
SuccessActionExitStatus=$_COCO_GUEST_PASS
FailureAction=exit
FailureActionExitStatus=1
[Service]
Type=oneshot
StandardOutput=journal+console
Environment=COCO_TYPE=$coco_type
Environment=COCO_RESULT_PORT=$_COCO_RESULT_PORT
Environment="COCO_TESTCASES=$testcases"
ExecStart=$units_dir/guest-test-runner.sh
EOF
}

# _coco_guest_dropin
# Emit the multi-user.target drop-in that pulls the guest self-check unit into the boot.
_coco_guest_dropin() {
    cat <<EOF
[Unit]
Wants=$COCO_GUEST_UNIT
After=$COCO_GUEST_UNIT
EOF
}

# _coco_collect_artifacts RESULTS DEST_DIR
# Decode the 'ARTIFACT=<name> DATA=<base64>' records the guest shipped alongside its per-check
# results into DEST_DIR, one file per record. Records whose name doesn't look like a plain file name
# are ignored, so a record can't write outside DEST_DIR.
_coco_collect_artifacts() {
    local results="${1:?}" dest_dir="${2:?}"
    local name data _

    mkdir -p "$dest_dir"
    while read -r name data _ || [[ -n "$name" ]]; do
        [[ "$name" == ARTIFACT=* && "$data" == DATA=* ]] || continue
        name="${name#ARTIFACT=}"
        data="${data#DATA=}"
        if [[ ! "$name" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]]; then
            echo "ignoring guest artifact with unexpected name '$name'" >&2
            continue
        fi
        if ! base64 -d <<<"$data" >"$dest_dir/$name"; then
            echo "failed to decode guest artifact '$name'" >&2
            rm -f "$dest_dir/$name"
            continue
        fi
        echo "collected guest artifact '$name' ($(stat -c%s "$dest_dir/$name") bytes)"
    done <"$results"
}

# coco_verify_snp_report REPORT [snpguest verify attestation options...]
# Verify the SNP attestation report REPORT with snpguest: the AMD certificate chain (ARK -> ASK -> VCEK)
# is valid, the report is signed by the VCEK, and only then that its fields match what the options
# expect (--report-data, --measurement, --host-data, each hex with a 0x prefix). The certificates must
# be pre-provisioned in a host directory named 'snp-certs', bound in via $TEST_BIND_DIRS: the
# harness runs the container without network, and the AMD KDS rate-limits hard enough that
# fetching them per test run would be flaky anyway.
coco_verify_snp_report() {
    local report="${1:?}"
    local certs_dir=/work/snp-certs
    shift

    # snpguest is part of the test image (see mkosi.conf.d/fedora): its absence is a broken image,
    # not a reason to silently skip the verification.
    if ! command -v snpguest >/dev/null; then
        echo "snpguest is not installed, cannot verify the SNP attestation report" >&2
        return 1
    fi

    if [[ ! -d "$certs_dir" ]]; then
        echo "no AMD certificates at $certs_dir; fetch them once on the host" \
            "(snpguest fetch ca/vcek) and pass the directory via \$TEST_BIND_DIRS" >&2
        return 1
    fi

    snpguest verify certs "$certs_dir"
    snpguest verify attestation "$certs_dir" "$report" "$@"
    snpguest display report "$report"
}

# coco_verify_snp_signed_report REPORT_SEQ WORKDIR [IGVM]
# Check a signed report produced by io.systemd.Report's GenerateSigned the way a remote verifier
# would, from nothing but the signed report: the tsm signature record must carry an SNP attestation
# report that verifies against the AMD certificate chain and binds the digest of the signed report
# bytes via its REPORT_DATA field. Without IGVM, the report must be a plain one, which embeds the
# digest. With IGVM, it must be the vTPM service report of the SVSM in that IGVM firmware: REPORT_DATA
# is SHA-512(digest || manifest), the manifest being the vTPM's EK, the report comes from VMPL 0
# where only the SVSM runs, and its launch measurement is the one igvmmeasure computes for IGVM.
# WORKDIR holds intermediate files.
coco_verify_snp_signed_report() {
    local report_seq="${1:?}" workdir="${2:?}" igvm="${3:-}"
    local message="$workdir/message.bin"
    local report_file="$workdir/attestation-report.bin"
    local manifest_file="$workdir/manifest.bin"
    local sig digest report_data
    local verify_args=()

    # The first JSON-SEQ record is the report itself: exactly the byte sequence that got signed,
    # including the leading record separator (0x1e) and the trailing newline, so 'head -n1'
    # reproduces it verbatim. Each further record is one signer backend's signature.
    head -n1 "$report_seq" >"$message"
    tr -d '\036' <"$message" | jq -e '.mediaType == "application/vnd.io.systemd.report"' >/dev/null
    digest="$(sha256sum "$message" | cut -d' ' -f1)"

    # Pick the tsm backend's signature record (other backends may be enabled too).
    sig="$(tail -n +2 "$report_seq" | tr -d '\036' | jq -c 'select(.mechanism == "tsm")')"
    test -n "$sig"
    assert_eq "$(jq -r .mediaType <<<"$sig")" "application/vnd.io.systemd.report.signature"
    assert_eq "$(jq -r .sha256 <<<"$sig")" "$digest"
    assert_eq "$(jq -r .data.provider <<<"$sig")" "sev_guest"
    jq -r .data.outblob <<<"$sig" | base64 -d >"$report_file"

    # What REPORT_DATA must be to bind the digest. The manifest is unauthenticated input until the
    # attestation report it is bound into has been verified below.
    if [[ -n "$igvm" ]]; then
        assert_eq "$(jq -r .data.serviceProvider <<<"$sig")" "svsm"
        assert_eq "$(jq -r .data.serviceGuid <<<"$sig")" "$COCO_SVSM_VTPM_GUID"
        jq -r .data.manifestblob <<<"$sig" | base64 -d >"$manifest_file"
        test -s "$manifest_file"
        report_data="$({ xxd -r -p <<<"$digest$(printf '00%.0s' {1..32})"; cat "$manifest_file"; } | sha512sum | cut -d' ' -f1)"
        verify_args+=(--measurement "0x$(igvmmeasure "$igvm" measure --bare)")
    else
        assert_eq "$(jq -r '.data.serviceProvider // ""' <<<"$sig")" ""
        report_data="$digest$(printf '00%.0s' {1..32})"
    fi

    # Authenticate the attestation report first, then check what it says.
    coco_verify_snp_report "$report_file" --report-data "0x$report_data" "${verify_args[@]}"

    if [[ -n "$igvm" ]]; then
        # The guest runs at VMPL 2 and can't request reports for a more privileged VMPL.
        assert_eq "$(snpguest display report "$report_file" --output json | jq -r .vmpl)" "0"
    fi
}

# vmspawn_boot_coco MACHINE COCO_TYPE WORKDIR TESTCASES [systemd-vmspawn args...]
# Boot a confidential guest with systemd-vmspawn, running the coco guest test runner. TESTCASES is the
# space-separated list of guest checks (testcase_coco_* names without the prefix).
# The caller supplies the boot-path-specific launch args — --image/--linux/--initrd and the guest
# kernel command line — plus any extra flags via "$@", so each per-boot-path scenario
# stays configurable. Per-check records shipped by the guest are collected over a vsock
# socket into WORKDIR/results and echoed; returns 0 iff the guest reported the success
# aggregate, otherwise dumps the console.
# Artifacts the guest checks exported are decoded into WORKDIR/artifacts.
vmspawn_boot_coco() {
    local machine="${1:?}" coco_type="${2:?}" workdir="${3:?}" testcases="${4:?}"
    shift 4

    local units_dir results console guest_unit guest_dropin rc=0 listener_pid=""
    units_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
    results="$workdir/results"
    console="$workdir/console.log"
    : >"$results"

    guest_unit="$(_coco_guest_unit "$coco_type" "$units_dir" "$testcases")"
    guest_dropin="$(_coco_guest_dropin)"

    # Collect the records the guest ships over vsock (single connection, guest closes when done):
    # per-check results and any artifacts the checks exported. The per-check breakdown is
    # best-effort: the aggregate exit status below is the authoritative pass/fail.
    socat -u "VSOCK-LISTEN:$_COCO_RESULT_PORT" "OPEN:$results,creat" &
    listener_pid=$!

    timeout -k 30 300 systemd-vmspawn \
        --machine="$machine" \
        --coco="$coco_type" \
        --ram=1G \
        --ephemeral \
        --console=read-only \
        --set-credential="systemd.extra-unit.$COCO_GUEST_UNIT:$guest_unit" \
        --set-credential="systemd.unit-dropin.multi-user.target:$guest_dropin" \
        "$@" \
        2>&1 | tee "$console" || rc="${PIPESTATUS[0]}"

    kill "$listener_pid" 2>/dev/null || :
    wait "$listener_pid" 2>/dev/null || :

    if [[ -s "$results" ]]; then
        echo "coco guest per-check results:"
        grep -v '^ARTIFACT=' "$results" || :
    fi
    _coco_collect_artifacts "$results" "$workdir/artifacts"

    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
        echo "systemd-vmspawn was killed by timeout (exit $rc)" >&2
        cat "$console" >&2
        return 1
    fi
    if [[ "$rc" -ne "$_COCO_GUEST_PASS" ]]; then
        echo "coco guest test runner failed: vmspawn exit $rc (expected $_COCO_GUEST_PASS)" >&2
        cat "$console" >&2
        return 1
    fi
    return 0
}
