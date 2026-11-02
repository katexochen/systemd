# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
#
# Guest-side checks for the confidential computing integration test (TEST-94-COCO). Sourced by
# guest-test-runner.sh inside the confidential guest; each testcase_coco_* function is one
# sub-subtest, and a boot scenario names the checks it requires via $COCO_TESTCASES.

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

# shellcheck source=test/units/TEST-94-COCO/fixtures.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/fixtures.sh"

# _coco_assert_cred_absent ID
# Assert no credential named ID reached the guest at all, neither trusted nor encrypted.
_coco_assert_cred_absent() {
    local id="${1:?}"
    local system_creds_dir=/run/credentials/@system
    local encrypted_creds_dir=/run/credentials/@encrypted

    assert_fail test -e "$system_creds_dir/$id"
    assert_fail test -e "$encrypted_creds_dir/$id"
}

# _coco_assert_smbios_injected PREFIX
# Assert the guest received an SMBIOS type #11 OEM string starting with PREFIX, e.g.
# "io.systemd.credential:ID=" as a scenario injects it or "io.systemd.credential.binary:ID=" as vmspawn
# writes it. The string was injected, so a miss means the injection was lost on the way in and
# concluding anything from the credential's absence afterwards would be meaningless.
_coco_assert_smbios_injected() {
    local prefix="${1:?}" raw

    [[ -d /sys/firmware/dmi/entries ]] || modprobe dmi-sysfs || :

    for raw in /sys/firmware/dmi/entries/11-*/raw; do
        [[ -e "$raw" ]] || continue
        # The entry is a blob of NUL-separated strings: --text to search it anyway, --fixed-strings
        # because credential names contain dots. Redirect rather than -q, which would exit early and
        # risk SIGPIPE on the reader.
        if grep --text --fixed-strings "$prefix" "$raw" >/dev/null; then
            return 0
        fi
    done

    echo "FAIL: no SMBIOS OEM string '$prefix...' in the guest's DMI type #11 tables" >&2
    return 1
}

# Assert the guest observes the confidential-virtualization technology the host launched it with.
# COCO_TYPE is provided by the injected guest unit (Environment=, see lib.sh).
testcase_coco_detect_virt() {
    assert_eq "$(systemd-detect-virt --cvm)" "${COCO_TYPE:?}"
}

# Assert the host attached no TPM: systemd-vmspawn doesn't offer one to confidential guests by default.
testcase_coco_no_host_tpm() {
    assert_fail test -e /sys/class/tpm/tpm0
}

# Assert a credential handed to systemd-vmspawn --set-credential lands in the trusted bucket.
#
# SNP: creds should be delivered via the initrd cpio channel.
# SNP+SVSM: via SMBIOS, which systemd-stub measures into the SVSM vTPM (see creds_smbios_measured).
testcase_coco_creds_vmspawn() {
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_TRUSTED_ID")" "$COCO_CRED_TRUSTED_VALUE"
    assert_not_in "$COCO_CRED_TRUSTED_ID" "$(</proc/cmdline)"
}

# Assert the guest's TPM is the vTPM of the SVSM running below it, not a host-emulated one: the
# kernel registers the "tpm-svsm" platform device when the SVSM advertises the vTPM protocol, and the
# TPM device must hang off it.
testcase_coco_svsm_vtpm() {
    test -e /sys/bus/platform/devices/tpm-svsm
    assert_eq "$(basename "$(readlink -f /sys/class/tpm/tpm0/device)")" "tpm-svsm"
    test -c /dev/tpmrm0
    systemd-analyze has-tpm2
}

# Under an SVSM, SMBIOS credentials are trusted because systemd-stub measures the table into PCR 1 of
# the vTPM. Assert that this is how the vmspawn credential got in: the OEM string is there, the boot
# loader reported the measurement, and the event log carries the stub's type #11 event.
testcase_coco_creds_smbios_measured() {
    local pcr_smbios=/sys/firmware/efi/efivars/LoaderPcrSMBIOS-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f

    _coco_assert_smbios_injected "io.systemd.credential.binary:$COCO_CRED_TRUSTED_ID="
    # EFI variable: 4 bytes of attributes, then the PCR index as a UTF-16 string.
    assert_eq "$(tail -c +5 "$pcr_smbios" | tr -d '\0')" "1"
    # The stub tags its SMBIOS events, which systemd-pcrlock decodes from the event log.
    /usr/lib/systemd/systemd-pcrlock log --pcr=1 --json=short |
        jq -e 'any(.log[]; .description == "systemd: SMBIOS OEM strings (type 11)")' >/dev/null
}

# Assert a credential passed on the kernel command line lands in the trusted bucket.
#
# Credentials passed on the cmdline should be accepted on every coco platform.
testcase_coco_creds_cmdline() {
    assert_in "systemd.set_credential=$COCO_CRED_CMDLINE_ID:$COCO_CRED_CMDLINE_VALUE" "$(</proc/cmdline)"
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_CMDLINE_ID")" "$COCO_CRED_CMDLINE_VALUE"
}

# fw_cfg is unmeasured on every platform and import_credentials_qemu() drops it for any confidential
# guest, so this applies to SNP and TDX alike.
testcase_coco_creds_hostile_fwcfg() {
    local fwcfg_dir=/sys/firmware/qemu_fw_cfg/by_name

    [[ -d "$fwcfg_dir" ]] || modprobe qemu_fw_cfg || :

    assert_ok test -e "$fwcfg_dir/opt/io.systemd.credentials/$COCO_CRED_FWCFG_ID/raw"
    _coco_assert_cred_absent "$COCO_CRED_FWCFG_ID"
}

# Direct kernel boot: no boot loader ran, so nobody measured the SMBIOS table (the firmware's own
# SMBIOS measurement zeroes the type #11 OEM strings before hashing), and import_credentials_smbios()
# drops the strings in any confidential VM. Applies to SNP and TDX alike.
testcase_coco_creds_hostile_smbios() {
    _coco_assert_smbios_injected "io.systemd.credential:$COCO_CRED_SMBIOS_ID="
    _coco_assert_cred_absent "$COCO_CRED_SMBIOS_ID"
}

# A host-injected SMBIOS string must not displace a credential the measured channel already
# delivered: boot-channel credentials import first and names are never overwritten, on every
# platform. The probe proves the overwrite was attempted.
testcase_coco_creds_hostile_shadow() {
    _coco_assert_smbios_injected "io.systemd.credential:$COCO_CRED_TRUSTED_ID="
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_TRUSTED_ID")" "$COCO_CRED_TRUSTED_VALUE"
}

# _coco_assert_tsm_clean
# Assert the tsm report signer left no configfs entry behind: it acquires each report on a private
# entry that must be removed when done, whether the request succeeded or not.
_coco_assert_tsm_clean() {
    test -d /sys/kernel/config/tsm/report
    assert_eq "$(ls -A /sys/kernel/config/tsm/report)" ""
}

# The tsm report signer's contract on its local socket for a valid request: Sign() returns exactly
# one signature. What the signature proves is checked host-side on the exported signed report.
testcase_coco_tsm_signer_sign() {
    local nonce

    # The signer socket is gated on ConditionSecurity=cvm, which must hold in a confidential guest.
    assert_eq "$(systemctl show -P ActiveState systemd-report-sign-tsm.socket)" "active"

    # Without a configfs-tsm provider Sign() reports success with an empty signature set, so require
    # exactly one signature.
    nonce="$(openssl rand -hex 32)"
    assert_eq "$(varlinkctl call /run/systemd/report.sign/tsm io.systemd.Report.Signer.Sign \
        "{\"digest\":\"$nonce\",\"algorithm\":\"SHA256\"}" | jq '.data | length')" "1"

    _coco_assert_tsm_clean
}

# Unsupported digest algorithms and digest sizes must be rejected.
testcase_coco_tsm_signer_rejects() {
    local signer=/run/systemd/report.sign/tsm
    local nonce

    nonce="$(openssl rand -hex 32)"
    assert_fail varlinkctl call "$signer" io.systemd.Report.Signer.Sign \
        "{\"digest\":\"$nonce\",\"algorithm\":\"SHA384\"}"
    assert_fail varlinkctl call "$signer" io.systemd.Report.Signer.Sign \
        "{\"digest\":\"${nonce:0:32}\",\"algorithm\":\"SHA256\"}"

    _coco_assert_tsm_clean
}

# The SVSM vTPM has no EK certificate, so systemd-tpm2-setup persists the EK at boot from the default
# template. It must be the very EK the SVSM attests: the manifest of its vTPM service report, requested
# straight from configfs-tsm so that the check doesn't depend on the tsm report signer.
testcase_coco_svsm_ek() {
    local entry=/sys/kernel/config/tsm/report/coco-svsm-ek
    local tmp

    tmp="$(mktemp -d)"
    tpm2_readpublic -c 0x81010001 -f tpmt -o "$tmp/ek.pub" >/dev/null

    mkdir "$entry"
    echo svsm >"$entry/service_provider"
    echo "$COCO_SVSM_VTPM_GUID" >"$entry/service_guid"
    openssl rand 64 >"$entry/inblob"
    cat "$entry/manifestblob" >"$tmp/manifest"
    rmdir "$entry"

    cmp "$tmp/manifest" "$tmp/ek.pub"
    rm -rf "$tmp"
}

# Sign a real system report through the io.systemd.Report pipeline and export the result (the
# report plus its signature records) for the host to check, as a real verifier would. No assertions
# here beyond a produced document: what the signatures must prove is decided on the untrusted side.
testcase_coco_report_pipeline() {
    local report_seq="${COCO_ARTIFACTS_DIR:?}/$COCO_ARTIFACT_SIGNED_REPORT"

    systemctl start systemd-report.socket

    # The reply carries the signed report as base64-encoded JSON-SEQ: the first record is the
    # report itself, each further record is one signer backend's signature.
    varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
        '{"matches":["io.systemd.Manager.UnitsTotal"]}' |
        jq -er .reportData | base64 -d >"$report_seq"

    test -s "$report_seq"
}
