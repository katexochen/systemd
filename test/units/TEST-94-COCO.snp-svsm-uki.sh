#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# SEV-SNP with COCONUT-SVSM: boot the UKI from the image's ESP on IGVM firmware that runs the SVSM at
# VMPL 0 and the guest at VMPL 2, with the SVSM's vTPM as the guest's TPM.
#
# Needs the host components of the coco mkosi profile: qemu-coconut (QEMU with KVM planes support,
# installed under its own prefix) and coconut-svsm (the IGVM firmware and its QEMU firmware descriptor).
# The host kernel must support KVM planes (downstream patch set).

set -eux
set -o pipefail

# shellcheck source=test/units/TEST-94-COCO/lib.sh
. "$(dirname "$0")"/TEST-94-COCO/lib.sh

if [[ "${COCO_TYPE:?}" != "sev-snp" ]]; then
    echo "host coco type is '$COCO_TYPE', not sev-snp, skipping"
    exit 77
fi

# systemd-report is optional, and a large part of the tests below will fail
# without it. Skip the whole test for simplicity.
[ -x /usr/lib/systemd/systemd-report ] || exit 77

QEMU_COCONUT_BIN=/usr/lib/qemu-coconut/bin
FIRMWARE="$(find /usr/share/qemu/firmware -name '*-coconut-svsm-x86_64.json' -print -quit 2>/dev/null || :)"
if [[ ! -x "$QEMU_COCONUT_BIN/qemu-system-x86_64" || -z "$FIRMWARE" ]]; then
    echo "qemu-coconut or the coconut-svsm firmware is not installed (see the coco mkosi profile), skipping"
    exit 77
fi
IGVM="$(jq -r .mapping.filename "$FIRMWARE")"

IMAGE_DIR="$(vmspawn_images_dir)"
MACHINE="coco-snp-svsm-$$"
WORKDIR="$(mktemp -d)"
at_exit() {
    set +e
    jobs -p | xargs -r kill 2>/dev/null
    machinectl terminate "$MACHINE" 2>/dev/null || :
    rm -rf "$WORKDIR"
}
trap at_exit EXIT

# fw_cfg is never measured, so it must stay ignored even though SMBIOS credentials are trusted here.
QEMU_EXTRA=(
    -fw_cfg "name=opt/io.systemd.credentials/$COCO_CRED_FWCFG_ID,string=$COCO_CRED_FWCFG_VALUE"
)

# The guest boots the UKI from the ESP; vmspawn delivers credentials via SMBIOS, which systemd-stub
# measures into the vTPM. vmspawn picks up the planes QEMU via PATH.
TESTCASES=(
    detect_virt            # systemd-detect-virt --cvm detects SNP as the CVM type
    svsm_vtpm              # the guest's TPM is the SVSM vTPM
    creds_vmspawn          # credential transport by vmspawn is working (via SMBIOS here)
    creds_smbios_measured  # the SMBIOS table carrying it was measured by the boot loader
    creds_hostile_fwcfg    # unmeasured fw_cfg credentials are still ignored
    tsm_signer_sign        # the tsm report signer returns exactly one signature
    tsm_signer_rejects     # the tsm report signer rejects malformed requests
    svsm_ek                # the EK persisted at boot is the one the SVSM attests in its vTPM service report
    report_pipeline        # signing a report via io.systemd.Report; the result is verified below, host-side
)
PATH="$QEMU_COCONUT_BIN:$PATH" \
SYSTEMD_VMSPAWN_QEMU_EXTRA="${QEMU_EXTRA[*]}" \
vmspawn_boot_coco "$MACHINE" "$COCO_TYPE" "$WORKDIR" \
    "${TESTCASES[*]}" \
    --image="$IMAGE_DIR/image.raw" \
    --firmware="$FIRMWARE" \
    --set-credential="$COCO_CRED_TRUSTED_ID:$COCO_CRED_TRUSTED_VALUE"

# The report_pipeline check exported the signed report; verify it as a real verifier would. Its tsm
# signature must be the SVSM's vTPM service report, from the firmware installed on this host.
test -s "$WORKDIR/artifacts/$COCO_ARTIFACT_SIGNED_REPORT"
coco_verify_snp_signed_report "$WORKDIR/artifacts/$COCO_ARTIFACT_SIGNED_REPORT" "$WORKDIR" "$IGVM"

# The tpm2 signature must be there too. A verifier can't trust it yet, though: the service report
# attests the vTPM's EK, but nothing in the signed report proves that the tpm2 record's signing key
# lives in that same vTPM. Until we close this gap, only check for its presence.
assert_eq "$(tail -n +2 "$WORKDIR/artifacts/$COCO_ARTIFACT_SIGNED_REPORT" | tr -d '\036' | jq -s '[.[] | select(.mechanism == "tpm2")] | length')" "1"
echo "SEV-SNP guest under COCONUT-SVSM correctly used the SVSM vTPM and accepted measured credentials"
