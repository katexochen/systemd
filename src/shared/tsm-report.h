/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "sd-id128.h"

#include "forward.h"

#define TSM_REPORT_DATA_SIZE 64U

/* SVSM attestation protocol, see "Secure VM Service Module for SEV-SNP Guests" (AMD doc 58019). */
#define TSM_SERVICE_PROVIDER_SVSM "svsm"
#define TSM_SVSM_SERVICE_VTPM     SD_ID128_MAKE(c4,76,f1,eb,01,23,45,a5,96,41,b4,e7,dd,e5,bf,e3)

/* Optional knobs. Mirrors the write-only attributes other than inblob.
 * Zero-initialize ({}) and set only what you need. NULL options == all defaults. */
typedef struct TsmReportOptions {
        unsigned privlevel;                  /* e.g. SEV-SNP VMPL */
        bool privlevel_set;                  /* privlevel_floor is used when unset */
        const char *service_provider;        /* e.g. "svsm", NULL for a plain report */
        sd_id128_t service_guid;             /* null: all services; requires service_provider */
        bool service_guid_set;
        unsigned service_manifest_version;   /* requires service_guid */
        bool service_manifest_version_set;   /* service's first manifest version is used when unset */
} TsmReportOptions;

/* Result. Mirrors the read-only attributes. */
typedef struct TsmReport {
        char *provider;             /* e.g. "sev_guest", "tdx_guest" */
        struct iovec outblob;       /* the attestation report */
        struct iovec auxblob;       /* optional, unset if empty (e.g. SEV cert_table) */
        struct iovec manifestblob;  /* optional, unset if empty */
} TsmReport;

TsmReport *tsm_report_free(TsmReport *report);
DEFINE_TRIVIAL_CLEANUP_FUNC(TsmReport*, tsm_report_free);

/* Acquire an attestation report via configfs-tsm.
 *   report_data: mandatory inblob to include in the report, TSM_REPORT_DATA_SIZE bytes
 *   options:     optional, NULL for defaults
 *   ret:         result, freed with tsm_report_free()
 * Returns
 *   -EOPNOTSUPP       if the configfs-tsm interface is absent.
 *   -ENXIO            if it is present but no provider is registered.
 *   -EPROTONOSUPPORT  if the service_provider concept isn't supported.
 * Other negative errnos are real failures. */
int tsm_report_acquire(
                const struct iovec *report_data,
                const TsmReportOptions *options,
                TsmReport **ret);
