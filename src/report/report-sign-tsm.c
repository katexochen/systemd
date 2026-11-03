/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "report-server.h"
#include "sha256.h"
#include "string-util.h"
#include "tsm-report.h"
#include "verbs.h"

COMMAND(
        "systemd-report-sign-tsm\0",
        "Get an attestation report via configfs Trusted Security Module (TSM) "
        "that includes the hash of the system report.",
        .man_pages = "systemd-report-sign-tsm@.service(8)\0",
        .option_namespace = "common",
);

const sd_varlink_server_flags_t report_server_flags = SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_MYSELF_ONLY;

typedef struct SignParameters {
        struct iovec digest;
        const char *algorithm;
} SignParameters;

static void sign_parameters_done(SignParameters *p) {
        iovec_done(&p->digest);
}

static int vl_method_sign(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",    SD_JSON_VARIANT_STRING, json_dispatch_unhex_iovec32,   offsetof(SignParameters, digest),    SD_JSON_MANDATORY },
                { "algorithm", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(SignParameters, algorithm), SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(sign_parameters_done) SignParameters sp = {};
        _cleanup_(tsm_report_freep) TsmReport *report = NULL;
        const TsmReportOptions *options = NULL;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &sp);
        if (r != 0)
                return r;

        if (!streq(sp.algorithm, "SHA256"))
                return sd_varlink_error_invalid_parameter_name(link, "algorithm");
        assert(sp.digest.iov_len == SHA256_DIGEST_SIZE);

        uint8_t report_data[TSM_REPORT_DATA_SIZE] = {};
        memcpy(report_data, sp.digest.iov_base, sp.digest.iov_len);

        /* Under an SVSM, prefer the vTPM service report, which binds the vTPM EK to the SNP report.
         * Fall back to a plain report otherwise. */

        static const TsmReportOptions svsm_options = {
                .service_provider = TSM_SERVICE_PROVIDER_SVSM,
                .service_guid = TSM_SVSM_SERVICE_VTPM,
                .service_guid_set = true,
        };
        options = &svsm_options;
        r = tsm_report_acquire(&IOVEC_MAKE(report_data, sizeof report_data), options, &report);
        if (r == -EPROTONOSUPPORT) {
                log_debug_errno(r, "No SVSM service attestation available, using plain report: %m");
                static const TsmReportOptions default_options = {};
                options = &default_options;
                r = tsm_report_acquire(&IOVEC_MAKE(report_data, sizeof report_data), options, &report);
        }
        if (IN_SET(r, -EOPNOTSUPP, -ENXIO))
                /* Returning an error will fail the whole report signing, so we return
                 * no signature instead which will be ignored by the aggregator. */
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_EMPTY_ARRAY("data"));
        if (r < 0)
                return log_error_errno(r, "Failed to acquire TSM report: %m");

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR("data",
                                        SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_OBJECT(
                                                                        SD_JSON_BUILD_PAIR_STRING("provider", report->provider),
                                                                        JSON_BUILD_PAIR_IOVEC_BASE64("outblob", &report->outblob),
                                                                        SD_JSON_BUILD_PAIR_CONDITION(iovec_is_set(&report->auxblob),
                                                                                        "auxblob", JSON_BUILD_IOVEC_BASE64(&report->auxblob)),
                                                                        SD_JSON_BUILD_PAIR_CONDITION(iovec_is_set(&report->manifestblob),
                                                                                        "manifestblob", JSON_BUILD_IOVEC_BASE64(&report->manifestblob)),
                                                                        SD_JSON_BUILD_PAIR_CONDITION(!!options->service_provider,
                                                                                        "serviceProvider", SD_JSON_BUILD_STRING(options->service_provider)),
                                                                        SD_JSON_BUILD_PAIR_CONDITION(options->service_guid_set,
                                                                                        "serviceGuid", SD_JSON_BUILD_UUID(options->service_guid))))));
}

int report_server_setup(sd_varlink_server *server) {
        return report_server_add_signer_interface(server, vl_method_sign);
}
