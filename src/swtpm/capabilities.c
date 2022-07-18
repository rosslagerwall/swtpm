/*
 * capabilities.c -- capabilities
 *
 * (c) Copyright IBM Corporation 2019.
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the names of the IBM Corporation nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>

#include <json-glib/json-glib.h>

#include "capabilities.h"
#include "logging.h"
#include "swtpm_nvstore.h"

/* Convert the RSA key size indicators supported by libtpms into capability
 * strings.
 * libtpms may return us something like this here:
 * "TPMAttributes":{"manufacturer":"id:00001014",\
 * "version":"id:20191023","model":"swtpm","RSAKeySizes":[1024,2048,3072]}}
 *
 * or an older version may not report RSA keysizes:
 * "TPMAttributes":{"manufacturer":"id:00001014",\
 * "version":"id:20191023","model":"swtpm"}}
 */
static int get_rsa_keysize_caps(char **keysizecaps)
{
    int ret = 0;
    char *start, *endptr;
    const char *needle = "\"RSAKeySizes\":[";
    char *info_data = TPMLIB_GetInfo(4 /*TPMLIB_INFO_TPMFEATURES*/);
    char buffer[128];
    off_t offset = 0;
    int n;

    if (!info_data)
        goto cleanup;

    start = strstr(info_data, needle);
    if (start) {
        start += strlen(needle);
        while (1) {
            unsigned long int keysize = strtoul(start, &endptr, 10);

            if (*endptr != ',' && *endptr != ']') {
                logprintf(STDERR_FILENO, "Malformed TPMLIB_GetInfo() string\n");
                ret = -1;
                goto cleanup;
            }

            n = snprintf(buffer + offset, sizeof(buffer) - offset,
                         ", \"rsa-keysize-%lu\"",
                          keysize);
            if (n < 0 || (unsigned)n >= sizeof(buffer) - offset) {
                logprintf(STDERR_FILENO, "%s: buffer is too small\n", __func__);
                ret = -1;
                goto cleanup;
            }
            if (*endptr == ']')
                break;

            offset += n;
            start = endptr + 1;
        }

        *keysizecaps = strndup(buffer, sizeof(buffer) - 1);
        if (*keysizecaps == NULL)
            goto oom;
    }

cleanup:
    free(info_data);
    return ret;

oom:
    logprintf(STDERR_FILENO, "Out of memory\n");
    ret = -1;
    goto cleanup;
}

#ifdef HAVE_LIBTPMS_SETPROFILE_API

static int get_profiles(gchar **profiles)
{
    char *info_data = TPMLIB_GetInfo(32 /*TPMLIB_INFO_AVAILABLE_PROFILES*/);
    JsonParser *jp = NULL;
    JsonReader *jr = NULL;
    GError *error = NULL;
    JsonNode *root;
    gint i, num;
    int ret = 0;
    GString *gstr = g_string_new(NULL);

    jp = json_parser_new();

    if (!json_parser_load_from_data(jp, info_data, -1, &error)) {
        logprintf(STDERR_FILENO,
                  "Could not parse JSON data: %s\n", error->message);
        g_error_free(error);
        goto error;
    }

    root = json_parser_get_root(jp);
    jr = json_reader_new(root);

    if (!json_reader_read_member(jr, "AvailableProfiles")) {
        logprintf(STDERR_FILENO,
                  "Missing 'AvailableProfiles' field: %s\n",
                  info_data);
        goto error_unref_jr;
    }

    num = json_reader_count_elements(jr);
    for (i = 0; i < num; i++) {
        if (!json_reader_read_element(jr, i) ||
            !json_reader_read_member(jr, "name")) {
            logprintf(STDERR_FILENO,
                      "Failed to traverse JSON list.\n");
            goto error_unref_jr;
        }
        g_string_append_printf(gstr, "%s\"%s\"",
                               i > 0 ? ", " : " ",
                               json_reader_get_string_value(jr));
        json_reader_end_element(jr);
        json_reader_end_element(jr);
    }


error_unref_jr:
    g_object_unref(jr);

error:
    g_object_unref(jp);
    *profiles = g_string_free(gstr, false);
    free(info_data);

    return ret;
}

#else

static int get_profiles(gchar **profiles SWTPM_UNUSED)
{
    return 0;
}

#endif

int capabilities_print_json(bool cusetpm, TPMLIB_TPMVersion tpmversion)
{
    char *string = NULL;
    int ret = -1;
    int n;
#ifdef WITH_SECCOMP
    const char *cmdarg_seccomp = "\"cmdarg-seccomp\", ";
#else
    const char *cmdarg_seccomp = "";
#endif
    const char *with_tpm1 = "";
    const char *with_tpm2 = "";
    char *keysizecaps = NULL;
    const char *nvram_backend_dir = "\"nvram-backend-dir\", ";
    const char *nvram_backend_file = "\"nvram-backend-file\"";
#ifdef HAVE_LIBTPMS_SETPROFILE_API
    g_autofree gchar *profiles = NULL;
    const char *cmdarg_profile = "\"cmdarg-profile\"";
#else
    const char *cmdarg_profile = NULL;
#endif
    bool comma1;

    if (TPMLIB_ChooseTPMVersion(tpmversion) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO, "Could not choose TPM version.\n");
        goto cleanup;
    }

    ret = get_rsa_keysize_caps(&keysizecaps);
    if (ret < 0)
        goto cleanup;

    if (tpmversion == TPMLIB_TPM_VERSION_2) {
        ret = get_profiles(&profiles);
        if (ret < 0)
            goto cleanup;
    }

    if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_1_2) == TPM_SUCCESS)
        with_tpm1 = "\"tpm-1.2\", ";
    if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) == TPM_SUCCESS)
        with_tpm2 = "\"tpm-2.0\", ";

    comma1 = keysizecaps || cmdarg_profile;

    n =  asprintf(&string,
         "{ "
         "\"type\": \"swtpm\", "
         "\"features\": [ "
             "%s%s%s%s%s%s%s%s%s%s%s%s%s"
          " ], "
#ifdef HAVE_LIBTPMS_SETPROFILE_API
         "\"profiles\": [%s ], "
#endif
         "\"version\": \"" VERSION "\" "
         "}",
         with_tpm1,
         with_tpm2,
         !cusetpm     ? "\"tpm-send-command-header\", ": "",
         true         ? "\"flags-opt-startup\", "      : "",
         cmdarg_seccomp,
         true         ? "\"cmdarg-key-fd\", "          : "",
         true         ? "\"cmdarg-pwd-fd\", "          : "",
         true         ? "\"cmdarg-print-states\", "    : "",
         nvram_backend_dir,
         nvram_backend_file,
         keysizecaps  ? keysizecaps                    : "",
         comma1       ? ", "                           : "",
         cmdarg_profile ? cmdarg_profile               : ""
#ifdef HAVE_LIBTPMS_SETPROFILE_API
                                                           ,
         profiles     ? profiles                       : ""
#endif
    );

    if (n < 0) {
        logprintf(STDERR_FILENO, "Out of memory\n");
        goto cleanup;
    }

    ret = 0;

    fprintf(stdout, "%s\n", string);

cleanup:
    free(keysizecaps);
    free(string);

    return ret;
}
