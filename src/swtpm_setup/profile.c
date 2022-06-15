/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * profile.c: TPM 2 profile handling
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2022
 */

#include "config.h"

#include "profile.h"
#include "swtpm_utils.h"

#include <json-glib/json-glib.h>

int check_json_profile(const char *json_profile)
{
    JsonParser *jp = NULL;
    JsonReader *jr = NULL;
    GError *error = NULL;
    JsonNode *root;
    int ret = -1;

    jp = json_parser_new();

    if (!json_parser_load_from_data(jp, json_profile, -1, &error)) {
        logerr(gl_LOGFILE, "Could not parse JSON profile: %s\n", error->message);
        g_error_free(error);
        goto error;
    }

    root = json_parser_get_root(jp);
    jr = json_reader_new(root);

    if (!json_reader_read_member(jr, "name")) {
        logerr(gl_LOGFILE, "Missing required 'name' field in JSON profile.\n");
        goto error_unref_jr;
    }

    ret = 0;

error_unref_jr:
    g_object_unref(jr);

error:
    g_object_unref(jp);
    return ret;
}
