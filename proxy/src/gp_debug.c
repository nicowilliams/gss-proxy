/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#include "config.h"
#include <gssapi/gssapi.h>
#include "gp_debug.h"

/* global debug switch */
int gp_debug;

void gp_debug_enable(void)
{
    gp_debug = 1;
    GPDEBUG("Debug Enabled\n");
}

void gp_log_failure(gss_OID mech, uint32_t maj, uint32_t min)
{
    uint32_t msgctx;
    uint32_t discard;
    gss_buffer_desc tmp;

    fprintf(stderr, "Failed with:");

    if (mech != GSS_C_NO_OID) {
        gss_oid_to_str(&discard, mech, &tmp);
        fprintf(stderr, " (OID: %s)", (char *)tmp.value);
        gss_release_buffer(&discard, &tmp);
    }

    msgctx = 0;
    gss_display_status(&discard, maj, GSS_C_GSS_CODE, mech, &msgctx, &tmp);
    fprintf(stderr, " %s,", (char *)tmp.value);
    gss_release_buffer(&discard, &tmp);

    msgctx = 0;
    gss_display_status(&discard, min, GSS_C_MECH_CODE, mech, &msgctx, &tmp);
    fprintf(stderr, " %s\n", (char *)tmp.value);
    gss_release_buffer(&discard, &tmp);
}
