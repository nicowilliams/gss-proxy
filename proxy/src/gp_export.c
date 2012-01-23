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
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include "gp_conv.h"
#include "gp_export.h"

/* FIXME: F I X M E
 *
 * FFFFF  I  X    X  M    M  EEEEE
 * F      I   X  X   MM  MM  E
 * FFF    I    XX    M MM M  EEE
 * F      I   X  X   M    M  E
 * F      I  X    X  M    M  EEEEE
 *
 * Credential functions should either be implemented with gss_export_cred()
 * or, lacking those calls in the gssapi implementation, by keeping state
 * in a table/list and returning a token.
 * In both cases the content should be encrypted.
 *
 * Temporarily we simply return straight out the gss_cred_id_t pointer as
 * a handle.
 *
 * THIS IS ONLY FOR THE PROTOTYPE
 *
 * *MUST* BE FIXED BEFORE ANY OFFICIAL RELEASE.
 */

int gp_export_gssx_cred(gss_cred_id_t *in, gssx_cred *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_name_t name;
    uint32_t lifetime;
    gss_cred_usage_t cred_usage;
    gss_OID_set mechanisms;
    int ret;

    ret_maj = gss_inquire_cred(&ret_min, *in,
                               &name, &lifetime, &cred_usage, &mechanisms);
    if (ret_maj) {
        ret = EINVAL;
        goto done;
    }

    out->cred_usage = gp_conv_gssx_to_cred_usage(cred_usage);

    ret = gp_conv_octet_string(sizeof(gss_cred_id_t), *in,
                               &out->cred_handle_reference);
    if (ret) {
        goto done;
    }
    out->needs_release = true;

    /* we take over control of the credentials from here on */
    /* when we will have gss_export_cred() we will actually free
     * them immediately instead */
    *in = NULL;

done:
    if (ret) {
    }
    return ret;
}

int gp_import_gssx_cred(octet_string *in, gss_cred_id_t *out)
{
    return 0;
}

