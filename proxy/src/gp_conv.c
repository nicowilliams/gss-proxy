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

int gp_conv_octet_string(size_t length, void *value, octet_string *out)
{
    out->octet_string_val = malloc(length);
    if (!out->octet_string_val) {
        return ENOMEM;
    }
    memcpy(out->octet_string_val, value, length);
    out->octet_string_len = length;
    return 0;
}

void gp_conv_gssx_to_oid(gssx_OID *in, gss_OID out)
{
    out->length = in->octet_string_len;
    out->elements = (void *)in->octet_string_val;
}

int gp_conv_oid_to_gssx(gss_OID in, gssx_OID *out)
{
    return gp_conv_octet_string(in->length, in->elements, out);
}

void gp_conv_gssx_to_buffer(gssx_buffer *in, gss_buffer_t out)
{
    out->length = in->octet_string_len;
    out->value = (void *)in->octet_string_val;
}

int gp_conv_buffer_to_gssx(gss_buffer_t in, gssx_buffer *out)
{
    return gp_conv_octet_string(in->length, in->value, out);
}

void gp_conv_gssx_to_cb(gssx_cb *in, gss_channel_bindings_t out)
{
    out->initiator_addrtype = in->initiator_addrtype;
    gp_conv_gssx_to_buffer(&in->initiator_address, &out->initiator_address);
    out->acceptor_addrtype = in->acceptor_addrtype;
    gp_conv_gssx_to_buffer(&in->acceptor_address, &out->acceptor_address);
    gp_conv_gssx_to_buffer(&in->application_data, &out->application_data);
}

int gp_conv_cb_to_gssx(gss_channel_bindings_t in, gssx_cb *out)
{
    int ret;

    out->initiator_addrtype = in->initiator_addrtype;
    ret = gp_conv_buffer_to_gssx(&in->initiator_address,
                                 &out->initiator_address);
    if (ret) {
        goto done;
    }
    out->acceptor_addrtype = in->acceptor_addrtype;
    ret = gp_conv_buffer_to_gssx(&in->acceptor_address,
                                 &out->acceptor_address);
    if (ret) {
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(&in->application_data,
                                 &out->application_data);
    if (ret) {
        goto done;
    }

    ret = 0;

done:
    if (ret) {
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out->initiator_address);
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out->acceptor_address);
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out->application_data);
    }
    return ret;
}

gssx_cred_usage gp_conv_cred_usage_to_gssx(gss_cred_usage_t in)
{
    switch (in) {
    case GSS_C_BOTH:
        return GSSX_C_BOTH;
    case GSS_C_INITIATE:
        return GSSX_C_INITIATE;
    case GSS_C_ACCEPT:
        return GSSX_C_ACCEPT;
    default:
        return 0;
    }
}

gss_cred_usage_t gp_conv_gssx_to_cred_usage(gssx_cred_usage in)
{
    switch (in) {
    case GSSX_C_BOTH:
        return GSS_C_BOTH;
    case GSSX_C_INITIATE:
        return GSS_C_INITIATE;
    case GSSX_C_ACCEPT:
        return GSS_C_ACCEPT;
    default:
        return 0;
    }
}

int gp_conv_err_to_gssx_string(uint32_t status, int type, gss_OID oid,
                               utf8string *ret_str)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    uint32_t msg_ctx;
    gss_buffer_desc gssbuf;
    char *str, *t;
    int ret;

    msg_ctx = 0;
    str = NULL;
    do {
        ret_maj = gss_display_status(&ret_min,
                                     status, type, oid,
                                     &msg_ctx, &gssbuf);
        if (ret_maj == 0) {
            if (str) {
                ret = asprintf(&t, "%s, %s", str, (char *)gssbuf.value);
                if (ret == -1) {
                    ret_maj = ENOMEM;
                } else {
                    free(str);
                    str = t;
                }
            } else {
                str = strdup((char *)gssbuf.value);
                if (!str) {
                    ret_maj = ENOMEM;
                }
            }
            gss_release_buffer(&ret_min, &gssbuf);
        }
        if (ret_maj) {
            goto done;
        }
    } while (msg_ctx);

    ret_str->utf8string_len = strlen(str + 1);
    ret_str->utf8string_val = str;

done:
    free(str);
    return ret_maj;
}

int gp_conv_name_to_gssx(gss_name_t in, gssx_name *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_buffer_desc name_buffer;
    gss_OID name_type;
    gss_buffer_desc exported_name;
    int ret;

    ret_maj = gss_display_name(&ret_min, in, &name_buffer, &name_type);
    if (ret_maj) {
        return -1;
    }

    out->display_name = malloc(sizeof(gssx_buffer));
    if (!out->display_name) {
        ret = ENOMEM;
        goto done;
    }

    ret = gp_conv_buffer_to_gssx(&name_buffer, out->display_name);
    if (ret) {
        goto done;
    }
    ret = gp_conv_oid_to_gssx(name_type, &out->name_type);
    if (ret) {
        goto done;
    }

    ret_maj = gss_export_name(&ret_min, in, &exported_name);
    if (ret_maj) {
        ret = -1;
        goto done;
    }

    out->exported_name.exported_name_len = 1;
    out->exported_name.exported_name_val = malloc(sizeof(gssx_buffer));
    if (!out->exported_name.exported_name_val) {
        ret = ENOMEM;
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(&exported_name,
                                 out->exported_name.exported_name_val);
    if (ret) {
        goto done;
    }

    /* out->exported_composite_name */
    /* out->name_attributes */

done:
    gss_release_buffer(&ret_min, &name_buffer);
    gss_release_buffer(&ret_min, &exported_name);
    if (ret) {
        if (out->display_name) {
            xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)out->display_name);
            free(out->display_name);
        }
        xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&out->name_type);
        if (out->exported_name.exported_name_val) {
            xdr_free((xdrproc_t)xdr_gssx_buffer,
                     (char *)out->exported_name.exported_name_val);
            free(out->exported_name.exported_name_val);
        }
    }
    return ret;
}

int gp_conv_ctx_id_to_gssx(gss_ctx_id_t in, gssx_ctx *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_name_t src_name = NULL;
    gss_name_t targ_name = NULL;
    uint32_t lifetime_rec;
    gss_OID mech_type;
    uint32_t ctx_flags;
    int is_locally_initiated;
    int is_open;
    int ret;

    ret_maj = gss_inquire_context(&ret_min, in, &src_name, &targ_name,
                                  &lifetime_rec, &mech_type, &ctx_flags,
                                  &is_locally_initiated, &is_open);
    if (ret_maj) {
        return -1;
    }

    /* TODO */
    /* out->exported_context_token; */
    /* out->state; */

    ret = gp_conv_oid_to_gssx(mech_type, &out->mech);
    if (ret) {
        goto done;
    }

    ret = gp_conv_name_to_gssx(src_name, &out->src_name);
    if (ret) {
        goto done;
    }

    ret = gp_conv_name_to_gssx(targ_name, &out->targ_name);
    if (ret) {
        goto done;
    }

    out->lifetime = lifetime_rec;

    out->ctx_flags = ctx_flags;

    if (is_locally_initiated) {
        out->locally_initiated = true;
    }

    if (is_open) {
        out->open = true;
    }

done:
    gss_release_name(&ret_min, &src_name);
    gss_release_name(&ret_min, &targ_name);
    if (ret) {
        xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&out->mech);
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)&out->src_name);
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)&out->targ_name);
    }
    return ret;
}

