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
#include <stdint.h>
#include <errno.h>
#include <gssapi/gssapi.h>
#include "gp_utils.h"
#include "gp_conv.h"
#include "gp_rpc_process.h"

int gp_accept_sec_context(struct gssproxy_ctx *gpctx,
                          union gp_rpc_arg *arg,
                          union gp_rpc_res *res)
{
    struct gssx_arg_accept_sec_context *asca;
    struct gssx_res_accept_sec_context *ascr;
    struct gssx_cred_info *info;
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_ctx_id_t ctx;
    gss_cred_id_t ach;
    gss_name_t desired_name = NULL;
    gss_buffer_desc desired_buffer;
    gss_OID_desc desired_type;
    gss_buffer_desc ibuf;
    struct gss_channel_bindings_struct cbs;
    gss_channel_bindings_t pcbs;
    gss_name_t src_name = NULL;
    gss_OID oid;
    gss_buffer_desc obuf = { 0, NULL };
    uint32_t ret_flags;
    uint32_t time_rec;
    gss_cred_id_t dch;
    int ret;

    asca = &arg->gssx_arg_accept_sec_context_arg;
    ascr = &res->gssx_res_accept_sec_context_res;

    /* FIXME: set context id from asca->call_ctx */
    ctx = GSS_C_NO_CONTEXT;

    if (asca->cred_handle) {
        if (asca->cred_handle->handle_info.handle_type != GSSX_C_HANDLE_CRED) {
            ret = EINVAL;
            goto done;
        }
        if (asca->cred_handle->handle_info.gssx_handle_info_u.cred_info.cred_info_len != 1) {
            ret = EINVAL;
            goto done;
        }
        info = asca->cred_handle->handle_info.gssx_handle_info_u.cred_info.cred_info_val;

        gp_conv_gssx_to_buffer(info->MN.exported_name.exported_name_val,
                               &desired_buffer);
        gp_conv_gssx_to_oid(&info->MN.name_type, &desired_type);

        ret_maj = gss_import_name(&ret_min, &desired_buffer,
                                  &desired_type, &desired_name);
        if (ret_maj) {
            ret = EINVAL;
            goto done;
        }

        ret_maj = gss_acquire_cred(&ret_min, desired_name,
                                info->acceptor_time_rec, /* ?? time_req */
    gss_OID_set,        /* desired_mechs */
                                gp_conv_gssx_to_cred_usage(info->cred_usage),
    gss_cred_id_t *,    /* output_cred_handle */
    gss_OID_set *,      /* actual_mechs */
    OM_uint32 *);       /* time_rec */
    } else {
        ach = GSS_C_NO_CREDENTIAL;
    }

    gp_conv_gssx_to_buffer(&asca->input_token, &ibuf);

    if (asca->input_cb) {
        pcbs = &cbs;
        gp_conv_gssx_to_cb(asca->input_cb, pcbs);
    } else {
        pcbs = GSS_C_NO_CHANNEL_BINDINGS;
    }

    ret_maj = gss_accept_sec_context(&ret_min,
                                     ctx,
                                     ach,
                                     &ibuf,
                                     pcbs,
                                     &src_name,
                                     &oid,
                                     &obuf,
                                     &ret_flags,
                                     &time_rec,
                                     &dch);

    ascr->status.major_status = ret_maj;
    ret = gp_conv_oid_to_gssx(oid, &ascr->status.mech);
    if (ret) {
        goto done;
    }
    ascr->status.minor_status = ret_min;
    if (ret_maj) {
        ret = gp_conv_err_to_gssx_strings(ret_maj, GSS_C_GSS_CODE, oid,
                                          &ascr->status.major_status_string);
        if (ret) {
            goto done;
        }
    }
    if (ret_min) {
        ret = gp_conv_err_to_gssx_strings(ret_min, GSS_C_MECH_CODE, oid,
                                          &ascr->status.minor_status_string);
        if (ret) {
            goto done;
        }
    }

    /* TODO */
    /* ascr->status.server_ctx; */

    if (ret_maj) {
        ret = 0;
        goto done;
    }

    ret = gp_conv_ctx_id_to_gssx(ctx, &ascr->context_handle);
    if (ret) {
        goto done;
    }

    ascr->output_token = malloc(sizeof(gssx_buffer));
    if (!ascr->output_token) {
        ret = ENOMEM;
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(obuf, ascr->output_token);
    if (ret) {
        goto done;
    }

done:
    if (ret) {
    }
    gss_release_name(&ret_min, &desired_name);
    gss_release_name(&ret_min, &src_name);
    gss_release_buffer(&ret_min, &obuf);
    dch
    return ret;
}
