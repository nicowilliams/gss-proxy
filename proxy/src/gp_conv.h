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

#ifndef _GSS_CONV_H_
#define _GSS_CONV_H_

#include <gssapi/gssapi.h>
#include "rpcgen/gss_proxy.h"

int gp_conv_octet_string(size_t length, void *value, octet_string *out);

void gp_conv_gssx_to_oid(gssx_OID *in, gss_OID out);
int gp_conv_oid_to_gssx(gss_OID in, gssx_OID *out);

void gp_conv_gssx_to_buffer(gssx_buffer *in, gss_buffer_t out);
int gp_conv_buffer_to_gssx(gss_buffer_t in, gssx_buffer *out);

void gp_conv_gssx_to_cb(gssx_cb *in, gss_channel_bindings_t out);
int gp_conv_cb_to_gssx(gss_channel_bindings_t in, gssx_cb *out);

gssx_cred_usage gp_conv_cred_usage_to_gssx(gss_cred_usage_t in);
gss_cred_usage_t gp_conv_gssx_to_cred_usage(gssx_cred_usage in);

int gp_conv_err_to_gssx_string(uint32_t status, int type, gss_OID oid,
                               utf8string *ret_str);

int gp_conv_name_to_gssx(gss_name_t in, gssx_name *out);

int gp_conv_ctx_id_to_gssx(gss_ctx_id_t in, gssx_ctx *out);

#endif /* _GSS_CONV_H_ */
