/* dns_dyn.h
 *
 * Copyright (c) 2010-2013 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef NDYNDNS_DNS_DYN_H_
#define NDYNDNS_DNS_DYN_H_

#include "cfg.h"

typedef enum {
    WC_NOCHANGE,
    WC_YES,
    WC_NO
} wc_state;

typedef enum {
    BMX_NOCHANGE,
    BMX_YES,
    BMX_NO
} backmx_state;

typedef enum {
    OFFLINE_NO,
    OFFLINE_YES
} offline_state;

typedef enum {
    SYSTEM_DYNDNS,
    SYSTEM_STATDNS,
    SYSTEM_CUSTOMDNS
} dyndns_system;

typedef struct {
    char *username;
    char *password;
    hostdata_t *hostlist;
    char *mx;
    wc_state wildcard;
    backmx_state backmx;
    offline_state offline;
    dyndns_system system;
} dyndns_conf_t;

extern dyndns_conf_t dyndns_conf;
void init_dyndns_conf();

void dd_work(char *curip);

#endif
