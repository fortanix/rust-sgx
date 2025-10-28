/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _PCE_CERT_H_
#define _PCE_CERT_H_
#include "sgx_tcrypto.h"

/*type for Platform Certificate Enclave information*/
typedef struct _pce_info_t{
    sgx_isv_svn_t pce_isvn;  /*PCE ISVSVN*/
    uint16_t      pce_id;
}pce_info_t;

typedef struct _psvn_t{
    sgx_cpu_svn_t    cpu_svn;
    sgx_isv_svn_t    isv_svn; /*PvE/QE SVN*/
}psvn_t;


#endif
