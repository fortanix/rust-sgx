/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include <string.h>
#include <inttypes.h>
#include <sgx_error.h>
#include <sgx_quote_3.h>
#include <sgx_utils.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <stdlib.h>
#include "../pce/pce_cert.h"

#define REF_N_SIZE_IN_BYTES    384
#define REF_E_SIZE_IN_BYTES    4
#define REF_D_SIZE_IN_BYTES    384
#define REF_P_SIZE_IN_BYTES    192
#define REF_Q_SIZE_IN_BYTES    192
#define REF_DMP1_SIZE_IN_BYTES 192
#define REF_DMQ1_SIZE_IN_BYTES 192
#define REF_IQMP_SIZE_IN_BYTES 192

#define REF_RSA_OAEP_3072_MOD_SIZE   384 //hardcode n size to be 384
#define REF_RSA_OAEP_3072_EXP_SIZE     4 //hardcode e size to be 4
#define ENCRYPTED_PPID_LENGTH 384
#define DECRYPTED_PPID_LENGTH 16

/** Structure definition of the RSA key used to decrypt the PCE's PPID */
typedef struct _pce_rsaoaep_3072_encrypt_pub_key_t {
    uint8_t n[REF_RSA_OAEP_3072_MOD_SIZE];   ///< RSA 3072 public modulus
    uint8_t e[REF_RSA_OAEP_3072_EXP_SIZE];   ///< RSA 3072 public exponent
} pce_rsaoaep_3072_encrypt_pub_key_t;

#define REF_N_SIZE_IN_UINT     REF_N_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_E_SIZE_IN_UINT     REF_E_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_D_SIZE_IN_UINT     REF_D_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_P_SIZE_IN_UINT     REF_P_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_Q_SIZE_IN_UINT     REF_Q_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_DMP1_SIZE_IN_UINT  REF_DMP1_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_DMQ1_SIZE_IN_UINT  REF_DMQ1_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_IQMP_SIZE_IN_UINT  REF_IQMP_SIZE_IN_BYTES/sizeof(unsigned int)

typedef struct _ref_rsa_params_t {
    unsigned int n[REF_N_SIZE_IN_UINT];
    unsigned int e[REF_E_SIZE_IN_UINT];
    unsigned int d[REF_D_SIZE_IN_UINT];
    unsigned int p[REF_P_SIZE_IN_UINT];
    unsigned int q[REF_Q_SIZE_IN_UINT];
    unsigned int dmp1[REF_DMP1_SIZE_IN_UINT];
    unsigned int dmq1[REF_DMQ1_SIZE_IN_UINT];
    unsigned int iqmp[REF_IQMP_SIZE_IN_UINT];
}ref_rsa_params_t;

uint32_t pce_get_pc_info(const sgx_report_t *report,
                         const uint8_t *public_key, uint32_t key_size,
                         uint8_t crypto_suite,
                         uint8_t *encrypted_ppid, uint32_t encrypted_ppid_buf_size,
                         uint32_t *encrypted_ppid_out_size,
                         pce_info_t *pce_info,
                         uint8_t *signature_scheme);

uint32_t pce_get_target_info(sgx_target_info_t *pce_target_info);

void print_err_status(char *str, sgx_status_t status);

sgx_status_t entry_point(uint8_t *decrypted_ppid) {
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_report_t id_enclave_report;

    sgx_target_info_t* pce_target_info;
    sgx_report_data_t report_data = { 0 };

    if (!(pce_target_info = (sgx_target_info_t*)malloc(sizeof(sgx_target_info_t)))) {
        sgx_status = SGX_ERROR_INVALID_PARAMETER;
        print_err_status("Failed to call into the PPID: failed to allocate memory for pce_target_info \n", sgx_status);
        goto CLEANUP;
    }

    if (SGX_SUCCESS != (sgx_status = pce_get_target_info(pce_target_info))) {
        print_err_status("Failed to call into the PCE: pce_get_target_info. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }

    if ((pce_target_info->attributes.flags & SGX_FLAGS_PROVISION_KEY) != SGX_FLAGS_PROVISION_KEY ||
        (pce_target_info->attributes.flags & SGX_FLAGS_DEBUG) != 0)
    {
        //PCE must have access to provisioning key
        //Can't be debug PCE
        print_err_status("PCE enclave can't be a DEBUG enclave. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        goto CLEANUP;
    }

    uint32_t enc_key_size = REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE;
    uint8_t enc_public_key[REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE];
    ref_rsa_params_t g_rsa_key = { 0 };
    g_rsa_key.e[0] = 0x10001;
    pce_rsaoaep_3072_encrypt_pub_key_t* p_rsa_pub_key = (pce_rsaoaep_3072_encrypt_pub_key_t*)enc_public_key;

    sgx_status = sgx_create_rsa_key_pair(REF_RSA_OAEP_3072_MOD_SIZE,
                                         REF_RSA_OAEP_3072_EXP_SIZE,
                                         (unsigned char*)g_rsa_key.n,
                                         (unsigned char*)g_rsa_key.d,
                                         (unsigned char*)g_rsa_key.e,
                                         (unsigned char*)g_rsa_key.p,
                                         (unsigned char*)g_rsa_key.q,
                                         (unsigned char*)g_rsa_key.dmp1,
                                         (unsigned char*)g_rsa_key.dmq1,
                                         (unsigned char*)g_rsa_key.iqmp);
    if (sgx_status != SGX_SUCCESS) {
        print_err_status("Failed to create RSA key in sgx_create_rsa_key_pair. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }

    // PCE wants the key in big endian
    size_t i;
    uint8_t* p_temp;
    p_temp = (uint8_t*)g_rsa_key.e;
    for (i = 0; i < REF_RSA_OAEP_3072_EXP_SIZE; i++) {
        p_rsa_pub_key->e[i] = *(p_temp + REF_RSA_OAEP_3072_EXP_SIZE - 1 - i); //create big endian e
    }
    p_temp = (uint8_t*)g_rsa_key.n;
    for (i = 0; i < REF_RSA_OAEP_3072_MOD_SIZE; i++) {
        p_rsa_pub_key->n[i] = *(p_temp + REF_RSA_OAEP_3072_MOD_SIZE - 1 - i); //create big endian n
    }

    sgx_sha_state_handle_t sha_handle = NULL;
    uint8_t crypto_suite = PCE_ALG_RSA_OAEP_3072;
    do {
        sgx_status = sgx_sha256_init(&sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;

        sgx_status = sgx_sha256_update(&crypto_suite,
            sizeof(uint8_t),
            sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        //(MOD followed by e)
        sgx_status = sgx_sha256_update(p_rsa_pub_key->n,
            sizeof(p_rsa_pub_key->n),
            sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        sgx_status = sgx_sha256_update(p_rsa_pub_key->e,
            sizeof(p_rsa_pub_key->e),
            sha_handle);
        if (SGX_SUCCESS != sgx_status)
            break;
        sgx_status = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
    } while (0);
    if (SGX_SUCCESS != sgx_status) {
        if (SGX_ERROR_OUT_OF_MEMORY != sgx_status)
            sgx_status = SGX_ERROR_UNEXPECTED;
        print_err_status("Unexpected error when decrypting ppid. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }

    sgx_status = sgx_create_report(pce_target_info, &report_data, &id_enclave_report);
    if (SGX_SUCCESS != sgx_status && SGX_ERROR_OUT_OF_MEMORY != sgx_status) {
        print_err_status("Unexpected error when creating sgx report in sgx_create_report. The error code is: 0x%04x.\n", sgx_status);
        sgx_status = SGX_ERROR_UNEXPECTED;
        goto CLEANUP;
    }

    uint8_t encrypted_ppid[REF_RSA_OAEP_3072_MOD_SIZE];
    uint32_t encrypted_ppid_ret_size;
    pce_info_t pce_info;
    uint8_t signature_scheme;

    sgx_status = pce_get_pc_info(&id_enclave_report,
                                 enc_public_key,
                                 enc_key_size,
                                 PCE_ALG_RSA_OAEP_3072,
                                 encrypted_ppid,
                                 REF_RSA_OAEP_3072_MOD_SIZE,
                                 &encrypted_ppid_ret_size,
                                 &pce_info,
                                 &signature_scheme);

    if (SGX_SUCCESS != sgx_status) {
        print_err_status("Failed to call into the PCE: pce_get_pc_info. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }

    if (signature_scheme != PCE_NIST_P256_ECDSA_SHA256) {
        sgx_status = -1;
        print_err_status("PCE returned incorrect signature scheme.\n", sgx_status);
        goto CLEANUP;
    }

    if (encrypted_ppid_ret_size != ENCRYPTED_PPID_LENGTH) {
        sgx_status = -1;
        print_err_status("PCE returned incorrect encrypted PPID size.\n", sgx_status);
        goto CLEANUP;
    }

    // Decrypt the PPID with the RSA private key generated with the new key and store it in the blob
    // Create a private key context
    void *rsa_key = NULL;
    sgx_status = sgx_create_rsa_priv2_key(REF_RSA_OAEP_3072_MOD_SIZE,
                                          REF_E_SIZE_IN_BYTES,
                                          (const unsigned char*)g_rsa_key.e,
                                          (const unsigned char*)g_rsa_key.p,
                                          (const unsigned char*)g_rsa_key.q,
                                          (const unsigned char*)g_rsa_key.dmp1,
                                          (const unsigned char*)g_rsa_key.dmq1,
                                          (const unsigned char*)g_rsa_key.iqmp,
                                          &rsa_key);

    if (sgx_status != SGX_SUCCESS) {
        print_err_status("Failed to create RSA private key in sgx_create_rsa_priv2_key. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }

    size_t ppid_size = 0;
    sgx_status = sgx_rsa_priv_decrypt_sha256(rsa_key,
                                             NULL,
                                             (&ppid_size),
                                             encrypted_ppid,
                                             REF_RSA_OAEP_3072_MOD_SIZE);

    if (sgx_status != SGX_SUCCESS) {
        print_err_status("Failed to compute size of decrypted ppid in sgx_rsa_priv_decrypt_sha256. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }

    unsigned char* dec_dat = NULL;

    if (!(dec_dat = (unsigned char*)malloc(ppid_size))) {
        sgx_status = SGX_ERROR_INVALID_PARAMETER;
        print_err_status("Failed to allocate memory for decrypted ppid. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }
    sgx_status = sgx_rsa_priv_decrypt_sha256(rsa_key,
                                             dec_dat,
                                             (&ppid_size),
                                             encrypted_ppid,
                                             REF_RSA_OAEP_3072_MOD_SIZE);

    if (sgx_status != SGX_SUCCESS) {
        print_err_status("Failed to decrypt ppid in sgx_rsa_priv_decrypt_sha256. The error code is: 0x%04x.\n", sgx_status);
        goto CLEANUP;
    }

    // Copy in the decrypted PPID
    memcpy(decrypted_ppid, dec_dat, DECRYPTED_PPID_LENGTH);

    CLEANUP:
    // Clear critical output data on error
    if (SGX_SUCCESS != sgx_status) {
        memset_s(&id_enclave_report, sizeof(id_enclave_report), 0, sizeof(id_enclave_report));
    }
    if (sha_handle != NULL) {
        sgx_sha256_close(sha_handle);
    }

    return sgx_status;
}
