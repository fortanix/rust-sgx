/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 /**
  * File: id_enclave.cpp
  *
  * Description: Get QE_ID for TD-based quoting
  *
  */

#include <string.h>
#include <inttypes.h>
#include <sgx_error.h>
#include <sgx_quote_3.h>
#include <sgx_utils.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <stdlib.h>

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

static ref_rsa_params_t g_rsa_key = { 0 };  // The private key used to encrypt the PPID.  Only used for PPID_CEARTEXT Cert_Data_Type

#define DECRYPTED_PPID_LENGTH 16

/**
 * External function exposed through the EDL used to return the QE report and the PPID encryption key required to get
 * the PCE identity information.  The PCE requires that the PPID be encrypted with a public key.  The reference supports
 * 1 type of certification data:
 *      1.  PPID_RSA3072_ENCRYPTED.
 * For PPID_RSA3072_ENCRYPTED, the QE will use the hardcoded public key owned by the quote verifier.
 *
 * @param p_pce_target_info
 *                 [In] Pointer to the target_info buffer of the PCE. It must not be NULL and the full target info
 *                 buffer must reside in the enclave's memory space.
 * @param p_ide_report
 *                 [Out] Pointer to the QE report buffer targeting the PCE. It must not be NULL and full report
 *                 buffer must reside in the enclave's memory space.
 * @param crypto_suite
 *                 [In] Indicates the crypto algorithm to use to encrypt the PPID. Currently, only RSA3072 keys are
 *                 supported.  This is the type of key this function will generate.
 * @param key_size [In] The size in bytes of the supplied p_public_key buffer.  Currently, it must be equal to the size
 *                 of an RSA3072 public key. 4 bytes 'e' and 384 bytes 'n'.
 * @param p_public_key
 *                 [In, Out] Pointer to the buffer that will contain the public key used to encrypt the PPID. It must
 *                 not be NULL and the buffer must reside within the enclave's memory space.
 *
 * @return SGX_SUCCESS Function successfully generated or retrieved the encryption key and generated a REPORT
 *         targeting the PCE.
 * @return SGX_ERROR_INVALID_PARAMETER Invalid parameter.
 * @return SGX_ERROR_UNEXPECTED An internal error occurred.
 */
sgx_status_t ide_get_pce_encrypt_key(
    const sgx_target_info_t* p_pce_target_info,
    sgx_report_t* p_ide_report,
    uint8_t crypto_suite,
    uint16_t cert_key_type,
    uint32_t key_size,
    uint8_t* p_public_key)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_report_data_t report_data = { 0 };
    sgx_sha_state_handle_t sha_handle = NULL;
    pce_rsaoaep_3072_encrypt_pub_key_t* p_rsa_pub_key;

    if (p_pce_target_info == NULL || !sgx_is_within_enclave(p_pce_target_info, sizeof(*p_pce_target_info))) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (p_public_key == NULL || !sgx_is_within_enclave(p_public_key, key_size)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (p_ide_report == NULL || !sgx_is_within_enclave(p_ide_report, sizeof(*p_ide_report))) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (crypto_suite != PCE_ALG_RSA_OAEP_3072) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (key_size != sizeof(*p_rsa_pub_key)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if ((p_pce_target_info->attributes.flags & SGX_FLAGS_PROVISION_KEY) != SGX_FLAGS_PROVISION_KEY ||
        (p_pce_target_info->attributes.flags & SGX_FLAGS_DEBUG) != 0)
    {
        //PCE must have access to provisioning key
        //Can't be debug PCE
        return(SGX_ERROR_INVALID_PARAMETER);
    }

    g_rsa_key.e[0] = 0x10001;
    p_rsa_pub_key = (pce_rsaoaep_3072_encrypt_pub_key_t*)p_public_key;

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
        return sgx_status;
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
        // !!! This is the translation of C++ code into C code. The previous code looked like this:
        // sgx_status = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)reinterpret_cast<sgx_sha256_hash_t *>(&report_data));
        sgx_status = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
    } while (0);
    if (SGX_SUCCESS != sgx_status) {
        if (SGX_ERROR_OUT_OF_MEMORY != sgx_status)
            sgx_status = SGX_ERROR_UNEXPECTED;
        goto ret_point;
    }

    sgx_status = sgx_create_report(p_pce_target_info, &report_data, p_ide_report);
    if (SGX_SUCCESS != sgx_status && SGX_ERROR_OUT_OF_MEMORY != sgx_status) {
        sgx_status = SGX_ERROR_UNEXPECTED;
    }

    ret_point:
    // Clear critical output data on error
    if (SGX_SUCCESS != sgx_status) {
        memset_s(p_ide_report, sizeof(*p_ide_report), 0, sizeof(*p_ide_report));
    }
    if (sha_handle != NULL) {
        sgx_sha256_close(sha_handle);
    }

    return sgx_status;
}

sgx_status_t ide_decrypt_ppid(uint32_t encrypted_ppid_size, uint8_t *p_encrypted_ppid, uint8_t* ppid)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    void *rsa_key = NULL;
    unsigned char* dec_dat = NULL;
    size_t ppid_size = 0;
    // Decrypt the PPID with the RSA private key generated with the new key and store it in the blob
    // Create a private key context
    /// todo: add a check to see if the private key was lost due to enlave unload or power loss.
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
        return sgx_status;
    }

    sgx_status = sgx_rsa_priv_decrypt_sha256(rsa_key,
                                             NULL,
                                             (&ppid_size),
                                             p_encrypted_ppid,
                                             REF_RSA_OAEP_3072_MOD_SIZE);

    if (sgx_status != SGX_SUCCESS) {
        return sgx_status;
    }

    if (!(dec_dat = (unsigned char*)malloc(ppid_size))) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_status = sgx_rsa_priv_decrypt_sha256(rsa_key,
                                                   dec_dat,
                                                   (&ppid_size),
                                                   p_encrypted_ppid,
                                                   REF_RSA_OAEP_3072_MOD_SIZE);

    if (sgx_status != SGX_SUCCESS) {
        return sgx_status;
    }

    // Copy in the decrypted PPID
    memcpy(ppid, dec_dat, DECRYPTED_PPID_LENGTH);

    return sgx_status;
}
