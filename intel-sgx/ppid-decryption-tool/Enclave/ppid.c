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

static ref_rsa_params_t g_rsa_key = { 0 };  // The private key used to encrypt the PPID.  Only used for PPID_CEARTEXT Cert_Data_Type

uint32_t pce_get_pc_info(const sgx_report_t *report,
                         const uint8_t *public_key, uint32_t key_size,
                         uint8_t crypto_suite,
                         uint8_t *encrypted_ppid, uint32_t encrypted_ppid_buf_size,
                         uint32_t *encrypted_ppid_out_size,
                         pce_info_t *pce_info,
                         uint8_t *signature_scheme);

uint32_t pce_get_target_info(sgx_target_info_t *pce_target_info);

void print_err_status(char *str, sgx_status_t status);

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
        uint32_t key_size,
        uint8_t* p_public_key)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_report_data_t report_data = { 0 };
    sgx_sha_state_handle_t sha_handle = NULL;
    pce_rsaoaep_3072_encrypt_pub_key_t* p_rsa_pub_key;

    if (p_pce_target_info == NULL || !sgx_is_within_enclave(p_pce_target_info, sizeof(*p_pce_target_info))) {
        print_err_status("p_pce_target_info is null or outside enclave memory. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (p_public_key == NULL || !sgx_is_within_enclave(p_public_key, key_size)) {
        print_err_status("p_public_key is null or outside enclave memory. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (p_ide_report == NULL || !sgx_is_within_enclave(p_ide_report, sizeof(*p_ide_report))) {
        print_err_status("p_ide_report is null or outside enclave memory. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (crypto_suite != PCE_ALG_RSA_OAEP_3072) {
        print_err_status("crypto_suite is not a PCE_ALG_RSA_OAEP_3072. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (key_size != sizeof(*p_rsa_pub_key)) {
        print_err_status("key_size doesn't equal the size of p_rsa_pub_key. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if ((p_pce_target_info->attributes.flags & SGX_FLAGS_PROVISION_KEY) != SGX_FLAGS_PROVISION_KEY ||
        (p_pce_target_info->attributes.flags & SGX_FLAGS_DEBUG) != 0)
    {
        //PCE must have access to provisioning key
        //Can't be debug PCE
        print_err_status("PCE enclave can't be a DEBUG enclave. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
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
        print_err_status("Failed to create RSA key in sgx_create_rsa_key_pair. The error code is: 0x%04x.\n", sgx_status);
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
        sgx_status = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
    } while (0);
    if (SGX_SUCCESS != sgx_status) {
        if (SGX_ERROR_OUT_OF_MEMORY != sgx_status)
            sgx_status = SGX_ERROR_UNEXPECTED;
        print_err_status("Unexpected error when decrypting ppid. The error code is: 0x%04x.\n", sgx_status);
        goto ret_point;
    }

    sgx_status = sgx_create_report(p_pce_target_info, &report_data, p_ide_report);
    if (SGX_SUCCESS != sgx_status && SGX_ERROR_OUT_OF_MEMORY != sgx_status) {
        print_err_status("Unexpected error when creating sgx report in sgx_create_report. The error code is: 0x%04x.\n", sgx_status);
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

/**
 * External function exposed through the EDL used to return the decrypted PPID
 * @param encrypted_ppid_size
 *                 [In] The size in bytes of the supplied p_encrypted_ppid buffer. Currently, it must be equal to the size
 *                  of RSA modulus (REF_RSA_OAEP_3072_MOD_SIZE) which is 384 bytes.
 * @param p_encrypted_ppid
 *                 [In] Pointer to the buffer containing encrypted PPID data. It must not be NULL and full buffer
 *                 must reside in the enclave's memory space.
 * @param ppid
 *                 [In, Out] Pointer to the buffer that will contain the decrypted PPID data. It must
 *                 not be NULL and the buffer must reside within the enclave's memory space. The size of the buffer
 *                 must always be equal to 16 bytes according to the official Intel documentation.

 * @return SGX_SUCCESS Function successfully decrypts the encrypted PPID.
 * @return SGX_ERROR_INVALID_PARAMETER Invalid parameter.
 * @return SGX_ERROR_UNEXPECTED An internal error occurred.
 */
sgx_status_t ide_decrypt_ppid(uint32_t encrypted_ppid_size, uint8_t *p_encrypted_ppid, uint8_t* ppid)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    void *rsa_key = NULL;
    unsigned char* dec_dat = NULL;
    size_t ppid_size = 0;

    if (p_encrypted_ppid == NULL || !sgx_is_within_enclave(p_encrypted_ppid, sizeof(*p_encrypted_ppid))) {
        print_err_status("p_encrypted_ppid is null or outside enclave memory. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ppid == NULL || !sgx_is_within_enclave(ppid, sizeof(*ppid))) {
        print_err_status("ppid is null or outside enclave memory. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // Decrypt the PPID with the RSA private key generated with the new key and store it in the blob
    // Create a private key context
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
        return sgx_status;
    }

    sgx_status = sgx_rsa_priv_decrypt_sha256(rsa_key,
                                             NULL,
                                             (&ppid_size),
                                             p_encrypted_ppid,
                                             REF_RSA_OAEP_3072_MOD_SIZE);

    if (sgx_status != SGX_SUCCESS) {
        print_err_status("Failed to compute size of decrypted ppid in sgx_rsa_priv_decrypt_sha256. The error code is: 0x%04x.\n", sgx_status);
        return sgx_status;
    }

    if (!(dec_dat = (unsigned char*)malloc(ppid_size))) {
        print_err_status("Failed to allocate memory for decrypted ppid. The error code is: 0x%04x.\n", SGX_ERROR_INVALID_PARAMETER);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_status = sgx_rsa_priv_decrypt_sha256(rsa_key,
                                             dec_dat,
                                             (&ppid_size),
                                             p_encrypted_ppid,
                                             REF_RSA_OAEP_3072_MOD_SIZE);

    if (sgx_status != SGX_SUCCESS) {
        print_err_status("Failed to decrypt ppid in sgx_rsa_priv_decrypt_sha256. The error code is: 0x%04x.\n", sgx_status);
        return sgx_status;
    }

    // Copy in the decrypted PPID
    memcpy(ppid, dec_dat, DECRYPTED_PPID_LENGTH);

    return sgx_status;
}

sgx_status_t entry_point(uint8_t *decrypted_ppid) {
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_report_t id_enclave_report;
    uint32_t enc_key_size = REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE;
    uint8_t enc_public_key[REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE];
    uint8_t encrypted_ppid[REF_RSA_OAEP_3072_MOD_SIZE];
    uint32_t encrypted_ppid_ret_size;
    pce_info_t pce_info;
    uint8_t signature_scheme;
    sgx_target_info_t* pce_target_info;

    if (!(pce_target_info = (sgx_target_info_t*)malloc(sizeof(sgx_target_info_t)))) {
        sgx_status = SGX_ERROR_INVALID_PARAMETER;
        print_err_status("Failed to call into the PPID: failed to allocate memory for pce_target_info \n", sgx_status);
        return sgx_status;
    }

    if (SGX_SUCCESS != (sgx_status = pce_get_target_info(pce_target_info))) {
        print_err_status("Failed to call into the PCE: pce_get_target_info. The error code is: 0x%04x.\n", sgx_status);
        return sgx_status;
    }

    sgx_status = ide_get_pce_encrypt_key(pce_target_info,
                                         &id_enclave_report,
                                         PCE_ALG_RSA_OAEP_3072,
                                         enc_key_size,
                                         enc_public_key);

    if (SGX_SUCCESS != sgx_status) {
        print_err_status("Failed to call into the PPID: ide_get_pce_encrypt_key. The error code is: 0x%04x.\n", sgx_status);
        return sgx_status;
    }

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
        return sgx_status;
    }

    if (signature_scheme != PCE_NIST_P256_ECDSA_SHA256) {
        sgx_status = -1;
        print_err_status("PCE returned incorrect signature scheme.\n", sgx_status);
        return sgx_status;
    }

    if (encrypted_ppid_ret_size != ENCRYPTED_PPID_LENGTH) {
        sgx_status = -1;
        print_err_status("PCE returned incorrect encrypted PPID size.\n", sgx_status);
        return sgx_status;
    }

    if (SGX_SUCCESS != (sgx_status = ide_decrypt_ppid(ENCRYPTED_PPID_LENGTH, encrypted_ppid, decrypted_ppid))) {
        print_err_status("Failed to call into the PPID: ide_decrypt_ppid. The error code is: 0x%04x.\n", sgx_status);
        return sgx_status;
    }

    return sgx_status;
}
