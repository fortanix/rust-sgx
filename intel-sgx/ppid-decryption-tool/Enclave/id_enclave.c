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


static const uint8_t g_ref_pubkey_e_be[REF_E_SIZE_IN_BYTES] = { 0x00,0x01,0x00,0x01 };
static const uint8_t g_ref_pubkey_n_be[REF_N_SIZE_IN_BYTES] =
{ 0xd3,0x96,0xf9,0x43,0x43,0x11,0x00,0x1c,0x69,0x44,0x9c,0x3b,0xfd,0xee,0x8f,0x38,
0xcd,0x95,0xcd,0xad,0x74,0x09,0x7c,0x87,0xf1,0xa7,0x65,0x02,0x4c,0x87,0xc1,0x57,
0x30,0xa5,0xc9,0xa6,0xa4,0xcc,0xf9,0x1d,0x62,0x18,0x1e,0x00,0xa6,0x74,0x27,0x58,
0x59,0xca,0x1b,0x1d,0xf5,0x31,0x0e,0xf2,0xd5,0xe1,0x79,0x37,0x39,0x94,0x3d,0x3d,
0xe2,0x50,0x93,0x12,0xd6,0x03,0xe5,0x19,0x3a,0x48,0xf0,0xae,0x0c,0x37,0xee,0xe0,
0x57,0x27,0xbd,0xec,0x17,0x1b,0x0f,0x39,0x86,0x06,0x54,0x20,0x74,0x84,0x34,0xbe,
0x34,0xfa,0x71,0x6f,0xa1,0xf5,0x4c,0x9a,0x52,0x0f,0xc4,0xbc,0x2d,0x7a,0x2e,0x17,
0xe3,0x5d,0xa2,0x0e,0xca,0x39,0x07,0x98,0xa9,0x05,0x1a,0x34,0xfb,0x8f,0x60,0x9c,
0x3a,0x1e,0x26,0x30,0x0b,0xf3,0xf3,0x49,0x40,0xd9,0xf7,0x5d,0xcb,0xd1,0xbf,0x57,
0x8d,0xe5,0x2d,0xce,0x98,0x57,0x35,0xf1,0x93,0xc3,0x19,0x2e,0x80,0x55,0x37,0xab,
0x8d,0x64,0x08,0xda,0xe6,0xdd,0x64,0xb4,0x62,0x83,0x8d,0x43,0xaa,0xd2,0x7b,0xc2,
0x63,0xaa,0x97,0xde,0xed,0x09,0x92,0xd6,0x88,0x56,0x86,0xcd,0x08,0x23,0x03,0x27,
0x9a,0x78,0x7c,0xf4,0x36,0x12,0xf5,0xb1,0xe6,0x1d,0x54,0xab,0x88,0x69,0xff,0x18,
0x4f,0xdc,0x87,0xee,0x34,0xa6,0x68,0xb1,0x81,0x67,0xb6,0xce,0x0a,0x70,0x14,0xbc,
0xb3,0xe1,0x8d,0x76,0x1c,0x73,0xde,0x00,0xab,0x41,0xca,0x40,0x51,0x53,0x63,0x04,
0xc3,0x63,0x0b,0xca,0x62,0xda,0xaa,0x9c,0xe5,0x01,0xb7,0xc0,0x0f,0x7e,0x0b,0xb0,
0xbe,0xe9,0xf8,0x0d,0xb3,0xb6,0x64,0xfd,0xcd,0x95,0x17,0x9c,0x57,0x8e,0xec,0xc4,
0xac,0x8b,0x36,0x01,0x5e,0x4c,0x6d,0x1e,0x21,0x49,0xa0,0x1d,0xde,0x04,0x39,0x6b,
0x34,0x68,0x44,0xea,0x06,0x76,0xe0,0x8d,0x1f,0xa2,0xc0,0x26,0x05,0xcc,0x91,0xbe,
0xa3,0x17,0xc8,0x75,0x46,0x85,0x10,0x39,0x16,0x50,0x8e,0x02,0x43,0x98,0x31,0x70,
0x69,0xd8,0x34,0x71,0x82,0xe7,0x48,0x26,0xcd,0xc1,0x82,0xd3,0xeb,0x6f,0xe9,0x58,
0xe7,0x06,0x77,0x10,0x1f,0xdf,0x49,0x76,0x30,0xa7,0x68,0x42,0xb0,0x16,0xd7,0xda,
0x92,0x75,0xd5,0x7f,0x2e,0x75,0x43,0xac,0x83,0xb0,0x1f,0xc3,0x90,0x19,0xce,0xaa,
0x94,0xd0,0x2e,0x5a,0x6c,0x13,0x72,0xe7,0xa6,0xb5,0xc0,0x45,0x81,0xe3,0x53,0x27 };

/** Structure definition of the RSA key used to decrypt the PCE's PPID */
typedef struct _pce_rsaoaep_3072_encrypt_pub_key_t {
    uint8_t n[REF_RSA_OAEP_3072_MOD_SIZE];   ///< RSA 3072 public modulus
    uint8_t e[REF_RSA_OAEP_3072_EXP_SIZE];   ///< RSA 3072 public exponent
} pce_rsaoaep_3072_encrypt_pub_key_t;

static const char QE_ID_STRING[] = "QE_ID_DER";

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
 * @param cert_key_type
 *                 [In] Indicates whether to use the hard-coded public key or generate a new one.  This option allows
 *                  the reference to demonstrate creating an encryption key on-demand or to use the hard-coded value.
 *                  Using the hard-coded value typically means the PPID is to remain private on the platform. Must be
 *                  PPID_RSA3072_ENCRYPTED.
 *
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
    // Only PPID_RSA3072_ENCRYPTED is supported when using production mode PCE.
    if (PPID_RSA3072_ENCRYPTED != cert_key_type) {
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
    //todo: Currenlty, the private key is stored temporarily in enclave global memory long enough
    // to last between get_pce_encrypt_key() and store_cert_data().  These calls surround the call to the PCE
    // get_pce_info() API.  There is a risk that if the enclave is unloaded directly or indirectly (by power state
    // change) the private key will be lost.  There should be more documentation about this situation w/r/t
    // detection and recovery.  Or, if that is not sufficient, then provide a way to store the key in the ECDSA
    // blob.  Since PPID_CLEARTEXT cert_key_type is not supported at this time, we can push the solution for later.
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

    // Raoul: (3) You'll need something like this. The PCE enclave requires that you pass in a report specifically designed for it. sgx reports can be used to sign something for a particular enclave. It's the key part of local attestation, and a way to set up a secure channel between two enclaves on the same platform. For us it wouldn't be required, but we have no choice since we can't modify the PCE enclave.
    // report_data = SHA256(crypto_suite||rsa_pub_key)||0-padding
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
/*        sgx_status = sgx_sha256_get_hash(sha_handle,
            reinterpret_cast<sgx_sha256_hash_t *>(&report_data));*/
    } while (0);
    if (SGX_SUCCESS != sgx_status) {
        if (SGX_ERROR_OUT_OF_MEMORY != sgx_status)
            sgx_status = SGX_ERROR_UNEXPECTED;
        goto ret_point;
    }

    // Raoul: (4) Creating the report is required, and needs to happen inside _a_ enclave
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

    //if (sizeof(ciphertext_data.ppid) < ppid_size) {
    //    ret = REFQE3_ERROR_CRYPTO;
    //    goto ret_point;
    //}
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
    memcpy(ppid, dec_dat, 16);

    return sgx_status;
}
