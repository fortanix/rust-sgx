/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include <stdio.h>
#include <sgx_urts.h>
#include "Enclave/ppid_u.h"
#include "pce/pce_enclave_u.h"

#define DECRYPTED_PPID_LENGTH 16

#define DEBUG_ENCLAVE 1
#define RELEASE_ENCLAVE 0

void print_decrypted_ppid(unsigned char decrypted_ppid[], size_t length) {
    printf("Decrypted PPID: ");
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", decrypted_ppid[i]); // Print each byte in hex
    }
    printf("\n");
}

uint32_t get_encrypted_ppid(const sgx_report_t *report,
                         const uint8_t *public_key, uint32_t key_size,
                         uint8_t crypto_suite,
                         uint8_t *encrypted_ppid, uint32_t encrypted_ppid_buf_size,
                         uint32_t *encrypted_ppid_out_size,
                         pce_info_t *pce_info,
                         uint8_t *signature_scheme) {

    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    sgx_enclave_id_t pce_enclave_eid = 0;

    if (SGX_SUCCESS != (sgx_status = sgx_create_enclave("pce/libsgx_pce.signed.so.1.25.100.1", RELEASE_ENCLAVE, &token, &updated, &pce_enclave_eid, NULL)))
    {
        fprintf(stderr, "Failed to create PCE enclave. The error code is:  0x%04x. \n", sgx_status);
        sgx_status = -1;
        goto CLEANUP;
    }

    sgx_status = get_encrypted_ppid(pce_enclave_eid,
                             (uint32_t*) &ecall_ret,
                             report,
                             public_key,
                             key_size,
                             crypto_suite,
                             encrypted_ppid,
                             encrypted_ppid_buf_size,
                             encrypted_ppid_out_size,
                             pce_info,
                             signature_scheme);

    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failed to call into PCE enclave: get_pc_info. The error code is: 0x%04x.\n", sgx_status);
        sgx_status = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to get PCE info. The error code is: 0x%04x.\n", ecall_ret);
        sgx_status = -1;
        goto CLEANUP;
    }

    CLEANUP:
    if(pce_enclave_eid != 0) {
        sgx_destroy_enclave(pce_enclave_eid);
    }
    return sgx_status;
}

uint32_t pce_get_target_info(sgx_target_info_t *pce_target_info) {
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    sgx_enclave_id_t pce_enclave_eid = 0;
    sgx_target_info_t pce_target_info_result;

    if (pce_target_info == NULL) {
        fprintf(stderr, "Error: pce_target_info is NULL.\n");
        sgx_status = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != (sgx_status = sgx_create_enclave("pce/libsgx_pce.signed.so.1.25.100.1", RELEASE_ENCLAVE, &token, &updated, &pce_enclave_eid, NULL)))
    {
        fprintf(stderr, "Failed to create PCE enclave. The error code is:  0x%04x. \n", sgx_status);
        sgx_status = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != (sgx_status = sgx_get_target_info(pce_enclave_eid, &pce_target_info_result))) {
        fprintf(stderr, "Failed to get pce target info. The error code is:  0x%04x.\n", sgx_status);
        sgx_status = -1;
        goto CLEANUP;
    }

    memcpy(pce_target_info, &pce_target_info_result, sizeof(sgx_target_info_t));

    CLEANUP:
    if(pce_enclave_eid != 0) {
        sgx_destroy_enclave(pce_enclave_eid);
    }
    return sgx_status;
}

void print_err_status(char *str, sgx_status_t err_status) {
    fprintf(stderr, str, err_status);
}

int main(int argc, char **argv)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    uint8_t decrypted_ppid[DECRYPTED_PPID_LENGTH];
    sgx_enclave_id_t ppid_enclave_eid = 0;

    memset(decrypted_ppid, 0x00, DECRYPTED_PPID_LENGTH);

    if (SGX_SUCCESS != (sgx_status = sgx_create_enclave("Enclave/ppid.so", DEBUG_ENCLAVE, &token, &updated, &ppid_enclave_eid, NULL)))
    {
        fprintf(stderr, "Failed to create PPID enclave. The error code is:  0x%04x.\n", sgx_status);
        sgx_status = -1;
        goto CLEANUP;
    }

    sgx_status = entry_point(ppid_enclave_eid, &ecall_ret, decrypted_ppid);

    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "Failure in ppid enclave. The error code is: 0x%04x.\n", sgx_status);
        sgx_status = -1;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != ecall_ret) {
        fprintf(stderr, "Failed to ecall in ppid enclave. The error code is: 0x%04x.\n", sgx_status);
        sgx_status = -1;
        goto CLEANUP;
    }

    print_decrypted_ppid(decrypted_ppid, sizeof(decrypted_ppid));

    CLEANUP:
    if(ppid_enclave_eid != 0) {
        sgx_destroy_enclave(ppid_enclave_eid);
    }
    return sgx_status;
}
