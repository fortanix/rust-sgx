/*
 * User-space utility to remove pages from EPC
 *
 * (C) Copyright 2015 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

#include "sgx.h"

#include <vector>
using std::vector;

// BEGIN user ABI

extern "C" {

struct sgx_ioctl_data {
	union {
		struct {
			unsigned long rbx;
			unsigned long rcx;
			unsigned long rdx;
		} /*in*/;
		struct {
			int exception;
			unsigned long data;
			unsigned long duration_encls;
			unsigned long duration_copy;
		} /*out*/;
	};
};

struct sgx_ioctl_vec_elem {
	int leaf;
	int return_flag;
	struct sgx_ioctl_data data;
};

struct sgx_ioctl_vec {
	int num;
	struct sgx_ioctl_vec_elem* ioctls;
};

#define RETURN_EXCEPTION    0x01 // return if an exception was encountered executing ENCLS
#define RETURN_ERROR        0x02 // return if EAX was not 0 after ENCLS
#define RETURN_ERROR_EBLOCK 0x04 // same as RETURN_ERROR but also continue on SGX_BLKSTATE

#define SGX_IOCTL 'G'
#define ENCLS_ECREATE_IOCTL _IOWR(SGX_IOCTL, 0x00, struct sgx_ioctl_data)
#define ENCLS_EADD_IOCTL    _IOWR(SGX_IOCTL, 0x01, struct sgx_ioctl_data)
#define ENCLS_EINIT_IOCTL   _IOWR(SGX_IOCTL, 0x02, struct sgx_ioctl_data)
#define ENCLS_EREMOVE_IOCTL _IOWR(SGX_IOCTL, 0x03, struct sgx_ioctl_data)
#define ENCLS_EDBGRD_IOCTL  _IOWR(SGX_IOCTL, 0x04, struct sgx_ioctl_data)
#define ENCLS_EDBGWR_IOCTL  _IOWR(SGX_IOCTL, 0x05, struct sgx_ioctl_data)
#define ENCLS_EEXTEND_IOCTL _IOWR(SGX_IOCTL, 0x06, struct sgx_ioctl_data)
#define ENCLS_ELDB_IOCTL    _IOWR(SGX_IOCTL, 0x07, struct sgx_ioctl_data)
#define ENCLS_ELDU_IOCTL    _IOWR(SGX_IOCTL, 0x08, struct sgx_ioctl_data)
#define ENCLS_EBLOCK_IOCTL  _IOWR(SGX_IOCTL, 0x09, struct sgx_ioctl_data)
#define ENCLS_EPA_IOCTL     _IOWR(SGX_IOCTL, 0x0a, struct sgx_ioctl_data)
#define ENCLS_EWB_IOCTL     _IOWR(SGX_IOCTL, 0x0b, struct sgx_ioctl_data)
#define ENCLS_ETRACK_IOCTL  _IOWR(SGX_IOCTL, 0x0c, struct sgx_ioctl_data)
#define ENCLS_EAUG_IOCTL    _IOWR(SGX_IOCTL, 0x0d, struct sgx_ioctl_data)
#define ENCLS_EMODPR_IOCTL  _IOWR(SGX_IOCTL, 0x0e, struct sgx_ioctl_data)
#define ENCLS_EMODT_IOCTL   _IOWR(SGX_IOCTL, 0x0f, struct sgx_ioctl_data)

#define SGX_META_IOCTL 'H'
#define SGX_IOADDR_IOCTL      _IOW(SGX_META_IOCTL, 0x00, struct sgx_ioctl_data)
#define SGX_MULTI_ENCLS_IOCTL _IOWR(SGX_META_IOCTL, 0x01, struct sgx_ioctl_vec)

};

// END user ABI

int sgxfd;

typedef intptr_t k_addr;

int main(int argc,char** argv) {
	int npages;

	if (argc!=2 || (npages=atoi(argv[1]))<1) {
		fprintf(stderr,"Usage: clear <numpages>\n");
		return 1;
	}

	if ((sgxfd = open("/dev/sgx", O_RDWR)) < 0) {
		perror("open");
		return 1;
	}

	struct sgx_ioctl_data data;
	if (ioctl(sgxfd, SGX_IOADDR_IOCTL, &data)<0) {
		perror("ioctl");
		return 1;
	}
	k_addr k_base=data.data;
	printf("EPC kernel address=%lx\n",k_base);

	vector<sgx_ioctl_vec_elem> calls(npages,{ENCLS_EREMOVE,0,{{{.rbx=0,.rcx=0,.rdx=0}}}});

	for (int i=0;i<npages;i++) {
		calls[i].data.rcx=k_base+(npages-1-i)*0x1000;
	}

	sgx_ioctl_vec arg {npages,&calls[0]};

	if (ioctl(sgxfd, SGX_MULTI_ENCLS_IOCTL, &arg)<0) {
		perror("ioctl");
				return 1;
	}

	int ret=0;
	for (int i=0;i<npages;i++) {
		auto& call=calls[i];
		if (call.data.exception!=-1) {
			printf("EREMOVE @%lx Exception=%d data=%016lx\n",k_base+(npages-1-i)*0x1000,call.data.exception,call.data.data);
			ret=1;
		} else if (call.data.data!=0) {
			printf("EREMOVE @%lx error=%lu\n",k_base+(npages-1-i)*0x1000,call.data.data);
			ret=1;
		}
	}

	return ret;
}
