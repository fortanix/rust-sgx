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
#include "ioctl.h"

#include <vector>
using std::vector;

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
