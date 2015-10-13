/*
 * Userspace test utility for b are-bones SGX EPC driver.
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
#include <sys/mman.h>

#include "sgx.h"

// BEGIN user ABI

struct sgx_ioctl_data {
	union {
		struct {
			unsigned long rbx;
			unsigned long rcx;
			unsigned long rdx;
		};
		struct {
			int exception;
			unsigned long data;
		};
	};
};

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
#define SGX_IOADDR_IOCTL _IOW(SGX_META_IOCTL, 0x00, struct sgx_ioctl_data)

// END user ABI

int sgxfd;

int encls(int ioctl_num,void* rcx,void* rbx,void* rdx) {
	printf("encls[%d] rcx=%p rbx=%p rdx=%p\n",_IOC_NR(ioctl_num),rcx,rbx,rdx);
	struct sgx_ioctl_data data={.rbx=(unsigned long)rbx,.rcx=(unsigned long)rcx,.rdx=(unsigned long)rdx};
	int ret=ioctl(sgxfd, ioctl_num, &data);
	if (ret < 0) {
		perror("ioctl");
		return -1;
	}
	if (data.exception!=-1) {
		printf("Exception=%d data=%016lx\n",data.exception,data.data);
		return -1;
	}
	return data.data;
}

int main(int argc,char** argv) {
	if ((sgxfd = open("/dev/sgx", O_RDWR)) < 0) {
		perror("open");
		return 1;
	}

	struct sgx_ioctl_data data;
	if (ioctl(sgxfd, SGX_IOADDR_IOCTL, &data)<0) {
		perror("ioctl");
                return 1;
	}
	char* epcmem=(char*)data.data;
	printf("EPC kernel address=%p\n",epcmem);

	pageinfo_t pageinfo={};
	secs_t secs={};
	secinfo_t secinfo={};

	secinfo.flags.page_type = PT_SECS;
	secinfo.flags.r = 1;
	secinfo.flags.w = 1;
	secinfo.flags.x = 0;

	secs.ssaFrameSize         = 1;
	secs.attributes.mode64bit = 1;
	secs.attributes.debug     = 0;
	secs.attributes.xfrm      = 0x03;

	secs.attributes.provisionkey  = 1;
	secs.attributes.einittokenkey = 0;

	secs.size     = 4096*2;
	secs.baseAddr = (uint64_t)mmap(NULL,4096*2,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE,sgxfd,4096*2);
	if (secs.baseAddr==(uint64_t)MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	pageinfo.srcpge  = (uint64_t)&secs;
	pageinfo.secinfo = (uint64_t)&secinfo;
	pageinfo.secs    = 0; // not used
	pageinfo.linaddr = 0; // not used

	printf("base %p pi %p secs %p secinfo %p\n",(void*)secs.baseAddr,&pageinfo,&secs,&secinfo);
	encls(ENCLS_ECREATE_IOCTL,epcmem,&pageinfo,0);
	encls(ENCLS_EREMOVE_IOCTL,epcmem,0,0);

	return 0;
}
