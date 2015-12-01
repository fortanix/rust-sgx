/*
 * Userspace test utility for bare-bones SGX EPC driver.
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
#include <time.h>

#include "sgx.h"

// BEGIN user ABI

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

static const char* g_leaf_names[]={"ECREATE","EADD","EINIT","EREMOVE","EDBGRD","EDBGWR","EEXTEND","ELDB","ELDU","EBLOCK","EPA","EWB","ETRACK","EAUG","EMODPR","EMODT"};

int sgxfd;

int encls(int ioctl_num,void* rcx,void* rbx,void* rdx) {
	printf("ENCLS[%s] rcx=%p rbx=%p rdx=%p\n",g_leaf_names[_IOC_NR(ioctl_num)],rcx,rbx,rdx);
	struct sgx_ioctl_data data={.rbx=(unsigned long)rbx,.rcx=(unsigned long)rcx,.rdx=(unsigned long)rdx};
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC_RAW,&start);
	int ret=ioctl(sgxfd, ioctl_num, &data);
	clock_gettime(CLOCK_MONOTONIC_RAW,&end);
	if (ret < 0) {
		perror("ioctl");
		return -1;
	}
	if (data.exception!=-1) {
		printf("Exception=%d data=%016lx\n",data.exception,data.data);
		return -1;
	}
	printf("%s copy=%luns encls=%luns user=%luns\n",g_leaf_names[_IOC_NR(ioctl_num)],data.duration_copy,data.duration_encls,end.tv_nsec-start.tv_nsec+(end.tv_sec-start.tv_sec)*1000000000L);
	return data.data;
}

typedef intptr_t u_addr;
typedef intptr_t k_addr;

int test_ecreate(k_addr k_base, u_addr u_base, size_t npages) {
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

	secs.size     = 4096*npages;
	secs.baseAddr = u_base;

	pageinfo.srcpge  = (uint64_t)&secs;
	pageinfo.secinfo = (uint64_t)&secinfo;
	pageinfo.secs    = 0; // not used
	pageinfo.linaddr = 0; // not used

	printf("base %p pi %p secs %p secinfo %p\n",(void*)u_base,&pageinfo,&secs,&secinfo);
	return encls(ENCLS_ECREATE_IOCTL,(void*)k_base,&pageinfo,0);
}

int test_eadd(k_addr k_page, u_addr u_page, k_addr k_secs) {
	static char page[4096]={};
	pageinfo_t pageinfo={};
	secinfo_t secinfo={};

	secinfo.flags.page_type = PT_REG;
	secinfo.flags.r = 1;
	secinfo.flags.w = 1;
	secinfo.flags.x = 1;

	pageinfo.srcpge  = (uint64_t)page;
	pageinfo.secinfo = (uint64_t)&secinfo;
	pageinfo.secs    = k_secs;
	pageinfo.linaddr = u_page;

	return encls(ENCLS_EADD_IOCTL,(void*)k_page,&pageinfo,0);
}

int test_eextend(k_addr k_chunk, k_addr k_secs) {
	return encls(ENCLS_EEXTEND_IOCTL,(void*)k_chunk,(void*)k_secs,0);
}

int test_eremove(k_addr k_page) {
	int ret=encls(ENCLS_EREMOVE_IOCTL,(void*)k_page,0,0);
	if (ret!=0) printf("EREMOVE=%d\n",ret);
	return ret;
}

int test_epa(k_addr k_page) {
	return encls(ENCLS_EPA_IOCTL,(void*)k_page,(void*)PT_VA,0);
}

int test_eblock(k_addr k_page) {
	int ret=encls(ENCLS_EBLOCK_IOCTL,(void*)k_page,0,0);
	if (ret!=0) printf("EBLOCK=%d\n",ret);
	return ret;
}

int test_etrack(k_addr k_secs) {
	int ret=encls(ENCLS_ETRACK_IOCTL,(void*)k_secs,0,0);
	if (ret!=0) printf("ETRACK=%d\n",ret);
	return ret;
}

int test_ewb(k_addr k_page, k_addr k_va_slot, void* page, pcmd_t* pcmd) {
	pageinfo_t pageinfo={};

	pageinfo.srcpge  = (uint64_t)page;
	pageinfo.secinfo = (uint64_t)pcmd;
	pageinfo.secs    = 0;
	pageinfo.linaddr = 0;

	int ret=encls(ENCLS_EWB_IOCTL,(void*)k_page,&pageinfo,(void*)k_va_slot);
	if (ret!=0) printf("EWB=%d\n",ret);
	return ret;
}

int test_eldu(k_addr k_page, u_addr u_page, k_addr k_secs, k_addr k_va_slot, void* page, pcmd_t* pcmd) {
	pageinfo_t pageinfo={};

	pageinfo.srcpge  = (uint64_t)page;
	pageinfo.secinfo = (uint64_t)pcmd;
	pageinfo.secs    = k_secs;
	pageinfo.linaddr = u_page;

	int ret=encls(ENCLS_ELDU_IOCTL,(void*)k_page,&pageinfo,(void*)k_va_slot);
	if (ret!=0) printf("ELDU=%d\n",ret);
	return ret;
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
	k_addr k_base=data.data;
	printf("EPC kernel address=%lx\n",k_base);

	u_addr u_base=(u_addr)mmap(NULL,4096*2,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE,sgxfd,4096*2);
	if (u_base==(u_addr)MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	printf("Enclave base address=%lx\n",u_base);

	char page1[4096];
	pcmd_t pcmd1;
	char page2[4096];
	pcmd_t pcmd2;

	test_ecreate(k_base,u_base,2);
	test_eadd(k_base+0x1000,u_base+0x0000,k_base);
	test_eextend(k_base+0x1000,k_base);
	test_eextend(k_base+0x1100,k_base);
	test_eextend(k_base+0x1200,k_base);
	test_eextend(k_base+0x1300,k_base);
	test_eextend(k_base+0x1400,k_base);
	test_eextend(k_base+0x1500,k_base);
	test_eextend(k_base+0x1600,k_base);
	test_eextend(k_base+0x1700,k_base);
	test_eextend(k_base+0x1800,k_base);
	test_eextend(k_base+0x1900,k_base);
	test_eextend(k_base+0x1a00,k_base);
	test_eextend(k_base+0x1b00,k_base);
	test_eextend(k_base+0x1c00,k_base);
	test_eextend(k_base+0x1d00,k_base);
	test_eextend(k_base+0x1e00,k_base);
	test_eextend(k_base+0x1f00,k_base);
	test_epa(k_base+0x2000);
	test_eblock(k_base+0x1000);
	test_etrack(k_base+0x0000);
	test_ewb(k_base+0x1000,k_base+0x2000,page1,&pcmd1);
	test_ewb(k_base,k_base+0x2008,page2,&pcmd2);
	test_eldu(k_base,0,0,k_base+0x2008,page2,&pcmd2);
	test_eldu(k_base+0x1000,u_base+0x0000,k_base,k_base+0x2000,page1,&pcmd1);
	test_eremove(k_base+0x2000);
	test_eremove(k_base+0x1000);
	test_eremove(k_base);

	return 0;
}
