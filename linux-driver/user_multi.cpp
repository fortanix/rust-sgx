/*
 * Userspace test utility for bare-bones SGX EPC driver. (multi version)
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

struct ioctl_call {
	sgx_ioctl_vec_elem ioctl;
	vector<void*> freelist;
};

static const char* g_leaf_names[]={"ECREATE","EADD","EINIT","EREMOVE","EDBGRD","EDBGWR","EEXTEND","ELDB","ELDU","EBLOCK","EPA","EWB","ETRACK","EAUG","EMODPR","EMODT"};

int sgxfd;

sgx_ioctl_data encls_args(void* rcx,void* rbx,void* rdx) {
	return {{{.rbx=(unsigned long)rbx,.rcx=(unsigned long)rcx,.rdx=(unsigned long)rdx}}};
}

typedef intptr_t u_addr;
typedef intptr_t k_addr;

ioctl_call test_ecreate(k_addr k_base, u_addr u_base, size_t npages) {
	pageinfo_t& pageinfo=*new pageinfo_t();
	secs_t& secs=*new secs_t();
	secinfo_t& secinfo=*new secinfo_t();

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

	return ioctl_call {
		{ENCLS_ECREATE,RETURN_EXCEPTION,encls_args((void*)k_base,&pageinfo,0)},
		{&pageinfo,&secs,&secinfo},
	};
}

struct page_t {char p[4096];};

ioctl_call test_eadd(k_addr k_page, u_addr u_page, k_addr k_secs) {
	page_t &page=*new page_t();
	pageinfo_t &pageinfo=*new pageinfo_t();
	secinfo_t &secinfo=*new secinfo_t();

	secinfo.flags.page_type = PT_REG;
	secinfo.flags.r = 1;
	secinfo.flags.w = 1;
	secinfo.flags.x = 1;

	pageinfo.srcpge  = (uint64_t)&page;
	pageinfo.secinfo = (uint64_t)&secinfo;
	pageinfo.secs    = k_secs;
	pageinfo.linaddr = u_page;

	return ioctl_call {
		{ENCLS_EADD,RETURN_EXCEPTION,encls_args((void*)k_page,&pageinfo,0)},
		{&pageinfo,&page,&secinfo},
	};
}

ioctl_call test_eextend(k_addr k_chunk, k_addr k_secs) {
	return ioctl_call {
		{ENCLS_EEXTEND,RETURN_EXCEPTION,encls_args((void*)k_chunk,(void*)k_secs,0)},
		{},
	};
}

ioctl_call test_eremove(k_addr k_page) {
	return ioctl_call {
		{ENCLS_EREMOVE,RETURN_EXCEPTION,encls_args((void*)k_page,0,0)},
		{},
	};
}

ioctl_call test_epa(k_addr k_page) {
	return ioctl_call {
		{ENCLS_EPA,RETURN_EXCEPTION,encls_args((void*)k_page,(void*)PT_VA,0)},
		{},
	};
}

ioctl_call test_eblock(k_addr k_page) {
	return ioctl_call {
		{ENCLS_EBLOCK,RETURN_EXCEPTION,encls_args((void*)k_page,0,0)},
		{},
	};
}

ioctl_call test_etrack(k_addr k_secs) {
	return ioctl_call {
		{ENCLS_ETRACK,RETURN_EXCEPTION,encls_args((void*)k_secs,0,0)},
		{},
	};
}

ioctl_call test_ewb(k_addr k_page, k_addr k_va_slot, void* page, pcmd_t* pcmd) {
	pageinfo_t& pageinfo=*new pageinfo_t();

	pageinfo.srcpge  = (uint64_t)page;
	pageinfo.secinfo = (uint64_t)pcmd;
	pageinfo.secs    = 0;
	pageinfo.linaddr = 0;

	return ioctl_call {
		{ENCLS_EWB,RETURN_EXCEPTION,encls_args((void*)k_page,&pageinfo,(void*)k_va_slot)},
		{&pageinfo},
	};
}

ioctl_call test_eldu(k_addr k_page, u_addr u_page, k_addr k_secs, k_addr k_va_slot, void* page, pcmd_t* pcmd) {
	pageinfo_t& pageinfo=*new pageinfo_t();

	pageinfo.srcpge  = (uint64_t)page;
	pageinfo.secinfo = (uint64_t)pcmd;
	pageinfo.secs    = k_secs;
	pageinfo.linaddr = u_page;

	return ioctl_call {
		{ENCLS_ELDU,RETURN_EXCEPTION,encls_args((void*)k_page,&pageinfo,(void*)k_va_slot)},
		{&pageinfo},
	};
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

	vector<sgx_ioctl_vec_elem> calls;
	vector<void*> freelist;

	auto add=[&calls,&freelist] (ioctl_call call) {
		calls.emplace_back(std::move(call.ioctl));
		std::move(call.freelist.begin(), call.freelist.end(), std::back_inserter(freelist));
	};

	char page1[4096];
	pcmd_t pcmd1;
	char page2[4096];
	pcmd_t pcmd2;

	add(std::move(test_ecreate(k_base,u_base,2)));
	add(std::move(test_eadd(k_base+0x1000,u_base+0x0000,k_base)));
	add(std::move(test_eextend(k_base+0x1000,k_base)));
	add(std::move(test_eextend(k_base+0x1100,k_base)));
	add(std::move(test_eextend(k_base+0x1200,k_base)));
	add(std::move(test_eextend(k_base+0x1300,k_base)));
	add(std::move(test_eextend(k_base+0x1400,k_base)));
	add(std::move(test_eextend(k_base+0x1500,k_base)));
	add(std::move(test_eextend(k_base+0x1600,k_base)));
	add(std::move(test_eextend(k_base+0x1700,k_base)));
	add(std::move(test_eextend(k_base+0x1800,k_base)));
	add(std::move(test_eextend(k_base+0x1900,k_base)));
	add(std::move(test_eextend(k_base+0x1a00,k_base)));
	add(std::move(test_eextend(k_base+0x1b00,k_base)));
	add(std::move(test_eextend(k_base+0x1c00,k_base)));
	add(std::move(test_eextend(k_base+0x1d00,k_base)));
	add(std::move(test_eextend(k_base+0x1e00,k_base)));
	add(std::move(test_eextend(k_base+0x1f00,k_base)));
	add(std::move(test_epa(k_base+0x2000)));
	add(std::move(test_eblock(k_base+0x1000)));
	add(std::move(test_etrack(k_base+0x0000)));
	add(std::move(test_ewb(k_base+0x1000,k_base+0x2000,page1,&pcmd1)));
	add(std::move(test_ewb(k_base,k_base+0x2008,page2,&pcmd2)));
	add(std::move(test_eldu(k_base,0,0,k_base+0x2008,page2,&pcmd2)));
	add(std::move(test_eldu(k_base+0x1000,u_base+0x0000,k_base,k_base+0x2000,page1,&pcmd1)));
	add(std::move(test_eremove(k_base+0x2000)));
	add(std::move(test_eremove(k_base+0x1000)));
	add(std::move(test_eremove(k_base)));

	sgx_ioctl_vec arg {calls.size(),&calls[0]};

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC_RAW,&start);
	if (ioctl(sgxfd, SGX_MULTI_ENCLS_IOCTL, &arg)<0) {
		perror("ioctl");
				return 1;
	}
	clock_gettime(CLOCK_MONOTONIC_RAW,&end);

	for (auto call: calls) {
		if (call.data.exception!=-1) {
			printf("%s Exception=%d data=%016lx\n",g_leaf_names[call.leaf],call.data.exception,call.data.data);
			return 1;
		}
		if (call.data.data!=0) {
			printf("%s=%lu\n",g_leaf_names[call.leaf],call.data.data);
		}
		printf("%s copy=%luns encls=%luns\n",g_leaf_names[call.leaf],call.data.duration_copy,call.data.duration_encls);
	}
	printf("real=%luns\n",end.tv_nsec-start.tv_nsec+(end.tv_sec-start.tv_sec)*1000000000L);

	for (auto ptr: freelist) {
		operator delete(ptr);
	}

	return 0;
}
