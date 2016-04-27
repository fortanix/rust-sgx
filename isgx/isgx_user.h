/*
 * (C) Copyright 2016 Intel Corporation
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef _UAPI_ASM_X86_SGX_H
#define _UAPI_ASM_X86_SGX_H

#include <linux/bitops.h>
#include <linux/ioctl.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define SGX_IOC_ENCLAVE_CREATE \
	_IOWR('p', 0x02, struct sgx_create_param)
#define SGX_IOC_ENCLAVE_ADD_PAGE \
	_IOW('p', 0x03, struct sgx_add_param)
#define SGX_IOC_ENCLAVE_INIT \
	_IOW('p', 0x04, struct sgx_init_param)
#define SGX_IOC_ENCLAVE_DESTROY \
	_IOW('p', 0x06, struct sgx_destroy_param)

/* SGX leaf instruction return values */
#define SGX_SUCCESS			0
#define SGX_INVALID_SIG_STRUCT		1
#define SGX_INVALID_ATTRIBUTE		2
#define SGX_BLKSTATE			3
#define SGX_INVALID_MEASUREMENT		4
#define SGX_NOTBLOCKABLE		5
#define SGX_PG_INVLD			6
#define SGX_LOCKFAIL			7
#define SGX_INVALID_SIGNATURE		8
#define SGX_MAC_COMPARE_FAIL		9
#define SGX_PAGE_NOT_BLOCKED		10
#define SGX_NOT_TRACKED			11
#define SGX_VA_SLOT_OCCUPIED		12
#define SGX_CHILD_PRESENT		13
#define SGX_ENCLAVE_ACT			14
#define SGX_ENTRYEPOCH_LOCKED		15
#define SGX_INVALID_LICENSE		16
#define SGX_PREV_TRK_INCMPL		17
#define SGX_PG_IS_SECS			18
#define SGX_INVALID_CPUSVN		32
#define SGX_INVALID_ISVSVN		64
#define SGX_UNMASKED_EVENT		128
#define SGX_INVALID_KEYNAME		256

/* IOCTL return values */
#define SGX_POWER_LOST_ENCLAVE		0xc0000002
#define SGX_LE_ROLLBACK			0xc0000003

/* SECINFO flags */
enum isgx_secinfo_flags {
	SGX_SECINFO_FL_R	= BIT_ULL(0),
	SGX_SECINFO_FL_W	= BIT_ULL(1),
	SGX_SECINFO_FL_X	= BIT_ULL(2),
};

/* SECINFO page types */
enum isgx_secinfo_pt {
	SGX_SECINFO_PT_SECS	= 0x000ULL,
	SGX_SECINFO_PT_TCS	= 0x100ULL,
	SGX_SECINFO_PT_REG	= 0x200ULL,
};

struct sgx_secinfo {
	__u64 flags;
	__u64 reserved[7];
} __aligned(128);

struct sgx_einittoken {
	__u32	valid;
	__u8	reserved1[206];
	__u16	isvsvnle;
	__u8	reserved2[92];
} __aligned(512);

struct sgx_create_param {
	void *secs;
	unsigned long addr;
};

#define SGX_ADD_SKIP_EEXTEND 0x1

struct sgx_add_param {
	unsigned long		addr;
	unsigned long		user_addr;
	struct isgx_secinfo	*secinfo;
	unsigned int		flags;
};

struct sgx_init_param {
	unsigned long		addr;
	void			*sigstruct;
	struct isgx_einittoken	*einittoken;
};

struct sgx_destroy_param {
	unsigned long addr;
};

#endif /* _UAPI_ASM_X86_SGX_H */
