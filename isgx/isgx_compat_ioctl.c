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

#include "isgx.h"
#include <linux/acpi.h>
#include <linux/compat.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/suspend.h>

#define ISGX32_IOC_ENCLAVE_CREATE \
	_IOWR('p', 0x02, struct sgx_create_param32)
#define ISGX32_IOC_ENCLAVE_ADD_PAGE \
	_IOW('p', 0x03, struct sgx_add_param32)
#define ISGX32_IOC_ENCLAVE_INIT \
	_IOW('p', 0x04, struct sgx_init_param32)
#define ISGX32_IOC_ENCLAVE_DESTROY \
	_IOW('p', 0x06, struct sgx_destroy_param32)

struct sgx_create_param32 {
	u32 secs;
	u32 addr;
};

static long enclave_create_compat(struct file *filep, unsigned int cmd,
				  unsigned long arg)
{
	struct sgx_create_param32 create_param32;
	struct sgx_create_param *create_param;
	unsigned long addr;
	int ret;

	if (copy_from_user(&create_param32, (void *)arg,
			   sizeof(create_param32)))
		return -EFAULT;

	create_param = compat_alloc_user_space(sizeof(*create_param));
	if (!create_param ||
	    __put_user((void __user *)(unsigned long)create_param32.secs,
		       &create_param->secs))
		return -EFAULT;

	ret = isgx_ioctl(filep, SGX_IOC_ENCLAVE_CREATE,
			 (unsigned long)create_param);
	if (ret)
		return ret;

	if (__get_user(addr, &create_param->addr))
		return -EFAULT;

	create_param32.addr = addr;

	if (copy_to_user((void *)arg, &create_param32, sizeof(create_param32)))
		return -EFAULT;

	return 0;
}

struct sgx_add_param32 {
	u32 addr;
	u32 user_addr;
	u32 secinfo;
	u32 flags;
};

static long enclave_add_page_compat(struct file *filep, unsigned int cmd,
				    unsigned long arg)
{
	struct sgx_add_param32 add_param32;
	struct sgx_add_param *add_param;

	if (copy_from_user(&add_param32, (void *)arg,
			   sizeof(add_param32)))
		return -EFAULT;

	add_param = compat_alloc_user_space(sizeof(*add_param));
	if (!add_param)
		return -EFAULT;

	if (__put_user((unsigned long)add_param32.addr,
		       &add_param->addr) ||
	    __put_user((unsigned long)add_param32.user_addr,
		       &add_param->user_addr) ||
	    __put_user((unsigned long)add_param32.secinfo,
		       &add_param->secinfo) ||
	    __put_user((unsigned long)add_param32.flags,
		       &add_param->flags))
		return -EFAULT;

	return isgx_ioctl(filep, SGX_IOC_ENCLAVE_ADD_PAGE,
			  (unsigned long)add_param);
}

struct sgx_init_param32 {
	u32 addr;
	u32 sigstruct;
	u32 einittoken;
};

static long enclave_init_compat(struct file *filep, unsigned int cmd,
				unsigned long arg)
{
	struct sgx_init_param32 init_param32;
	struct sgx_init_param *init_param;

	if (copy_from_user(&init_param32, (void *)arg,
			   sizeof(init_param32)))
		return -EFAULT;

	init_param = compat_alloc_user_space(sizeof(*init_param));
	if (!init_param)
		return -EFAULT;

	if (__put_user((void __user *)(unsigned long)init_param32.addr,
		       &init_param->addr) ||
	    __put_user((void __user *)(unsigned long)init_param32.sigstruct,
		       &init_param->sigstruct) ||
	    __put_user((void __user *)(unsigned long)init_param32.einittoken,
		       &init_param->einittoken))
		return -EFAULT;

	return isgx_ioctl(filep, SGX_IOC_ENCLAVE_INIT,
			  (unsigned long)init_param);
}

struct sgx_destroy_param32 {
	u32 addr;
};

static long enclave_destroy_compat(struct file *filep, unsigned int cmd,
				   unsigned long arg)
{
	struct sgx_destroy_param32 destroy_param32;
	struct sgx_destroy_param *destroy_param;

	if (copy_from_user(&destroy_param32, (void *)arg,
			   sizeof(destroy_param32)))
		return -EFAULT;

	destroy_param = compat_alloc_user_space(sizeof(*destroy_param));
	if (!destroy_param)
		return -EFAULT;

	if (__put_user((void __user *)(unsigned long)destroy_param32.addr,
		       &destroy_param->addr))
		return -EFAULT;

	return isgx_ioctl(filep, SGX_IOC_ENCLAVE_DESTROY,
			  (unsigned long)destroy_param);
}

long isgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case ISGX32_IOC_ENCLAVE_CREATE:
		return enclave_create_compat(filep, cmd, arg);
	case ISGX32_IOC_ENCLAVE_ADD_PAGE:
		return enclave_add_page_compat(filep, cmd, arg);
	case ISGX32_IOC_ENCLAVE_INIT:
		return enclave_init_compat(filep, cmd, arg);
	case ISGX32_IOC_ENCLAVE_DESTROY:
		return enclave_destroy_compat(filep, cmd, arg);
	default:
		return -EINVAL;
	}
}
