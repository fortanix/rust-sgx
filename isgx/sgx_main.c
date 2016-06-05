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

#include "sgx.h"
#include <linux/acpi.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/hashtable.h>
#include <linux/kthread.h>
#include <linux/platform_device.h>

#define DRV_DESCRIPTION "Intel SGX Driver"
#define DRV_VERSION "0.10"

#define ENCLAVE_SIZE_MAX_64 (64ULL * 1024ULL * 1024ULL * 1024ULL)
#define ENCLAVE_SIZE_MAX_32 (2ULL * 1024ULL * 1024ULL * 1024ULL)

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@intel.com>");
MODULE_VERSION(DRV_VERSION);

/*
 * Global data.
 */

struct workqueue_struct *sgx_add_page_wq;
unsigned long sgx_epc_base;
unsigned long sgx_epc_size;
#ifdef CONFIG_X86_64
void *sgx_epc_mem;
#endif
u64 sgx_enclave_size_max_32 = ENCLAVE_SIZE_MAX_32;
u64 sgx_enclave_size_max_64 = ENCLAVE_SIZE_MAX_64;
u64 sgx_xfrm_mask = 0x3;
u32 sgx_ssaframesize_tbl[64];

#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	return sgx_ioctl(filep, cmd, arg);
}
#endif

static int sgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &sgx_vm_ops;
#if !defined(VM_RESERVED)
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO;
#else
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_RESERVED | VM_IO;
#endif

	return 0;
}

static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (len < 2 * PAGE_SIZE || (len & (len - 1)))
		return -EINVAL;

	/* On 64-bit architecture, allow mmap() to exceed 32-bit enclave
	 * limit only if the task is not running in 32-bit compatibility
	 * mode.
	 */
	if (len > sgx_enclave_size_max_32)
#ifdef CONFIG_X86_64
		if (test_thread_flag(TIF_ADDR32))
			return -EINVAL;
#else
		return -EINVAL;
#endif

#ifdef CONFIG_X86_64
	if (len > sgx_enclave_size_max_64)
		return -EINVAL;
#endif

	addr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,
					      flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = (addr + (len - 1)) & ~(len - 1);

	return addr;
}

static const struct file_operations sgx_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

static struct miscdevice sgx_dev = {
	.name	= "sgx",
	.fops	= &sgx_fops,
	.mode   = S_IRUGO | S_IWUGO,
};

static int sgx_init_platform(void)
{
	unsigned int eax, ebx, ecx, edx;
	int i;

	cpuid(0, &eax, &ebx, &ecx, &edx);
	if (eax < SGX_CPUID) {
		pr_err("isgx: CPUID is missing the SGX leaf instruction\n");
		return -ENODEV;
	}

	if (!boot_cpu_has(X86_FEATURE_SGX)) {
		pr_err("isgx: CPU is missing the SGX feature\n");
		return -ENODEV;
	}

	cpuid_count(SGX_CPUID, 0x0, &eax, &ebx, &ecx, &edx);
	if (!(eax & 1)) {
		pr_err("isgx: CPU does not support the SGX 1.0 instruction set\n");
		return -ENODEV;
	}

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		cpuid_count(SGX_CPUID, 0x1, &eax, &ebx, &ecx, &edx);
		sgx_xfrm_mask = (((u64)edx) << 32) + (u64)ecx;
		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1 << i) & sgx_xfrm_mask)
				sgx_ssaframesize_tbl[i] =
					(168 + eax + ebx + PAGE_SIZE - 1) /
					PAGE_SIZE;
		}
	}

	cpuid_count(SGX_CPUID, 0x0, &eax, &ebx, &ecx, &edx);
	if (edx & 0xFFFF) {
#ifdef CONFIG_X86_64
		sgx_enclave_size_max_64 = 2ULL << (edx & 0xFF);
#endif
		sgx_enclave_size_max_32 = 2ULL << ((edx >> 8) & 0xFF);
	}

	cpuid_count(SGX_CPUID, 0x2, &eax, &ebx, &ecx, &edx);

	/* The should be at least one EPC area or something is wrong. */
	if ((eax & 0xf) != 0x1)
		return -ENODEV;

	sgx_epc_base = (((u64)(ebx & 0xfffff)) << 32) +
		(u64)(eax & 0xfffff000);
	sgx_epc_size = (((u64)(edx & 0xfffff)) << 32) +
		(u64)(ecx & 0xfffff000);

	if (!sgx_epc_base)
		return -ENODEV;

	return 0;
}

static int sgx_pm_suspend(struct device *dev)
{
	struct sgx_tgid_ctx *ctx;
	struct sgx_enclave *encl;

	kthread_stop(kisgxswapd_tsk);
	kisgxswapd_tsk = NULL;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &ctx->enclave_list, enclave_list) {
			sgx_invalidate(encl);
			encl->flags |= ISGX_ENCLAVE_SUSPEND;
			flush_work(&encl->add_page_work);
		}
	}

	return 0;
}

static int sgx_pm_resume(struct device *dev)
{
	kisgxswapd_tsk = kthread_run(kisgxswapd, NULL, "kisgxswapd");
	return 0;
}

static SIMPLE_DEV_PM_OPS(sgx_drv_pm, sgx_pm_suspend, sgx_pm_resume);

static int sgx_drv_init(struct device *dev)
{
	unsigned int wq_flags;
	int ret;

	pr_info("isgx: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return -ENODEV;

	ret = sgx_init_platform();
	if (ret)
		return ret;

	pr_info("isgx: EPC memory range 0x%lx-0x%lx\n", sgx_epc_base,
		sgx_epc_base + sgx_epc_size);

#ifdef CONFIG_X86_64
	sgx_epc_mem = ioremap_cache(sgx_epc_base, sgx_epc_size);
	if (!sgx_epc_mem)
		return -ENOMEM;
#endif

	ret = sgx_page_cache_init(sgx_epc_base, sgx_epc_size);
	if (ret)
		goto out_iounmap;

	wq_flags = WQ_UNBOUND | WQ_FREEZABLE;
#ifdef WQ_NON_REENETRANT
	wq_flags |= WQ_NON_REENTRANT;
#endif
	sgx_add_page_wq = alloc_workqueue("isgx-add-page-wq", wq_flags, 1);
	if (!sgx_add_page_wq) {
		pr_err("isgx: alloc_workqueue() failed\n");
		ret = -ENOMEM;
		goto out_iounmap;
	}

	sgx_dev.parent = dev;
	ret = misc_register(&sgx_dev);
	if (ret) {
		pr_err("isgx: misc_register() failed\n");
		goto out_workqueue;
	}

	return 0;
out_workqueue:
	destroy_workqueue(sgx_add_page_wq);
out_iounmap:
#ifdef CONFIG_X86_64
	iounmap(sgx_epc_mem);
#endif
	return ret;
}

static int sgx_drv_probe(struct platform_device *pdev)
{
	unsigned int eax, ebx, ecx, edx;
	int i;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return -ENODEV;

	cpuid(0, &eax, &ebx, &ecx, &edx);
	if (eax < SGX_CPUID) {
		pr_err("isgx: CPUID is missing the SGX leaf instruction\n");
		return -ENODEV;
	}

	if (!boot_cpu_has(X86_FEATURE_SGX)) {
		pr_err("isgx: CPU is missing the SGX feature\n");
		return -ENODEV;
	}

	cpuid_count(SGX_CPUID, 0x0, &eax, &ebx, &ecx, &edx);
	if (!(eax & 1)) {
		pr_err("isgx: CPU does not support the SGX 1.0 instruction set\n");
		return -ENODEV;
	}

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		cpuid_count(SGX_CPUID, 0x1, &eax, &ebx, &ecx, &edx);
		sgx_xfrm_mask = (((u64)edx) << 32) + (u64)ecx;
		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1 << i) & sgx_xfrm_mask)
				sgx_ssaframesize_tbl[i] =
					(168 + eax + ebx + PAGE_SIZE - 1) /
					PAGE_SIZE;
		}
	}

	cpuid_count(SGX_CPUID, 0x0, &eax, &ebx, &ecx, &edx);
	if (edx & 0xFFFF) {
#ifdef CONFIG_X86_64
		sgx_enclave_size_max_64 = 2ULL << (edx & 0xFF);
#endif
		sgx_enclave_size_max_32 = 2ULL << ((edx >> 8) & 0xFF);
	}

	return sgx_drv_init(&pdev->dev);
}

static int sgx_drv_remove(struct platform_device *pdev)
{
	misc_deregister(&sgx_dev);
	destroy_workqueue(sgx_add_page_wq);
#ifdef CONFIG_X86_64
	iounmap(sgx_epc_mem);
#endif
	sgx_page_cache_teardown();

	return 0;
}

static struct platform_driver sgx_drv = {
	.probe = sgx_drv_probe,
	.remove = sgx_drv_remove,
	.driver = {
		.name		= "intel_sgx",
		.pm		= &sgx_drv_pm,
	},
};

static struct platform_device *sgx_pdev;

static int __init sgx_init(void)
{
	struct platform_device *pdev;
	int rc;

	rc = platform_driver_register(&sgx_drv);
	if (rc < 0)
		return rc;

	pdev = platform_device_register_simple("intel_sgx", -1, NULL, 0);
	if (IS_ERR(pdev)) {
		platform_driver_unregister(&sgx_drv);
		return PTR_ERR(pdev);
	}

	sgx_pdev = pdev;

	return 0;
}

static void __exit sgx_exit(void)
{
	platform_device_unregister(sgx_pdev);
	platform_driver_unregister(&sgx_drv);
}

module_init(sgx_init);
module_exit(sgx_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS("acpi*:INT0E0C:*");
