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
#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/shmem_fs.h>

static void isgx_vma_open(struct vm_area_struct *vma)
{
	struct isgx_enclave *enclave;
	struct isgx_vma *evma;

	/* Was vm_private_data nullified as a result of the previous fork? */
	enclave = vma->vm_private_data;
	if (!enclave)
		goto out_fork;

	/* Was the process forked? mm_struct changes when the process is
	 * forked.
	 */
	mutex_lock(&enclave->lock);
	evma = list_first_entry(&enclave->vma_list,
				struct isgx_vma, vma_list);
	if (evma->vma->vm_mm != vma->vm_mm) {
		mutex_unlock(&enclave->lock);
		goto out_fork;
	}
	mutex_unlock(&enclave->lock);

	mutex_lock(&enclave->lock);
	if (!list_empty(&enclave->vma_list)) {
		evma = kzalloc(sizeof(*evma), GFP_KERNEL);
		if (!evma) {
			isgx_invalidate(enclave);
		} else {
			evma->vma = vma;
			list_add_tail(&evma->vma_list, &enclave->vma_list);
		}
	}
	mutex_unlock(&enclave->lock);

	kref_get(&enclave->refcount);
	return;
out_fork:
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
	vma->vm_private_data = NULL;
}

static void isgx_vma_close(struct vm_area_struct *vma)
{
	struct isgx_enclave *enclave = vma->vm_private_data;
	struct isgx_vma *evma;

	/* If process was forked, VMA is still there but
	 * vm_private_data is set to NULL.
	 */
	if (!enclave)
		return;

	mutex_lock(&enclave->lock);

	/* On vma_close() we remove the vma from vma_list
	 * there is a possibility that evma is not found
	 * in case vma_open() has failed on memory allocation
	 * and vma list has then been emptied
	 */
	evma = isgx_find_vma(enclave, vma->vm_start);
	if (evma) {
		list_del(&evma->vma_list);
		kfree(evma);
	}

	vma->vm_private_data = NULL;

	isgx_zap_tcs_ptes(enclave, vma);
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);

	mutex_unlock(&enclave->lock);

	kref_put(&enclave->refcount, isgx_enclave_release);
}

static int do_eldu(struct isgx_enclave *enclave,
		   struct isgx_enclave_page *enclave_page,
		   struct isgx_epc_page *epc_page,
		   struct page *backing,
		   bool is_secs)
{
	struct sgx_page_info pginfo;
	void *secs_ptr = NULL;
	void *epc_ptr;
	void *va_ptr;
	int ret;

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	if (!is_secs)
		secs_ptr = isgx_get_epc_page(enclave->secs_page.epc_page);
	pginfo.secs = (unsigned long)secs_ptr;

	epc_ptr = isgx_get_epc_page(epc_page);
	va_ptr = isgx_get_epc_page(enclave_page->va_page->epc_page);

	pginfo.linaddr = is_secs ? 0 : enclave_page->addr;
	pginfo.pcmd = (unsigned long)&enclave_page->pcmd;

	ret = __eldu((unsigned long)&pginfo,
		     (unsigned long)epc_ptr,
		     (unsigned long)va_ptr +
		     enclave_page->va_offset);

	isgx_put_epc_page(va_ptr);
	isgx_put_epc_page(epc_ptr);

	if (!is_secs)
		isgx_put_epc_page(secs_ptr);

	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);
	WARN_ON(ret);
	if (ret)
		return -EFAULT;

	return 0;
}

static struct isgx_enclave_page *isgx_vma_do_fault(struct vm_area_struct *vma,
						   unsigned long addr,
						   int reserve)
{
	struct isgx_enclave *enclave = vma->vm_private_data;
	struct isgx_enclave_page *entry;
	struct isgx_epc_page *epc_page;
	struct isgx_epc_page *secs_epc_page = NULL;
	struct page *backing;
	unsigned free_flags = ISGX_FREE_SKIP_EREMOVE;
	int rc;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!enclave)
		return ERR_PTR(-EFAULT);

	entry = isgx_enclave_find_page(enclave, addr);
	if (!entry)
		return ERR_PTR(-EFAULT);

	/* We use atomic allocation in the #PF handler in order to avoid ABBA
	 * deadlock with mmap_sems.
	 */
	epc_page = isgx_alloc_epc_page(enclave->tgid_ctx, ISGX_ALLOC_ATOMIC);
	if (IS_ERR(epc_page))
		return (struct isgx_enclave_page *)epc_page;

	/* The SECS page is not currently accounted. */
	secs_epc_page = isgx_alloc_epc_page(NULL, ISGX_ALLOC_ATOMIC);
	if (IS_ERR(secs_epc_page)) {
		isgx_free_epc_page(epc_page, enclave, ISGX_FREE_SKIP_EREMOVE);
		return (struct isgx_enclave_page *)secs_epc_page;
	}

	mutex_lock(&enclave->lock);

	if (list_empty(&enclave->vma_list)) {
		entry = ERR_PTR(-EFAULT);
		goto out;
	}

	if (!(enclave->flags & ISGX_ENCLAVE_INITIALIZED)) {
		isgx_dbg(enclave, "cannot fault, unitialized\n");
		entry = ERR_PTR(-EFAULT);
		goto out;
	}

	if (reserve && (entry->flags & ISGX_ENCLAVE_PAGE_RESERVED)) {
		isgx_dbg(enclave, "cannot fault, 0x%lx is reserved\n",
			 entry->addr);
		entry = ERR_PTR(-EBUSY);
		goto out;
	}

	/* Legal race condition, page is already faulted. */
	if (entry->epc_page) {
		if (reserve)
			entry->flags |= ISGX_ENCLAVE_PAGE_RESERVED;
		goto out;
	}

	/* If SECS is evicted then reload it first */
	if (enclave->flags & ISGX_ENCLAVE_SECS_EVICTED) {
		backing = isgx_get_backing(enclave, &enclave->secs_page);
		if (IS_ERR(backing)) {
			entry = (void *)backing;
			goto out;
		}

		rc = do_eldu(enclave, &enclave->secs_page, secs_epc_page,
			     backing, true /* is_secs */);
		isgx_put_backing(backing, 0);
		if (rc)
			goto out;

		enclave->secs_page.epc_page = secs_epc_page;
		enclave->flags &= ~ISGX_ENCLAVE_SECS_EVICTED;

		/* Do not free */
		secs_epc_page = NULL;
	}

	backing = isgx_get_backing(enclave, entry);
	if (IS_ERR(backing)) {
		entry = (void *)backing;
		goto out;
	}

	do_eldu(enclave, entry, epc_page, backing, false /* is_secs */);
	rc = vm_insert_pfn(vma, entry->addr, PFN_DOWN(epc_page->pa));
	isgx_put_backing(backing, 0);

	if (rc) {
		free_flags = 0;
		goto out;
	}

	enclave->secs_child_cnt++;

	entry->epc_page = epc_page;

	if (reserve)
		entry->flags |= ISGX_ENCLAVE_PAGE_RESERVED;

	/* Do not free */
	epc_page = NULL;

	list_add_tail(&entry->load_list, &enclave->load_list);
out:
	mutex_unlock(&enclave->lock);
	if (epc_page)
		isgx_free_epc_page(epc_page, enclave, free_flags);
	if (secs_epc_page)
		isgx_free_epc_page(secs_epc_page, NULL,
				   ISGX_FREE_SKIP_EREMOVE);
	return entry;
}

static int isgx_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	unsigned long addr = (unsigned long)vmf->virtual_address;
	struct isgx_enclave_page *entry;

	entry = isgx_vma_do_fault(vma, addr, 0);

	if (!IS_ERR(entry) || PTR_ERR(entry) == -EBUSY)
		return VM_FAULT_NOPAGE;
	else
		return VM_FAULT_SIGBUS;
}

static inline int isgx_vma_access_word(struct isgx_enclave *enclave,
				       unsigned long addr,
				       void *buf,
				       int len,
				       int write,
				       struct isgx_enclave_page *enclave_page,
				       int i)
{
	char data[sizeof(unsigned long)];
	int align, cnt, offset;
	void *vaddr;
	int ret;

	offset = ((addr + i) & (PAGE_SIZE - 1)) & ~(sizeof(unsigned long) - 1);
	align = (addr + i) & (sizeof(unsigned long) - 1);
	cnt = sizeof(unsigned long) - align;
	cnt = min(cnt, len - i);

	if (write) {
		if (enclave_page->flags & ISGX_ENCLAVE_PAGE_TCS &&
		    (offset < 8 || (offset + (len - i)) > 16))
			return -ECANCELED;

		if (align || (cnt != sizeof(unsigned long))) {
			vaddr = isgx_get_epc_page(enclave_page->epc_page);
			ret = __edbgrd((void *)((unsigned long)vaddr + offset),
				       (unsigned long *)data);
			isgx_put_epc_page(vaddr);
			if (ret) {
				isgx_dbg(enclave, "EDBGRD returned %d\n", ret);
				return -EFAULT;
			}
		}

		memcpy(data + align, buf + i, cnt);
		vaddr = isgx_get_epc_page(enclave_page->epc_page);
		ret = __edbgwr((void *)((unsigned long)vaddr + offset),
			       (unsigned long *)data);
		isgx_put_epc_page(vaddr);
		if (ret) {
			isgx_dbg(enclave, "EDBGWR returned %d\n", ret);
			return -EFAULT;
		}
	} else {
		if (enclave_page->flags & ISGX_ENCLAVE_PAGE_TCS &&
		    (offset + (len - i)) > 72)
			return -ECANCELED;

		vaddr = isgx_get_epc_page(enclave_page->epc_page);
		ret = __edbgrd((void *)((unsigned long)vaddr + offset),
			       (unsigned long *)data);
		isgx_put_epc_page(vaddr);
		if (ret) {
			isgx_dbg(enclave, "EDBGRD returned %d\n", ret);
			return -EFAULT;
		}

		memcpy(buf + i, data + align, cnt);
	}

	return cnt;
}

static int isgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
			   void *buf, int len, int write)
{
	struct isgx_enclave *enclave = vma->vm_private_data;
	struct isgx_enclave_page *entry = NULL;
	const char *op_str = write ? "EDBGWR" : "EDBGRD";
	int ret = 0;
	int i;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!enclave)
		return -EFAULT;

	if (!(enclave->flags & ISGX_ENCLAVE_DEBUG) ||
	    !(enclave->flags & ISGX_ENCLAVE_INITIALIZED) ||
	    (enclave->flags & ISGX_ENCLAVE_SUSPEND))
		return -EFAULT;

	isgx_dbg(enclave, "%s addr=0x%lx, len=%d\n", op_str, addr, len);

	for (i = 0; i < len; i += ret) {
		if (!entry || !((addr + i) & (PAGE_SIZE - 1))) {
			if (entry)
				entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;

			do {
				entry = isgx_vma_do_fault(
					vma, (addr + i) & PAGE_MASK, true);
			} while (entry == ERR_PTR(-EBUSY));

			if (IS_ERR(entry)) {
				ret = PTR_ERR(entry);
				entry = NULL;
				break;
			}
		}

		/* No locks are needed because used fields are immutable after
		 * intialization.
		 */
		ret = isgx_vma_access_word(enclave, addr, buf, len, write,
					   entry, i);
		if (ret < 0)
			break;
	}

	if (entry)
		entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;

	return (ret < 0 && ret != -ECANCELED) ? ret : i;
}

struct vm_operations_struct isgx_vm_ops = {
	.close = isgx_vma_close,
	.open = isgx_vma_open,
	.fault = isgx_vma_fault,
	.access = isgx_vma_access,
};
