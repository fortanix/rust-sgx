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
#include <linux/highmem.h>
#include <linux/shmem_fs.h>

void *sgx_get_epc_page(struct sgx_epc_page *entry)
{
#ifdef CONFIG_X86_32
	return kmap_atomic_pfn(PFN_DOWN(entry->pa));
#else
	return sgx_epc_mem + (entry->pa - sgx_epc_base);
#endif
}

void sgx_put_epc_page(void *epc_page_vaddr)
{
#ifdef CONFIG_X86_32
	kunmap_atomic(epc_page_vaddr);
#else
#endif
}

struct page *sgx_get_backing(struct sgx_enclave *enclave,
			     struct sgx_enclave_page *entry)
{
	struct page *backing;
	struct inode *inode;
	struct address_space *mapping;
	gfp_t gfpmask;
	pgoff_t index;

	inode = enclave->backing->f_path.dentry->d_inode;
	mapping = inode->i_mapping;
	gfpmask = mapping_gfp_mask(mapping);

	index = (entry->addr - enclave->base) >> PAGE_SHIFT;
	backing = shmem_read_mapping_page_gfp(mapping, index, gfpmask);

	return backing;
}

void sgx_put_backing(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	page_cache_release(backing_page);
}

/**
 * sgx_find_vma() - find VMA for the enclave address
 * @enclave:	the enclave to be searched
 * @addr:	the linear address to query
 *
 * Finds VMA for the given address of the enclave. Returns the VMA if
 * there is one containing the given address.
 */
struct sgx_vma *sgx_find_vma(struct sgx_enclave *enclave,
			     unsigned long addr)
{
	struct sgx_vma *tmp;
	struct sgx_vma *evma;

	list_for_each_entry_safe(evma, tmp, &enclave->vma_list, vma_list) {
		if (evma->vma->vm_start <= addr && evma->vma->vm_end > addr)
			return evma;
	}

	sgx_dbg(enclave, "cannot find VMA at 0x%lx\n", addr);
	return NULL;
}

/**
 * sgx_zap_tcs_ptes() - clear PTEs that contain TCS pages
 * @enclave	an enclave
 * @vma:	a VMA of the enclave
 */
void sgx_zap_tcs_ptes(struct sgx_enclave *enclave, struct vm_area_struct *vma)
{
	struct sgx_enclave_page *entry;
	struct rb_node *rb;

	rb = rb_first(&enclave->enclave_rb);
	while (rb) {
		entry = container_of(rb, struct sgx_enclave_page, node);
		rb = rb_next(rb);
		if (entry->epc_page && (entry->flags & ISGX_ENCLAVE_PAGE_TCS) &&
		    entry->addr >= vma->vm_start &&
		    entry->addr < vma->vm_end)
			zap_vma_ptes(vma, entry->addr, PAGE_SIZE);
	}
}

/**
 * sgx_pin_mm - pin the mm_struct of an enclave
 *
 * @encl:	an enclave
 *
 * Locks down mmap_sem of an enclave if it still has VMAs and was not suspended.
 * Returns true if this the case.
 */
bool sgx_pin_mm(struct sgx_enclave *encl)
{
	if (encl->flags & ISGX_ENCLAVE_SUSPEND)
		return false;

	mutex_lock(&encl->lock);
	if (!list_empty(&encl->vma_list)) {
		atomic_inc(&encl->mm->mm_count);
	} else {
		mutex_unlock(&encl->lock);
		return false;
	}
	mutex_unlock(&encl->lock);

	down_read(&encl->mm->mmap_sem);

	if (list_empty(&encl->vma_list)) {
		sgx_unpin_mm(encl);
		return false;
	}

	return true;
}

/**
 * sgx_unpin_mm - unpin the mm_struct of an enclave
 *
 * @encl:	an enclave
 *
 * Unlocks the mmap_sem.
 */
void sgx_unpin_mm(struct sgx_enclave *encl)
{
	up_read(&encl->mm->mmap_sem);
	mmdrop(encl->mm);
}

/**
 * sgx_unpin_mm - invalidate the enclave
 *
 * @encl:	an enclave
 *
 * Unmap TCS pages and empty the VMA list.
 */
void sgx_invalidate(struct sgx_enclave *encl)
{
	struct sgx_vma *vma;

	list_for_each_entry(vma, &encl->vma_list, vma_list)
		sgx_zap_tcs_ptes(encl, vma->vma);

	while (!list_empty(&encl->vma_list)) {
		vma = list_first_entry(&encl->vma_list, struct sgx_vma,
				       vma_list);
		list_del(&vma->vma_list);
		kfree(vma);
	}
}

/**
 * sgx_find_enclave() - find enclave given a virtual address
 * @mm:		the address space where we query the enclave
 * @addr:	the virtual address to query
 * @vma:	VMA if an enclave is found or NULL if not
 *
 * Finds an enclave given a virtual address and a address space where to seek it
 * from. The return value is zero on success. Otherwise, it is either positive
 * for SGX specific errors or negative for the system errors.
 */
int sgx_find_enclave(struct mm_struct *mm, unsigned long addr,
		     struct vm_area_struct **vma)
{
	struct sgx_enclave *enclave;

	*vma = find_vma(mm, addr);

	if (!(*vma) || (*vma)->vm_ops != &sgx_vm_ops ||
	    addr < (*vma)->vm_start)
		return -EINVAL;

	/* Is ECREATE already done? */
	enclave = (*vma)->vm_private_data;
	if (!enclave)
		return -ENOENT;

	if (enclave->flags & ISGX_ENCLAVE_SUSPEND) {
		sgx_info(enclave,  "suspend ID has been changed");
		return SGX_POWER_LOST_ENCLAVE;
	}

	return 0;
}

/**
 * sgx_enclave_find_page() - find an enclave page
 * @encl:	the enclave to query
 * @addr:	the virtual address to query
 */
struct sgx_enclave_page *sgx_enclave_find_page(struct sgx_enclave *enclave,
					       unsigned long addr)
{
	struct rb_node *node = enclave->enclave_rb.rb_node;

	while (node) {
		struct sgx_enclave_page *data =
			container_of(node, struct sgx_enclave_page, node);

		if (data->addr > addr)
			node = node->rb_left;
		else if (data->addr < addr)
			node = node->rb_right;
		else
			return data;
	}

	return NULL;
}

void sgx_enclave_release(struct kref *ref)
{
	struct rb_node *rb1, *rb2;
	struct sgx_enclave_page *entry;
	struct sgx_va_page *va_page;
	struct sgx_enclave *enclave =
		container_of(ref, struct sgx_enclave, refcount);

	mutex_lock(&sgx_tgid_ctx_mutex);
	if (!list_empty(&enclave->enclave_list))
		list_del(&enclave->enclave_list);

	mutex_unlock(&sgx_tgid_ctx_mutex);

	rb1 = rb_first(&enclave->enclave_rb);
	while (rb1) {
		entry = container_of(rb1, struct sgx_enclave_page, node);
		rb2 = rb_next(rb1);
		rb_erase(rb1, &enclave->enclave_rb);
		if (entry->epc_page) {
			list_del(&entry->load_list);
			sgx_free_epc_page(entry->epc_page, enclave, 0);
		}
		kfree(entry);
		rb1 = rb2;
	}

	while (!list_empty(&enclave->va_pages)) {
		va_page = list_first_entry(&enclave->va_pages,
					   struct sgx_va_page, list);
		list_del(&va_page->list);
		sgx_free_epc_page(va_page->epc_page, enclave, 0);
		kfree(va_page);
	}

	if (enclave->secs_page.epc_page)
		sgx_free_epc_page(enclave->secs_page.epc_page, enclave, 0);

	enclave->secs_page.epc_page = NULL;

	if (enclave->tgid_ctx)
		kref_put(&enclave->tgid_ctx->refcount, release_tgid_ctx);

	if (enclave->backing)
		fput(enclave->backing);

	kfree(enclave);
}
