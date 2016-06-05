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
#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/shmem_fs.h>

struct sgx_add_page_req {
	struct list_head list;
	struct sgx_enclave_page *enclave_page;
	struct sgx_secinfo secinfo;
	u16 mrmask;
};

static u16 sgx_isvsvnle_min;
atomic_t sgx_nr_pids = ATOMIC_INIT(0);

static struct sgx_tgid_ctx *find_tgid_epc_cnt(struct pid *tgid)
{
	struct sgx_tgid_ctx *ctx;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list)
		if (pid_nr(ctx->tgid) == pid_nr(tgid))
			return ctx;

	return NULL;
}

static int add_tgid_ctx(struct sgx_enclave *enclave)
{
	struct sgx_tgid_ctx *ctx;
	struct pid *tgid = get_pid(task_tgid(current));

	mutex_lock(&sgx_tgid_ctx_mutex);

	ctx = find_tgid_epc_cnt(tgid);
	if (ctx) {
		kref_get(&ctx->refcount);
		enclave->tgid_ctx = ctx;
		mutex_unlock(&sgx_tgid_ctx_mutex);
		put_pid(tgid);
		return 0;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		put_pid(tgid);
		return -ENOMEM;
	}

	ctx->tgid = tgid;
	kref_init(&ctx->refcount);
	INIT_LIST_HEAD(&ctx->enclave_list);

	list_add(&ctx->list, &sgx_tgid_ctx_list);
	atomic_inc(&sgx_nr_pids);

	enclave->tgid_ctx = ctx;

	mutex_unlock(&sgx_tgid_ctx_mutex);
	return 0;
}

void release_tgid_ctx(struct kref *ref)
{
	struct sgx_tgid_ctx *pe =
		container_of(ref, struct sgx_tgid_ctx, refcount);
	mutex_lock(&sgx_tgid_ctx_mutex);
	list_del(&pe->list);
	atomic_dec(&sgx_nr_pids);
	mutex_unlock(&sgx_tgid_ctx_mutex);
	put_pid(pe->tgid);
	kfree(pe);
}

static int enclave_rb_insert(struct rb_root *root,
			     struct sgx_enclave_page *data)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct sgx_enclave_page *this =
			container_of(*new, struct sgx_enclave_page, node);

		parent = *new;
		if (data->addr < this->addr)
			new = &((*new)->rb_left);
		else if (data->addr > this->addr)
			new = &((*new)->rb_right);
		else
			return -EFAULT;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return 0;
}

/**
 * construct_enclave_page() - populate a new enclave page instance
 * @enclave	an enclave
 * @entry	the enclave page to be populated
 * @addr	the linear address of the enclave page
 *
 * Allocates VA slot for the enclave page and fills out its fields. Returns
 * an error code on failure that can be either a POSIX error code or one of the
 * error codes defined in sgx_user.h.
 */
static int construct_enclave_page(struct sgx_enclave *enclave,
				  struct sgx_enclave_page *entry,
				  unsigned long addr)
{
	struct sgx_va_page *va_page;
	struct sgx_epc_page *epc_page = NULL;
	unsigned int va_offset = PAGE_SIZE;
	void *vaddr;
	int ret = 0;

	list_for_each_entry(va_page, &enclave->va_pages, list) {
		va_offset = sgx_alloc_va_slot(va_page);
		if (va_offset < PAGE_SIZE)
			break;
	}

	if (va_offset == PAGE_SIZE) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;

		epc_page = sgx_alloc_epc_page(enclave->tgid_ctx, 0);
		if (IS_ERR(epc_page)) {
			kfree(va_page);
			return PTR_ERR(epc_page);
		}

		vaddr = sgx_get_epc_page(epc_page);
		if (!vaddr) {
			sgx_warn(enclave, "kmap of a new VA page failed %d\n",
				 ret);
			sgx_free_epc_page(epc_page, enclave,
					  ISGX_FREE_SKIP_EREMOVE);
			kfree(va_page);
			return -EFAULT;
		}

		ret = __epa(vaddr);
		sgx_put_epc_page(vaddr);

		if (ret) {
			sgx_warn(enclave, "EPA returned %d\n", ret);
			sgx_free_epc_page(epc_page, enclave,
					  ISGX_FREE_SKIP_EREMOVE);
			kfree(va_page);
			return -EFAULT;
		}

		va_page->epc_page = epc_page;
		va_offset = sgx_alloc_va_slot(va_page);
		list_add(&va_page->list, &enclave->va_pages);
	}

	entry->enclave = enclave;
	entry->va_page = va_page;
	entry->va_offset = va_offset;
	entry->addr = addr;

	return 0;
}

static int get_enclave(unsigned long addr, struct sgx_enclave **enclave)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret;

	down_read(&mm->mmap_sem);

	ret = sgx_find_enclave(mm, addr, &vma);
	if (!ret) {
		*enclave = vma->vm_private_data;
		kref_get(&(*enclave)->refcount);
	}

	up_read(&mm->mmap_sem);

	return ret;
}

static int validate_secs(const struct sgx_secs *secs)
{
	u32 needed_ssaframesize = 1;
	u32 tmp;
	int i;

	if (secs->flags & SGX_SECS_A_RESERVED_MASK)
		return -EINVAL;

	if (secs->flags & SGX_SECS_A_MODE64BIT) {
#ifdef CONFIG_X86_64
		if (secs->size > sgx_enclave_size_max_64)
			return -EINVAL;
#else
		return -EINVAL;
#endif
	} else {
		/* On 64-bit architecture allow 32-bit enclaves only in
		 * the compatibility mode.
		 */
#ifdef CONFIG_X86_64
		if (!test_thread_flag(TIF_ADDR32))
			return -EINVAL;
#endif
		if (secs->size > sgx_enclave_size_max_32)
			return -EINVAL;
	}

	if ((secs->xfrm & 0x3) != 0x3 || (secs->xfrm & ~sgx_xfrm_mask))
		return -EINVAL;

	/* SKL quirk */
	if ((secs->xfrm & BIT(3)) != (secs->xfrm & BIT(4)))
		return -EINVAL;

	for (i = 2; i < 64; i++) {
		tmp = sgx_ssaframesize_tbl[i];
		if (((1 << i) & secs->xfrm) && (tmp > needed_ssaframesize))
			needed_ssaframesize = tmp;
	}

	if (!secs->ssaframesize || !needed_ssaframesize ||
	    needed_ssaframesize > secs->ssaframesize)
		return -EINVAL;

	/* Must be power of two  */
	if (secs->size == 0 || (secs->size & (secs->size - 1)) != 0)
		return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED1_SIZE; i++)
		if (secs->reserved1[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED2_SIZE; i++)
		if (secs->reserved2[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED3_SIZE; i++)
		if (secs->reserved3[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED4_SIZE; i++)
		if (secs->reserved[i])
			return -EINVAL;

	return 0;
}

static long sgx_ioctl_enclave_create(struct file *filep, unsigned int cmd,
				     unsigned long arg)
{
	struct sgx_enclave_create *createp = (struct sgx_enclave_create *)arg;
	struct sgx_page_info pginfo;
	struct sgx_secinfo secinfo;
	struct sgx_enclave *enclave = NULL;
	struct sgx_secs *secs = NULL;
	struct sgx_epc_page *secs_epc;
	struct vm_area_struct *vma;
	struct sgx_vma *evma;
	void *secs_vaddr = NULL;
	struct file *backing;
	long ret;

	secs = kzalloc(sizeof(*secs),  GFP_KERNEL);
	if (!secs)
		return -ENOMEM;

	ret = copy_from_user(secs, (void __user *)createp->src, sizeof(*secs));
	if (ret) {
		kfree(secs);
		return ret;
	}

	if (validate_secs(secs)) {
		kfree(secs);
		return -EINVAL;
	}

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, secs->base);
	if (!vma || vma->vm_ops != &sgx_vm_ops ||
	    vma->vm_start != secs->base ||
	    vma->vm_end != (secs->base + secs->size)) {
		ret = -EINVAL;
		goto out;
	}

	backing = shmem_file_setup("dev/sgx", secs->size + PAGE_SIZE,
				   VM_NORESERVE);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto out;
	}

	enclave = kzalloc(sizeof(*enclave), GFP_KERNEL);
	if (!enclave) {
		fput(backing);
		ret = -ENOMEM;
		goto out;
	}

	kref_init(&enclave->refcount);
	INIT_LIST_HEAD(&enclave->add_page_reqs);
	INIT_LIST_HEAD(&enclave->va_pages);
	INIT_LIST_HEAD(&enclave->vma_list);
	INIT_LIST_HEAD(&enclave->load_list);
	INIT_LIST_HEAD(&enclave->enclave_list);
	mutex_init(&enclave->lock);
	INIT_WORK(&enclave->add_page_work, sgx_add_page_worker);

	enclave->owner = current->group_leader;
	enclave->mm = current->mm;
	enclave->base = secs->base;
	enclave->size = secs->size;
	enclave->backing = backing;

	secs_epc = sgx_alloc_epc_page(enclave->tgid_ctx, 0);
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		secs_epc = NULL;
		goto out;
	}

	ret = add_tgid_ctx(enclave);
	if (ret)
		goto out;

	ret = construct_enclave_page(enclave, &enclave->secs_page,
				     enclave->base + enclave->size);
	if (ret)
		goto out;

	secs_vaddr = sgx_get_epc_page(secs_epc);

	pginfo.srcpge = (unsigned long)secs;
	pginfo.linaddr = 0;
	pginfo.secinfo = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));
	ret = __ecreate((void *)&pginfo, secs_vaddr);

	sgx_put_epc_page(secs_vaddr);

	if (ret) {
		sgx_info(enclave, "ECREATE returned %ld\n", ret);
		goto out;
	}

	enclave->secs_page.epc_page = secs_epc;
	createp->src = (unsigned long)enclave->base;

	if (secs->flags & SGX_SECS_A_DEBUG)
		enclave->flags |= ISGX_ENCLAVE_DEBUG;

	evma = kzalloc(sizeof(*evma), GFP_KERNEL);
	if (!evma) {
		ret = -ENOMEM;
		goto out;
	}
	evma->vma = vma;
	list_add_tail(&evma->vma_list, &enclave->vma_list);
	vma->vm_private_data = enclave;

	mutex_lock(&sgx_tgid_ctx_mutex);
	list_add_tail(&enclave->enclave_list, &enclave->tgid_ctx->enclave_list);
	mutex_unlock(&sgx_tgid_ctx_mutex);
out:
	if (ret && enclave)
		kref_put(&enclave->refcount, sgx_enclave_release);
	up_read(&current->mm->mmap_sem);
	kfree(secs);
	return ret;
}

static int validate_secinfo(struct sgx_secinfo *secinfo)
{
	u64 perm = secinfo->flags & ISGX_SECINFO_PERMISSION_MASK;
	u64 page_type = secinfo->flags & ISGX_SECINFO_PAGE_TYPE_MASK;
	int i;

	if ((secinfo->flags & ISGX_SECINFO_RESERVED_MASK) ||
	    ((perm & SGX_SECINFO_W) && !(perm & SGX_SECINFO_R)) ||
	    (page_type != SGX_SECINFO_TCS &&
	     page_type != SGX_SECINFO_REG))
		return -EINVAL;

	for (i = 0; i < sizeof(secinfo->reserved) / sizeof(u64); i++)
		if (secinfo->reserved[i])
			return -EINVAL;

	return 0;
}

static int validate_tcs(struct sgx_tcs *tcs)
{
	int i;

	/* If FLAGS is not zero, ECALL will fail. */
	if ((tcs->flags != 0) ||
	    (tcs->ossa & (PAGE_SIZE - 1)) ||
	    (tcs->ofsbase & (PAGE_SIZE - 1)) ||
	    (tcs->ogsbase & (PAGE_SIZE - 1)) ||
	    ((tcs->fslimit & 0xFFF) != 0xFFF) ||
	    ((tcs->gslimit & 0xFFF) != 0xFFF))
		return -EINVAL;

	for (i = 0; i < sizeof(tcs->reserved) / sizeof(u64); i++)
		if (tcs->reserved[i])
			return -EINVAL;

	return 0;
}

static int __enclave_add_page(struct sgx_enclave *enclave,
			      struct sgx_enclave_page *enclave_page,
			      struct sgx_enclave_add_page *addp,
			      struct sgx_secinfo *secinfo)
{
	u64 page_type = secinfo->flags & ISGX_SECINFO_PAGE_TYPE_MASK;
	struct sgx_tcs *tcs;
	struct page *backing;
	struct sgx_add_page_req *req = NULL;
	int ret;
	int empty;
	void *user_vaddr;
	void *tmp_vaddr;
	struct page *tmp_page;

	tmp_page = alloc_page(GFP_HIGHUSER);
	if (!tmp_page)
		return -ENOMEM;

	tmp_vaddr = kmap(tmp_page);
	ret = copy_from_user((void *)tmp_vaddr, (void *)addp->src, PAGE_SIZE);
	kunmap(tmp_page);
	if (ret) {
		__free_page(tmp_page);
		return -EFAULT;
	}

	if (validate_secinfo(secinfo)) {
		__free_page(tmp_page);
		return -EINVAL;
	}

	if (page_type == SGX_SECINFO_TCS) {
		tcs = (struct sgx_tcs *)kmap(tmp_page);
		ret = validate_tcs(tcs);
		kunmap(tmp_page);
		if (ret) {
			__free_page(tmp_page);
			return ret;
		}
	}

	ret = construct_enclave_page(enclave, enclave_page, addp->addr);
	if (ret) {
		__free_page(tmp_page);
		return -EINVAL;
	}

	mutex_lock(&enclave->lock);

	if (enclave->flags & ISGX_ENCLAVE_INITIALIZED) {
		ret = -EINVAL;
		goto out;
	}

	if (sgx_enclave_find_page(enclave, addp->addr)) {
		ret = -EEXIST;
		goto out;
	}

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	backing = sgx_get_backing(enclave, enclave_page);
	if (IS_ERR((void *)backing)) {
		ret = PTR_ERR((void *)backing);
		goto out;
	}

	user_vaddr = kmap(backing);
	tmp_vaddr = kmap(tmp_page);
	memcpy(user_vaddr, tmp_vaddr, PAGE_SIZE);
	kunmap(backing);
	kunmap(tmp_page);

	if (page_type == SGX_SECINFO_TCS)
		enclave_page->flags |= ISGX_ENCLAVE_PAGE_TCS;

	memcpy(&req->secinfo, secinfo, sizeof(*secinfo));

	req->enclave_page = enclave_page;
	req->mrmask = addp->mrmask;
	empty = list_empty(&enclave->add_page_reqs);
	kref_get(&enclave->refcount);
	list_add_tail(&req->list, &enclave->add_page_reqs);
	if (empty)
		queue_work(sgx_add_page_wq, &enclave->add_page_work);

	sgx_put_backing(backing, true /* write */);
out:

	if (ret) {
		kfree(req);
		sgx_free_va_slot(enclave_page->va_page,
				 enclave_page->va_offset);
	} else {
		ret = enclave_rb_insert(&enclave->enclave_rb, enclave_page);
		WARN_ON(ret);
	}

	mutex_unlock(&enclave->lock);
	__free_page(tmp_page);
	return ret;
}

static long sgx_ioctl_enclave_add_page(struct file *filep, unsigned int cmd,
				       unsigned long arg)
{
	struct sgx_enclave_add_page *addp;
	struct sgx_enclave *enclave;
	struct sgx_enclave_page *page;
	struct sgx_secinfo secinfo;
	int ret;

	addp = (struct sgx_enclave_add_page *)arg;
	if (addp->addr & (PAGE_SIZE - 1))
		return -EINVAL;

	if (copy_from_user(&secinfo, (void __user *)addp->secinfo,
			   sizeof(secinfo)))
		return -EFAULT;

	ret = get_enclave(addp->addr, &enclave);
	if (ret)
		return ret;

	if (addp->addr < enclave->base ||
	    addp->addr > (enclave->base + enclave->size - PAGE_SIZE)) {
		kref_put(&enclave->refcount, sgx_enclave_release);
		return -EINVAL;
	}

	page = kzalloc(sizeof(*page), GFP_KERNEL);
	if (!page) {
		kref_put(&enclave->refcount, sgx_enclave_release);
		return -ENOMEM;
	}

	ret = __enclave_add_page(enclave, page, addp, &secinfo);
	kref_put(&enclave->refcount, sgx_enclave_release);

	if (ret)
		kfree(page);

	return ret;
}

static int __sgx_enclave_init(struct sgx_enclave *enclave,
			      char *sigstruct,
			      struct sgx_einittoken *einittoken)
{
	int ret = SGX_UNMASKED_EVENT;
	struct sgx_epc_page *secs_epc = enclave->secs_page.epc_page;
	void *secs_va = NULL;
	int i;
	int j;

	if (einittoken->valid && einittoken->isvsvnle < sgx_isvsvnle_min)
		return SGX_LE_ROLLBACK;

	for (i = 0; i < EINIT_TRY_COUNT; i++) {
		for (j = 0; j < EINIT_SPIN_COUNT; j++) {
			mutex_lock(&enclave->lock);
			secs_va = sgx_get_epc_page(secs_epc);
			ret = __einit(sigstruct, einittoken, secs_va);
			sgx_put_epc_page(secs_va);
			mutex_unlock(&enclave->lock);
			if (ret == SGX_UNMASKED_EVENT)
				continue;
			else
				break;
		}

		if (ret != SGX_UNMASKED_EVENT)
			goto out;

		msleep_interruptible(EINIT_BACKOFF_TIME);
		if (signal_pending(current))
			return -EINTR;
	}

out:
	if (ret) {
		sgx_info(enclave, "EINIT returned %d\n", ret);
	} else {
		enclave->flags |= ISGX_ENCLAVE_INITIALIZED;

		if (einittoken->isvsvnle > sgx_isvsvnle_min)
			sgx_isvsvnle_min = einittoken->isvsvnle;
	}

	return ret;
}

static long sgx_ioctl_enclave_init(struct file *filep, unsigned int cmd,
				   unsigned long arg)
{
	int ret = -EINVAL;
	struct sgx_enclave_init *initp = (struct sgx_enclave_init *)arg;
	unsigned long enclave_id = initp->addr;
	char *sigstruct;
	struct sgx_einittoken *einittoken;
	struct sgx_enclave *enclave;
	struct page *initp_page;

	initp_page = alloc_page(GFP_HIGHUSER);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
	einittoken = (struct sgx_einittoken *)
		((unsigned long)sigstruct + PAGE_SIZE / 2);

	ret = copy_from_user(sigstruct, (void __user *)initp->sigstruct,
			     SIGSTRUCT_SIZE);
	if (ret)
		goto out_free_page;

	ret = copy_from_user(einittoken, (void __user *)initp->einittoken,
			     EINITTOKEN_SIZE);
	if (ret)
		goto out_free_page;

	ret = get_enclave(enclave_id, &enclave);
	if (ret)
		goto out_free_page;

	mutex_lock(&enclave->lock);
	if (enclave->flags & ISGX_ENCLAVE_INITIALIZED) {
		ret = -EINVAL;
		mutex_unlock(&enclave->lock);
		goto out;
	}
	mutex_unlock(&enclave->lock);

	flush_work(&enclave->add_page_work);

	ret = __sgx_enclave_init(enclave, sigstruct, einittoken);
out:
	kref_put(&enclave->refcount, sgx_enclave_release);
out_free_page:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

typedef long (*sgx_ioctl_t)(struct file *filep, unsigned int cmd,
			     unsigned long arg);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	sgx_ioctl_t handler = NULL;
	long ret;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		handler = sgx_ioctl_enclave_create;
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		handler = sgx_ioctl_enclave_add_page;
		break;
	case SGX_IOC_ENCLAVE_INIT:
		handler = sgx_ioctl_enclave_init;
		break;
	default:
		return -EINVAL;
	}

	if (copy_from_user(data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = handler(filep, cmd, (unsigned long)((void *)data));
	if (!ret && (cmd & IOC_OUT)) {
		if (copy_to_user((void __user *)arg, data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}

	return ret;
}

static int sgx_add_page(struct sgx_epc_page *secs_page,
			struct sgx_epc_page *epc_page,
			unsigned long linaddr,
			struct sgx_secinfo *secinfo,
			struct page *backing)
{
	struct sgx_page_info pginfo;
	void *epc_page_vaddr;
	int ret;

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	pginfo.secs = (unsigned long)sgx_get_epc_page(secs_page);
	epc_page_vaddr = sgx_get_epc_page(epc_page);

	pginfo.linaddr = linaddr;
	pginfo.secinfo = (unsigned long)secinfo;
	ret = __eadd(&pginfo, epc_page_vaddr);

	sgx_put_epc_page(epc_page_vaddr);
	sgx_put_epc_page((void *)(unsigned long)pginfo.secs);
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);

	return ret;
}

static int sgx_measure(struct sgx_epc_page *secs_page,
		       struct sgx_epc_page *epc_page,
		       u16 mrmask)
{
	void *secs;
	void *epc;
	int ret = 0;
	int i, j;

	for (i = 0, j = 1; i < 0x1000 && !ret; i += 0x100, j <<= 1) {
		if (!(j & mrmask))
			continue;

		secs = sgx_get_epc_page(secs_page);
		epc = sgx_get_epc_page(epc_page);

		ret = __eextend(secs, (void *)((unsigned long)epc + i));

		sgx_put_epc_page(epc);
		sgx_put_epc_page(secs);
	}

	return ret;
}

static bool process_add_page_req(struct sgx_add_page_req *req)
{
	struct page *backing;
	struct sgx_epc_page *epc_page;
	struct sgx_enclave_page *enclave_page = req->enclave_page;
	struct sgx_enclave *enclave = enclave_page->enclave;
	unsigned free_flags = ISGX_FREE_SKIP_EREMOVE;
	struct vm_area_struct *vma;
	int ret;

	epc_page = sgx_alloc_epc_page(enclave->tgid_ctx, 0);
	if (IS_ERR(epc_page))
		return false;

	if (!sgx_pin_mm(enclave)) {
		sgx_free_epc_page(epc_page, enclave, free_flags);
		return false;
	}

	mutex_lock(&enclave->lock);

	if (list_empty(&enclave->vma_list) ||
	    sgx_find_enclave(enclave->mm, enclave_page->addr, &vma))
		goto out;

	backing = sgx_get_backing(enclave, enclave_page);
	if (IS_ERR(backing))
		goto out;

	/* Do not race with do_exit() */
	if (!atomic_read(&enclave->mm->mm_users)) {
		sgx_put_backing(backing, 0);
		goto out;
	}

	ret = vm_insert_pfn(vma, enclave_page->addr, PFN_DOWN(epc_page->pa));
	if (ret)
		goto out;

	ret = sgx_add_page(enclave->secs_page.epc_page, epc_page,
			   enclave_page->addr, &req->secinfo, backing);

	sgx_put_backing(backing, 0);
	free_flags = 0;
	if (ret) {
		sgx_warn(enclave, "EADD returned %d\n", ret);
		zap_vma_ptes(vma, enclave_page->addr, PAGE_SIZE);
		goto out;
	}

	enclave->secs_child_cnt++;

	ret = sgx_measure(enclave->secs_page.epc_page, epc_page, req->mrmask);
	if (ret) {
		sgx_warn(enclave, "EEXTEND returned %d\n", ret);
		zap_vma_ptes(vma, enclave_page->addr, PAGE_SIZE);
		goto out;
	}

	enclave_page->epc_page = epc_page;
	list_add_tail(&enclave_page->load_list, &enclave->load_list);

	mutex_unlock(&enclave->lock);
	sgx_unpin_mm(enclave);
	return true;
out:
	sgx_free_epc_page(epc_page, enclave, free_flags);
	mutex_unlock(&enclave->lock);
	sgx_unpin_mm(enclave);
	return false;
}

void sgx_add_page_worker(struct work_struct *work)
{
	struct sgx_enclave *enclave;
	struct sgx_add_page_req *req;
	bool skip_rest = false;
	bool is_empty = false;

	enclave = container_of(work, struct sgx_enclave, add_page_work);

	do {
		schedule();

		if (enclave->flags & ISGX_ENCLAVE_SUSPEND)
			skip_rest = true;

		mutex_lock(&enclave->lock);
		req = list_first_entry(&enclave->add_page_reqs,
				       struct sgx_add_page_req, list);
		list_del(&req->list);
		is_empty = list_empty(&enclave->add_page_reqs);
		mutex_unlock(&enclave->lock);

		if (!skip_rest)
			if (!process_add_page_req(req))
				skip_rest = true;

		kfree(req);
	} while (!kref_put(&enclave->refcount, sgx_enclave_release) &&
		 !is_empty);
}
