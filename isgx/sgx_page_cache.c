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
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>

static LIST_HEAD(sgx_free_list);
static DEFINE_SPINLOCK(sgx_free_list_lock);

LIST_HEAD(sgx_tgid_ctx_list);
DEFINE_MUTEX(sgx_tgid_ctx_mutex);
static unsigned int sgx_nr_total_epc_pages;
static unsigned int sgx_nr_free_epc_pages;
static unsigned int sgx_nr_low_epc_pages = ISGX_NR_LOW_EPC_PAGES_DEFAULT;
static unsigned int sgx_nr_high_epc_pages;
struct task_struct *kisgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(kisgxswapd_waitq);

static struct sgx_tgid_ctx *isolate_tgid_ctx(unsigned long nr_to_scan)
{
	struct sgx_tgid_ctx *ctx = NULL;
	int i;

	mutex_lock(&sgx_tgid_ctx_mutex);

	if (list_empty(&sgx_tgid_ctx_list)) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		return NULL;
	}

	for (i = 0; i < nr_to_scan; i++) {
		/* Peek TGID context from the head. */
		ctx = list_first_entry(&sgx_tgid_ctx_list,
				       struct sgx_tgid_ctx,
				       list);

		/* Move to the tail so that we do not encounter it in the
		 * next iteration.
		 */
		list_move_tail(&ctx->list, &sgx_tgid_ctx_list);

		/* Non-empty TGID context? */
		if (!list_empty(&ctx->enclave_list) &&
		    kref_get_unless_zero(&ctx->refcount))
			break;

		ctx = NULL;
	}

	mutex_unlock(&sgx_tgid_ctx_mutex);

	return ctx;
}

static struct sgx_enclave *isolate_enclave(struct sgx_tgid_ctx *ctx,
					   unsigned long nr_to_scan)
{
	struct sgx_enclave *encl = NULL;
	int i;

	mutex_lock(&sgx_tgid_ctx_mutex);

	if (list_empty(&ctx->enclave_list)) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		return NULL;
	}

	for (i = 0; i < nr_to_scan; i++) {
		/* Peek enclave from the head. */
		encl = list_first_entry(&ctx->enclave_list,
					struct sgx_enclave,
					enclave_list);

		/* Move to the tail so that we do not encounter it in the
		 * next iteration.
		 */
		list_move_tail(&encl->enclave_list, &ctx->enclave_list);

		/* Enclave with faulted pages?  */
		if (!list_empty(&encl->load_list) &&
		    kref_get_unless_zero(&encl->refcount))
			break;

		encl = NULL;
	}

	mutex_unlock(&sgx_tgid_ctx_mutex);

	return encl;
}

static void sgx_isolate_pages(struct sgx_enclave *encl,
			      struct list_head *dst,
			      unsigned long nr_to_scan)
{
	struct sgx_enclave_page *entry;
	int i;

	mutex_lock(&encl->lock);

	for (i = 0; i < nr_to_scan; i++) {
		if (list_empty(&encl->load_list))
			break;

		entry = list_first_entry(&encl->load_list,
					 struct sgx_enclave_page,
					 load_list);

		if (!(entry->flags & ISGX_ENCLAVE_PAGE_RESERVED)) {
			entry->flags |= ISGX_ENCLAVE_PAGE_RESERVED;
			list_move_tail(&entry->load_list, dst);
		} else {
			list_move_tail(&entry->load_list, &encl->load_list);
		}
	}

	mutex_unlock(&encl->lock);
}

static void sgx_ipi_cb(void *info)
{
}

static void do_eblock(struct sgx_epc_page *epc_page)
{
	void *vaddr;

	vaddr = sgx_get_epc_page(epc_page);
	BUG_ON(__eblock((unsigned long)vaddr));
	sgx_put_epc_page(vaddr);
}

static void do_etrack(struct sgx_epc_page *epc_page)
{
	void *epc;

	epc = sgx_get_epc_page(epc_page);
	BUG_ON(__etrack(epc));
	sgx_put_epc_page(epc);
}

static int do_ewb(struct sgx_enclave *enclave,
		  struct sgx_enclave_page *enclave_page,
		  struct page *backing)
{
	struct sgx_page_info pginfo;
	void *epc;
	void *va;
	int ret;

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	epc = sgx_get_epc_page(enclave_page->epc_page);
	va = sgx_get_epc_page(enclave_page->va_page->epc_page);

	pginfo.pcmd = (unsigned long)&enclave_page->pcmd;
	pginfo.linaddr = 0;
	pginfo.secs = 0;
	ret = __ewb(&pginfo, epc,
		    (void *)((unsigned long)va + enclave_page->va_offset));

	sgx_put_epc_page(va);
	sgx_put_epc_page(epc);
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);

	if (ret != 0 && ret != SGX_NOT_TRACKED)
		sgx_err(enclave, "EWB returned %d\n", ret);

	return ret;
}

void sgx_free_enclave_page(struct sgx_enclave_page *entry,
		    struct sgx_enclave *encl,
		    unsigned int flags)
{
	sgx_free_epc_page(entry->epc_page, encl, flags);
	entry->epc_page = NULL;
	entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
}

static void sgx_write_pages(struct list_head *src)
{
	struct sgx_enclave *enclave;
	struct sgx_enclave_page *entry;
	struct sgx_enclave_page *tmp;
	struct page *pages[ISGX_NR_SWAP_CLUSTER_MAX + 1];
	struct sgx_vma *evma;
	int cnt = 0;
	int i = 0;
	int ret;

	if (list_empty(src))
		return;

	entry = list_first_entry(src, struct sgx_enclave_page, load_list);
	enclave = entry->enclave;

	if (!sgx_pin_mm(enclave)) {
		while (!list_empty(src)) {
			entry = list_first_entry(src, struct sgx_enclave_page,
						 load_list);
			list_del(&entry->load_list);
			mutex_lock(&enclave->lock);
			sgx_free_enclave_page(entry, enclave, 0);
			mutex_unlock(&enclave->lock);
		}

		return;
	}

	/* EBLOCK */

	list_for_each_entry_safe(entry, tmp, src, load_list) {
		mutex_lock(&enclave->lock);
		evma = sgx_find_vma(enclave, entry->addr);
		if (!evma) {
			list_del(&entry->load_list);
			sgx_free_enclave_page(entry, enclave, 0);
			mutex_unlock(&enclave->lock);
			continue;
		}

		pages[cnt] = sgx_get_backing(enclave, entry);
		if (IS_ERR(pages[cnt])) {
			list_del(&entry->load_list);
			list_add_tail(&entry->load_list, &enclave->load_list);
			entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
			mutex_unlock(&enclave->lock);
			continue;
		}

		zap_vma_ptes(evma->vma, entry->addr, PAGE_SIZE);
		do_eblock(entry->epc_page);
		cnt++;
		mutex_unlock(&enclave->lock);
	}

	/* ETRACK */

	mutex_lock(&enclave->lock);
	do_etrack(enclave->secs_page.epc_page);
	mutex_unlock(&enclave->lock);

	/* EWB */

	mutex_lock(&enclave->lock);
	i = 0;

	while (!list_empty(src)) {
		entry = list_first_entry(src, struct sgx_enclave_page,
					 load_list);
		list_del(&entry->load_list);

		evma = sgx_find_vma(enclave, entry->addr);
		if (evma) {
			ret = do_ewb(enclave, entry, pages[i]);
			BUG_ON(ret != 0 && ret != SGX_NOT_TRACKED);
			/* Only kick out threads with an IPI if needed. */
			if (ret) {
				smp_call_function(sgx_ipi_cb, NULL, 1);
				BUG_ON(do_ewb(enclave, entry, pages[i]));
			}
			enclave->secs_child_cnt--;
		}

		sgx_free_enclave_page(entry, enclave,
				      evma ? ISGX_FREE_SKIP_EREMOVE : 0);
		sgx_put_backing(pages[i++], evma);
	}

	/* Allow SECS page eviction only when the enclave is initialized. */
	if (!enclave->secs_child_cnt &&
	    (enclave->flags & ISGX_ENCLAVE_INITIALIZED)) {
		pages[cnt] = sgx_get_backing(enclave, &enclave->secs_page);
		if (!IS_ERR(pages[cnt])) {
			BUG_ON(do_ewb(enclave, &enclave->secs_page,
				      pages[cnt]));
			enclave->flags |= ISGX_ENCLAVE_SECS_EVICTED;

			sgx_free_enclave_page(&enclave->secs_page, enclave,
					      ISGX_FREE_SKIP_EREMOVE);
			sgx_put_backing(pages[cnt], true);
		}
	}

	mutex_unlock(&enclave->lock);

	sgx_unpin_mm(enclave);
}

static void sgx_swap_pages(unsigned long nr_to_scan)
{
	struct sgx_tgid_ctx *ctx;
	struct sgx_enclave *encl;
	LIST_HEAD(cluster);

	ctx = isolate_tgid_ctx(nr_to_scan);
	if (!ctx)
		return;

	encl = isolate_enclave(ctx, nr_to_scan);
	if (!encl)
		goto out;

	sgx_isolate_pages(encl, &cluster, nr_to_scan);
	sgx_write_pages(&cluster);

	kref_put(&encl->refcount, sgx_enclave_release);
out:
	kref_put(&ctx->refcount, release_tgid_ctx);
}

int kisgxswapd(void *p)
{
	DEFINE_WAIT(wait);
	unsigned int nr_free;
	unsigned int nr_high;

	for ( ; ; ) {
		if (kthread_should_stop())
			break;

		spin_lock(&sgx_free_list_lock);
		nr_free = sgx_nr_free_epc_pages;
		nr_high = sgx_nr_high_epc_pages;
		spin_unlock(&sgx_free_list_lock);

		if (nr_free < nr_high) {
			sgx_swap_pages(ISGX_NR_SWAP_CLUSTER_MAX);
			schedule();
		} else {
			prepare_to_wait(&kisgxswapd_waitq,
					&wait, TASK_INTERRUPTIBLE);

			if (!kthread_should_stop())
				schedule();

			finish_wait(&kisgxswapd_waitq, &wait);
		}
	}

	pr_info("%s: done\n", __func__);
	return 0;
}

int sgx_page_cache_init(resource_size_t start, unsigned long size)
{
	unsigned long i;
	struct sgx_epc_page *new_epc_page, *entry;
	struct list_head *parser, *temp;

	for (i = 0; i < size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(*new_epc_page), GFP_KERNEL);
		if (!new_epc_page)
			goto err_freelist;
		new_epc_page->pa = start + i;

		spin_lock(&sgx_free_list_lock);
		list_add_tail(&new_epc_page->free_list, &sgx_free_list);
		sgx_nr_total_epc_pages++;
		sgx_nr_free_epc_pages++;
		spin_unlock(&sgx_free_list_lock);
	}

	sgx_nr_high_epc_pages = 2 * sgx_nr_low_epc_pages;
	kisgxswapd_tsk = kthread_run(kisgxswapd, NULL, "kisgxswapd");

	return 0;
err_freelist:
	list_for_each_safe(parser, temp, &sgx_free_list) {
		spin_lock(&sgx_free_list_lock);
		entry = list_entry(parser, struct sgx_epc_page, free_list);
		list_del(&entry->free_list);
		spin_unlock(&sgx_free_list_lock);
		kfree(entry);
	}
	return -ENOMEM;
}

void sgx_page_cache_teardown(void)
{
	struct sgx_epc_page *entry;
	struct list_head *parser, *temp;

	if (kisgxswapd_tsk)
		kthread_stop(kisgxswapd_tsk);

	spin_lock(&sgx_free_list_lock);
	list_for_each_safe(parser, temp, &sgx_free_list) {
		entry = list_entry(parser, struct sgx_epc_page, free_list);
		list_del(&entry->free_list);
		kfree(entry);
	}
	spin_unlock(&sgx_free_list_lock);
}

static struct sgx_epc_page *sgx_alloc_epc_page_fast(void)
{
	struct sgx_epc_page *entry = NULL;

	spin_lock(&sgx_free_list_lock);

	if (!list_empty(&sgx_free_list)) {
		entry = list_first_entry(&sgx_free_list, struct sgx_epc_page,
					 free_list);
		list_del(&entry->free_list);
		sgx_nr_free_epc_pages--;
	}

	spin_unlock(&sgx_free_list_lock);

	return entry;
}

struct sgx_epc_page *sgx_alloc_epc_page(
	struct sgx_tgid_ctx *tgid_epc_cnt,
	unsigned int flags)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_alloc_epc_page_fast();
		if (entry) {
			if (tgid_epc_cnt)
				atomic_inc(&tgid_epc_cnt->epc_cnt);
			break;
		} else if (flags & ISGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_swap_pages(ISGX_NR_SWAP_CLUSTER_MAX);
		schedule();
	}

	if (sgx_nr_free_epc_pages < sgx_nr_low_epc_pages)
		wake_up(&kisgxswapd_waitq);

	return entry;
}

void sgx_free_epc_page(struct sgx_epc_page *entry,
		       struct sgx_enclave *encl,
		       unsigned int flags)
{
	void *epc;
	int ret;

	if (encl) {
		atomic_dec(&encl->tgid_ctx->epc_cnt);

		if (encl->flags & ISGX_ENCLAVE_SUSPEND)
			flags |= ISGX_FREE_SKIP_EREMOVE;
	}

	if (!(flags & ISGX_FREE_SKIP_EREMOVE)) {
		epc = sgx_get_epc_page(entry);
		ret = __eremove(epc);
		sgx_put_epc_page(epc);

		if (ret) {
			pr_err("EREMOVE returned %d\n", ret);
			BUG();
		}
	}

	spin_lock(&sgx_free_list_lock);
	list_add(&entry->free_list, &sgx_free_list);
	sgx_nr_free_epc_pages++;
	spin_unlock(&sgx_free_list_lock);
}
