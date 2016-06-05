/*
 * (C) Copyright 2016 Intel Corporation
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef __ARCH_ISGX_H__
#define __ARCH_ISGX_H__

#include "sgx_user.h"
#include "sgx_arch.h"
#include <linux/kref.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

/* Number of times to spin before going to sleep because of an interrupt
 * storm.
 */
#define EINIT_SPIN_COUNT	20

/* Number of tries in total before giving up with EINIT. During each try
 * EINIT is called the number of times specified by EINIT_SPINT_COUNT.
 */
#define EINIT_TRY_COUNT		50

/* Time to sleep between each try. */
#define EINIT_BACKOFF_TIME	20

#define ISGX_ENCLAVE_PAGE_TCS		0x1
#define ISGX_ENCLAVE_PAGE_RESERVED	0x2

struct sgx_epc_page {
	resource_size_t		pa;
	struct list_head	free_list;
};

#define ISGX_VA_SLOT_COUNT 512

struct sgx_va_page {
	struct sgx_epc_page	*epc_page;
	DECLARE_BITMAP(slots, ISGX_VA_SLOT_COUNT);
	struct list_head	list;
};

/**
 * sgx_alloc_va_slot() - allocate VA slot from a VA page
 *
 * @page: VA page
 *
 * Returns offset to a free VA slot. If there are no free slots, an offset of
 * PAGE_SIZE is returned.
 */
static inline unsigned int sgx_alloc_va_slot(struct sgx_va_page *page)
{
	int slot = find_first_zero_bit(page->slots, ISGX_VA_SLOT_COUNT);

	if (slot < ISGX_VA_SLOT_COUNT)
		set_bit(slot, page->slots);

	return slot << 3;
}

/**
 * sgx_free_va_slot() - free VA slot from a VA page
 *
 * @page:	VA page
 * @offset:	the offset of the VA slot
 *
 * Releases VA slot.
 */
static inline void sgx_free_va_slot(struct sgx_va_page *page,
				    unsigned int offset)
{
	clear_bit(offset >> 3, page->slots);
}

struct sgx_enclave_page {
	unsigned long		addr;
	unsigned int		flags;
	struct sgx_epc_page	*epc_page;
	struct list_head	load_list;
	struct sgx_enclave	*enclave;
	struct sgx_va_page	*va_page;
	unsigned int		va_offset;
	struct sgx_pcmd		pcmd;
	struct rb_node		node;
};

#define ISGX_ENCLAVE_INITIALIZED	0x01
#define ISGX_ENCLAVE_DEBUG		0x02
#define ISGX_ENCLAVE_SECS_EVICTED	0x04
#define ISGX_ENCLAVE_SUSPEND		0x08

struct sgx_vma {
	struct vm_area_struct	*vma;
	struct list_head	vma_list;
};

struct sgx_tgid_ctx {
	struct pid			*tgid;
	atomic_t			epc_cnt;
	struct kref			refcount;
	struct list_head		enclave_list;
	struct list_head		list;
};

struct sgx_enclave {
	/* the enclave lock */
	struct mutex			lock;
	unsigned int			flags;
	struct task_struct		*owner;
	struct mm_struct		*mm;
	struct file			*backing;
	struct list_head		vma_list;
	struct list_head		load_list;
	struct kref			refcount;
	unsigned long			base;
	unsigned long			size;
	struct list_head		va_pages;
	struct rb_root			enclave_rb;
	struct list_head		add_page_reqs;
	struct work_struct		add_page_work;
	unsigned int			secs_child_cnt;
	struct sgx_enclave_page	secs_page;
	struct sgx_tgid_ctx		*tgid_ctx;
	struct list_head		enclave_list;
};

extern struct workqueue_struct *sgx_add_page_wq;
extern unsigned long sgx_epc_base;
extern unsigned long sgx_epc_size;
#ifdef CONFIG_X86_64
extern void *sgx_epc_mem;
#endif
extern u64 sgx_enclave_size_max_32;
extern u64 sgx_enclave_size_max_64;
extern u64 sgx_xfrm_mask;
extern u32 sgx_ssaframesize_tbl[64];

extern struct vm_operations_struct sgx_vm_ops;
extern atomic_t sgx_nr_pids;

/* Message macros */
#define sgx_dbg(encl, fmt, ...)					\
	pr_debug_ratelimited("isgx: [%d:0x%p] " fmt,			\
			     pid_nr((encl)->tgid_ctx->tgid),		\
			     (void *)(encl)->base, ##__VA_ARGS__)
#define sgx_info(encl, fmt, ...)					\
	pr_info_ratelimited("isgx: [%d:0x%p] " fmt,			\
			    pid_nr((encl)->tgid_ctx->tgid),		\
			    (void *)(encl)->base, ##__VA_ARGS__)
#define sgx_warn(encl, fmt, ...)					\
	pr_warn_ratelimited("isgx: [%d:0x%p] " fmt,			\
			    pid_nr((encl)->tgid_ctx->tgid),		\
			    (void *)(encl)->base, ##__VA_ARGS__)
#define sgx_err(encl, fmt, ...)					\
	pr_err_ratelimited("isgx: [%d:0x%p] " fmt,			\
			   pid_nr((encl)->tgid_ctx->tgid),		\
			   (void *)(encl)->base, ##__VA_ARGS__)

/*
 * Ioctl subsystem.
 */

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif
void sgx_add_page_worker(struct work_struct *work);

/*
 * Utility functions
 */

void *sgx_get_epc_page(struct sgx_epc_page *entry);
void sgx_put_epc_page(void *epc_page_vaddr);
struct page *sgx_get_backing(struct sgx_enclave *enclave,
			     struct sgx_enclave_page *entry);
void sgx_put_backing(struct page *backing, bool write);
void sgx_insert_pte(struct sgx_enclave *enclave,
		    struct sgx_enclave_page *enclave_page,
		    struct sgx_epc_page *epc_page,
		    struct vm_area_struct *vma);
int sgx_eremove(struct sgx_epc_page *epc_page);
struct sgx_vma *sgx_find_vma(struct sgx_enclave *enclave,
			     unsigned long addr);
void sgx_zap_tcs_ptes(struct sgx_enclave *enclave,
		      struct vm_area_struct *vma);
bool sgx_pin_mm(struct sgx_enclave *encl);
void sgx_unpin_mm(struct sgx_enclave *encl);
void sgx_invalidate(struct sgx_enclave *encl);
int sgx_find_enclave(struct mm_struct *mm, unsigned long addr,
		     struct vm_area_struct **vma);
struct sgx_enclave_page *sgx_enclave_find_page(struct sgx_enclave *enclave,
					       unsigned long addr);
void sgx_enclave_release(struct kref *ref);
void release_tgid_ctx(struct kref *ref);

/*
 * Page cache subsystem.
 */

#define ISGX_NR_LOW_EPC_PAGES_DEFAULT	32
#define ISGX_NR_SWAP_CLUSTER_MAX	16

extern struct mutex sgx_tgid_ctx_mutex;
extern struct list_head sgx_tgid_ctx_list;
extern struct task_struct *kisgxswapd_tsk;

enum sgx_alloc_flags {
	ISGX_ALLOC_ATOMIC	= BIT(0),
};

enum sgx_free_flags {
	ISGX_FREE_SKIP_EREMOVE	= BIT(0),
};

int kisgxswapd(void *p);
int sgx_page_cache_init(resource_size_t start, unsigned long size);
void sgx_page_cache_teardown(void);
struct sgx_epc_page *sgx_alloc_epc_page(
	struct sgx_tgid_ctx *tgid_epc_cnt, unsigned int flags);
void sgx_free_epc_page(struct sgx_epc_page *entry,
		       struct sgx_enclave *encl,
		       unsigned int flags);

#endif /* __ARCH_X86_ISGX_H__ */
