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

#include "isgx_user.h"
#include "sgx.h"
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

struct isgx_epc_page {
	resource_size_t		pa;
	struct list_head	free_list;
};

#define ISGX_VA_SLOT_COUNT 512

struct isgx_va_page {
	struct isgx_epc_page	*epc_page;
	DECLARE_BITMAP(slots, ISGX_VA_SLOT_COUNT);
	struct list_head	list;
};

/**
 * isgx_alloc_va_slot() - allocate VA slot from a VA page
 *
 * @page: VA page
 *
 * Returns offset to a free VA slot. If there are no free slots, an offset of
 * PAGE_SIZE is returned.
 */
static inline unsigned int isgx_alloc_va_slot(struct isgx_va_page *page)
{
	int slot = find_first_zero_bit(page->slots, ISGX_VA_SLOT_COUNT);

	if (slot < ISGX_VA_SLOT_COUNT)
		set_bit(slot, page->slots);

	return slot << 3;
}

/**
 * isgx_free_va_slot() - free VA slot from a VA page
 *
 * @page:	VA page
 * @offset:	the offset of the VA slot
 *
 * Releases VA slot.
 */
static inline void isgx_free_va_slot(struct isgx_va_page *page,
				     unsigned int offset)
{
	clear_bit(offset >> 3, page->slots);
}

struct isgx_enclave_page {
	unsigned long		addr;
	unsigned int		flags;
	struct isgx_epc_page	*epc_page;
	struct list_head	load_list;
	struct isgx_enclave	*enclave;
	struct isgx_va_page	*va_page;
	unsigned int		va_offset;
	struct sgx_pcmd		pcmd;
	struct rb_node		node;
};

#define ISGX_ENCLAVE_INITIALIZED	0x01
#define ISGX_ENCLAVE_DEBUG		0x02
#define ISGX_ENCLAVE_SECS_EVICTED	0x04
#define ISGX_ENCLAVE_SUSPEND		0x08

struct isgx_vma {
	struct vm_area_struct	*vma;
	struct list_head	vma_list;
};

struct isgx_tgid_ctx {
	struct pid			*tgid;
	atomic_t			epc_cnt;
	struct kref			refcount;
	struct list_head		enclave_list;
	struct list_head		list;
};

struct isgx_enclave {
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
	struct isgx_enclave_page	secs_page;
	struct isgx_tgid_ctx		*tgid_ctx;
	struct list_head		enclave_list;
};

extern struct workqueue_struct *isgx_add_page_wq;
extern unsigned long isgx_epc_base;
extern unsigned long isgx_epc_size;
#ifdef CONFIG_X86_64
extern void *isgx_epc_mem;
#endif
extern u64 isgx_enclave_size_max_32;
extern u64 isgx_enclave_size_max_64;
extern u64 isgx_xfrm_mask;
extern u32 isgx_ssaframesize_tbl[64];

extern struct vm_operations_struct isgx_vm_ops;
extern atomic_t isgx_nr_pids;

/* Message macros */
#define isgx_dbg(encl, fmt, ...)					\
	pr_debug_ratelimited("isgx: [%d:0x%p] " fmt,			\
			     pid_nr((encl)->tgid_ctx->tgid),		\
			     (void *)(encl)->base, ##__VA_ARGS__)
#define isgx_info(encl, fmt, ...)					\
	pr_info_ratelimited("isgx: [%d:0x%p] " fmt,			\
			    pid_nr((encl)->tgid_ctx->tgid),		\
			    (void *)(encl)->base, ##__VA_ARGS__)
#define isgx_warn(encl, fmt, ...)					\
	pr_warn_ratelimited("isgx: [%d:0x%p] " fmt,			\
			    pid_nr((encl)->tgid_ctx->tgid),		\
			    (void *)(encl)->base, ##__VA_ARGS__)
#define isgx_err(encl, fmt, ...)					\
	pr_err_ratelimited("isgx: [%d:0x%p] " fmt,			\
			   pid_nr((encl)->tgid_ctx->tgid),		\
			   (void *)(encl)->base, ##__VA_ARGS__)

/*
 * Ioctl subsystem.
 */

long isgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long isgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif
void isgx_add_page_worker(struct work_struct *work);

/*
 * Utility functions
 */

void *isgx_get_epc_page(struct isgx_epc_page *entry);
void isgx_put_epc_page(void *epc_page_vaddr);
struct page *isgx_get_backing(struct isgx_enclave *enclave,
			      struct isgx_enclave_page *entry);
void isgx_put_backing(struct page *backing, bool write);
void isgx_insert_pte(struct isgx_enclave *enclave,
		     struct isgx_enclave_page *enclave_page,
		     struct isgx_epc_page *epc_page,
		     struct vm_area_struct *vma);
int isgx_eremove(struct isgx_epc_page *epc_page);
int isgx_test_and_clear_young(struct isgx_enclave_page *page);
struct isgx_vma *isgx_find_vma(struct isgx_enclave *enclave,
			       unsigned long addr);
void isgx_zap_tcs_ptes(struct isgx_enclave *enclave,
		       struct vm_area_struct *vma);
bool isgx_pin_mm(struct isgx_enclave *encl);
void isgx_unpin_mm(struct isgx_enclave *encl);
void isgx_invalidate(struct isgx_enclave *encl);
int isgx_find_enclave(struct mm_struct *mm, unsigned long addr,
		      struct vm_area_struct **vma);
struct isgx_enclave_page *isgx_enclave_find_page(struct isgx_enclave *enclave,
						 unsigned long enclave_la);
void isgx_enclave_release(struct kref *ref);
void release_tgid_ctx(struct kref *ref);

/*
 * Page cache subsystem.
 */

#define ISGX_NR_LOW_EPC_PAGES_DEFAULT	32
#define ISGX_NR_SWAP_CLUSTER_MAX	16

extern struct mutex isgx_tgid_ctx_mutex;
extern struct list_head isgx_tgid_ctx_list;
extern struct task_struct *kisgxswapd_tsk;

enum isgx_alloc_flags {
	ISGX_ALLOC_ATOMIC	= BIT(0),
};

enum isgx_free_flags {
	ISGX_FREE_SKIP_EREMOVE	= BIT(0),
};

int kisgxswapd(void *p);
int isgx_page_cache_init(resource_size_t start, unsigned long size);
void isgx_page_cache_teardown(void);
struct isgx_epc_page *isgx_alloc_epc_page(
	struct isgx_tgid_ctx *tgid_epc_cnt, unsigned int flags);
void isgx_free_epc_page(struct isgx_epc_page *entry,
			struct isgx_enclave *encl,
			unsigned int flags);

#endif /* __ARCH_X86_ISGX_H__ */
