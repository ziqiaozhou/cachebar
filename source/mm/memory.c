/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

/*
 * 05.04.94  -  Multi-page memory management added for v1.1.
 * 		Idea by Alex Bligh (alex@cconcepts.co.uk)
 *
 * 16.07.99  -  Support of BIGMEM added by Gerhard Wichert, Siemens AG
 *		(Gerhard.Wichert@pdb.siemens.de)
 *
 * Aug/Sep 2004 Changed to four level page tables (Andi Kleen)
 */

#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/kallsyms.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#include <linux/myservice.h>
#include <linux/pid_namespace.h>
#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <linux/prefetch.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/perf_event.h>
#include "internal.h"
#include <linux/list_sort.h>
#include<linux/workqueue.h>
//#include <linux/percpu.h>
DEFINE_PER_CPU(unsigned long long,global_interval)=0;
DEFINE_PER_CPU(unsigned long long,global_interval_normal)=0; 
DEFINE_PER_CPU(unsigned long long,global_interval_early)=0; 
DEFINE_PER_CPU(unsigned long long,global_count)=0; 
DEFINE_PER_CPU(unsigned long long,global_count_normal)=0; 
DEFINE_PER_CPU(unsigned long long,global_count_total)=0;
DEFINE_PER_CPU(unsigned long long,global_count_normal_total)=0;
DEFINE_PER_CPU(unsigned long long,global_count_early)=0; 
DEFINE_PER_CPU(unsigned long long,global_interval_coa)=0;
DEFINE_PER_CPU(unsigned long long,global_interval_coa_normal)=0; 
DEFINE_PER_CPU(unsigned long long,global_interval_coa_early)=0; 
DEFINE_PER_CPU(unsigned long long,global_interval_coa_fail)=0; 
DEFINE_PER_CPU(unsigned long long,global_count_coa)=0; 
DEFINE_PER_CPU(unsigned long long,global_count_coa_normal)=0; 
DEFINE_PER_CPU(unsigned long long,global_count_coa_early)=0;
DEFINE_PER_CPU(unsigned long long,global_count_coa_fail)=0;
DEFINE_PER_CPU(unsigned long long,global_prefetch)=0;
DEFINE_PER_CPU(unsigned long long,global_prefetch_count)=0;  
DEFINE_PER_CPU(unsigned long long,global_all_prefetch_count)=0;
DEFINE_PER_CPU(unsigned long long,global_before_prefetch_count)=0;
DEFINE_PER_CPU(unsigned long long,global_ins_count)=0;

static int handle_double_cache_pte_fault(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid);
void __get_page_tail_foll(struct page *page,
			bool get_page_head)
{
	/*
	 * If we're getting a tail page, the elevated page->_count is
	 * required only in the head page and we will elevate the head
	 * page->_count and tail page->_mapcount.
	 *
	 * We elevate page_tail->_mapcount for tail pages to force
	 * page_tail->_count to be zero at all times to avoid getting
	 * false positives from get_page_unless_zero() with
	 * speculative page access (like in
	 * page_cache_get_speculative()) on tail pages.
	 */
	VM_BUG_ON(atomic_read(&page->first_page->_count) <= 0);
	VM_BUG_ON(atomic_read(&page->_count) != 0);
	VM_BUG_ON(page_mapcount(page) < 0);
	if (get_page_head){
		atomic_inc(&page->first_page->_count);
	}
	atomic_inc(&page->_mapcount);
	inc_page_counter_by_ns(page,ns_of_pid(task_pid(current)));
}
EXPORT_SYMBOL(__get_page_tail_foll);/*internal.h*/
void get_huge_page_tail(struct page* page)
{
	/*
	 * __split_huge_page_refcount() cannot run
	 * from under us.
	 */
	VM_BUG_ON(page_mapcount(page) < 0);
	VM_BUG_ON(atomic_read(&page->_count) != 0);
	atomic_inc(&page->_mapcount);
	inc_page_counter_by_ns(page,ns_of_pid(task_pid(current)));
}
EXPORT_SYMBOL(get_huge_page_tail);/*mm.h*/
void page_dup_rmap(struct page *page)
{
	atomic_inc(&page->_mapcount);
	//	inc_page_counter_by_ns(page,ns_of_pid(task_pid(current)));

}
EXPORT_SYMBOL(page_dup_rmap);/*rmap.h*/


#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
#warning Unfortunate NUMA and NUMA Balancing config, growing page-frame for last_cpupid.
#endif

#ifndef CONFIG_NEED_MULTIPLE_NODES
/* use the per-pgdat data instead for discontigmem - mbligh */
unsigned long max_mapnr;
struct page *mem_map;

EXPORT_SYMBOL(max_mapnr);
EXPORT_SYMBOL(mem_map);
#endif

/*
 * A number of key systems in x86 including ioremap() rely on the assumption
 * that high_memory defines the upper bound on direct map memory, then end
 * of ZONE_NORMAL.  Under CONFIG_DISCONTIG this means that max_low_pfn and
 * highstart_pfn must be the same; there must be no gap between ZONE_NORMAL
 * and ZONE_HIGHMEM.
 */
void * high_memory;

EXPORT_SYMBOL(high_memory);

/*
 * Randomize the address space (stacks, mmaps, brk, etc.).
 *
 * ( When CONFIG_COMPAT_BRK=y we exclude brk from randomization,
 *   as ancient (libc5 based) binaries can segfault. )
 */
int randomize_va_space __read_mostly =
#ifdef CONFIG_COMPAT_BRK
1;
#else
2;
#endif

static int __init disable_randmaps(char *s)
{
	randomize_va_space = 0;
	return 1;
}
__setup("norandmaps", disable_randmaps);

unsigned long zero_pfn __read_mostly;
unsigned long highest_memmap_pfn __read_mostly;

/*
 * CONFIG_MMU architectures set up ZERO_PAGE in their paging_init()
 */
static int __init init_zero_pfn(void)
{
	zero_pfn = page_to_pfn(ZERO_PAGE(0));
	return 0;
}
core_initcall(init_zero_pfn);


#if defined(SPLIT_RSS_COUNTING)

void sync_mm_rss(struct mm_struct *mm)
{
	int i;

	for (i = 0; i < NR_MM_COUNTERS; i++) {
		if (current->rss_stat.count[i]) {
			add_mm_counter(mm, i, current->rss_stat.count[i]);
			current->rss_stat.count[i] = 0;
		}
	}
	current->rss_stat.events = 0;
}

static void add_mm_counter_fast(struct mm_struct *mm, int member, int val)
{
	struct task_struct *task = current;

	if (likely(task->mm == mm))
	  task->rss_stat.count[member] += val;
	else
	  add_mm_counter(mm, member, val);
}
#define inc_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, 1)
#define dec_mm_counter_fast(mm, member) add_mm_counter_fast(mm, member, -1)

/* sync counter once per 64 page faults */
#define TASK_RSS_EVENTS_THRESH	(64)
static void check_sync_rss_stat(struct task_struct *task)
{
	if (unlikely(task != current))
	  return;
	if (unlikely(task->rss_stat.events++ > TASK_RSS_EVENTS_THRESH))
	  sync_mm_rss(task->mm);
}
#else /* SPLIT_RSS_COUNTING */

#define inc_mm_counter_fast(mm, member) inc_mm_counter(mm, member)
#define dec_mm_counter_fast(mm, member) dec_mm_counter(mm, member)

static void check_sync_rss_stat(struct task_struct *task)
{
}

#endif /* SPLIT_RSS_COUNTING */

#ifdef HAVE_GENERIC_MMU_GATHER

static int tlb_next_batch(struct mmu_gather *tlb)
{
	struct mmu_gather_batch *batch;

	batch = tlb->active;
	if (batch->next) {
		tlb->active = batch->next;
		return 1;
	}

	if (tlb->batch_count == MAX_GATHER_BATCH_COUNT)
	  return 0;

	batch = (void *)__get_free_pages(GFP_NOWAIT | __GFP_NOWARN, 0);
	if (!batch)
	  return 0;

	tlb->batch_count++;
	batch->next = NULL;
	batch->nr   = 0;
	batch->max  = MAX_GATHER_BATCH;

	tlb->active->next = batch;
	tlb->active = batch;

	return 1;
}

/* tlb_gather_mmu
 *	Called to initialize an (on-stack) mmu_gather structure for page-table
 *	tear-down from @mm. The @fullmm argument is used when @mm is without
 *	users and we're going to destroy the full address space (exit/execve).
 */
void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm, unsigned long start, unsigned long end)
{
	tlb->mm = mm;

	/* Is it from 0 to ~0? */
	tlb->fullmm     = !(start | (end+1));
	tlb->need_flush_all = 0;
	tlb->start	= start;
	tlb->end	= end;
	tlb->need_flush = 0;
	tlb->local.next = NULL;
	tlb->local.nr   = 0;
	tlb->local.max  = ARRAY_SIZE(tlb->__pages);
	tlb->active     = &tlb->local;
	tlb->batch_count = 0;

#ifdef CONFIG_HAVE_RCU_TABLE_FREE
	tlb->batch = NULL;
#endif
}

void tlb_flush_mmu(struct mmu_gather *tlb)
{
	struct mmu_gather_batch *batch;
	if (!tlb->need_flush)
	  return;
	tlb->need_flush = 0;
	tlb_flush(tlb);
#ifdef CONFIG_HAVE_RCU_TABLE_FREE
	tlb_table_flush(tlb);
#endif

	for (batch = &tlb->local; batch; batch = batch->next) {
		free_pages_and_swap_cache(batch->pages, batch->nr);
		batch->nr = 0;
	}
	tlb->active = &tlb->local;
}

/* tlb_finish_mmu
 *	Called at the end of the shootdown operation to free up any resources
 *	that were required.
 */
void tlb_finish_mmu(struct mmu_gather *tlb, unsigned long start, unsigned long end)
{
	struct mmu_gather_batch *batch, *next;

	tlb_flush_mmu(tlb);

	/* keep the page table cache within bounds */
	check_pgt_cache();

	for (batch = tlb->local.next; batch; batch = next) {
		next = batch->next;
		free_pages((unsigned long)batch, 0);
	}
	tlb->local.next = NULL;
}

/* __tlb_remove_page
 *	Must perform the equivalent to __free_pte(pte_get_and_clear(ptep)), while
 *	handling the additional races in SMP caused by other CPUs caching valid
 *	mappings in their TLBs. Returns the number of free page slots left.
 *	When out of page slots we must call tlb_flush_mmu().
 */
int __tlb_remove_page(struct mmu_gather *tlb, struct page *page)
{
	struct mmu_gather_batch *batch;

	VM_BUG_ON(!tlb->need_flush);

	batch = tlb->active;
	batch->pages[batch->nr++] = page;
	if (batch->nr == batch->max) {
		if (!tlb_next_batch(tlb))
		  return 0;
		batch = tlb->active;
	}
	VM_BUG_ON(batch->nr > batch->max);

	return batch->max - batch->nr;
}

#endif /* HAVE_GENERIC_MMU_GATHER */

#ifdef CONFIG_HAVE_RCU_TABLE_FREE

/*
 * See the comment near struct mmu_table_batch.
 */

static void tlb_remove_table_smp_sync(void *arg)
{
	/* Simply deliver the interrupt */
}

static void tlb_remove_table_one(void *table)
{
	/*
	 * This isn't an RCU grace period and hence the page-tables cannot be
	 * assumed to be actually RCU-freed.
	 *
	 * It is however sufficient for software page-table walkers that rely on
	 * IRQ disabling. See the comment near struct mmu_table_batch.
	 */
	smp_call_function(tlb_remove_table_smp_sync, NULL, 1);
	__tlb_remove_table(table);
}

static void tlb_remove_table_rcu(struct rcu_head *head)
{
	struct mmu_table_batch *batch;
	int i;

	batch = container_of(head, struct mmu_table_batch, rcu);

	for (i = 0; i < batch->nr; i++)
	  __tlb_remove_table(batch->tables[i]);

	free_page((unsigned long)batch);
}

void tlb_table_flush(struct mmu_gather *tlb)
{
	struct mmu_table_batch **batch = &tlb->batch;

	if (*batch) {
		call_rcu_sched(&(*batch)->rcu, tlb_remove_table_rcu);
		*batch = NULL;
	}
}

void tlb_remove_table(struct mmu_gather *tlb, void *table)
{
	struct mmu_table_batch **batch = &tlb->batch;

	tlb->need_flush = 1;

	/*
	 * When there's less then two users of this mm there cannot be a
	 * concurrent page-table walk.
	 */
	if (atomic_read(&tlb->mm->mm_users) < 2) {
		__tlb_remove_table(table);
		return;
	}

	if (*batch == NULL) {
		*batch = (struct mmu_table_batch *)__get_free_page(GFP_NOWAIT | __GFP_NOWARN);
		if (*batch == NULL) {
			tlb_remove_table_one(table);
			return;
		}
		(*batch)->nr = 0;
	}
	(*batch)->tables[(*batch)->nr++] = table;
	if ((*batch)->nr == MAX_TABLE_BATCH)
	  tlb_table_flush(tlb);
}

#endif /* CONFIG_HAVE_RCU_TABLE_FREE */

/*
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
static void free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
			unsigned long addr)
{
	pgtable_t token = pmd_pgtable(*pmd);
	pmd_clear(pmd);
	pte_free_tlb(tlb, token, addr);
	atomic_long_dec(&tlb->mm->nr_ptes);
}

static inline void free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
		  continue;
		free_pte_range(tlb, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
	  return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
		  return;
	}
	if (end - 1 > ceiling - 1)
	  return;

	pmd = pmd_offset(pud, start);
	pud_clear(pud);
	pmd_free_tlb(tlb, pmd, start);
}

static inline void free_pud_range(struct mmu_gather *tlb, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
		  continue;
		free_pmd_range(tlb, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
	  return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
		  return;
	}
	if (end - 1 > ceiling - 1)
	  return;

	pud = pud_offset(pgd, start);
	pgd_clear(pgd);
	pud_free_tlb(tlb, pud, start);
}

/*
 * This function frees user-level page tables of a process.
 */
void free_pgd_range(struct mmu_gather *tlb,
			unsigned long addr, unsigned long end,
			unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	/*
	 * The next few lines have given us lots of grief...
	 *
	 * Why are we testing PMD* at this top level?  Because often
	 * there will be no work to do at all, and we'd prefer not to
	 * go all the way down to the bottom just to discover that.
	 *
	 * Why all these "- 1"s?  Because 0 represents both the bottom
	 * of the address space and the top of it (using -1 for the
	 * top wouldn't help much: the masks would do the wrong thing).
	 * The rule is that addr 0 and floor 0 refer to the bottom of
	 * the address space, but end 0 and ceiling 0 refer to the top
	 * Comparisons need to use "end - 1" and "ceiling - 1" (though
	 * that end 0 case should be mythical).
	 *
	 * Wherever addr is brought up or ceiling brought down, we must
	 * be careful to reject "the opposite 0" before it confuses the
	 * subsequent tests.  But what about where end is brought down
	 * by PMD_SIZE below? no, end can't go down to 0 there.
	 *
	 * Whereas we round start (addr) and ceiling down, by different
	 * masks at different levels, in order to test whether a table
	 * now has no other vmas using it, so can be freed, we don't
	 * bother to round floor or end up - the tests don't need that.
	 */

	addr &= PMD_MASK;
	if (addr < floor) {
		addr += PMD_SIZE;
		if (!addr)
		  return;
	}
	if (ceiling) {
		ceiling &= PMD_MASK;
		if (!ceiling)
		  return;
	}
	if (end - 1 > ceiling - 1)
	  end -= PMD_SIZE;
	if (addr > end - 1)
	  return;

	pgd = pgd_offset(tlb->mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
		  continue;
		free_pud_range(tlb, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}

void free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *vma,
			unsigned long floor, unsigned long ceiling)
{
	while (vma) {
		struct vm_area_struct *next = vma->vm_next;
		unsigned long addr = vma->vm_start;

		/*
		 * Hide vma from rmap and truncate_pagecache before freeing
		 * pgtables
		 */
		unlink_anon_vmas(vma);
		unlink_file_vma(vma);

		if (is_vm_hugetlb_page(vma)) {
			hugetlb_free_pgd_range(tlb, addr, vma->vm_end,
						floor, next? next->vm_start: ceiling);
		} else {
			/*
			 * Optimization: gather nearby vmas into one call down
			 */
			while (next && next->vm_start <= vma->vm_end + PMD_SIZE
						&& !is_vm_hugetlb_page(next)) {
				vma = next;
				next = vma->vm_next;
				unlink_anon_vmas(vma);
				unlink_file_vma(vma);
			}
			free_pgd_range(tlb, addr, vma->vm_end,
						floor, next? next->vm_start: ceiling);
		}
		vma = next;
	}
}

int __pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
			pmd_t *pmd, unsigned long address)
{
	spinlock_t *ptl;
	pgtable_t new = pte_alloc_one(mm, address);
	int wait_split_huge_page;
	if (!new)
	  return -ENOMEM;

	/*
	 * Ensure all pte setup (eg. pte page lock and page clearing) are
	 * visible before the pte is made visible to other CPUs by being
	 * put into page tables.
	 *
	 * The other side of the story is the pointer chasing in the page
	 * table walking code (when walking the page table without locking;
	 * ie. most of the time). Fortunately, these data accesses consist
	 * of a chain of data-dependent loads, meaning most CPUs (alpha
	 * being the notable exception) will already guarantee loads are
	 * seen in-order. See the alpha page table accessors for the
	 * smp_read_barrier_depends() barriers in page table walking code.
	 */
	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */

	ptl = pmd_lock(mm, pmd);
	wait_split_huge_page = 0;
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		atomic_long_inc(&mm->nr_ptes);
		pmd_populate(mm, pmd, new);
		new = NULL;
	} else if (unlikely(pmd_trans_splitting(*pmd)))
	  wait_split_huge_page = 1;
	spin_unlock(ptl);
	if (new)
	  pte_free(mm, new);
	if (wait_split_huge_page)
	  wait_split_huge_page(vma->anon_vma, pmd);
	return 0;
}

int __pte_alloc_kernel(pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one_kernel(&init_mm, address);
	if (!new)
	  return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&init_mm.page_table_lock);
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		pmd_populate_kernel(&init_mm, pmd, new);
		new = NULL;
	} else
	  VM_BUG_ON(pmd_trans_splitting(*pmd));
	spin_unlock(&init_mm.page_table_lock);
	if (new)
	  pte_free_kernel(&init_mm, new);
	return 0;
}

static inline void init_rss_vec(int *rss)
{
	memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}

static inline void add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
	int i;

	if (current->mm == mm)
	  sync_mm_rss(mm);
	for (i = 0; i < NR_MM_COUNTERS; i++)
	  if (rss[i])
		add_mm_counter(mm, i, rss[i]);
}

/*
 * This function is called to print an error when a bad pte
 * is found. For example, we might have a PFN-mapped pte in
 * a region that doesn't allow it.
 *
 * The calling function must still handle the error.
 */
static void print_bad_pte(struct vm_area_struct *vma, unsigned long addr,
			pte_t pte, struct page *page)
{
	pgd_t *pgd = pgd_offset(vma->vm_mm, addr);
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);
	struct address_space *mapping;
	pgoff_t index;
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			return;
		}
		if (nr_unshown) {
			printk(KERN_ALERT
						"BUG: Bad page map: %lu messages suppressed\n",
						nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
	  resume = jiffies + 60 * HZ;

	mapping = vma->vm_file ? vma->vm_file->f_mapping : NULL;
	index = linear_page_index(vma, addr);

	printk(KERN_ALERT
				"BUG: Bad page map in process %s  pte:%08llx pmd:%08llx\n",
				current->comm,
				(long long)pte_val(pte), (long long)pmd_val(*pmd));
	if (page)
	  dump_page(page);
	printk(KERN_ALERT
				"addr:%p vm_flags:%08lx anon_vma:%p mapping:%p index:%lx\n",
				(void *)addr, vma->vm_flags, vma->anon_vma, mapping, index);
	/*
	 * Choose text because data symbols depend on CONFIG_KALLSYMS_ALL=y
	 */
	if (vma->vm_ops)
	  printk(KERN_ALERT "vma->vm_ops->fault: %pSR\n",
				  vma->vm_ops->fault);
	if (vma->vm_file)
	  printk(KERN_ALERT "vma->vm_file->f_op->mmap: %pSR\n",
				  vma->vm_file->f_op->mmap);
	dump_stack();
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

static inline bool is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

/*
 * vm_normal_page -- This function gets the "struct page" associated with a pte.
 *
 * "Special" mappings do not wish to be associated with a "struct page" (either
 * it doesn't exist, or it exists but they don't want to touch it). In this
 * case, NULL is returned here. "Normal" mappings do have a struct page.
 *
 * There are 2 broad cases. Firstly, an architecture may define a pte_special()
 * pte bit, in which case this function is trivial. Secondly, an architecture
 * may not have a spare pte bit, which requires a more complicated scheme,
 * described below.
 *
 * A raw VM_PFNMAP mapping (ie. one that is not COWed) is always considered a
 * special mapping (even if there are underlying and valid "struct pages").
 * COWed pages of a VM_PFNMAP are always normal.
 *
 * The way we recognize COWed pages within VM_PFNMAP mappings is through the
 * rules set up by "remap_pfn_range()": the vma will have the VM_PFNMAP bit
 * set, and the vm_pgoff will point to the first PFN mapped: thus every special
 * mapping will always honor the rule
 *
 *	pfn_of_page == vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT)
 *
 * And for normal mappings this is false.
 *
 * This restricts such mappings to be a linear translation from virtual address
 * to pfn. To get around this restriction, we allow arbitrary mappings so long
 * as the vma is not a COW mapping; in that case, we know that all ptes are
 * special (because none can have been COWed).
 *
 *
 * In order to support COW of arbitrary special mappings, we have VM_MIXEDMAP.
 *
 * VM_MIXEDMAP mappings can likewise contain memory with or without "struct
 * page" backing, however the difference is that _all_ pages with a struct
 * page (that is, those where pfn_valid is true) are refcounted and considered
 * normal pages by the VM. The disadvantage is that pages are refcounted
 * (which can be slower and simply not an option for some PFNMAP users). The
 * advantage is that we don't have to follow the strict linearity rule of
 * PFNMAP mappings in order to support COWable mappings.
 *
 */
#ifdef __HAVE_ARCH_PTE_SPECIAL
# define HAVE_PTE_SPECIAL 1
#else
# define HAVE_PTE_SPECIAL 0
#endif
struct page* vm_normal_pfn_to_page(struct vm_area_struct *vma, unsigned long addr,
			pte_t pte,unsigned long pfn){
	if (HAVE_PTE_SPECIAL) {
		if (likely(!pte_special(pte)))
		  goto check_pfn;
		if (vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)){
			//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
			return NULL;
		}
		if (!is_zero_pfn(pfn))
		  print_bad_pte(vma, addr, pte, NULL);
		//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
		return NULL;
	}
	/* !HAVE_PTE_SPECIAL case follows: */
	if (unlikely(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP))) {
		if (vma->vm_flags & VM_MIXEDMAP) {
			if (!pfn_valid(pfn))
			  return NULL;
			goto out;
		} else {
			unsigned long off;
			off = (addr - vma->vm_start) >> PAGE_SHIFT;
			if (pfn == vma->vm_pgoff + off){
				//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
				return NULL;
			}
			if (!is_cow_mapping(vma->vm_flags)){
				//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
				return NULL;
			}
		}
	}

	if (is_zero_pfn(pfn)){
		//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
		return NULL;
	}
check_pfn:
	if (unlikely(pfn > highest_memmap_pfn)) {
		print_bad_pte(vma, addr, pte, NULL);
		return NULL;
	}

	/*
	 * NOTE! We still have PageReserved() pages in the page tables.
	 * eg. VDSO mappings can cause them to exist.
	 */
out:
	return pfn_to_page(pfn);
}
struct page *vm_normal_page(struct vm_area_struct *vma, unsigned long addr,
			pte_t pte)
{
	unsigned long pfn = pte_pfn(pte);

	if (HAVE_PTE_SPECIAL) {
		if (likely(!pte_special(pte)))
		  goto check_pfn;
		if (vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)){
			//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
			return NULL;
		}
		if (!is_zero_pfn(pfn))
		  print_bad_pte(vma, addr, pte, NULL);
		//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
		return NULL;
	}
	/* !HAVE_PTE_SPECIAL case follows: */
	if (unlikely(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP))) {
		if (vma->vm_flags & VM_MIXEDMAP) {
			if (!pfn_valid(pfn))
			  return NULL;
			goto out;
		} else {
			unsigned long off;
			off = (addr - vma->vm_start) >> PAGE_SHIFT;
			if (pfn == vma->vm_pgoff + off){
				//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
				return NULL;
			}
			if (!is_cow_mapping(vma->vm_flags)){
				//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
				return NULL;
			}
		}
	}

	if (is_zero_pfn(pfn)){
		//	print_bad_pte(vma, addr, pte, NULL);//ziqiao
		return NULL;
	}
check_pfn:
	if (unlikely(pfn > highest_memmap_pfn)) {
		print_bad_pte(vma, addr, pte, NULL);
		return NULL;
	}

	/*
	 * NOTE! We still have PageReserved() pages in the page tables.
	 * eg. VDSO mappings can cause them to exist.
	 */
out:
	return pfn_to_page(pfn);
}

/*
 * copy one vm_area from one task to the other. Assumes the page tables
 * already present in the new task to be cleared in the whole range
 * covered by this vma.
 */

static inline unsigned long
copy_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			pte_t *dst_pte, pte_t *src_pte, pmd_t *dst_pmd, pmd_t *src_pmd,struct vm_area_struct *vma,
			unsigned long addr, int *rss)
{
	unsigned long vm_flags = vma->vm_flags;
	pte_t pte = *src_pte;
	struct page *page;
	spinlock_t *src_ptl, *dst_ptl;
	src_ptl = pte_lockptr(src_mm, src_pmd);
	dst_ptl = pte_lockptr(dst_mm, dst_pmd);

	/* pte contains position in swap or file, so copy. */
	if (unlikely(!pte_present(pte))) {
		if (!pte_file(pte)) {
			swp_entry_t entry = pte_to_swp_entry(pte);

			if (swap_duplicate(entry) < 0)
			{
				printk("from copy one pte, pte=%lx",pte.pte);
				return entry.val;
			}
			/* make sure dst_mm is on swapoff's mmlist. */
			if (unlikely(list_empty(&dst_mm->mmlist))) {
				spin_lock(&mmlist_lock);
				if (list_empty(&dst_mm->mmlist))
				  list_add(&dst_mm->mmlist,
							  &src_mm->mmlist);
				spin_unlock(&mmlist_lock);
			}
			if (likely(!non_swap_entry(entry)))
			  rss[MM_SWAPENTS]++;
			else if (is_migration_entry(entry)) {
				page = migration_entry_to_page(entry);

				if (PageAnon(page))
				  rss[MM_ANONPAGES]++;
				else
				  rss[MM_FILEPAGES]++;

				if (is_write_migration_entry(entry) &&
							is_cow_mapping(vm_flags)) {
					/*
					 * COW mappings require pages in both
					 * parent and child to be set to read.
					 */
					make_migration_entry_read(&entry);
					pte = swp_entry_to_pte(entry);
					if (pte_swp_soft_dirty(*src_pte))
					  pte = pte_swp_mksoft_dirty(pte);
					set_pte_at(src_mm, addr, src_pte, pte);
				}
			}
		}
		goto out_set_pte;
	}

	/*
	 * If it's a COW mapping, write protect it both
	 * in the parent and the child
	 */
	if (is_cow_mapping(vm_flags)) {
		ptep_set_wrprotect(src_mm, addr, src_pte);
		pte = pte_wrprotect(pte);
	}

	/*
	 * If it's a shared mapping, mark it clean in
	 * the child
	 */
	if (vm_flags & VM_SHARED)
	  pte = pte_mkclean(pte);
	pte = pte_mkold(pte);

	page = vm_normal_page(vma, addr, pte);
	if (page) {
		get_page(page);
		page_dup_rmap(page);
		spin_unlock(src_ptl);
		spin_unlock(dst_ptl);
		inc_page_counter_in_ns(page,vma);
		spin_lock(dst_ptl);
		spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);

		if (PageAnon(page))
		  rss[MM_ANONPAGES]++;
		else
		  rss[MM_FILEPAGES]++;
	}

out_set_pte:
	set_pte_at(dst_mm, addr, dst_pte, pte);
	return 0;
}

int copy_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
			unsigned long addr, unsigned long end)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int progress = 0;
	int rss[NR_MM_COUNTERS];
	swp_entry_t entry = (swp_entry_t){0};

again:
	init_rss_vec(rss);

	dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
	if (!dst_pte)
	  return -ENOMEM;
	src_pte = pte_offset_map(src_pmd, addr);
	src_ptl = pte_lockptr(src_mm, src_pmd);
	spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;
	arch_enter_lazy_mmu_mode();
	do {
		/*
		 * We are holding two locks at this point - either of them
		 * could generate latencies in another task on another CPU.
		 */
		if (progress >= 32) {
			progress = 0;
			if (need_resched() ||
						spin_needbreak(src_ptl) || spin_needbreak(dst_ptl))
			  break;
		}
		if (pte_none(*src_pte)) {
			progress++;
			continue;
		}
		entry.val = copy_one_pte(dst_mm, src_mm, dst_pte, src_pte,dst_pmd,src_pmd,
					vma, addr, rss);
		if (entry.val)
		  break;
		progress += 8;
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();
	spin_unlock(src_ptl);
	pte_unmap(orig_src_pte);
	add_mm_rss_vec(dst_mm, rss);
	pte_unmap_unlock(orig_dst_pte, dst_ptl);
	cond_resched();
	if (entry.val) {
		if (add_swap_count_continuation(entry, GFP_KERNEL) < 0)
		  return -ENOMEM;
		progress = 0;
	}
	if (addr != end)
	  goto again;
	return 0;
}

static inline int copy_pmd_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			pud_t *dst_pud, pud_t *src_pud, struct vm_area_struct *vma,
			unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
	  return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_trans_huge(*src_pmd)) {
			int err;
			VM_BUG_ON(next-addr != HPAGE_PMD_SIZE);
			err = copy_huge_pmd(dst_mm, src_mm,
						dst_pmd, src_pmd, addr, vma);
			if (err == -ENOMEM)
			  return -ENOMEM;
			if (!err)
			  continue;
			/* fall through */
		}
		if (pmd_none_or_clear_bad(src_pmd))
		  continue;
		if (copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						vma, addr, next))
		  return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int copy_pud_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			pgd_t *dst_pgd, pgd_t *src_pgd, struct vm_area_struct *vma,
			unsigned long addr, unsigned long end)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = pud_alloc(dst_mm, dst_pgd, addr);
	if (!dst_pud)
	  return -ENOMEM;
	src_pud = pud_offset(src_pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(src_pud))
		  continue;
		if (copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						vma, addr, next))
		  return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

int copy_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			struct vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */
	bool is_cow;
	int ret;

	/*
	 * Don't copy ptes where a page fault will fill them correctly.
	 * Fork becomes much lighter when there are big shared or private
	 * readonly mappings. The tradeoff is that copy_page_range is more
	 * efficient than faulting.
	 */
	if (!(vma->vm_flags & (VM_HUGETLB | VM_NONLINEAR |
						VM_PFNMAP | VM_MIXEDMAP))) {
		if (!vma->anon_vma)
		  return 0;
	}

	if (is_vm_hugetlb_page(vma))
	  return copy_hugetlb_page_range(dst_mm, src_mm, vma);

	if (unlikely(vma->vm_flags & VM_PFNMAP)) {
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 */
		ret = track_pfn_copy(vma);
		if (ret)
		  return ret;
	}

	/*
	 * We need to invalidate the secondary MMU mappings only when
	 * there could be a permission downgrade on the ptes of the
	 * parent mm. And a permission downgrade will only happen if
	 * is_cow_mapping() returns true.
	 */
	is_cow = is_cow_mapping(vma->vm_flags);
	mmun_start = addr;
	mmun_end   = end;
	if (is_cow)
	  mmu_notifier_invalidate_range_start(src_mm, mmun_start,
				  mmun_end);

	ret = 0;
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
		  continue;
		if (unlikely(copy_pud_range(dst_mm, src_mm, dst_pgd, src_pgd,
							vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	if (is_cow)
	  mmu_notifier_invalidate_range_end(src_mm, mmun_start, mmun_end);
	return ret;
}

static unsigned long zap_pte_range(struct mmu_gather *tlb,
			struct vm_area_struct *vma, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			struct zap_details *details)
{
	struct mm_struct *mm = tlb->mm;
	int force_flush = 0;
	int rss[NR_MM_COUNTERS];
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;

again:
	init_rss_vec(rss);
	start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = start_pte;
	arch_enter_lazy_mmu_mode();
	do {
		pte_t ptent = *pte;
		if (pte_none(ptent)) {
			continue;
		}

		if (pte_present(ptent)) {
			struct page *page;

			page = vm_normal_page(vma, addr, ptent);
			if (unlikely(details) && page) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping &&
							details->check_mapping != page->mapping)
				  continue;
				/*
				 * Each page->index must be checked when
				 * invalidating or truncating nonlinear.
				 */
				if (details->nonlinear_vma &&
							(page->index < details->first_index ||
							 page->index > details->last_index))
				  continue;
			}
			ptent = ptep_get_and_clear_full(mm, addr, pte,
						tlb->fullmm);
			tlb_remove_tlb_entry(tlb, pte, addr);
			if (unlikely(!page))
			  continue;
			if (unlikely(details) && details->nonlinear_vma
						&& linear_page_index(details->nonlinear_vma,
							addr) != page->index) {
				pte_t ptfile = pgoff_to_pte(page->index);
				if (pte_soft_dirty(ptent))
				  pte_file_mksoft_dirty(ptfile);
				set_pte_at(mm, addr, pte, ptfile);
			}
			if (PageAnon(page))
			  rss[MM_ANONPAGES]--;
			else {
				if (pte_dirty(ptent))
				  set_page_dirty(page);
				if (pte_young(ptent) &&
							likely(!(vma->vm_flags & VM_SEQ_READ)))
				  mark_page_accessed(page);
				rss[MM_FILEPAGES]--;
			}
			page_remove_rmap(page);
			dec_page_counter_in_ns(page,vma);
			if (unlikely(page_mapcount(page) < 0))
			  print_bad_pte(vma, addr, ptent, page);
			force_flush = !__tlb_remove_page(tlb, page);
			if (force_flush)
			  break;
			continue;
		}
		/*
		 * If details->check_mapping, we leave swap entries;
		 * if details->nonlinear_vma, we leave file entries.
		 */
		if (unlikely(details))
		  continue;
		if (pte_file(ptent)) {
			if (unlikely(!(vma->vm_flags & VM_NONLINEAR)))
			  print_bad_pte(vma, addr, ptent, NULL);
		} else {
			swp_entry_t entry = pte_to_swp_entry(ptent);

			if (!non_swap_entry(entry))
			  rss[MM_SWAPENTS]--;
			else if (is_migration_entry(entry)) {
				struct page *page;

				page = migration_entry_to_page(entry);

				if (PageAnon(page))
				  rss[MM_ANONPAGES]--;
				else
				  rss[MM_FILEPAGES]--;
			}
			if (unlikely(!free_swap_and_cache(entry)))
			  print_bad_pte(vma, addr, ptent, NULL);
		}
		pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
	} while (pte++, addr += PAGE_SIZE, addr != end);

	add_mm_rss_vec(mm, rss);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(start_pte, ptl);

	/*
	 * mmu_gather ran out of room to batch pages, we break out of
	 * the PTE lock to avoid doing the potential expensive TLB invalidate
	 * and page-free while holding it.
	 */
	if (force_flush) {
		unsigned long old_end;

		force_flush = 0;

		/*
		 * Flush the TLB just for the previous segment,
		 * then update the range to be the remaining
		 * TLB range.
		 */
		old_end = tlb->end;
		tlb->end = addr;

		tlb_flush_mmu(tlb);

		tlb->start = addr;
		tlb->end = old_end;

		if (addr != end)
		  goto again;
	}

	return addr;
}

static inline unsigned long zap_pmd_range(struct mmu_gather *tlb,
			struct vm_area_struct *vma, pud_t *pud,
			unsigned long addr, unsigned long end,
			struct zap_details *details)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_trans_huge(*pmd)) {
			if (next - addr != HPAGE_PMD_SIZE) {
#ifdef CONFIG_DEBUG_VM
				if (!rwsem_is_locked(&tlb->mm->mmap_sem)) {
					pr_err("%s: mmap_sem is unlocked! addr=0x%lx end=0x%lx vma->vm_start=0x%lx vma->vm_end=0x%lx\n",
								__func__, addr, end,
								vma->vm_start,
								vma->vm_end);
					BUG();
				}
#endif
				split_huge_page_pmd(vma, addr, pmd);
			} else if (zap_huge_pmd(tlb, vma, pmd, addr))
			  goto next;
			/* fall through */
		}
		/*
		 * Here there can be other concurrent MADV_DONTNEED or
		 * trans huge page faults running, and if the pmd is
		 * none or trans huge it can change under us. This is
		 * because MADV_DONTNEED holds the mmap_sem in read
		 * mode.
		 */
		if (pmd_none_or_trans_huge_or_clear_bad(pmd))
		  goto next;
		next = zap_pte_range(tlb, vma, pmd, addr, next, details);
next:
		cond_resched();
	} while (pmd++, addr = next, addr != end);

	return addr;
}

static inline unsigned long zap_pud_range(struct mmu_gather *tlb,
			struct vm_area_struct *vma, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			struct zap_details *details)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
		  continue;
		next = zap_pmd_range(tlb, vma, pud, addr, next, details);
	} while (pud++, addr = next, addr != end);

	return addr;
}

static void unmap_page_range(struct mmu_gather *tlb,
			struct vm_area_struct *vma,
			unsigned long addr, unsigned long end,
			struct zap_details *details)
{
	pgd_t *pgd;
	unsigned long next;

	if (details && !details->check_mapping && !details->nonlinear_vma)
	  details = NULL;

	BUG_ON(addr >= end);
	mem_cgroup_uncharge_start();
	tlb_start_vma(tlb, vma);
	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
		  continue;
		next = zap_pud_range(tlb, vma, pgd, addr, next, details);
	} while (pgd++, addr = next, addr != end);
	tlb_end_vma(tlb, vma);
	mem_cgroup_uncharge_end();
}


static void unmap_single_vma(struct mmu_gather *tlb,
			struct vm_area_struct *vma, unsigned long start_addr,
			unsigned long end_addr,
			struct zap_details *details)
{
	unsigned long start = max(vma->vm_start, start_addr);
	unsigned long end;

	if (start >= vma->vm_end)
	  return;
	end = min(vma->vm_end, end_addr);
	if (end <= vma->vm_start)
	  return;

	if (vma->vm_file)
	  uprobe_munmap(vma, start, end);

	if (unlikely(vma->vm_flags & VM_PFNMAP))
	  untrack_pfn(vma, 0, 0);

	if (start != end) {
		if (unlikely(is_vm_hugetlb_page(vma))) {
			/*
			 * It is undesirable to test vma->vm_file as it
			 * should be non-null for valid hugetlb area.
			 * However, vm_file will be NULL in the error
			 * cleanup path of do_mmap_pgoff. When
			 * hugetlbfs ->mmap method fails,
			 * do_mmap_pgoff() nullifies vma->vm_file
			 * before calling this function to clean up.
			 * Since no pte has actually been setup, it is
			 * safe to do nothing in this case.
			 */
			if (vma->vm_file) {
				i_mmap_lock_write(vma->vm_file->f_mapping);
				__unmap_hugepage_range_final(tlb, vma, start, end, NULL);
				i_mmap_unlock_write(vma->vm_file->f_mapping);
			}
		} else
		  unmap_page_range(tlb, vma, start, end, details);
	}
}

/**
 * unmap_vmas - unmap a range of memory covered by a list of vma's
 * @tlb: address of the caller's struct mmu_gather
 * @vma: the starting vma
 * @start_addr: virtual address at which to start unmapping
 * @end_addr: virtual address at which to end unmapping
 *
 * Unmap all pages in the vma list.
 *
 * Only addresses between `start' and `end' will be unmapped.
 *
 * The VMA list must be sorted in ascending virtual address order.
 *
 * unmap_vmas() assumes that the caller will flush the whole unmapped address
 * range after unmap_vmas() returns.  So the only responsibility here is to
 * ensure that any thus-far unmapped pages are flushed before unmap_vmas()
 * drops the lock and schedules.
 */
void unmap_vmas(struct mmu_gather *tlb,
			struct vm_area_struct *vma, unsigned long start_addr,
			unsigned long end_addr)
{
	struct mm_struct *mm = vma->vm_mm;

	mmu_notifier_invalidate_range_start(mm, start_addr, end_addr);
	for ( ; vma && vma->vm_start < end_addr; vma = vma->vm_next)
	  unmap_single_vma(tlb, vma, start_addr, end_addr, NULL);
	mmu_notifier_invalidate_range_end(mm, start_addr, end_addr);
}

/**
 * zap_page_range - remove user pages in a given range
 * @vma: vm_area_struct holding the applicable pages
 * @start: starting address of pages to zap
 * @size: number of bytes to zap
 * @details: details of nonlinear truncation or shared cache invalidation
 *
 * Caller must protect the VMA list
 */
void zap_page_range(struct vm_area_struct *vma, unsigned long start,
			unsigned long size, struct zap_details *details)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_gather tlb;
	unsigned long end = start + size;

	lru_add_drain();
	tlb_gather_mmu(&tlb, mm, start, end);
	update_hiwater_rss(mm);
	mmu_notifier_invalidate_range_start(mm, start, end);
	for ( ; vma && vma->vm_start < end; vma = vma->vm_next)
	  unmap_single_vma(&tlb, vma, start, end, details);
	mmu_notifier_invalidate_range_end(mm, start, end);
	tlb_finish_mmu(&tlb, start, end);
}

/**
 * zap_page_range_single - remove user pages in a given range
 * @vma: vm_area_struct holding the applicable pages
 * @address: starting address of pages to zap
 * @size: number of bytes to zap
 * @details: details of nonlinear truncation or shared cache invalidation
 *
 * The range must fit into one VMA.
 */
static void zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
			unsigned long size, struct zap_details *details)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_gather tlb;
	unsigned long end = address + size;

	lru_add_drain();
	tlb_gather_mmu(&tlb, mm, address, end);
	update_hiwater_rss(mm);
	mmu_notifier_invalidate_range_start(mm, address, end);
	unmap_single_vma(&tlb, vma, address, end, details);
	mmu_notifier_invalidate_range_end(mm, address, end);
	tlb_finish_mmu(&tlb, address, end);
}

/**
 * zap_vma_ptes - remove ptes mapping the vma
 * @vma: vm_area_struct holding ptes to be zapped
 * @address: starting address of pages to zap
 * @size: number of bytes to zap
 *
 * This function only unmaps ptes assigned to VM_PFNMAP vmas.
 *
 * The entire address range must be fully contained within the vma.
 *
 * Returns 0 if successful.
 */
int zap_vma_ptes(struct vm_area_struct *vma, unsigned long address,
			unsigned long size)
{
	if (address < vma->vm_start || address + size > vma->vm_end ||
				!(vma->vm_flags & VM_PFNMAP))
	  return -1;
	zap_page_range_single(vma, address, size, NULL);
	return 0;
}
EXPORT_SYMBOL_GPL(zap_vma_ptes);

/**
 * follow_page_mask - look up a page descriptor from a user-virtual address
 * @vma: vm_area_struct mapping @address
 * @address: virtual address to look up
 * @flags: flags modifying lookup behaviour
 * @page_mask: on output, *page_mask is set according to the size of the page
 *
 * @flags can have FOLL_ flags set, defined in <linux/mm.h>
 *
 * Returns the mapped (struct page *), %NULL if no mapping exists, or
 * an error pointer if there is a mapping to something not represented
 * by a page descriptor (see also vm_normal_page()).
 */
struct page *follow_page_mask(struct vm_area_struct *vma,
			unsigned long address, unsigned int flags,
			unsigned int *page_mask)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	*page_mask = 0;

	page = follow_huge_addr(mm, address, flags & FOLL_WRITE);
	if (!IS_ERR(page)) {
		BUG_ON(flags & FOLL_GET);
		goto out;
	}

	page = NULL;
	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
	  goto no_page_table;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud))
	  goto no_page_table;
	if (pud_huge(*pud) && vma->vm_flags & VM_HUGETLB) {
		if (flags & FOLL_GET)
		  goto out;
		page = follow_huge_pud(mm, address, pud, flags & FOLL_WRITE);
		goto out;
	}
	if (unlikely(pud_bad(*pud)))
	  goto no_page_table;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
	  goto no_page_table;
	if (pmd_huge(*pmd) && vma->vm_flags & VM_HUGETLB) {
		page = follow_huge_pmd(mm, address, pmd, flags & FOLL_WRITE);
		if (flags & FOLL_GET) {
			/*
			 * Refcount on tail pages are not well-defined and
			 * shouldn't be taken. The caller should handle a NULL
			 * return when trying to follow tail pages.
			 */
			if (PageHead(page))
			  get_page(page);
			else {
				page = NULL;
				goto out;
			}
		}
		goto out;
	}
	if ((flags & FOLL_NUMA) && pmd_numa(*pmd))
	  goto no_page_table;
	if (pmd_trans_huge(*pmd)) {
		if (flags & FOLL_SPLIT) {
			split_huge_page_pmd(vma, address, pmd);
			goto split_fallthrough;
		}
		ptl = pmd_lock(mm, pmd);
		if (likely(pmd_trans_huge(*pmd))) {
			if (unlikely(pmd_trans_splitting(*pmd))) {
				spin_unlock(ptl);
				wait_split_huge_page(vma->anon_vma, pmd);
			} else {
				page = follow_trans_huge_pmd(vma, address,
							pmd, flags);
				spin_unlock(ptl);
				*page_mask = HPAGE_PMD_NR - 1;
				goto out;
			}
		} else
		  spin_unlock(ptl);
		/* fall through */
	}
split_fallthrough:
	if (unlikely(pmd_bad(*pmd)))
	  goto no_page_table;

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);

	pte = *ptep;
	if (!pte_present(pte)) {
		swp_entry_t entry;
		/*
		 * KSM's break_ksm() relies upon recognizing a ksm page
		 * even while it is being migrated, so for that case we
		 * need migration_entry_wait().
		 */
		if (likely(!(flags & FOLL_MIGRATION)))
		  goto no_page;
		if (pte_none(pte) || pte_file(pte))
		  goto no_page;
		entry = pte_to_swp_entry(pte);
		if (!is_migration_entry(entry))
		  goto no_page;
		pte_unmap_unlock(ptep, ptl);
		migration_entry_wait(mm, pmd, address);
		goto split_fallthrough;
	}
	if ((flags & FOLL_NUMA) && pte_numa(pte))
	  goto no_page;
	if ((flags & FOLL_WRITE) && !pte_write(pte))
	  goto unlock;

	page = vm_normal_page(vma, address, pte);
	if (unlikely(!page)) {
		if ((flags & FOLL_DUMP) ||
					!is_zero_pfn(pte_pfn(pte)))
		  goto bad_page;
		page = pte_page(pte);
	}

	if (flags & FOLL_GET)
	  get_page_foll(page);
	if (flags & FOLL_TOUCH) {
		if ((flags & FOLL_WRITE) &&
					!pte_dirty(pte) && !PageDirty(page))
		  set_page_dirty(page);
		/*
		 * pte_mkyoung() would be more correct here, but atomic care
		 * is needed to avoid losing the dirty bit: it is easier to use
		 * mark_page_accessed().
		 */
		mark_page_accessed(page);
	}
	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		/*
		 * The preliminary mapping check is mainly to avoid the
		 * pointless overhead of lock_page on the ZERO_PAGE
		 * which might bounce very badly if there is contention.
		 *
		 * If the page is already locked, we don't need to
		 * handle it now - vmscan will handle it later if and
		 * when it attempts to reclaim the page.
		 */
		if (page->mapping && trylock_page(page)) {
			lru_add_drain();  /* push cached pages to LRU */
			/*
			 * Because we lock page here, and migration is
			 * blocked by the pte's page reference, and we
			 * know the page is still mapped, we don't even
			 * need to check for file-cache page truncation.
			 */
			mlock_vma_page(page);
			unlock_page(page);
		}
	}
unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return page;

bad_page:
	pte_unmap_unlock(ptep, ptl);
	return ERR_PTR(-EFAULT);

no_page:
	pte_unmap_unlock(ptep, ptl);
	if (!pte_none(pte))
	  return page;

no_page_table:
	/*
	 * When core dumping an enormous anonymous area that nobody
	 * has touched so far, we don't want to allocate unnecessary pages or
	 * page tables.  Return error instead of NULL to skip handle_mm_fault,
	 * then get_dump_page() will return NULL to leave a hole in the dump.
	 * But we can only make this optimization where a hole would surely
	 * be zero-filled if handle_mm_fault() actually did handle it.
	 */
	if ((flags & FOLL_DUMP) &&
				(!vma->vm_ops || !vma->vm_ops->fault))
	  return ERR_PTR(-EFAULT);
	return page;
}

static inline int stack_guard_page(struct vm_area_struct *vma, unsigned long addr)
{
	return stack_guard_page_start(vma, addr) ||
		stack_guard_page_end(vma, addr+PAGE_SIZE);
}

/**
 * __get_user_pages() - pin user pages in memory
 * @tsk:	task_struct of target task
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying pin behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 * @nonblocking: whether waiting for disk IO or mmap_sem contention
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with. vmas will only
 * remain valid while mmap_sem is held.
 *
 * Must be called with mmap_sem held for read or write.
 *
 * __get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * __get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If @gup_flags & FOLL_WRITE == 0, the page must not be written to. If
 * the page is written to, set_page_dirty (or set_page_dirty_lock, as
 * appropriate) must be called after the page is finished with, and
 * before put_page is called.
 *
 * If @nonblocking != NULL, __get_user_pages will not wait for disk IO
 * or mmap_sem contention, and if waiting is needed to pin all pages,
 * *@nonblocking will be set to 0.
 *
 * In most cases, get_user_pages or get_user_pages_fast should be used
 * instead of __get_user_pages. __get_user_pages should be used only if
 * you need some special @gup_flags.
 */
long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
			unsigned long start, unsigned long nr_pages,
			unsigned int gup_flags, struct page **pages,
			struct vm_area_struct **vmas, int *nonblocking)
{
	long i;
	unsigned long vm_flags;
	unsigned int page_mask;

	if (!nr_pages)
	  return 0;

	VM_BUG_ON(!!pages != !!(gup_flags & FOLL_GET));

	/* 
	 * Require read or write permissions.
	 * If FOLL_FORCE is set, we only require the "MAY" flags.
	 */
	vm_flags  = (gup_flags & FOLL_WRITE) ?
		(VM_WRITE | VM_MAYWRITE) : (VM_READ | VM_MAYREAD);
	vm_flags &= (gup_flags & FOLL_FORCE) ?
		(VM_MAYREAD | VM_MAYWRITE) : (VM_READ | VM_WRITE);

	/*
	 * If FOLL_FORCE and FOLL_NUMA are both set, handle_mm_fault
	 * would be called on PROT_NONE ranges. We must never invoke
	 * handle_mm_fault on PROT_NONE ranges or the NUMA hinting
	 * page faults would unprotect the PROT_NONE ranges if
	 * _PAGE_NUMA and _PAGE_PROTNONE are sharing the same pte/pmd
	 * bitflag. So to avoid that, don't set FOLL_NUMA if
	 * FOLL_FORCE is set.
	 */
	if (!(gup_flags & FOLL_FORCE))
	  gup_flags |= FOLL_NUMA;

	i = 0;

	do {
		struct vm_area_struct *vma;

		vma = find_extend_vma(mm, start);
		if (!vma && in_gate_area(mm, start)) {
			unsigned long pg = start & PAGE_MASK;
			pgd_t *pgd;
			pud_t *pud;
			pmd_t *pmd;
			pte_t *pte;

			/* user gate pages are read-only */
			if (gup_flags & FOLL_WRITE)
			  return i ? : -EFAULT;
			if (pg > TASK_SIZE)
			  pgd = pgd_offset_k(pg);
			else
			  pgd = pgd_offset_gate(mm, pg);
			BUG_ON(pgd_none(*pgd));
			pud = pud_offset(pgd, pg);
			BUG_ON(pud_none(*pud));
			pmd = pmd_offset(pud, pg);
			if (pmd_none(*pmd))
			  return i ? : -EFAULT;
			VM_BUG_ON(pmd_trans_huge(*pmd));
			pte = pte_offset_map(pmd, pg);
			if (pte_none(*pte)) {
				pte_unmap(pte);
				return i ? : -EFAULT;
			}
			vma = get_gate_vma(mm);
			if (pages) {
				struct page *page;

				page = vm_normal_page(vma, start, *pte);
				if (!page) {
					if (!(gup_flags & FOLL_DUMP) &&
								is_zero_pfn(pte_pfn(*pte)))
					  page = pte_page(*pte);
					else {
						pte_unmap(pte);
						return i ? : -EFAULT;
					}
				}
				pages[i] = page;
				get_page(page);
			}
			pte_unmap(pte);
			page_mask = 0;
			goto next_page;
		}

		if (!vma ||
					(vma->vm_flags & (VM_IO | VM_PFNMAP)) ||
					!(vm_flags & vma->vm_flags))
		  return i ? : -EFAULT;

		if (is_vm_hugetlb_page(vma)) {
			i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &nr_pages, i, gup_flags);
			continue;
		}

		do {
			struct page *page;
			unsigned int foll_flags = gup_flags;
			unsigned int page_increm;

			/*
			 * If we have a pending SIGKILL, don't keep faulting
			 * pages and potentially allocating memory.
			 */
			if (unlikely(fatal_signal_pending(current)))
			  return i ? i : -ERESTARTSYS;

			cond_resched();
			while (!(page = follow_page_mask(vma, start,
								foll_flags, &page_mask))) {
				int ret;
				unsigned int fault_flags = 0;

				/* For mlock, just skip the stack guard page. */
				if (foll_flags & FOLL_MLOCK) {
					if (stack_guard_page(vma, start))
					  goto next_page;
				}
				if (foll_flags & FOLL_WRITE)
				  fault_flags |= FAULT_FLAG_WRITE;
				if (nonblocking)
				  fault_flags |= FAULT_FLAG_ALLOW_RETRY;
				if (foll_flags & FOLL_NOWAIT)
				  fault_flags |= (FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT);

				ret = handle_mm_fault(mm, vma, start,
							fault_flags);

				if (ret & VM_FAULT_ERROR) {
					if (ret & VM_FAULT_OOM)
					  return i ? i : -ENOMEM;
					if (ret & (VM_FAULT_HWPOISON |
									VM_FAULT_HWPOISON_LARGE)) {
						if (i)
						  return i;
						else if (gup_flags & FOLL_HWPOISON)
						  return -EHWPOISON;
						else
						  return -EFAULT;
					}
					if (ret & VM_FAULT_SIGBUS)
					  return i ? i : -EFAULT;
					BUG();
				}

				if (tsk) {
					if (ret & VM_FAULT_MAJOR)
					  tsk->maj_flt++;
					else
					  tsk->min_flt++;
				}

				if (ret & VM_FAULT_RETRY) {
					if (nonblocking)
					  *nonblocking = 0;
					return i;
				}

				/*
				 * The VM_FAULT_WRITE bit tells us that
				 * do_wp_page has broken COW when necessary,
				 * even if maybe_mkwrite decided not to set
				 * pte_write. We can thus safely do subsequent
				 * page lookups as if they were reads. But only
				 * do so when looping for pte_write is futile:
				 * in some cases userspace may also be wanting
				 * to write to the gotten user page, which a
				 * read fault here might prevent (a readonly
				 * page might get reCOWed by userspace write).
				 */
				if ((ret & VM_FAULT_WRITE) &&
							!(vma->vm_flags & VM_WRITE))
				  foll_flags &= ~FOLL_WRITE;

				cond_resched();
			}
			if (IS_ERR(page))
			  return i ? i : PTR_ERR(page);
			if (pages) {
				pages[i] = page;

				flush_anon_page(vma, page, start);
				flush_dcache_page(page);
				page_mask = 0;
			}
next_page:
			if (vmas) {
				vmas[i] = vma;
				page_mask = 0;
			}
			page_increm = 1 + (~(start >> PAGE_SHIFT) & page_mask);
			if (page_increm > nr_pages)
			  page_increm = nr_pages;
			i += page_increm;
			start += page_increm * PAGE_SIZE;
			nr_pages -= page_increm;
		} while (nr_pages && start < vma->vm_end);
	} while (nr_pages);
	return i;
}
EXPORT_SYMBOL(__get_user_pages);

/*
 * fixup_user_fault() - manually resolve a user page fault
 * @tsk:	the task_struct to use for page fault accounting, or
 *		NULL if faults are not to be recorded.
 * @mm:		mm_struct of target mm
 * @address:	user address
 * @fault_flags:flags to pass down to handle_mm_fault()
 *
 * This is meant to be called in the specific scenario where for locking reasons
 * we try to access user memory in atomic context (within a pagefault_disable()
 * section), this returns -EFAULT, and we want to resolve the user fault before
 * trying again.
 *
 * Typically this is meant to be used by the futex code.
 *
 * The main difference with get_user_pages() is that this function will
 * unconditionally call handle_mm_fault() which will in turn perform all the
 * necessary SW fixup of the dirty and young bits in the PTE, while
 * handle_mm_fault() only guarantees to update these in the struct page.
 *
 * This is important for some architectures where those bits also gate the
 * access permission to the page because they are maintained in software.  On
 * such architectures, gup() will not be enough to make a subsequent access
 * succeed.
 *
 * This should be called with the mm_sem held for read.
 */
int fixup_user_fault(struct task_struct *tsk, struct mm_struct *mm,
			unsigned long address, unsigned int fault_flags)
{
	struct vm_area_struct *vma;
	vm_flags_t vm_flags;
	int ret;

	vma = find_extend_vma(mm, address);
	if (!vma || address < vma->vm_start)
	  return -EFAULT;

	vm_flags = (fault_flags & FAULT_FLAG_WRITE) ? VM_WRITE : VM_READ;
	if (!(vm_flags & vma->vm_flags))
	  return -EFAULT;

	ret = handle_mm_fault(mm, vma, address, fault_flags);
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
		  return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
		  return -EHWPOISON;
		if (ret & VM_FAULT_SIGBUS)
		  return -EFAULT;
		BUG();
	}
	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
		  tsk->maj_flt++;
		else
		  tsk->min_flt++;
	}
	return 0;
}

/*
 * get_user_pages() - pin user pages in memory
 * @tsk:	the task_struct to use for page fault accounting, or
 *		NULL if faults are not to be recorded.
 * @mm:		mm_struct of target mm
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @write:	whether pages will be written to by the caller
 * @force:	whether to force write access even if user mapping is
 *		readonly. This will result in the page being COWed even
 *		in MAP_SHARED mappings. You do not want this.
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with. vmas will only
 * remain valid while mmap_sem is held.
 *
 * Must be called with mmap_sem held for read or write.
 *
 * get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If write=0, the page must not be written to. If the page is written to,
 * set_page_dirty (or set_page_dirty_lock, as appropriate) must be called
 * after the page is finished with, and before put_page is called.
 *
 * get_user_pages is typically used for fewer-copy IO operations, to get a
 * handle on the memory by some means other than accesses via the user virtual
 * addresses. The pages may be submitted for DMA to devices or accessed via
 * their kernel linear mapping (via the kmap APIs). Care should be taken to
 * use the correct cache flushing APIs.
 *
 * See also get_user_pages_fast, for performance critical applications.
 */
long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
			unsigned long start, unsigned long nr_pages, int write,
			int force, struct page **pages, struct vm_area_struct **vmas)
{
	int flags = FOLL_TOUCH;

	if (pages)
	  flags |= FOLL_GET;
	if (write)
	  flags |= FOLL_WRITE;
	if (force)
	  flags |= FOLL_FORCE;

	return __get_user_pages(tsk, mm, start, nr_pages, flags, pages, vmas,
				NULL);
}
EXPORT_SYMBOL(get_user_pages);

/**
 * get_dump_page() - pin user page in memory while writing it to core dump
 * @addr: user address
 *
 * Returns struct page pointer of user page pinned for dump,
 * to be freed afterwards by page_cache_release() or put_page().
 *
 * Returns NULL on any kind of failure - a hole must then be inserted into
 * the corefile, to preserve alignment with its headers; and also returns
 * NULL wherever the ZERO_PAGE, or an anonymous pte_none, has been found -
 * allowing a hole to be left in the corefile to save diskspace.
 *
 * Called without mmap_sem, but after all other threads have been killed.
 */
#ifdef CONFIG_ELF_CORE
struct page *get_dump_page(unsigned long addr)
{
	struct vm_area_struct *vma;
	struct page *page;

	if (__get_user_pages(current, current->mm, addr, 1,
					FOLL_FORCE | FOLL_DUMP | FOLL_GET, &page, &vma,
					NULL) < 1)
	  return NULL;
	flush_cache_page(vma, addr, page_to_pfn(page));
	return page;
}
#endif /* CONFIG_ELF_CORE */

pte_t *__get_locked_pte(struct mm_struct *mm, unsigned long addr,
			spinlock_t **ptl)
{
	pgd_t * pgd = pgd_offset(mm, addr);
	pud_t * pud = pud_alloc(mm, pgd, addr);
	if (pud) {
		pmd_t * pmd = pmd_alloc(mm, pud, addr);
		if (pmd) {
			VM_BUG_ON(pmd_trans_huge(*pmd));
			return pte_alloc_map_lock(mm, pmd, addr, ptl);
		}
	}
	return NULL;
}

/*
 * This is the old fallback for page remapping.
 *
 * For historical reasons, it only allows reserved pages. Only
 * old drivers should use this, and they needed to mark their
 * pages reserved for the old functions anyway.
 */
static int insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page, pgprot_t prot)
{
	struct mm_struct *mm = vma->vm_mm;
	int retval;
	pte_t *pte;
	spinlock_t *ptl;

	retval = -EINVAL;
	if (PageAnon(page))
	  goto out;
	retval = -ENOMEM;
	flush_dcache_page(page);
	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte)
	  goto out;
	retval = -EBUSY;
	if (!pte_none(*pte))
	  goto out_unlock;

	/* Ok, finally just insert the thing.. */
	get_page(page);
	inc_mm_counter_fast(mm, MM_FILEPAGES);
	page_add_file_rmap(page);
	set_pte_at(mm, addr, pte, mk_pte(page, prot));

	retval = 0;
	pte_unmap_unlock(pte, ptl);
	inc_page_counter_in_ns(page,vma);

	return retval;
out_unlock:
	pte_unmap_unlock(pte, ptl);
out:
	return retval;
}

/**
 * vm_insert_page - insert single page into user vma
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @page: source kernel page
 *
 * This allows drivers to insert individual pages they've allocated
 * into a user vma.
 *
 * The page has to be a nice clean _individual_ kernel allocation.
 * If you allocate a compound page, you need to have marked it as
 * such (__GFP_COMP), or manually just split the page up yourself
 * (see split_page()).
 *
 * NOTE! Traditionally this was done with "remap_pfn_range()" which
 * took an arbitrary page protection parameter. This doesn't allow
 * that. Your vma protection will have to be set up correctly, which
 * means that if you want a shared writable mapping, you'd better
 * ask for a shared writable mapping!
 *
 * The page does not need to be reserved.
 *
 * Usually this function is called from f_op->mmap() handler
 * under mm->mmap_sem write-lock, so it can change vma->vm_flags.
 * Caller must set VM_MIXEDMAP on vma if it wants to call this
 * function from other places, for example from page-fault handler.
 */
int vm_insert_page(struct vm_area_struct *vma, unsigned long addr,
			struct page *page)
{
	if (addr < vma->vm_start || addr >= vma->vm_end)
	  return -EFAULT;
	if (!page_count(page))
	  return -EINVAL;
	if (!(vma->vm_flags & VM_MIXEDMAP)) {
		BUG_ON(down_read_trylock(&vma->vm_mm->mmap_sem));
		BUG_ON(vma->vm_flags & VM_PFNMAP);
		vma->vm_flags |= VM_MIXEDMAP;
	}
	return insert_page(vma, addr, page, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_insert_page);

static int insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, pgprot_t prot)
{
	struct mm_struct *mm = vma->vm_mm;
	int retval;
	pte_t *pte, entry;
	spinlock_t *ptl;

	retval = -ENOMEM;
	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte)
	  goto out;
	retval = -EBUSY;
	if (!pte_none(*pte))
	  goto out_unlock;

	/* Ok, finally just insert the thing.. */
	entry = pte_mkspecial(pfn_pte(pfn, prot));
	set_pte_at(mm, addr, pte, entry);
	update_mmu_cache(vma, addr, pte); /* XXX: why not for insert_page? */

	retval = 0;
out_unlock:
	pte_unmap_unlock(pte, ptl);
out:
	return retval;
}

/**
 * vm_insert_pfn - insert single pfn into user vma
 * @vma: user vma to map to
 * @addr: target user address of this page
 * @pfn: source kernel pfn
 *
 * Similar to vm_insert_page, this allows drivers to insert individual pages
 * they've allocated into a user vma. Same comments apply.
 *
 * This function should only be called from a vm_ops->fault handler, and
 * in that case the handler should return NULL.
 *
 * vma cannot be a COW mapping.
 *
 * As this is called only for pages that do not currently exist, we
 * do not need to flush old virtual caches or the TLB.
 */
int vm_insert_pfn(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn)
{
	int ret;
	pgprot_t pgprot = vma->vm_page_prot;
	/*
	 * Technically, architectures with pte_special can avoid all these
	 * restrictions (same for remap_pfn_range).  However we would like
	 * consistency in testing and feature parity among all, so we should
	 * try to keep these invariants in place for everybody.
	 */
	BUG_ON(!(vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)));
	BUG_ON((vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)) ==
				(VM_PFNMAP|VM_MIXEDMAP));
	BUG_ON((vma->vm_flags & VM_PFNMAP) && is_cow_mapping(vma->vm_flags));
	BUG_ON((vma->vm_flags & VM_MIXEDMAP) && pfn_valid(pfn));

	if (addr < vma->vm_start || addr >= vma->vm_end)
	  return -EFAULT;
	if (track_pfn_insert(vma, &pgprot, pfn))
	  return -EINVAL;

	ret = insert_pfn(vma, addr, pfn, pgprot);

	return ret;
}
EXPORT_SYMBOL(vm_insert_pfn);

int vm_insert_mixed(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn)
{
	BUG_ON(!(vma->vm_flags & VM_MIXEDMAP));

	if (addr < vma->vm_start || addr >= vma->vm_end)
	  return -EFAULT;

	/*
	 * If we don't have pte special, then we have to use the pfn_valid()
	 * based VM_MIXEDMAP scheme (see vm_normal_page), and thus we *must*
	 * refcount the page if pfn_valid is true (hence insert_page rather
	 * than insert_pfn).  If a zero_pfn were inserted into a VM_MIXEDMAP
	 * without pte special, it would there be refcounted as a normal page.
	 */
	if (!HAVE_PTE_SPECIAL && pfn_valid(pfn)) {
		struct page *page;

		page = pfn_to_page(pfn);
		return insert_page(vma, addr, page, vma->vm_page_prot);
	}
	return insert_pfn(vma, addr, pfn, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_insert_mixed);

/*
 * maps a range of physical memory into the requested pages. the old
 * mappings are removed. any references to nonexistent pages results
 * in null mappings (currently treated as "copy-on-access")
 */
static int remap_pte_range(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pte_t *pte;
	spinlock_t *ptl;

	pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
	  return -ENOMEM;
	arch_enter_lazy_mmu_mode();
	do {
		BUG_ON(!pte_none(*pte));
		set_pte_at(mm, addr, pte, pte_mkspecial(pfn_pte(pfn, prot)));
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);
	return 0;
}

static inline int remap_pmd_range(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	pfn -= addr >> PAGE_SHIFT;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
	  return -ENOMEM;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		if (remap_pte_range(mm, pmd, addr, next,
						pfn + (addr >> PAGE_SHIFT), prot))
		  return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int remap_pud_range(struct mm_struct *mm, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	pfn -= addr >> PAGE_SHIFT;
	pud = pud_alloc(mm, pgd, addr);
	if (!pud)
	  return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (remap_pmd_range(mm, pud, addr, next,
						pfn + (addr >> PAGE_SHIFT), prot))
		  return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

/**
 * remap_pfn_range - remap kernel memory to userspace
 * @vma: user vma to map to
 * @addr: target user address to start at
 * @pfn: physical address of kernel memory
 * @size: size of map area
 * @prot: page protection flags for this mapping
 *
 *  Note: this is only safe if the mm semaphore is held when called.
 */
int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, unsigned long size, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	int err;

	/*
	 * Physically remapped pages are special. Tell the
	 * rest of the world about it:
	 *   VM_IO tells people not to look at these pages
	 *	(accesses can have side effects).
	 *   VM_PFNMAP tells the core MM that the base pages are just
	 *	raw PFN mappings, and do not have a "struct page" associated
	 *	with them.
	 *   VM_DONTEXPAND
	 *      Disable vma merging and expanding with mremap().
	 *   VM_DONTDUMP
	 *      Omit vma from core dump, even when VM_IO turned off.
	 *
	 * There's a horrible special case to handle copy-on-write
	 * behaviour that some programs depend on. We mark the "original"
	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
	 * See vm_normal_page() for details.
	 */
	if (is_cow_mapping(vma->vm_flags)) {
		if (addr != vma->vm_start || end != vma->vm_end)
		  return -EINVAL;
		vma->vm_pgoff = pfn;
	}

	err = track_pfn_remap(vma, &prot, pfn, addr, PAGE_ALIGN(size));
	if (err)
	  return -EINVAL;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;

	BUG_ON(addr >= end);
	pfn -= addr >> PAGE_SHIFT;
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		err = remap_pud_range(mm, pgd, addr, next,
					pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
		  break;
	} while (pgd++, addr = next, addr != end);

	if (err)
	  untrack_pfn(vma, pfn, PAGE_ALIGN(size));

	return err;
}
EXPORT_SYMBOL(remap_pfn_range);

/**
 * vm_iomap_memory - remap memory to userspace
 * @vma: user vma to map to
 * @start: start of area
 * @len: size of area
 *
 * This is a simplified io_remap_pfn_range() for common driver use. The
 * driver just needs to give us the physical memory range to be mapped,
 * we'll figure out the rest from the vma information.
 *
 * NOTE! Some drivers might want to tweak vma->vm_page_prot first to get
 * whatever write-combining details or similar.
 */
int vm_iomap_memory(struct vm_area_struct *vma, phys_addr_t start, unsigned long len)
{
	unsigned long vm_len, pfn, pages;

	/* Check that the physical memory area passed in looks valid */
	if (start + len < start)
	  return -EINVAL;
	/*
	 * You *really* shouldn't map things that aren't page-aligned,
	 * but we've historically allowed it because IO memory might
	 * just have smaller alignment.
	 */
	len += start & ~PAGE_MASK;
	pfn = start >> PAGE_SHIFT;
	pages = (len + ~PAGE_MASK) >> PAGE_SHIFT;
	if (pfn + pages < pfn)
	  return -EINVAL;

	/* We start the mapping 'vm_pgoff' pages into the area */
	if (vma->vm_pgoff > pages)
	  return -EINVAL;
	pfn += vma->vm_pgoff;
	pages -= vma->vm_pgoff;

	/* Can we fit all of the mapping? */
	vm_len = vma->vm_end - vma->vm_start;
	if (vm_len >> PAGE_SHIFT > pages)
	  return -EINVAL;

	/* Ok, let it rip */
	return io_remap_pfn_range(vma, vma->vm_start, pfn, vm_len, vma->vm_page_prot);
}
EXPORT_SYMBOL(vm_iomap_memory);

static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			pte_fn_t fn, void *data)
{
	pte_t *pte;
	int err;
	pgtable_t token;
	spinlock_t *uninitialized_var(ptl);

	pte = (mm == &init_mm) ?
		pte_alloc_kernel(pmd, addr) :
		pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
	  return -ENOMEM;

	BUG_ON(pmd_huge(*pmd));

	arch_enter_lazy_mmu_mode();

	token = pmd_pgtable(*pmd);

	do {
		err = fn(pte++, token, addr, data);
		if (err)
		  break;
	} while (addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();

	if (mm != &init_mm)
	  pte_unmap_unlock(pte-1, ptl);
	return err;
}

static int apply_to_pmd_range(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, unsigned long end,
			pte_fn_t fn, void *data)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	BUG_ON(pud_huge(*pud));

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
	  return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		err = apply_to_pte_range(mm, pmd, addr, next, fn, data);
		if (err)
		  break;
	} while (pmd++, addr = next, addr != end);
	return err;
}

static int apply_to_pud_range(struct mm_struct *mm, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			pte_fn_t fn, void *data)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pud = pud_alloc(mm, pgd, addr);
	if (!pud)
	  return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		err = apply_to_pmd_range(mm, pud, addr, next, fn, data);
		if (err)
		  break;
	} while (pud++, addr = next, addr != end);
	return err;
}

/*
 * Scan a region of virtual memory, filling in page tables as necessary
 * and calling a provided function on each leaf page table.
 */
int apply_to_page_range(struct mm_struct *mm, unsigned long addr,
			unsigned long size, pte_fn_t fn, void *data)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + size;
	int err;

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		err = apply_to_pud_range(mm, pgd, addr, next, fn, data);
		if (err)
		  break;
	} while (pgd++, addr = next, addr != end);

	return err;
}
EXPORT_SYMBOL_GPL(apply_to_page_range);

/*
 * handle_pte_fault chooses page fault handler according to an entry
 * which was read non-atomically.  Before making any commitment, on
 * those architectures or configurations (e.g. i386 with PAE) which
 * might give a mix of unmatched parts, do_swap_page and do_nonlinear_fault
 * must check under lock before unmapping the pte and proceeding
 * (but do_wp_page is only called after already making such a check;
 * and do_anonymous_page can safely check later on).
 */
static inline int pte_unmap_same(struct mm_struct *mm, pmd_t *pmd,
			pte_t *page_table, pte_t orig_pte)
{
	int same = 1;
#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT)
	if (sizeof(pte_t) > sizeof(unsigned long)) {
		spinlock_t *ptl = pte_lockptr(mm, pmd);
		spin_lock(ptl);
		same = pte_same(*page_table, orig_pte);
		spin_unlock(ptl);
	}
#endif
	pte_unmap(page_table);
	return same;
}

static inline void cow_user_page(struct page *dst, struct page *src, unsigned long va, struct vm_area_struct *vma)
{
	/*
	 * If the source page was a PFN mapping, we don't have
	 * a "struct page" for it. We do a best-effort copy by
	 * just copying from the original user address. If that
	 * fails, we just zero-fill it. Live with it.
	 */
	if (unlikely(!src)) {
		void *kaddr = kmap_atomic(dst);
		void __user *uaddr = (void __user *)(va & PAGE_MASK);

		/*
		 * This really shouldn't fail, because the page is there
		 * in the page tables. But it might just be unreadable,
		 * in which case we just give up and fill the result with
		 * zeroes.
		 */
		if (__copy_from_user_inatomic(kaddr, uaddr, PAGE_SIZE))
		  clear_page(kaddr);
		kunmap_atomic(kaddr);
		flush_dcache_page(dst);
	} else{
		copy_user_highpage(dst, src, va, vma);
	}
}

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus we can safely just mark it writable once we've done any necessary
 * COW.
 *
 * We also mark the page dirty at this point even though the page will
 * change only once the write actually happens. This avoids a few races,
 * and potentially makes it more efficient.
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), with pte both mapped and locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */

struct sclock_coa_parent *get_original(struct sclock_coa_parent *coa_parent);
void del_page_from_coa(struct page* old_page){
	if(!old_page)
	  return;
	//retry:
	if(old_page->coa_head){
		unsigned long flags;
		struct sclock_coa_parent* coa_entry,*coa_parent;
		coa_entry=list_entry(old_page->coa_head,struct sclock_coa_parent,head);
		coa_list_lock(get_original(coa_entry));
		printk("del page from copy on write\n");
		if(coa_entry->pfn!=page_to_pfn(old_page)){
			coa_list_unlock(get_original(coa_entry));
			printk("different, give up....\n");
			return;
		}
		if(coa_entry->parent_head){
			//	struct sclock_coa_parent *coa_parent=list_entry(coa_entry->parent_head,struct sclock_coa_parent,head);
			coa_entry->pfn=COA_DEL;
			//goto reuse;
		}else{
			del_coa_parent_slow(coa_entry);
		}
		coa_list_unlock(get_original(coa_entry));
	}
}

static int do_wp_page(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, pte_t *page_table, pmd_t *pmd,
			spinlock_t *ptl, pte_t orig_pte)
__releases(ptl)
{
	struct page *old_page, *new_page = NULL;
	pte_t entry;
	int ret = 0;
	int page_mkwrite = 0;
	struct page *dirty_page = NULL;
	unsigned long mmun_start = 0;	/* For mmu_notifiers */
	unsigned long mmun_end = 0;	/* For mmu_notifiers */
	old_page = vm_normal_page(vma, address, orig_pte);
	unsigned long flags;
	if (!old_page) {
		/*
		 * VM_MIXEDMAP !pfn_valid() case
		 *
		 * We should not cow pages in a shared writeable mapping.
		 * Just mark the pages writable as we can't do any dirty
		 * accounting on raw pfn maps.
		 */
		if ((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
					(VM_WRITE|VM_SHARED))
		  goto reuse;
		goto gotten;
	}
	/*
	 * Take out anonymous pages first, anonymous shared vmas are
	 * not dirty accountable.
	 */
	if (PageAnon(old_page) && !PageKsm(old_page)) {
		if (!trylock_page(old_page)) {
			page_cache_get(old_page);
			pte_unmap_unlock(page_table, ptl);
			lock_page(old_page);
			page_table = pte_offset_map_lock(mm, pmd, address,
						&ptl);
			if (!pte_same(*page_table, orig_pte)) {
				unlock_page(old_page);
				goto unlock;
			}
			page_cache_release(old_page);
		}
		/*if write to a coa page, delete it to avoid merge*/
		if (reuse_swap_page(old_page)) {
			/*
			 * The page is all ours.  Move it to our anon_vma so
			 * the rmap code will not search our parent or siblings.
			 * Protected against the rmap code by the page lock.
			 */
			page_move_anon_rmap(old_page, vma, address);
			unlock_page(old_page);
			goto reuse;
		}
		unlock_page(old_page);
	} else if (unlikely((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
					(VM_WRITE|VM_SHARED))) {
		/*
		 * Only catch write-faults on shared writable pages,
		 * read-only shared pages can get COWed by
		 * get_user_pages(.write=1, .force=1).
		 */
		if (vma->vm_ops && vma->vm_ops->page_mkwrite) {
			struct vm_fault vmf;
			int tmp;

			vmf.virtual_address = (void __user *)(address &
						PAGE_MASK);
			vmf.pgoff = old_page->index;
			vmf.flags = FAULT_FLAG_WRITE|FAULT_FLAG_MKWRITE;
			vmf.page = old_page;

			/*
			 * Notify the address space that the page is about to
			 * become writable so that it can prohibit this or wait
			 * for the page to get into an appropriate state.
			 *
			 * We do this without the lock held, so that it can
			 * sleep if it needs to.
			 */
			page_cache_get(old_page);
			pte_unmap_unlock(page_table, ptl);

			tmp = vma->vm_ops->page_mkwrite(vma, &vmf);
			if (unlikely(tmp &
							(VM_FAULT_ERROR | VM_FAULT_NOPAGE))) {
				ret = tmp;
				goto unwritable_page;
			}
			if (unlikely(!(tmp & VM_FAULT_LOCKED))) {
				lock_page(old_page);
				if (!old_page->mapping) {
					ret = 0; /* retry the fault */
					unlock_page(old_page);
					goto unwritable_page;
				}
			} else
			  VM_BUG_ON(!PageLocked(old_page));

			/*
			 * Since we dropped the lock we need to revalidate
			 * the PTE as someone else may have changed it.  If
			 * they did, we just return, as we can count on the
			 * MMU to tell us if they didn't also make it writable.
			 */
			page_table = pte_offset_map_lock(mm, pmd, address,
						&ptl);
			if (!pte_same(*page_table, orig_pte)) {
				unlock_page(old_page);
				goto unlock;
			}

			page_mkwrite = 1;
		}
		dirty_page = old_page;
		get_page(dirty_page);

reuse:
		/*
		 * Clear the pages cpupid information as the existing
		 * information potentially belongs to a now completely
		 * unrelated process.
		 */
		if (old_page)
		  page_cpupid_xchg_last(old_page, (1 << LAST_CPUPID_SHIFT) - 1);

		flush_cache_page(vma, address, pte_pfn(orig_pte));
		entry = pte_mkyoung(orig_pte);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		if (ptep_set_access_flags(vma, address, page_table, entry,1))
		  update_mmu_cache(vma, address, page_table);
		pte_unmap_unlock(page_table, ptl);
		ret |= VM_FAULT_WRITE;

		if (!dirty_page){
			return ret;
		}
		/*
		 * Yes, Virginia, this is actually required to prevent a race
		 * with clear_page_dirty_for_io() from clearing the page dirty
		 * bit after it clear all dirty ptes, but before a racing
		 * do_wp_page installs a dirty pte.
		 *
		 * __do_fault is protected similarly.
		 */
		if (!page_mkwrite) {
			wait_on_page_locked(dirty_page);
			set_page_dirty_balance(dirty_page, page_mkwrite);
			/* file_update_time outside page_lock */
			if (vma->vm_file)
			  vma_file_update_time(vma);
		}
		put_page(dirty_page);
		if (page_mkwrite) {
			struct address_space *mapping = dirty_page->mapping;

			set_page_dirty(dirty_page);
			unlock_page(dirty_page);
			page_cache_release(dirty_page);
			if (mapping)	{
				/*
				 * Some device drivers do not set page.mapping
				 * but still dirty their pages
				 */
				balance_dirty_pages_ratelimited(mapping);
			}
		}
		del_page_from_coa(old_page);
		return ret;
	}

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	page_cache_get(old_page);
gotten:
	pte_unmap_unlock(page_table, ptl);

	if (unlikely(anon_vma_prepare(vma)))
	  goto oom;

	if (is_zero_pfn(pte_pfn(orig_pte))) {
		new_page = alloc_zeroed_user_highpage_movable(vma, address);
		if (!new_page)
		  goto oom;
	} else {
		new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
		if (!new_page)
		  goto oom;
		cow_user_page(new_page, old_page, address, vma);
	}
	__SetPageUptodate(new_page);
	if (mem_cgroup_newpage_charge(new_page, mm, GFP_KERNEL))
	  goto oom_free_new;
	mmun_start  = address & PAGE_MASK;
	mmun_end    = mmun_start + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);
	/*
	 * Re-check the pte - we dropped the lock
	 */
	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (likely(pte_same(*page_table, orig_pte))) {
		if (old_page) {
			if (!PageAnon(old_page)) {
				dec_mm_counter_fast(mm, MM_FILEPAGES);
				inc_mm_counter_fast(mm, MM_ANONPAGES);
			}
		} else
		  inc_mm_counter_fast(mm, MM_ANONPAGES);
		flush_cache_page(vma, address, pte_pfn(orig_pte));
		entry = mk_pte(new_page, vma->vm_page_prot);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		/*
		 * Clear the pte entry and flush it first, before updating the
		 * pte with the new entry. This will avoid a race condition
		 * seen in the presence of one thread doing SMC and another
		 * thread doing COW.
		 */
		ptep_clear_flush(vma, address, page_table);
		/*
		 * We call the notify macro here because, when using secondary
		 * mmu page tables (such as kvm shadow page tables), we want the
		 * new page to be mapped directly into the secondary page table.
		 */
		page_add_new_anon_rmap(new_page, vma, address);

		set_pte_at_notify(mm, address, page_table, entry);
		update_mmu_cache(vma, address, page_table);
		pte_unmap_unlock(page_table, ptl);


		if (old_page) {
			/*
			 * Only after switching the pte to the new page may
			 * we remove the mapcount here. Otherwise another
			 * process may come and find the rmap count decremented
			 * before the pte is switched to the new page, and
			 * "reuse" the old page writing into it while our pte
			 * here still points into it and can be read by other
			 * threads.
			 *
			 * The critical issue is to order this
			 * page_remove_rmap with the ptp_clear_flush above.
			 * Those stores are ordered by (if nothing else,)
			 * the barrier present in the atomic_add_negative
			 * in page_remove_rmap.
			 *
			 * Then the TLB flush in ptep_clear_flush ensures that
			 * no process can access the old page before the
			 * decremented mapcount is visible. And the old page
			 * cannot be reused until after the decremented
			 * mapcount is visible. So transitively, TLBs to
			 * old page will be flushed before it can be reused.
			 */
			page_remove_rmap(old_page);
			dec_page_counter_in_ns(old_page,vma);
		}
		page_table = pte_offset_map_lock(mm, pmd, address, &ptl);

		/* Free the old page.. */
		new_page = old_page;
		ret |= VM_FAULT_WRITE;
	} else
	  mem_cgroup_uncharge_page(new_page);

	if (new_page)
	  page_cache_release(new_page);
unlock:
	pte_unmap_unlock(page_table, ptl);
after_lock:
	if (mmun_end > mmun_start)
	  mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
	if (old_page) {
		/*
		 * Don't let another task, with possibly unlocked vma,
		 * keep the mlocked page.
		 */
		if ((ret & VM_FAULT_WRITE) && (vma->vm_flags & VM_LOCKED)) {
			lock_page(old_page);	/* LRU manipulation */
			munlock_vma_page(old_page);
			unlock_page(old_page);
		}
		page_cache_release(old_page);
	}
	return ret;
oom_free_new:
	page_cache_release(new_page);
oom:
	if (old_page)
	  page_cache_release(old_page);
	return VM_FAULT_OOM;

unwritable_page:
	page_cache_release(old_page);
	return ret;
}
static void unmap_mapping_range_vma(struct vm_area_struct *vma,
			unsigned long start_addr, unsigned long end_addr,
			struct zap_details *details)
{
	zap_page_range_single(vma, start_addr, end_addr - start_addr, details);
}
static inline void unmap_mapping_range_tree(struct rb_root *root,
			struct zap_details *details)
{
	struct vm_area_struct *vma;
	pgoff_t vba, vea, zba, zea;

	vma_interval_tree_foreach(vma, root,
				details->first_index, details->last_index) {

		vba = vma->vm_pgoff;
		vea = vba + vma_pages(vma) - 1;
		/* Assume for now that PAGE_CACHE_SHIFT == PAGE_SHIFT */
		zba = details->first_index;
		if (zba < vba)
		  zba = vba;
		zea = details->last_index;
		if (zea > vea)
		  zea = vea;

		unmap_mapping_range_vma(vma,
					((zba - vba) << PAGE_SHIFT) + vma->vm_start,
					((zea - vba + 1) << PAGE_SHIFT) + vma->vm_start,
					details);
	}
}
static inline void unmap_mapping_range_list(struct list_head *head,
			struct zap_details *details)
{
	struct vm_area_struct *vma;

	/*
	 * In nonlinear VMAs there is no correspondence between virtual address
	 * offset and file offset.  So we must perform an exhaustive search
	 * across *all* the pages in each nonlinear VMA, not just the pages
	 * whose virtual address lies outside the file truncation point.
	 */
	list_for_each_entry(vma, head, shared.nonlinear) {
		details->nonlinear_vma = vma;
		unmap_mapping_range_vma(vma, vma->vm_start, vma->vm_end, details);
	}
}

/**
 * unmap_mapping_range - unmap the portion of all mmaps in the specified address_space corresponding to the specified page range in the underlying file.
 * @mapping: the address space containing mmaps to be unmapped.
 * @holebegin: byte in first page to unmap, relative to the start of
 * the underlying file.  This will be rounded down to a PAGE_SIZE
 * boundary.  Note that this is different from truncate_pagecache(), which
 * must keep the partial page.  In contrast, we must get rid of
 * partial pages.
 * @holelen: size of prospective hole in bytes.  This will be rounded
 * up to a PAGE_SIZE boundary.  A holelen of zero truncates to the
 * end of the file.
 * @even_cows: 1 when truncating a file, unmap even private COWed pages;
 * but 0 when invalidating pagecache, don't throw away private data.
 */
void unmap_mapping_range(struct address_space *mapping,
			loff_t const holebegin, loff_t const holelen, int even_cows)
{
	struct zap_details details;
	pgoff_t hba = holebegin >> PAGE_SHIFT;
	pgoff_t hlen = (holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* Check for overflow. */
	if (sizeof(holelen) > sizeof(hlen)) {
		long long holeend =
			(holebegin + holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (holeend & ~(long long)ULONG_MAX)
		  hlen = ULONG_MAX - hba + 1;
	}

	details.check_mapping = even_cows? NULL: mapping;
	details.nonlinear_vma = NULL;
	details.first_index = hba;
	details.last_index = hba + hlen - 1;
	if (details.last_index < details.first_index)
	  details.last_index = ULONG_MAX;

	i_mmap_lock_write(mapping);
	if (unlikely(!RB_EMPTY_ROOT(&mapping->i_mmap)))
	  unmap_mapping_range_tree(&mapping->i_mmap, &details);
	if (unlikely(!list_empty(&mapping->i_mmap_nonlinear)))
	  unmap_mapping_range_list(&mapping->i_mmap_nonlinear, &details);

	i_mmap_unlock_write(mapping);
}
EXPORT_SYMBOL(unmap_mapping_range);

/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int do_swap_page(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, pte_t *page_table, pmd_t *pmd,
			unsigned int flags, pte_t orig_pte)
{
	spinlock_t *ptl;
	struct page *page, *swapcache;
	swp_entry_t entry;
	pte_t pte;
	int locked;
	struct mem_cgroup *ptr;
	int exclusive = 0;
	int ret = 0;

	if (!pte_unmap_same(mm, pmd, page_table, orig_pte))
	  goto out;

	entry = pte_to_swp_entry(orig_pte);
	if (unlikely(non_swap_entry(entry))) {
		if (is_migration_entry(entry)) {
			migration_entry_wait(mm, pmd, address);
		} else if (is_hwpoison_entry(entry)) {
			ret = VM_FAULT_HWPOISON;
		} else {
			print_bad_pte(vma, address, orig_pte, NULL);
			ret = VM_FAULT_SIGBUS;
		}
		goto out;
	}
	delayacct_set_flag(DELAYACCT_PF_SWAPIN);
	page = lookup_swap_cache(entry);
	if (!page) {
		page = swapin_readahead(entry,
					GFP_HIGHUSER_MOVABLE, vma, address);
		if (!page) {
			/*
			 * Back out if somebody else faulted in this pte
			 * while we released the pte lock.
			 */
			page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
			if (likely(pte_same(*page_table, orig_pte)))
			{ ret = VM_FAULT_OOM;
				printk("not same pte %lx %lx",page_table->pte,orig_pte.pte);
			}
				delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
			goto unlock;
		}

		/* Had to read the page from swap area: Major fault */
		ret = VM_FAULT_MAJOR;
		count_vm_event(PGMAJFAULT);
		mem_cgroup_count_vm_event(mm, PGMAJFAULT);
	} else if (PageHWPoison(page)) {
		/*
		 * hwpoisoned dirty swapcache pages are kept for killing
		 * owner processes (which may be unknown at hwpoison time)
		 */
		ret = VM_FAULT_HWPOISON;
		delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
		swapcache = page;
		goto out_release;
	}

	swapcache = page;
	locked = lock_page_or_retry(page, mm, flags);

	delayacct_clear_flag(DELAYACCT_PF_SWAPIN);
	if (!locked) {
		ret |= VM_FAULT_RETRY;
		goto out_release;
	}

	/*
	 * Make sure try_to_free_swap or reuse_swap_page or swapoff did not
	 * release the swapcache from under us.  The page pin, and pte_same
	 * test below, are not enough to exclude that.  Even if it is still
	 * swapcache, we need to check that the page's swap has not changed.
	 */
	if (unlikely(!PageSwapCache(page) || page_private(page) != entry.val))
	  goto out_page;

	page = ksm_might_need_to_copy(page, vma, address);
	if (unlikely(!page)) {
		ret = VM_FAULT_OOM;
		printk("swap fault due to !page\n");
		page = swapcache;
		goto out_page;
	}

	if (mem_cgroup_try_charge_swapin(mm, page, GFP_KERNEL, &ptr)) {
		printk("swap fault due to mem_cgroup_try_charge_swapin\n");	
		ret = VM_FAULT_OOM;
		goto out_page;
	}

	/*
	 * Back out if somebody else already faulted in this pte.
	 */
	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (unlikely(!pte_same(*page_table, orig_pte)))
	  goto out_nomap;

	if (unlikely(!PageUptodate(page))) {
		ret = VM_FAULT_SIGBUS;
		goto out_nomap;
	}

	/*
	 * The page isn't present yet, go ahead with the fault.
	 *
	 * Be careful about the sequence of operations here.
	 * To get its accounting right, reuse_swap_page() must be called
	 * while the page is counted on swap but not yet in mapcount i.e.
	 * before page_add_anon_rmap() and swap_free(); try_to_free_swap()
	 * must be called after the swap_free(), or it will never succeed.
	 * Because delete_from_swap_page() may be called by reuse_swap_page(),
	 * mem_cgroup_commit_charge_swapin() may not be able to find swp_entry
	 * in page->private. In this case, a record in swap_cgroup  is silently
	 * discarded at swap_free().
	 */

	inc_mm_counter_fast(mm, MM_ANONPAGES);
	dec_mm_counter_fast(mm, MM_SWAPENTS);
	pte = mk_pte(page, vma->vm_page_prot);
	if ((flags & FAULT_FLAG_WRITE) && reuse_swap_page(page)) {
		pte = maybe_mkwrite(pte_mkdirty(pte), vma);
		flags &= ~FAULT_FLAG_WRITE;
		ret |= VM_FAULT_WRITE;
		exclusive = 1;
	}
	flush_icache_page(vma, page);
	if (pte_swp_soft_dirty(orig_pte))
	  pte = pte_mksoft_dirty(pte);
	set_pte_at(mm, address, page_table, pte);
	pte_unmap_unlock(page_table, ptl);

	if (page == swapcache)
	  do_page_add_anon_rmap(page, vma, address, exclusive);
	else /* ksm created a completely new copy */
	  page_add_new_anon_rmap(page, vma, address);
	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);

	/* It's better to call commit-charge after rmap is established */
	mem_cgroup_commit_charge_swapin(page, ptr);

	swap_free(entry);
	if (vm_swap_full() || (vma->vm_flags & VM_LOCKED) || PageMlocked(page))
	  try_to_free_swap(page);
	unlock_page(page);
	if (page != swapcache) {
		/*
		 * Hold the lock to avoid the swap entry to be reused
		 * until we take the PT lock for the pte_same() check
		 * (to avoid false positives from pte_same). For
		 * further safety release the lock after the swap_free
		 * so that the swap count won't change under a
		 * parallel locked swapcache.
		 */
		unlock_page(swapcache);
		page_cache_release(swapcache);
	}

	if (flags & FAULT_FLAG_WRITE) {
		ret |= do_wp_page(mm, vma, address, page_table, pmd, ptl, pte);
		if (ret & VM_FAULT_ERROR)
		  ret &= VM_FAULT_ERROR;
		goto out;
	}

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, address, page_table);
unlock:
	pte_unmap_unlock(page_table, ptl);
out:
	return ret;
out_nomap:
	mem_cgroup_cancel_charge_swapin(ptr);
	pte_unmap_unlock(page_table, ptl);
out_page:
	unlock_page(page);
out_release:
	page_cache_release(page);
	if (page != swapcache) {
		unlock_page(swapcache);
		page_cache_release(swapcache);
	}
	return ret;
}

/*
 * This is like a special single-page "expand_{down|up}wards()",
 * except we must first make sure that 'address{-|+}PAGE_SIZE'
 * doesn't hit another vma.
 */
static inline int check_stack_guard_page(struct vm_area_struct *vma, unsigned long address)
{
	address &= PAGE_MASK;
	if ((vma->vm_flags & VM_GROWSDOWN) && address == vma->vm_start) {
		struct vm_area_struct *prev = vma->vm_prev;

		/*
		 * Is there a mapping abutting this one below?
		 *
		 * That's only ok if it's the same stack mapping
		 * that has gotten split..
		 */
		if (prev && prev->vm_end == address)
		  return prev->vm_flags & VM_GROWSDOWN ? 0 : -ENOMEM;

		expand_downwards(vma, address - PAGE_SIZE);
	}
	if ((vma->vm_flags & VM_GROWSUP) && address + PAGE_SIZE == vma->vm_end) {
		struct vm_area_struct *next = vma->vm_next;

		/* As VM_GROWSDOWN but s/below/above/ */
		if (next && next->vm_start == address + PAGE_SIZE)
		  return next->vm_flags & VM_GROWSUP ? 0 : -ENOMEM;

		expand_upwards(vma, address + PAGE_SIZE);
	}
	return 0;
}

/*
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int do_anonymous_page(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, pte_t *page_table, pmd_t *pmd,
			unsigned int flags)
{
	struct page *page;
	spinlock_t *ptl;
	pte_t entry;

	pte_unmap(page_table);

	/* Check if we need to add a guard page to the stack */
	if (check_stack_guard_page(vma, address) < 0)
	  return VM_FAULT_SIGBUS;

	/* Use the zero-page for reads */
	if (!(flags & FAULT_FLAG_WRITE)) {
		entry = pte_mkspecial(pfn_pte(my_zero_pfn(address),
						vma->vm_page_prot));
		page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
		if (!pte_none(*page_table))
		  goto unlock;
		goto setpte;
	}

	/* Allocate our own private page. */
	if (unlikely(anon_vma_prepare(vma)))
	  goto oom;
	page = alloc_zeroed_user_highpage_movable(vma, address);
	if (!page)
	  goto oom;
	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceeding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
	__SetPageUptodate(page);

	if (mem_cgroup_newpage_charge(page, mm, GFP_KERNEL))
	  goto oom_free_page;

	entry = mk_pte(page, vma->vm_page_prot);
	if (vma->vm_flags & VM_WRITE)
	  entry = pte_mkwrite(pte_mkdirty(entry));

	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (!pte_none(*page_table))
	  goto release;

	inc_mm_counter_fast(mm, MM_ANONPAGES);
	set_pte_at(mm, address, page_table, entry);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, address, page_table);
	pte_unmap_unlock(page_table, ptl);
	page_add_new_anon_rmap(page, vma, address);
	return 0;

setpte:
	set_pte_at(mm, address, page_table, entry);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, address, page_table);

unlock:
/*
		if(flags&FAULT_FLAG_RSVD){
	//		//printk("FAULT_FLAG_RSVD,lock=%lx\n",ptl);
	//page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
	return handle_double_cache_pte_fault(mm, vma, address,
	page_table, pmd, ptl, entry,false);
	}
*/
	pte_unmap_unlock(page_table, ptl);
	return 0;
release:
	mem_cgroup_uncharge_page(page);
	page_cache_release(page);
	goto unlock;
oom_free_page:
	page_cache_release(page);
oom:
	return VM_FAULT_OOM;
}

/*
 * __do_fault() tries to create a new page mapping. It aggressively
 * tries to share with existing pages, but makes a separate copy if
 * the FAULT_FLAG_WRITE is set in the flags parameter in order to avoid
 * the next page fault.
 *
 * As this is called only for pages that do not currently exist, we
 * do not need to flush old virtual caches or the TLB.
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte neither mapped nor locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int __do_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, pmd_t *pmd,
			pgoff_t pgoff, unsigned int flags, pte_t orig_pte)
{
	pte_t *page_table;
	spinlock_t *ptl;
	struct page *page;
	struct page *cow_page;
	pte_t entry;
	int anon = 0;
	struct page *dirty_page = NULL;
	struct vm_fault vmf;
	int ret;
	int page_mkwrite = 0;

	/*
	 * If we do COW later, allocate page befor taking lock_page()
	 * on the file cache page. This will reduce lock holding time.
	 */
	if ((flags & FAULT_FLAG_WRITE) && !(vma->vm_flags & VM_SHARED)) {

		if (unlikely(anon_vma_prepare(vma)))
		  return VM_FAULT_OOM;

		cow_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
		if (!cow_page)
		  return VM_FAULT_OOM;

		if (mem_cgroup_newpage_charge(cow_page, mm, GFP_KERNEL)) {
			page_cache_release(cow_page);
			return VM_FAULT_OOM;
		}
	} else
	  cow_page = NULL;

	vmf.virtual_address = (void __user *)(address & PAGE_MASK);
	vmf.pgoff = pgoff;
	vmf.flags = flags;
	vmf.page = NULL;

	ret = vma->vm_ops->fault(vma, &vmf);
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE |
						VM_FAULT_RETRY)))
	  goto uncharge_out;

	if (unlikely(PageHWPoison(vmf.page))) {
		if (ret & VM_FAULT_LOCKED)
		  unlock_page(vmf.page);
		ret = VM_FAULT_HWPOISON;
		goto uncharge_out;
	}

	/*
	 * For consistency in subsequent calls, make the faulted page always
	 * locked.
	 */
	if (unlikely(!(ret & VM_FAULT_LOCKED)))
	  lock_page(vmf.page);
	else
	  VM_BUG_ON(!PageLocked(vmf.page));

	page = vmf.page;

	/* Mark the page as used on fault. */
	if (PageReadaheadUnused(page))
	  ClearPageReadaheadUnused(page);

	/*
	 * Should we do an early C-O-W break?
	 */
	if (flags & FAULT_FLAG_WRITE) {
		if (!(vma->vm_flags & VM_SHARED)) {
			page = cow_page;
			anon = 1;
			copy_user_highpage(page, vmf.page, address, vma);
			__SetPageUptodate(page);
		} else {
			/*
			 * If the page will be shareable, see if the backing
			 * address space wants to know that the page is about
			 * to become writable
			 */
			if (vma->vm_ops->page_mkwrite) {
				int tmp;

				unlock_page(page);
				vmf.flags = FAULT_FLAG_WRITE|FAULT_FLAG_MKWRITE;
				tmp = vma->vm_ops->page_mkwrite(vma, &vmf);
				if (unlikely(tmp &
								(VM_FAULT_ERROR | VM_FAULT_NOPAGE))) {
					ret = tmp;
					goto unwritable_page;
				}
				if (unlikely(!(tmp & VM_FAULT_LOCKED))) {
					lock_page(page);
					if (!page->mapping) {
						ret = 0; /* retry the fault */
						unlock_page(page);
						goto unwritable_page;
					}
				} else
				  VM_BUG_ON(!PageLocked(page));
				page_mkwrite = 1;
			}
		}

	}

	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);

	/*
	 * This silly early PAGE_DIRTY setting removes a race
	 * due to the bad i386 page protection. But it's valid
	 * for other architectures too.
	 *
	 * Note that if FAULT_FLAG_WRITE is set, we either now have
	 * an exclusive copy of the page, or this is a shared mapping,
	 * so we can make it writable and dirty to avoid having to
	 * handle that later.
	 */
	/* Only go through if we didn't race with anybody else... */
	if (likely(pte_same(*page_table, orig_pte))) {
		flush_icache_page(vma, page);
		entry = mk_pte(page, vma->vm_page_prot);
		if (flags & FAULT_FLAG_WRITE)
		  entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		else if (pte_file(orig_pte) && pte_file_soft_dirty(orig_pte))
		  pte_mksoft_dirty(entry);
		set_pte_at(mm, address, page_table, entry);

		/* no need to invalidate: a not-present page won't be cached */
		update_mmu_cache(vma, address, page_table);
		pte_unmap_unlock(page_table, ptl);

		if (anon) {
			inc_mm_counter_fast(mm, MM_ANONPAGES);
			page_add_new_anon_rmap(page, vma, address);
		} else {
			inc_mm_counter_fast(mm, MM_FILEPAGES);
			page_add_file_rmap(page);
			inc_page_counter_in_ns(page,vma);
			if (flags & FAULT_FLAG_WRITE) {
				dirty_page = page;
				get_page(dirty_page);
			}
		}
		//	set_pte_at(mm, address, page_table, entry);

		/* no need to invalidate: a not-present page won't be cached */
		//	update_mmu_cache(vma, address, page_table);
	} else {
		if (cow_page)
		  mem_cgroup_uncharge_page(cow_page);
		if (anon)
		  page_cache_release(page);
		else
		  anon = 1; /* no anon but release faulted_page */
		pte_unmap_unlock(page_table, ptl);

	}

	//pte_unmap_unlock(page_table, ptl);

	if (dirty_page) {
		struct address_space *mapping = page->mapping;
		int dirtied = 0;

		if (set_page_dirty(dirty_page))
		  dirtied = 1;
		unlock_page(dirty_page);
		put_page(dirty_page);
		if ((dirtied || page_mkwrite) && mapping) {
			/*
			 * Some device drivers do not set page.mapping but still
			 * dirty their pages
			 */
			balance_dirty_pages_ratelimited(mapping);
		}

		/* file_update_time outside page_lock */
		if (vma->vm_file && !page_mkwrite)
		  vma_file_update_time(vma);
	} else {
		unlock_page(vmf.page);
		if (anon)
		  page_cache_release(vmf.page);
	}
	/*	if(flags&FAULT_FLAG_RSVD){
	//		//printk("FAULT_FLAG_RSVD,lock=%lx\n",ptl);
	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
	return ret|handle_double_cache_pte_fault(mm, vma, address,
	page_table, pmd, ptl, entry,false);
	}
*/
	return ret;

unwritable_page:
	page_cache_release(page);
	return ret;
uncharge_out:
	/* fs's fault handler get error */
	if (cow_page) {
		mem_cgroup_uncharge_page(cow_page);
		page_cache_release(cow_page);
	}
	return ret;
}

static int do_linear_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, pte_t *page_table, pmd_t *pmd,
			unsigned int flags, pte_t orig_pte)
{
	pgoff_t pgoff = (((address & PAGE_MASK)
					- vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;

	pte_unmap(page_table);
	return __do_fault(mm, vma, address, pmd, pgoff, flags, orig_pte);
}

/*
 * Fault of a previously existing named mapping. Repopulate the pte
 * from the encoded file_pte if possible. This enables swappable
 * nonlinear vmas.
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int do_nonlinear_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, pte_t *page_table, pmd_t *pmd,
			unsigned int flags, pte_t orig_pte)
{
	pgoff_t pgoff;

	flags |= FAULT_FLAG_NONLINEAR;

	if (!pte_unmap_same(mm, pmd, page_table, orig_pte))
	  return 0;

	if (unlikely(!(vma->vm_flags & VM_NONLINEAR))) {
		/*
		 * Page table corrupted: show pte and kill process.
		 */
		print_bad_pte(vma, address, orig_pte, NULL);
		return VM_FAULT_SIGBUS;
	}

	pgoff = pte_to_pgoff(orig_pte);
	return __do_fault(mm, vma, address, pmd, pgoff, flags, orig_pte);
}

int numa_migrate_prep(struct page *page, struct vm_area_struct *vma,
			unsigned long addr, int page_nid,
			int *flags)
{
	get_page(page);

	count_vm_numa_event(NUMA_HINT_FAULTS);
	if (page_nid == numa_node_id()) {
		count_vm_numa_event(NUMA_HINT_FAULTS_LOCAL);
		*flags |= TNF_FAULT_LOCAL;
	}

	return mpol_misplaced(page, vma, addr);
}

int do_numa_page(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long addr, pte_t pte, pte_t *ptep, pmd_t *pmd)
{
	struct page *page = NULL;
	spinlock_t *ptl;
	int page_nid = -1;
	int last_cpupid;
	int target_nid;
	bool migrated = false;
	int flags = 0;

	/*
	 * The "pte" at this point cannot be used safely without
	 * validation through pte_unmap_same(). It's of NUMA type but
	 * the pfn may be screwed if the read is non atomic.
	 *
	 * ptep_modify_prot_start is not called as this is clearing
	 * the _PAGE_NUMA bit and it is not really expected that there
	 * would be concurrent hardware modifications to the PTE.
	 */
	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (unlikely(!pte_same(*ptep, pte))) {
		pte_unmap_unlock(ptep, ptl);
		goto out;
	}

	pte = pte_mknonnuma(pte);
	set_pte_at(mm, addr, ptep, pte);
	update_mmu_cache(vma, addr, ptep);

	page = vm_normal_page(vma, addr, pte);
	if (!page) {
		pte_unmap_unlock(ptep, ptl);
		return 0;
	}
	BUG_ON(is_zero_pfn(page_to_pfn(page)));

	/*
	 * Avoid grouping on DSO/COW pages in specific and RO pages
	 * in general, RO pages shouldn't hurt as much anyway since
	 * they can be in shared cache state.
	 */
	if (!pte_write(pte))
	  flags |= TNF_NO_GROUP;

	/*
	 * Flag if the page is shared between multiple address spaces. This
	 * is later used when determining whether to group tasks together
	 */
	if (page_mapcount(page) > 1 && (vma->vm_flags & VM_SHARED))
	  flags |= TNF_SHARED;

	last_cpupid = page_cpupid_last(page);
	page_nid = page_to_nid(page);
	target_nid = numa_migrate_prep(page, vma, addr, page_nid, &flags);
	pte_unmap_unlock(ptep, ptl);
	if (target_nid == -1) {
		put_page(page);
		goto out;
	}

	/* Migrate to the requested node */
	migrated = migrate_misplaced_page(page, vma, target_nid);
	if (migrated) {
		page_nid = target_nid;
		flags |= TNF_MIGRATED;
	}

out:
	if (page_nid != -1)
	  task_numa_fault(last_cpupid, page_nid, 1, flags);
	/*if(flags&FAULT_FLAG_RSVD){
		//		//printk("FAULT_FLAG_RSVD,lock=%lx\n",ptl);
		ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
		return handle_double_cache_pte_fault(mm, vma, addr,
				ptep, pmd, ptl, pte,true);
	}*/

	return 0;
}
/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int handle_pte_fault(struct mm_struct *mm,
			struct vm_area_struct *vma, unsigned long address,
			pte_t *pte, pmd_t *pmd, unsigned int flags)
{
	pte_t entry;
	spinlock_t *ptl;
	entry = *pte;
	int ret=0;
	if (!pte_present(entry)) {
		if (pte_none(entry)) {
			if (vma->vm_ops) {
				if (likely(vma->vm_ops->fault))
				{  ret= do_linear_fault(mm, vma, address,
							pte, pmd, flags, entry);
				if(ret&VM_FAULT_OOM)  
				  printk("bad in do_linear_fault");
				return ret;
				}
			}
			ret= do_anonymous_page(mm, vma, address,
						pte, pmd, flags);
			if(ret&VM_FAULT_OOM)  
			  printk("bad in do_anon_fault");  
			return ret;	

		}
		if (pte_file(entry)){
			ret= do_nonlinear_fault(mm, vma, address,
						pte, pmd, flags, entry);
			if(ret&VM_FAULT_OOM)	
			  printk("bad in do_non_linear_fault");
			return ret;
		}
		ret= do_swap_page(mm, vma, address,
					pte, pmd, flags, entry);
		if(ret&VM_FAULT_OOM)  
		{ printk("bad in do_swap_fault");

		}
		return ret;
	}
	if (pte_numa(entry))
	{ ret=do_numa_page(mm, vma, address, entry, pte, pmd);
		if(ret&VM_FAULT_OOM)  
		  printk("bad in do_numa_fault");
		return ret;
	}
	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (unlikely(!pte_same(*pte, entry)))
	  goto unlock;
	if (flags & FAULT_FLAG_WRITE) {
		if (!pte_write(entry))
		{
			ret= do_wp_page(mm, vma, address,
						pte, pmd, ptl, entry);
			if(ret&VM_FAULT_OOM)	
			  printk("bad in do_wp_fault");
			return ret;
		}
		entry = pte_mkdirty(entry);
	}
	if(flags&FAULT_FLAG_RSVD){
		//		//printk("FAULT_FLAG_RSVD,lock=%lx\n",ptl);
		return handle_double_cache_pte_fault(mm, vma, address,
					pte, pmd, ptl, entry,true);
	}
	entry = pte_mkyoung(entry);
	if (ptep_set_access_flags(vma, address, pte, entry, flags & FAULT_FLAG_WRITE)) {
		update_mmu_cache(vma, address, pte);
	} else {
		/*
		 * This is needed only for protection faults but the arch code
		 * is not yet telling us if this is a protection fault or not.
		 * This still avoids useless tlb flushes for .text page faults
		 * with threads.
		 */
		if (flags & FAULT_FLAG_WRITE)
		  flush_tlb_fix_spurious_fault(vma, address);
	}
unlock:
	pte_unmap_unlock(pte, ptl);
	//printk("unlock at handle_pte\n");
	return 0;
}

/*
 * By the time we get here, we already hold the mm semaphore
 */
static int __handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, unsigned int flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (unlikely(is_vm_hugetlb_page(vma)))
	  return hugetlb_fault(mm, vma, address, flags);

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
	  return VM_FAULT_OOM;
	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
	  return VM_FAULT_OOM;
	if (pmd_none(*pmd) && transparent_hugepage_enabled(vma)) {
		int ret = VM_FAULT_FALLBACK;
		if (!vma->vm_ops)
		  ret = do_huge_pmd_anonymous_page(mm, vma, address,
					  pmd, flags);
		if (!(ret & VM_FAULT_FALLBACK))
		  return ret;
	} else {
		pmd_t orig_pmd = *pmd;
		int ret;

		barrier();
		if (pmd_trans_huge(orig_pmd)) {
			unsigned int dirty = flags & FAULT_FLAG_WRITE;

			/*
			 * If the pmd is splitting, return and retry the
			 * the fault.  Alternative: wait until the split
			 * is done, and goto retry.
			 */
			if (pmd_trans_splitting(orig_pmd))
			  return 0;

			if (pmd_numa(orig_pmd))
			  return do_huge_pmd_numa_page(mm, vma, address,
						  orig_pmd, pmd);

			if (dirty && !pmd_write(orig_pmd)) {
				ret = do_huge_pmd_wp_page(mm, vma, address, pmd,
							orig_pmd);
				if (!(ret & VM_FAULT_FALLBACK))
				  return ret;
			} else {
				huge_pmd_set_accessed(mm, vma, address, pmd,
							orig_pmd, dirty);
				return 0;
			}
		}
	}

	/*
	 * Use __pte_alloc instead of pte_alloc_map, because we can't
	 * run pte_offset_map on the pmd, if an huge pmd could
	 * materialize from under us from a different thread.
	 */
	if (unlikely(pmd_none(*pmd)) &&
				unlikely(__pte_alloc(mm, vma, pmd, address)))
	  return VM_FAULT_OOM;
	/* if an huge pmd materialized from under us just retry later */
	if (unlikely(pmd_trans_huge(*pmd)))
	  return 0;
	/*
	 * A regular pmd is established and it can't morph into a huge pmd
	 * from under us anymore at this point because we hold the mmap_sem
	 * read mode and khugepaged takes it in write mode. So now it's
	 * safe to run pte_offset_map().
	 */
	pte = pte_offset_map(pmd, address);
	return handle_pte_fault(mm, vma, address, pte, pmd, flags);
}

int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long address, unsigned int flags)
{
	int ret;

	__set_current_state(TASK_RUNNING);

	count_vm_event(PGFAULT);
	mem_cgroup_count_vm_event(mm, PGFAULT);

	/* do counter updates before entering really critical section. */
	check_sync_rss_stat(current);

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
	  mem_cgroup_oom_enable();

	ret = __handle_mm_fault(mm, vma, address, flags);

	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_oom_disable();
		/*
		 * The task may have entered a memcg OOM situation but
		 * if the allocation error was handled gracefully (no
		 * VM_FAULT_OOM), there is no need to kill anything.
		 * Just clean up the OOM state peacefully.
		 */
		if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
		  mem_cgroup_oom_synchronize(false);
	}

	return ret;
}

#ifndef __PAGETABLE_PUD_FOLDED
/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
	  return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
	  pud_free(mm, new);
	else
	  pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}
#endif /* __PAGETABLE_PUD_FOLDED */

#ifndef __PAGETABLE_PMD_FOLDED
/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = pmd_alloc_one(mm, address);
	if (!new)
	  return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
#ifndef __ARCH_HAS_4LEVEL_HACK
	if (pud_present(*pud))		/* Another has populated it */
	  pmd_free(mm, new);
	else
	  pud_populate(mm, pud, new);
#else
	if (pgd_present(*pud))		/* Another has populated it */
	  pmd_free(mm, new);
	else
	  pgd_populate(mm, pud, new);
#endif /* __ARCH_HAS_4LEVEL_HACK */
	spin_unlock(&mm->page_table_lock);
	return 0;
}
#endif /* __PAGETABLE_PMD_FOLDED */

#if !defined(__HAVE_ARCH_GATE_AREA)

#if defined(AT_SYSINFO_EHDR)
static struct vm_area_struct gate_vma;

static int __init gate_vma_init(void)
{
	gate_vma.vm_mm = NULL;
	gate_vma.vm_start = FIXADDR_USER_START;
	gate_vma.vm_end = FIXADDR_USER_END;
	gate_vma.vm_flags = VM_READ | VM_MAYREAD | VM_EXEC | VM_MAYEXEC;
	gate_vma.vm_page_prot = __P101;

	return 0;
}
__initcall(gate_vma_init);
#endif

struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
#ifdef AT_SYSINFO_EHDR
	return &gate_vma;
#else
	return NULL;
#endif
}

int in_gate_area_no_mm(unsigned long addr)
{
#ifdef AT_SYSINFO_EHDR
	if ((addr >= FIXADDR_USER_START) && (addr < FIXADDR_USER_END))
	  return 1;
#endif
	return 0;
}

#endif	/* __HAVE_ARCH_GATE_AREA */

static int __follow_pte(struct mm_struct *mm, unsigned long address,
			pte_t **ptepp, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
	  goto out;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
	  goto out;

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
	  goto out;

	/* We cannot handle huge page PFN maps. Luckily they don't exist. */
	if (pmd_huge(*pmd))
	  goto out;

	ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!ptep)
	  goto out;
	if (!pte_present(*ptep))
	  goto unlock;
	*ptepp = ptep;
	return 0;
unlock:
	pte_unmap_unlock(ptep, *ptlp);
out:
	return -EINVAL;
}

static inline int follow_pte(struct mm_struct *mm, unsigned long address,
			pte_t **ptepp, spinlock_t **ptlp)
{
	int res;

	/* (void) is needed to make gcc happy */
	(void) __cond_lock(*ptlp,
				!(res = __follow_pte(mm, address, ptepp, ptlp)));
	return res;
}

/**
 * follow_pfn - look up PFN at a user virtual address
 * @vma: memory mapping
 * @address: user virtual address
 * @pfn: location to store found PFN
 *
 * Only IO mappings and raw PFN mappings are allowed.
 *
 * Returns zero and the pfn at @pfn on success, -ve otherwise.
 */
int follow_pfn(struct vm_area_struct *vma, unsigned long address,
			unsigned long *pfn)
{
	int ret = -EINVAL;
	spinlock_t *ptl;
	pte_t *ptep;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))
	  return ret;

	ret = follow_pte(vma->vm_mm, address, &ptep, &ptl);
	if (ret)
	  return ret;
	*pfn = pte_pfn(*ptep);
	pte_unmap_unlock(ptep, ptl);
	return 0;
}
EXPORT_SYMBOL(follow_pfn);

#ifdef CONFIG_HAVE_IOREMAP_PROT
int follow_phys(struct vm_area_struct *vma,
			unsigned long address, unsigned int flags,
			unsigned long *prot, resource_size_t *phys)
{
	int ret = -EINVAL;
	pte_t *ptep, pte;
	spinlock_t *ptl;

	if (!(vma->vm_flags & (VM_IO | VM_PFNMAP)))
	  goto out;

	if (follow_pte(vma->vm_mm, address, &ptep, &ptl))
	  goto out;
	pte = *ptep;

	if ((flags & FOLL_WRITE) && !pte_write(pte))
	  goto unlock;

	*prot = pgprot_val(pte_pgprot(pte));
	*phys = (resource_size_t)pte_pfn(pte) << PAGE_SHIFT;

	ret = 0;
unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return ret;
}

int generic_access_phys(struct vm_area_struct *vma, unsigned long addr,
			void *buf, int len, int write)
{
	resource_size_t phys_addr;
	unsigned long prot = 0;
	void __iomem *maddr;
	int offset = addr & (PAGE_SIZE-1);

	if (follow_phys(vma, addr, write, &prot, &phys_addr))
	  return -EINVAL;

	maddr = ioremap_prot(phys_addr, PAGE_SIZE, prot);
	if (write)
	  memcpy_toio(maddr + offset, buf, len);
	else
	  memcpy_fromio(buf, maddr + offset, len);
	iounmap(maddr);

	return len;
}
EXPORT_SYMBOL_GPL(generic_access_phys);
#endif

/*
 * Access another process' address space as given in mm.  If non-NULL, use the
 * given task for page fault accounting.
 */
static int __access_remote_vm(struct task_struct *tsk, struct mm_struct *mm,
			unsigned long addr, void *buf, int len, int write)
{
	struct vm_area_struct *vma;
	void *old_buf = buf;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages(tsk, mm, addr, 1,
					write, 1, &page, &vma);
		if (ret <= 0) {
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
#ifdef CONFIG_HAVE_IOREMAP_PROT
			vma = find_vma(mm, addr);
			if (!vma || vma->vm_start > addr)
			  break;
			if (vma->vm_ops && vma->vm_ops->access)
			  ret = vma->vm_ops->access(vma, addr, buf,
						  len, write);
			if (ret <= 0)
#endif
			  break;
			bytes = ret;
		} else {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
			  bytes = PAGE_SIZE-offset;

			maddr = kmap(page);
			if (write) {
				copy_to_user_page(vma, page, addr,
							maddr + offset, buf, bytes);
				set_page_dirty_lock(page);
			} else {
				copy_from_user_page(vma, page, addr,
							buf, maddr + offset, bytes);
			}
			kunmap(page);
			page_cache_release(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);

	return buf - old_buf;
}

/**
 * access_remote_vm - access another process' address space
 * @mm:		the mm_struct of the target address space
 * @addr:	start address to access
 * @buf:	source or destination buffer
 * @len:	number of bytes to transfer
 * @write:	whether the access is a write
 *
 * The caller must hold a reference on @mm.
 */
int access_remote_vm(struct mm_struct *mm, unsigned long addr,
			void *buf, int len, int write)
{
	return __access_remote_vm(NULL, mm, addr, buf, len, write);
}

/*
 * Access another process' address space.
 * Source/target buffer must be kernel space,
 * Do not walk the page table directly, use get_user_pages
 */
int access_process_vm(struct task_struct *tsk, unsigned long addr,
			void *buf, int len, int write)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
	  return 0;

	ret = __access_remote_vm(tsk, mm, addr, buf, len, write);
	mmput(mm);

	return ret;
}

/*
 * Print the name of a VMA.
 */
void print_vma_addr(char *prefix, unsigned long ip)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	/*
	 * Do not print if we are in atomic
	 * contexts (in exception stacks, etc.):
	 */
	if (preempt_count())
	return;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, ip);
	if (vma && vma->vm_file) {
		struct file *f = vma->vm_file;
		char *buf = (char *)__get_free_page(GFP_KERNEL);
		if (buf) {
			char *p;

			p = d_path(&f->f_path, buf, PAGE_SIZE);
			if (IS_ERR(p))
			  p = "?";
			printk(KERN_DEBUG"%s%s[%lx+%lx]", prefix, kbasename(p),
						vma->vm_start,
						vma->vm_end - vma->vm_start);
			free_page((unsigned long)buf);
		}
	}
	up_read(&mm->mmap_sem);
}

#if defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_DEBUG_ATOMIC_SLEEP)
void might_fault(void)
{
	/*
	 * Some code (nfs/sunrpc) uses socket ops on kernel memory while
	 * holding the mmap_sem, this is safe because kernel memory doesn't
	 * get paged out, therefore we'll never actually fault, and the
	 * below annotations will generate false positives.
	 */
	if (segment_eq(get_fs(), KERNEL_DS))
	  return;

	/*
	 * it would be nicer only to annotate paths which are not under
	 * pagefault_disable, however that requires a larger audit and
	 * providing helpers like get_user_atomic.
	 */
	if (in_atomic())
	  return;

	__might_sleep(__FILE__, __LINE__, 0);

	if (current->mm)
	  might_lock_read(&current->mm->mmap_sem);
}
EXPORT_SYMBOL(might_fault);
#endif

#if defined(CONFIG_TRANSPARENT_HUGEPAGE) || defined(CONFIG_HUGETLBFS)
static void clear_gigantic_page(struct page *page,
			unsigned long addr,
			unsigned int pages_per_huge_page)
{
	int i;
	struct page *p = page;

	might_sleep();
	for (i = 0; i < pages_per_huge_page;
				i++, p = mem_map_next(p, page, i)) {
		cond_resched();
		clear_user_highpage(p, addr + i * PAGE_SIZE);
	}
}
void clear_huge_page(struct page *page,
			unsigned long addr, unsigned int pages_per_huge_page)
{
	int i;

	if (unlikely(pages_per_huge_page > MAX_ORDER_NR_PAGES)) {
		clear_gigantic_page(page, addr, pages_per_huge_page);
		return;
	}

	might_sleep();
	for (i = 0; i < pages_per_huge_page; i++) {
		cond_resched();
		clear_user_highpage(page + i, addr + i * PAGE_SIZE);
	}
}

static void copy_user_gigantic_page(struct page *dst, struct page *src,
			unsigned long addr,
			struct vm_area_struct *vma,
			unsigned int pages_per_huge_page)
{
	int i;
	struct page *dst_base = dst;
	struct page *src_base = src;

	for (i = 0; i < pages_per_huge_page; ) {
		cond_resched();
		copy_user_highpage(dst, src, addr + i*PAGE_SIZE, vma);

		i++;
		dst = mem_map_next(dst, dst_base, i);
		src = mem_map_next(src, src_base, i);
	}
}

void copy_user_huge_page(struct page *dst, struct page *src,
			unsigned long addr, struct vm_area_struct *vma,
			unsigned int pages_per_huge_page)
{
	int i;

	if (unlikely(pages_per_huge_page > MAX_ORDER_NR_PAGES)) {
		copy_user_gigantic_page(dst, src, addr, vma,
					pages_per_huge_page);
		return;
	}

	might_sleep();
	for (i = 0; i < pages_per_huge_page; i++) {
		cond_resched();
		copy_user_highpage(dst + i, src + i, addr + i*PAGE_SIZE, vma);
	}
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE || CONFIG_HUGETLBFS */

#if USE_SPLIT_PTE_PTLOCKS && ALLOC_SPLIT_PTLOCKS
bool ptlock_alloc(struct page *page)
{
	spinlock_t *ptl;

	ptl = kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	if (!ptl)
	  return false;
	page->ptl = ptl;
	return true;
}

void ptlock_free(struct page *page)
{
	kfree(page->ptl);
}
#endif
long pte_to_physical(pte_t * pte,long address){
	return ((pte_val(*pte)&PAGE_MASK)|(address &~PAGE_MASK));
}
static struct kmem_cache* sclock_coa_children_cachep;
static struct kmem_cache* sclock_coa_parent_cachep;
void  coa_cache_init(void){
	sclock_coa_children_cachep=kmem_cache_create("sclock_coa_children_cachep", sizeof(struct sclock_coa_children), ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
	sclock_coa_parent_cachep=kmem_cache_create("sclock_coa_parent_cachep", sizeof(struct sclock_coa_parent), ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
}
struct sclock_coa_parent* init_coa_parent(struct page* page){
	struct sclock_coa_parent* coa_parent=kmem_cache_alloc(sclock_coa_parent_cachep,GFP_KERNEL);
	if(coa_parent==NULL)
	  return NULL;
	mutex_init(&coa_parent->lock);

	coa_parent->pfn=page_to_pfn(page);
	init_copy_num(coa_parent);
	coa_parent->parent_head=NULL;
	coa_parent->owner=NULL;
	INIT_LIST_HEAD(&coa_parent->head);
	page->coa_head=&coa_parent->head;
	//	printk("add one parent into list\n");
	list_add_tail(&coa_parent->node,parent_page_headp);
	return coa_parent;
}
void coa_parent_free(struct sclock_coa_parent *coa_parent){
	kmem_cache_free(sclock_coa_parent_cachep,coa_parent);

}
void coa_children_free(struct sclock_coa_children *coa_children){
	kmem_cache_free(sclock_coa_children_cachep,coa_children);
}


int compare_sclock_owner(void* priv,struct list_head* a,struct list_head* b){
	struct sclock_coa_children* a_entry,* b_entry;
	unsigned long a_count,b_count;
	a_entry=list_entry(a,struct sclock_coa_children,head);
	b_entry=list_entry(b,struct sclock_coa_children,head);
	a_count=a_entry->owner;
	b_count=b_entry->owner;
	if(a_count<b_count)
	  return -1;
	if(a_count==b_count)
	  return 0;
	return 1;
}
static int	add_page_into_children_pages(struct sclock_coa_parent* coa_parent,struct page* page,struct pid_namespace *pid_ns){
	//	if(sclock_coa_children_cachep==NULL)
	//	struct sclock_coa_children* coa_children=kmalloc(sclock_coa_children_cachep,GFP_KERNEL);
	struct sclock_coa_children*	coa_children=kmem_cache_alloc(sclock_coa_children_cachep,GFP_KERNEL);
	struct page* source;
	unsigned long flags;
	if(coa_children==NULL)
	  return -1;
	//printk("add one copy, page=%lx,index=%lx\n",page,page->index);
	coa_children->pfn=page_to_pfn(page);
	coa_children->parent_head=&coa_parent->head;
	coa_children->owner=pid_ns;
	page->coa_head=&(coa_children->head);
	source =pfn_to_page(coa_parent->pfn);
	//	printk("add one copy %lx: %d,%dfor %lx->count%d,mapcount%d in process %s pid=%d\n",coa_children->pfn,atomic_read(&page->_count),page_mapcount(page),page_to_pfn(source),atomic_read(&source->_count),page_mapcount(source),current->comm,current->pid);
	coa_list_lock(coa_parent);
	if(get_copy_num(coa_parent)>=0)	
	  inc_copy_num(coa_parent);
	else{
		set_copy_num(1,coa_parent);
	}
	list_add_tail(&coa_children->head,&coa_parent->head);
	coa_list_unlock(coa_parent);
	//	list_sort(NULL,&coa_parent->head,compare_sclock_owner);
	return 0;
}
static int memcmp_pages(struct page *page1, struct page *page2)
{
	char *addr1, *addr2;
	int ret;

	addr1 = kmap_atomic(page1);
	addr2 = kmap_atomic(page2);
	ret = memcmp(addr1, addr2, PAGE_SIZE);
	kunmap_atomic(addr2);
	kunmap_atomic(addr1);
	return ret;
}

static inline int pages_identical(struct page *page1, struct page *page2)
{
	return !memcmp_pages(page1, page2);
}


struct sclock_coa_parent *get_original(struct sclock_coa_parent *coa_parent){
	if(coa_parent->parent_head==NULL){
		return coa_parent;
	}
	return list_entry(coa_parent->parent_head,struct sclock_coa_parent,head);
}
static int __do_copy_on_read(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd,spinlock_t *ptl, pte_t orig_pte)__releases(ptl){
	struct page *old_page=NULL, *new_page = NULL,*real_new_page=NULL;
	pte_t entry=orig_pte;
	bool isFile=false,pte_lock=true;
	int ret = 0;
	unsigned int cpu;
	int reuse=0;
	bool not_new=false;
	struct sclock_coa_children* coa_children;
	struct pid_namespace* pid_ns=NULL,*ns;
	struct sclock_coa_parent * coa_parent;
	unsigned long mmun_start = 0;	/* For mmu_notifiers */
	unsigned long mmun_end = 0;	/* For mmu_notifiers */
	unsigned long flags;
	unsigned long long time1=get_rdtsc();
	if(!(sclock_control->action&request_coa)){
		mm->def_flags&=~VM_ISOLATION;
		vma->vm_flags&=~VM_ISOLATION;
		goto not_coa;
	}
	if(!mm->owner){
		goto not_coa;
	}
	if(!(mm->def_flags&VM_ISOLATION)){
		goto not_coa;
	}
	pid_ns=ns_of_pid(task_pid(mm->owner));
	old_page = vm_normal_page(vma, address, orig_pte);
	if (!old_page) {
		/*
		 * VM_MIXEDMAP !pfn_valid() case
		 *
		 * We should not cow pages in a shared writeable mapping.
		 * Just mark the pages writable as we can't do any dirty
		 * accounting on raw pfn maps.
		 */
		//	printk(KERN_DEBUG"-----------!old_page------------\n");
		goto gotten;
	}
	if(PageAnon(old_page)&&!PageKsm(old_page)){
		if (!trylock_page(old_page)) {
			page_cache_get(old_page);
			pte_unmap_unlock(page_table, ptl);
			lock_page(old_page);
			page_table = pte_offset_map_lock(mm, pmd, address,
						&ptl);
			if (!pte_same(*page_table, orig_pte)) {
				unlock_page(old_page);
				goto unlock;
			}
			page_cache_release(old_page);
		}
		if (reuse_swap_page(old_page)) {
			/*
			 * The page is all ours.  Move it to our anon_vma so
			 * the rmap code will not search our parent or siblings.
			 * Protected against the rmap code by the page lock.
			 */
			page_move_anon_rmap(old_page, vma, address);
			unlock_page(old_page);
			goto not_coa;
		}
		unlock_page(old_page);
	}
	if(!isContainerSharedPage(old_page)){
		//	clear_bit(PG_isolation,&old_page->flags);//to exclusive state
		goto not_coa;
	}

	page_cache_get(old_page);

gotten:
	pte_unmap_unlock(page_table, ptl);
	/*check copy or parent and get coa_parent*/
	if(old_page){
check_coa_head:
		if(!old_page->coa_head){
			init_coa_parent(old_page);
			//goto reuse;
		}
		coa_parent=list_entry(old_page->coa_head,struct sclock_coa_parent,head);

		
		//	goto reuse;

		if(pid_ns==coa_parent->owner){
reuse:
			if (old_page)
			  page_cache_release(old_page);
			page_table = pte_offset_map_lock(mm, pmd, address,
						&ptl);
			if (!pte_same(*page_table, orig_pte)) {
				pte_unmap_unlock(page_table, ptl);
				goto early_out;
			}
not_coa:

			ret|=VM_FAULT_WRITE;
			//	ptep_clear_flush(vma, address, page_table);
			//		set_pte_at_notify(mm, address, page_table, entry);
			if (old_page)
			  page_cpupid_xchg_last(old_page, (1 << LAST_CPUPID_SHIFT) - 1);
			flush_cache_page(vma, address, pte_pfn(orig_pte));
			entry = pte_mkyoung(orig_pte);
			entry.pte&=~_PAGE_ISOLATION;
			if (ptep_set_access_flags(vma, address, page_table, entry,1))
			  update_mmu_cache(vma, address, page_table);
			pte_unmap_unlock(page_table, ptl);
			goto early_out;
		}

	}

	//check whether the owner still exists
	//	printk("continue coa\n");

		/*check whether we can use a exited exclusive page for this pid_ns*/
	if(coa_parent){
		struct sclock_coa_parent * original=get_original(coa_parent);
		coa_list_lock(original);
		if(coa_parent->pfn!=page_to_pfn(old_page)){
			coa_list_unlock(original);
		}else{
			list_for_each_entry(coa_children,&get_original(coa_parent)->head,head){
				if(coa_children->owner==pid_ns){
					unsigned long coa_pfn=coa_children->pfn;
					if((coa_pfn!=COA_DEL)&&(coa_pfn!=COA_SKIP)){
						new_page=pfn_to_page(coa_pfn);
						if((new_page->coa_head==&(coa_children->head))&&page_mapped(new_page)&&pages_identical(new_page,old_page)){
							coa_list_unlock(original);
							__SetPageUptodate(new_page);
							page_cache_get(new_page);
							not_new=true;
							if(sclock_control->debug)
							  printk("reuse the container's exclusive copy at %lx ->page%lx, number of copies=%d\n",address,page_to_pfn(new_page),get_copy_num(original));
							if (unlikely(anon_vma_prepare(vma)))
							  goto oom;
							goto new_page_got;
						}
					}
				}
			}
			coa_list_unlock(original);
		}
	}
	if(old_page&&(coa_parent->owner==NULL)){//first accessed shared page with COA alert
		coa_parent->owner=pid_ns;
		goto reuse;
	}
	if (unlikely(anon_vma_prepare(vma))) 
	  goto oom;
	/*check whether we can use a exited exclusive page for this pid_ns*/
	if (is_zero_pfn(pte_pfn(orig_pte))) {//assign a full zero page to the new page
		new_page = alloc_zeroed_user_highpage_movable(vma, address);
		//	printk(KERN_DEBUG"----------------gotten. assign  full zero---------------\n");
		if (!new_page)
		{
			printk("!new page from coa\n");
			goto oom;
		}
	} else {//if it is not zero, copy old to new
		new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
		if (!new_page)
		{
			printk("!new page from coa\n");
			goto oom;
		}
		cow_user_page(new_page, old_page, address, vma);
	}
	__SetPageUptodate(new_page);
	if (mem_cgroup_newpage_charge(new_page, mm, GFP_KERNEL)){
		printk("oom");
		goto oom_free_new;
	}
new_page_got:
	//notify mmu about this new virtual page's update
	mmun_start  = address & PAGE_MASK;
	mmun_end    = mmun_start + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(mm,mmun_start,mmun_end);
	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (likely((pte_same(*page_table, orig_pte)))) {
		if(old_page){
			if (!PageAnon(old_page)) {
				dec_mm_counter_fast(mm, MM_FILEPAGES);
				inc_mm_counter_fast(mm, MM_ANONPAGES);
			}
		}else
		  inc_mm_counter_fast(mm,MM_ANONPAGES);
		flush_cache_page(vma, address, pte_pfn(orig_pte));
		entry =pte_mkyoung( mk_pte(new_page, vma->vm_page_prot));
		entry.pte&=~(_PAGE_ISOLATION);
		ptep_clear_flush(vma,address,page_table);
		set_pte_at(mm, address, page_table, entry);
		update_mmu_cache(vma, address, page_table);
		pte_unmap_unlock(page_table, ptl);
		if(not_new){
			lock_page(new_page);
			//	page_cache_get(new_page);
			page_add_anon_rmap(new_page, vma, address);
			unlock_page(new_page);
		}
		else
		  page_add_new_anon_rmap(new_page, vma, address);
		real_new_page=not_new?NULL:new_page;
		if(not_new){
			coa_children->pfn=page_to_pfn(new_page);
		}
		if (old_page) {
			page_remove_rmap(old_page);//old_page->'s _mapcount -1		
			dec_page_counter_in_ns(old_page,vma);
			new_page=old_page;
			//	test_and_clear_bit(PG_isolation,&old_page->flags);
		}		/* Free the old page.. */
		ret|=VM_FAULT_WRITE;
		pte_lock=false;
	} else{
		if(!not_new){
			mem_cgroup_uncharge_page(new_page);
		}
	}
	if(new_page)
	  page_cache_release(new_page);
unlock:
	if(pte_lock)
	  pte_unmap_unlock(page_table, ptl);
	if (mmun_end > mmun_start)
	  mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
	if (old_page) {
		/*
		 * Don't let another task, with possibly unlocked vma,
		 * keep the mlocked page.
		 */
		if ( (ret&VM_FAULT_WRITE)&&(vma->vm_flags&VM_LOCKED)) {
			lock_page(old_page);	/* LRU manipulation */
			munlock_vma_page(old_page);
			unlock_page(old_page);
		}
		page_cache_release(old_page);
		if(real_new_page){
			//	printk("new page by coa at %lx",address);
			add_page_into_children_pages(get_original(coa_parent),real_new_page,pid_ns);
			//dump_page(real_new_page);
		}
	}
	__get_cpu_var(global_interval_coa_normal)+=get_rdtsc()-time1;
	__get_cpu_var(global_count_coa_normal)++;
	return ret;
early_out:
	__get_cpu_var(global_interval_coa_early)+=get_rdtsc()-time1; 
	__get_cpu_var(global_count_coa_early)++;
	return ret;
oom_free_new:
	page_cache_release(new_page);
oom:
	//	pte_unmap_unlock(page_table, ptl);
	if (old_page)
	  page_cache_release(old_page);
	printk("oom======from coa\n");
	__get_cpu_var(global_interval_coa_fail)+=get_rdtsc()-time1;
	__get_cpu_var(global_count_coa_fail)++;

	return VM_FAULT_OOM;

}


void mkOneScolor(struct sclock_LRU* sclock_entry,unsigned long pfn){
	INIT_LIST_HEAD(&(sclock_entry->sclock_lru));
	//	sclock_entry->sclock_lru.next=&(sclock_entry->sclock_lru);
	//	sclock_entry->sclock_lru.prev=&(sclock_entry->sclock_lru);
	//	ptep_clear_flush(vma,address,pte_table);
	atomic_set(&sclock_entry->access_times,1);
//	INIT_LIST_HEAD(&sclock_entry->pte_map);
//	atomic_set(&sclock_entry->pte_count,0);
	sclock_entry->pfn=pfn;
}
/*
   void mkOneScolor_queue(struct sclock_LRU* sclock_entry,unsigned long pfn){
   INIT_LIST_HEAD_RCU(&(sclock_entry->sclock_lru));
//	sclock_entry->sclock_lru.next=&(sclock_entry->sclock_lru);
//	sclock_entry->sclock_lru.prev=&(sclock_entry->sclock_lru);
//	ptep_clear_flush(vma,address,pte_table);
atomic_set(&sclock_entry->access_times,1);
INIT_LIST_HEAD(&sclock_entry->pte_map);
atomic_set(&sclock_entry->pte_count,1);
sclock_entry->pfn=pfn;
}*/
void mkOneSclockVirtual(struct sclock_LRU_virtual* sclock_entry,unsigned long address,struct mm_struct * mm,pte_t* ptep,unsigned long pfn){
	INIT_LIST_HEAD_RCU(&(sclock_entry->sclock_lru));
	//	sclock_entry->sclock_lru.next=&(sclock_entry->sclock_lru);
	//	sclock_entry->sclock_lru.prev=&(sclock_entry->sclock_lru);
	//	ptep_clear_flush(vma,address,pte_table);
	atomic_set(&sclock_entry->access_times,1);
	sclock_entry->ptep=ptep;
	sclock_entry->mm=mm;
	sclock_entry->pfn=pfn;
	sclock_entry->address=address;
}
void mkOneCacheableLRU(struct sclock_LRU* sclock_entry,long address, pte_t * page_table,struct mm_struct *mm,struct page* page){
	pte_t pte_entry=*page_table;
	//	sclock_entry=kmalloc(sizeof(struct sclock_LRU),GFP_KERNEL);
	//	sclock_entry->owner=mm->owner;
	//	sclock_entry->address=address;
	INIT_LIST_HEAD(&(sclock_entry->sclock_lru));
	//	sclock_entry->sclock_lru.next=&(sclock_entry->sclock_lru);
	//	sclock_entry->sclock_lru.prev=&(sclock_entry->sclock_lru);
	//	ptep_clear_flush(vma,address,pte_table);
	atomic_set(&sclock_entry->access_times,1);
	sclock_entry->pfn=page_to_pfn(page);
	printk(KERN_DEBUG"after initial entry,pfn=%lx\n",sclock_entry->pfn);
	pte_entry.pte&=~_PAGE_CACHE_UC_MINUS;
	pte_entry.pte&=~_PAGE_NCACHE;
	//sclock_entry->pte=pte_entry;

	set_pte_at_notify(mm, address, page_table, pte_entry);
	//	update_mmu_cache(sclock_entry->vma, sclock_entry->address, sclock_entry->pte);
}
#define PAGE_NCACHE_ALL (_PAGE_NCACHE|_PAGE_CACHE_UC_MINUS)	
#define _PAGE_OTHER	(_PAGE_NCACHE >>> (_PAGE_SIZE))
#define _PAGE_RSV	((_AT(pteval_t, 1) <<52)-(_AT(pteval_t, 1) <<39))

struct stable_node {
	union {
		struct rb_node node;	/* when node of stable tree */
		struct {		/* when listed for migration */
			struct list_head *head;
			struct list_head list;
		};
	};
	struct hlist_head hlist;
	unsigned long kpfn;
#ifdef CONFIG_NUMA
	int nid;
#endif
};

/**
 * struct rmap_item - reverse mapping item for virtual addresses
 * @rmap_list: next rmap_item in mm_slot's singly-linked rmap_list
 * @anon_vma: pointer to anon_vma for this mm,address, when in stable tree
 * @nid: NUMA node id of unstable tree in which linked (may not match page)
 * @mm: the memory structure this rmap_item is pointing into
 * @address: the virtual address this rmap_item tracks (+ flags in low bits)
 * @oldchecksum: previous checksum of the page at that virtual address
 * @node: rb node of this rmap_item in the unstable tree
 * @head: pointer to stable_node heading this list in the stable tree
 * @hlist: link into hlist of rmap_items hanging off that stable_node
 **/
struct rmap_item {
	struct rmap_item *rmap_list;
	union {
		struct anon_vma *anon_vma;	/* when stable */
#ifdef CONFIG_NUMA
		int nid;		/* when node of unstable tree */
#endif
	};
	struct mm_struct *mm;
	unsigned long address;		/* + low bits used for flags below */
	unsigned int oldchecksum;	/* when unstable */
	union {
		struct rb_node node;	/* when node of unstable tree */
		struct {		/* when listed from stable tree */
			struct stable_node *head;
			struct hlist_node hlist;		};
	};
};


static int do_ksm_page_clear(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags){
#ifndef CONFIG_KVM 
	return -1;
#else
	struct stable_node *stable_node;
	struct rmap_item *rmap_item;
	pte_t* pte,pte_entry;
	int ret=-1;	
	struct mm_struct * mm;
	struct task_struct * task;
	unsigned long address;
	stable_node = page_stable_node(page);
	//printk("ksm\n");
	if (!stable_node)
	  return -1;
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		struct anon_vma *anon_vma = rmap_item->anon_vma;
		struct anon_vma_chain *vmac;
		struct vm_area_struct *vma;
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					0, ULONG_MAX) {
			vma = vmac->vma;
			if((mm=vma->vm_mm))
			  if((task=mm->owner))
				if(ns_of_pid(task_pid(task))==pid_ns_ref){
					address= page_address_in_vma(page, vma);
					pte=find_pte(vma->vm_mm,address);
					if(pte){	
						ret++;
						pte->pte&=~flags;
						flush_tlb_page(vma,address);
						update_mmu_cache(vma, address,pte);
					}
				}
		}	
		anon_vma_unlock_read(anon_vma);
	}
	return ret;
#endif
}
static int do_file_page_clear(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags){
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	int ret=-1;	struct vm_area_struct *vma;
	unsigned long address;
	struct mm_struct * mm;
	struct task_struct * task;
	pte_t* pte,pte_entry; 
	//printk("file\n");
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);
#ifdef CONFIG_I_MMAP_SPINLOCK
	//spin_lock(&mapping->i_mmap_spinlock);
#else
	i_mmap_lock_read(mapping);

#endif
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		if(vma){
			if((mm=vma->vm_mm))
			  if((task=mm->owner))
				if(ns_of_pid(task_pid(task))==pid_ns_ref){
					address = vma_to_address(page, vma);
					pte=find_pte(mm,address);
					if(pte){
						ret++;
						pte->pte&=~flags;
						flush_tlb_page(vma,address);
						update_mmu_cache(vma, address,pte);
					}
				}
		}
	}
#ifdef CONFIG_I_MMAP_SPINLOCK
	//spin_unlock(&mapping->i_mmap_spinlock);
#else
	i_mmap_unlock_read(mapping);

#endif
	//	mutex_unlock(&mapping->i_mmap_mutex);
	return ret;
}
static int do_anon_page_clear(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags){
	struct anon_vma * anon_vma;
	int ret=-1;
	struct anon_vma_chain *avc;
	pte_t* pte,pte_entry; 
	unsigned long address;
	pgoff_t pgoff;
	struct mm_struct * mm;
	struct task_struct * task;
	struct vm_area_struct *vma;
	//printk("anon\n");

	anon_vma=page_lock_anon_vma_read(page);
	if (!anon_vma)
	  return ret;
	pgoff=page->index<<(PAGE_CACHE_SHIFT-PAGE_SHIFT);
	anon_vma_interval_tree_foreach(avc,&anon_vma->rb_root,pgoff,pgoff){
		vma=avc->vma;
		if(vma){
			if((mm=vma->vm_mm))
			  if((task=mm->owner))
				if(ns_of_pid(task_pid(task))==pid_ns_ref){
					address = page_address_in_vma(page, vma);
					pte=find_pte(vma->vm_mm,address);
					if(pte){
						ret++;
						pte->pte&=~flags;
						flush_tlb_page(vma,address);
						//	update_mmu_cache(vma, address,pte);
					}
				}
		}
	}
unlock:	page_unlock_anon_vma_read(anon_vma);
		return ret;
}
static int do_ksm_page_set(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags,int count){
#ifndef CONFIG_KVM 
	return -1;
#else
	struct stable_node *stable_node;
	struct rmap_item *rmap_item;
	pte_t* pte,pte_entry; 
	struct anon_vma *anon_vma;
	struct anon_vma_chain *vmac;
	struct vm_area_struct *vma;
	struct mm_struct * mm;
	struct task_struct * task;
	unsigned long address;
	int ret=0;
	stable_node = page_stable_node(page);
	if (!stable_node)
	  return -1;
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		anon_vma = rmap_item->anon_vma;
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					0, ULONG_MAX) {
			vma = vmac->vma;
			if((mm=vma->vm_mm))
			  if((mm->def_flags&VM_NCACHE)&&(task=mm->owner))
				if(ns_of_pid(task_pid(task))==pid_ns_ref){
					address= vma_to_address(page, vma);
					spinlock_t *ptl;
			//		if(!follow_pte(mm,address,&pte,&ptl)){

						pte=find_pte(mm,address);
						if(pte&&pte_present(*pte)){
							if(((pte->pte&flags)!=flags)){													
								ret++;
								pte->pte|=flags;
								flush_tlb_page(vma,address);
								if(ret>=get_page_counter_in_ns(page,pid_ns_ref))
								{
						//			pte_unmap_unlock(pte, ptl);
									break;
								}
								//	update_mmu_cache(vma, address,pte);
							}
						}
						//pte_unmap_unlock(pte, ptl);
					//}
				}
		}	
		anon_vma_unlock_read(anon_vma);
	}
	return ret;
unlock:	
	anon_vma_unlock_read(anon_vma);
	return ret;
#endif
}
static int do_file_page_set_irq(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags,int count){
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct mm_struct * mm;
	struct task_struct * task;
	unsigned long address;
	pte_t* pte,pte_entry; 
	int ret=0;
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);
	/*	if(!mutex_trylock(&mapping->i_mmap_mutex))
		{
		if(!page_mapped(page))
		return;
		mutex_lock(&mapping->i_mmap_mutex);
		}*/

#ifdef CONFIG_I_MMAP_SPINLOCK
	unsigned long irqflags;
	//spin_lock_irqsave(&mapping->i_mmap_spinlock,irqflags);
#else
	i_mmap_lock_read(mapping);

#endif
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		if((mm=vma->vm_mm))
		  if((mm->def_flags&VM_NCACHE)&&(task=mm->owner))
			if(ns_of_pid(task_pid(task))==pid_ns_ref){
				address = vma_to_address(page, vma);
				spinlock_t *ptl;
			//	if(!follow_pte(mm,address,&pte,&ptl)){
					pte=find_pte(mm,address);
					if(pte)
					  if(((pte->pte&flags)!=flags)){
						  ret++;
						  pte->pte|=flags;
						  flush_tlb_page(vma,address);
						  if(ret>=get_page_counter_in_ns(page,pid_ns_ref))
						  {
					//		  pte_unmap_unlock(pte, ptl);
							  break;
						  }
						  //  update_mmu_cache(vma, address,pte);
					  }
					//pte_unmap_unlock(pte, ptl);
				//}
			}
	}
unlock:	

#ifdef CONFIG_I_MMAP_SPINLOCK
	//spin_unlock_irqrestore(&mapping->i_mmap_spinlock,irqflags);
#else
	i_mmap_unlock_read(mapping);

#endif
	//mutex_unlock(&mapping->i_mmap_mutex);
	return ret;
}


static int do_file_page_set(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags,int count){
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct mm_struct * mm;
	struct task_struct * task;
	unsigned long address;
	pte_t* pte,pte_entry; 
	int ret=0;
	unsigned long irqflags;
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);
	/*	if(!mutex_trylock(&mapping->i_mmap_mutex))
		{
		if(!page_mapped(page))
		return;
		mutex_lock(&mapping->i_mmap_mutex);
		}*/

#ifdef CONFIG_I_MMAP_SPINLOCK
	//spin_lock(&mapping->i_mmap_spinlock);
#else

	i_mmap_lock_read(mapping);
#endif
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		if(vma&&(mm=vma->vm_mm)&&(mm->def_flags&VM_NCACHE)&&(task=mm->owner)&&(ns_of_pid(task_pid(task))==pid_ns_ref)){
				address = vma_to_address(page, vma);
				spinlock_t *ptl;
			//	if(!follow_pte(mm,address,&pte,&ptl)){
					pte=find_pte(mm,address);
					if(pte&&pte_present(*pte))
					  if(((pte->pte&flags)!=flags)){
						  ret++;
						  pte->pte|=flags;
						  flush_tlb_page(vma,address);
						  if(ret>= get_page_counter_in_ns(page,pid_ns_ref))  		
						  {
			//				  pte_unmap_unlock(pte, ptl);
							  break;
						  }
						  update_mmu_cache(vma, address,pte);
					  }
			//		pte_unmap_unlock(pte, ptl);
			//	}
			}
	}
unlock:	

	i_mmap_unlock_read(mapping);

	return ret;
}
static int do_anon_page_set_care(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags,int count){

	struct anon_vma * anon_vma;
	struct anon_vma_chain *avc;
	pte_t* pte; 
	unsigned long address;
	pgoff_t pgoff;
	struct vm_area_struct *vma;
	struct mm_struct* mm;
	struct task_struct * task;
	int ret=0;
	anon_vma=page_lock_anon_vma_read(page);
	if (!anon_vma){
		return ret;
	}
	pgoff=page->index<<(PAGE_CACHE_SHIFT-PAGE_SHIFT);
	anon_vma_interval_tree_foreach(avc,&anon_vma->rb_root,pgoff,pgoff){
		vma=avc->vma;
		if(vma){
			if((mm=vma->vm_mm))
			  if((task=mm->owner))
				if(ns_of_pid(task_pid(task))==pid_ns_ref){
					address = vma_to_address(page, vma);
					pte=find_pte(mm,address);
					if(pte)
					  if(((pte->pte&flags)!=flags)){
						  ret++;
						  pte->pte|=flags;
						  flush_tlb_page(vma,address);
						  if(ret>= get_page_counter_in_ns(page,pid_ns_ref))
							break;
						  //	  update_mmu_cache(vma, address,pte);
					  }
				}
		}
	}
unlock:	page_unlock_anon_vma_read(anon_vma);
		return ret;
}
static int do_anon_page_set(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags,int count){

	struct anon_vma * anon_vma;
	struct anon_vma_chain *avc;
	pte_t* pte; 
	unsigned long address;
	pgoff_t pgoff;
	struct vm_area_struct *vma;
	struct mm_struct* mm;
	struct task_struct * task;
	int ret=0;
	anon_vma=page_lock_anon_vma_read(page);
	if (!anon_vma){
		return ret;
	}
	pgoff=page->index<<(PAGE_CACHE_SHIFT-PAGE_SHIFT);
	anon_vma_interval_tree_foreach(avc,&anon_vma->rb_root,pgoff,pgoff){
		vma=avc->vma;
		if(vma&&(mm=vma->vm_mm)&&(task=mm->owner)){
			if(ns_of_pid(task_pid(task))==pid_ns_ref){
				address = vma_to_address(page, vma);
				spinlock_t *ptl;
				//if(find_pte(mm,address,&pte,&ptl)){
					pte=find_pte(mm,address);
					if(pte&&pte_present(*pte))
					  if(((pte->pte&flags)!=flags)){
						  /*		if(pte->pte|_PAGE_ACCESSED){
						  //printk("PAGE_ACCESSED in anon");
						  ret=-1;
						  goto unlock;// cannot marked as UC...
						  }*/
						  ret++;
						  pte->pte|=flags;
						  flush_tlb_page(vma,address);
						  if(ret>= get_page_counter_in_ns(page,pid_ns_ref))
						  {
					//		  pte_unmap_unlock(pte, ptl); 
							  break;
						  }
						 // update_mmu_cache(vma, address,pte);
					  }
					//pte_unmap_unlock(pte, ptl);
			//	}
			}
		}
	}
unlock:	page_unlock_anon_vma_read(anon_vma);
		return ret;
	}
	int do_page_setirq(struct page* page,struct pid_namespace* pid_ns, pteval_t flags,int count){	
	if(page_mapped(page)&&page_rmapping(page)){
			//	if(page_mapcount(page)>0){
			//printk("mapcount==%d\n",page_mapcount(page));
			if(PageKsm(page)){
				return do_ksm_page_set(page,pid_ns,flags,count);
				//printk("map=%d",	do_ksm_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}else if(PageAnon(page)){
				return do_anon_page_set(page,pid_ns,flags,count);
				//printk("map=%d",	do_anon_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}
			else if(page_mapping(page)){
				return do_file_page_set_irq(page,pid_ns,flags,count);
				//printk("map=%d",	do_file_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}
			//}
		}
		return -1;
	}
	int do_page_set_care(struct page* page,struct pid_namespace* pid_ns, pteval_t flags,int count){
		if(page_mapped(page)&&page_rmapping(page)){
			//	if(page_mapcount(page)>0){
			//printk("mapcount==%d\n",page_mapcount(page));
			if(PageKsm(page)){
				return do_ksm_page_set(page,pid_ns,flags,count);
				//printk("map=%d",	do_ksm_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}else if(PageAnon(page)){
				return do_anon_page_set_care(page,pid_ns,flags,count);
				//printk("map=%d",	do_anon_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}
			else if(page_mapping(page)){
				return do_file_page_set(page,pid_ns,flags,count);
				//printk("map=%d",	do_file_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}
			//}
		}
		return -1;
	}
	int do_page_set(struct page* page,struct pid_namespace* pid_ns, pteval_t flags,int count){
		if(page_mapped(page)&&page_rmapping(page)){
			//	if(page_mapcount(page)>0){
			//printk("mapcount==%d\n",page_mapcount(page));
			if(PageKsm(page)){
				return do_ksm_page_set(page,pid_ns,flags,count);
				//printk("map=%d",	do_ksm_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}else if(PageAnon(page)){
				return do_anon_page_set(page,pid_ns,flags,count);
				//printk("map=%d",	do_anon_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}
			else if(page_mapping(page)){
				return do_file_page_set(page,pid_ns,flags,count);
				//printk("map=%d",	do_file_page_clear(page,pid_ns,_PAGE_CACHE_PROTECT));
			}
			//}
		}
		return -1;
	}
	struct list_head * getElementInList(struct list_head* head,int n){
		if(n==1)
		  return head->next;
		return getElementInList(head->next,n-1); 
	}

#if 0
	static int _try_switch_NCache_virtual(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid)
	{
		//	struct task_struct* task=current;
		unsigned long FN;//,pfn_one;
		struct page* page;
		//	struct list_head* tmp;
		int set_number;
		struct mm_struct *mm_one;
		//	unsigned int random;
		atomic_t * counter;
		//	struct page* page_one;
		unsigned long address_one;
		struct sclock_LRU_virtual* sclock_entry,*sclock_one;
		//struct list_head *pid_ns->sclock_lru;
		struct list_head * lru_head;//,*lru_head;
		struct list_head* del_candidate;
		pte_t pte_entry,*pte_one;
		struct pid_namespace* pid_ns;
		int ret=0;
		bool set_protect=true;
		unsigned long mmun_start=0, mmun_end = 0;	/* For mmu_notifiers */
		//	page_one=NULL;
		page=NULL;
		bool addNewLRU=1;
		int findNToDel=0;
		unsigned long flags;
		pte_entry=orig_pte;
		if(update_protection_cache(0)<=0){
			//		ptep_clear_flush(vma, address, page_table);
			//printk("not protectin mode\n");
			pte_entry.pte&=~_PAGE_CACHE_PROTECT;	
			set_pte_at_notify(mm, address, page_table, pte_entry);
			flush_tlb_page(vma,address);
			goto unlock;
		}
		if(mm->def_flags&VM_CACHE_PROTECT==0){
			//		ptep_clear_flush(vma, address, page_table);
			//printk("not protectin mode\n");
			pte_entry.pte&=~_PAGE_CACHE_PROTECT;
			set_pte_at_notify(mm, address, page_table, pte_entry);
			flush_tlb_page(vma,address);
			goto unlock;
		}
		FN=pte_pfn(orig_pte);
		if(!pfn_valid(FN)){
			//printk("UNVALID fn\n");
			//	ptep_clear_flush(vma, address, page_table);
			pte_entry.pte&=~_PAGE_CACHE_PROTECT;
			set_pte_at_notify(mm, address, page_table, pte_entry);
			flush_tlb_page(vma,address);
			goto unlock;
		}
		set_number=(unsigned long)FN&(unsigned long)(NPageColor-1);
		mmun_start=address;
		mmun_end=address+PAGE_SIZE;
		pid_ns=ns_of_pid(task_pid(mm->owner));
		//	ptep_clear_flush(vma, address, page_table);
		pte_entry.pte&=~_PAGE_NCACHE;
		set_pte_at_notify(mm, address, page_table, pte_entry);
		flush_tlb_page(vma,address);
		pte_unmap_unlock(page_table, ptl);
		if(pid_ns->sclock_lru_counter==NULL||pid_ns->sclock_lru==NULL){
			goto out;
		}
		counter=&(pid_ns->sclock_lru_counter[set_number]);
		lru_head=&(pid_ns->sclock_lru[set_number]);
		//	spin_lock(&(pid_ns->sclock_lock[set_number]));
		//	//printk("lock for %d\n",set_number);
		if(atomic_read(counter)<protection_level(0)){
			goto add;
		}
		spin_lock(&(pid_ns->sclock_lock[set_number]));
		list_for_each_entry(sclock_entry,lru_head,sclock_lru){
			if(pte_pfn(*(sclock_entry->ptep))!=sclock_entry->pfn){
				findNToDel=1;
				addNewLRU=0;
				del_candidate=&sclock_entry->sclock_lru;
				set_protect=false;
				goto find_del;
			}
			if((sclock_entry->ptep->pte&_PAGE_CACHE_PROTECT)||atomic_read(&sclock_entry->access_times)==SCLOCK_TO_BE_DEL){
				findNToDel=1;
				addNewLRU=0;
				del_candidate=&sclock_entry->sclock_lru;
				set_protect=false;
				goto find_del;
				//	continue;
			}
			if(pte_present(*(sclock_entry->ptep))){
				findNToDel=1;
				addNewLRU=0;
				del_candidate=&sclock_entry->sclock_lru;
				set_protect=true;
				goto find_del;
			}else{
				findNToDel=1;
				addNewLRU=0;
				del_candidate=&sclock_entry->sclock_lru;
				set_protect=false;
				goto find_del;
			}

		}
		if(addNewLRU>0&&findNToDel==0){
			del_candidate=lru_head->next;
			findNToDel=1;
			addNewLRU=0;
		}
find_del:
		//	for(i=0;i<findNToDel;i++){
		list_del_init(del_candidate);
		sclock_entry=list_entry(del_candidate,struct sclock_LRU,sclock_lru);
		pte_one=sclock_entry->ptep;
		//	page_one=pfn_to_page(sclock_entry->pfn);
		//		if(find_pte(mm,address)==pte_one)
		mm_one=sclock_entry->mm;
		address_one=sclock_entry->address;

		//sclock_entry=list_entry(del_candidate,struct sclock_LRU,sclock_lru);
		//	pfn_one=sclock_entry->pfn;
		//	}
		spin_unlock(&(pid_ns->sclock_lock[set_number]));
		if(!set_protect){
			goto add;
		}
		pte_one->pte|=_PAGE_CACHE_PROTECT;
		//	if(invalid)
		mmu_notifier_invalidate_page(mm_one, address_one);

		//		for(i=0;i<findNToDel;i++){
		//	sclock_entry=list_entry(del_candidate,struct sclock_LRU,sclock_lru);
		//	if(pfn_valid(pfn_one))
		//	  page_one=pfn_to_page(pfn_one);
		//	if(page_one){
		//	if(page_mapcount(page_one)>=0){
		//for shared memory, mark UC from C if they are accessed in other PTE mapped to it.
		//printk("shared page to be replaced\n");
		/*	if (!trylock_page(page_one)) {
			page_cache_get(page_one);
			lock_page(page_one);
			page_cache_release(page_one);
			}*/
		/*	if(PageKsm(page_one)){
		//printk("set for mapped =%d",do_ksm_page_set(page_one,pid_ns,_PAGE_CACHE_PROTECT));
		do_ksm_page_set(page_one,pid_ns,_PAGE_CACHE_PROTECT);
		}	
		else if(PageAnon(page_one)){
		//printk("set for mapped =%d",do_anon_page_set(page_one,pid_ns,_PAGE_CACHE_PROTECT));
		do_anon_page_set(page_one,pid_ns,_PAGE_CACHE_PROTECT);
		}	
		else if(page_mapping(page_one)) {
		//printk("set for mapped =%d",do_file_page_set(page_one,pid_ns,_PAGE_CACHE_PROTECT));
		do_file_page_set(page_one,pid_ns,_PAGE_CACHE_PROTECT);
		}*/
		//	unlock_page(page_one);
		//	}
		//	}
		//	}

add:
		if(addNewLRU){
			if(findNToDel>0){
				//	sclock_one=sclock_entry;
				//	sclock_one=list_entry_rcu(del_candidate,struct sclock_LRU,sclock_lru);
				spin_lock(&(pid_ns->sclock_lock[set_number]));
				mkOneSclockVirtual(sclock_entry,address,mm,page_table,FN);
				list_add_tail(&sclock_entry->sclock_lru,lru_head);
				spin_unlock(&(pid_ns->sclock_lock[set_number]));
				//printk("replace\n");
			}else{
				sclock_one=kmalloc(sizeof(struct sclock_LRU_virtual),GFP_KERNEL);
				if(!sclock_one){
					addNewLRU=0;
					//printk("fail alloc new LRU\n");
				}
				spin_lock(&(pid_ns->sclock_lock[set_number]));
				mkOneSclockVirtual(sclock_one,address,mm,page_table,FN);
				list_add_tail(&sclock_one->sclock_lru,lru_head);
				spin_unlock(&(pid_ns->sclock_lock[set_number]));
				atomic_inc(counter);
				//printk("list_add_rcu sclock_one->pfn=%lx,sub %d",sclock_one->pfn,findNToDel-addNewLRU);
			}
		}
		if(invalid)
		  mmu_notifier_invalidate_page(mm, address);
		//	atomic_sub(findNToDel-addNewLRU,counter);
		/*	if(page){
			page_cache_release(page);
			}*/
		/*	if (mmun_end > mmun_start)
			mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
			*/		pte_entry.pte&=~_PAGE_NCACHE;

		return ret;
unlock:
		//printk("unlock earlier");

		pte_unmap_unlock(page_table, ptl);
		//	//printk("unlock at end\n");
out:
		if(invalid)
		  mmu_notifier_invalidate_page(mm, address);

		/*	if(page){
			page_cache_release(page);
			}*/
		/*	if (mmun_end > mmun_start)
			mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
			*/	return ret;
	}
#endif
#define MAX_QUICK_MAP 1024
	struct sclock_page_pte_map** quick_pte_map_old;
	LIST_HEAD(quick_pte_map_head);
	static DEFINE_SPINLOCK(quick_pte_map_mutex);
	atomic_t quick_pte_map_index=ATOMIC_INIT(0);

	/*struct sclock_page_pte_map * sclock_pte_map_alloc_quick_old(void){
	  struct sclock_page_pte_map* ret;
	  int index;
	  index=atomic_dec_return(&quick_pte_map_index);
	  if(index>0){
	  ret=(struct sclock_page_pte_map* )quick_pte_map[index];
	  quick_pte_map[index]=NULL;
	  return ret;
	  }
	  atomic_inc(&quick_pte_map_index);
	  return NULL;
	  }*/
	struct sclock_page_pte_map * sclock_pte_map_alloc_quick(void){

		struct sclock_page_pte_map* ret=NULL;
		struct list_head* entry;

		spin_lock(&quick_pte_map_mutex);
		if(list_empty(&quick_pte_map_head)){
			spin_unlock(&quick_pte_map_mutex);
			return NULL;
		}
		entry=quick_pte_map_head.next;
		atomic_dec(&quick_pte_map_index);
		list_del_init(entry);
		spin_unlock(&quick_pte_map_mutex);
		ret=list_entry(entry,struct sclock_page_pte_map,head);
		return ret;
	};
bool sclock_pte_map_free_quick(struct sclock_page_pte_map* pte_map){
	struct list_head* entry;
	bool ret=true;
	if(atomic_read(&quick_pte_map_index)>=MAX_QUICK_MAP){

		kmem_cache_free(sclock_page_pte_map_cache,pte_map);
		ret=false;
		goto out;
	}
	spin_lock(&quick_pte_map_mutex);
	atomic_inc(&quick_pte_map_index);
	list_add_tail(&pte_map->head,&quick_pte_map_head);
	spin_unlock(&quick_pte_map_mutex);
out:
	if(atomic_read(&(pte_map->sclock_pte_map_vma_counter->counter))==0&&pte_map->sclock_pte_map_vma_counter->legal==false)
	  destroy_sclock_pte_map_vma_counter(pte_map->sclock_pte_map_vma_counter);
	else
	  atomic_dec(&(pte_map->sclock_pte_map_vma_counter->counter));
	return true;
};/*
	 int do_page_reverse_clear(struct sclock_LRU * sclock_entry, pteval_t flags){
		 struct list_head* pte_head;
		 struct sclock_page_pte_map* pte_map,*n;
		 unsigned long pfn=sclock_entry->pfn;
		 pte_head=&sclock_entry->pte_map;
		 list_for_each_entry_safe(pte_map,n,pte_head,head){
		 if(pte_pfn(*(pte_map->ptep))==pfn){
	//	printk("set pte,%lx",flags);
	flush_tlb_page(pte_map->vma,pte_map->address);
	pte_map->ptep->pte&=~flags;
	//update_mmu_cache(pte_map->vma, pte_map->address,pte_map->ptep);
	}else{
	//	printk("not same, del pte directly\n");
	list_del(&pte_map->head);
	sclock_pte_map_free_quick(pte_map);
	}
	}
one:
if(pte_pfn(*(sclock_entry->ptep))==pfn){
flush_tlb_page(sclock_entry->vma,sclock_entry->address);
sclock_entry->ptep->pte&=~flags;
update_mmu_cache(sclock_entry->vma, sclock_entry->address,sclock_entry->ptep);

}
return 	atomic_read(&sclock_entry->pte_count);
}*/
void clean_sclock_pte_map(struct sclock_LRU * sclock_entry){
/*	struct list_head* 	pte_head=&sclock_entry->pte_map;
	struct sclock_page_pte_map* pte_map,*n;	
	if(pte_head==NULL)
	  return;
	if(list_empty(pte_head)){
		return;
	}
	list_for_each_entry_safe(pte_map,n,pte_head,head){

		list_del(&pte_map->head);
		sclock_pte_map_free_quick(pte_map);
	}
*/
	};
/*
int do_page_reverse_set(struct sclock_LRU * sclock_entry, pteval_t flags){
	struct list_head* pte_head;
	struct sclock_page_pte_map* pte_map,*n;
	unsigned long pfn=sclock_entry->pfn;
	pte_head=&sclock_entry->pte_map;
	if(list_empty(pte_head)){
		goto out;
	}
	list_for_each_entry_safe(pte_map,n,pte_head,head){
		if(pte_pfn(*(pte_map->ptep))!=pfn||!pte_map->sclock_pte_map_vma_counter->legal||!pte_map->vma){
			list_del_init(&pte_map->head);
			sclock_pte_map_free_quick(pte_map);
			continue;
		}
		if(pte_present(*(pte_map->ptep)))	{
			pte_map->ptep->pte|=flags;
			if(pte_map->vma->vm_start<pte_map->address||pte_map->vma->vm_start<pte_map->address){
				pte_map->vma=find_vma(pte_map->vma->vm_mm,pte_map->address);
			}
			//if((pte_map->ptep==find_pte(pte_map->vma->vm_mm,pte_map->address))){
			if(pte_map->vma)
			  flush_tlb_page(pte_map->vma,pte_map->address);
		}
		//	update_mmu_cache(pte_map->vma, pte_map->address,pte_map->ptep);
		list_del_init(&pte_map->head);
		sclock_pte_map_free_quick(pte_map);
		}
out:
	return 	atomic_read(&sclock_entry->pte_count);
};*/
/*
   int do_page_reverse_set_del(struct sclock_LRU * sclock_entry, pteval_t flags){
   struct list_head* pte_head;
   struct sclock_page_pte_map* pte_map,*n;
   unsigned long pfn=sclock_entry->pfn;
   pte_head=&sclock_entry->pte_map;
   list_for_each_entry_safe(pte_map,n,pte_head,head){
   if(pte_pfn(*(pte_map->ptep))==pfn){
   if(pte_present(*(pte_map->ptep)))
   pte_map->ptep->pte|=flags;
//	printk(" same, set pte and del\n");
}
list_del(&pte_map->head);
sclock_pte_map_free_quick(pte_map);
}
if(pte_pfn(*(sclock_entry->ptep))==pfn)
if(pte_present(*(sclock_entry->ptep)))
sclock_entry->ptep->pte|=flags;
return 	0;

}*/
/*struct sclock_page_pte_map* list_pte_map_create(pte_t* ptep,struct vm_area_struct* vma,unsigned long addr){
	struct sclock_page_pte_map* map;
	map=sclock_pte_map_alloc_quick();
	if(map==NULL)
	  map=kmem_cache_alloc(sclock_page_pte_map_cache,GFP_KERNEL);
	map->ptep=ptep;
	map->vma=vma;
	map->address=addr;
	map->sclock_pte_map_vma_counter=vma->sclock_pte_map_vma_counter;
	add_sclock_pte_map(vma);
	//list_add(&map->head_for_mm,&vma->sclock_all_pte_map);
	return map;
};
int list_pte_map_add(struct sclock_page_pte_map* map,struct sclock_LRU* sclock_entry){
	list_add(&map->head,&sclock_entry->pte_map);
	atomic_inc(&sclock_entry->pte_count);
	return 0;
};*/
static void remove_queue_work(struct work_struct * work){
	struct fault_entry* fault_entry=container_of(work,struct fault_entry,work); 
	do_page_set(pfn_to_page(fault_entry->pfn),fault_entry->pid_ns,_PAGE_CACHE_PROTECT,1000);
	kmem_cache_free(sclock_fault_entry_cache,fault_entry);       
}
static void fault_queue_work(struct work_struct * work){
	struct fault_entry* fault_entry=container_of(work,struct fault_entry,work);
	try_switch_NCache(fault_entry->mm,fault_entry->vma,fault_entry->address,fault_entry->pfn,fault_entry->orig_pte,true);
	kmem_cache_free(sclock_fault_entry_cache,fault_entry);
}
static int _try_switch_NCache(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid){
	unsigned long long time1;
	time1=get_rdtsc();
	struct page* page,*page_one;
	atomic_t * counter,*UC_counter;
	struct sclock_LRU* sclock_entry;
	struct list_head * lru_head,* del_candidate;
	pte_t pte_entry;
	struct pid_namespace* pid_ns=NULL;
	int ret=0,set_number,findNToDel=0,pte_count,seq=0;
	bool set_protect=true,addNewLRU=true;
	unsigned long pfn,pfn_one,flags;	/* For mmu_notifiers */
	//	struct sclock_page_pte_map* pte_map;//reverse
	pfn=pte_pfn(orig_pte);
	if(sclock_control->action&request_lru==0){
		mm->def_flags&=~VM_CACHE_PROTECT;
		vma->vm_flags&=~VM_CACHE_PROTECT;
		vma->vm_page_prot.pgprot&=~VM_CACHE_PROTECT;
		goto setearly;
	}
	if(mm->def_flags&VM_CACHE_PROTECT==0){
		goto setearly;
	}
	if(mm->owner==NULL)
	  goto setearly;
	page= vm_normal_pfn_to_page(vma, address, orig_pte,pfn);
	if (!page||!page_mapped(page)) {
		goto setearly;
	}
//	prefetch_range(kmap(page),PAGE_SIZE);
//	kunmap(page);
	page_table->pte&=~_PAGE_CACHE_PROTECT;
	flush_tlb_page(vma,address);
	update_mmu_cache(vma, address, page_table);
	pte_unmap_unlock(page_table,ptl);
	set_number=pfn&(NPageColor-1);
	pid_ns=ns_of_pid(task_pid(mm->owner));
	if(pid_ns->sclock_lru==NULL){
		initPidNsProtection(pid_ns);
	}
	counter=&(pid_ns->sclock_lru_counter[set_number]);
	lru_head=&(pid_ns->sclock_lru[set_number]);
	//	spin_lock(&(pid_ns->sclock_lock[set_number]));
	spin_lock(&(pid_ns->sclock_lock[set_number]));
	if(test_bit(PG_cacheable,&page->flags)){
		list_for_each_entry(sclock_entry,lru_head,sclock_lru){
			if(sclock_entry->pfn==pfn){
				spin_unlock(&(pid_ns->sclock_lock[set_number]));
				if(sclock_control->debug==1){
					printk("[in queue]page %lx already in set %d for ns=%lx,address=%lx,task=%s,pte=%lx\n",pfn,set_number,pid_ns,address,mm->owner->comm,page_table);
				}
				page_table=pte_offset_map_lock(mm, pmd, address, &ptl);  
				goto setearly;
			}
		}
	}
	if(atomic_read(counter)<get_k_of_ns(pid_ns)){
		findNToDel=0;
		addNewLRU=true;
		spin_unlock(&(pid_ns->sclock_lock[set_number]));
		goto early_add;
	}
	del_candidate=lru_head->next;
	findNToDel=1;
find_del:
	sclock_entry=list_entry(del_candidate,struct sclock_LRU,sclock_lru);
		page_one=pfn_to_page(sclock_entry->pfn);
	list_del_init(&sclock_entry->sclock_lru);
	
	atomic_dec(&(pid_ns->sclock_lru_counter[set_number]));
	spin_unlock(&(pid_ns->sclock_lock[set_number]));
	if(sclock_control->debug==1){
		printk("[replace]page %lx replace page %lx in queue in set %d for ns=%lx, address=%lx,task=%s,pte=%lx\n",pfn,sclock_entry->pfn,set_number,pid_ns,address,mm->owner->comm,page_table);
	}
	if(page_one)
	{
		if(page_mapped(page_one)&& page_rmapping(page_one)){
		  int welock=true;
		  if(!trylock_page(page_one))
			  {
				  welock=false;  //	  atomic_inc(&(pid_ns->sclock_lru_counter[set_number]));
				  //lock_page(page_one);
			  }
			  if(page_mapped(page_one)&& page_rmapping(page_one))
			  {
				  page_cache_get(page_one);
				  clear_bit(PG_cacheable,&page_one->flags);
				  if(do_page_set(page_one,pid_ns,_PAGE_CACHE_PROTECT,1000)){
					  //if(do_page_reverse_set(sclock_entry,_PAGE_CACHE_PROTECT)){
					  	  if(page_mapped(page_one)){
							  if(sclock_control->flush==1){
								  clflush_all(kmap(page_one),PAGE_SIZE);
								  kunmap(page_one);
							  }else if(sclock_control->flush==2){
								  clflush_one(kmap(page_one),address&PAGE_SIZE);
								  kunmap(page_one);
							  }
						  }
				  }
					  page_cache_release(page_one);
					  }
					  if(welock)
						unlock_page(page_one);
					  //	}
			//	queue_work(para->workqueue,&fault_entry->work);
		}

		}
		set_bit(PG_cacheable,&page->flags);
		mkOneScolor(sclock_entry,pfn);
			//list_pte_map_add(pte_map,sclock_entry);//reverse
		spin_lock(&(pid_ns->sclock_lock[set_number]));
		list_add_tail(&sclock_entry->sclock_lru,&(pid_ns->sclock_lru[set_number]));
		atomic_inc(&(pid_ns->sclock_lru_counter[set_number]));
		spin_unlock(&(pid_ns->sclock_lock[set_number]));
		if(sclock_control->debug==1){
			printk("[add]page %lx enqueued in set %d for ns=%lx,address=%lx,task=%s,pte=%lx\n",pfn,set_number,pid_ns,address,mm->owner->comm,page_table);
		}
		//	if(!(page_table->pte&_PAGE_NCACHE))
		//	global_count_early++;   
		//	global_interval_early+=get_rdtsc()-time1;
		goto normal_out;

early_add:
	//flush_tlb_page(vma,address);
	//	pte_map->ptep=page_table;//reverse
	//	pte_unmap_unlock(page_table,ptl);
	sclock_entry=kmem_cache_alloc(sclock_entry_cache,GFP_KERNEL);
	if(!sclock_entry){
		addNewLRU=0;
		//		pte_unmap_unlock(page_table, ptl);
		ret=0;
		//sclock_pte_map_free_quick(pte_map);//reverse
		printk("failed alloc new LRU");
		//	atomic_dec(&(pid_ns->sclock_lru_counter[set_number]));
		goto out;
	}
	mkOneScolor(sclock_entry,pfn);
	//		pte_map=list_pte_map_create(page_table,vma,address);
	//	list_pte_map_add(pte_map,sclock_entry);//reverse
	spin_lock(&(pid_ns->sclock_lock[set_number]));
	atomic_inc(&(pid_ns->sclock_lru_counter[set_number]));
	list_add_tail(&sclock_entry->sclock_lru,&(pid_ns->sclock_lru[set_number]));
	spin_unlock(&(pid_ns->sclock_lock[set_number]));
normal_out:
		__get_cpu_var(global_count_normal)++;
	__get_cpu_var(global_interval_normal)+=(get_rdtsc()-time1);
	return ret;
setearly:
	page_table->pte&=~_PAGE_CACHE_PROTECT;	
	flush_tlb_page(vma,address);
	update_mmu_cache(vma, address, page_table);
unlock:
	pte_unmap_unlock(page_table, ptl);
out:
	__get_cpu_var(global_count_early)++;   
	__get_cpu_var(global_interval_early)+=(get_rdtsc()-time1);
	return ret;
}




pte_t * find_pte_check_pfn(struct mm_struct * mm, unsigned long address,unsigned long pfn){
	pte_t * pte=find_pte(mm,address);
	if(pte)
	  if(pte_pfn(*pte)!=pfn)
		return NULL;
	return pte;
}


static inline int get_random_number(void){
	int i;
	get_random_bytes ( &i, sizeof (i) );
	return i;
}

#define trigger_by_isolation( page_table)\
	((((page_table->pte)&_PAGE_RSV)==(_PAGE_ISOLATION|_PAGE_NCACHE))||(((page_table->pte)&_PAGE_RSV)==_PAGE_ISOLATION))?true:false
#define trigger_by_NCache( page_table)\
	((page_table->pte&_PAGE_RSV)==_PAGE_NCACHE)?true:false
	int check_other_rsv(pte_t* pte){
		if(!trigger_by_NCache(pte)&&!trigger_by_isolation(pte)){
			printk(KERN_DEBUG"Other reserved bit detected");
			return -1;// other reserved bit used! pgtable_bad();
		}
		return 0;
	}

	int do_copy_on_read(struct mm_struct *mm, struct vm_area_struct *vma,
				unsigned long address, unsigned int flags)
	{
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;
		pte_t entry;
		spinlock_t *ptl;
		if (unlikely(is_vm_hugetlb_page(vma)))
		  return hugetlb_fault(mm, vma, address, flags);
		pgd = pgd_offset(mm, address);
		pud = pud_alloc(mm, pgd, address);
		if (!pud)
		  return VM_FAULT_OOM;
		pmd = pmd_alloc(mm, pud, address);
		if (!pmd)
		  return VM_FAULT_OOM;
		if (pmd_none(*pmd) && transparent_hugepage_enabled(vma)) {
			int ret = VM_FAULT_FALLBACK;
			if (!vma->vm_ops)
			  ret = do_huge_pmd_anonymous_page(mm, vma, address,
						  pmd, flags);
			if (!(ret& VM_FAULT_FALLBACK))
			  return ret;
		} else {
			pmd_t orig_pmd = *pmd;
			int ret;
			barrier();
			if (pmd_trans_huge(orig_pmd)) {
				unsigned int dirty = flags & FAULT_FLAG_WRITE;
				/*
				 * If the pmd is splitting, return and retry the
				 * the fault.  Alternative: wait until the split
				 * is done, and goto retry.
				 */
				if (pmd_trans_splitting(orig_pmd))
				  return 0;
				if (pmd_numa(orig_pmd))
				  return do_huge_pmd_numa_page(mm, vma, address,
							  orig_pmd, pmd);

				if (dirty && !pmd_write(orig_pmd)) {
					ret = do_huge_pmd_wp_page(mm, vma, address, pmd,
								orig_pmd);
					if (!(ret & VM_FAULT_FALLBACK))
					  return ret;
				} else {
					huge_pmd_set_accessed(mm, vma, address, pmd,
								orig_pmd, dirty);
					return 0;
				}
			}
		}
		/*
		 * Use __pte_alloc instead of pte_alloc_map, because we can't
		 * run pte_offset_map on the pmd, if an huge pmd could
		 * materialize from under us from a different thread.
		 */
		if (unlikely(pmd_none(*pmd)) &&
					unlikely(__pte_alloc(mm, vma, pmd, address)))
		  return VM_FAULT_OOM;
		/* if an huge pmd materialized from under us just retry later */
		if (unlikely(pmd_trans_huge(*pmd)))
		  return 0;
		/*
		 * A regular pmd is established and it can't morph into a huge pmd
		 * from under us anymore at this point because we hold the mmap_sem
		 =* read mode and khugepaged takes it in write mode. So now it's
		 * safe to run pte_offset_map().
		 */
		pte = pte_offset_map(pmd, address);
		entry = *pte;
		if (!pte_present(entry)) {
			if (pte_none(entry)) {
				if (vma->vm_ops) {
					if (likely(vma->vm_ops->fault))
					  return do_linear_fault(mm, vma, address,
								  pte, pmd, flags, entry);
				}
				return do_anonymous_page(mm, vma, address,
							pte, pmd, flags);
			}
			if (pte_file(entry))
			  return do_nonlinear_fault(mm, vma, address,
						  pte, pmd, flags, entry);
			return do_swap_page(mm, vma, address,
						pte, pmd, flags, entry);
		}
		ptl = pte_lockptr(mm, pmd);
		//	//printk("before locking");
		spin_lock(ptl);
		//	//printk("lock");
		if (unlikely(!pte_same(*pte, entry)))
		  goto unlock;
		if(trigger_by_isolation(pte)==1){
			//	printk(KERN_DEBUG"triggerd by isolation\n");
			return	__do_copy_on_read(mm,vma,address,pte,pmd,ptl,entry);
		}
		else if(trigger_by_NCache(pte)==1){
			//	printk(KERN_DEBUG"triggerd by NCache\n");
			return	_try_switch_NCache(mm,vma,address,pte,pmd,ptl,entry,true);
		}
unlock:
		pte_unmap_unlock(pte, ptl);
		//	//printk("unlock not trigger");
		return 0;
	}

	static int _do_copy_on_read(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd,spinlock_t *ptl, pte_t orig_pte)
	{
		if(trigger_by_isolation(page_table)==1)
		{
			//	printk(KERN_DEBUG"triggerd by isolation\n");
			return	__do_copy_on_read(mm,vma,address, page_table,pmd,ptl, orig_pte);
		}
		else if(trigger_by_NCache(page_table)==1){
			//	printk(KERN_DEBUG"triggerd by NCache\n");
			return	_try_switch_NCache(mm,vma,address, page_table,pmd,ptl, orig_pte,true);
		}
		pte_unmap_unlock(page_table, ptl);
		//	//printk("unlock not trigger");
		return VM_FAULT_RSVD;
	}
	static int _manage_cacheability(struct mm_struct *mm, struct vm_area_struct *vma,
				unsigned long address, pte_t *page_table, pmd_t *pmd,
				spinlock_t *ptl, pte_t orig_pte)
	{
		int ret=VM_FAULT_RSVD;
		if(trigger_by_NCache(page_table)==1){
			////printk("triggerd by NCache\n");
			return	_try_switch_NCache(mm,vma,address, page_table,pmd,ptl, orig_pte,true);
		}
		if(((page_table->pte)&_PAGE_RSV)==0)
		  ret=0;
		pte_unmap_unlock(page_table, ptl);
		//printk("unlock in _manage_cacheability,pte=%lx\n",page_table->pte);
		return ret;
	}

	static int handle_double_cache_pte_fault_one(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid) 
	{
		int ret=VM_FAULT_RSVD;
		/*	if(mm->def_flags&VM_ISOLATION){
			return _do_copy_on_read(mm,vma,address, page_table,pmd,ptl, orig_pte);
			}else if(mm->def_flags&VM_NCACHE){
			return _manage_cacheability(mm,vma,address, page_table,pmd,ptl, orig_pte);
			}
			*/
		if(trigger_by_isolation(page_table)==1)
		{
			//	printk(KERN_DEBUG"triggerd by isolation\n");
			ret=__do_copy_on_read(mm,vma,address, page_table,pmd,ptl, orig_pte);
			page_table = pte_offset_map_lock(mm, pmd, address,
						&ptl);
			if(trigger_by_NCache(page_table)==1){
				return	ret|_try_switch_NCache(mm,vma,address, page_table,pmd,ptl, orig_pte,invalid);

			}
		}
		if(trigger_by_NCache(page_table)==1){
			////printk("triggerd by NCache\n");
			return	_try_switch_NCache(mm,vma,address, page_table,pmd,ptl, orig_pte,invalid);
		}
		if(((page_table->pte)&_PAGE_RSV)==0)
		  ret=-2;
		/*	if(page_table->pte&(_PAGE_COA<<3)){
			}*/
		pte_unmap_unlock(page_table,ptl);
		//printk("unlock at handle_double_cache_pte\n");
		return ret;
	}
struct vm_area_struct * find_vma_by_vfn(struct mm_struct *mm, unsigned long pfn)
{
	struct vm_area_struct *vma = NULL;

	if (mm) {
		vma = ACCESS_ONCE(mm->mmap_cache);
		if (!(vma &&(( vma->vm_end)>>PAGE_SHIFT) > pfn && ((vma->vm_start)>>PAGE_SHIFT) <= pfn)) {
			struct rb_node *rb_node;

			rb_node = mm->mm_rb.rb_node;
			vma = NULL;
			while (rb_node) {
				struct vm_area_struct * vma_tmp;

				vma_tmp = rb_entry(rb_node,
							struct vm_area_struct, vm_rb); 
				if ((( vma_tmp->vm_end)>>PAGE_SHIFT) > pfn) {
					vma = vma_tmp;
					if (((vma_tmp->vm_start)>>PAGE_SHIFT) <= pfn)
					  break;
					rb_node = rb_node->rb_left;
				} else
				  rb_node = rb_node->rb_right;
			}
			if (vma)
			  mm->mmap_cache = vma;
		}
	}

	return vma;
}
static int prefetch_next(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid){
	unsigned long next_address=address+PAGE_SIZE;
	pte_t * next_page_table, next_orig_pte;
	struct vm_area_struct * next_vma;
	if(sclock_control->debug>4)
	  write_trace(next_address>>PAGE_SHIFT,2);
	next_vma=find_vma_by_vfn(mm,next_address>>PAGE_SHIFT);
	if(!next_vma)
	{
		printk("no vma found\n");
		return 0;
	}
	pgd_t *	pgd = pgd_offset(mm, next_address);
	pud_t *	pud = pud_alloc(mm, pgd, next_address);
	if (!pud)
	  return 0;
	pmd = pmd_alloc(mm, pud, next_address);
	if(!pmd||pmd_none(*pmd))
	  return 0;
	next_page_table = pte_offset_map(pmd, next_address);
	if(!next_page_table){
		return 0;
	}
	if(!pte_present(*next_page_table)){
		return 0;
	}
	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	next_orig_pte=*next_page_table;
	//if(sclock_control->debug>5)
	  //printk("start to prefetch %lx for %s\n",next_address,mm->owner->comm);
	if(sclock_control->debug>4)
	  write_trace(next_address>>PAGE_SHIFT,1);
	handle_double_cache_pte_fault_one(mm,next_vma,next_address,next_page_table,pmd,ptl,next_orig_pte,invalid); 
	return 0;
}

static int prefetch_pte(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid)
{
		//if((mm->start_code<address)&& (mm->end_code>address)){
	if(strstr(mm->owner->comm,"run")!=NULL){
		return prefetch_next(mm,vma,address,page_table,pmd,ptl,orig_pte,invalid);
	}
	if(!(orig_pte.pte&_PAGE_NX))	{
		unsigned long next_address,ret=0,prefetch_results[MAXPREFETCH];
		int id;
		struct vm_area_struct * next_vma;
		unsigned long key_vpn[MAX_KEY];
		unsigned int key_id[MAX_KEY];
		struct file * file;
		char * p;
		char buf[IMAGE_NAME_LEN];

		unsigned long current_vpage=address>>PAGE_SHIFT,prefetch_offset;
		int i;
		struct prefetchForProcess* prefetch_map;

		pte_t * next_page_table,next_orig_pte;
		__get_cpu_var(global_ins_count)++;
		prefetch_map=find_prefetch_map(current->comm);
		if(prefetch_map==NULL)
		  return 0;
		file=vma->vm_file;
		if(!file)
		  return 0;

		memset(buf,0,IMAGE_NAME_LEN);
		p=d_path(&file->f_path,buf,IMAGE_NAME_LEN-1);
		if (IS_ERR(p)){
			printk("error path\n");
			return 0;
		}	
		if(sclock_control->debug>5)
		  printk("filename=%s\n",p);
		id=find_image_id_by_path(p,prefetch_map);
		if(id<1||id>prefetch_map->max_id){
			if(sclock_control->debug>5)
			  printk("id<1");
			return 0;
		}
		key_id[0]=id;
		key_vpn[0]=current_vpage-((find_base_address_by_vma(prefetch_map,vma,id))>>PAGE_SHIFT);
		if(current_vpage!=atomic64_read(&current->last_ins_page)){
			prefetch_offset=current_vpage-atomic64_read(&current->last_ins_page);
			atomic64_set(&current->prefetch_ins_page_offset,prefetch_offset);
			atomic_set(&current->prefetch_ins_count,id);
			atomic64_set(&current->last_ins_page,current_vpage);  
		}
		next_address=address;
		if((sclock_control->debug>4)){
			struct prefetch* prefetch;
			if(sclock_control->debug>5)
			  printk("see <%ld,%ld>",key_vpn[0],key_id[0]);
			__get_cpu_var(global_before_prefetch_count)++;
			if((prefetch=find_prefetches_by_map(prefetch_map,key_vpn,key_id))==NULL){
				if(sclock_control->debug>5)
				  printk("not found");
				return 0;
			}
			for(i=0;(i<MAXPREFETCH)&&(prefetch->vpn[i]>0);i++){
				unsigned long base_next=find_base_address_by_image_id(prefetch_map,mm,prefetch->id[i]);
				if(base_next==0){
				  if(sclock_control->debug>5)
					printk("not found image");
					return 0;
				}
				prefetch_results[i]=(prefetch->vpn[i]<<PAGE_SHIFT)+base_next;
				if(sclock_control->debug>5){
					printk("prefetch=<%ld,%ld>=%lx",prefetch->vpn[i],prefetch->id[i],prefetch_results[i]);
				}
				__get_cpu_var(global_all_prefetch_count)++;
				unsigned long long time1=get_rdtsc();
				if(prefetch_results[i]!=0){
					next_address=prefetch_results[i];
				}else{
					next_address=address+(1-2*i)*PAGE_SIZE;
				}
				if((vma->vm_end&PAGE_MASK)<next_address||(vma->vm_start&PAGE_MASK)>=next_address){
					next_vma=find_vma_by_vfn(mm,next_address>>PAGE_SHIFT);
				}
				else
				  next_vma=vma;
				if(!next_vma)
				{
					printk("no vma found\n");
					return 0;
				}
				pgd_t *	pgd = pgd_offset(mm, next_address);
				pud_t *	pud = pud_alloc(mm, pgd, next_address);
				if (!pud)
				  return 0;
				pmd = pmd_alloc(mm, pud, next_address);
				if(!pmd||pmd_none(*pmd))
				  return 0;
				next_page_table = pte_offset_map(pmd, next_address);
				if(!next_page_table){
					return 0;
				}
				if(pte_present(*next_page_table)){
					return 0;
				}
				ptl = pte_lockptr(mm, pmd);
				spin_lock(ptl);
				next_orig_pte=*next_page_table;
				if(sclock_control->debug>5)
				  printk("start to prefetch\n");
				ret|=handle_double_cache_pte_fault_one(mm,next_vma,next_address,next_page_table,pmd,ptl,next_orig_pte,invalid); 
				__get_cpu_var(global_prefetch_count)++;
				__get_cpu_var(global_prefetch)+=get_rdtsc()-time1;
			}

		}
	}
	return 0;

}

static int handle_double_cache_pte_fault(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid) 
{
	//__get_cpu_var(global_count)++;

	int	ret=handle_double_cache_pte_fault_one(mm,vma,address,page_table,pmd,ptl,orig_pte,invalid);
/*	if(((find_prefetch_map(mm->owner->comm)!=NULL)||(strstr(mm->owner->comm,"run")!=NULL))&&(sclock_control->debug>4)){
		write_trace(address>>PAGE_SHIFT,0);
	}
	if(!(sclock_control->debug>2))
	  return 0;
	return prefetch_pte(mm,vma,address,page_table,pmd,ptl,orig_pte,invalid);
*/
	return 0;
	}
static int handle_double_cache_pte_fault0(struct mm_struct *mm, struct vm_area_struct *vma,unsigned long address, pte_t *page_table, pmd_t *pmd, spinlock_t *ptl, pte_t orig_pte,bool invalid) 
{
	unsigned long next_address,ret=0;
	struct vm_area_struct * next_vma;
	pte_t * next_page_table,next_orig_pte;
	ret=handle_double_cache_pte_fault_one(mm,vma,address,page_table,pmd,ptl,orig_pte,invalid);
	if(!(sclock_control->debug>2))
	  return ret;
	long current_vpage=address>>PAGE_SHIFT,prefetch_offset;
	int i;
	if((mm->start_code<address)&& (mm->end_code>address)){
		if(current_vpage!=atomic64_read(&current->last_ins_page)){
			prefetch_offset=current_vpage-atomic64_read(&current->last_ins_page);
			if(atomic64_read(&current->prefetch_ins_page_offset)!=prefetch_offset){
				atomic64_set(&current->prefetch_ins_page_offset,prefetch_offset);
				atomic_set(&current->prefetch_ins_count,1);
			}else{
				atomic_inc(&current->prefetch_ins_count);
			}
			atomic64_set(&current->last_ins_page,current_vpage);  
		}
		next_address=address;
		if((sclock_control->debug>4)){
			for(i=0;i<atomic_read(&current->prefetch_ins_count);i++){
				next_address=next_address&PAGE_MASK+PAGE_SIZE*atomic64_read(&current->prefetch_ins_page_offset);
				if((vma->vm_end&PAGE_MASK)<next_address||(vma->vm_start&PAGE_MASK)>=next_address){
					unsigned long offset1=vma->vm_start-(vma->vm_start&PAGE_MASK),offset2=(vma->vm_end-(vma->vm_end&PAGE_MASK));
					next_address=next_address&PAGE_MASK+((offset1>offset2)?offset2:(offset1-1));
					next_vma=find_vma_by_vfn(mm,next_address>>PAGE_SHIFT);
				}
				else
				  next_vma=vma;
				next_page_table = pte_offset_map_lock(mm,pmd, address,&ptl);
				if(!next_page_table||pte_none(*next_page_table))
				  return 0;
				next_orig_pte=*next_page_table;
				ret|=handle_double_cache_pte_fault_one(mm,next_vma,next_address,next_page_table,pmd,ptl,next_orig_pte,invalid); 
			}
		}
	}
	return 0;
}
int handle_double_cache_mm_fault(struct mm_struct *mm,struct vm_area_struct* vma,unsigned long address,unsigned int flags){
	int ret;
	__set_current_state(TASK_RUNNING);
	count_vm_event(PGFAULT);
	mem_cgroup_count_vm_event(mm, PGFAULT);
	/* do counter updates before entering really critical section. */
	check_sync_rss_stat(current);
	if (flags & FAULT_FLAG_USER)
		  mem_cgroup_oom_enable();
		if(vma->vm_flags&VM_ISOLATION){
			ret=do_copy_on_read(mm,vma,address,flags);
		}else{
		//	ret=manage_cacheability(mm,vma,address,flags);
		}
		if (flags & FAULT_FLAG_USER) {
			mem_cgroup_oom_disable();
			/*
			 * The task may have entered a memcg OOM situation but
			 * if the allocation error was handled gracefully (no
			 * VM_FAULT_OOM), there is no need to kill anything.
			 * Just clean up the OOM state peacefully.
			 */
			if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
			  mem_cgroup_oom_synchronize(false);
		}
		return ret;
	}

