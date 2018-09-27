#include<linux/pid_namespace.h>
#include<linux/list.h>
#include<linux/myservice.h>
#include<linux/mm_types.h>
#include<linux/sched.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include<linux/kernel.h>
#include<linux/list.h>
#include <linux/freezer.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/bitops.h>
#include <linux/hugetlb.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/mmu_notifier.h>
#include <asm/tlbflush.h>
#include "internal.h"
#include <linux/swap.h>
#include <linux/ksm.h>
#include <linux/list_sort.h>
#include <linux/rbtree.h>
#include <linux/pagemap.h>
#include <linux/bitops.h>
#include <linux/swap.h>
#include <linux/cred.h>
#include <linux/rculist.h>
#include <linux/perf_event.h>
#include <linux/random.h>

extern struct list_head all_pid_ns_head;
static DEFINE_MUTEX(sclock_thread_mutex);
DECLARE_WAIT_QUEUE_HEAD(lru_thread_wait);
static DEFINE_MUTEX(lru_thread_mutex);
DECLARE_WAIT_QUEUE_HEAD(sclock_thread_wait);
struct anon_vma *page_trylock_anon_vma_read(struct page *page);

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
int k_dev_change(int k_dev){
	static int k_dev_change=0;
	if(k_dev>=0)
	  k_dev_change=k_dev;
	return k_dev_change;
}
static struct list_head * getElementInList(struct list_head* head,int n){
	if(n==1)
	  return head->next;
	return getElementInList(head->next,n-1); 
}


void update_daemon_para(bool change,int fixed,unsigned int t){
	if(!((useSClockDaemon(false)&&change)||((!useSClockDaemon(false)&&(!change)))))
	  useSClockDaemon(true);
	k_dev_change(fixed);
	sclock_control_op->set_sleep_microsec(t);
	printk(KERN_DEBUG" protection_level=%d,frequency = %u,dev=%d.\n",protection_level(0),sclock_thread_sleep_millisecs(0),k_dev_change(-1));

}
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



#define MAX_PTE_COPY 20
struct pte_map_vec{
	pte_t * pteps[MAX_PTE_COPY];
	struct vm_area_struct* vmas[MAX_PTE_COPY];
	unsigned long addrs[MAX_PTE_COPY];
	 spinlock_t* ptl[MAX_PTE_COPY];
};

pte_t *page_find_pte_nolock(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp, int sync)
{
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (unlikely(PageHuge(page))) {
		/* when pud is not present, pte will be NULL */
		pte = huge_pte_offset(mm, address);
		if (!pte)
			return NULL;

		goto check;
	}

	pmd = mm_find_pmd(mm, address);
	if (!pmd)
		return NULL;

	if (pmd_trans_huge(*pmd))
		return NULL;

	pte = pte_offset_map(pmd, address);
	/* Make a quick check before getting the lock */
	if (!sync && !pte_present(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

check:
//	spin_lock_irqsave(ptl);
	if (pte_present(*pte) && (page_to_pfn(page) == pte_pfn(*pte))) {
		return pte;
	}
//	pte_unmap_unlock(pte, ptl);
	return NULL;
}
 int get_anon_page_state(struct anon_vma ** anon_vmap,struct page* page, pteval_t flags,	struct pte_map_vec* pte_maps){
	struct anon_vma * anon_vma;
	int ret=0,count=0,count_accessed=0;
	struct anon_vma_chain *avc;
	pte_t* pte,pte_entry; 
	unsigned long address;
	pgoff_t pgoff;
	struct mm_struct * mm;
	struct task_struct * task;
	struct pid_namespace* pid_ns=NULL,tmp_ns; 
	struct vm_area_struct *vma;
	anon_vma=page_trylock_anon_vma_read(page);
	if (!anon_vma){
	*anon_vmap=NULL;
		return ret;
	}
	pgoff=page->index<<(PAGE_CACHE_SHIFT-PAGE_SHIFT);
	anon_vma_interval_tree_foreach(avc,&anon_vma->rb_root,pgoff,pgoff){
		vma=avc->vma;
		if(vma){
			if((mm=vma->vm_mm)&&(task=mm->owner)){
				address = page_address_in_vma(page, vma);
				spinlock_t *ptl;
			//	printk("page_check\n");
				pte = page_find_pte_nolock(page, mm, address, &ptl, 0); 
				//	page_unmap_unlock(pte,ptl);
				if(pte){
					if(pte_present(*pte)&&pte_page(*pte)==page){
				/*		if(pte->pte&_PAGE_DIRTY){
							return -1;
						}*/
						if(pte->pte&flags){
							count=0;
							pte->pte&=~flags;
							count_accessed++;
							pte_maps->pteps[0]=pte;
							pte_maps->vmas[0]=vma;
							pte_maps->addrs[0]=address;
							pte_maps->ptl[0]=ptl;
							goto unlock;
						}else{
							if(count>MAX_PTE_COPY){
								count=0;
								goto unlock;
							}
							pte_maps->pteps[count]=pte;
							pte_maps->vmas[count]=vma;
							pte_maps->addrs[count]=address;
							pte_maps->ptl[count]=ptl;
							count++;
						}

					}
				}
			}
		}
	}
unlock:	
	*anon_vmap=anon_vma;
	//	page_unlock_anon_vma_read(anon_vma);
	return count_accessed==0?count:0;
}
 int get_file_page_state(struct page* page,unsigned long flags,	struct pte_map_vec* pte_maps){
	struct vm_area_struct *vma;
	unsigned long address;
	int count=-1;
	pte_t * pte;

	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	//printk("file\n");
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);
	i_mmap_lock_read(mapping);
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff){
		if(vma){
			address = page_address_in_vma(page, vma);
			spinlock_t *ptl;
			//	printk("page_check\n");
			pte = page_find_pte_nolock(page, vma->vm_mm, address, &ptl, 0); 
			if(pte){
					if(pte_present(*pte)&&pte_page(*pte)==page){
				/*	if(pte->pte&_PAGE_DIRTY){
						count=-2;
						continue;
					}*/
					if(pte->pte&flags){
						count=-1;
						pte->pte&=~flags;
						continue;
					}else if(count>-1){
						if(count>MAX_PTE_COPY){
							count=0;
							goto unlock;
						}
						pte_maps->pteps[count]=pte;
						pte_maps->vmas[count]=vma;
						pte_maps->addrs[count]=address;
						pte_maps->ptl[count]=ptl;
						count++;
					}
				}
			}
		}
	}
unlock:
	i_mmap_unlock_read(mapping);
	return count>0?count:(count+1);

}
 int get_ksm_page_state(struct page* page,unsigned long flags,	struct pte_map_vec* pte_maps){
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
	int count=-1;
	stable_node = page_stable_node(page);
	if (!stable_node)
	  return -1;
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		anon_vma = rmap_item->anon_vma;
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					0, ULONG_MAX) {
			vma = vmac->vma;
			address= page_address_in_vma(page, vma);
			spinlock_t *ptl;
			pte = page_find_pte_nolock(page, vma->vm_mm, address, &ptl, 0); 
			if(pte){
					if(pte_present(*pte)&&pte_page(*pte)==page){
				/*	if(pte->pte&_PAGE_DIRTY){
						count=-1;
						goto unlock;
					}*/
					if(pte->pte&flags){
						count=0;
						pte->pte&=~flags;
						goto unlock;
					}else{
						if(count>MAX_PTE_COPY){
							count=0;
							goto unlock;
						}
						pte_maps->pteps[count]=pte;
						pte_maps->vmas[count]=vma;
						pte_maps->addrs[count]=address;
						pte_maps->ptl[count]=ptl;
						count++;
					}
				}
			}
		}
		anon_vma_unlock_read(anon_vma);
	}
	return count;
unlock:	
	anon_vma_unlock_read(anon_vma);
	return count;
#endif
}
  int get_anon_copy_page_state(struct anon_vma ** anon_vma, struct page* page, pteval_t flags,	struct pte_map_vec* pte_maps){
	return get_anon_page_state(anon_vma,page,flags,pte_maps);
}

int get_copy_page_state(struct anon_vma ** anon_vma,struct page* page,pteval_t flags,struct pte_map_vec* pte_maps){
	if(page_mapped(page)&&page_rmapping(page)){
		if(PageKsm(page)){
			return -1;
			//	return get_ksm_copy_page_state(page,flags);
		}else if(PageAnon(page)){
			return get_anon_copy_page_state(anon_vma,page,flags,pte_maps);
		}
		else if(page_mapping(page)){
			return -1;
		}
	}
	return -1;
}
static int find_vma_links(struct mm_struct *mm, unsigned long addr,
		unsigned long end, struct vm_area_struct **pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			/* Fail if an existing vma overlaps the area */
			if (vma_tmp->vm_start < end)
				return -ENOMEM;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
	  *pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return 0;
}
void clean_links(struct mm_struct *mm, unsigned long addr,
			unsigned long end, struct vm_area_struct **pprev,
			struct rb_node ***rb_link, struct rb_node **rb_parent){

}
int remap_tofilesource(struct page* source,unsigned long address,struct vm_area_struct *vma,struct vm_area_struct **new_vma){
	struct mm_struct * mm=vma->vm_mm;
	struct vm_area_struct *vma_tmp, *prev;
	struct rb_node **rb_link, *rb_parent;
	int ret=-1;
	unsigned long addr_tmp;
	pte_t pte_tmp;
	unsigned long flags;
	struct address_space *mapping = source->mapping;
	pgoff_t pgoff = source->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	//printk("file\n");
	if (PageHuge(source))
	  pgoff = source->index << compound_order(source);
	i_mmap_lock_read(mapping);
	vma_interval_tree_foreach(vma_tmp, &mapping->i_mmap, pgoff, pgoff){
		if(vma_tmp){
			if(vma_tmp->vm_file&&page_mapped_in_vma(source,vma_tmp)){
				i_mmap_unlock_read(mapping);
		//		try_to_unmap_one(page,vma,address,TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
				ret=mmap_region_to_mm(mm,vma,new_vma,vma_tmp->vm_file,address&PAGE_MASK,PAGE_SIZE,vma->vm_flags|mm->def_flags|VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC,pgoff);
				if(ret!=address&PAGE_MASK){
					printk("change virtual address\n");
					return -1;
				}
				if(*new_vma==NULL){
				  *new_vma=vma;
				  printk("failed new vma\n");
				  return -1;
				}
				ret=0;
				return ret;	
			}
		}
	}
	i_mmap_unlock_read(mapping);
	return ret;
}
int cow_page(struct vm_area_struct *vma, struct page *page,
		pte_t *orig_pte)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr;
	pte_t *ptep;
	spinlock_t *ptl;
	int swapped;
	int err = -EFAULT;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */
	addr = page_address_in_vma(page, vma);
	if (addr == -EFAULT)
		goto out;
	BUG_ON(PageTransCompound(page));
	mmun_start = addr;
	mmun_end   = addr + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);
	ptep = page_check_address(page, mm, addr, &ptl, 0);
	if (!ptep)
		goto out_mn;
	if (pte_write(*ptep) || pte_dirty(*ptep)) {
		pte_t entry;

		swapped = PageSwapCache(page);
		flush_cache_page(vma, addr, page_to_pfn(page));
		/*
		 * Ok this is tricky, when get_user_pages_fast() run it doesn't
		 * take any lock, therefore the check that we are going to make
		 * with the pagecount against the mapcount is racey and
		 * O_DIRECT can happen right after the check.
		 * So we clear the pte and flush the tlb before the check
		 * this assure us that no O_DIRECT can happen after the check
		 * or in the middle of the check.
		 */
		entry = ptep_clear_flush(vma, addr, ptep);
		/*
		 * Check that no O_DIRECT or similar I/O is in progress on the
		 * page
		 */
		if (page_mapcount(page) + 1 + swapped != page_count(page)) {
			set_pte_at(mm, addr, ptep, entry);
			printk("not consist mapcount\n");		
			dump_page(page);
			goto out_unlock;
		}
		if (pte_dirty(entry))
			set_page_dirty(page);
		entry = pte_mkclean(pte_wrprotect(entry));
		set_pte_at_notify(mm, addr, ptep, entry);
	}
	*orig_pte = *ptep;
	err = 0;

out_unlock:
	pte_unmap_unlock(ptep, ptl);
out_mn:
	mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
out:
	return err;
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


int replace_anon_page(struct vm_area_struct * vma, unsigned long address,pte_t* ptep,spinlock_t * ptl,struct page* page,struct page* source){
	struct mm_struct * mm=vma->vm_mm;
	pte_t entry,orig_pte;
	pmd_t *pmd;
	struct vm_area_struct * new_vma;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */
	unsigned long err=-1;
	bool was_mapped=false;
	//printk("before:page%lx counter=%d,map_count=%d\n",page,atomic_read(&page->_count),page_mapcount(page));
	pmd = mm_find_pmd(mm, address);
	if (!pmd)
	  goto out;
	BUG_ON(pmd_trans_huge(*pmd));
	orig_pte=*ptep;
	if(!trylock_page(page)){
		return err;
	}
	if(cow_page(vma,page,&orig_pte)){
		  goto unlock_before_ptelock;
	}
/*	if(PageAnon(source)){
		if(!trylock_page(source))
		  goto unlock_before_ptelock;
		printk("anon \n");
		err=0;
	}*/	
	mmun_start = address;
	mmun_end   = address + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	if(pte_page(*ptep)!=page||!pte_same(*ptep,orig_pte)){
		goto after;
	}

	if(!err){
use:
		flush_cache_page(vma, address, pte_pfn(*ptep));
		ptep_clear_flush(vma, address, ptep);
		//	if(PageTail(source)&&compound_head(source)==NULL)
		//	  goto after;
		entry=mk_pte(source, vma->vm_page_prot);
		entry.pte|=_PAGE_ISOLATION;
		entry.pte&=~_PAGE_RW;
		page_cache_get(source);
		page_add_anon_rmap_lock(source, vma, address);
		set_pte_at_notify(mm, address, ptep, entry);
		page_remove_rmap(page);
		err=0;
		if (!page_mapped(page)){
			try_to_free_swap(page);
		}
		
//				printk("after: source%lx counter=%d,map_count=%d\n",source,atomic_read(&source->_count),page_mapcount(source));
	}
after:
	pte_unmap_unlock(ptep, ptl);
	if(mmun_start<mmun_end)
	  mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);

/*	if ((vma->vm_flags & VM_LOCKED)) {
		munlock_vma_page(page);
		if (!PageMlocked(source)) {
			unlock_page(page);
			lock_page(source);
			mlock_vma_page(source);
			unlock_page(source);
		}else
		  unlock_page(page);
	}else*/
	//unlock_page(source);
unlock_before_ptelock:
	unlock_page(page);
	if(!err&&was_mapped){
		inc_page_counter_in_ns(source,vma);
		dec_page_counter_in_ns(page,vma);
		put_page(page);
	}
out:
	return err;

}
int replace_file_page(struct vm_area_struct * vma, unsigned long address,pte_t* ptep,spinlock_t * ptl,struct page* page,struct page* source){
	struct mm_struct * mm=vma->vm_mm;
	pte_t entry,orig_pte;
	pmd_t *pmd;
	bool was_mapped=false;
	struct vm_area_struct * new_vma;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */
	unsigned long err=-1;
	//printk("before:page%lx counter=%d,map_count=%d\n",page,atomic_read(&page->_count),page_mapcount(page));
	//orig_pte=*ptep;
	if(pte_page(*ptep)!=page)
	{
		return err;
	}
	if(!trylock_page(page)){
		return err;
	}
	if(cow_page(vma,page,&orig_pte)){
		goto out;
	}
	  
	mmun_start = address;
	mmun_end   = address + PAGE_SIZE;
	mmu_notifier_invalidate_range_start(mm, mmun_start, mmun_end);
	pmd = mm_find_pmd(mm, address);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))){
		goto out;
	}
	if (pmd_trans_huge(*pmd))
	  goto out;
	
	ptep = pte_offset_map_lock(mm, pmd, address,&ptl);
	/* Make a quick check before getting the lock */
	if (!pte_present(*ptep)) {
		pte_unmap_unlock(ptep,ptl);
		goto out;
	}
	if(pte_page(*ptep)!=page||!pte_same(*ptep,orig_pte)){
		goto after;
	}

	if(page_mapping(source)){
		//	printk("before: source%lx counter=%d,map_count=%d\n",source,atomic_read(&source->_count),page_mapcount(source));
		//	get_page(source);
		pte_unmap_unlock(ptep, ptl);

		unlock_page(page);
		if(	remap_tofilesource( source,address,vma,&new_vma)){
			printk("failed\n");
			goto out;
		}

		//	dump_page(page);
		//lock_page(page);
		//	printk("vma=%lx, start=%lx,end=%lx,new_vma=%lx,start=%lx,end=%lx",vma,vma->vm_start,vma->vm_end,new_vma,new_vma->vm_start,new_vma->vm_end);
		//vma=find_vma(mm,address);
		vma=new_vma;
		//printk("vma=%lx",vma);
		err=0;
		pmd = mm_find_pmd(mm, address);
		if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))){
			goto out;
		}
		if (pmd_trans_huge(*pmd))
		  goto out;
		ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	}else
	  unlock_page(page);
	if(!err){
use:
		if(PageTail(source)&&compound_head(source)==NULL)
		  goto after;
		entry=mk_pte(source, vma->vm_page_prot);
		entry=pte_mkold(entry);
		entry.pte|=_PAGE_ISOLATION;
		page_cache_get(source);
		flush_cache_page(vma, address, pte_pfn(*ptep));
		page_add_file_rmap(source);
		inc_mm_counter_fast(mm, MM_FILEPAGES);
		ptep_clear_flush(vma, address, ptep);
		//		entry.pte&=~_PAGE_RW;
		set_pte_at_notify(mm, address, ptep, entry);
		update_mmu_cache(vma, address, ptep);
		//	page_remove_rmap(page);
		was_mapped=true;
		if (!page_mapped(page)){
			try_to_free_swap(page);
		}
	}
after:
	pte_unmap_unlock(ptep, ptl);
//	if(!err)
//	printk("after: source%lx counter=%d,map_count=%d,is mapped=%d\n",source,atomic_read(&source->_count),page_mapcount(source),page_mapped_in_vma(source,vma));
	if(mmun_start<mmun_end)
	  mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
	if(!err&&was_mapped){
		inc_page_counter_in_ns(source,vma);
		//put_page(page);
	}
out:

	return err;
}
int replace_same_page(struct vm_area_struct *vma, struct page *page,
			struct page *source, pte_t orig_pte)
{
	struct mm_struct *mm = vma->vm_mm;
	pmd_t *pmd;
	pte_t *ptep,entry;
	spinlock_t *ptl;
	unsigned long address;
	int err = -EFAULT;
	address = page_address_in_vma(page, vma);
	if (address == -EFAULT)
	  return -1;
	/*pmd = mm_find_pmd(mm, address);
	if (!pmd)
	  return -1;
	BUG_ON(pmd_trans_huge(*pmd));
	ptl = pte_lockptr(mm, pmd);
	ptep = pte_offset_map(pmd, address);
	if(pte_page(*ptep)!=page){
		return -1;
	}*/
	if(PageKsm(source)){
		return -1;
	}else if(PageAnon(source)){
		return replace_anon_page(vma,address,&orig_pte,ptl,page,source);
	}else if(page_mapping(source)){
		if(mapping_mapped(page_mapping(source))&&!PageSwapCache(source))
		  return replace_file_page(vma,address,&orig_pte,ptl,page,source);
	}

	return -1;
}
int replace_page_via_one_pte(struct vm_area_struct * vma, unsigned long address,pte_t* ptep,spinlock_t * ptl,struct page* page,struct page* source){
	if(PageKsm(source)){
		return -1;
	}else if(PageAnon(source)){
		return replace_anon_page(vma,address,ptep,ptl,page,source);
	}else if(page_mapping(source)){
		if(mapping_mapped(page_mapping(source))&&!PageSwapCache(source))
		  return replace_file_page(vma,address,ptep,ptl,page,source);
	}
	return -1;
}

static int sclockd_should_run(int request)
{
	int ret=useSClockDaemon(false);
	if(request&request_coa){
		ret|=(update_isolation_mode(0)>0);
	}
	if(request&request_lru){
		ret|=1;
	}
	return ret;
}

static unsigned long scan_parent_page(void){
	struct pid_namespace* pid_ns;
	struct sclock_coa_children * coa_children,*tmp_children;
	struct sclock_coa_parent* coa_parent,*tmp_parent;
	struct page * page,*source=NULL,*last_page=NULL;
	struct vm_area_struct* vma;
	 spinlock_t* ptl;
	 unsigned long pfn,orig_pfn,local_pfn;
	 int coa_time=0;
	 struct list_head* parent_head;
	 int i,count,ret=0;
	 unsigned long err;
	 pte_t orig_pte,*ptep;
	 unsigned long flags;
	 	//
//	printk("start scan parent and copy\n");
		mutex_lock(&all_coa_parent_head_lock);
	 list_for_each_entry_safe(coa_parent,tmp_parent,parent_page_headp,node){
		 // cond_resched();
		 if(!sclockd_should_run(request_coa)){
			 return ret;
		 }
		 source=NULL;
		 coa_list_lock(coa_parent);
		 pfn=coa_parent->pfn;
		 //if(pfn!=orig_pfn)
		 if(pfn_valid(pfn)){
		 coa_parent->owner=NULL;
		 }
		 coa_list_unlock(coa_parent);
	 }
	 mutex_unlock(&all_coa_parent_head_lock);
}
void del_coa_parent_slow(struct sclock_coa_parent* coa_entry){
	struct sclock_coa_children *coa_entry2,* tmp_entry;
	struct page* successor_page;
	struct list_head* head=&coa_entry->head,*successor;
	int *copy;
	bool no_nice_successor=true;
	coa_entry->pfn=COA_SKIP;
	if(get_copy_num(coa_entry)>0){
		coa_entry2=list_entry(head->next,struct sclock_coa_children,head);
		successor=head->next;
		list_for_each_entry_safe(coa_entry2,tmp_entry,&coa_entry->head,head){
			if(pfn_valid(coa_entry2->pfn)){
				no_nice_successor=false;
				goto successor;
			}
			if(get_copy_num(coa_entry)<=0)
			  goto nocopy;
		}
		coa_entry->pfn=COA_NO_HEAD;
		if(!no_nice_successor){
successor:
			successor_page=pfn_to_page(coa_entry2->pfn);
			successor_page->coa_head=head;//change pointer
			coa_entry->pfn=coa_entry2->pfn;
			coa_entry->owner=coa_entry2->owner;
			coa_entry2->pfn=COA_DEL;
		}

	}else{
nocopy:
		coa_entry->pfn=COA_DEL;
	}

}
void del_original_slow(struct page * page){
	struct sclock_coa_parent* coa_entry;
	page->coa_head=NULL;
	struct list_head* head=page->coa_head;
	if(head!=NULL){
		coa_entry=list_entry(head,struct sclock_coa_parent,head);
		del_coa_parent_slow(coa_entry);
	}
}
static int max_merge=20;
static unsigned long  scan_children_copy(void){
	struct pid_namespace* pid_ns;
	struct sclock_coa_children * coa_children,*tmp_children;
	struct sclock_coa_parent* coa_parent,*tmp_parent;
	struct page * page,*source=NULL,*last_page=NULL;
	struct vm_area_struct* vma;
	 spinlock_t* ptl;
	 unsigned long pfn,orig_pfn,local_pfn;
	 int coa_time=0;
	 struct list_head* parent_head;
	 int i,count,ret=0;
	 unsigned long err;
	 pte_t orig_pte,*ptep;
	 unsigned long flags;
	 	//
//	printk("start scan parent and copy\n");
		mutex_lock(&all_coa_parent_head_lock);
	 list_for_each_entry_safe(coa_parent,tmp_parent,parent_page_headp,node){
		 // cond_resched();
		 if(!sclockd_should_run(request_coa)){
			 return ret;
		 }
		 source=NULL;
		 coa_list_lock(coa_parent);
retry:
		 pfn=coa_parent->pfn;
		 //if(pfn!=orig_pfn)
		 if(pfn_valid(pfn)){
			 source =pfn_to_page(pfn);
		 }else{
			 switch(pfn){
				 case COA_SKIP:
					 goto next_source;
				 case COA_DEL:
					 if(get_copy_num(coa_parent)>0){
						 goto bad_head;
					 }
					 list_del(&coa_parent->node);
					 coa_list_unlock(coa_parent);
					 coa_parent_free(coa_parent);
					 continue;
					 break;
				 case COA_NO_HEAD:
					 goto bad_head;
					 break;
				 default:
					 goto next_source;
			 }
			 goto next_source;
		 }
		 if(source->coa_head!=&coa_parent->head){
bad_head:
		//	 printk("bad head for %lx\n",pfn);
			 ret++;
			 del_coa_parent_slow(coa_parent);
			 if(pfn_valid(coa_parent->pfn)){
				 goto retry;

			 }else if(coa_parent->pfn!=COA_NO_HEAD){
				 goto next_source;
			 }
		 }
		 struct pte_map_vec original_pte_maps;
		 if((get_copy_num(coa_parent)<=0)&&(!isContainerSharedPage(source))){
			 del_original_slow(source);
			 //	printk(KERN_ALERT"remove unshared original\n");
			 source->flags&=~PG_isolation;//exclusive
			 ret++;
			 list_del_init(&coa_parent->node);
			 coa_list_unlock(coa_parent);
			 coa_parent_free(coa_parent);
			 continue;
			 //	 goto next_source;
		 }
		 orig_pfn=coa_parent->pfn;
		 coa_list_unlock(coa_parent);

scan_chlidren:
		 last_page=NULL;
		 pid_ns=NULL;
		 coa_list_unlock(coa_parent);
		 if((source!=NULL)&& get_copy_num(coa_parent)>0){
			 //	printk("try original=%lx,copy=%d\n",pfn,get_copy_num(coa_parent));
			 tmp_children=list_entry(coa_parent->head.next,struct sclock_coa_children,head);
			 while((&tmp_children->head!=&coa_parent->head)&&(tmp_children->parent_head==&coa_parent->head)){
				 
				 struct anon_vma * anon_vmap=NULL;
				 
				 struct pte_map_vec pte_maps;
				 coa_children=tmp_children;
				 if(!sclockd_should_run(request_coa)){
					 coa_list_unlock(coa_parent);
					 goto out;
				 }
				 pfn=coa_children->pfn;
				 if(pfn==COA_SKIP)
				   goto next_children_lock;
				 if(pfn==COA_DEL){
					 goto del_one_copy_lock;
				 }
				 coa_children->pfn=COA_SKIP;//avoid other use;
				 coa_list_unlock(coa_parent);
				 page=pfn_to_page(pfn);
				 if(page->coa_head!=&coa_children->head){
					 goto del_one_copy;
				 }
				 if(!page_mapped(page)){
					 goto del_one_copy;
				 }
				 count=get_copy_page_state(&anon_vmap,page,_PAGE_ACCESSED,&pte_maps);
				 switch(count){
					 case -1:
del_one_copy:
						 coa_list_lock(coa_parent);
						 page->coa_head=NULL;
del_one_copy_lock:
						 if(anon_vmap){
							 page_unlock_anon_vma_read(anon_vmap);
						//printk("unlock aon vma=%lx at page=%lx",anon_vmap,page);  
							 anon_vmap=NULL;
						 }
						 tmp_children=list_entry(coa_children->head.next,struct sclock_coa_children,head);
						 list_del_init(&coa_children->head);
						 //		unlock_page(source);
						 dec_copy_num(coa_parent);
						 coa_children_free(coa_children);
						 //printk("del one children%lx from %lx\n",coa_children->pfn,coa_parent->pfn);
						 break;
					 case 0:
						 coa_children->pfn=pfn;
						 if(anon_vmap){
							 page_unlock_anon_vma_read(anon_vmap);
						 //printk("unlock aon vma=%lx at page=%lx",anon_vmap,page);
							 anon_vmap=NULL;
						 }

						 goto next_children;
						 break;
						 //		printk("try count=%d, for pfn=%lx,source=%lx,anon=%d\n",count,pfn,page_to_pfn(source),PageAnon(source));
						 //mutex_lock(&(coa_parent->lock));
						 /*if(pid_ns&&(pid_ns==coa_children->owner)){//same-source copy for same pid_ns, merge them
							 if(!pages_identical(last_page,page)){
								last_page=page;
								 goto next_children;
								 break;
							 }
							 printk("merge same pid_ns\n");
							 vma=pte_maps.vmas[0];
							 orig_pte=*(pte_maps.pteps[0]);
							 err=replace_same_page(vma,page,last_page,orig_pte);	
							 source=last_page;
							 if(!err){
								 last_page=page;
								 goto del_one_copy;
								 break;
							 }
						 }
						 pid_ns=coa_children->owner;
						 last_page=page;
						 break;*/
					 case 1:
						 ret++;
						 //	source=NULL;
						 ptep=pte_maps.pteps[0];
						 if(ptep)
						   orig_pte=*(ptep);
						 //	printk("merge\n");
						 ptl=pte_maps.ptl[0];
						 vma=pte_maps.vmas[0];
						 struct mm_struct *mm=vma->vm_mm;
						// down_read(&mm->mmap_sem);
					/*	 if(coa_parent->pfn!=orig_pfn){
							 up_read(&mm->mmap_sem);
							 goto next_source_nolock;
						 }
						 */if(!pages_identical(source,page)){
							 //	spin_unlock_irqrestore(&(get_original(coa_parent)->lock),flags);
							 //up_read(&mm->mmap_sem);
							 goto del_one_copy;
							 }
						 //printk("try count=%d, for pfn=%lx,source=%lx,anon=%d,map_count=%d,count=%d====>",count,pfn,page_to_pfn(source),PageAnon(source),page_mapcount(page),atomic_read(&page->_count));
						 if(anon_vmap){
							 page_unlock_anon_vma_read(anon_vmap);
							 //printk("unlock aon vma=%lx at page=%lx",anon_vmap,page);          
							 anon_vmap=NULL;
						 }
							 err=replace_same_page(vma,page,source,orig_pte);			
						 
						 //	 printk("map_count=%d,count=%d\n",page_mapcount(page),atomic_read(&page->_count));
						 // up_read(&mm->mmap_sem);
							 if(!err){
								 /*clflush_all(kmap(source),PAGE_SIZE);
								   kunmap(source);
								   */ goto del_one_copy;
							 }
							 break;
					 default:
							 ret++;
							 //	source=NULL;
							 err=0;
							 if(!pages_identical(source,page)){
								 goto del_one_copy;
							 }
							 //printk("try count=%d, for pfn=%lx,source=%lx,anon=%d,map_count=%d,count=%d====>",count,pfn,page_to_pfn(source),PageAnon(source),page_mapcount(page),atomic_read(&page->_count));

							 if(anon_vmap){
								 page_unlock_anon_vma_read(anon_vmap);
								 anon_vmap=NULL;  
							 }
							 for(i=0;i<count;i++){
								 ptep=pte_maps.pteps[i];
								 orig_pte=*(ptep);
								 ptl=pte_maps.ptl[i];
								 vma=pte_maps.vmas[i];
								 struct mm_struct *mm=vma->vm_mm;
								 //down_read(&mm->mmap_sem);
								 err+=replace_page_via_one_pte(vma,pte_maps.addrs[i],ptep,ptl,page,source);
								 //up_read(&mm->mmap_sem);
								 //	 printk("map_count=%d,count=%d\n",page_mapcount(page),atomic_read(&page->_count));

							 }
							 if(!err){
								 /* clflush_all(kmap(source),PAGE_SIZE);
									kunmap(source);
							*/ goto del_one_copy;
						 }
next_children:
						 coa_list_lock(coa_parent);
next_children_lock:
						 tmp_children=list_entry(coa_children->head.next,struct sclock_coa_children,head);
						 break;
				 }
				 
			 }
		 }
next_source:
		 coa_list_unlock(coa_parent);
	 }
out:
	 mutex_unlock(&all_coa_parent_head_lock);
	 return ret;
}
static int page_acessed_one(struct page* page, struct vm_area_struct * vma, unsigned long address,int * mapcount,unsigned long * vm_flags){
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	int referenced = 0;
	unsigned long flags;
	pte_t *pte;

	/*
	 * rmap might return false positives; we must filter
	 * these out using page_check_address().
	 */
	pte=page_check_address(page, mm, address, &ptl, 0);
//	pte =page_find_pte_nolock(page, mm, address, &ptl, 0);
	if (!pte)
	  goto out;
	if (vma->vm_flags & VM_LOCKED) {
		*mapcount = 0;	/* break early from loop */
		*vm_flags |= VM_LOCKED;
		pte_unmap_unlock(pte, ptl);	
		goto out;
	}

	/*
	 * Don't treat a reference through a sequentially read
	 * mapping as such.  If the page has been used in
	 * another mapping, we will catch it; if this other
	 * mapping is already gone, the unmap path will have
	 * set PG_referenced or activated the page.
	 */
	if(pte->pte&_PAGE_ACCESSED){
		pte->pte&=~_PAGE_ACCESSED;
	//	flush_tlb_page(vma,address);
		if (likely(!(vma->vm_flags & VM_SEQ_READ)))
		  referenced++;
	}
	pte_unmap_unlock(pte, ptl);
	(*mapcount)--;

	if (referenced)
	  *vm_flags |= vma->vm_flags;
out:
	return referenced;
}
static int do_ksm_accessed(struct page* page,int pid_ns_level){
#ifndef CONFIG_KVM
	return -1;
#else
	struct stable_node *stable_node;
	struct rmap_item *rmap_item;
	pte_t* pte,pte_entry;
	int ret=0;	
	struct mm_struct * mm;
	struct task_struct * task;
	unsigned long address;
	unsigned long vm_flags;
	unsigned	int mapcount;
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
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(ns_of_pid(task_pid(task))->level>=pid_ns_level){
				  address = page_address_in_vma(page, vma);
				  ret+=page_acessed_one(page,vma,address,&mapcount,&vm_flags);
			  }
		}	
		anon_vma_unlock_read(anon_vma);
	}
	return ret;
#endif
}
static int do_file_accessed(struct page* page,int pid_ns_level){
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	int ret=0;	struct vm_area_struct *vma;
	unsigned long address;
	struct mm_struct * mm;
	struct task_struct * task;
	pte_t* pte,pte_entry; 
	unsigned long vm_flags;
	unsigned long irqflags;
	unsigned	int mapcount=page_mapcount(page);
	//printk("file\n");
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);

	if(!i_mmap_trylock_read(mapping)){
		return page_mapcount(page);
	}
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		if(vma){
			struct mm_struct * mm;
			struct task_struct * task;
			mm=vma->vm_mm;
			if(mm!=NULL){
				task=mm->owner;
				if(task!=NULL)
				  if(ns_of_pid(task_pid(task))->level>=pid_ns_level){
					  address =vma_to_address(page, vma);
					  ret+=page_acessed_one(page,vma,address,&mapcount,&vm_flags);
					  if(!mapcount)
						break;
				  }
			}
		}
	}
i_mmap_unlock_read(mapping);
	return ret;
}
struct anon_vma *page_trylock_anon_vma_read(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	struct anon_vma *root_anon_vma;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long) ACCESS_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
	  goto out;
	if (!page_mapped(page))
	  goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);

	root_anon_vma = ACCESS_ONCE(anon_vma->root);
	if(!root_anon_vma)
	  return NULL;
	if (down_read_trylock(&root_anon_vma->rwsem)) {
		/*
		 *		 * If the page is still mapped, then this anon_vma is still
		 *				 * its anon_vma, and holding the mutex ensures that it will
		 *						 * not go away, see anon_vma_free().
		 *								 */
		if (!page_mapped(page)) {
			up_read(&root_anon_vma->rwsem);
			anon_vma = NULL;
		}
		goto out;
	}else{
		anon_vma = NULL;
	}

out:
	rcu_read_unlock();
	return anon_vma;
}
static int do_anon_accessed(struct page* page,int pid_ns_level){
	struct anon_vma * anon_vma;
	int ret=0;
	struct anon_vma_chain *avc;
	pte_t* pte,pte_entry; 
	unsigned long address;
	pgoff_t pgoff;
	struct mm_struct * mm;
	unsigned long vm_flags;
	unsigned	int mapcount;
	struct task_struct * task;
	struct vm_area_struct *vma;
	//printk("anon\n");

	anon_vma=page_trylock_anon_vma_read(page);
	if (!anon_vma){
		ret=page_mapcount(page);
		return ret;
	}
	pgoff=page->index<<(PAGE_CACHE_SHIFT-PAGE_SHIFT);
	anon_vma_interval_tree_foreach(avc,&anon_vma->rb_root,pgoff,pgoff){
		vma=avc->vma;
		if(vma){
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(ns_of_pid(task_pid(task))->level>=pid_ns_level){
				  address = page_address_in_vma(page, vma);
				  ret+=page_acessed_one(page,vma,address,&mapcount,&vm_flags);
			  }
		}
	}
unlock:	page_unlock_anon_vma_read(anon_vma);
		return ret;
}

int do_page_count_accessed(struct page* page,int pid_ns_level){
	int reference=0;
	int we_locked=0;
	if(page){
		if(page_mapped(page)&& page_rmapping(page)){
			if ( (!PageAnon(page) || PageKsm(page))) {
				we_locked = trylock_page(page);
				if (!we_locked) {
					return 1;
				}
				if(PageKsm(page)){
					reference= 	do_ksm_accessed(page,pid_ns_level);
				}else if(PageAnon(page)){
					reference+= 	do_anon_accessed(page,pid_ns_level);
				}
				else if(page_mapping(page)){
					reference+= do_file_accessed(page,pid_ns_level);		
				}
				if (we_locked)
				  unlock_page(page);
			}
		}
	}
	return reference;

}
int do_lru_count_accessed(struct sclock_LRU* sclock_entry,int pid_ns_level){
	struct page* page;
	page=pfn_to_page(sclock_entry->pfn);
	if(page_mapped(page)&& page_rmapping(page)){
		if(PageKsm(page)){
			return 	do_ksm_accessed(page,pid_ns_level);
		}else if(PageAnon(page)){
			return 	do_anon_accessed(page,pid_ns_level);
		}
		else if(page_mapping(page)){
			return do_file_accessed(page,pid_ns_level);		
		}
	}
}
static unsigned int daemon_times=0;
static int generate_k(void){
	int k;
	unsigned int  dividors=0;
	unsigned int number;
	get_random_bytes(&number,sizeof(unsigned int));
	number=number%sclock_control->Prob.total;
	for(k=0;k<ASSOCIATIVITY+1;k++){
		dividors=dividors+sclock_control->Prob.map[k];
		if(number<dividors)
		  return k+1;
	}
	return -1;
}
void do_sclock_lru_trim(unsigned int i, struct pid_namespace * pid_ns){
	unsigned long flags;
	struct list_head * lru_head;
	struct sclock_LRU *sclock_entry;
	struct page * page;
	while(true){
		spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
		if((atomic_read(&(pid_ns->sclock_lru_counter[i])))*sclock_control->debug<=get_k_of_ns(pid_ns))
		  break;
		lru_head=&(pid_ns->sclock_lru[i]);
		if(list_empty(lru_head)){
			set_k_of_ns(pid_ns,get_k_of_ns(pid_ns)+1);
			printk("abnormal list empty in sclock_lru\n");
			spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
			return;
		}
		sclock_entry=list_entry(lru_head->next,struct sclock_LRU,sclock_lru);
		//to_del=to_del->next;
		atomic_dec(&(pid_ns->sclock_lru_counter[i]));
		list_del_init(&sclock_entry->sclock_lru);
		/*	while(atomic_read(&(sclock_entry->access_times))==SCLOCK_LOCKED){
			to_del=to_del->next;
			sclock_entry=list_entry(tail,struct sclock_LRU,sclock_lru);
			}*/
		spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
		page=pfn_to_page(sclock_entry->pfn);
		//pte_count=atomic_read(&sclock_entry->pte_count);
		//	do_page_reverse_set(sclock_entry,_PAGE_CACHE_PROTECT);
		if(page&&page_mapped(page)&&page_rmapping(page)){
			do_page_setirq(page,pid_ns,_PAGE_CACHE_PROTECT,1000);
		//	do_page_reverse_set(sclock_entry,_PAGE_CACHE_PROTECT);
			if(sclock_control->flush){
				clflush_all(kmap(page),PAGE_SIZE);
				kunmap(page);
			}
		}
		clean_sclock_pte_map(sclock_entry);
		kmem_cache_free(sclock_entry_cache,sclock_entry);
		spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
	}
}
#define times_to_change sclock_control->TIMES_TO_CHANGE
static int scan_sclock_lru_ins(void){
	struct pid_namespace* pid_ns;
	struct sclock_LRU * sclock_entry,*n;
	struct mm_struct* mm_one;
	struct list_head* lru_head,*tail,*lru_UC_head,*to_del;
	struct vm_area_struct* vma_one;
	pte_t *pte_one,pte_entry;
	int i,seq=0,j;
	int count,k_change,pte_count;
	unsigned int new_k;
	int diff;
	bool change=false;
	struct page* page;
	long address_one;
	int fix_number=0;
	static int times=0,change_time=0;
	bool dec=false,full=false,UC_full=false;
	daemon_times++;
	unsigned long flags,pfn;
	if(daemon_times>times_to_change&&times_to_change>0){
		daemon_times=0;
		change=true;
	}else{
		change=false;
	}
	mutex_lock(&pid_ns_mutex);
//	printk("scan cache queue\n");
	list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
		//	printk("scan\n");
		if(pid_ns->level<sclock_control->level){
			continue;
		}
		fix_number++;
		if(fix_number<sclock_control->fix_number){
			//skip
		}else if(fix_number==sclock_control->fix_number){
			new_k=sclock_control->protect_lines;
			diff=atomic_read(&pid_ns->k)-new_k;
			if(diff!=0){
				set_k_of_ns(pid_ns,new_k);
				printk("set k =%d for ns=%lx,diff=%d\n",new_k,pid_ns,diff);
			}

		}else{
			if(change){
				new_k=generate_k();
				diff=atomic_read(&pid_ns->k)-new_k;
				set_k_of_ns(pid_ns,new_k);
				//	printk("changed k to %d, pid_ns=%lx\n",new_k,pid_ns);
			}
		}
		if(pid_ns->sclock_lru_counter&&pid_ns->sclock_lru&&pid_ns->level>=sclock_control->level){
			for(i=0;i<NPageColor;i++){
				//	lru_UC_head=&(pid_ns->sclock_lru[i]);
				seq=0;
				spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
				if(diff<0){
					//	atomic_set(&(pid_ns->sclock_lru_counter[i]),COUNT_MASK&atomic_read(&(pid_ns->sclock_lru_counter[i])));
				}
				int count=0;
				atomic_t * lru_counter;
				while(diff>0){
					if((atomic_read(&(pid_ns->sclock_lru_counter[i])))+atomic_read(&(pid_ns->sclock_ins_lru_counter[i]))<=get_k_of_ns(pid_ns))
					  break;
					
					if(atomic_read(&(pid_ns->sclock_lru_counter[i]))>0){
						lru_head=&(pid_ns->sclock_lru[i]);
						lru_counter=&(pid_ns->sclock_lru_counter[i]);
					}else{
						lru_head=&(pid_ns->sclock_ins_lru[i]);
						lru_counter=&(pid_ns->sclock_ins_lru_counter[i]);
					}
					if(list_empty(lru_head)){
						set_k_of_ns(pid_ns,get_k_of_ns(pid_ns)+1);
						printk("abnormal list empty in sclock_lru\n");
						spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
						goto unlock;
					}
					sclock_entry=list_entry(lru_head->next,struct sclock_LRU,sclock_lru);
					//to_del=to_del->next;
					atomic_dec(lru_counter);
					list_del_init(&sclock_entry->sclock_lru);
					/*	while(atomic_read(&(sclock_entry->access_times))==SCLOCK_LOCKED){
						to_del=to_del->next;
						sclock_entry=list_entry(tail,struct sclock_LRU,sclock_lru);
						}*/
					spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
					page=pfn_to_page(sclock_entry->pfn);
					//pte_count=atomic_read(&sclock_entry->pte_count);
					//	do_page_reverse_set(sclock_entry,_PAGE_CACHE_PROTECT);
					if(page&&page_mapped(page)&&page_rmapping(page)){
						//	do_page_setirq(page,pid_ns,_PAGE_CACHE_PROTECT,1000);
						do_page_reverse_set(sclock_entry,_PAGE_CACHE_PROTECT);
						if(sclock_control->flush){
							clflush_all(kmap(page),PAGE_SIZE);
							kunmap(page);
						}
					}
					clean_sclock_pte_map(sclock_entry);
					kmem_cache_free(sclock_entry_cache,sclock_entry);
					spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
					count++;
				}
				spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
				spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
				lru_head=&(pid_ns->sclock_lru[i]);
				list_splice_tail_init(&pid_ns->sclock_ins_lru[i],lru_head);
				atomic_set(&(pid_ns->sclock_lru_counter[i]),atomic_read(&(pid_ns->sclock_ins_lru_counter[i]))+atomic_read(&(pid_ns->sclock_lru_counter[i])));
				atomic_set(&(pid_ns->sclock_ins_lru_counter[i]),0);
				list_for_each_entry(sclock_entry,lru_head,sclock_lru){
					if(atomic_read(&sclock_entry->access_times)==SCLOCK_TO_BE_DEL){
						//continue;
					}else{
						seq++;
						atomic_set(&sclock_entry->access_times,seq);
						pfn=sclock_entry->pfn;
						if(pfn_valid(pfn)){
							page=pfn_to_page(pfn);
							spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
							//	cond_resched();
							count=do_page_count_accessed(page,1);
							//count=1;
							spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
							if(pfn!=sclock_entry->pfn)
							  count=1000;
							if(count>0){
								atomic_add(count,&sclock_entry->access_times);
							}
						}
					}
				}
				spin_unlock_irqrestore(&(pid_ns->sclock_lock[i]),flags);
				spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
				sort_sclock_lru(lru_head);
				spin_unlock_irqrestore(&(pid_ns->sclock_lock[i]),flags);
			}
		}
	}
unlock:
	mutex_unlock(&pid_ns_mutex);
	return 0;
}
static int local_request_lru=false;
static int scan_sclock_lru(void){
	struct pid_namespace* pid_ns;
	struct sclock_LRU * sclock_entry,*n;
	struct mm_struct* mm_one;
	struct list_head* lru_head,*tail,*lru_UC_head,*to_del;
	struct vm_area_struct* vma_one;
	pte_t *pte_one,pte_entry;
	int i,seq=0,j;
	int count,k_change,pte_count;
	unsigned int new_k;
	int diff;
	bool change=false;
	struct page* page;
	long address_one;
	int fix_number=0;
	static int times=0,change_time=0;
	bool dec=false,full=false,UC_full=false;
	daemon_times++;
	unsigned long flags,pfn;
	/*if(sclock_control->debug){
		if(sclock_control->action&request_lru){
			sclock_control->action&=~request_lru;
			printk("turn off\n");
		}
		else{
			printk("turn on\n");
			sclock_control->action|=request_lru;
			request_lru(sclock_control->expected_action,sclock_control->level,sclock_control->userid,sclock_control->sleep);
			struct task_struct *p;
			for_each_process(p){  
				if(p->mm&&ns_of_pid(task_pid(p))->level>=sclock_control->level){
					requestCacheProtectOthers(p); 
				}
			}

		}
}
*/
	if(daemon_times>times_to_change&&times_to_change>0){
		daemon_times=0;
		change=true;
	}else{
		change=false;
	}
mutex_lock(&pid_ns_mutex);
//	printk("scan cache queue\n");
list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
	//	printk("scan\n");
	if(pid_ns->level<sclock_control->level){
		continue;
	}
	fix_number++;
	if(fix_number<sclock_control->fix_number){
		//skip
	}else if(fix_number==sclock_control->fix_number){
		new_k=sclock_control->protect_lines;
		diff=atomic_read(&pid_ns->k)-new_k;
		if(diff!=0){
			set_k_of_ns(pid_ns,new_k);
			printk("set k =%d for ns=%lx,diff=%d\n",new_k,pid_ns,diff);
		}

	}else{
		if(change){
			new_k=generate_k();
			diff=atomic_read(&pid_ns->k)-new_k;
			set_k_of_ns(pid_ns,new_k);
			//	printk("changed k to %d, pid_ns=%lx\n",new_k,pid_ns);
		}
	}
	if(pid_ns->sclock_lru_counter&&pid_ns->sclock_lru&&pid_ns->level>=sclock_control->level){
		for(i=0;i<NPageColor;i++){
			//	lru_UC_head=&(pid_ns->sclock_lru[i]);
			seq=0;
			spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
				if(diff<0){
					//	atomic_set(&(pid_ns->sclock_lru_counter[i]),COUNT_MASK&atomic_read(&(pid_ns->sclock_lru_counter[i])));
				}
				int count=0;
				atomic_t * lru_counter;
				while(diff>0){
					if((atomic_read(&(pid_ns->sclock_lru_counter[i])))+atomic_read(&(pid_ns->sclock_ins_lru_counter[i]))<=get_k_of_ns(pid_ns))
					  break;
					//		if(atomic_read(&(pid_ns->sclock_lru_counter[i]))>0){
					lru_head=&(pid_ns->sclock_lru[i]);
					lru_counter=&(pid_ns->sclock_lru_counter[i]);
					//		}else{
					//			lru_head=&(pid_ns->sclock_ins_lru[i]);
					//			lru_counter=&(pid_ns->sclock_ins_lru_counter[i]);
					//		}
					if(list_empty(lru_head)){
						set_k_of_ns(pid_ns,get_k_of_ns(pid_ns)+1);
						printk("abnormal list empty in sclock_lru\n");
						spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
						goto unlock;
					}
					sclock_entry=list_entry(lru_head->next,struct sclock_LRU,sclock_lru);
					//to_del=to_del->next;
					atomic_dec(lru_counter);
					list_del_init(&sclock_entry->sclock_lru);
					/*	while(atomic_read(&(sclock_entry->access_times))==SCLOCK_LOCKED){
						to_del=to_del->next;
						sclock_entry=list_entry(tail,struct sclock_LRU,sclock_lru);
						}*/
					spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
					page=pfn_to_page(sclock_entry->pfn);
					//pte_count=atomic_read(&sclock_entry->pte_count);
					//	do_page_reverse_set(sclock_entry,_PAGE_CACHE_PROTECT);
					clear_bit(PG_cacheable,&page->flags);
					if(page&&page_mapped(page)&&page_rmapping(page)){
						do_page_setirq(page,pid_ns,_PAGE_CACHE_PROTECT,1000);
						//do_page_reverse_set(sclock_entry,_PAGE_CACHE_PROTECT);
						if(sclock_control->flush){
							clflush_all(kmap(page),PAGE_SIZE);
							kunmap(page);
						}
					}
					clean_sclock_pte_map(sclock_entry);
					kmem_cache_free(sclock_entry_cache,sclock_entry);
					spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
					count++;
				}
				spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
				spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
				lru_head=&(pid_ns->sclock_lru[i]);
				//list_splice_tail_init(&pid_ns->sclock_ins_lru[i],lru_head);
				//	atomic_set(&(pid_ns->sclock_lru_counter[i]),atomic_read(&(pid_ns->sclock_ins_lru_counter[i]))+atomic_read(&(pid_ns->sclock_lru_counter[i])));
				//	atomic_set(&(pid_ns->sclock_ins_lru_counter[i]),0);
				list_for_each_entry(sclock_entry,lru_head,sclock_lru){
					if(atomic_read(&sclock_entry->access_times)==SCLOCK_TO_BE_DEL){
						//continue;
					}else{
						seq++;
						atomic_set(&sclock_entry->access_times,seq);
						pfn=sclock_entry->pfn;
						if(pfn_valid(pfn)){
							page=pfn_to_page(pfn);
							spin_unlock_irqrestore(&pid_ns->sclock_lock[i],flags);
							//	cond_resched();
						//	count=do_page_count_accessed(page,1);
							count=1;
							spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
							if(pfn!=sclock_entry->pfn)
							  count=1000;
							if(count>0){
								atomic_add(count,&sclock_entry->access_times);
							}
						}
					}
				}
				spin_unlock_irqrestore(&(pid_ns->sclock_lock[i]),flags);
				spin_lock_irqsave(&pid_ns->sclock_lock[i],flags);
				sort_sclock_lru(lru_head);
				spin_unlock_irqrestore(&(pid_ns->sclock_lock[i]),flags);
			}
		}
	}
unlock:
mutex_unlock(&pid_ns_mutex);
return 0;
}
static int do_sclock_coa_scan(void){
	if(sclock_control->fix_number>0||sclock_control->protect_lines>16){
		return 0;
	}
	if((sclock_control->action&request_coa)==request_coa)
		scan_children_copy();
	//  sclock_control_op->sleep_microsec_inc();
	//	else
	//  sclock_control_op->reset_sleep_microsec();
	//}
	return 0;
}
static int do_sclock_lru_scan(void){
	if(sclock_control->expected_action&request_lru==request_lru){
		scan_sclock_lru();
	}
	return 0;

}
int count_coa=0;
static int sclockd__thread(void *nothing)
{
	set_freezable();
	set_user_nice(current, 5);
	while (!kthread_should_stop()) {
	//	mutex_lock(&sclock_thread_mutex);
		if(sclockd_should_run(request_coa)){

			count_coa++;
			do_sclock_coa_scan();
			if(count_coa==10)
			{  scan_parent_page();
				count_coa=0;
			}
		}
	//	mutex_unlock(&sclock_thread_mutex);
		try_to_freeze();
		if(sclockd_should_run(request_coa)){

			schedule_timeout_interruptible( msecs_to_jiffies(sclock_thread_sleep_millisecs(0))/10);
		}else{
			wait_event_freezable(sclock_thread_wait,
						sclockd_should_run(request_coa)||kthread_should_stop());
		}
	}
	return 0;
}
static int lru__thread(void *nothing)
{
	set_freezable();
	set_user_nice(current, 5);
	while (!kthread_should_stop()) {
//		mutex_lock(&lru_thread_mutex);
		if(sclockd_should_run(request_lru)){
			do_sclock_lru_scan();
		}
//		mutex_unlock(&lru_thread_mutex);
		try_to_freeze();
		if(sclockd_should_run(request_lru)){
			schedule_timeout_interruptible( msecs_to_jiffies(sclock_thread_sleep_millisecs(0)/10));
		}else{
			wait_event_freezable(lru_thread_wait,
						sclockd_should_run(request_lru)||kthread_should_stop());
		}
	}
	return 0;
}
/*static int lru_trim_thread(unsigned long set_number,struct pid_namespace* pid_ns)
{
	set_freezable();
	set_user_nice(current, 5);
	while (!kthread_should_stop()) {
		mutex_lock(&lru_thread_mutex);
		if(sclock->control->request_lru){
			do_sclock_lru_trim(set_number,pid_ns);
		}
		mutex_unlock(&lru_thread_mutex);
		try_to_freeze();
		wait_event_freezable(lru_thread_wait,false);
	}
	return 0;
}
*/
int fault_fifo_in(struct fifo_head* fifo,struct fifo * new_one){
	spin_lock(&fifo->lock_last);
	if(fifo->last)
	  fifo->last->next=new_one;
	else
	  fifo->first=new_one;
	fifo->last=new_one;
	atomic_inc(&fifo->count);
	spin_unlock(&fifo->lock_last);
	return 1;
};
bool fault_fifo_empty(struct fifo_head* fifo){
	return fifo->first==NULL;
};
void init_fault_fifo(struct fifo* fifo){
	fifo->next=NULL;
}
void init_fault_fifo_head(struct fifo_head* fifo){
	fifo->last=NULL;
	fifo->first=NULL;
	atomic_set(&fifo->count,0);
	spin_lock_init(&fifo->lock_last);
};
int fault_fifi_out(struct fifo_head* fifo){
	spin_lock(&fifo->lock_last);
	fifo->first=fifo->first->next;
	if(fifo->first==NULL)
	  fifo->last=NULL;
	atomic_dec(&fifo->count);
	spin_unlock(&fifo->lock_last);
	return 1;
};
bool fault_fifo_not_empty(struct fifo_head * fifo){
	return fifo->first!=NULL;
}
int queue_fault_fn(void* data){
	struct queue_thread_data* para=(struct queue_thread_data*) data;
	struct fifo_head* fault_fifo=&para->fifo;
	struct fault_entry* fault_entry;
	set_freezable();
	set_user_nice(current, -1);
	while(!kthread_should_stop()){
		//mutex_lock(&para->queue_thread_mutex);
		while(!fault_fifo_empty(fault_fifo)){
			fault_entry=container_of(fault_fifo->first,struct fault_entry,fifo);
			//printk("handle %lx %lx in thread %d",fault_entry->address,fault_entry->pfn,para->cpuid);
			//down_read(&fault_entry->mm->mmap_sem);
			//try_switch_NCache(fault_entry->mm,fault_entry->vma,fault_entry->address,fault_entry->pfn,fault_entry->orig_pte,true);
			//up_read(&fault_entry->mm->mmap_sem);
			fault_fifi_out(fault_fifo);
			kmem_cache_free(sclock_fault_entry_cache,fault_entry);
		}
		//printk("end of fifo\n");
		//mutex_unlock(&para->queue_thread_mutex);
		try_to_freeze();
		wait_event_freezable(para->queue_thread_wait,fault_fifo_not_empty(fault_fifo));
	}
	return 0;
}
int queue_remove_fn(void* data){
	struct queue_thread_data* para=(struct queue_thread_data*) data;
	struct fifo_head* fault_fifo=&para->fifo;
	struct fault_entry* fault_entry;
	set_freezable();
	set_user_nice(current, -1);
	while(!kthread_should_stop()){
		//mutex_lock(&para->queue_thread_mutex);
		while(!fault_fifo_empty(fault_fifo)){
			fault_entry=container_of(fault_fifo->first,struct fault_entry,fifo);
			//printk("handle %lx %lx in thread %d",fault_entry->address,fault_entry->pfn,para->cpuid);
			//down_read(&fault_entry->mm->mmap_sem);
			//up_read(&fault_entry->mm->mmap_sem);
			do_page_set(pfn_to_page(fault_entry->pfn),fault_entry->pid_ns,_PAGE_CACHE_PROTECT,1000);  
			fault_fifi_out(fault_fifo);
			kmem_cache_free(sclock_fault_entry_cache,fault_entry);
		}
		//printk("end of fifo\n");
		//mutex_unlock(&para->queue_thread_mutex);
		try_to_freeze();
		wait_event_freezable(para->queue_thread_wait,fault_fifo_not_empty(fault_fifo));
	}
	return 0;
}
static void queue_fault_tasklet(struct queue_thread_data* para){
	struct fifo_head* fault_fifo=&para->fifo;
	struct fault_entry* fault_entry;
	while(!fault_fifo_empty(fault_fifo)){
		fault_entry=container_of(fault_fifo->first,struct fault_entry,fifo);
		//printk("handle %lx %lx in thread %d",fault_entry->address,fault_entry->pfn,para->cpuid);
	//	try_switch_NCache(fault_entry->mm,fault_entry->vma,fault_entry->address,fault_entry->pfn,fault_entry->orig_pte,true);
		fault_fifi_out(fault_fifo);
		kmem_cache_free(sclock_fault_entry_cache,fault_entry);
	}
}
struct kmem_cache* sclock_fault_entry_cache=NULL;
struct queue_thread_data * queue_paras;
static int __init sclockd_init(void){
	struct task_struct * sclock_thread,*lru_thread,*queue_threads;
	int num_cpu=num_online_cpus();
	int err=0;
	sclock_thread = kthread_run(sclockd__thread, NULL, "sclockd");
	lru_thread = kthread_run(lru__thread, NULL, "lru_sclockd");
	int i=0;
	/*	if(!sclock_fault_entry_cache)
		sclock_fault_entry_cache=kmem_cache_create("sclock_fault_entry_cache", sizeof(struct fault_entry), ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
		queue_paras=kmalloc(sizeof(struct queue_thread_data)*num_cpu,GFP_KERNEL);
	//	tasklet_queue=kmalloc(sizeof(struct tasklet_struct)*num_cpu,GFP_KERNEL);
	for(i=0;i<num_cpu;i++){
	queue_paras[i].cpuid=i;
	init_fault_fifo_head(&(queue_paras[i].fifo));
	init_waitqueue_head(&(queue_paras[i].queue_thread_wait));
	mutex_init(&(queue_paras[i].queue_thread_mutex));

	queue_threads=kthread_create(queue_remove_fn,(void*)(&queue_paras[i]),"queue%d",i);
	if (!IS_ERR(queue_threads))
	wake_up_process(queue_threads);
	//	queue_paras[i].workqueue=alloc_ordered_workqueue("queue_%d", WQ_MEM_RECLAIM, i);
	//tasklet_init(&(queue_paras[i].tasklet_queue),queue_fault_tasklet,(void*)(&queue_paras[i]));
	}
	*/	if (IS_ERR(sclock_thread)||IS_ERR(lru_thread)) {
		pr_err("sclock_thread: creating failed!\n");
		err = PTR_ERR(sclock_thread);
	}
	printk("creat sclockd_thread");
	return err;
}

module_init(sclockd_init);


