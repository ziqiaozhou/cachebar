#include<linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/myservice.h>
#include <linux/mm.h>
#include<linux/seq_file.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/bitops.h>
#include <linux/hugetlb.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/random.h>
#include <linux/mmu_notifier.h>
#include <asm/tlbflush.h>
#include "internal.h"
#include <linux/swap.h>
#include <linux/pid_namespace.h>
#include <linux/cred.h>
#include <linux/ksm.h>
#include <linux/rbtree.h>
#include <linux/highmem.h>
#include <linux/list_sort.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/timex.h>
#include <linux/cpufreq.h>
#define CACHEABLE 1
#define UNCACHEABLE 0
static struct kmem_cache* sclock_pte_map_vma_counterp;
//static kmem_cache* page_counter_cachep=kmem_cache_create("sclock_page_pte_map", sizeof(struct sclock_page_pte_map), ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
struct sclock_pte_map_vma_counter *  create_sclock_pte_map_vma_counter(void){
	if(!sclock_pte_map_vma_counterp)
	  sclock_pte_map_vma_counterp=kmem_cache_create("sclock_pte_map_vma_counterp",sizeof(struct sclock_pte_map_vma_counter),ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
	struct sclock_pte_map_vma_counter * counter=kmem_cache_alloc(sclock_pte_map_vma_counterp,GFP_KERNEL);
	atomic_set(&counter->counter,0);
	counter->legal=true;
	return counter;
}
void destroy_sclock_pte_map_vma_counter(struct sclock_pte_map_vma_counter* counter){
	kmem_cache_free(sclock_pte_map_vma_counterp,counter);
}
unsigned long start_time_lru;
unsigned long start_time_coa;
void reset_coa_time(int cpu){
	per_cpu(global_count_coa,cpu)=0;
	per_cpu(global_count_coa_normal,cpu)=0;
	per_cpu(global_count_coa_early,cpu)=0; 
	per_cpu(global_interval_coa,cpu)=0;
	per_cpu(global_interval_coa_normal,cpu)=0;
	per_cpu(global_interval_coa_early,cpu)=0; 
	per_cpu(global_ins_count,cpu)=0;
}
void print_coa_time(int cpu){
	printk("cpu %s :coa normal count=%llu,early count=%llu,normal time=%llu,early time=%llu\n",cpu,per_cpu(global_count_coa_normal,cpu),per_cpu(global_count_coa_early,cpu),per_cpu(global_count_coa_normal,cpu)?per_cpu(global_interval_coa_normal,cpu)/per_cpu(global_count_coa_normal,cpu):0,per_cpu(global_count_coa_early,cpu)?per_cpu(global_interval_coa_early,cpu)/per_cpu(global_count_coa_early,cpu):0);

}	
void print_lru_time(int cpu){
		printk("\nnormal=%llu,=%llu,%llu,early=%llu,=%llu,%llu,interested total=%llu,count=%llu,avg=%llu,total fault>100000=%llu times, normal>100000 =%llu times",per_cpu(global_interval_normal,cpu),per_cpu(global_count_normal,cpu),per_cpu(global_count_normal,cpu)?per_cpu(global_interval_normal,cpu)/per_cpu(global_count_normal,cpu):0,per_cpu(global_interval_early,cpu),per_cpu(global_count_early,cpu),per_cpu(global_count_early,cpu)?per_cpu(global_interval_early,cpu)/per_cpu(global_count_early,cpu):0,per_cpu(global_interval,cpu),per_cpu(global_count,cpu),per_cpu(global_count,cpu)?per_cpu(global_interval,cpu)/per_cpu(global_count,cpu):0,per_cpu(global_count_total,cpu),per_cpu(global_count_normal_total,cpu));
}
void print_lru_total_time(void){
	unsigned long long total=0,early=0,num=0,num_early=0,num_over=0,prefetch=0,prefetch_num=0,failed_prefetch_num,fault=0,num_fault=0,num_ins_fault=0,before_prefetch_num=0;
	int cpu; 
	for_each_present_cpu(cpu)
	{
		prefetch+=per_cpu(global_prefetch,cpu);
		failed_prefetch_num+=per_cpu(global_all_prefetch_count,cpu)-per_cpu(global_prefetch_count,cpu);
		prefetch_num+=per_cpu(global_prefetch_count,cpu);
		total+=per_cpu(global_interval_normal,cpu);
		before_prefetch_num+=per_cpu(global_before_prefetch_count,cpu);
		num_over+=per_cpu(global_count_normal_total,cpu);
		num+=per_cpu(global_count_normal,cpu);
		early+=per_cpu(global_interval_early,cpu);
		num_early+=per_cpu(global_count_early,cpu);
		num_ins_fault+=per_cpu(global_ins_count,cpu);
		num_fault+=per_cpu(global_count,cpu);
	}
	int i;
	printk("normal total=%llu, num=%llu, avg=%llu,over 100000=%llu; early total=%llu,num=%llu,avg=%llu, total avg=%llu,prefetch num=%llu, avg=%llu, failed prefetch=%llu,before prefetch=%llu, num_ins_fault=%llu,num_fault=%llu\n",total,num,num?total/num:0,num_over,early,num_early,num_early?early/num_early:0,num+num_early?(total+early)/(num+num_early):0,prefetch_num,prefetch_num?prefetch/prefetch_num:0,failed_prefetch_num,before_prefetch_num,num_ins_fault,num_fault);
/*	for(i=0;i<num_online_cpus();i++){
		printk("queue fifo %d count=%d, is empty %d\n",i,atomic_read(&(queue_paras[i].fifo.count)),fault_fifo_not_empty(&(queue_paras[i].fifo))?1:0);
	}*/
}
void reset_lru_time(int cpu){
	per_cpu(global_interval_normal,cpu)=0;
per_cpu(global_prefetch_count,cpu)=0;
per_cpu(global_prefetch,cpu)=0;
per_cpu(global_all_prefetch_count,cpu)=0;
per_cpu(global_before_prefetch_count,cpu)=0;	
per_cpu(global_interval,cpu)=0;
	per_cpu(global_interval_early,cpu)=0;
	per_cpu(global_count_normal,cpu)=0;
	per_cpu(global_count,cpu)=0;
	per_cpu(global_count_early,cpu)=0;
}
static LIST_HEAD(parent_page_head);
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
static inline unsigned long
__vma_address(struct page *page, struct vm_area_struct *vma)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);

	if (unlikely(is_vm_hugetlb_page(vma)))
	  pgoff = page->index << huge_page_order(page_hstate(page));

	return vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
}
unsigned long
vma_to_address(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address = __vma_address(page, vma);

	/* page should be within @vma mapping range */
	VM_BUG_ON(address < vma->vm_start || address >= vma->vm_end);

	return address;
}

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
struct sclockControl sclock_control_paras={
	.action=release_both,
	.level=-1,
	.userid=-1,
	.orig_sleep_microsec=1000,
	.sleep_microsec=1000,
	.protect_lines=10,
	.TIMES_TO_CHANGE=10,
	.debug=1,
	.fix_number=0,
	.flush=1,

};
int get_k_of_ns(struct pid_namespace* pid_ns){
	return atomic_read(&pid_ns->k);
}
int get_current_k(void){
	return atomic_read(&ns_of_pid(task_pid(current))->k);
}
void dec_k_of_ns(struct pid_namespace* pid_ns){
	atomic_dec(&pid_ns->k);
}
void inc_k_of_ns(struct pid_namespace* pid_ns){
	atomic_inc(&pid_ns->k);
}
int set_k_of_ns(struct pid_namespace* pid_ns,unsigned int k){
	atomic_set(&pid_ns->k,k);
	return 1;
}

void cpuid_sclock(struct cpuidRegs *regs) {
	asm __volatile__ ("cpuid": "+a" (regs->eax), "+b" (regs->ebx), "+c" (regs->ecx), "+d" (regs->edx));
};

void cpuid_cacheInfo(int index, struct cacheInfo *cacheInfo) {
  struct cpuidRegs *regs = (struct cpuidRegs *)cacheInfo;
  regs->eax = 4;
  regs->ecx = index;
  cpuid_sclock(regs);
};

static struct cacheInfo l3Info;
static int getL3Info(void) {
	struct cacheInfo new_l3Info;
	if (l3Info.level < 0)
	  return 0;
	int i; 
	for (i = 0; cpuid_cacheInfo(i, &new_l3Info), new_l3Info.type !=0; i++){
		if (new_l3Info.type !=0)
		  memcpy(&new_l3Info,&l3Info,sizeof(struct cacheInfo));
		if (l3Info.level == 3)
		  break;
	}
	if (l3Info.level<1){
		printk("cpuid failed, get cache info from cpuinfo and assume way=8\n");
		struct cpuinfo_x86* c=&cpu_data(0);
		l3Info.lineSize=c->x86_cache_alignment;
		l3Info.associativity=8-1;
		l3Info.partitions=1-1;
		l3Info.sets=(c->x86_cache_size<<10)/((l3Info.associativity+1)*(l3Info.lineSize+1));
		l3Info.level=2;
	}
	printk("Cache level=%d",l3Info.level);
	return l3Info.level;
};

int cpuid_size(void) {
  if (!getL3Info()){
    printk("failed cpuid_assoc\n");
  }
  return (l3Info.lineSize +1)*(l3Info.partitions + 1) *(l3Info.associativity + 1)*(l3Info.sets + 1);
};

int cpuid_colours(void) {
	if (!getL3Info()){
		printk("failed cpuid_assoc\n");
	}
  return (l3Info.sets + 1)*(l3Info.partitions + 1)*(l3Info.lineSize +1) / 4096;
};

int cpuid_assoc(void) {
  if (!getL3Info()){
    printk("failed cpuid_assoc\n");
  } 
  return l3Info.associativity+1;
}
int cpuid_linesize(void) {
	if (!getL3Info()){
		printk("failed cpuid_linesize\n");
	}
	printk("line size=%d",l3Info.lineSize);
	return l3Info.lineSize;
};
 unsigned long ASSOCIATIVITY;
 unsigned long CACHE_SIZE;
 int CACHE_BLOCK_SIZE;
 unsigned long NPageColor;

unsigned int sclock_thread_sleep_millisecs(unsigned int t){
	//	static unsigned int sclock_thread_sleep_millisecs = 1000;
	if(t>0){
		sclock_control->sleep_microsec=t;
		sclock_control->orig_sleep_microsec=t;
	}
	return sclock_control->sleep_microsec;
}


struct sclockControl* sclock_control=&sclock_control_paras;

unsigned int sclock_thread_sleep_millisec_inc(void){
	sclock_control->sleep_microsec*=2;
	return sclock_control->sleep_microsec;
}
void sclock_reset_sleep(void){
	sclock_control->sleep_microsec=sclock_control->orig_sleep_microsec;
}
struct sclockControlOp sclock_control_op_detail={
	.set_sleep_microsec=sclock_thread_sleep_millisecs,
	.sleep_microsec_inc=sclock_thread_sleep_millisec_inc,
	.reset_sleep_microsec=sclock_reset_sleep,
};

struct sclockControlOp* sclock_control_op=& sclock_control_op_detail;

char *getActionStr(unsigned int action);
extern wait_queue_head_t sclock_thread_wait;
extern wait_queue_head_t lru_thread_wait;
struct kmem_cache* sclock_cachep;
struct kmem_cache* sclock_all_cachep;
int protection_cache_min_level=0;
int protection_cache_min_userid=0;
/*int link_page_pte(struct page* page,pte_t * ptep,struct mm_struct *mm){
	struct pid_namespace* ns;
	struct sclock_page_pte_map* pte_map;
	if(!mm->owner){
		return -1;
	}
	if(ns=ns_of_pid(task_pid(mm->owner))){
		if(ns->sclock_page_pte){
			pte_map=kmem_cache_alloc(sclock_page_pte_map_cachep,GFP_KERNEL);
			pte_map->ptep=ptep;
			list_add_rcu(&pte_map->head,&ns->sclock_page_pte[page_to_pfn(page)]);
			return 0;
		}
	}
	return -1;

}
int unlink_page_pte(struct page* page,pte_t * ptep,struct mm_struct *mm){
	struct pid_namespace* ns;
	struct sclock_page_pte_map* pte_map;
	if(!mm->owner){
		return -1;
	}
	if(ns=ns_of_pid(task_pid(mm->owner))){
		if(ns->sclock_page_pte){
			list_for_each_entry_rcu(pte_map,&ns->sclock_page_pte[page_to_pfn(page)],head){
				//	pte_map=kmem_cache_alloc(sclock_page_pte_map_cachep,GFP_KERNEL);
				//	pte_map->ptep=ptep;
				list_del_rcu(&pte_map->head);
				synchronize_rcu();
				kfree(pte_map);
				return 0;
			}
		}
	}
	return -1;

	}*/



static int do_ksm_page_count(struct page* page,struct pid_namespace* pid_ns_ref){
#ifndef CONFIG_KVM
	return 0;
#else
	struct stable_node *stable_node;
	struct rmap_item *rmap_item;
	pte_t* pte,pte_entry;
	int ret=0;	
	struct mm_struct * mm;
	struct task_struct * task;
	unsigned long address;
	stable_node = page_stable_node(page);
	//printk("ksm\n");
	if (!stable_node)
	  return ret;
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		struct anon_vma *anon_vma = rmap_item->anon_vma;
		struct anon_vma_chain *vmac;
		struct vm_area_struct *vma;
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					0, ULONG_MAX) {
			vma = vmac->vma;
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(ns_of_pid(task_pid(task))==pid_ns_ref){
				  ret++;
			  }
		}	
		anon_vma_unlock_read(anon_vma);
	}
	return ret;
#endif
}
static int do_file_page_count(struct page* page,struct pid_namespace* pid_ns_ref){
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	int ret=0;	struct vm_area_struct *vma;
	unsigned long address;
	struct mm_struct * mm;
	struct task_struct * task;
	pte_t* pte,pte_entry; 
	//printk("file\n");
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);
i_mmap_lock_read(mapping);
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		if(vma){
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(ns_of_pid(task_pid(task))==pid_ns_ref){
				  ret++;
			  }
		}
	}
i_mmap_unlock_read(mapping);
	return ret;
}
static int do_anon_page_count(struct page* page,struct pid_namespace* pid_ns_ref){
	struct anon_vma * anon_vma;
	int ret=0;
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
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(ns_of_pid(task_pid(task))==pid_ns_ref){
				  ret++;
			  }
		}
	}
unlock:	page_unlock_anon_vma_read(anon_vma);
		return ret;
}
static int do_ksm_page_shared(struct page* page){
#ifndef CONFIG_KVM
	return false;
#else
	struct stable_node *stable_node;
	struct rmap_item *rmap_item;
	struct pid_namespace* pid_ns_ref;
	pte_t* pte,pte_entry;
	int ret=0;	
	struct mm_struct * mm;
	struct task_struct * task;
	unsigned long address;
	stable_node = page_stable_node(page);
	//printk("ksm\n");
	if (!stable_node)
	  return false;
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		struct anon_vma *anon_vma = rmap_item->anon_vma;
		struct anon_vma_chain *vmac;
		struct vm_area_struct *vma;
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					0, ULONG_MAX) {
			vma = vmac->vma;
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(pid_ns_ref==NULL)
				pid_ns_ref=ns_of_pid(task_pid(task));
			  else
				if(ns_of_pid(task_pid(task))!=pid_ns_ref){
					return true;
				}
		}	
		anon_vma_unlock_read(anon_vma);
	}
	return false;
#endif
}
static int do_file_page_shared(struct page* page){
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct pid_namespace* pid_ns_ref;
	int ret=0;	struct vm_area_struct *vma;
	unsigned long address;
	struct mm_struct * mm;
	struct task_struct * task;
	pte_t* pte,pte_entry; 
	//printk("file\n");
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);


i_mmap_lock_read(mapping);

	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		if(vma){
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(pid_ns_ref==NULL)
				pid_ns_ref=ns_of_pid(task_pid(task));
			  else
				if(ns_of_pid(task_pid(task))!=pid_ns_ref){

					goto unlock;
				}
		}
	}
unlock:
	i_mmap_unlock_read(mapping);
	return false;
}
static int do_anon_page_shared(struct page* page){
	struct anon_vma * anon_vma;
	int ret=0;
	struct pid_namespace* pid_ns_ref;
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
			if((mm=vma->vm_mm)&&(task=mm->owner))
			  if(pid_ns_ref==NULL)
				pid_ns_ref=ns_of_pid(task_pid(task));
			  else
				if(ns_of_pid(task_pid(task))!=pid_ns_ref){
					return true;
				}
		}
	}
unlock:	page_unlock_anon_vma_read(anon_vma);
		return false;
}



int compare_sclock(void* priv,struct list_head* a,struct list_head* b){
	struct sclock_LRU* a_entry,* b_entry;
	int a_count,b_count;
	a_entry=list_entry(a,struct sclock_LRU,sclock_lru);
	b_entry=list_entry(b,struct sclock_LRU,sclock_lru);
	a_count=atomic_read(&a_entry->access_times);
	b_count=atomic_read(&b_entry->access_times);
	if(a_count<b_count)
	  return -1;
	if(a_count==b_count)
	  return 0;
	return 1;
}
void sort_sclock_lru(struct list_head* lru_head){
	list_sort(NULL,lru_head,compare_sclock);
}


inline int get_protection_cache_level(void){
	return protection_cache_min_level;
}
inline int get_protection_cache_userid(void){
	return protection_cache_min_userid;
}
inline int update_protection_paras(int level, int userid){
	protection_cache_min_level=level;
	protection_cache_min_userid=userid;
	return 0;
}
inline	long
get_rdtsc(void)
{
	unsigned int higher32bits, lower32bits;
	unsigned long chk_idxer;
	__asm__ volatile("rdtsc":"=a"(lower32bits),"=d"(higher32bits)
			);
	chk_idxer = higher32bits;
	chk_idxer = (chk_idxer << 32) + lower32bits;
	return chk_idxer;
}
bool double_queue(int set){
	static bool val=false;
	if(set>-1){
		val=set>0;
	}
	return val;
}
inline int protection_UC(int k){
	static int protection_UC=10;
	if(k>0)
	  protection_UC=k;
	return protection_UC;
}

inline int update_protection_cache(int change){
	static int protection_cache=0;
	protection_cache+=change;
	return (sclock_control->action&request_lru)>0;
}
inline bool useSClockDaemon(bool change){
	static bool useSClock=true;
	if(change)
	  useSClock=!useSClock;
	return (useSClock&&(sclock_control->action&request_both)); 
}

inline int update_isolation_mode(int change){
	static int isolation_mode=0;
	isolation_mode+=change;
	return (sclock_control->action&request_coa)>0;
}
inline int protection_level(int k){
//	static int protection_level_k=5;
	if(k>0){
		 sclock_control->protect_lines=k;
	}
	return sclock_control->protect_lines;
}

unsigned long getCurrentChildrenDefFlag(void){
	unsigned long flags=0;
	struct pid_namespace* pid_ns=ns_of_pid(task_pid(current));
	if(sclock_control->action&request_coa){
		if(pid_ns->level>=sclock_control->level&&task_uid(current).val>=sclock_control->userid){
			flags|=VM_ISOLATION;
		}
	}
	if(sclock_control->action&request_lru){
		if(pid_ns->level>=sclock_control->level&&task_uid(current).val>=sclock_control->userid){
			flags|=VM_CACHE_PROTECT;
		}
	}
	if(update_protection_cache(0)>0){
		flags|=(pid_ns->sclock_lru_counter)?
			VM_CACHE_PROTECT:0;
	}
	if(current)
	  if(current->mm)
		if(current->mm->def_flags&VM_ISOLATION){
			flags|=VM_ISOLATION;
		}
	return flags;
}




pte_t* find_pte_lock
(struct mm_struct* mm,unsigned long address, spinlock_t* ptl){
	pgd_t* pgd=NULL;
	pud_t* pud=NULL;
	pmd_t* pmd=NULL;
	pte_t* pte=NULL;
	pgd = pgd_offset(mm, address);
	if(pgd_none(*pgd)){
		//	printk(KERN_NOTICE"not mapped in the pgd 0x%lx", pgd_val(*pgd));
		return NULL;
	}
	pud=pud_offset(pgd,address);
	if(pud_none(*pud)){
		//	printk(KERN_NOTICE"not mapped in the pud 0x%lx",pud_val(*pud));
		return NULL;
	}
	pmd=pmd_offset(pud,address);
	if(pmd_none(*pmd)){
		//	printk(KERN_NOTICE"not mapped in the pmd 0x%lx",pmd_val(*pmd));
		return NULL;
	}
	ptl=pte_lockptr(mm,pmd);
	pte = pte_offset_map_lock(mm,pmd, address,&ptl);  
	if(pte_none(*pte)){
		//	printk(KERN_NOTICE"not mapped in the pte 0x%lx",pte_val(*pte));
		return NULL;
	}
	//	printk(KERN_DEBUG"[address=%lx]",address);
	return pte;
}

void add_sclock_pte_map(struct vm_area_struct * vma)
{
	atomic_inc(&(vma->sclock_pte_map_vma_counter->counter));
}
void remove_sclock_pte_map(struct vm_area_struct * vma){
	/*while((&vma->sclock_all_pte_map)->next!=&vma->sclock_all_pte_map){
	 pte_map=list_entry((&vma->sclock_all_pte_map)->next,struct sclock_page_pte_map,head_for_mm);

	 list_del_init(&pte_map->head_for_mm);
	 }*/
	vma->sclock_pte_map_vma_counter->legal=false;
}
inline pte_t* find_pte(struct mm_struct* mm,unsigned long address){
	pgd_t* pgd_one;
	pud_t* pud;
	pmd_t* pmd;
	pte_t* pte;
	//	if(mm==NULL)
	//	  return NULL;
	//	if(mm->owner==NULL)
	//	  return NULL;
	//	printk("mm->owner=%s,pgd=%lx,address=%lx",mm->owner->comm,mm->pgd,address);
	if(mm==NULL)
	  return NULL;
	if(mm->pgd==NULL)
	  return NULL;
	if((unsigned long)(address>>PGDIR_SHIFT)==0){
		pgd_one=mm->pgd;
	}else
	  pgd_one = pgd_offset(mm, address);
	if(pgd_none(*pgd_one)||pgd_bad(*pgd_one)){
		//	printk(KERN_NOTICE"not mapped in the pgd 0x%lx", pgd_val(*pgd));
		return NULL;
	}
	pud=pud_offset(pgd_one,address);
	if(pud_none(*pud)||pud_bad(*pud)){
		//	printk(KERN_NOTICE"not mapped in the pud 0x%lx",pud_val(*pud));
		return NULL;
	}
	pmd=pmd_offset(pud,address);
	if(pmd_none(*pmd)||pmd_bad(*pmd)){
		//	printk(KERN_NOTICE"not mapped in the pmd 0x%lx",pmd_val(*pmd));
		return NULL;
	}
	pte = pte_offset_map(pmd, address);  
	if(pte_none(*pte)){
		//	printk(KERN_NOTICE"not mapped in the pte 0x%lx",pte_val(*pte));
		return NULL;
	}
	//	printk(KERN_DEBUG"[address=%lx]",address);
	return pte;
}


void do_ksm_page_isolation(struct page* page){
#ifndef CONFIG_KVM
	return;
#else
	struct stable_node *stable_node;
	struct rmap_item *rmap_item;
	int isIsolated=-1;
	pte_t* pte,pte_entry; 
	unsigned long address;
	VM_BUG_ON(!PageKsm(page));
	VM_BUG_ON(!PageLocked(page));
	stable_node = page_stable_node(page);
	if (!stable_node)
	  return ;
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		struct anon_vma *anon_vma = rmap_item->anon_vma;
		struct anon_vma_chain *vmac;
		struct vm_area_struct *vma;
		anon_vma_lock_read(anon_vma);
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					0, ULONG_MAX) {
			vma = vmac->vma;
			//	printk(KERN_DEBUG"find ksm vma\n");
			if(vma->vm_flags&VM_ISOLATION){
				//		printk(KERN_DEBUG"is isolated page\n");
				address= vma_to_address(page, vma);
				pte=find_pte(vma->vm_mm,address);
				if(pte){
					pte_entry=*pte;
					if(pte_present(*pte)){
						if(!(pte_val(*pte)&_PAGE_ISOLATION)){
							isIsolated++;
							ptep_clear_flush(vma,address,pte);
							pte->pte|=_PAGE_ISOLATION;
							//set_pte_at(vma->vm_mm, address, pte, pte_entry);
								flush_tlb_page(address,vma);
							//update_mmu_cache(vma, address, pte);
							//		printk(KERN_DEBUG"set page isolation at pte =0x%lx at adddress [%lx]--[%lx]",pte_val(*pte),address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
						}
					}
				}
			}	
		}
		anon_vma_unlock_read(anon_vma);
	}
	if(isIsolated>0){
		set_bit(PG_isolation,&page->flags);
	//	if(!page->coa_head)
	//	  init_coa_parent(page);
	}
#endif
	//test_and_clear_bit(PG_isolation,&page->flags);
}

void do_anon_page_isolation(struct page* page){
	struct anon_vma * anon_vma;
	struct anon_vma_chain *avc;
	int isIsolated=-1;
	pte_t* pte,pte_entry; 
	unsigned long address;
	pgoff_t pgoff;
	struct vm_area_struct *vma;
	get_page(page);
	anon_vma=page_lock_anon_vma_read(page);
	pgoff=page->index<<(PAGE_CACHE_SHIFT-PAGE_SHIFT);
	anon_vma_interval_tree_foreach(avc,&anon_vma->rb_root,pgoff,pgoff){
		vma=avc->vma;
		if(vma){
			address = vma_to_address(page, vma);
			//		printk(KERN_DEBUG"find anon vma at address %lx\n",address);
			if(vma->vm_mm->def_flags&VM_ISOLATION){
				//	printk(KERN_DEBUG"is isolated page\n");
				pte=find_pte(vma->vm_mm,address);
				if(pte){
					if(pte_present(*pte)){
						if(!(pte_val(*pte)&_PAGE_ISOLATION)){
							pte_entry=*pte;
							isIsolated++;
							ptep_clear_flush(vma,address,pte);
							pte->pte|=_PAGE_ISOLATION;
						//	set_pte_at(vma->vm_mm, address, pte, pte_entry);
						//	update_mmu_cache(vma, address, pte);
						 flush_tlb_page(vma,address);

						//	printk(KERN_DEBUG"set page isolation at pte =0x%lx at adddress [%lx]--[%lx]",pte_val(*pte),address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
						}
					}
				}	
			}
		}
	}
	page_unlock_anon_vma_read(anon_vma);

	if(isIsolated>0){
		set_bit(PG_isolation,&page->flags);
//		if(!page->coa_head)
//		  init_coa_parent(page);
	}
	//test_and_clear_bit(PG_isolation,&page->flags);

}

void do_file_page_isolation(struct page* page){
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	int isIsolated=-1;
	unsigned long address;
	pte_t* pte,pte_entry; 
	unsigned long flags;
	if (PageHuge(page))
	  pgoff = page->index << compound_order(page);
	i_mmap_lock_read(mapping);
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		//	printk(KERN_DEBUG"find file vma\n");
		if(vma)
		  if(vma->vm_flags&VM_ISOLATION){
			  //		printk(KERN_DEBUG"is isolated page\n");
			  address = vma_to_address(page, vma);
			  if(vma->vm_mm){
				  pte=find_pte(vma->vm_mm,address);
				  if(pte){
					  if(pte_present(*pte)){
						  isIsolated++;
						  if(!(pte_val(*pte)&_PAGE_ISOLATION)){
							  pte_entry=*pte;
							  //ptep_clear_flush(vma,address,pte);
							  pte->pte|=_PAGE_ISOLATION;
							  flush_tlb_page(vma,address);
							  // set_pte_at(vma->vm_mm, address, pte, pte_entry);
							  //  update_mmu_cache(vma, address, pte);
							  //		printk(KERN_DEBUG"set page isolation at pte =0x%lx at adddress [%lx]--[%lx]",pte_val(*pte),address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
						  }
					  }
				  }		
			  }
		  }
	}
	i_mmap_unlock_read(mapping);
	if(isIsolated>0){
		set_bit(PG_isolation,&page->flags);
	//	if(!page->coa_head)
		//  init_coa_parent(page);
	}


}
#define PAGE_COUNTER_IN_NS_LOW ((1<<PAGE_COUNT_IN_NS_LOW_BIT)-1L)
#define pfn_to_low(pfn) pfn&PAGE_COUNTER_IN_NS_LOW
#define pfn_to_high(pfn) (unsigned long)(pfn>>PAGE_COUNT_IN_NS_LOW_BIT)
int isContainerSharedPage(struct page* page){
	struct pid_namespace* pid_ns;
	unsigned long pfn=page_to_pfn(page);
	int count=0;
	unsigned long low;
	unsigned long high;
	low=pfn_to_low(pfn);
	high=pfn_to_high(pfn);
	list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
		if(atomic_read(&(pid_ns->page_counter[low][high]))>0&&pid_ns->level>=sclock_control->level)
		  count++;
	}
	return count>1;

	/*	if(page_mapped(page)){
		if(PageKsm(page)){
		return 	do_ksm_page_shared(page);
		}else if(PageAnon(page)){
		return 	do_anon_page_shared(page);
		}
		else if(page_mapping(page)){
		return do_file_page_shared(page);		
		}
		}
		return false;
		*/
}
long show_page_counter(void){
	struct pid_namespace* pid_ns;
	unsigned long pfn;
	struct page* page;
	for(pfn=0;pfn<max_pfn;pfn++){
		if(pfn_valid(pfn)){
			page=pfn_to_page(pfn);
			if(page){
				list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
					printk("%d::%d,\t",pfn,atomic_read(&pid_ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]));
				}
				printk(" %d,=%d\n",ns_of_pid(task_pid(current))->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)],page_mapcount(page));
			}
		}
	}
	return 0;
}

void copy_all_page_counter(struct page* from,struct page* to){
	struct pid_namespace * ns;
	unsigned long pfn,pfn0;
	pfn=page_to_pfn(to);
	pfn0=page_to_pfn(from);
	list_for_each_entry(ns,&all_pid_ns_head,entry){
		if(ns->level>0)
		  atomic_set(&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]),atomic_read(&(ns->page_counter[pfn_to_low(pfn0)][pfn_to_high(pfn0)])));
	}
/*	ns=&init_pid_ns;
	if(!ns->page_counter)
	init_pid_ns_counter(ns);
	atomic_set(&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]),atomic_read(&(ns->page_counter[pfn_to_low(pfn0)][pfn_to_high(pfn0)])));
	*/

}
int get_page_counter_in_ns(struct page* page,struct pid_namespace* ns){
	unsigned long pfn=page_to_pfn(page);
if( ns->page_counter)
	return atomic_read(&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]));
/*	if(page_mapped(page)){
		if(PageKsm(page)){
			return 	do_ksm_page_count(page,ns);
		}else if(PageAnon(page)){
			return 	do_anon_page_count(page,ns);
		}
		else if(page_mapping(page)){
			return do_file_page_count(page,ns);		
		}
	}*/
	return 0;

}
int inc_page_counter_in_ns(struct page* page,struct vm_area_struct* vma){
	struct pid_namespace* ns;
	unsigned long pfn;
	struct task_struct * p;
	atomic_t * counter;
	int i;
	p=vma->vm_mm?vma->vm_mm->owner:current;
	p=p?p:current;
	ns=p?ns_of_pid(task_pid(p)):NULL;
	if(ns==NULL){
	  return -1;
	  printk("ns==null ,not chang counter");
	}
	if(ns->level<sclock_control->level)
	  return 0;
	pfn=page_to_pfn(page);
	if(!ns->page_counter){
		return 0;
		//init_pid_ns_counter(ns);
		printk("creat page_counter!-----%d,%d\n",max_pfn,max_pfn>>10);
	}
	counter=&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]);
	//	if(atomic_read(counter)>=0){
	atomic_inc(counter);
	if(sclock_control->action&request_coa)
	  check_isolation(page);
	//	}
	//	else
	//	  atomic_set(counter,0);
	return atomic_read(counter);
}
int inc_page_counter_in_ns_nocheck(struct page* page,struct vm_area_struct* vma){
	struct pid_namespace* ns;
	unsigned long pfn;
	struct task_struct * p;
	atomic_t * counter;
	int i;
	p=vma->vm_mm?vma->vm_mm->owner:current;
	p=p?p:current;
	ns=p?ns_of_pid(task_pid(p)):NULL;
	if(ns==NULL){
	  return -1;
	  printk("ns==null ,not chang counter");
	}
	if(ns->level<sclock_control->level)
	  return 0;
	pfn=page_to_pfn(page);
	if(!ns->page_counter){
		return 0;
		//init_pid_ns_counter(ns);
		printk("creat page_counter!-----%d,%d\n",max_pfn,max_pfn>>10);
	}
	counter=&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]);
	//	if(atomic_read(counter)>=0){
	atomic_inc(counter);
	//	}
	//	else
	//	  atomic_set(counter,0);
	return atomic_read(counter);
}

int inc_page_counter_by_ns(struct page* page,struct pid_namespace* ns){
	unsigned long pfn;
	int i;
	atomic_t * counter;
	if(ns->level<sclock_control->level)
	  return 0;
	if(!ns->page_counter){
	return 0;
		//init_pid_ns_counter(ns);
	//	printk("creat page_counter!-----%d,%d\n",max_pfn,max_pfn>>10);
	}
	pfn=page_to_pfn(page);
	counter=&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]);
	//	if(atomic_read(counter)>=0){
	if(sclock_control->action&request_coa)  
	  check_isolation(page);
	atomic_inc(counter);
	//	}
	//	else
	atomic_set(counter,0);
	//	return atomic_read(counter);
}
int inc_page_counter_by_ns_nocheck(struct page* page,struct pid_namespace* ns){
	unsigned long pfn;
	int i;
	atomic_t * counter;
	if(ns->level<sclock_control->level)
	  return 0;
	if(!ns->page_counter){
	return 0;
		//init_pid_ns_counter(ns);
	//	printk("creat page_counter!-----%d,%d\n",max_pfn,max_pfn>>10);
	}
	pfn=page_to_pfn(page);
	counter=&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]);
	//	if(atomic_read(counter)>=0){
	atomic_inc(counter);
	//	}
	//	else
	atomic_set(counter,0);
	//	return atomic_read(counter);
}
int set_page_counter_in_ns(int val, struct page* page,struct vm_area_struct* vma){
	struct pid_namespace* ns;
	unsigned long pfn;
	struct task_struct * p;
	int i;
	atomic_t * counter;
	/*	if(!vma->vm_mm){
		return -1;
		}
		if(!vma->vm_mm->owner){
		return -1;
		}
		ns=ns_of_pid(task_pid(vma->vm_mm->owner));
		*/
	p=vma->vm_mm?vma->vm_mm->owner:current;
	p=p?p:current;
	ns=p?ns_of_pid(task_pid(p)):NULL;
	if(ns==NULL){
		return -1;
		printk("ns==null ,not chang counter");
	}
	if(ns->level<sclock_control->level)
	  return -1;
	if(!ns->page_counter){
	return 0;
		//	init_pid_ns_counter(ns);
		printk("creat page_counter!-----%d,%d\n",max_pfn,max_pfn>>10);
	}
	pfn=page_to_pfn(page);
	counter=&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]);
	atomic_set(counter,val);
	return atomic_read(counter);
}
int reset_page_counter_in_ns(struct page* page){
	struct pid_namespace * ns;
	unsigned long pfn;
	pfn=page_to_pfn(page);
//while(!mutex_trylock(&pid_ns_mutex)){
//}
	list_for_each_entry(ns,&all_pid_ns_head,entry){
	if(ns->level>=sclock_control->level)
		atomic_set(&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]),0);
	}	
//	mutex_unlock(&pid_ns_mutex);
/*	ns=&init_pid_ns;
	atomic_set(&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]),0);
*/
}
int dec_page_counter_in_ns(struct page* page,struct vm_area_struct* vma){

	struct pid_namespace* ns;
	unsigned long pfn;
	struct task_struct * p;
	int i;
	atomic_t * counter;
	p=vma->vm_mm?vma->vm_mm->owner:current;
	p=p?p:current;
	ns=p?ns_of_pid(task_pid(p)):NULL;
	if(ns==NULL){
		return -1;
		printk("ns==null ,not chang counter");
	}
	if(ns->level<sclock_control->level)
	  return -1;
	if(!ns->page_counter){
		return 0;
		//init_pid_ns_counter(ns);
		//	printk("creat page_counter!-----%d,%d\n",max_pfn,max_pfn>>10);
	}
	pfn=page_to_pfn(page);
	counter=&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]);
	//	if(atomic_read(counter)>=0)
	atomic_dec(counter);
	//	else
	//	  atomic_set(counter,0);
	return atomic_read(counter);
}
int dec_page_counter_by_ns(struct page* page,struct pid_namespace* ns){
	unsigned long pfn;
	int i;
	atomic_t * counter;
	if(ns->level<sclock_control->level)
	  return -1;
	if(!ns->page_counter){
		init_pid_ns_counter(ns);
		printk("creat page_counter!-----%d,%d\n",max_pfn,max_pfn>>10);
	}
	pfn=page_to_pfn(page);
	counter=&(ns->page_counter[pfn_to_low(pfn)][pfn_to_high(pfn)]);
	//	if(atomic_read(counter)>=0)
	atomic_dec(counter);
	//else
	//  atomic_set(counter,0);
	return atomic_read(counter);
}

void check_isolation(struct page* page){
	pte_t * pte;
	unsigned long address;
	spinlock_t* ptl;
	if(sclock_control->action&request_coa){
		if(test_bit(PG_isolation,&page->flags)){
			return;
		}
		//	if(test_bit(PG_isolation,&page->flags)){
		//if(current->mm->def_flags&VM_ISOLATION)
		//	printk(KERN_DEBUG"!!!!!!!!!!!!!!\n");
		if(isContainerSharedPage(page)){
		//	printk("check isolation\n");

			if(page_mapped(page)){
				if(PageKsm(page)){
					do_ksm_page_isolation(page);
					return;
				}
				else if(PageAnon(page)){
					do_anon_page_isolation(page);
					return;
				}
				else if(page_mapping(page)){
					do_file_page_isolation(page);
					return;
				}
			}
		}
		//}
	}
}
struct page *page_trans_compound_anon(struct page *page)
{
	struct page *head; 
	if (PageTransCompound(page)) {
		head= compound_head(page);
		/*
		 * head may actually be splitted and freed from under
		 * us but it's ok here.
		 */
		if (PageAnon(head))
		  return head;
	}
	return NULL;
}


int page_trans_compound_anon_split(struct page *page)
{
	int ret = 0;
	struct page *transhuge_head = page_trans_compound_anon(page);
	if (transhuge_head) {
		/* Get the reference on the head to split it. */
		if (get_page_unless_zero(transhuge_head)) {
			/*
			 * Recheck we got the reference while the head
			 * was still anonymous.
			 */
			if (PageAnon(transhuge_head))
				ret = split_huge_page(transhuge_head);
			else
				/*
				 * Retry later if split_huge_page run
				 * from under us.
				 */
				ret = 1;
			put_page(transhuge_head);
		} else
			/* Retry later if split_huge_page run from under us. */
			ret = 1;
	}
	return ret;
}

int memcmp_pages(struct page *page1, struct page *page2){
	char *addr1, *addr2;
	int ret;
	addr1 = kmap_atomic(page1);
	addr2 = kmap_atomic(page2);
	ret = memcmp(addr1, addr2, PAGE_SIZE);
	kunmap_atomic(addr2);
	kunmap_atomic(addr1);
	return ret;
}

inline int pages_identical(struct page *page1, struct page *page2)
{
	return !memcmp_pages(page1, page2);
}
int write_protect_page(struct vm_area_struct *vma, struct page *page,
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


int merge_into_one_page(struct vm_area_struct *vma,struct page *page, struct page *kpage)
{
	pte_t orig_pte = __pte(0);
	int err = -EFAULT;
	//spinlock_t *ptl;
	if (page == kpage)			/* ksm page forked */
	  return 0;
	lock_page(page);
	/*
	 * If this anonymous page is mapped only here, its pte may need
	 * to be write-protected.  If it's mapped elsewhere, all of its
	 * ptes are necessarily already write-protected.  But in either
	 * case, we need to lock and check page_count is not raised.
	 */
	err = replace_same_page(vma, page, kpage, orig_pte);
	if ((vma->vm_flags & VM_LOCKED) && kpage && !err) {
		munlock_vma_page(page);
		if (!PageMlocked(kpage)) {
			unlock_page(page);
			lock_page(kpage);
			mlock_vma_page(kpage);
			page = kpage;
		}
	}
	unlock_page(page);
	//	printk(KERN_DEBUG"out-------\n");
	return err;
}

void deduplicate(struct page* page,struct vm_area_struct * vma){
	struct sclock_coa_children* coa_children;
	struct sclock_coa_parent* coa_parent;
	struct page* source;
	if(test_and_clear_bit(PG_isolation,&page->flags)){
		if(page->coa_head){//use COA
			coa_children=list_entry(page->coa_head,struct sclock_coa_children,head);
			if(coa_children->parent_head){//check whether this page is children 
				coa_parent=list_entry(coa_children->parent_head,struct sclock_coa_parent,head);
				mutex_lock(&coa_parent->lock);
				if(coa_parent->pfn==COA_DEL||coa_parent->pfn==COA_SKIP)
				  source=NULL;
				else
				  source =pfn_to_page(coa_parent->pfn);
				if(source!=NULL){
					if(get_copy_num(coa_parent)>0){
						if(pages_identical(page,source))
						merge_into_one_page(vma,page,source);
					}
				}
				mutex_unlock(&coa_parent->lock);

			}
		}
	}

}
long releaseIsolationOne(struct task_struct *p){
	struct vm_area_struct* vma;
	pte_t* pte,pte_entry;
	unsigned long address;
	struct page* page;
	if(p==NULL)
	  return -1;
	printk("release isolation task name= %s\n",p->comm);
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_ISOLATION){
			p->mm->def_flags&=~VM_ISOLATION;
			update_isolation_mode(-1);
		}else{
			return -1;
		}
	}else{
		return -1;
	}
	for(;vma;vma=vma->vm_next){
		//	count++;
		vma->vm_flags&=~VM_ISOLATION;
		vma->vm_page_prot.pgprot&=~_PAGE_ISOLATION;
		address=vma->vm_start;
		while(address<vma->vm_end){
			pte=find_pte(p->mm,address);
			if(pte!=NULL){						
				page= pte_page(*pte);
				if(page){
					deduplicate(page,vma);	
				}
				if(pte->pte&_PAGE_ISOLATION){
					pte_entry=*pte;
					pte_entry.pte&=~_PAGE_ISOLATION;
					//	printk(KERN_DEBUG"clear page isolation at pte =0x%lx at adddress [%lx]--[%lx]\n",pte_val(*pte),address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
					set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
					flush_tlb_page(vma, address);
					//	update_mmu_cache(vma, address, pte);
				}
			}
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}	
	}
	return 0;

}
long requestIsolationOne(struct task_struct* p){
	struct vm_area_struct* vma;
	struct mm_struct* mm;
	pte_t* pte,pte_entry;
	unsigned long address;
	struct page* page;
	struct file *file;
	int count=0;
	pid_t tid;
	if(p==NULL)
	  return -1;
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_ISOLATION){
			return -1;
		}
		update_isolation_mode(1);
		p->mm->def_flags|=VM_ISOLATION;
	}else{
		return -1;
	}
	while(vma!=NULL){
		//	printk(KERN_DEBUG"vma->vm_flag=[%lx]\n",vma->vm_flags);
		//printk(KERN_DEBUG"vma->vm_page_prot=[%lx]\n",vma->vm_page_prot.pgprot);
		mm=vma->vm_mm;
		count++;
		vma->vm_flags|=VM_ISOLATION;
		vma->vm_page_prot.pgprot|=_PAGE_ISOLATION;
		address=vma->vm_start;
		//vma->vm_page_prot.pgprot&=~_PAGE_PRESENT;
		//address=vma->vm_start;
		while(address<vma->vm_end){
			pte=find_pte(mm,address);
			if(pte!=NULL){						
				page= pte_page(*pte);
				//	printk(KERN_DEBUG"set page isolation at adddress [%lx]--[%lx]\n",address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
				if(isContainerSharedPage(page)){
					//	printk(KERN_DEBUG"set pte isolation at pte =0x%lx at adddress [%lx]--[%lx]\n",pte_val(*pte),address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
					pte_entry=*pte;
					pte_entry.pte|=_PAGE_ISOLATION;
					set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
					//		flush_tlb_page(vma, address);
					//	update_mmu_cache(vma, address, pte);
				}else{
				//	test_and_set_bit(PG_isolation,&page->flags);//unshared but may shared page,need tracking
				}
			}
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}	
		vma=vma->vm_next;
	}
	flush_tlb_mm(p->mm);
	return 0;

}
long releaseIsolationByPid(unsigned int pid){
	struct task_struct * p=pid?find_task_by_vpid((int)pid):current;
	return releaseIsolationOne(p);
}
long releaseIsolation(void){
	return releaseIsolationByPid(0);
}

int requestIsolationByPid(unsigned int pid){
	struct task_struct * p=pid?find_task_by_vpid((int)pid):current;
}
int requestIsolation(void){
	return 	requestIsolationByPid(0);
}
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

int initPidNsProtection(struct pid_namespace* pid_ns){
	int i;
	if(pid_ns->sclock_lru==NULL){
		pid_ns->sclock_lru=(struct list_head*)kmalloc(sizeof(struct list_head)*NPageColor,GFP_KERNEL);
		pid_ns->sclock_ins_lru=(struct list_head*)kmalloc(sizeof(struct list_head)*NPageColor,GFP_KERNEL);
		pid_ns->sclock_lru_counter=kzalloc(sizeof(atomic_t)*NPageColor,GFP_KERNEL);
		pid_ns->sclock_ins_lru_counter=kzalloc(sizeof(atomic_t)*NPageColor,GFP_KERNEL);
		pid_ns->sclock_lock=kmalloc(sizeof(spinlock_t)*NPageColor,GFP_KERNEL);
	atomic_set(&pid_ns->k,10);
		//	atomic_set(&pid_ns->k,generate_k());
		if(pid_ns->sclock_lru==NULL||pid_ns->sclock_lru_counter==NULL)
		  return -1;
		for(i=0;i<NPageColor;i++)
		{
			INIT_LIST_HEAD(&(pid_ns->sclock_ins_lru[i]));
	spin_lock_init(&(pid_ns->sclock_lock[i]));
			INIT_LIST_HEAD(&(pid_ns->sclock_lru[i]));
		}
		return 0;
	}
}

int requestCacheProtectCurrent(struct task_struct *p){
	pte_t* pte,pte_entry;
	struct page* page;
	unsigned long address;
	struct vm_area_struct* vma;
	struct pid_namespace* pid_ns;
	struct mm_struct* mm;
	struct file *file;
	pid_t tid;
	char buf[50];
	int count=0;
	int i;
//	unsigned long pfn;
	pid_ns=ns_of_pid(task_pid(p));
	//	struct list_head **all_lru=getAllScolorLRU(p);
	if(pid_ns->sclock_lru==NULL){	//all_lru=kmalloc(sizeof(struct list_head*),GFP_KERNEL);
		if(initPidNsProtection(pid_ns)<0)
		  return -1;	
	}
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_NCACHE){
			printk("already get");
			return -1;
		}
		p->mm->def_flags|=VM_CACHE_PROTECT;
		update_protection_cache(1);
	}else{
		return -1;
	}
	while(vma!=NULL){
		//	printk(KERN_DEBUG"vma->vm_flag=[%lx]\n",vma->vm_flags);
		//	printk(KERN_DEBUG"vma->vm_page_prot=[%lx]\n",vma->vm_page_prot.pgprot);
		mm=vma->vm_mm;
		count++;
		file= vma->vm_file;
		if(file){
			file = vma_pr_or_file(vma);
			if(file){
		//		printk(KERN_DEBUG"[file]%s",buf);
			}
		}
		if(!mm){
		//	printk(KERN_DEBUG"[vdso]");

		}else if(vma->vm_start <= mm->brk &&
				vma->vm_end >= mm->start_brk){
		//	printk(KERN_DEBUG"[heap]");
		}
		tid = vm_is_stack(p, vma, 1);

		if(tid>0){
		//	printk(KERN_DEBUG"[stack]");
		}
		vma->vm_flags|=VM_CACHE_PROTECT;
		vma->vm_page_prot.pgprot|=_PAGE_CACHE_PROTECT;
		address=vma->vm_start;
		while(address<vma->vm_end){
			pte=find_pte(mm,address);
			if(pte!=NULL){						
				page= pte_page(*pte);
				//	printk(KERN_DEBUG"set page isolation at adddress [%lx]--[%lx]\n",address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
				if(pte_present(*pte)&&(pte->pte&_PAGE_USER)){
				//	pfn=pte_pfn(pte_entry);
				//	if(!valid_pfn(pfn)){
						pte_entry=*pte;
						pte_entry.pte|=_PAGE_CACHE_PROTECT;
						set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
				//	}
					//	flush_tlb_page(vma, address);
					//	update_mmu_cache(vma, address, pte);
				}
			}
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}	
		vma=vma->vm_next;
	}
//	printk(KERN_DEBUG"there are %d vma\n",count);
		flush_tlb_mm(p->mm);
return 0;

}
int requestProtectCurrent(struct task_struct *p){
	pte_t* pte,pte_entry;
	struct page* page;
	unsigned long address;
	struct vm_area_struct* vma;
	struct pid_namespace* pid_ns;
	struct mm_struct* mm;
	struct file *file;
	pid_t tid;
	int count=0;
	int i;
	pid_ns=ns_of_pid(task_pid(p));

	//	struct list_head **all_lru=getAllScolorLRU(p);
	if(pid_ns->sclock_lru==NULL){	//all_lru=kmalloc(sizeof(struct list_head*),GFP_KERNEL);
		//	printk(KERN_DEBUG"initialize sclock_lru for level %d at pid=%d",task_pid(p)->level,pid_nr(task_pid(p)));
		if(initPidNsProtection(pid_ns)<0)
		  return -1;		
	}
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_PROTECT){
			return -1;
		}
		p->mm->def_flags|=VM_PROTECT;
		update_isolation_mode(1);
		update_protection_cache(1);
	}else{
		return -1;
	}
	while(vma!=NULL){
	//	printk(KERN_DEBUG"vma->vm_flag=[%lx]\n",vma->vm_flags);
	//	printk(KERN_DEBUG"vma->vm_page_prot=[%lx]\n",vma->vm_page_prot.pgprot);
		mm=vma->vm_mm;
		count++;
		file= vma->vm_file;
		if(file){
			file = vma_pr_or_file(vma);
			if(file){
			//	printk(KERN_DEBUG"[file]%s",buf);
			}
		}
		if(!mm){
		//	printk(KERN_DEBUG"[vdso]");

		}else if(vma->vm_start <= mm->brk &&
					vma->vm_end >= mm->start_brk){
	//		printk(KERN_DEBUG"[heap]");
		}
		tid = vm_is_stack(p, vma, 1);

		if(tid>0){
			printk(KERN_DEBUG"[stack]");
		}
		vma->vm_flags|=VM_PROTECT;
		vma->vm_page_prot.pgprot|=_PAGE_PROTECT;
		address=vma->vm_start;
		while(address<vma->vm_end){
			pte=find_pte(mm,address);
			if(pte!=NULL){						
				page= pte_page(*pte);
				//test_and_set_bit(PG_isolation,&page->flags);
				//	printk(KERN_DEBUG"set page isolation at adddress [%lx]--[%lx]\n",address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
				pte_entry=*pte;
				if(pte_present(*pte)&&(pte->pte&_PAGE_USER)){
				//	pfn=pte_pfn(pte_entry);
				//	if(!valid_pfn(pfn)){
						pte_entry=*pte;
						pte_entry.pte|=_PAGE_CACHE_PROTECT;
						set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
				//	}
				}
				if(page_mapcount(page)>1){
					//	printk(KERN_DEBUG"set pte isolation at pte =0x%lx at adddress [%lx]--[%lx]\n",pte_val(*pte),address,(((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT)-1);
					pte_entry.pte|=_PAGE_ISOLATION;
				}
				set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
				//	flush_tlb_page(vma, address);
				//	update_mmu_cache(vma, address, pte);
			}
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}	
		vma=vma->vm_next;
	}
	//printk(KERN_DEBUG"there are %d vma\n",count);
	flush_tlb_mm(p->mm);
	return 0;

}
long RedoRequestProtectOthers(struct task_struct *p){
	pte_t* pte,pte_entry;
	unsigned long address;
	int i;
	struct vm_area_struct* vma;
	struct pid_namespace* pid_ns=ns_of_pid(task_pid(p));
	if(pid_ns->sclock_lru==NULL)
	  if(initPidNsProtection(pid_ns)<0)
		return -1;
	if(p->mm){
		vma=p->mm->mmap;
		p->mm->def_flags|=VM_CACHE_PROTECT;
	}else{
		return -1;
	}
	while(vma!=NULL){
		vma->vm_flags|=VM_CACHE_PROTECT;
		vma->vm_page_prot.pgprot|=_PAGE_CACHE_PROTECT;
		address=vma->vm_start;
		while(address<vma->vm_end){		
			pte=find_pte(p->mm,address);
			if(pte){
				if(pte->pte&_PAGE_CACHE_UC){
				}else{
					pte_entry=*pte;
					if(pte_present(*pte)&&(pte->pte&_PAGE_USER)){
						pte_entry.pte|=_PAGE_CACHE_PROTECT;
						set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
									//		update_mmu_cache(vma, address, pte);
					}
				}
			}
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}
		vma=vma->vm_next;
	}
	flush_tlb_mm(p->mm);
	return 0;
oom:
	return -1;
}
long requestProtectOthers(struct task_struct *p){
	pte_t* pte,pte_entry;
	unsigned long address;
	int i;
	struct vm_area_struct* vma;
	struct pid_namespace* pid_ns=ns_of_pid(task_pid(p));
	if(pid_ns->sclock_lru==NULL)
	  if(initPidNsProtection(pid_ns)<0)
		return -1;
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_CACHE_PROTECT){
			return -1;
		}
		p->mm->def_flags|=VM_CACHE_PROTECT;

	}else{
		return -1;
	}
	while(vma!=NULL){
		vma->vm_flags|=VM_CACHE_PROTECT;
		vma->vm_page_prot.pgprot|=_PAGE_CACHE_PROTECT;
		address=vma->vm_start;
		while(address<vma->vm_end){		
			pte=find_pte(p->mm,address);
			if(pte){
				if(pte->pte&_PAGE_CACHE_UC){
				}else{
					pte_entry=*pte;
					if(pte_present(*pte)&&(pte->pte&_PAGE_USER)){
						pte_entry.pte|=_PAGE_CACHE_PROTECT;
						set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
									//		update_mmu_cache(vma, address, pte);
					}
				}
			}
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}
		vma=vma->vm_next;
	}
	flush_tlb_mm(p->mm);
	return 0;
oom:
	return -1;
}
long requestCacheProtectOthers(struct task_struct *p){
	return requestProtectOthers(p);
}
long releaseProtectOthers(struct task_struct *p){
	pte_t* pte, pte_entry;
	unsigned long address;
	struct vm_area_struct* vma;
		//=ns_of_pid(task_pid(p));
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_CACHE_PROTECT){
			p->mm->def_flags&=~VM_CACHE_PROTECT;
		}else{
			printk("-------p->mm==NULL\n");
			return -1;
		}
	}else{
		return -1;
	}
	for(;vma!=NULL;vma=vma->vm_next){
		vma->vm_flags&=~VM_CACHE_PROTECT;
		vma->vm_page_prot.pgprot&=~_PAGE_CACHE_PROTECT;
		for(address=vma->vm_start;address<vma->vm_end;address+=PAGE_SIZE){		
			pte=find_pte(p->mm,address);
			if(pte!=NULL){
				if(pte->pte&_PAGE_NCACHE){
					pte_entry=*pte;
					pte_entry.pte&=~_PAGE_CACHE_PROTECT;
				//	printk(KERN_DEBUG"clear PAGE_NCACHE+PAGE_CACHE_UC,address=%lx ,pte=%lx ",address,pte->pte);
					set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
					//	flush_tlb_page(vma, address);
					//	update_mmu_cache(vma, address, pte);
				}
			}
		}
	}

	flush_tlb_mm(p->mm);
	return 0;
}
long releaseCacheProtectOthers(struct task_struct * p){
	return releaseProtectOthers(p);
}
long releaseCacheProtectCurrent(struct task_struct *p){
	struct pid_namespace* pid_ns=ns_of_pid(task_pid(p));
	if(releaseProtectOthers(p)>-1){
		update_protection_cache(-1);
		printk("protection_cache -1\n");
		return 0;
	}
	return -1;
}
long releaseProtectCurrent(struct task_struct *p){
	pte_t* pte, pte_entry;
	unsigned long start=0,address=0;
	struct vm_area_struct* vma;
	struct pid_namespace* pid_ns=ns_of_pid(task_pid(p));
	if(p->mm){
		vma=p->mm->mmap;
		start=vma->vm_start;
		if(p->mm->def_flags&VM_PROTECT){
			p->mm->def_flags&=~VM_PROTECT;
			update_protection_cache(-1);
			update_isolation_mode(-1);
			printk("---------update_protection_cache(-1),isolation(-1)\n");
		}else{
			printk("-------p->mm==NULL\n");
			return -1;
		}
	}else{
		return -1;
	}
	for(;vma!=NULL;vma=vma->vm_next){
		vma->vm_flags&=~VM_PROTECT;
		vma->vm_page_prot.pgprot&=~_PAGE_PROTECT;
		for(address=vma->vm_start;address<vma->vm_end;address+=PAGE_SIZE){		
			pte=find_pte(p->mm,address);
			if(pte!=NULL){
				if(pte->pte&_PAGE_NCACHE){
					pte_entry=*pte;
					pte_entry.pte&=~_PAGE_PROTECT;
					//		printk(KERN_DEBUG"clear PAGE_NCACHE+PAGE_CACHE_UC,address=%lx ,pte=%lx ",address,pte->pte);
					set_pte_at(vma->vm_mm, address, pte, pte_entry);
					//	flush_tlb_page(vma, address);
					//	update_mmu_cache(vma, address, pte);
				}
			}
		}
	}
	if(start>address)
	  mmu_notifier_invalidate_range_start(p->mm, start,address);
	return 0;
}
long releaseUCOne(struct task_struct *p){
	pte_t* pte, pte_entry;
	unsigned long address;
	struct vm_area_struct* vma;
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_CACHE_UC_MINUS){
			p->mm->def_flags&=~VM_CACHE_UC_MINUS;
		}else{
			return -1;
		}
	}else{
		return -1;
	}
	for(;vma!=NULL;vma=vma->vm_next){
		vma->vm_flags&=~VM_CACHE_UC_MINUS;
		vma->vm_page_prot.pgprot&=~_PAGE_CACHE_UC_MINUS;
		for(address=vma->vm_start;address<vma->vm_end;address+=PAGE_SIZE){		
			pte=find_pte(p->mm,address);
			if(pte!=NULL){
				if(pte->pte&_PAGE_CACHE_UC_MINUS){
					//	pte->pte&=~_PAGE_NCACHE;
				//	printk(KERN_DEBUG"clear PAGE_NCACHE+PAGE_CACHE_UC,address=%lx ,pte=%lx ",address,pte->pte);
					pte_entry=*pte;
					pte_entry.pte&=~_PAGE_CACHE_UC_MINUS;
					set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
					flush_tlb_page(vma, address);
					update_mmu_cache(vma, address, pte);
				}
			}
		}
	}
	return 0;
}

long setUC(struct task_struct *p){
	pte_t* pte, pte_entry;
	unsigned long address;
	int i;
	struct vm_area_struct* vma;
	struct pid_namespace* pid_ns=ns_of_pid(task_pid(p));
	if(pid_ns->sclock_lru==NULL){
		//	all_lru=kmalloc(sizeof(struct list_head*),GFP_KERNEL);
		printk(KERN_DEBUG"initialize sclock_lru for level %d at pid=%d",task_pid(p)->level,pid_nr(task_pid(p)));
		pid_ns->sclock_lru=(struct list_head*)kmalloc(sizeof(struct list_head)*NPageColor,GFP_KERNEL);
		pid_ns->sclock_lru_counter=kzalloc(sizeof(atomic_t)*NPageColor,GFP_KERNEL);
		pid_ns->sclock_lock=kmalloc(sizeof(spinlock_t)*NPageColor,GFP_KERNEL);
		if(pid_ns->sclock_lru==NULL)
		  return -1;
		for(i=0;i<NPageColor;i++)
		{
			spin_lock_init(&(pid_ns->sclock_lock[i]));
			INIT_LIST_HEAD(&(pid_ns->sclock_lru[i]));
		}
		//	INIT_LIST_HEAD(&(pid_ns->sclock_lru[i]));
	}
	//	return 0;
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_NCACHE){
			return -1;
		}
		p->mm->def_flags|=VM_CACHE_UC_MINUS;
	}else{
		return -1;
	}
	while(vma!=NULL){
			vma->vm_flags|=VM_CACHE_UC_MINUS;
			vma->vm_page_prot.pgprot|=_PAGE_CACHE_UC_MINUS;
			address=vma->vm_start;
			while(address<vma->vm_end){
				pte=find_pte(p->mm,address);
				if(pte){
					if(pte->pte&_PAGE_CACHE_UC){
					}else{
						pte_entry=*pte;
						if(pte_present(*pte)&&(pte->pte&_PAGE_USER)){
							pte_entry.pte&=~_PAGE_CACHE_UC_MINUS;
							printk(KERN_DEBUG"set NCACHE at address=%lx ,pte=%lx ",address,pte->pte);
						}
						set_pte_at_notify(vma->vm_mm, address, pte, pte_entry);
						flush_tlb_page(vma, address);
						update_mmu_cache(vma, address, pte);
					}
				}
				address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
			}
			vma=vma->vm_next;
	}
	return 0;
}

long showOneTskPTE(struct task_struct *p){
	pte_t* pte,pte_entry;
	unsigned long address;
	int i;
	unsigned int action=0;
	int count,count_N,count_UC,count_coa;
int count_C[NPageColor];
for(i=0;i<NPageColor;i++){
count_C[i]=0;
}
struct vm_area_struct* vma;
	struct pid_namespace* pid_ns=ns_of_pid(task_pid(p));
	if(p->mm){
		vma=p->mm->mmap;
		if(p->mm->def_flags&VM_CACHE_PROTECT){
			action|=request_lru;
		}else if(p->mm->def_flags&VM_ISOLATION){
			action|=request_coa;
		}else{
		//	printk("def_flags not protected\n");
			return -1;
		}
	}else{
	//	printk("no mm, process=%s\n",p->comm);

		return -1;
	}
	count=count_N=count_UC=count_coa=0;
	while(vma!=NULL){
		address=vma->vm_start;
		while(address<vma->vm_end){		
			pte=find_pte(p->mm,address);
			if(pte){
				if(pte_present(*pte)){
					if(pte->pte&_PAGE_NCACHE){
						count_N++;
					}
					if(pte->pte&_PAGE_ISOLATION){
						count_coa++;
					}

					if (pte->pte&_PAGE_CACHE_UC_MINUS){
						count_UC++;
					}else{
						struct page*page0=pte_page(*pte);
						if(page0&&page_mapped(page0))
						  count_C[page_to_pfn(page0)%NPageColor]=count_C[page_to_pfn(page0)%NPageColor]+1;
					}
					count++;
				}
			}
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}
		vma=vma->vm_next;
	}
	printk("[process:%s[%s], %d fault, and %d UC,%d C,%d COA",p->comm,getActionStr(action),count_N,count_UC,count-count_UC,count_coa);
	for(i=0;i<NPageColor;i++){
		printk("%d->%d\t",i,count_C[i]);
	}
		return 0;
oom:
	return -1;
}

long showMarkedPTE(void){
	struct task_struct * p;
	struct pid_namespace* pid_ns;
	struct sclock_coa_children * entry,*tmp;
	struct sclock_coa_parent *coa_parent;
	int copy_count,i;
	int min_uid=task_uid(current).val;
	int min_level=task_pid(current)->level;
	printk("show para Protection, protection_level=%d,frequency = %u.\n",protection_level(0),sclock_thread_sleep_millisecs(0));
	if(parent_page_headp){
		list_for_each_entry(coa_parent,parent_page_headp,node){
			printk(KERN_ALERT"source pfn=%lx, copy =%d",coa_parent->pfn,get_copy_num(coa_parent));
		}
	}
	for_each_process(p){
		printk("process:%s",p->comm);
		if(p->mm==NULL){
			//		printk("p->n==NULL,%s\n",p->comm);
			continue;
		}else{
			if(((ns_of_pid(task_pid(p))->level)>=min_level)){
				if(showOneTskPTE(p)==0){
					//	printk(KERN_DEBUG "-------------protected [process id= %d],tsk=%lx [state=%d][pid_ns=%lx] process name=%s, def_FLAGS=%lx,address for mm=%ls---------------------\n",p->pid,p,(int)p->state,ns_of_pid(task_pid(p)),p->comm,p->mm->def_flags,p->mm);
				}else{
					//	printk(KERN_DEBUG "-------------not protected [process id= %d],tsk=%ls, [state=%d][pid_ns=%lx] process name=%s, def_FLAGS=%lx,mm=%lx---------------------\n",p->pid,p,(int)p->state,ns_of_pid(task_pid(p)),p->comm,p->mm->def_flags,p->mm);
				}

			}
			else{
				printk("level=%d,proces:%s\n",ns_of_pid(task_pid(p)));
			}
		}
	}
	int cpu;
	for_each_present_cpu(cpu){
		print_coa_time(cpu);
		print_lru_time(cpu);
	}
	print_lru_total_time();
	for (i=0;i<ASSOCIATIVITY;i++){
		printk("%d",sclock_control->Prob.map[i]);
	}
	printk("];\n");
	//printk(KERN_DEBUG"start Protect.\n");
	return 0;
}


long requestProtect(void){
	struct task_struct * p;
	int min_uid=task_uid(current).val;
	int min_level=task_pid(current)->level;
	for_each_process(p){
		if(p->mm==NULL){
			printk("p->n==NULL\n");
			continue;
		}else{
			if((((int)(task_uid(p).val))>=min_uid)&&((task_pid(p)->level)>=min_level)){
				//	printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
				if(p==current){
					if(requestProtectCurrent(p)<0)
					  return -1;
				}else{
					if(requestProtectOthers(p)<0)
					  continue;
				}
			}
		}
	}

	//printk(KERN_DEBUG"start Protect.\n");
	return 0;
}
long requestProtectPara(int min_uid,int min_level){
	struct task_struct * p;
	int cur_uid=task_uid(current).val;
	int cur_level=task_pid(current)->level;
	min_uid=(min_uid>=cur_uid)?min_uid:cur_uid;
	min_level=(min_level>=cur_level)?min_level:cur_level;
	printk("uid>%d,level>%d",min_uid,min_level);
	for_each_process(p){
		printk(KERN_DEBUG "[process id= %d] [state=%d][userid=%d][level=%d] process name=%s\n",p->pid,(int)p->state,task_uid(p).val,task_pid(p)->level,p->comm);
		if((((int)(task_uid(p).val))>=min_uid)&&((task_pid(p)->level)>=min_level)){
			if(p->mm==NULL){
				printk("p->n==NULL\n");
				continue;
			}else{
				printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
				if(p==current){
					if(requestProtectCurrent(p)<0)
					  return -1;
				}else{
					if(requestProtectOthers(p)<0)
					  continue;
				}
			}
		}
	}
	printk(KERN_DEBUG"start para Protect.\n");
	return 0;
}

long requestExplicitProtectPara(int min_uid,int min_level,char* name){
	struct task_struct * p;
	int cur_uid=task_uid(current).val;
	int cur_level=task_pid(current)->level;
	min_uid=(min_uid>=cur_uid)?min_uid:cur_uid;
	min_level=(min_level>=cur_level)?min_level:cur_level;
	printk("uid>%d,level>%d",min_uid,min_level);
	for_each_process(p){
		//	printk(KERN_DEBUG "[process id= %d] [state=%d][userid=%d][level=%d] process name=%s\n",p->pid,(int)p->state,task_uid(p).val,task_pid(p)->level,p->comm);
		if((((int)(task_uid(p).val))>=min_uid)&&((task_pid(p)->level)>=min_level)){
			if(p->mm==NULL){
				printk("p->n==NULL\n");
				continue;
			}else{
				printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
				if(strcmp(p->comm,name)==0){
					if(requestProtectCurrent(p)<0)
					  return -1;
				}else{
					if(requestProtectOthers(p)<0)
					  continue;
				}
			}
		}
	}
	printk(KERN_DEBUG"start para Protect.\n");
	return 0;
}


long requestUC(void){
	struct task_struct * p;
	if(releaseIsolation()==-1)
	  //	if()
	  for_each_process(p){
		  printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
		  setUC(p);
	  }
	printk(KERN_DEBUG"stop Protect.\n");
	return 0;
}
struct kmem_cache *sclock_page_pte_map_cache;
struct kmem_cache *sclock_entry_cache;

int init_protection_mem(void){
  sclock_page_pte_map_cache=kmem_cache_create("page_pte_map_in_sclock", sizeof(struct sclock_page_pte_map), ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
  sclock_entry_cache=kmem_cache_create("sclock_entry", sizeof(struct sclock_LRU), ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);

}

long requestCacheProtectPara(int min_uid,int min_level,int k,unsigned int useSClockd,unsigned int millisecs,unsigned int fixed){
	struct task_struct * p;
	int cur_uid=task_uid(current).val;
	int cur_level=task_pid(current)->level;
	min_uid=(min_uid>=cur_uid)?min_uid:cur_uid;
	min_level=(min_level>=cur_level)?min_level:cur_level;
	printk("uid>%d,level>%d",min_uid,min_level);
	if(init_protection_mem()<0)
	  return -1;
	protection_level(k);
//	useSClockDaemon(change==1);
	update_daemon_para(useSClockd,fixed,millisecs);
//	sclock_thread_sleep_millisecs(millisecs);
	for_each_process(p){
		printk(KERN_DEBUG "[process id= %d] [state=%d][userid=%d][level=%d] process name=%s\n",p->pid,(int)p->state,task_uid(p).val,task_pid(p)->level,p->comm);
		if((((int)(task_uid(p).val))>=min_uid)&&((task_pid(p)->level)>=min_level)){
			if(p->mm==NULL){
				printk("p->n==NULL\n");
				continue;
			}else{
				printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
				if(p==current){
					if(requestCacheProtectCurrent(p)<0)
					  return -1;
				}else{
					if(requestCacheProtectOthers(p)<0)
					  continue;
				}
			}
		}
	}
	if(	useSClockDaemon(false)){
	  wake_up_interruptible(&lru_thread_wait);
	  printk("start daemon\n");
	}
	printk(KERN_DEBUG"start para Protection, protection_level=%d,frequency = %u.\n",protection_level(0),sclock_thread_sleep_millisecs(0));
	return 0;
}
long releaseProtect(void){
	struct task_struct * p;
struct list_head *lruh,*lru,*tmp;
	int i;
	struct sclock_LRU* sclock_pte,*n;
struct pid_namespace* pid_ns;
	int min_uid=task_uid(current).val;
	int min_level=task_pid(current)->level;
	if(update_protection_cache(0)>1){
		releaseProtectOthers(current);
		return 0;
	}else{
		for_each_process(p){
			if((((int)(task_pid(p)->level))>=min_level)&&(task_uid(p).val>=min_uid)){
				printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
				releaseProtectOthers(p);
				printk(KERN_DEBUG"stop Protect.\n");
			}
		}
	}
	list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
		if(pid_ns->sclock_lru!=NULL){
			i=0;
			/*delete and free all element in the lru list*/
			for(lruh=&(pid_ns->sclock_lru[0]);i<NPageColor;lruh=&(pid_ns->sclock_lru[i])){
				i++;
				if(list_empty(lruh)){
					continue;
				}
				if(lruh!=NULL){
					list_for_each_safe(lru,tmp,lruh){
						sclock_pte=list_entry(lru,typeof(*sclock_pte),sclock_lru);
						list_del(&sclock_pte->sclock_lru);
					//	synchronize_rcu();
						kfree(sclock_pte);
						sclock_pte=NULL;
					}
				}
			}
			printk("try to free pid_ns->sclock_lru");
			kfree(pid_ns->sclock_lru);
			pid_ns->sclock_lru=NULL;
			printk("free sclock_lru\n");
		}
	}

	return 0;
}
long releaseExplicitProtectPara(int min_uid,int min_level,char* name){

	struct task_struct * p;
	int cur_uid=task_uid(current).val;
	int cur_level=task_pid(current)->level;
	min_uid=(min_uid>=cur_uid)?min_uid:cur_uid;
	min_level=(min_level>=cur_level)?min_level:cur_level;
	if(update_protection_cache(0)>1){
		for_each_process(p){
			if(task_pid(p)->level>=current && strcmp(p->comm,name)==0){
				releaseProtectOthers(p);
			}
			return 0;
		}	
	}else{
		for_each_process(p){
			if((((int)(task_pid(p)->level))>=min_level)&&(task_uid(p).val>=min_uid)){
				printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
				releaseProtectOthers(p);
				printk(KERN_DEBUG"stop Protect.\n");
			}
		}
	}
	return 0;

}

long releaseIsolationPara(int min_uid,int min_level){

	struct task_struct * p;
	struct list_head *lruh,*lru,*tmp;
	int i;
	unsigned long flags,pfn;
	struct sclock_coa_children * coa_children,*tmp_children;
	struct sclock_coa_parent * coa_parent,*tmp_parent;
	struct pid_namespace* pid_ns;struct sclock_LRU* sclock_pte,*n;
	int cur_uid=task_uid(current).val;
	int cur_level=task_pid(current)->level;
	min_uid=(min_uid>=cur_uid)?min_uid:cur_uid;
	min_level=(min_level>=cur_level)?min_level:cur_level;
	for_each_process(p){
		if((((int)(task_pid(p)->level))>=min_level)&&((int)((task_uid(p).val))>=min_uid)){
			releaseIsolationOne(p);
		}
	}
	mutex_lock(&all_coa_parent_head_lock);
	list_for_each_entry_safe(coa_parent,tmp_parent,parent_page_headp,node){
		coa_list_lock(coa_parent);
		list_for_each_entry_safe(coa_children,tmp_children,&coa_parent->head,head){
			pfn=coa_children->pfn;
			if(pfn_valid(pfn)){
				struct page* page=pfn_to_page(pfn);
				page->coa_head=NULL;
				list_del(&coa_children->head);
				coa_children_free(coa_children);

			}
		}
		pfn=coa_parent->pfn;
		if(pfn_valid(pfn)){
			struct page* parent_page=pfn_to_page(pfn);
			parent_page->coa_head=NULL;
		}
		list_del(&coa_parent->node);
		
		coa_list_unlock(coa_parent);
		coa_parent_free(coa_parent);
	}
	mutex_unlock(&all_coa_parent_head_lock);

}

long releaseProtectPara(int min_uid,int min_level){

	struct task_struct * p;
	struct list_head *lruh,*lru,*tmp;
	int i;
	struct pid_namespace* pid_ns;struct sclock_LRU* sclock_pte,*n;
	int cur_uid=task_uid(current).val;
	int cur_level=task_pid(current)->level;
	min_uid=(min_uid>=cur_uid)?min_uid:cur_uid;
	min_level=(min_level>=cur_level)?min_level:cur_level;
	if(update_protection_cache(0)>1){
		releaseProtectCurrent(current);
		return 0;
	}else{
		if(releaseProtectCurrent(current)>0){
			for_each_process(p){
				if((((int)(task_pid(p)->level))>=min_level)&&((int)((task_uid(p).val))>=min_uid)){
					printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
					if(p==current){
						//	releaseProtectCurrent(p);
					}else
					  releaseProtectOthers(p);
					printk(KERN_DEBUG"stop Protect.\n");
				}
			}
		}else
		  return -1;
	}
	list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
		if(pid_ns->sclock_lru!=NULL){
			i=0;
			/*delete and free all element in the lru list*/
			for(lruh=&(pid_ns->sclock_lru[0]);i<NPageColor;lruh=&(pid_ns->sclock_lru[i])){
				i++;
				if(list_empty(lruh)){
					continue;
				}
				if(lruh!=NULL){
					list_for_each_safe(lru,tmp,lruh){
						sclock_pte=list_entry(lru,typeof(*sclock_pte),sclock_lru);
						list_del(&sclock_pte->sclock_lru);
						//		synchronize_rcu();
						kfree(sclock_pte);
						sclock_pte=NULL;
					}
				}
			}
			printk("try to free pid_ns->sclock_lru");
			kfree(pid_ns->sclock_lru);
			pid_ns->sclock_lru=NULL;
			printk("free sclock_lru\n");
		}
	}
	return 0;
}
long releaseCacheProtectPara(int min_uid,int min_level){

	struct task_struct * p;
	struct list_head *lruh,*lru,*tmp;
	int i;
	struct pid_namespace* pid_ns;struct sclock_LRU* sclock_pte,*n;
	int cur_uid=task_uid(current).val;
	int cur_level=task_pid(current)->level;
	min_uid=(min_uid>=cur_uid)?min_uid:cur_uid;
	min_level=(min_level>=cur_level)?min_level:cur_level;
	if(update_protection_cache(0)>1){
		releaseCacheProtectCurrent(current);
		return 0;
	}else{
		if(releaseCacheProtectCurrent(current)>-1){
			for_each_process(p){
				if((((int)(task_pid(p)->level))>=min_level)&&((int)((task_uid(p).val))>=min_uid)){
					printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
					if(p==current){
						//	releaseCacheProtectCurrent(p);
					}else
					  if(releaseCacheProtectOthers(p)>-1)
						printk(KERN_DEBUG"stop Protect.\n");
				}
			}
		}else
		  return -1;
	}
	list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
		if(pid_ns->sclock_lru!=NULL){
			i=0;
			/*delete and free all element in the lru list*/
			for(lruh=&(pid_ns->sclock_lru[0]);i<NPageColor;lruh=&(pid_ns->sclock_lru[i])){
				i++;
				if(list_empty(lruh)){
					continue;
				}
				if(lruh!=NULL){
					list_for_each_safe(lru,tmp,lruh){
						sclock_pte=list_entry(lru,typeof(*sclock_pte),sclock_lru);
						list_del(&sclock_pte->sclock_lru);
					//	synchronize_rcu();
						kfree(sclock_pte);
						sclock_pte=NULL;
					}
				}
			}
			i=0;
			printk("try to free pid_ns->sclock_lru");
			kfree(pid_ns->sclock_lru);
		kfree(pid_ns->sclock_ins_lru);
			kfree(pid_ns->sclock_lru_counter);
			kfree(pid_ns->sclock_ins_lru_counter);
				pid_ns->sclock_ins_lru_counter=NULL;
			pid_ns->sclock_ins_lru=NULL;
			pid_ns->sclock_lru_counter=NULL;
			pid_ns->sclock_lru=NULL;
			printk("free sclock_lru\n");
		}
	}
	return 0;
}

long releaseUC(void){
	struct task_struct * p;
	//	if()
	if(update_isolation_mode(0)>1){
		releaseUCOne(current);
		return 0;
	}else
	  for_each_process(p){
		  printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
		  releaseUCOne(p);
		  printk(KERN_DEBUG"stop Protect.\n");
		  return 0;
	  }
	return 0;
}

int sclock_control_add(unsigned int action,unsigned int level,unsigned int userid,unsigned int sleep,unsigned int lines);
asmlinkage long sys_isolation(int type,int nPara,unsigned int paras[],char* name) {
	long t=get_rdtsc(),tt;
	int cpu;
	long ret=0;
	switch(type){
		case 1000:
			ret=showMarkedPTE();
			break;
		case 0:
			ret= requestProtectPara(paras[0],paras[1]);
			break;
		case 4:
			ret= requestExplicitProtectPara(paras[0],paras[1],name);
			break;
		case -4:
			ret=releaseExplicitProtectPara(paras[0],paras[1],name);
			break;
		case 5:
			ret= requestProtectCurrent(current);
			break;
		case -5:
			ret= releaseProtectCurrent(current);
			break;
		case 6:
			for_each_present_cpu(cpu)
				reset_lru_time(cpu);
			
			ret= requestCacheProtectPara(paras[0],paras[1],paras[2],paras[3],paras[4],paras[5]);
			break;
		case 7:
			for_each_present_cpu(cpu)
				reset_lru_time(cpu);
			double_queue(0);
			ret= requestCacheProtectPara(paras[0],paras[1],paras[2],paras[3],paras[4],paras[5]);
			break;
		case 8:
			return requestIsolationByPid(paras[0]);
			break;
		case -8:
			return releaseIsolationByPid(paras[0]);
			break;

		case -6:
			ret= releaseCacheProtectPara(paras[0],paras[1]);
			break;
		case 100:
			ret= show_page_counter();
			break;
		case 2:
			ret=	sclock_control_add(request_coa,paras[0],0,1000,0);
			break;
		case 3:
			ret= 	sclock_control_add(request_lru,paras[0],0,1000,10);
			break;
		case 1:
			ret= requestIsolation();
			break;
		case -3:
			ret= sclock_control_add(release_lru,2,0,1000,0);
			break;
		case -2:
			ret=	sclock_control_add(release_coa,2,0,1000,0);

			break;
		case -1:
			ret= releaseIsolation();
			break;
		case -10:
			ret= releaseProtectPara(paras[0],paras[1]);
			break;
		default:
			ret= requestIsolation();
			break;
	}
	tt=get_rdtsc();
	printk(KERN_DEBUG"---@@@@#####time cost=%d\n\n",tt-t);

	return ret;
}
#define MAX_MEM 2000
asmlinkage long sys_get_physical_addr(long mem[]){
	struct task_struct p=*current;
	struct vm_area_struct* vma=p.mm->mmap;
	pte_t* pte, pte_entry;
	int count=0;
	struct page* page;
	unsigned long address,phy_addr;
		while(vma!=NULL){
			printk(KERN_DEBUG"vm_flag=[%lx]",vma->vm_flags);
		printk(KERN_DEBUG"vm_page_prot=[%lx]\n",vma->vm_page_prot.pgprot);
		address=vma->vm_start;
		while(address<vma->vm_end){
			pte=find_pte(p.mm,address);
			if(pte!=NULL&&count<MAX_MEM){
				page=pte_page(*pte);
				phy_addr=(pte_val(*pte)&PAGE_MASK)|(address &~PAGE_MASK);
				mem[count]=(pte_val(*pte)&PAGE_MASK)|(address&~PAGE_MASK);
				count++;
		//		printk(KERN_DEBUG"virtual=%lx,physical=%lx,pfn=%lx\n,pte=%lx",address,phy_addr,page_to_pfn(page),pte->pte);
			}
			if(count>MAX_MEM)
				return 0;
			address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
		}
		vma=vma->vm_next;
	}
	return count;
}
asmlinkage long sys_set_cacheability(unsigned long addr,size_t len, size_t cacheable) {
	struct task_struct * p=current;
	//	struct mm_struct * mm=current->mm;
	pte_t* pte, pte_entry;
	struct mm_struct * mm;
	unsigned long mmun_end=addr+len,mmun_start=addr;
	unsigned long address=addr;
	struct vm_area_struct* vma;
	vma=find_vma(p->mm,address);
	if(p->mm==NULL){
	//	printk("p->mm==NULL\n");
		return -1;
	}
	mm=p->mm;
	//printk(KERN_DEBUG"[process id= %d][name=%s][exec_vm=%d][start=0x%lx][end=0x%lx]",p->pid,p->comm,(int)(p->mm->exec_vm),vma->vm_start,vma->vm_end);
	if(cacheable==2){
		pte=find_pte(vma->vm_mm,address);
		if(pte)
		  return pte_pfn(*pte);
		else
			return -1;
	}
	if(cacheable==100){
		while(vma!=NULL){
			address=vma->vm_start;
			while(address<vma->vm_end){		
				pte=find_pte(p->mm,address);
				if(pte!=NULL){
					if(pte_present(*pte)){
					//	printk(KERN_DEBUG"address=%lx ,pte=%lx ",address,pte->pte);
						pte->pte|=_PAGE_CACHE_UC_MINUS;
						//	pte->pte|=_PAGE_NCACHE;
						flush_tlb_page(vma, address);
						update_mmu_cache(vma, address, pte);
					}
				}
				address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
			}
			vma=vma->vm_next;
		}
		return 0;
	}
	if(cacheable==200){
		while(vma!=NULL){
			address=vma->vm_start;
			while(address<vma->vm_end){		
				pte=find_pte(p->mm,address);
				if(pte!=NULL){
				//	printk(KERN_DEBUG"address=%lx ,pte=%lx ",address,pte->pte);
					pte->pte|=_PAGE_CACHE_UC;
					//	pte->pte|=_PAGE_NCACHE;
					flush_tlb_page(vma, address);
					update_mmu_cache(vma, address, pte);
				}
				address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
			}
			vma=vma->vm_next;
		}
		return 0;
	}

	if(cacheable==300){
		while(vma!=NULL){
			address=vma->vm_start;
			while(address<vma->vm_end){		
				pte=find_pte(p->mm,address);
				if(pte!=NULL){
				//	printk(KERN_DEBUG"address=%lx ,pte=%lx ",address,pte->pte);
					pte->pte!=~_PAGE_CACHE_UC;
					//pte->pte|=_PAGE_NCACHE;
					flush_tlb_page(vma, address);
					update_mmu_cache(vma, address, pte);
				}
				address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
			}
			vma=vma->vm_next;
		}
		return 0;
	}
	while(addr+len>address){
		if(vma!=NULL){
			if(vma->vm_start<=address&&vma->vm_end>address){
				pte=find_pte(p->mm,address);
				if(pte!=NULL){
					if(cacheable==UNCACHEABLE){
						pte->pte|=_PAGE_CACHE_UC_MINUS;
						clflush_all(address,PAGE_SIZE);
						//pte->pte|=_PAGE_NCACHE;

					}else if(cacheable==3){
						pte->pte|=_PAGE_CACHE_UC;
						clflush_all(address,PAGE_SIZE);
					}
					else if(cacheable==CACHEABLE){
						pte->pte&=~_PAGE_CACHE_UC;
						clflush_all(address,PAGE_SIZE);
						//pte->pte&=~_PAGE_NCACHE;
					}else if(cacheable==6){
						pte->pte&=~_PAGE_CACHE_UC;
						clflush_all(address,PAGE_SIZE);
					}
					else if(cacheable==4){
						pte->pte|=_PAGE_CACHE_UC_MINUS;
						//pte->pte|=_PAGE_NCACHE;
					}
					else if(cacheable==5){
						pte->pte&=~_PAGE_CACHE_UC;
						//pte->pte|=_PAGE_NCACHE;
					}
				//	printk(KERN_DEBUG"address=%lx ,pte=%lx\n",address,pte->pte);
				}
				flush_tlb_page(vma, address);
				update_mmu_cache(vma, address, pte);

				address=((address>>PAGE_SHIFT)+1)<<PAGE_SHIFT;
			}else{
				vma=vma->vm_next;
			}
		}else{
			break;
		}
	}
	if (mmun_end > mmun_start)
	  mmu_notifier_invalidate_range_end(mm, mmun_start, mmun_end);
//	printk(KERN_DEBUG"start Protect.\n");
	return 0;
}
int arrangeAction[16]={
	0,
	1,
	2,
	3,
	4,
	4,
	6,
	6,
	8,
	9,
	8,
	9,
	12,
	12,
	12,
	12,
};

static const char *const  ActionStr[16]={
	"INIT",
	"requestcoa",
	"requestlru",
	"requestboth",
	"releasecoa",
	"releasecoa",
	"requestlru,releasecoa",
	"requestlru,releasecoa",
	"releaselru",
	"requestcoa,releaselru",
	"releaselru",
	"requestcoa,releaselru",
	"releaseboth",
	"releaseboth",
	"releaseboth",
	"releaseboth"
};

void releaselru(unsigned int action,unsigned int level,unsigned int userid,unsigned int sleep){
	struct task_struct* p;
	int cpu;
	sclock_control->action&=(unsigned int)(~request_lru);
sclock_control->expected_action&=(unsigned int)(~request_lru);      
	sclock_control->expected_action&=(unsigned int)(~request_lru);
	sclock_control->level=-1;
	sclock_control->userid=-1;
	sclock_control_op->set_sleep_microsec(sleep);
	for_each_present_cpu(cpu){
		print_lru_time(cpu);
		reset_lru_time(cpu);
	}
	for_each_process(p){
		if((((int)(task_pid(p)->level))>=level)){
			printk(KERN_DEBUG "[process id= %d] [state=%d] process name=%s\n",p->pid,(int)p->state,p->comm);
			if(releaseCacheProtectOthers(p)>-1)
			  printk(KERN_DEBUG "stop Protect.\n");
		}
	}
}
static inline void destroycoa(void){
}

void releasecoa(unsigned int action,unsigned int level,unsigned int userid,unsigned int sleep){
	sclock_control->action&=(unsigned int)(~request_coa);
	sclock_control->expected_action&=(unsigned int)(~request_coa);
	sclock_control->level=-1;
	sclock_control->userid=-1;
	sclock_control_op->set_sleep_microsec(sleep);
	releaseIsolationPara(((int)userid),((int)level));
	int cpu;
	for_each_present_cpu(cpu){
		print_coa_time(cpu);
		reset_coa_time(cpu);
	}
	destroycoa();
}
void requestlru(unsigned int action,unsigned int level,unsigned int userid,unsigned int sleep,unsigned int k){
	struct task_struct * p;
	struct pid_namespace * pid_ns;
	if(sleep!=0){
		sclock_control_op->set_sleep_microsec(sleep);
		if(!useSClockDaemon(false)){
			useSClockDaemon(true);
		}
		printk("wake the daemon\n");
		wake_up_interruptible(&lru_thread_wait);
	}else{
		sclock_control_op->set_sleep_microsec(sleep);
		if(useSClockDaemon(false)){
			useSClockDaemon(true);
		}
	}

	int cpu;
	for_each_present_cpu(cpu)
		reset_lru_time(cpu);
	if(init_protection_mem()<0){
		releaselru(release_lru,level, userid,sleep);
		return -1;
	}
	list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
		if(pid_ns->level>=sclock_control->level)
		  initPidNsProtection(pid_ns);
	}
		protection_level(k);
	sclock_control->action&=(unsigned int)(~release_lru);
	sclock_control->expected_action&=(unsigned int)(~release_lru);
	sclock_control->level=sclock_control->level>level?level:sclock_control->level;
	sclock_control->userid=sclock_control->userid>userid?userid:sclock_control->userid;
	if(sclock_control->debug>2){
		read_prefetchfile("/home/ziqiao/prefetch_table.txt","/home/ziqiao/image_map.txt","canneal");
		print_prefetch();
	}
	for_each_process(p){
		if(p->mm&&ns_of_pid(task_pid(p))->level>=sclock_control->level){
			requestCacheProtectOthers(p);
		}
	}
}
struct list_head* parent_page_headp;
DEFINE_MUTEX(all_coa_parent_head_lock);
static inline void initcoa(void){
	coa_cache_init();
int cpu;
	for_each_present_cpu(cpu)
		reset_coa_time(cpu);	
	parent_page_headp =&parent_page_head;
}
void requestcoa(unsigned int action,unsigned int level,unsigned int userid,unsigned int sleep){
	struct task_struct * p;

	initcoa();

	if(sleep!=0){
		sclock_control_op->set_sleep_microsec(sleep);
		if(!useSClockDaemon(false)){
			useSClockDaemon(true);
		}
		wake_up_interruptible(&sclock_thread_wait);
	}else{
		sclock_control_op->set_sleep_microsec(sleep);
		if(useSClockDaemon(false)){
			useSClockDaemon(true);
		}
	}

	for_each_process(p){
		if(p->mm&&ns_of_pid(task_pid(p))->level>=level){
			requestIsolationByPid(task_pid(p));
		}
	}
	sclock_control->action&=(unsigned int)(~release_coa);
	sclock_control->level=sclock_control->level>level?level:sclock_control->level;
	sclock_control->userid=sclock_control->userid>userid?userid:sclock_control->userid;
}

int sclock_control_add(unsigned int action,unsigned int level,unsigned int userid,unsigned int sleep,unsigned int lines){
	unsigned int orig_action=sclock_control->action;
	int ret=-1;
	sclock_control->action|=action;
	sclock_control->protect_lines=lines;
	sclock_control_op->set_sleep_microsec(sleep);
	if((action&release_lru)&&(orig_action&request_lru)){
		releaselru(action,level,userid,sleep);
		ret++;
	}
	if((action&release_coa)&&(orig_action&request_coa)){
		releasecoa(action,level,userid,sleep);
		ret++;
	}
	if(action&request_lru){
		requestlru(action,level,userid,sleep,lines);
		ret++;
	}
	if(action&request_coa){
		requestcoa(action,level,userid,sleep);
		ret++;
	}
	sclock_control->expected_action|=action;
	if(ret>=0)
	  printk(KERN_DEBUG "control action=%d, level=%d,userid=%d",sclock_control->action,sclock_control->level,sclock_control->userid);
	else{
		printk("error action\n");
	}
	return ret;
}

/*
 * format is protect action= %s, level=%d,userid=%s
 * */
#define LINE_SIZE 2048

char *getActionStr(unsigned int action){
	return ActionStr[action];
}
static char* PROB_MAP="prob_map[";
static void init_sclock_paras(void){

	int i;
	ASSOCIATIVITY=cpuid_assoc();
	//#define CACHE_SET_SIZE cpuid_size()
	CACHE_SIZE=cpuid_size();
	CACHE_BLOCK_SIZE =cache_line_size();
	NPageColor=cpuid_colours();
	printk(KERN_DEBUG "asso=%d,color=%d,size=%u",ASSOCIATIVITY,NPageColor,CACHE_SIZE);
	unsigned int mem[40];
	unsigned int *prob_val=kzalloc(sizeof(unsigned int)*ASSOCIATIVITY,GFP_KERNEL);
	if(!prob_val){
		prob_val=mem;
	}
	prob_val[3]=1;
	sclock_control->Prob.total=1;
	for(i=4;i<ASSOCIATIVITY-2;i++){
		prob_val[i]=5;
		sclock_control->Prob.total+=prob_val[i];
	}
	sclock_control->Prob.map=prob_val;
}
/*level=l userid=u sleep=s action=a*/
static int sclock_control_write(struct file *file, const char __user *buf, size_t len, loff_t * ppos){
	int i, err;
	unsigned long reg;
	char actionarr[20],*action=actionarr;
	char *ptr;
	char line[LINE_SIZE];
	int length;
	size_t linelen;
	unsigned int actionid=sclock_control->action, 
				 level=sclock_control->level,
				 userid=sclock_control->userid,
				 sleep=sclock_control->sleep_microsec,
				 lines=sclock_control->protect_lines,
				 test=sclock_control->fix_number,
				 flush=0,debug=1;
	memset(line, 0, LINE_SIZE);
	length = len;
	copy_from_user(line, buf, length);
	linelen = strlen(line);
	line[linelen]='\0';
	unsigned int total=0,k=0;
	ptr = line + linelen - 1;
	if(sclock_control->Prob.map==NULL){
		init_sclock_paras();
	}
	ptr=line;
	while(1){
		if (strncmp(ptr, "level=", 6)==0){
			level = simple_strtoul(ptr+ 6, &ptr, 0);
			ptr = skip_spaces(ptr);
		}else if (strncmp(ptr, "userid=", 7)==0){
			userid= simple_strtoul(ptr + 7, &ptr, 0);
			ptr = skip_spaces(ptr);
		}else if (strncmp(ptr, "sleep=", 6)==0){
			sleep= simple_strtoul(ptr + 6, &ptr, 0);
			ptr = skip_spaces(ptr);
		}else if(strncmp(ptr,PROB_MAP,strlen(PROB_MAP))==0){
			ptr=line+strlen(PROB_MAP);
			ptr = skip_spaces(line+strlen(PROB_MAP));
			while(strncmp(ptr, "]", 1)!=0){
				if(k>=ASSOCIATIVITY){
					printk("error probability map\n");
					return 0;
				}
				sclock_control->Prob.map[k]=simple_strtoul(ptr + 1, &ptr, 0);
				total+=	sclock_control->Prob.map[k];
				ptr = skip_spaces(ptr);
				k++;
			}
			ptr = skip_spaces(ptr+1);

			while(k<ASSOCIATIVITY){
				sclock_control->Prob.map[k]=0;
				k++;
			}
			sclock_control->Prob.total=total?total:1;
			//	return len;
		}else if (strncmp(ptr, "change=", 7)==0){
			sclock_control->TIMES_TO_CHANGE= simple_strtoul(ptr + 7, &ptr, 0);
			ptr = skip_spaces(ptr);
		}else if (strncmp(ptr, "debug=", 6)==0){
			sclock_control->debug=simple_strtoul(ptr + 6, &ptr, 0);
			if((sclock_control->debug!=3)&&(trace_file!=NULL))
			{
				filp_close(trace_file,NULL);
				trace_file=NULL;
			}
			if((sclock_control->debug==3)&&(trace_file==NULL)){
				trace_file=filp_open("/tmp/trace_queue.txt",O_WRONLY|O_APPEND,0);
			}
			ptr = skip_spaces(ptr);
		}else if (strncmp(ptr, "test=", 5)==0){
			test= simple_strtoul(ptr + 5, &ptr, 0);
			sclock_control->fix_number=test;
			ptr = skip_spaces(ptr);
		}else if (strncmp(ptr, "lines=", 6)==0){
			lines= simple_strtoul(ptr + 6, &ptr, 0);
			ptr = skip_spaces(ptr);
		}else if (strncmp(ptr, "flush=", 6)==0){
			flush=simple_strtoul(ptr + 6, &ptr, 0);
			sclock_control->flush=flush;
			ptr = skip_spaces(ptr);
		}else if (strncmp(ptr, "action=", 7)==0){
			ptr = skip_spaces(ptr+7);
			action=ptr;
			printk(KERN_DEBUG "parse action =%s\n",action);
			actionid=-1;
			for(i=0;i<16;i++){
				if(strncmp(action,ActionStr[i],
								strlen(ActionStr[i]))==0){
					ptr=skip_spaces(ptr+strlen(ActionStr[i]));
					actionid=i;
					break;
				}
			}
		}else{
			break;
		}
	}
	printk("sclock_control action=%s %d %d %d\n",action,actionid,level,userid,sleep);
	sclock_control_add(actionid,level,userid,sleep,lines);
	return len;
}
static int sclock_control_show(struct seq_file *seq, void *offset)
{
	int k=0;
struct pid_namespace* pid_ns;
	if(sclock_control->Prob.map==NULL){
		init_sclock_paras();
	}
	seq_printf(seq, "level=%d\nuserid=%d\nsleep=%d\nactual\n"
				"sleep=%d\naction=%s\ntest=%d\nlines=%d\n"
				"flush=%d,debug=%d, TIMES_TO_CHANGE=%d\n"
				"probability map=[",
				sclock_control->level,
				sclock_control->userid,
				sclock_control->orig_sleep_microsec,
				sclock_control->sleep_microsec,
				getActionStr(sclock_control->action),
				sclock_control->fix_number,
				sclock_control->protect_lines,
				sclock_control->flush,
				sclock_control->debug,
				sclock_control->TIMES_TO_CHANGE);
	for(k=0;k<ASSOCIATIVITY;k++){
		seq_printf(seq,"\t%d",(sclock_control->Prob.map[k]));
	}
	seq_printf(seq,"]\n");

	list_for_each_entry(pid_ns,&all_pid_ns_head,entry){
		seq_printf(seq,"\nk of %lx=%d\n",pid_ns,atomic_read(&pid_ns->k));
		for(k=0;k<NPageColor;k++)
		  seq_printf(seq,"counter%d=%d, ins counter=%d\t",k,atomic_read(&pid_ns->sclock_lru_counter[k]),atomic_read(&pid_ns->sclock_ins_lru_counter[k]));
	}

	return 0;
}
static int sclock_control_open(struct inode *inode, struct file *file)
{
	return single_open(file, sclock_control_show, NULL);
}

static const struct file_operations proc_sclock_control_operations={
	.owner			= THIS_MODULE,
	.read=seq_read,
	.write=sclock_control_write,
	.open=sclock_control_open,
	.llseek=seq_lseek,
	.release		= seq_release,
};

static int __init sclock_control_if_init(void)
{
	proc_create("sclock_control", S_IWUSR | S_IRUGO, NULL, &proc_sclock_control_operations);

	//#define NBlockColor CACHE_SIZE/(ASSOCIATIVITY*CACHE_BLOCK_SIZE)

	return 0;
}
static void __exit sclock_control_if_exit(void)
{
	remove_proc_entry("sclock_control",NULL);
}


module_init(sclock_control_if_init);

module_exit(sclock_control_if_exit);

