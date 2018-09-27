#ifndef _LINUX_MYSERVICE_H
#define _LINUX_MYSERVICE_H
#include<linux/list.h>
#include<asm/pgtable.h>
#include <linux/percpu.h>
extern struct file* trace_file;
struct sclock_pte_map_vma_counter{
	atomic_t counter;
	bool legal;
};
struct sclock_pte_map_vma_counter* create_sclock_pte_map_vma_counter(void);
void destroy_sclock_pte_map_vma_counter(struct sclock_pte_map_vma_counter* counter);
struct cpuidRegs {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
};

void page_add_anon_rmap_lock(struct page *page,
	struct vm_area_struct *vma, unsigned long address);

#define CACHETYPE_NULL		0
#define CACHETYPE_DATA		1
#define CACHETYPE_INSTRUCTION	2
#define CACHETYPE_UNIFIED	3
/*#define CACHE_SET_SIZE 4096
#define ASSOCIATIVITY 16
#define CACHE_SIZE 8024*1024
#define CACHE_BLOCK_SIZE 64
#define NBlockColor CACHE_SIZE/(ASSOCIATIVITY*CACHE_BLOCK_SIZE)
#define NPageColor 128
*/
unsigned long
vma_to_address(struct page *page, struct vm_area_struct *vma);

extern  unsigned long ASSOCIATIVITY;
//#define CACHE_SET_SIZE cpuid_l3size()
extern  unsigned long CACHE_SIZE;
extern  int CACHE_BLOCK_SIZE;
//#define NBlockColor CACHE_SIZE/(ASSOCIATIVITY*CACHE_BLOCK_SIZE)
extern  unsigned long NPageColor;
extern struct mutex all_coa_parent_head_lock;
struct cacheInfo {
  uint32_t	type:5;
  uint32_t	level:3;
  uint32_t	selfInitializing:1;
  uint32_t	fullyAssociative:1;
  uint32_t	reserved1:4;
  uint32_t	logIds:12;
  uint32_t	phyIds:6;

  uint32_t	lineSize:12;
  uint32_t	partitions:10;
  uint32_t	associativity:10;

  uint32_t	sets:32;

  uint32_t	wbinvd:1;
  uint32_t	inclusive:1;
  uint32_t	complexIndex:1;
  uint32_t	reserved2:29;
};


void cpuid_sclock(struct cpuidRegs *regs);
void getCacheInfo(int index, struct cacheInfo *cacheInfo);


int cpuid_l3size(void);
int cpuid_l3colours(void);
int cpuid_l3assoc(void);
struct probe_map{
	unsigned int* map;
	unsigned int total;
};

struct sclockControl{
	unsigned int action;
	unsigned int expected_action;
	unsigned int level;
	unsigned int userid;
	unsigned int orig_sleep_microsec;
	unsigned int sleep_microsec;
	unsigned int fix_number;
	unsigned int  flush;
	unsigned int debug;
	unsigned int TIMES_TO_CHANGE;
	unsigned int protect_lines;
	struct probe_map Prob;
};
#define MAXPREFETCH 4
#define MAX_KEY 2

struct prefetch{
	unsigned long key_vpn[MAX_KEY];
	unsigned int key_id[MAX_KEY];
	unsigned long vpn[MAXPREFETCH];
	unsigned int id[MAXPREFETCH];
	struct rb_node node;
};
struct prefetchForProcess{
	struct rb_root* prefetch_roots;
	char processname[100];
	struct imagename* image_map;
	int max_id;
	int max_key;
};
#define IMAGE_NAME_LEN 500
struct imagename{
	char name[IMAGE_NAME_LEN];
};
#define MAX_PROCESS 10
extern struct prefetchForProcess prefetch_process_array[MAX_PROCESS];
int read_prefetchfile(char filename[],char imagename[],char processname []);
int print_prefetch(void);
void clean_allprefetch(void);
void clean_prefetch_map(struct prefetchForProcess* p);

struct prefetch* find_prefetches(char processname[],unsigned long vpn[],unsigned int id[]);
struct prefetch* find_prefetches_by_map(struct prefetchForProcess* prefetch_map,unsigned long vpn[],unsigned int id[]);
unsigned long find_base_address_by_vma(struct prefetchForProcess* prefetch_map,struct vm_area_struct * vma,unsigned long id); 
unsigned long find_base_address_by_image_id(struct prefetchForProcess* prefetch_map,struct mm_struct * mm,unsigned long id); 
struct prefetchForProcess* find_prefetch_map(char processname[]);
int find_image_id_by_path(char path[],struct prefetchForProcess* prefetch_map);
 struct sclockControlOp{
	unsigned int (*sleep_microsec_inc)(void);
	unsigned int (*set_sleep_microsec)(unsigned int);
	void (*reset_sleep_microsec)(void);
	unsigned int (*set_level)(unsigned int);
	unsigned int (*set_action)(unsigned int);
	unsigned int (* set_userid)(unsigned int);
	char* (*get_action_str)(unsigned int);
};
#define COA_SKIP 0
#define COA_DEL -1
#define COA_NO_HEAD -2
struct sclock_coa_parent{
	struct list_head head;
	unsigned long pfn;
	struct list_head* parent_head;
	struct pid_namespace* owner;
	atomic_t copy_counter;
	struct list_head node;
	struct mutex lock;
};
static inline void coa_list_lock(struct sclock_coa_parent* coa_parent){
	mutex_lock(&coa_parent->lock);
}
static inline int coa_list_trylock(struct sclock_coa_parent* coa_parent){
	return mutex_trylock(&coa_parent->lock);
}
long RedoRequestProtectOthers(struct task_struct *p);
static inline void coa_list_unlock(struct sclock_coa_parent* coa_parent){
	mutex_unlock(&coa_parent->lock);
}
static inline int get_copy_num(struct sclock_coa_parent* coa_parent){
	return atomic_read(&coa_parent->copy_counter);
}
static inline void inc_copy_num(struct sclock_coa_parent* coa_parent){
	atomic_inc(&coa_parent->copy_counter);
}

static inline void set_copy_num(int i,struct sclock_coa_parent* coa_parent){
	atomic_set(&coa_parent->copy_counter,i);
}
static inline void init_copy_num(struct sclock_coa_parent* coa_parent){
	atomic_set(&coa_parent->copy_counter,0);
}
static inline void dec_copy_num(struct sclock_coa_parent* coa_parent){
 atomic_dec(&coa_parent->copy_counter);
}
struct sclock_coa_children{
	struct list_head head;
	unsigned long pfn;
	struct list_head* parent_head;
	struct pid_namespace* owner;
//	unsigned int copy_number;
};
struct sclock_LRU_double{
	struct list_head sclock_lru;
	struct list_head pte_map;
	//unsigned long address;
	//struct task_struct* owner;
	unsigned long pfn;
	atomic_t access_times;
	atomic_t pte_count;
};//per container per color
struct sclock_LRU{
	struct list_head sclock_lru;
//	pte_t* ptep;
	//unsigned long address;
	//struct task_struct* owner;
	unsigned long pfn;
//	unsigned long address;
//	struct vm_area_struct* vma;
	struct list_head pte_map;
	atomic_t access_times;
	atomic_t pte_count;
};//per container per color

struct sclock_LRU_virtual{
	struct list_head sclock_lru;
	pte_t*  ptep;
	unsigned long address;
	unsigned long pfn;
	struct mm_struct * mm;
	//struct task_struct* owner;
//	unsigned long pfn;
	atomic_t access_times;
};//per container per color

struct sclock_page_pte_map{
	pte_t * ptep;
	struct vm_area_struct *vma;
	unsigned long address;
	struct list_head head;
	struct sclock_pte_map_vma_counter* sclock_pte_map_vma_counter;
};
void add_sclock_pte_map(struct vm_area_struct * vma);
void remove_sclock_pte_map(struct vm_area_struct * vma);
void clean_sclock_pte_map(struct sclock_LRU * sclock_entry);
extern struct mutex pid_ns_mutex; 
extern struct list_head all_pid_ns_head;
extern struct kmem_cache* sclock_cachep;
extern struct kmem_cache* sclock_all_cachep;
int initPidNsProtection(struct pid_namespace* pid_ns);
extern wait_queue_head_t sclock_thread_wait;
extern wait_queue_head_t lru_thread_wait; 
extern struct kmem_cache *sclock_page_pte_map_cache;
extern struct kmem_cache *sclock_entry_cache;
extern struct sclockControl* sclock_control;
extern struct sclockControlOp* sclock_control_op;
extern struct list_head* parent_page_headp;
void  coa_cache_init(void);
struct sclock_coa_parent* init_coa_parent(struct page* page);
void coa_parent_free(struct sclock_coa_parent *coa_parent);
void coa_children_free(struct sclock_coa_children *coa_chlidren);
pte_t* find_pte(struct mm_struct* mm, unsigned long address);
int handle_double_cache_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, unsigned int flags);
int get_k_of_ns(struct pid_namespace* pid_ns);
int get_current_k(void);
void dec_k_of_ns(struct pid_namespace* pid_ns);
void inc_k_of_ns(struct pid_namespace* pid_ns);
int set_k_of_ns(struct pid_namespace* pid_ns,unsigned int k);
DECLARE_PER_CPU(unsigned long long,global_interval);
DECLARE_PER_CPU(unsigned long long,global_interval_normal); 
DECLARE_PER_CPU(unsigned long long,global_interval_early); 
DECLARE_PER_CPU(unsigned long long,global_count); 
DECLARE_PER_CPU(unsigned long long,global_count_normal_total);
DECLARE_PER_CPU(unsigned long long,global_count_total);
DECLARE_PER_CPU(unsigned long long,global_count_normal); 
DECLARE_PER_CPU(unsigned long long,global_count_early); 
DECLARE_PER_CPU(unsigned long long,global_interval_coa);
DECLARE_PER_CPU(unsigned long long,global_interval_coa_normal); 
DECLARE_PER_CPU(unsigned long long,global_interval_coa_early); 
DECLARE_PER_CPU(unsigned long long,global_interval_coa_fail); 
DECLARE_PER_CPU(unsigned long long,global_count_coa); 
DECLARE_PER_CPU(unsigned long long,global_count_coa_normal); 
DECLARE_PER_CPU(unsigned long long,global_count_coa_early);
DECLARE_PER_CPU(unsigned long long,global_count_coa_fail);
DECLARE_PER_CPU(unsigned long long,global_prefetch);
DECLARE_PER_CPU(unsigned long long,global_prefetch_count);
 DECLARE_PER_CPU(unsigned long long,global_all_prefetch_count);
DECLARE_PER_CPU(unsigned long long,global_before_prefetch_count);
DECLARE_PER_CPU(unsigned long long,global_ins_count);
void write_trace(unsigned long vpn,unsigned int id);
int do_copy_on_read(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, unsigned int flags);
int manage_cacheability(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, unsigned int flags);
void check_isolation(struct page* page);
int merge_into_one_page(struct vm_area_struct *vma,
		struct page *page, struct page *kpage);
int compare_sclock(void* priv,struct list_head* a,struct list_head* b);
void sort_sclock_lru(struct list_head* lru_head);
void del_coa_parent_slow(struct sclock_coa_parent* coa_entry);
void del_original_slow(struct page * page);

pte_t *page_find_pte(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp, int sync);

static inline void clflush_all(unsigned long from,unsigned long size){
        unsigned long offset;
        for(offset=0;offset<size;offset+=CACHE_BLOCK_SIZE){
//              smp_mb();
                clflush((unsigned long)from+offset);
        }
}
static inline void clflush_one(unsigned long from,unsigned long offset){
clflush(from+offset);
}
#define	request_coa 1
#define	request_lru 2
#define	request_both 3
#define	release_coa 4
#define	release_lru 8
#define	release_both 12
unsigned long mmap_region_to_mm(struct mm_struct *mm,struct vm_area_struct *vma,struct vm_area_struct **new_vma,struct file *file, unsigned long addr,
			unsigned long len, vm_flags_t vm_flags, unsigned long pgoff);
unsigned long map_anon_to_mm(struct mm_struct *mm, unsigned long addr, unsigned long len);
int replace_same_page(struct vm_area_struct *vma, struct page *page,
		struct page *source, pte_t orig_pte);
//int remap_tofilesource(struct page* source,unsigned long address,struct vm_area_struct *vma);
void clean_links(struct mm_struct *mm, unsigned long addr,
			unsigned long end, struct vm_area_struct **pprev,
			struct rb_node ***rb_link, struct rb_node **rb_parent);
//int	add_page_into_children_pages(struct page* page,struct pid_namespace* pid_ns);
struct sclock_coa_parent *get_original(struct sclock_coa_parent *coa_parent);
#define VM_CACHE_PROTECT (VM_NCACHE|VM_CACHE_UC_MINUS)
#define VM_PROTECT (VM_CACHE_PROTECT|VM_ISOLATION)
#define _PAGE_CACHE_PROTECT (_PAGE_NCACHE|_PAGE_CACHE_UC_MINUS)
#define _PAGE_PROTECT (_PAGE_CACHE_PROTECT|_PAGE_ISOLATION)
#define SCLOCK_TO_BE_DEL -2
#define SCLOCK_LOCKED -3
#define SCLOCK_DUPLICATED -4
long get_rdtsc(void);
void update_daemon_para(bool change,int fixed,unsigned int t);
 bool useSClockDaemon(bool change);
struct list_head** getAllScolorLRU(struct task_struct * task);
int protection_level(int k);
int protection_UC(int k);
int do_page_count(struct sclock_LRU* sclock_entry, pteval_t flags);
int do_page_count_accessed(struct page* page,int pid_ns_level);
int do_lru_count_accessed(struct sclock_LRU* sclock_entry,int pid_ns_level);
int do_page_reverse_set(struct sclock_LRU* sclock_entry, pteval_t flags);
int do_page_reverse_clear(struct sclock_LRU* sclock_entry, pteval_t flags);
void init_pid_ns_counter(struct pid_namespace* ns);
int update_isolation_mode(int change);
pte_t* find_pte_lock
(struct mm_struct* mm, unsigned long address, spinlock_t* ptl);
int update_protection_cache(int change);
int get_protection_cache_level(void);
int get_protection_cache_userid(void);
bool double_queue(int set);
int update_protection_paras(int level, int userid);
void copy_all_page_counter(struct page* from,struct page* to);
int dec_page_counter_in_ns(struct page* page,struct vm_area_struct* vma);
int inc_page_counter_in_ns(struct page* page,struct vm_area_struct* vma);
int inc_page_counter_by_ns(struct page* page,struct pid_namespace* ns);
int dec_page_counter_by_ns(struct page* page,struct pid_namespace* ns);
int set_page_counter_in_ns(int val, struct page* page,struct vm_area_struct* vma);
int get_page_counter_in_ns(struct page* page,struct pid_namespace* ns);
int reset_page_counter_in_ns(struct page* page);
unsigned long getCurrentChildrenDefFlag(void);
int isContainerSharedPage(struct page* page);
//int do_ksm_page_set(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags);
//int do_file_page_set(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags);
//int do_anon_page_set(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags);

int do_page_setirq(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags,int count);
int do_page_set(struct page* page,struct pid_namespace* pid_ns_ref, pteval_t flags,int count);
int link_page_pte(struct page* page,pte_t * ptep,struct mm_struct *mm);
unsigned int sclock_thread_sleep_millisecs(unsigned int t);
#endif


