#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/sched.h>
#include<linux/proc_fs.h>
#include <linux/types.h>
#include<linux/mm.h>
#include<asm/pgtable.h>
#include<asm/page.h>
#include <linux/tty.h>		/* For the tty declarations */
#include<linux/spinlock.h>
#include <linux/version.h>	/* For LINUX_VERSION_CODE */
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/myservice.h>
static struct kmem_cache* prefetch_cachep=NULL;

struct prefetchForProcess prefetch_process_array[MAX_PROCESS];

int check_same_vpns(unsigned long vpn1[],unsigned long vpn2[],unsigned int id1[],unsigned int id2[],unsigned int max_key){
	int i;
	unsigned long current_key=0;
	for(i=0;((vpn1[i]>0)||(vpn2[i]>0))&&(i<max_key);i++){
		if(vpn1[i]<vpn2[i])
		  return -1;
		else if(vpn1[i]>vpn2[i])
		  return 1;
		else
		  continue;
	}
	for(i=1;((vpn1[i]>0)||(vpn2[i]>0))&&(i<max_key);i++){
		if(id1[i]<id2[i])
		  return -1;
		else if(id1[i]>id2[i])
		  return 1;
		else
		  continue;
	}

	return 0;
}


int prefetch_insert(struct rb_root* root,struct prefetch * prefetch,unsigned int max_key){
	struct rb_node ** new=&(root->rb_node),*parent=NULL;
	while(*new){
		struct prefetch * this=container_of(*new,struct prefetch,node);
		parent=*new;
		int compare=check_same_vpns(prefetch->key_vpn,this->key_vpn,prefetch->key_id,this->key_id,max_key);
		if(compare<0){
			new=&((*new)->rb_left);
		}else if(compare>0)
		  new=&((*new)->rb_right);
		else{
			printk("error duplicate keys\n");
			return -1;
			new=&((*new)->rb_left);
		}
	}
	rb_link_node(&prefetch->node,parent,new);
	rb_insert_color(&prefetch->node,root);
	return 0;
}
struct prefetch* prefetch_search(struct rb_root * root,unsigned long key_vpn[],unsigned int key_id[],unsigned int max_key){
	struct rb_node* node=(root->rb_node);
	struct prefetch* prefetch=NULL;
	while(node){
		prefetch=rb_entry(node,struct prefetch,node);
		int compare=check_same_vpns(key_vpn,prefetch->key_vpn,key_id,prefetch->key_id,max_key);
		if(compare<0)
		  node=node->rb_left;
		else if(compare>0)
		  node=node->rb_right;
		else{
			return prefetch;
		}
	}	
	return NULL;
}
struct file* file_open(const char* path, int flags, int rights) {
	struct file* filp = NULL;
	mm_segment_t oldfs;
	int err = 0;

	oldfs = get_fs();
	set_fs(get_ds());
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if(IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}
void file_close(struct file* file) {
	filp_close(file, NULL);
}
int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(file, data, size, &offset);

	set_fs(oldfs);
	return ret;
}
DEFINE_SPINLOCK(lock_trace);

	struct file * trace_file=NULL;
	void write_trace(unsigned long vpn, unsigned int id){
		char buf[20];
		if(trace_file==NULL)
		  trace_file=filp_open("/home/ziqiao/trace_queue.txt",O_WRONLY|O_APPEND,0);
		memset(buf,0,20);
		switch(id){
			case 0:
				sprintf(buf,"%lx\n",vpn);
				break;
			case 1:
				sprintf(buf,"+%lx\n",vpn);   
				break;
			case 2:
				sprintf(buf,"-%lx\n",vpn);  
				break;
			default:
				break;
		}
		if(trace_file==NULL){
			printk("error open NULL file\n");
			return;
		}
		file_write(trace_file,0,buf,20);

	}

int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
	mm_segment_t oldfs;
	int ret;
	oldfs = get_fs();
	set_fs(get_ds());
	ret = vfs_read(file, data, size, &offset);
	set_fs(oldfs);
	return ret;
}  

void clean_prefetch_map(struct prefetchForProcess* prefetch_map){
int i;
	struct prefetch * prefetch_entry,*n;
	for(i=0;i<prefetch_map->max_id;i++){ 
		struct rb_root *prefetch_root=&prefetch_map->prefetch_roots[i];
		rbtree_postorder_for_each_entry_safe(prefetch_entry,n,prefetch_root,node){
			rb_erase(&prefetch_entry->node,prefetch_root);
			kmem_cache_free(prefetch_cachep,prefetch_entry);
		}
	}
	kfree(prefetch_map->prefetch_roots);
	kfree(prefetch_map->image_map);
};
int find_image_id_by_path(char path[],struct prefetchForProcess* prefetch_map){
	if(!prefetch_map->image_map){
		printk("not prefetch_map");
		return 0;
	}
	int i=0;
	while(i<prefetch_map->max_id){
		if(strlen(prefetch_map->image_map[i].name)>0)
		  if(strstr(path,prefetch_map->image_map[i].name)!=NULL){
			  return i+1;
		  }
		i++;
	}
	return -1;
}
unsigned long find_base_address_by_mm_path(struct mm_struct* mm,char path[]){
	struct file* file;
	char buf[IMAGE_NAME_LEN],*p;
	struct vm_area_struct * vma=mm->mmap;
	unsigned long base;
	while(vma){
		if(vma->vm_file){
			memset(buf,0,IMAGE_NAME_LEN);
			p=d_path(&(vma->vm_file->f_path),buf,IMAGE_NAME_LEN-1);
			if(strlen(path)&&(strstr(p,path)!=NULL))
			  return vma->vm_start;
		}
		vma=vma->vm_next;
	}
	return 0;
}

unsigned long find_base_address_by_path(struct vm_area_struct* vma){
	struct file* file=vma->vm_file;
	unsigned long base;
	while(vma){
		if(vma->vm_file==file){
				base=vma->vm_start;
		}else{
			break;
		}
		vma=vma->vm_prev;
	}
	return base;
}

struct prefetchForProcess* find_prefetch_map(char processname[]){
	struct prefetchForProcess* prefetch_map;
	int i;
	for (i=0;i<10;i++){
		if(strcmp(prefetch_process_array[i].processname,processname)==0){
			return &(prefetch_process_array[i]);
		}
	}
	return NULL;
}
unsigned long find_base_address_by_image_id(struct prefetchForProcess* prefetch_map,struct mm_struct * mm,unsigned long id){
	if(id==0)
	  return 0;
	if(current->image_base_address[id-1]<=0){
		current->image_base_address[id-1]=find_base_address_by_mm_path(mm,prefetch_map->image_map[id-1].name);
	}
	if(sclock_control->debug>5)
	  printk("image=%d, %s, base=%lx",id,prefetch_map->image_map[id-1].name,current->image_base_address[id-1]);
	return current->image_base_address[id-1];
}
unsigned long find_base_address_by_vma(struct prefetchForProcess* prefetch_map,struct vm_area_struct * vma,unsigned long id){
	if(id==0)
	  return 0;
	if(current->image_base_address[id-1]<=0){
		current->image_base_address[id-1]=find_base_address_by_path(vma);
	}
	if(sclock_control->debug>5)
	  printk("image=%d, %s, base=%lx",id,prefetch_map->image_map[id-1].name,current->image_base_address[id-1]);
	return current->image_base_address[id-1];
}
int read_imagemap_file(struct file* f_map,struct prefetchForProcess* prefetch_map){
	int ret=1,i,count;
	unsigned long id=0,max_image=0,offset=0;
	static int BUF_SIZE=2049;
	char buf[BUF_SIZE],*ptr,*last_line,name[1024],*pname;
	while(ret>0){
		memset(buf,0,BUF_SIZE);
		ret=file_read(f_map,offset,buf,BUF_SIZE-1);
		ptr=buf;
		if(ret<0)
		  return 0;
		count=0;
		while(strlen(ptr)){
		//	printk("strlen=%d,",strlen(ptr));
			if(count>=MAXPREFETCH){
				printk("bad file format!\n");
			//	kmem_cache_free(prefetch_cachep,prefetch);
				break;
			}
			id=simple_strtoul(ptr,&ptr,0);
			if(id==0){
				ptr = skip_spaces(ptr);
				max_image=simple_strtoul(ptr,&ptr,0);
				prefetch_map->max_id=max_image;
				prefetch_map->image_map=kzalloc(sizeof(struct imagename)*max_image,GFP_KERNEL);
				prefetch_map->prefetch_roots=kzalloc(sizeof(struct rb_root)*max_image,GFP_KERNEL);
				for(i=0;i<max_image;i++){
					prefetch_map->prefetch_roots[i]=RB_ROOT;
				}
				ptr = skip_spaces(ptr);
				prefetch_map->max_key=simple_strtoul(ptr,&ptr,0);
				printk("max_id=%d max_key= %d\n",max_image,prefetch_map->max_key); 
				ptr++;
				ptr = skip_spaces(ptr);
				id=simple_strtoul(ptr,&ptr,0);
			}
			if(ptr[0]=='\n'){
				last_line=ptr;
				ptr++;
				continue;
			}
			ptr = skip_spaces(ptr);
			printk("ptr=%s\n",ptr);
			char * tmp=ptr;
			bool right_end=false;
			while(strlen(tmp)){
				if(tmp[0]=='\n'){
					last_line=tmp;
					right_end=true;
					break;
				}else
				  tmp++;
			}
			if(!right_end)
			  break;
			if(!prefetch_map->image_map){
				printk("bad image mape\n");
				return 0;
			}
			memset(prefetch_map->image_map[id-1].name,0,IMAGE_NAME_LEN);
			if(last_line-ptr)
			  memcpy(prefetch_map->image_map[id-1].name,ptr,last_line-ptr);
			ptr=last_line+1;
			printk("process %d, id=%d,image=%s",i,id,prefetch_map->image_map[id-1].name);
			ptr = skip_spaces(ptr);
		}
		offset+=last_line-buf+1;
	}
	return ret;
}
#define NOT_COMPLETE -2
#define BAD_FORMAT -1
int scan_one_prefetch(struct prefetchForProcess* prefetch_map,struct prefetch* prefetch,char* ptr,char ** ptrp){
	unsigned long address;
	int count=0;
	int err=NOT_COMPLETE;
	while(strlen(ptr)>1){
		address=simple_strtoul(ptr,&ptr,0);
		if(count<prefetch_map->max_key)
		  prefetch->key_vpn[count]=address;
		else
		  prefetch->vpn[count-prefetch_map->max_key]=address;
		if(strlen(ptr)>1){
			if(ptr[0]!='_'){
				printk("bad format _\n");
				return BAD_FORMAT;
			}
			ptr++;
			unsigned int id=simple_strtoul(ptr,&ptr,0);
			if(count<prefetch_map->max_key)
			  prefetch->key_id[count]=id;
			else
			  prefetch->id[count-prefetch_map->max_key]=id;
			count++;
		}else{
			return NOT_COMPLETE;
		}
		if(ptr[0]=='\n'){
			err=0;
			goto out;
		}
		ptr = skip_spaces(ptr);
	}
out:
	if(count<=prefetch_map->max_key){
		printk("bad format _\n");
		return BAD_FORMAT;
	}
	if(!err)
	  *ptrp=ptr;
	return err;
};
int scan_prefetch_file(struct file* f,struct prefetchForProcess* prefetch_map){
	static int BUF_SIZE=2048;
	char buf[BUF_SIZE],*ptr,*last_line,name[1024],*pname;
	unsigned long address,id, offset=0;
	int i,count=0,j;
	struct prefetch* prefetch=kmem_cache_zalloc(prefetch_cachep,GFP_KERNEL);
	int ret=1;
	trace_file=filp_open("/home/ziqiao/trace_queue.txt",O_WRONLY|O_APPEND,0);
	printk("start");
	while(ret>0){
		memset(buf,0,BUF_SIZE);
		ret=file_read(f,offset,buf,BUF_SIZE-1);
		ptr=buf;
		if(ret<0)
		  return 0;
		while(strlen(ptr)){
			//	printk("strlen=%d,",strlen(ptr));
			for(i=0;i<prefetch_map->max_key;i++){
				prefetch->key_vpn[i]=0;
				prefetch->key_id[i]=0;
			}
			for(i=0;i<MAXPREFETCH;i++){
				prefetch->vpn[i]=0;
				prefetch->id[i]=0;
			}
			int err=scan_one_prefetch(prefetch_map,prefetch,ptr,&last_line);
			if(err)
			  break;
			printk("insert %d %d\n",prefetch->key_vpn[0],prefetch->key_id[0]);
			prefetch_insert(&(prefetch_map->prefetch_roots[prefetch->key_id[0]-1]),prefetch,prefetch_map->max_key);
			prefetch=kmem_cache_alloc(prefetch_cachep,GFP_KERNEL);
			ptr=last_line+1;
		}
		offset+=last_line-buf+1;
		//		printk("line offset=%d\n",offset);
	}
	return ret;
}
struct prefetchForProcess* find_available_prefetch_map(char processname[]){
	struct prefetchForProcess * prefetch_map;
	int i;
	for(i=0;i<10;i++){
		prefetch_map=&prefetch_process_array[i];
		if(prefetch_map->processname[0]==0){
			strcpy(prefetch_map->processname,processname);
			break;
		}
		if(strcmp(prefetch_map->processname, processname)==0){
			clean_prefetch_map(prefetch_map);
			break;
		}
		if(i==MAX_PROCESS-1){
			printk("MAX PROCESS");
			return NULL;
		}
	}
	return prefetch_map;
}

int read_prefetchfile(char filename[],char mapname[],char processname[]){
	struct file *f,*f_map;
	struct prefetch* prefetch;
	struct prefetchForProcess* prefetch_map;
	int i;
	int total=0;
	if(!prefetch_cachep){
	 for(i=0;i<10;i++)
		memset(prefetch_process_array[i].processname,0,100);
		prefetch_cachep=kmem_cache_create("prefetch",sizeof(struct prefetch),ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);
	}
	  prefetch_map=find_available_prefetch_map(processname);
	if(!prefetch_map)
	  return 0;
	f = filp_open(filename,O_RDONLY,0);
	if(f == NULL){
		printk(KERN_ALERT "filp_open error!!.\n");
		return 0;
	}
	f_map=filp_open(mapname,O_RDONLY,0);
	if(f_map == NULL){
		printk(KERN_ALERT "filp_open error!!.\n");
		return 0;
	}
	if(!prefetch_cachep){
		printk("bad cachep\n");
	}
	read_imagemap_file(f_map,prefetch_map);
	scan_prefetch_file(f,prefetch_map);
	filp_close(f,NULL);
	filp_close(f_map,NULL);
}


int print_prefetch(void){
	struct prefetchForProcess* prefetch_map;
	int i,j;
	for(i=0;i<10;i++){
		prefetch_map=&prefetch_process_array[i];
		if(prefetch_map->processname[0]!=0){
			for(j=0;j<prefetch_map->max_id;j++){
				printk("process %d, image of %d is %s\n",i,j+1,prefetch_process_array[i].image_map[j].name);
				struct rb_root *prefetch_root=&prefetch_map->prefetch_roots[j];
				struct prefetch * prefetch_entry,*n;
				printk("%s",prefetch_map->processname);
				rbtree_postorder_for_each_entry_safe(prefetch_entry,n,prefetch_root,node){
					printk("<%ld,%ld>,%ld,%ld",prefetch_entry->key_vpn[0],prefetch_entry->key_id[0],prefetch_entry->vpn[0],prefetch_entry->id[0]);   
				}
			}
		}
		printk("\n");
	}
	return 0;
}

void clean_allprefetch(void){
	struct prefetchForProcess* prefetch_map;
	int i,j;
	for(i=0;i<10;i++){
		prefetch_map=&(prefetch_process_array[i]);
		if(prefetch_map->processname[0]!=0){
			clean_prefetch_map(prefetch_map);
		}
	}
}
struct prefetch* find_prefetches(char processname[],unsigned long key_vpn[],unsigned int key_id[]){
	int i=0,j=0,k=0,match_n=0;
	struct prefetchForProcess* prefetch_map;
	struct prefetch * prefetch_entry=NULL;
	for (i=0;i<10;i++){
		if(strcmp(prefetch_process_array[i].processname,processname)==0){
			prefetch_map=&prefetch_process_array[i];
			struct rb_root * root=&(prefetch_map->prefetch_roots[key_id[0]-1]);
			prefetch_entry=prefetch_search(root,key_vpn,key_id,prefetch_map->max_key);
		}
	}
	return prefetch_entry;
}

struct prefetch*  find_prefetches_by_map(struct prefetchForProcess* prefetch_map,unsigned long key_vpn[],unsigned int key_id[]){
	int j=0;
	struct prefetch * prefetch_entry;
	//printk("%s",prefetch_map->processname);
	int ret=-1;
	struct rb_root * root=&(prefetch_map->prefetch_roots[key_id[0]-1]);
	prefetch_entry=prefetch_search(root,key_vpn,key_id,prefetch_map->max_key);
	return prefetch_entry;

}


