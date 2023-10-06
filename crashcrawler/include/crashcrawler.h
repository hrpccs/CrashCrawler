#ifndef EXITCATCH_H
#define EXITCATCH_H

#define MAX_STACK_DEPTH 20	//parameter for BPF_MAP_TYPE_STACK_TRACE
#define TASK_COMM_LEN 16
#define VALUESIZE  MAX_STACK_DEPTH * sizeof(size_t)


// should get from kernel header ?
// #define MAX_VMA_ENTRY 51
#define MAX_VMA_ENTRY 110//max dynamic lib searching level
#define MAXLEN_VMA_NAME 64
#define MAX_LEVEL 8

/*

the macro below are all default configuration in linux kernel for x86_64

*/

#define PAGE_SHIFT 12 //
#define PAGE_SIZE (1<<PAGE_SHIFT)
#define TOP_OF_KERNEL_STACK_PADDING 0
#define KASAN_STACK_ORDER 0

#define THREAD_SIZE (PAGE_SIZE<<2)
//from /include/linux/sched/prio.h
#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)

#define MAX_USER_RT_PRIO	100
#define MAX_RT_PRIO		MAX_USER_RT_PRIO
#define MAX_PRIO		(MAX_RT_PRIO + NICE_WIDTH)
#define DEFAULT_PRIO		(MAX_RT_PRIO + NICE_WIDTH / 2)
//from /include/linux/kdev_t.h
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

//from /include/linux/kdev.h
#define MAJOR(dev)	((dev)>>8)
#define MINOR(dev)	((dev) & 0xff)

//from /include/linux/mm.h
#define VM_NONE		0x00000000
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008
/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080


//rom /linux/include/uapi/asm-generic/resource.h
#ifndef RLIMIT_RSS
# define RLIMIT_RSS		5	/* max resident set size */
#endif

struct mmap_struct{
	unsigned long start; //segment start address
	unsigned long end;	//segment end address
	unsigned long flags;	//segement rwx
	unsigned long long pgoff;	//page offset
	unsigned long ino;	//inode number
	unsigned long dev;			//device num
	unsigned long parent_ino;
	char name[MAX_LEVEL][MAXLEN_VMA_NAME+1];	//abslote object file path
};


//check handle_event() in exitcatch.c for concrete description
struct event{ 
		unsigned long kernel_stack_id; //key to access kernel stack map
		unsigned long user_stack_id;	//kep to access user stack map
		unsigned long count;			//mmap count
		struct mmap_struct mmap[MAX_VMA_ENTRY]; //get mmap from kernel space
		int sig;						//signal resulting crash
		int exit_code;					

		int pid;
		int tid;
		char comm[TASK_COMM_LEN];// task name

		int ppid;

		unsigned int flags; 
		
		
		unsigned min_flt,maj_flt; 
		unsigned cmin_flt,cmaj_flt;

		unsigned long long cutime; 
		unsigned long long cstime;
		unsigned long long stime;
		unsigned long long utime;
		unsigned long long cgtime; 
		unsigned long long gtime; 

		int prio; //task->prio - MAX_RT_PRIO  
		int nice; // prio  - DEFAULT_PRIO
		int num_threads; //task->signal->nr_threads;
		unsigned long long start_time; //

		unsigned long mm_vsize; //
		unsigned long mm_rss;	//mm_rss
	    unsigned long rsslim; //
		unsigned long mm_start_code; //
		unsigned long mm_end_code; //
		unsigned long mm_start_stack; //
		unsigned long esp; //
		unsigned long eip; //

		int exit_signal;  
		unsigned int cpu;
		unsigned int rt_priority;
		unsigned int policy;

		unsigned long mm_start_data;
		unsigned long mm_end_data;
		unsigned long mm_start_brk;
		unsigned long mm_arg_start;
		unsigned long mm_arg_end;
		unsigned long mm_env_start;
		unsigned long mm_env_end;

		unsigned long long process_time_ns;
		
};


#endif
