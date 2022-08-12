#ifndef EXITCATCH_H
#define EXITCATCH_H

#define MAX_STACK_DEPTH 20
#define TASK_COMM_LEN 16
#define VALUESIZE  MAX_STACK_DEPTH * sizeof(size_t)


// should get from kernel header ?
#define MAX_VMA_ENTRY 35
#define MAXLEN_VMA_NAME 64
#define MAX_LEVEL 8
#define PAGE_SHIFT 13 //8KB differs from kernels
#define PAGE_SIZE 
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
	unsigned long start;
	unsigned long end;
	unsigned long flags;
	unsigned long long pgoff;
	unsigned long ino;
	dev_t dev;
	char name[MAX_LEVEL][MAXLEN_VMA_NAME+1];
};

struct event{
		unsigned long kernel_stack_id;
		unsigned long user_stack_id;
		unsigned long count;
		struct mmap_struct mmap[MAX_VMA_ENTRY];
		int sig;
		int exit_code;

		pid_t pid;//1  done
		pid_t tid;//  done
		char comm[TASK_COMM_LEN];//2  done
		long state; // + exit_state 3

		pid_t ppid;//4 ppid  done
		pid_t pgid;// 5 pgid
		pid_t sid; //6 sid

		//info in signal_struct
		int sig_tty_index; //7 tty_nr
		int sig_tty_driver_major;
		int sig_tty_driver_minor_start;
		int tty_pgrp;		//8 tty_pgrp
		unsigned int flags; //9 task->flags;  done
		
		// int permitted; no need , because we are the boss
		unsigned min_flt,maj_flt; //10 - 13  done
		unsigned cmin_flt,cmaj_flt;

		unsigned long long cutime; //14-17  done
		unsigned long long cstime;
		unsigned long long stime;
		unsigned long long utime;
		unsigned long long cgtime;  done
		unsigned long long gtime;  done

		int prio; //18 task->prio - MAX_RT_PRIO  done
		int nice; //19 prio  - DEFAULT_PRIO
		int num_threads; //20 task->signal->nr_threads;
						//21 0
		unsigned long long start_time; //22  done

		unsigned long mm_vsize; //23  done
		unsigned long mm_rss;						//24 mm_rss
	    unsigned long rsslim; //24
		unsigned long mm_start_code; //25  done
		unsigned long mm_end_code; //26  done
		unsigned long mm_start_stack; //27  done
		unsigned long esp; //28
		unsigned long eip; //29









};


#endif