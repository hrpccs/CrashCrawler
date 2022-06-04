#ifndef EXITCATCH_H
#define EXITCATCH_H

#define MAX_STACK_DEPTH 20
#define TASK_COMM_LEN 16
#define VALUESIZE  MAX_STACK_DEPTH * sizeof(size_t)


// should get from kernel header ?
#define MAX_VMA_ENTRY 50 
#define MAXLEN_VMA_NAME 64
#define PAGE_SHIFT 13 //8KB differs from kernels
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



// enum vma_type {
// 	file,
	
// }

struct mmap_struct{
	unsigned long start;
	unsigned long end;
	unsigned long flags;
	unsigned long long pgoff;
	unsigned long ino;
	dev_t dev;
	char name[MAXLEN_VMA_NAME]; //name
	
};

struct event{
		pid_t pid;
		pid_t tid;
		pid_t ppid;
		int sig;
		int exit_code;
		char comm[TASK_COMM_LEN];
		unsigned long stack_id;
		unsigned int count;
		struct mmap_struct mmap[MAX_VMA_ENTRY];
};


#endif