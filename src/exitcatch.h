#ifndef EXITCATCH_H
#define EXITCATCH_H

#define MAX_STACK_DEPTH 20
#define TASK_COMM_LEN 16
#define VALUESIZE  MAX_STACK_DEPTH * sizeof(size_t)

#define MAX_VMA_ENTRY 50 
#define MAXLEN_VMA_NAME 64
#define PAGE_SHIFT 13 //8KB differs from kernels

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