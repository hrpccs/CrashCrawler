// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exitcatch.h"


//Use a ringbuffer Map to send data down to userspace 
struct {
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,64 * sizeof(struct event));
}rb SEC(".maps");

//Use to store stacktrace and will be used by bpf_get_stackid()
struct {
	__uint(type,BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size,sizeof(u32));
	__uint(value_size,VALUESIZE);
	__uint(max_entries,8192);
} map_stack_traces SEC(".maps");

// the path in the debugfs, and debugfs need to be mounted
SEC("tp/sched/sched_process_exit") 
int trace_event_raw_sched_process_exit(struct trace_event_raw_sched_process *ctx)
{
	struct task_struct *task;
	struct vm_area_struct *vma;
	struct file *file;
	struct event *e;


	// get information in task_struct
	task = (struct task_struct *)bpf_get_current_task();
	vma = BPF_CORE_READ(task->mm->mmap)

	long long temp = 0;
	int exitcode = BPF_CORE_READ(task,exit_code);

	if(exitcode == 0){ //exit normally
		return 0;
	}
	//Log event to ringbuffer to be read by userspace 
	e = bpf_ringbuf_reserve(&rb,sizeof(*e), 0);
	if(e){
		e->stack_id = bpf_get_stackid(ctx,&map_stack_traces,0);
		e->exit_code = exitcode >> 8;
		e->sig = exitcode & 0xff;
		e->pid = BPF_CORE_READ(task,tgid);
		e->tid = BPF_CORE_READ(task,pid);
		e->ppid = BPF_CORE_READ(task,parent,pid);
		bpf_get_current_comm(&(e->comm),TASK_COMM_LEN);
		
		#pragma clang loop unroll(full)
		for(int i=0;i<MAX_MMAP_ENTRY;i++){
			if(!vma){
				file = BPF_CORE_READ(vma->vm_file);
				if(file){
					e->mmap[i].dev = BPF_CORE_READ(vma->vm_file->f_inode->i_sb->s_dev);
					e->mmap[i].ino = BPF_CORE_READ(vma->vm_file->f_inode->i_ino);
					temp = BPF_CORE_READ(vma->vm_pgoff);
					e->mmap[i].pgoff = temp << PAGE_SHIFT;
				}
				e->mmap[i].start = BPF_CORE_READ(vma->vm_start);
				e->mmap[i].end = BPF_CORE_READ(vma->vm_end);
				e->mmap[i].flags = BPF_CORE_READ(vma->vm_flags);
				
			}
		}
		bpf_ringbuf_submit(e,0);
	}

	return 0;
}
char _license[] SEC("license") = "GPL";
