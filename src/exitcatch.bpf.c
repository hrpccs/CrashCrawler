// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exitcatch.h"


//Use a ringbuffer Map to send data down to userspace 
struct {
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 1024);
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
	struct event *e;

	// get information in task_struct
	task = (struct task_struct *)bpf_get_current_task();
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
		// e->pid = BPF_CORE_READ(task,pid);
		// e->tid = BPF_CORE_READ(task,tgid);
		e->pid = BPF_CORE_READ(task,tgid);
		e->tid = BPF_CORE_READ(task,pid);
		e->ppid = BPF_CORE_READ(task,parent,pid);
		bpf_get_current_comm(&(e->comm),TASK_COMM_LEN);
		bpf_ringbuf_submit(e,0);
	}

	return 0;
}
char _license[] SEC("license") = "GPL";
