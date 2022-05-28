// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 10

//Use to store stacktrace and will be used by bpf_get_stackid()
struct bpf_map_def SEC("maps") map_stack_traces = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = sizeof(size_t) * MAX_STACK_DEPTH,
	.max_entries = 8192
};

//Use a ringbuffer Map to send data down to userspace 
struct bpf_map_def SEC("maps") rb = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 256 * 1024,
};

//Define the format of the event to send to userspace
struct event{
		__u64 start_time;
		__u64 exit_time;
		__u32 pid;
		__u32 tid;
		__u32 ppid;
		__u32 sig;
		int exit_code;
		char comm[TASK_COMM_LEN];
		unsigned long stack_id;
};


SEC("tracepoint/sched/sched_process_exit") // the path in the debugfs, and debugfs need to be mounted
int tracepoint__sched__sched_process_exit(void *ctx)
{
	struct task_struct *task;
	struct event *e;

	u64 pid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid;
	pid = pid >> 32; 
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
		e->start_time = BPF_CORE_READ(task,start_time);
		e->ppid = BPF_CORE_READ(task,parent,pid);
		e->exit_time = bpf_ktime_get_ns();
		bpf_get_current_comm(&(e->comm),TASK_COMM_LEN);
	}

	return 0;
}
char _license[] SEC("license") = "GPL";
