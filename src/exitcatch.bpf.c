// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

SEC("tracepoint/sched/sched_process_exit") // the path in the debugfs
int tracepoint__sched__sched_process_exit(void *ctx)
{
	struct {
		__u64 start_time;
		__u64 exit_time;
		__u32 pid;
		__u32 tid;
		__u32 ppid;
		__u32 sig;
		int exit_code;
		char comm[TASK_COMM_LEN];
	}event;
	__u64 pid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid;
	pid = pid >> 32; 
	struct task_struct *task;
	// get information in task_struct
	// exit_code,
	task = (struct task_struct *)bpf_get_current_task();
	int exitcode = BPF_CORE_READ(task,exit_code);
	if(exitcode == 0){ //exit normally
		return 0;
	}
	event.exit_code = exitcode >> 8;
	event.sig = exitcode & 0xff; 
	event.start_time = BPF_CORE_READ(task,start_time);
	event.ppid = BPF_CORE_READ(task,parent,pid);
	bpf_get_current_comm(&(event.comm),TASK_COMM_LEN);
	event.exit_time = bpf_ktime_get_ns();

	char str[] = "comm:%s exitcode:%d signal:%d\n";
	bpf_trace_printk(str,sizeof(str),event.comm,event.exit_code,event.sig);
	return 0;
}
char _license[] SEC("license") = "GPL";
