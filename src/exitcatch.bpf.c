// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "exitcatch.h"

#define MAX_STRLEN 20

// Use a ringbuffer Map to send data down to userspace
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * sizeof(struct event));
} rb SEC(".maps");

// Use to store stacktrace and will be used by bpf_get_stackid()
struct
{
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, VALUESIZE);
	__uint(max_entries, 8192);
} map_stack_traces SEC(".maps");

static char *simple_dname(const struct dentry *dentry, char *buffer, int buflen)
{
	struct qstr dname = BPF_CORE_READ(dentry, d_name);
	if (dname.len < MAXLEN_VMA_NAME)
	{
		bpf_probe_read_kernel_str(buffer, dname.len & (MAXLEN_VMA_NAME - 1), dname.name);
		return buffer;
	}
	return buffer + buflen + 1;
}

// the path in the debugfs, and debugfs need to be mounted
// SEC("tp/sched/sched_process_exit")
// int trace_event_raw_sched_process_exit(void *ctx)
SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe__do_exit, long exitcode)
{
	struct task_struct *task;
	struct vm_area_struct *vma;
	struct file *file;
	struct path filepath;
	struct event *e;

	if (exitcode == 0 || exitcode >> 8 != 0)
	{ // exit normally
		return 0;
	}

	// get information in task_struct
	task = (struct task_struct *)bpf_get_current_task();
	vma = BPF_CORE_READ(task, mm, mmap);

	long long temp = 0;
	char *tptr = 0;

	// Log event to ringbuffer to be read by userspace
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e)
	{
		e->stack_id = bpf_get_stackid(ctx, &map_stack_traces, 0);
		e->exit_code = exitcode >> 8;
		e->sig = exitcode & 0xff;
		e->pid = BPF_CORE_READ(task, tgid);
		e->tid = BPF_CORE_READ(task, pid);
		e->ppid = BPF_CORE_READ(task, parent, pid);
		bpf_get_current_comm(&(e->comm), TASK_COMM_LEN);
		int count = 0;

#pragma unroll
		for (int i = 0; i < MAX_VMA_ENTRY; i++)
		{
			if (vma)
			{
				file = BPF_CORE_READ(vma, vm_file);
				if (!file)
				{
					vma = BPF_CORE_READ(vma, vm_next);
					continue;
				}
				e->mmap[count].dev = BPF_CORE_READ(vma, vm_file, f_inode, i_sb, s_dev);
				e->mmap[count].ino = BPF_CORE_READ(vma, vm_file, f_inode, i_ino);
				temp = BPF_CORE_READ(vma, vm_pgoff);
				e->mmap[count].pgoff = temp << PAGE_SHIFT;

				e->mmap[count].start = BPF_CORE_READ(vma, vm_start);
				e->mmap[count].end = BPF_CORE_READ(vma, vm_end);
				e->mmap[count].flags = BPF_CORE_READ(vma, vm_flags);
				filepath = BPF_CORE_READ(file, f_path);
				struct dentry *dentry = filepath.dentry;
				struct qstr dname = BPF_CORE_READ(dentry, d_name);

				//read abs path of share lib
				// MAXLEN_VMA_NAME = 2^n;
				for (int i = MAX_LEVEL - 1; i >= 0; i--)
				{
					bpf_probe_read_kernel_str(&(e->mmap[count].name[i][0]), (dname.len + 5) & (MAXLEN_VMA_NAME - 1), dname.name - 4); // weak ptr offset
					dentry = BPF_CORE_READ(dentry, d_parent);
					dname = BPF_CORE_READ(dentry, d_name);
				}
				count++;
			}
			vma = BPF_CORE_READ(vma, vm_next);
		}
		e->count = count;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}
char _license[] SEC("license") = "GPL";
