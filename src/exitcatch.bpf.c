// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include "exitcatch.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STRLEN 20

// Use a ringbuffer Map to send data down to userspace
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 15);
} rb SEC(".maps");

// Use to store kernel stacktrace and will be used by bpf_get_stackid()
struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(u32));
  __uint(value_size, VALUESIZE);
  __uint(max_entries, 8192);
} map_kernel_stack_traces SEC(".maps");

// Use to store user stacktrace
struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(u32));
  __uint(value_size, VALUESIZE);
  __uint(max_entries, 8192);
} map_user_stack_traces SEC(".maps");

// get rsslim from signal , inspired by kernel function - do_task_stat()
static unsigned long get_rsslim(struct signal_struct *sig) {
  struct rlimit rlim[16];
  bpf_probe_read_kernel_str((void *)rlim, sizeof(rlim), (void *)(&(sig->rlim)));
  return rlim[RLIMIT_RSS].rlim_cur;
}

// get rsslim from signal , inspired by kernel function - do_task_stat()
static unsigned long get_mm_rss(struct mm_struct *mm) {
  struct mm_rss_stat rss_stat = BPF_CORE_READ(mm, rss_stat);
  return rss_stat.count[0].counter + rss_stat.count[1].counter +
         rss_stat.count[3].counter;
}

// the path in the debugfs, and debugfs need to be mounted first

SEC("fentry/do_exit")
int BPF_PROG(fentry_do_exit, long exitcode) {
  struct task_struct *task;
  struct vm_area_struct *vma;
  struct mm_struct *mm;
  struct file *file;
  struct path filepath;
  struct event *e;
  int ttid, ttgid = 0;
  long long t = bpf_get_current_pid_tgid();
  ttid = t & 0xffff;
  ttgid = t >> 32;
  // Compute the process time for a specific catch
  u64 t_start = bpf_ktime_get_ns();
  if (exitcode == 0 || exitcode >> 8 != 0) { // exit normally
    return 0;
  }
  bpf_printk("exitcode %x tid %d pid %d", exitcode, ttid, ttgid);
  // get information in task_struct
  task = (struct task_struct *)bpf_get_current_task_btf();
  vma = task->mm->mmap;
  mm = task->mm;
  long long temp = 0;
  char *tptr = 0;
  // Log event to ringbuffer to be read by userspace
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (e) {
    e->kernel_stack_id = bpf_get_stackid(ctx, &map_kernel_stack_traces, 0);
    e->user_stack_id =
        bpf_get_stackid(ctx, &map_user_stack_traces, BPF_F_USER_STACK);
    e->exit_code = exitcode >> 8;
    e->sig = exitcode & 0xff;
    e->pid = task->tgid;
    e->tid = task->pid;
    e->ppid = task->parent->pid;
    e->policy = (task->policy);
    e->prio = (task->prio);
    e->rt_priority = (task->rt_priority);
    e->utime = (task->utime);
    e->stime = (task->stime);
    e->gtime = (task->gtime);
    e->start_time = (task->start_time);
    bpf_get_current_comm(&(e->comm), TASK_COMM_LEN);

    e->flags = (task->flags);

    e->num_threads = (task->signal->nr_threads);

    e->prio = (task->prio);

    e->start_time = (task->start_time);
    e->cutime = (task->signal->cutime);
    e->cstime = (task->signal->cstime);
    e->cgtime = (task->signal->cgtime);
    e->gtime = (task->gtime);
    e->utime = (task->utime);
    e->stime = (task->stime);

    e->min_flt = (task->min_flt);
    e->maj_flt = (task->maj_flt);
    e->cmaj_flt = (task->signal->cmin_flt);
    e->cmin_flt = (task->signal->cmaj_flt);

    e->mm_vsize = (mm->total_vm);
    e->mm_rss = get_mm_rss(mm);
    e->rsslim = get_rsslim((task->signal));
    e->mm_start_code = (mm->start_code);
    e->mm_end_code = (mm->end_code);
    e->mm_start_stack = (mm->start_stack);

    e->exit_signal = (task->exit_signal);
    // e->cpu = BPF_CORE_READ(task, cpu);
    e->cpu = 0;
    e->rt_priority = (task->rt_priority);
    e->policy = (task->policy);

    // this code to get user sapce register are inspired by
    // task_pt_regs(task) in linux/arch/x86/include/asm/processor.h
    void *__current_stack_page = (task->stack);
    void *__ptr =
        __current_stack_page + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
    struct pt_regs *_tctx = ((struct pt_regs *)__ptr) - 1;
    e->esp = BPF_CORE_READ(_tctx, sp);
    e->eip = BPF_CORE_READ(_tctx, ip);

    e->mm_start_data = (mm->start_data);
    e->mm_end_data = (mm->end_data);
    e->mm_start_brk = (mm->start_brk);
    e->mm_arg_start = (mm->arg_start);
    e->mm_arg_end = (mm->arg_end);
    e->mm_env_start = (mm->env_start);
    e->mm_env_end = (mm->env_end);
    // get file mapping

    int count = 0;
#pragma unroll

    //
    for (int i = 0; i < MAX_VMA_ENTRY; i++) {
      // if (vma) //a trick: no nullptr check will not result in segment fault
      // crash in BPF code
      // and reduce the state the verifier store when loading BPF program.

      {
        file = (vma->vm_file);
        if (!file) {
          vma = (vma->vm_next); // drop the non-exceutable segment
                                // to gain deeper lib searching
          vma = (vma->vm_next);
          continue;
        }
        e->mmap[count].dev = (vma->vm_file->f_inode->i_sb->s_dev);
        e->mmap[count].ino = (vma->vm_file->f_inode->i_ino);
        temp = (vma->vm_pgoff);
        e->mmap[count].pgoff = temp << PAGE_SHIFT;

        e->mmap[count].start = (vma->vm_start);
        e->mmap[count].end = (vma->vm_end);
        e->mmap[count].flags = (vma->vm_flags);
        // filepath = file->f_path.dentry;
        struct dentry *dentry = file->f_path.dentry;
        // struct qstr dname = BPF_CORE_READ(dentry,d_name);

        // read abs path of share lib , inspired by d_path() kernel function
        // MAXLEN_VMA_NAME = 2^n;
        for (int k = MAX_LEVEL - 1; k >= 0; k--) {
          int len = dentry->d_name.len;
          char *name = dentry->d_name.name;
          bpf_probe_read_kernel_str(&(e->mmap[count].name[k][0]),
                                    (len + 5) & (MAXLEN_VMA_NAME - 1),
                                    name - 4); // weak ptr offset
          dentry = (dentry->d_parent);
          //   dname = (dentry-> d_name);
        }
        count++;
        if ((vma->vm_flags) & VM_EXEC) {

          vma = (vma->vm_next); // a trick that will gain deeper dynamic lib
                                // searching while may miss some thirdparty
                                // dynamic lib
          vma = (vma->vm_next); // it is vary useful for searching GNU dynamic
                                // lib because the elf loading convention
          vma = (vma->vm_next);
        }
        vma = (vma->vm_next);
      }
    }
    e->count = count;
    u64 t_end = bpf_ktime_get_ns();
    e->process_time_ns = t_end - t_start;
    bpf_printk("submit a event\n");
    bpf_ringbuf_submit(e, 0);
  } else {
    bpf_printk("tid %d pid %d exitcode %lx, can't get a ringbuffer entry\n",
               ttid, ttgid, exitcode);
  }
  return 0;
}
char _license[] SEC("license") = "GPL";
