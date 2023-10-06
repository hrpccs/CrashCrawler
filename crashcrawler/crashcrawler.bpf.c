// #define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include "crashcrawler.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STRLEN 20

// Use a ringbuffer Map to send data down to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * sizeof(struct event));
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
static unsigned long  __always_inline  get_rsslim(struct signal_struct* sig) {
    struct rlimit rlim[16];
    bpf_probe_read_kernel_str((void*)rlim, sizeof(rlim), (void*)(&(sig->rlim)));
    return rlim[RLIMIT_RSS].rlim_cur;
}

// get rsslim from signal , inspired by kernel function - do_task_stat()
static unsigned long __always_inline  get_mm_rss(struct mm_struct* mm) {
    struct mm_rss_stat rss_stat = BPF_CORE_READ(mm, rss_stat);
    return rss_stat.count[0].counter + rss_stat.count[1].counter +
           rss_stat.count[3].counter;
}

// the path in the debugfs, and debugfs need to be mounted first
SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe__do_exit_no_path, long exitcode) {
    struct task_struct* task;
    struct vm_area_struct* vma;
    struct mm_struct* mm;
    struct file* file;
    struct path filepath;
    struct event* e;

    // Compute the process time for a specific catch
    u64 t_start = bpf_ktime_get_ns();
    if (exitcode == 0 || exitcode >> 8 != 0 ||
        (exitcode & 0xff) == 13) { // exit normally
        return 0;
    }
    // get information in task_struct
    task = (struct task_struct*)bpf_get_current_task();
    vma = BPF_CORE_READ(task,mm, mmap);
    mm = BPF_CORE_READ(task,mm);

    long long temp = 0;
    char* tptr = 0;
    // Log event to ringbuffer to be read by userspace
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->kernel_stack_id = bpf_get_stackid(ctx, &map_kernel_stack_traces, 0);
        e->user_stack_id =
                bpf_get_stackid(ctx, &map_user_stack_traces, BPF_F_USER_STACK);
        e->exit_code = exitcode >> 8;
        e->sig = exitcode & 0xff;
        e->pid = BPF_CORE_READ(task,tgid);
        e->tid = BPF_CORE_READ(task,pid);
        e->ppid = BPF_CORE_READ(task,parent, pid);
        e->policy = BPF_CORE_READ(task,policy);
        e->prio = BPF_CORE_READ(task,prio);
        e->rt_priority = BPF_CORE_READ(task,rt_priority);
        e->utime = BPF_CORE_READ(task,utime);
        e->stime = BPF_CORE_READ(task,stime);
        e->gtime = BPF_CORE_READ(task,gtime);
        e->start_time = BPF_CORE_READ(task,start_time);
        bpf_get_current_comm(&(e->comm), TASK_COMM_LEN);

        e->flags = BPF_CORE_READ(task,flags);

        e->num_threads = BPF_CORE_READ(task,signal, nr_threads);

        e->prio = BPF_CORE_READ(task,prio);

        e->start_time = BPF_CORE_READ(task,start_time);
        e->cutime = BPF_CORE_READ(task,signal, cutime);
        e->cstime = BPF_CORE_READ(task,signal, cstime);
        e->cgtime = BPF_CORE_READ(task,signal, cgtime);
        e->gtime = BPF_CORE_READ(task,gtime);
        e->utime = BPF_CORE_READ(task,utime);
        e->stime = BPF_CORE_READ(task,stime);

        e->min_flt = BPF_CORE_READ(task,min_flt);
        e->maj_flt = BPF_CORE_READ(task,maj_flt);
        e->cmaj_flt = BPF_CORE_READ(task,signal, cmin_flt);
        e->cmin_flt = BPF_CORE_READ(task,signal, cmaj_flt);

        e->mm_vsize = BPF_CORE_READ(mm, total_vm);
        e->mm_rss = get_mm_rss(mm);
        e->rsslim = get_rsslim(BPF_CORE_READ(task,signal));
        e->mm_start_code = BPF_CORE_READ(mm, start_code);
        e->mm_end_code = BPF_CORE_READ(mm, end_code);
        e->mm_start_stack = BPF_CORE_READ(mm, start_stack);

        e->exit_signal = BPF_CORE_READ(task,exit_signal);
        // e->cpu = task->cpu);
        e->cpu = 0;
        e->rt_priority = BPF_CORE_READ(task,rt_priority);
        e->policy = BPF_CORE_READ(task,policy);

        // this code to get user sapce register are inspired by
        // task_pt_regs(task) in linux/arch/x86/include/asm/processor.h
        e->esp = 1;
        // e->eip = BPF_CORE_READ(_tctx, ip);
        e->eip = 1;

        e->mm_start_data = BPF_CORE_READ(mm, start_data);
        e->mm_end_data = BPF_CORE_READ(mm, end_data);
        e->mm_start_brk = BPF_CORE_READ(mm, start_brk);
        e->mm_arg_start = BPF_CORE_READ(mm, arg_start);
        e->mm_arg_end = BPF_CORE_READ(mm, arg_end);
        e->mm_env_start = BPF_CORE_READ(mm, env_start);
        e->mm_env_end = BPF_CORE_READ(mm, env_end);
        // get file mapping

        file = BPF_CORE_READ(vma, vm_file);
        if (file == NULL) {
            bpf_printk("file is null\n");
        }
        filepath = BPF_CORE_READ(file, f_path);
        struct dentry* dentry = filepath.dentry;
        struct qstr dname = BPF_CORE_READ(dentry, d_name);
        // read abs path of share lib , inspired by d_path() kernel function
        // MAXLEN_VMA_NAME = 2^n;
        for (int k = MAX_LEVEL - 1; k >= 0; k--) {
            // bpf_probe_read_kernel_str(&(e->mmap[count].name[k][4]),
            // (dname.len + 5) & (MAXLEN_VMA_NAME - 1), dname.name); // weak ptr
            // offset bpf_printk("name: %s\n", &(e->mmap[count].name[k][4]));
            bpf_probe_read_kernel_str(&(e->mmap[0].name[k][0]),
                                      (dname.len + 5) & (MAXLEN_VMA_NAME - 1),
                                      dname.name); // weak ptr offset
            // bpf_printk("name: %s\n", &(e->mmap[0].name[k][0]));
            dentry = BPF_CORE_READ(dentry, d_parent);
            dname = BPF_CORE_READ(dentry, d_name);
        }

        int count = 0;
#pragma unroll

        for (int i = 0; i < 110; i++) {
            // if (vma) //a trick: no nullptr check will not result in segment
            // fault crash in BPF code
            // and reduce the state the verifier store when loading BPF program.
            {
                file = BPF_CORE_READ(vma, vm_file);
                if (!file) {
                    vma = BPF_CORE_READ(
                            vma, vm_next); // drop the non-exceutable segment to
                                           // gain deeper lib searching
                    vma = BPF_CORE_READ(vma, vm_next);
                    continue;
                }
                struct inode* f_inode = BPF_CORE_READ(file, f_inode);
                e->mmap[count].dev = BPF_CORE_READ(f_inode, i_sb, s_dev);
                e->mmap[count].ino = BPF_CORE_READ(f_inode, i_ino);
                temp = BPF_CORE_READ(vma, vm_pgoff);
                e->mmap[count].pgoff = temp << PAGE_SHIFT;

                e->mmap[count].start = BPF_CORE_READ(vma, vm_start);
                e->mmap[count].end = BPF_CORE_READ(vma, vm_end);
                e->mmap[count].flags = BPF_CORE_READ(vma, vm_flags);
                count++;
                if (BPF_CORE_READ(vma, vm_flags) & VM_EXEC) {
                    vma = BPF_CORE_READ(
                            vma, vm_next); // a trick that will gain deeper
                                           // dynamic lib searching while may
                                           // miss some thirdparty dynamic lib
                    vma = BPF_CORE_READ(
                            vma, vm_next); // it is vary useful for searching
                                           // GNU dynamic lib because the elf
                                           // loading convention
                    vma = BPF_CORE_READ(vma, vm_next);
                }
                vma = BPF_CORE_READ(vma, vm_next);
            }
        }
        e->count = count;
        u64 t_end = bpf_ktime_get_ns();
        e->process_time_ns = t_end - t_start;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe__do_exit_wit_path, long exitcode) {
    struct task_struct* task;
    struct vm_area_struct* vma;
    struct mm_struct* mm;
    struct file* file;
    struct path filepath;
    struct event* e;

    // Compute the process time for a specific catch
    u64 t_start = bpf_ktime_get_ns();
    if (exitcode == 0 || exitcode >> 8 != 0 ||
        (exitcode & 0xff) == 13) { // exit normally
        return 0;
    }
    // get information in task_struct
    task = (struct task_struct*)bpf_get_current_task();
    vma = BPF_CORE_READ(task,mm, mmap);
    mm = BPF_CORE_READ(task,mm);

    long long temp = 0;
    char* tptr = 0;
    // Log event to ringbuffer to be read by userspace
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->kernel_stack_id = bpf_get_stackid(ctx, &map_kernel_stack_traces, 0);
        e->user_stack_id =
                bpf_get_stackid(ctx, &map_user_stack_traces, BPF_F_USER_STACK);
        e->exit_code = exitcode >> 8;
        e->sig = exitcode & 0xff;
        e->pid = BPF_CORE_READ(task,tgid);
        e->tid = BPF_CORE_READ(task,pid);
        e->ppid = BPF_CORE_READ(task,parent, pid);
        e->policy = BPF_CORE_READ(task,policy);
        e->prio = BPF_CORE_READ(task,prio);
        e->rt_priority = BPF_CORE_READ(task,rt_priority);
        e->utime = BPF_CORE_READ(task,utime);
        e->stime = BPF_CORE_READ(task,stime);
        e->gtime = BPF_CORE_READ(task,gtime);
        e->start_time = BPF_CORE_READ(task,start_time);
        bpf_get_current_comm(&(e->comm), TASK_COMM_LEN);

        e->flags = BPF_CORE_READ(task,flags);

        e->num_threads = BPF_CORE_READ(task,signal, nr_threads);

        e->prio = BPF_CORE_READ(task,prio);

        e->start_time = BPF_CORE_READ(task,start_time);
        e->cutime = BPF_CORE_READ(task,signal, cutime);
        e->cstime = BPF_CORE_READ(task,signal, cstime);
        e->cgtime = BPF_CORE_READ(task,signal, cgtime);
        e->gtime = BPF_CORE_READ(task,gtime);
        e->utime = BPF_CORE_READ(task,utime);
        e->stime = BPF_CORE_READ(task,stime);

        e->min_flt = BPF_CORE_READ(task,min_flt);
        e->maj_flt = BPF_CORE_READ(task,maj_flt);
        e->cmaj_flt = BPF_CORE_READ(task,signal, cmin_flt);
        e->cmin_flt = BPF_CORE_READ(task,signal, cmaj_flt);

        e->mm_vsize = BPF_CORE_READ(mm, total_vm);
        e->mm_rss = get_mm_rss(mm);
        e->rsslim = get_rsslim(BPF_CORE_READ(task,signal));
        e->mm_start_code = BPF_CORE_READ(mm, start_code);
        e->mm_end_code = BPF_CORE_READ(mm, end_code);
        e->mm_start_stack = BPF_CORE_READ(mm, start_stack);

        e->exit_signal = BPF_CORE_READ(task,exit_signal);
        // e->cpu = task->cpu);
        e->cpu = 0;
        e->rt_priority = BPF_CORE_READ(task,rt_priority);
        e->policy = BPF_CORE_READ(task,policy);

        // this code to get user sapce register are inspired by
        // task_pt_regs(task) in linux/arch/x86/include/asm/processor.h
        e->esp = 1;
        // e->eip = BPF_CORE_READ(_tctx, ip);
        e->eip = 1;

        e->mm_start_data = BPF_CORE_READ(mm, start_data);
        e->mm_end_data = BPF_CORE_READ(mm, end_data);
        e->mm_start_brk = BPF_CORE_READ(mm, start_brk);
        e->mm_arg_start = BPF_CORE_READ(mm, arg_start);
        e->mm_arg_end = BPF_CORE_READ(mm, arg_end);
        e->mm_env_start = BPF_CORE_READ(mm, env_start);
        e->mm_env_end = BPF_CORE_READ(mm, env_end);
        // get file mapping

        int count = 0;
#pragma unroll

        for (int i = 0; i < 45; i++) {
            // if (vma) //a trick: no nullptr check will not result in segment
            // fault crash in BPF code
            // and reduce the state the verifier store when loading BPF program.
            {
                file = BPF_CORE_READ(vma, vm_file);
                if (!file) {
                    vma = BPF_CORE_READ( vma, vm_next); // drop the non-exceutable segment to // gain deeper lib searching
                    vma = BPF_CORE_READ(vma, vm_next);
                    continue;
                }
                struct inode* f_inode = BPF_CORE_READ(file, f_inode);
                e->mmap[count].dev = BPF_CORE_READ(f_inode, i_sb, s_dev);
                e->mmap[count].ino = BPF_CORE_READ(f_inode, i_ino);
                temp = BPF_CORE_READ(vma, vm_pgoff);
                e->mmap[count].pgoff = temp << PAGE_SHIFT;

                e->mmap[count].start = BPF_CORE_READ(vma, vm_start);
                e->mmap[count].end = BPF_CORE_READ(vma, vm_end);
                e->mmap[count].flags = BPF_CORE_READ(vma, vm_flags);
                filepath = BPF_CORE_READ(file, f_path);
                struct dentry* dentry = filepath.dentry;
                struct qstr dname = BPF_CORE_READ(dentry, d_name);
                // read abs path of share lib , inspired by d_path() kernel
                // function MAXLEN_VMA_NAME = 2^n;
                for (int k = MAX_LEVEL - 1; k >= 0; k--) {
                    // bpf_probe_read_kernel_str(&(e->mmap[count].name[k][4]),
                    // (dname.len + 5) & (MAXLEN_VMA_NAME - 1), dname.name); //
                    // weak ptr offset bpf_printk("name: %s\n",
                    // &(e->mmap[count].name[k][4]));
                    bpf_probe_read_kernel_str(&(e->mmap[count].name[k][0]),
                                              (dname.len + 5) &
                                                      (MAXLEN_VMA_NAME - 1),
                                              dname.name); // weak ptr offset
                    bpf_printk("name: %s\n", &(e->mmap[count].name[k][0]));

                    dentry = BPF_CORE_READ(dentry, d_parent);
                    dname = BPF_CORE_READ(dentry, d_name);
                }
                count++;
                if (BPF_CORE_READ(vma, vm_flags) & VM_EXEC) {
                    vma = BPF_CORE_READ( vma, vm_next); // a trick that will gain deeper // dynamic lib searching while may // miss some thirdparty dynamic lib
                    vma = BPF_CORE_READ( vma, vm_next); // it is vary useful for searching // GNU dynamic lib because the elf // loading convention
                    vma = BPF_CORE_READ(vma, vm_next);
                }
                vma = BPF_CORE_READ(vma, vm_next);
            }
        }
        e->count = count;
        u64 t_end = bpf_ktime_get_ns();
        e->process_time_ns = t_end - t_start;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}


SEC("fentry/do_exit")
int BPF_PROG(fentry__do_exit, long exitcode) {
    struct task_struct* task;
    struct vm_area_struct* vma;
    struct mm_struct* mm;
    struct file* file;
    struct path filepath;
    struct event* e;

    // Compute the process time for a specific catch
    u64 t_start = bpf_ktime_get_ns();
    if (exitcode == 0 || exitcode >> 8 != 0 ||
        (exitcode & 0xff) == 13) { // exit normally
        return 0;
    }
    // get information in task_struct
    task = (struct task_struct*)bpf_get_current_task_btf();
    mm = task->mm;
    vma = task->mm->mmap;

    long long temp = 0;
    char* tptr = 0;
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
        e->policy = task->policy;
        e->prio = task->prio;
        e->rt_priority = task->rt_priority;
        e->utime = task->utime;
        e->stime = task->stime;
        e->gtime = task->gtime;
        e->start_time = task->start_time;
        bpf_get_current_comm(&(e->comm), TASK_COMM_LEN);

        e->flags = task->flags;

        e->num_threads = task->signal->nr_threads;

        e->prio = task->prio;

        e->start_time = task->start_time;
        e->cutime = task->signal->cutime;
        e->cstime = task->signal->cstime;
        e->cgtime = task->signal->cgtime;
        e->gtime = task->gtime;
        e->utime = task->utime;
        e->stime = task->stime;

        e->min_flt = task->min_flt;
        e->maj_flt = task->maj_flt;
        e->cmaj_flt = task->signal->cmin_flt;
        e->cmin_flt = task->signal->cmaj_flt;

        e->mm_vsize = mm->total_vm;
        e->mm_rss = get_mm_rss(mm);
        e->rsslim = get_rsslim(task->signal);
        e->mm_start_code = mm->start_code;
        e->mm_end_code = mm->end_code;
        e->mm_start_stack = mm->start_stack;

        e->exit_signal = task->exit_signal;
        // e->cpu = task->cpu);
        e->cpu = 0;
        e->rt_priority = task->rt_priority;
        e->policy = task->policy;

        // this code to get user sapce register are inspired by
        // task_pt_regs(task) in linux/arch/x86/include/asm/processor.h
        e->esp = 1;
        // e->eip = BPF_CORE_READ(_tctx, ip);
        e->eip = 1;

        e->mm_start_data = mm->start_data;
        e->mm_end_data = mm->end_data;
        e->mm_start_brk = mm->start_brk;
        e->mm_arg_start = mm->arg_start;
        e->mm_arg_end = mm->arg_end;
        e->mm_env_start = mm->env_start;
        e->mm_env_end = mm->env_end;
        // get file mapping
        file = BPF_CORE_READ(vma, vm_file);
        if (file == NULL) {
            bpf_printk("file is null\n");
        }
        filepath = BPF_CORE_READ(file, f_path);
        struct dentry* dentry = filepath.dentry;
        struct qstr dname = BPF_CORE_READ(dentry, d_name);
        // read abs path of share lib , inspired by d_path() kernel function
        // MAXLEN_VMA_NAME = 2^n;
        for (int k = MAX_LEVEL - 1; k >= 0; k--) {
            // bpf_probe_read_kernel_str(&(e->mmap[count].name[k][4]),
            // (dname.len + 5) & (MAXLEN_VMA_NAME - 1), dname.name); // weak ptr
            // offset bpf_printk("name: %s\n", &(e->mmap[count].name[k][4]));
            bpf_probe_read_kernel_str(&(e->mmap[0].name[k][0]),
                                      (dname.len + 5) & (MAXLEN_VMA_NAME - 1),
                                      dname.name); // weak ptr offset
            // bpf_printk("name: %s\n", &(e->mmap[0].name[k][0]));
            dentry = BPF_CORE_READ(dentry, d_parent);
            dname = BPF_CORE_READ(dentry, d_name);
        }      
        int count = 0;
#pragma unroll
        for (int i = 0; i < MAX_VMA_ENTRY; i++) {
             file = vma->vm_file;
             if (!file) {
                 vma = vma->vm_next->vm_next; // drop the non-exceutable segment to // gain deeper lib searching
                 continue;
             }
             e->mmap[count].dev = vma->vm_file->f_inode->i_sb->s_dev;
             e->mmap[count].ino = vma->vm_file->f_inode->i_ino;
             temp = vma->vm_pgoff;
             e->mmap[count].pgoff = temp << PAGE_SHIFT;
             e->mmap[count].start = vma->vm_start;
             e->mmap[count].end =   vma->vm_end;
             e->mmap[count].flags = vma->vm_flags;
             count++;
             if (vma->vm_flags & VM_EXEC) {
                 vma = vma->vm_next->vm_next->vm_next; // a trick that will gain deeper // dynamic lib searching while may // miss some thirdparty dynamic lib
                  // it is vary useful for searching // GNU dynamic lib because the elf // loading convention
                 
             }
             vma = vma->vm_next;
        }
        e->count = count;
        u64 t_end = bpf_ktime_get_ns();
        e->process_time_ns = t_end - t_start;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
