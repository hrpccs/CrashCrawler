#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

long long time_sum = 0;
long count = 0;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, int);
  __type(value, long long);
} enter_time SEC(".maps");

SEC("fentry/do_coredump")
int BPF_PROG(enter) {
  long long t = bpf_ktime_get_ns();
  int pid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&enter_time, &pid, &t, BPF_ANY);
  return 0;
}

SEC("fexit/do_coredump")
int BPF_PROG(exit1) {
  int pid = bpf_get_current_pid_tgid();
  long long *t = bpf_map_lookup_elem(&enter_time, &pid);
  if (t) {
    long long time = bpf_ktime_get_ns() - *t;
    __sync_fetch_and_add(&time_sum, time);
    __sync_fetch_and_add(&count, 1);
    bpf_map_delete_elem(&enter_time, &pid);
  }
  return 0;
}