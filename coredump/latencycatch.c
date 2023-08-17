// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "color.h"
#include "latencycatch.skel.h"
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  /*
          this function is used to set to enable and redirect the output of
     bpf_trace_printk to stderr when LIBBPF_DEBUG is set
  */

  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
  /*
          handling signal to stop exitcatch process
  */
  exiting = true;
}

int main(int argc, char **argv) {
  /*
          THe main function.
  */
  // sudo mount -t debugfs none /sys/kernel/debug
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  int err;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  open_opts.btf_custom_path = "/sys/kernel/btf/vmlinux";
  struct latencycatch_bpf *skel = latencycatch_bpf__open_opts(&open_opts);
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = latencycatch_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = latencycatch_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  long long time_sum = 0;
  int count = 0;
  long long last_time_sum = 0;
  int last_count = 0;

  while (!exiting) {
    sleep(1);
    // get the value of time_sum and count
    time_sum = skel->bss->time_sum;
    count = skel->bss->count;
    // print the average time
    // ns us ms s
    if (count != 0) {
      printf("coredump Count : %d\n", count);
      printf("Average time: %lld ns\n", time_sum / count);
      printf("Average time: %lld us\n", time_sum / count / 1000);
      printf("Average time: %lld ms\n", time_sum / count / 1000000);
      printf("Average time: %lld s\n", time_sum / count / 1000000000);
    } else {
      printf("no coredump within 1s\n");
    }

    time_sum = 0;
    count = 0;
  }

cleanup:
  /* Clean up */
  latencycatch_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}