#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <stdarg.h>
#include "hello.skel.h"
#ifdef  DEBUG
#define FLAGS_bpf_libbpf_debug 1
#else
#define FLAGS_bpf_libbpf_debug 0
#endif

int print_libbpf_log(enum libbpf_print_level lvl, const char * fmt,va_list args){
    if(!FLAGS_bpf_libbpf_debug && lvl >= LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr,fmt,args);
}


int main(int argc,char** argv){
    struct hello_bpf * obj;
    int err = 0;
    //set the memory limit for BPF program 
    struct rlimit rlim = {
        .rlim_cur = 512UL << 20,
        .rlim_max = 512UL << 20,
    };
    //check whether the debugfs has been mounted
     

    err = setrlimit(RLIMIT_MEMLOCK,&rlim);
    if(err){
        fprintf(stderr,"failed to change rlimit\n");
        return 1;
    }
    obj = hello_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = hello_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	err = hello_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
    //set the bpf_log
    libbpf_set_print(print_libbpf_log);
    
	printf
	    ("Successfully started! Tracing /sys/kernel/debug/tracing/trace_pipe...\n");

	system("cat /sys/kernel/debug/tracing/trace_pipe");
    return 0;
cleanup:
    hello_bpf__destroy(obj);
    return err != 0;
}