### Introduction

Developing the *CrashCrawler* for https://github.com/oscomp/proj160-osmatch-crash-collection

We build this CrashCrawler application with C and eBPF program with libbpf with CO-RE

To compile this project, you need libbpf with CO-RE and a linux kernel that supports eBPF and provide BTF 

### libbpf with CO-RE

To use BTF and CO-RE, `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y` need to be enabled. If you don't want to rebuild the kernel, the following distos have enabled those options by default:

- Ubuntu 20.10+
- Fedora 31+
- RHEL 8.2+
- Debian 11+

And to build bpf applications, the following development tools should also be installed:

```
# Ubuntu
sudo apt-get install -y make clang llvm libelf-dev linux-tools-$(uname -r)

# RHEL
sudo yum install -y make clang llvm elfutils-libelf-devel bpftool

# WSL2 
# bpftool which shall be compiled and installed from kernel souce code provided by Microsoft
# source code
https://github.com/microsoft/WSL2-Linux-Kernel 
# can reffer to link below for instruction
https://gist.github.com/MarioHewardt/5759641727aae880b29c8f715ba4d30f
```

### BTF for distribution 

If you want to install this application for another machine with different kernel version, you may change the default BTF path for the BTFGen, which will generate a min_size_BTF file you need for supporting eBPF program on target machine. Check [this](https://kinvolk.io/blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/) for more details for BTF. 

Below are just for *CrashCrawler*:

```bash
```



