### Introduction

Developing the *CrashCrawler* for https://github.com/oscomp/proj160-osmatch-crash-collection

You can also reffer our github https://github.com/hrpccs/OScomp

We build this CrashCrawler application with C and eBPF program with libbpf with CO-RE

To compile this project, you need libbpf with CO-RE and a linux kernel that supports eBPF and provide BTF 

### Final Round Submit
You can refer to our final round [Develop Reprot](doc/SYSU-160%20CrashCrawler%E5%BC%80%E5%8F%91%E6%96%87%E6%A1%A3.md) . 

We also prepare our [Breif Introducing PPT](./doc/Crashcrawler_SYSU.pptx). 

If needed, you can also refer to our source code in `./src` and build them in `./build` with our makefile.


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

### Build and Run our demo

```bash
git clone https://gitlab.eduxiji.net/fuhengyu/sysu-proj160.git
cd build
make build -j 4
sudo mount -t debugfs none /sys/kernel/debug 
sudo ./exitcatch.bin <Self-designed Path>
```



