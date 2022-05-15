INCLUDE_PATH := -I/usr/include -I../src -I/usr/include/x86_64-linux-gnu -I../src/libbpf/usr/include
bpftool := $(shell which bpftool || ../tools/bpftool)
LIBBPF_OBJ := $(abspath ./libbpf.a)
LIBBPF_SRC := $(abspath ../libbpf/src)
CFLAGS := -g -O2
SRCDIR := $(abspath ../src)
target := exitcatch
SRC_TARGET := $(SRCDIR)/$(target)
HEADER_DIR := /../src/libbpf/usr/include

DEBUG ?= 


ifdef DEBUG
	CFLAGS += -D DEBUG
endif

.DEBFAULT: build

build:$(LIBBPF_OBJ) $(SRCDIR)/vmlinux.h $(LIBBPF_OBJ)
	clang $(CFLAGS) -target bpf $(INCLUDE_PATH) -c $(SRC_TARGET).bpf.c -o $(target).bpf.o 
	$(bpftool) gen skeleton  $(target).bpf.o > $(SRC_TARGET).skel.h
	clang $(CFLAGS) -Wall $(INCLUDE_PATH) -c $(SRC_TARGET).c -o $(target).o
	clang -Wall $(CFLAGS) $(target).o -static $(LIBBPF_OBJ) -lelf -lz -o $(target)

$(SRCDIR)/vmlinux.h:
	$(bpftool) btf dump file /sys/kernel/btf/vmlinux format c > $(SRCDIR)/vmlinux.h


libbpf:$(LIBBPF_OBJ)
	
$(LIBBPF_OBJ):$(LIBBPF_SRC)/Makefile
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 DESTDIR=$(LIBBPF_SRC)/../../build OBJDIR=$(dir $@) INCLUDEDIR=$(HEADER_DIR)  LIBDIR=$(HEADER_DIR) install
	
$(LIBBPF_SRC)/Makefile:
	git submodule update --init --recursive 


clean:
	rm -rf $(target) *.o ../src/$(target).skel.h 
cleanall:
	rm -rf $(target) *.o ../src/$(target).skel.h libbpf.* staticobjs ../src/libbpf/usr/include ../src/vmlinux.h
