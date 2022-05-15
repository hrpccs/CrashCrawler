INCLUDE_PATH := -I/usr/include -I../src -I/usr/include/x86_64-linux-gnu -I../src/libbpf/usr/include
bpftool := $(shell which bpftool || ../tools/bpftool)
LIBBPF_OBJ := $(abspath ./libbpf.a)
LIBBPF_SRC := $(abspath ../libbpf/src)
CFLAGS := -g -O2
DEBUG_CFLAGS := -g -O2 -D DEBUG
SRCDIR := $(abspath ../src)
target := exitcatch
SRC_TARGET := $(SRCDIR)/$(target)
HEADER_DIR := /../src/libbpf/usr/include

build:$(LIBBPF_OBJ)  
	clang $(CFLAGS) -target bpf $(INCLUDE_PATH) -c $(SRC_TARGET).bpf.c -o $(target).bpf.o 
	$(bpftool) gen skeleton  $(target).bpf.o > $(SRC_TARGET).skel.h
	clang $(CFLAGS) -Wall $(INCLUDE_PATH) -c $(SRC_TARGET).c -o $(target).o
	clang -Wall $(CFLAGS) $(target).o -static $(LIBBPF_OBJ) -lelf -lz -o $(target)

debug:$(LIBBPF_OBJ)
	clang $(DEBUG_CFLAGS) -target bpf $(INCLUDE_PATH) -c $(SRC_TARGET).bpf.c -o $(target).bpf.o 
	$(bpftool) gen skeleton $(target).bpf.o > $(SRC_TARGET).skel.h
	clang $(DEBUG_CFLAGS) -Wall $(INCLUDE_PATH) -c $(SRC_TARGET).c -o $(target).o
	clang -Wall $(DEBUG_CFLAGS) $(target).o -static $(LIBBPF_OBJ) -lelf -lz -o $(target)

libbpf:$(LIBBPF_OBJ)
	
$(LIBBPF_OBJ):$(LIBBPF_SRC)/Makefile
	@echo $(HEADER_DIR)
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 DESTDIR=$(LIBBPF_SRC)/../../build OBJDIR=$(dir $@) INCLUDEDIR=$(HEADER_DIR)  LIBDIR=$(HEADER_DIR) install
	
$(SRCDIR)/Makefile:
	git submodule update --init --recursive 


clean:
	rm -rf $(target) *.o libbpf.* staticobjs 
