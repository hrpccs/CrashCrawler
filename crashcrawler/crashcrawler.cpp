// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "crashcrawler.h"
#include "color.h"
#include "crashcrawler.skel.h"
#include "path_utils.h"
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
PathUtils path_utils;
#define NAMELIMIT   100
#define MAXLEN_PATH 100
#define LISTLIMT    500000
const char* kallysyms_path = "/proc/kallsyms";
char log_path[MAXLEN_PATH] = "/var/log/crashlog";

char sys_info_buf[8000];

struct symbol_node {
    /*
        One node for kernel symbol table.
    */
    unsigned long int address;
    char flag;
    char name[NAMELIMIT];
    //    symbol_node(unsigned long int _addr = 0, char _flag = 0, _name = ""):
};

struct symbol_list {
    /*
        The whole table for kernel symbol table.
    */
    struct symbol_node node_array[LISTLIMT];
    int length;
};

struct object_file {
    char exec_file_path[MAX_LEVEL * MAXLEN_VMA_NAME + MAX_LEVEL];
    unsigned long segment_start;
    unsigned long segment_end;
};
struct symbol_list sym_list;

static int char2int(char c) {
    /*
        char2int is used to convert char to int
        input:
            c: char to be convert;
        output:
            return an int
    */
    if (c <= '9' && c >= '0')
        return c - '0';
    else
        return c - 'a' + 10;
}

static long int get_index(int n) {
    /*
        get_index is used to do exponent arithmetic.
        input:
            n index to calculate;
        output:
            return the result
    */
    long int ans = 1;
    while (n--)
        ans *= 16;
    return ans;
}

static void sym_initialize() {
    /*
        sym_initialize is used to initialize the kernel symbol table.
    */
    FILE* fp = fopen(kallysyms_path, "r");
    char* line = NULL;
    size_t len = 0;
    size_t read_count;
    sym_list.length = 0;
    while ((read_count = getline(&line, &len, fp)) != -1) {
        int mod = 0;
        for (int i = 0; i < read_count; i++) {
            if (line[i] == '\t' || line[i] == '\n')
                break;
            if (line[i] == ' ') {
                ++mod;
                continue;
            }
            if (mod == 0) {
                if (i == 0)
                    sym_list.node_array[sym_list.length].address = 0;
                sym_list.node_array[sym_list.length].address +=
                        get_index(15 - i) * char2int(line[i]);
            } else if (mod == 1) {
                sym_list.node_array[sym_list.length].flag = line[i];
            } else {
                if (i == 19)
                    memset(sym_list.node_array[sym_list.length].name,
                           0,
                           sizeof(sym_list.node_array[sym_list.length].name));
                sym_list.node_array[sym_list.length].name[i - 19] = line[i];
            }
        }
        ++sym_list.length;
    }
}

static int search_kernel_symbol(unsigned long query) {
    /*
        search_kernel_symbol uses binary search(lower bound version) to search
       for kernel stack symbol. input: query: the address in kernel stack;
        output:
            return the index in kernel symbol table.
    */
    int left = 0, right = sym_list.length;
    while (left < right) {
        int mid = (left + right) / 2;
        if (sym_list.node_array[mid].address >= query)
            right = mid;
        else
            left = mid + 1;
    }
    left = left > 0 ? --left : left;
    return left;
}

static int search_object_file(unsigned long query,
                              struct object_file* files,
                              int file_count) {
    /*
        search_object_symbol uses binary search(lower bound version) to search
       for user stack symbol. input: query: the address in user stack; output:
            return the index in user symbol table.
    */
    int left = 0, right = file_count - 1;
    while (left < right) {
        int mid = (left + right) / 2;
        if (files[mid].segment_start >= query)
            right = mid;
        else
            left = mid + 1;
    }
    left = left > 0 ? --left : left;
    return left;
}

unsigned int dump_elf_for_offset(const char *filename) {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "Failed to initialize libelf\n");
    exit(1);
  }

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  Elf *elf = elf_begin(fileno(file), ELF_C_READ, NULL);
  if (elf == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;

#if defined(__x86_64__) || defined(__aarch64__)
  Elf64_Word entry_offset;
#else
  Elf32_Word entry_offset;
#endif
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &shdr) != &shdr) {
      fprintf(stderr, "Failed to read ELF header\n");
      exit(1);
    }

    if (shdr.sh_type == SHT_PROGBITS && shdr.sh_flags == 6) {
      entry_offset = shdr.sh_offset;
#ifdef DEBUG
      printf("dump_elf_for_offset: %x, %016lx: 0x%016lx\n", shdr.sh_type,
             shdr.sh_offset, shdr.sh_addr);
#endif
      break;
    }
  }
  elf_end(elf);
  return entry_offset;
}

int dump_elf_for_func_symbols(const char *filename, const unsigned long paddr, char * stack_func_name) {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    fprintf(stderr, "Failed to initialize libelf\n");
    exit(1);
  }

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  Elf *elf = elf_begin(fileno(file), ELF_C_READ, NULL);
  if (elf == NULL) {
    fprintf(stderr, "Failed to open ELF file\n");
    exit(1);
  }

  GElf_Shdr shdr;
  Elf_Scn *scn = NULL;
  Elf_Scn *symtab_scn_array[2] = {NULL};
  int symtab_scn_array_size = 0;
  Elf_Scn *symtab_scn = NULL;

  int cnt = 0;
  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &shdr) != &shdr) {
      fprintf(stderr, "Failed to read ELF header\n");
      exit(1);
    }
    // Critical filter: Look for the dynamic symbol table.
    if (shdr.sh_type == SHT_DYNSYM || shdr.sh_type == SHT_SYMTAB) {
      // printf("%d, Count: %d\n", shdr.sh_type, ++cnt);
      // symtab_scn = scn;
      symtab_scn_array[symtab_scn_array_size++] = scn;
    }
  }

  if (!symtab_scn_array_size) {
	sprintf(stack_func_name, "[No Function Name]");
	return 1;
  }

  unsigned long func_offset = 0x7f7f7f7f;
  char  func_name[NAMELIMIT] = {0};
  for (int idx = 0; idx < symtab_scn_array_size; ++idx) {
    symtab_scn = symtab_scn_array[idx];

    if (gelf_getshdr(symtab_scn, &shdr) != &shdr) {
      fprintf(stderr, "Failed to read ELF header\n");
      exit(1);
    }

    // Get & Traverse the symbol table.
    Elf_Data *symtab_data = elf_getdata(symtab_scn, NULL);
    if (!symtab_data) {
      fprintf(stderr, "Failed to read symbol table data");
      exit(1);
    }

    int num_symbols = symtab_data->d_size / sizeof(GElf_Sym);
    GElf_Sym *symbols = (GElf_Sym *)symtab_data->d_buf;

    for (int i = 0; i < num_symbols; i++) {
      GElf_Sym *symbol = &symbols[i];

      // Critical filter for determined functions.
      if (GELF_ST_TYPE(symbol->st_info) == STT_FUNC && symbol->st_value != 0) {
		unsigned long current_addr = (unsigned long)symbol->st_value;
				// if(paddr > current_addr && func_offset > (paddr - current_addr)){
		if(paddr > current_addr){
				const char * symbol_name =
					elf_strptr(elf, shdr.sh_link, symbol->st_name);
			printf("0x%016lx,0x%016lx,0x%016lx,0x%016lx,%s\n", current_addr, paddr, func_offset, paddr - current_addr, symbol_name);
			if(func_offset > (paddr - current_addr)){
				func_offset = paddr - current_addr;
				strncpy(func_name, symbol_name, NAMELIMIT);
				func_name[NAMELIMIT - 1] = '\0';
				// }
				printf("0x%016lx %s\n", (unsigned long)symbol->st_value, symbol_name);
				#ifdef DEBUG
				#endif
			}
		}
      }
    }
  }
  if(func_offset != 0x7f7f7f7f)
  {
	sprintf(stack_func_name, "%s+0x%lx", func_name, func_offset);
	return 0;
  }
  else 
  {
	sprintf(stack_func_name, "[No Function Name]");
	return 1;
  }
  elf_end(elf);
//   return 0;
}

static int get_user_func_name(unsigned long vaddr, const char *object_file_path, char *stack_func_name)
{
	/*
		get_user_func_name is used to search for the symbol name of a specific
		virtual address in user stack.
		input:
			vaddr: specific address of memory;
			object_file_path: binary Path of the specific tmpAddr;
			stack_func_name: the return function name of the virtual address;
		output: return a int indicate whether is a successful search;
			0: successful search;
			1: failed;
	*/
	FILE *fp;
	unsigned long offset = 0, paddr = 0;
	char cmd[NAMELIMIT];
	int found_symbols = 0;
	memset(stack_func_name, 0, sizeof(stack_func_name));
	/*
		Reading offset
	*/
	offset = dump_elf_for_offset(object_file_path);
	paddr = vaddr + offset;
	/*
		Reading function symbols
	*/
	return dump_elf_for_func_symbols(object_file_path, paddr, stack_func_name);
}

static void print_logo() {
    /*
        print_logo is used to print the welcome page with some basic
       information.
    */
    FILE* fp;
    fp = fopen("../crashcrawler/logo/2.txt", "r");
    while (1) {
        memset(sys_info_buf, 0, sizeof(sys_info_buf));
        void* ptr = fgets(sys_info_buf, sizeof(sys_info_buf), fp);
        if (ptr == NULL)
            break;
        printf("%s", sys_info_buf);
    }
    fclose(fp);
}
static void sysinfo_initialize() {
    /*
        sysinfo_initialize is used to print the static information
        of the computer, like CPU info, Memory info, etc.
        硬件信息脚本
        https://blog.csdn.net/LvJzzZ/article/details/112029991
    */
    print_logo();
    FILE* fp;
    fp = popen("bash ../crashcrawler/hardware.sh", "r");
    while (1) {
        memset(sys_info_buf, 0, sizeof(sys_info_buf));
        void* ptr = fgets(sys_info_buf, sizeof(sys_info_buf), fp);
        if (ptr == NULL)
            break;
        printf("%s", sys_info_buf);
    }
    pclose(fp);
}
struct crashcrawler_bpf* skel;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
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
        handling signal to stop crashcrawler process
    */
    exiting = true;
}

static void memory_calculate(unsigned long mem, char* buffer) {
    /*
        memory_calculate is used to calcalate the memory size
        and return it with correspondent size.
    */
    if (mem < 1024)
        sprintf(buffer, "%8.2fB", (float)mem);
    else if (mem < 1024 * 1024)
        sprintf(buffer, "%8.2fKB", (float)mem / 1024);
    else
        sprintf(buffer, "%8.2fMB", (float)mem / (1024 * 1024));
}
static void print_process_report(const struct event* e, FILE* fp) {
    /*
        print_process_report is used to print the info read by eBPF
        function and organize it in readable format.
        input:
            e: the pointer points to the data read by eBPF function.
            fp: the file pointer points to the output log files.
            stack_func_name: the return function name of the virtual address;
        output: No return values.
    */

    const long ns2us = 1000;

    fprintf(fp,
            "\n========================Process's Brief "
            "Report===========================\n");
    fprintf(fp, "Time Report\n");
    fprintf(fp,
            "                    %-17s%-15s%-20s\n",
            "Current Process",
            "Subprocess",
            "Subprocess(On vCPU)");
    fprintf(fp,
            "    %-16s%-17llu%-15llu%-20llu\n",
            "User Mode(us)",
            e->utime / ns2us,
            e->cutime / ns2us,
            e->gtime / ns2us);
    fprintf(fp,
            "    %-16s%-17llu%-15llu%-20llu\n",
            "System Mode(us)",
            e->stime / ns2us,
            e->cstime / ns2us,
            e->cgtime / ns2us);
    fprintf(fp, "Schedule Report\n");
    fprintf(fp,
            "    %-36s%10d\n",
            "Schedule Priority(Default)",
            e->prio - DEFAULT_PRIO);
    fprintf(fp,
            "    %-36s%10d\n",
            "Schedule Priority(Nice)",
            e->prio - MAX_RT_PRIO);
    fprintf(fp,
            "    %-36s%10d\n",
            "Schedule Priority(Realtime)",
            e->rt_priority);
    fprintf(fp, "    %-36s%10d\n", "Schedule Policy", e->policy); // done
    fprintf(fp, "    %-36s%10d\n", "Threads Number", e->num_threads);
    fprintf(fp, "    %-36s%10d\n", "CPU Number(Last Executed On)", e->cpu);
    fprintf(fp,
            "    %-36s%10d\n",
            "Exit Signal(Report by waitpid())",
            e->exit_signal);
    fprintf(fp, "Memory Report\n");
    fprintf(fp,
            "    %-36s%10.2f\n",
            "Virtual Memory Size(KB)",
            (float)e->mm_vsize * PAGE_SIZE / 1024);
    fprintf(fp,
            "    %-36s%10.2f\n",
            "Resident Set Size(RSS/KB)",
            (float)e->mm_rss * PAGE_SIZE / 1024);
    fprintf(fp,
            "    %-36s%10.2f\n",
            "Soft Limit Of Rss(KB)",
            (float)e->rsslim / 1024);
    fprintf(fp,
            "    %-36s%10.2f\n",
            "Text Segement Size(KB)",
            (float)(e->mm_end_code - e->mm_start_code) / 1024);
    fprintf(fp,
            "    %-36s%10.2f\n",
            "BSS Segement Size(KB)",
            (float)(e->mm_end_data - e->mm_start_data) / 1024);
    fprintf(fp,
            "    %-36s%10.2f\n",
            "Text Segement Size(KB)",
            (float)(e->mm_end_code - e->mm_start_code) / 1024);
    fprintf(fp, "Page Fault Report\n");
    fprintf(fp,
            "                    %-20s%-15s\n",
            "Current Process",
            "Subprocess");
    fprintf(fp,
            "    %-16s%-20u%-15u\n",
            "Major Faults",
            e->maj_flt,
            e->cmaj_flt);
    fprintf(fp,
            "    %-16s%-20u%-15u\n",
            "Minor Faults",
            e->min_flt,
            e->cmin_flt);

    printf(PURPLE
           "\n========================Process's Brief "
           "Report===========================\n" NONE);
    printf(YELLOW "Time Report\n" NONE);
    printf("                    %-17s%-15s%-20s\n",
           "Current Process",
           "Subprocess",
           "Subprocess(On vCPU)");
    printf("    %-16s%-17llu%-15llu%-20llu\n",
           "User Mode(us)",
           e->utime / ns2us,
           e->cutime / ns2us,
           e->gtime / ns2us);
    printf("    %-16s%-17llu%-15llu%-20llu\n",
           "System Mode(us)",
           e->stime / ns2us,
           e->cstime / ns2us,
           e->cgtime / ns2us);
    printf(YELLOW "Schedule Report\n" NONE);
    printf("    %-36s%10d\n",
           "Schedule Priority(Default)",
           e->prio - DEFAULT_PRIO);
    printf("    %-36s%10d\n", "Schedule Priority(Nice)", e->prio - MAX_RT_PRIO);
    printf("    %-36s%10d\n", "Schedule Priority(Realtime)", e->rt_priority);
    printf("    %-36s%10d\n", "Schedule Policy", e->policy); // done
    printf("    %-36s%10d\n", "Threads Number", e->num_threads);
    printf("    %-36s%10d\n", "CPU Number(Last Executed On)", e->cpu);
    printf("    %-36s%10d\n",
           "Exit Signal(Report by waitpid())",
           e->exit_signal);
    printf(YELLOW "Memory Report\n" NONE);
    printf("    %-36s%10.2f\n",
           "Virtual Memory Size(KB)",
           (float)e->mm_vsize * PAGE_SIZE / 1024);
    printf("    %-36s%10.2f\n",
           "Resident Set Size(RSS/KB)",
           (float)e->mm_rss * PAGE_SIZE / 1024);
    printf("    %-36s%10.2f\n",
           "Soft Limit Of Rss(KB)",
           (float)e->rsslim / 1024);
    printf("    %-36s%10.2f\n",
           "Text Segement Size(KB)",
           (float)(e->mm_end_code - e->mm_start_code) / 1024);
    printf("    %-36s%10.2f\n",
           "BSS Segement Size(KB)",
           (float)(e->mm_end_data - e->mm_start_data) / 1024);
    printf("    %-36s%10.2f\n",
           "Text Segement Size(KB)",
           (float)(e->mm_end_code - e->mm_start_code) / 1024);
    printf(YELLOW "Page Fault Report\n" NONE);
    printf("                    %-20s%-15s\n", "Current Process", "Subprocess");
    printf("    %-16s%-20u%-15u\n", "Major Faults", e->maj_flt, e->cmaj_flt);
    printf("    %-16s%-20u%-15u\n", "Minor Faults", e->min_flt, e->cmin_flt);
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
    /*
        handle_event is used to handle data delivered from the kernel
        space to user space

        input:
            ctx: the pointer points to task context
            data: the pointer  points to the data comes from ring_buffer
            data_sz: size in byte of data.
        output: return a int indicate whether is a successful handling;
            0: successful handling;
            1: failed;
    */
    struct object_file* files;
    int file_counts = 0;
    struct event* e = (struct event*)data;
    struct tm* tm;
    char ts[64];
    time_t t;
    unsigned long stack = 0;
    unsigned long stacks[MAX_STACK_DEPTH] = {0};

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%m-%d_%H:%M:%S", tm);

    long clockticks = sysconf(_SC_CLK_TCK);
    printf("%ld\n", clockticks);
    printf("%lf\n", (double)e->utime / clockticks);
    printf("%lf\n", (double)e->stime / clockticks);
    printf("%ld\n", e->gtime / clockticks);
    printf("%ld\n", e->start_time);

    char filename[NAMELIMIT] = {0};
    snprintf(filename, NAMELIMIT, "%s_%s_%d.log", e->comm, ts, e->tid);
    FILE* fp = fopen(filename, "w");
    fprintf(fp, "\n			  %s\n", filename);
    printf(YELLOW "\n			  %s\n" NONE, filename);
    chdir(log_path);
    int ret = bpf_map__lookup_elem(skel->maps.map_kernel_stack_traces,
                                   &e->kernel_stack_id,
                                   sizeof(unsigned int),
                                   &stacks,
                                   VALUESIZE,
                                   0);

    if (ret != 0) {
        fprintf(fp, "Error finding Kernel stack trace\n");
        printf("Error finding Kernel stack trace\n");
        return 0;
    }
    fprintf(fp,
            "%-14s %-16s %-7s %-7s %-7s %-9s %s\n",
            "TIME",
            "COMM",
            "TID",
            "PID",
            "PPID",
            "EXIT CODE",
            "SIGNALS");
    fprintf(fp,
            "%-14s %-16s %-7d %-7d %-7d %-9d %d\n",
            ts,
            e->comm,
            e->tid,
            e->pid,
            e->ppid,
            e->exit_code,
            e->sig);
    printf(HEAD "%-14s %-16s %-7s %-7s %-7s %-9s %s" NONE "\n",
           "TIME",
           "COMM",
           "TID",
           "PID",
           "PPID",
           "EXIT CODE",
           "SIGNALS");
    printf(LIGHT_GREEN "%-14s" YELLOW " %-16s" NONE " %-7d %-7d %-7d" RED
                       " %-9d %d\n" NONE,
           ts,
           e->comm,
           e->tid,
           e->pid,
           e->ppid,
           e->exit_code,
           e->sig);
    // Print brief report to the process
    print_process_report(e, fp);
    // Trace and dependencies
    fprintf(fp,
            "\n====================Stack Trace And "
            "Dependencies=========================\n");
    printf(PURPLE
           "\n====================Stack Trace And "
           "Dependencies=========================\n" NONE);
    fprintf(fp, "Kernel Stack Trace\n");
    printf(YELLOW "Kernel Stack Trace:\n" NONE);
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        stack = stacks[i];
        if (stack == 0) {
            break;
        }
        int index = search_kernel_symbol(stack);
        fprintf(fp,
                "    %#lx %s+%#lx\n",
                stack,
                sym_list.node_array[index].name,
                stack - sym_list.node_array[index].address);
        printf("    %#lx %s+%#lx\n",
               stack,
               sym_list.node_array[index].name,
               stack - sym_list.node_array[index].address);
    }

    // Get and print User stacktrace
    ret = bpf_map__lookup_elem(skel->maps.map_user_stack_traces,
                               &e->user_stack_id,
                               sizeof(unsigned int),
                               &stacks,
                               VALUESIZE,
                               0);

    if (ret != 0) {
        fprintf(fp, "Error finding User stack trace\n");
        printf("Error finding User stack trace\n");
        return 0;
    }
    // share lib
    const struct mmap_struct* curr;
    // get relavent files count
    int last_inode = -1;
    for (int i = 0; i < e->count; i++) {
        curr = &(e->mmap[i]);
        if ((curr->flags & VM_EXEC) && curr->ino != last_inode) {
            last_inode = curr->ino;
            file_counts++;
        }
    }

    files = (struct object_file*)malloc(sizeof(struct object_file) *
                                        file_counts);

    last_inode = -1;
    for (int i = 0, j = 0; i < e->count; i++) {
        curr = &(e->mmap[i]);
		if(i == 0){
           	int index = 0;
           	for (int level = 0; level < MAX_LEVEL; level++) {
               	if (curr->name[level][0] == '\0' ||
                   	curr->name[level][0] == '/') {
                   	continue;
               	}
               	index += sprintf(files[j].exec_file_path + index,
                                	"/%s",
                                	curr->name[level]);
           	}
           	files[j].exec_file_path[index] = '\0';
			// printf("first filepath %s\n", files[j].exec_file_path);
			path_utils.set_inode_path(curr->ino, std::string(files[j].exec_file_path));
		}
        if ((curr->flags & VM_EXEC) && curr->ino != last_inode) {
            files[j].segment_end = curr->end;
            files[j].segment_start = curr->start;

			std::string path = path_utils.get_inode_path(curr->ino, curr->dev);
			if(path == ""){
				fprintf(fp, "Error finding file path\n");
				printf("Error finding file path\n");
				// return 0;
			}
			strcpy(files[j].exec_file_path, path.c_str());

            // int index = 0;
            // for (int level = 0; level < MAX_LEVEL; level++) {
            //     if (curr->name[level][0] == '\0' ||
            //         curr->name[level][0] == '/') {
            //         continue;
            //     }
            //     index += sprintf(files[j].exec_file_path + index,
            //                      "/%s",
            //                      curr->name[level]);
            // }
            // files[j].exec_file_path[index] = '\0';
            last_inode = curr->ino;
            j++;
        }
    }

    fprintf(fp, "User Stack Trace\n");
    printf(YELLOW "User Stack Trace:\n" NONE);
    char stack_func_name[NAMELIMIT] = {0};
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        stack = stacks[i];
        if (stack == 0) {
            break;
        }
        int index = search_object_file(stack, files, file_counts);
        get_user_func_name(stack - files[index].segment_start,
                           (const char*)files[index].exec_file_path,
                           stack_func_name);
        fprintf(fp, "    0x%016lx %s\n", stack, stack_func_name);
        printf("    0x%016lx %s\n", stack, stack_func_name);
    }

    fprintf(fp, "[Dependencies] Dynamic Libs:\n");
    printf(YELLOW "[Dependencies] Dynamic Libs:" NONE "\n");
    for (int i = 0; i < e->count; i++) {
        curr = &(e->mmap[i]);
        if (!(curr->flags & VM_EXEC)) {
            continue;
        }
        fprintf(fp,
                "    0x%016lx-0x%016lx %c%c%c%c %08llx %02x:%02x %lu ",
                curr->start,
                curr->end,
                curr->flags & VM_READ ? 'r' : '-',
                curr->flags & VM_WRITE ? 'w' : '-',
                curr->flags & VM_EXEC ? 'x' : '-',
                curr->flags & VM_MAYSHARE ? 's' : 'p',
                curr->pgoff,
                MAJOR(curr->dev),
                MINOR(curr->dev),
                curr->ino);
        printf("    0x%016lx-0x%016lx %c%c%c%c %08llx %02x:%02x %lu ",
               curr->start,
               curr->end,
               curr->flags & VM_READ ? 'r' : '-',
               curr->flags & VM_WRITE ? 'w' : '-',
               curr->flags & VM_EXEC ? 'x' : '-',
               curr->flags & VM_MAYSHARE ? 's' : 'p',
               curr->pgoff,
               MAJOR(curr->dev),
               MINOR(curr->dev),
               curr->ino);
        printf("%s\n", path_utils.get_inode_path(curr->ino, curr->dev).c_str());

        // for (int i = 0; i < MAX_LEVEL; i++)
        // {
        // 	if (curr->name[i][0] == '\0' || curr->name[i][0] == '/')
        // 	{
        // 		continue;
        // 	}
        // 	fprintf(fp, "/%s", curr->name[i]);
        // 	printf("/%s", curr->name[i]);
        // }
        // fprintf(fp, "\n");
        // printf("\n");
    }
    fprintf(fp,
            "Kernel program time expense for BPF: %llu ns\n",
            e->process_time_ns);
    printf(YELLOW "Kernel program time expense for BPF: %llu ns\n" NONE,
           e->process_time_ns);
    fprintf(fp, "\n");
    printf("\n");
    fclose(fp);
    free(files);
    return 0;
}

int main(int argc, char** argv) {
    /*
        THe main function.
    */
    sysinfo_initialize();
    sym_initialize();

    printf(YELLOW ">>>>>>>Finished initializing...\n" NONE);
    // sudo mount -t debugfs none /sys/kernel/debug
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct ring_buffer* rb = NULL;
	struct bpf_link* link = NULL;
    int err;

    long long opt;
    int mode = 0;
    while((opt = getopt(argc, argv, "p:m:d")) != -1){
        switch(opt){
            case 'p':
                strcpy(log_path, optarg);
                break;
            case 'm':
                mode = atoi(optarg);
                break;
            default:
                printf("Usage: %s [-p log_path] [-m 1/2/3 (kprobe_with_path/kprobe_without_path/fentry)]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }


    printf(BLUE "Log will be saved in: %s" NONE "\n", log_path);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    open_opts.btf_custom_path = "/sys/kernel/btf/vmlinux";
    skel = crashcrawler_bpf__open_opts(&open_opts);
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    // err = crashcrawler_bpf__load(skel);
	err = bpf_object__load(skel->obj);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    // err = crashcrawler_bpf__attach(skel);

	// attach single prog 
    switch(mode){
        case 1:
            link = bpf_program__attach(skel->progs.kprobe__do_exit_wit_path);
            printf("attach kprobe__do_exit_wit_path\n");
            break;
        case 2:
            link = bpf_program__attach(skel->progs.kprobe__do_exit_no_path);
            printf("attach kprobe__do_exit_no_path\n");
            break;
        case 3:
            link = bpf_program__attach(skel->progs.fentry__do_exit);
            printf("attach fentry__do_exit\n");
            break;
        default:
            printf("wrong mode, must be 1,2,3\n");
            exit(EXIT_FAILURE);
    }
    if (link == NULL) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    mkdir(log_path, S_IRWXU);
    chdir(log_path);
    //
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    /* Process events */

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    crashcrawler_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}