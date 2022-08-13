// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <bpf/libbpf.h>
#include "exitcatch.h"
#include "exitcatch.skel.h"
#include "color.h"
#define NAMELIMIT 100
#define MAXLEN_PATH 100
#define LISTLIMT 500000
const char *KALLPATH = "/proc/kallsyms";
char logpath[MAXLEN_PATH] = "/var/log/crashlog";

char sysinfo_buffer[800];

typedef struct
{
	/*
		One node for symbol table
	*/
	unsigned long int address;
	char flag;
	char name[NAMELIMIT];
	//    symbolNode(unsigned long int _addr = 0, char _flag = 0, _name = ""):
} symbolNode;

typedef struct
{
	/*
		The whole table
	*/
	symbolNode nodeArray[LISTLIMT];
	int length;
} symbolList;

struct RelaventFile
{
	char exec_file_path[MAX_LEVEL * MAXLEN_VMA_NAME + MAX_LEVEL];
	unsigned long segment_start;
	unsigned long segment_end;
};
symbolList symList;

static int char2int(char c)
{
	if (c <= '9' && c >= '0')
		return c - '0';
	else
		return c - 'a' + 10;
}
static long int calIndex(int n)
{
	long int ans = 1;
	while (n--)
		ans *= 16;
	return ans;
}
static void initializeSym()
{
	FILE *fp = fopen(KALLPATH, "r");
	char *line = NULL;
	size_t len = 0;
	size_t readLength;
	symList.length = 0;
	while ((readLength = getline(&line, &len, fp)) != -1)
	{
		int mod = 0;
		for (int i = 0; i < readLength; i++)
		{
			if (line[i] == '\t' || line[i] == '\n')
				break;
			if (line[i] == ' ')
			{
				++mod;
				continue;
			}
			if (mod == 0)
			{
				if (i == 0)
					symList.nodeArray[symList.length].address = 0;
				symList.nodeArray[symList.length].address += calIndex(15 - i) * char2int(line[i]);
			}
			else if (mod == 1)
			{
				symList.nodeArray[symList.length].flag = line[i];
			}
			else
			{
				if (i == 19)
					memset(symList.nodeArray[symList.length].name, 0, sizeof(symList.nodeArray[symList.length].name));
				symList.nodeArray[symList.length].name[i - 19] = line[i];
			}
		}
		++symList.length;
	}
}
static int searchKernelSymbol(unsigned long query)
{
	int left = 0, right = symList.length;
	while (left < right)
	{
		int mid = (left + right) / 2;
		if (symList.nodeArray[mid].address >= query)
			right = mid;
		else
			left = mid + 1;
	}
	left = left > 0 ? --left : left;
	return left;
}
static int searchUserFile(unsigned long query, struct RelaventFile *files, int fileCount)
{
	int left = 0, right = fileCount - 1;
	while (left < right)
	{
		int mid = (left + right) / 2;
		if (files[mid].segment_start >= query)
			right = mid;
		else
			left = mid + 1;
	}
	left = left > 0 ? --left : left;
	return left;
}
static int userstackNameSearch(unsigned long virtualAddr, const char *filePath, char *stackFunctionName)
{
	/*
		userstackNameSearch is used to search for the symbol name of a specific
		virtual address in user stack.
		input:
			virtualAddr: specific address of memory;
			filePath: binary Path of the specific tmpAddr;
			stackFunctionName: the return name of a stack;
		output: return a int indicate whether is a successful search;
			0: successful search;
			1: failed;
	*/
	FILE *fp;
	unsigned long offset = 0, physicalAddr = 0, flag = 1, stackAddr = 0;
	char cmd[NAMELIMIT];
	int foundSymbols = 0;
	memset(stackFunctionName, 0, sizeof(stackFunctionName));
	/*
		Reading offset
	*/
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "readelf -l %s | awk '$4==\"E\"{print x};{x=$2}'", filePath);
	fp = popen(cmd, "r");
	fscanf(fp, "%lx", &offset);
	physicalAddr = virtualAddr + offset;
	pclose(fp);
	/*
		Reading function symbols
	*/
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "nm -n -D -C %s | awk '$2==\"t\" || $2==\"T\"{print $1, $3}'", filePath);
	fp = popen(cmd, "r");
	char tmpName[NAMELIMIT] = {0};
	while (fscanf(fp, "%lx", &stackAddr) == 1)
	{
		foundSymbols = 1;
		if (physicalAddr < stackAddr)
		{
			flag = 0;
			break;
		}
		fscanf(fp, "%s", tmpName);
		offset = physicalAddr - stackAddr;
	}
	if (!flag)
	{
		sprintf(stackFunctionName, "%s+0x%lx", tmpName, offset);
		return flag;
	}
	if (foundSymbols)
	{
		sprintf(stackFunctionName, "[No Function Name]");
		return flag;
	}
	// Looking for the stack in the dynamic Libs
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "nm -n -C %s | awk '$2==\"t\" || $2==\"T\"{print $1, $3}'", filePath);
	fp = popen(cmd, "r");
	while (fscanf(fp, "%lx", &stackAddr) == 1)
	{
		if (physicalAddr < stackAddr)
		{
			flag = 0;
			break;
		}
		fscanf(fp, "%s", tmpName);
		offset = physicalAddr - stackAddr;
	}
	if (!flag)
		sprintf(stackFunctionName, "%s+0x%lx", tmpName, offset);
	else
		sprintf(stackFunctionName, "[No Function Name]");
	return flag;
}
static void initializeSysInfo()
{
	/*
		硬件信息脚本
		https://blog.csdn.net/LvJzzZ/article/details/112029991
	*/
	FILE *fp;
	fp = popen("bash ../src/hardware.sh", "r");
	while (1)
	{
		memset(sysinfo_buffer, 0, sizeof(sysinfo_buffer));
		void *ptr = fgets(sysinfo_buffer, sizeof(sysinfo_buffer), fp);
		if (ptr == NULL)
			break;
		printf("%s", sysinfo_buffer);
	}
	pclose(fp);
}
struct exitcatch_bpf *skel;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void printf_info(struct event *e)
{
	// time
	const long ns2us = 1000;
	printf(BLUE "=====================Process's Brief Report===========================\n" NONE);
	printf(YELLOW "---------------------------Time Report--------------------------------\n" NONE);
	printf("User Mode Time: %ldus\n", e->utime / ns2us);
	printf("System Mode Time: %ldus\n", e->stime / ns2us);
	printf("task schedule priority: %ld\n", e->prio - MAX_RT_PRIO);
	printf("task schedule nice: %ld\n", e->prio - DEFAULT_PRIO);
	printf("number of thread : %ld\n", e->num_threads);

	printf("Virtual Memory info:\n");
	printf("");
	printf("\t\t%-13s%-13s%-20s\n", "Main Process", "Subprocess", "Subprocess(On vCPU)");
	printf("%-16s%-13lu%-13lu%-20lu\n", "User Mode(us)", e->utime / ns2us, e->cutime / ns2us, e->gtime / ns2us);
	// printf("%-16s%-13ld%-13ld%-20ld\n", "System Mode(us)", e->stime / ns2us, e->cstime / ns2us, e->cgtime / ns2us);
	printf("cutime:%luus\n", e->cutime / ns2us); //14-17  done ns
	printf("cstime:%luus\n", e->cstime / ns2us);
	// printf("stime:%luus\n", e->stime / ns2us);
	// printf("utime:%luus\n", e->utime / ns2us);
	// printf("cgtime:%luus\n", e->cgtime / ns2us);
	// printf("gtime:%luus\n", e->gtime / ns2us);

	// printf("prio:%d\n", e->prio); //18 task->prio - MAX_RT_PRIO  done
	// printf("nice:%d\n", e->nice); //19 prio  - DEFAULT_PRIO
	// printf("num_threads:%d\n", e->num_threads); //20 task->signal->nr_threads;
	// //unsigned long long start_time; //22  done

	// printf("mm_vsize:%lu\n",e->mm_vsize); //23  done
	// printf("mm_rss:%lu\n",e->mm_rss);	//24 mm_rss//done
	// printf("rsslim:%lu\n",e->rsslim); //24
	// printf("mm_start_code:%lu\n",e->mm_start_code); //25  done
	// printf("mm_end_code:%lu\n",e->mm_end_code); //26  done
	// printf("mm_start_stack:%lu\n",e->mm_start_stack); //27  done
	// // printf("esp:%lu\n",e->esp); //28//done
	// // printf("eip:%lu\n",e->eip); //29//done

	// printf("exit_signal:%d\n", e->exit_signal);  //done
	// printf("cpu: %n",e->cpu);//done
	// printf("rt_priority: %n",e->rt_priority);//done
	// printf("policy: %n",e->policy);//done

	// printf("mm_start_data:%lu\n",e->mm_start_data);//done
	// printf("mm_end_data:%lu\n",e->mm_end_data);//done
	// printf("mm_start_brk:%lu\n",e->mm_start_brk);//done
	// printf("mm_arg_start:%lu\n",e->mm_arg_start);//done
	// printf("mm_arg_end:%lu\n",e->mm_arg_end);//done
	// printf("mm_env_start:%lu\n",e->mm_env_start);//done
	// printf("mm_env_end:%lu\n",e->mm_env_end);//done
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct RelaventFile *files;
	int file_count = 0;
	const struct event *e = data;
	struct tm *tm;
	char ts[64];
	time_t t;
	unsigned long stack = 0;
	unsigned long stacks[MAX_STACK_DEPTH] = {0};

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%m-%d_%H:%M:%S", tm);

	char filename[NAMELIMIT] = {0};
	strcpy(filename, e->comm);
	strcat(filename, "_");
	strcat(filename, ts);
	strcat(filename, ".log");
	printf(YELLOW "\n			  %s\n" NONE, filename);
	chdir(logpath);
	FILE *fp = fopen(filename, "w");
	int ret = bpf_map__lookup_elem(
		skel->maps.map_kernel_stack_traces,
		&e->kernel_stack_id,
		sizeof(unsigned int),
		&stacks,
		VALUESIZE,
		0);

	if (ret != 0)
	{
		printf("Error finding Kernel stack trace\n");
		return 0;
	}
	fprintf(fp, "%-14s %-16s %-7s %-7s %-7s %-9s %s\n",
			"TIME", "COMM", "TID", "PID", "PPID", "EXIT CODE", "SIGNALS");
	fprintf(fp, "%-14s %-16s %-7d %-7d %-7d %-9d %d\n",
			ts, e->comm, e->tid, e->pid, e->ppid, e->exit_code, e->sig);
	fprintf(fp, "Stack Trace:\n");
	printf(HEAD "%-14s %-16s %-7s %-7s %-7s %-9s %s" NONE "\n",
		   "TIME", "COMM", "TID", "PID", "PPID", "EXIT CODE", "SIGNALS");
	printf(LIGHT_GREEN "%-14s" YELLOW " %-16s" NONE " %-7d %-7d %-7d" RED " %-9d %d\n" NONE,
		   ts, e->comm, e->tid, e->pid, e->ppid, e->exit_code, e->sig);
	// Print brief report to the process
	printf_info(e);
	// Trace and dependencies
	printf(YELLOW "Kernel Stack Trace:\n" NONE);
	for (int i = 0; i < MAX_STACK_DEPTH; i++)
	{
		stack = stacks[i];
		if (stack == 0)
		{
			break;
		}
		int index = searchKernelSymbol(stack);
		fprintf(fp, "    %#lx %s+%#lx\n", stack, symList.nodeArray[index].name, stack - symList.nodeArray[index].address);
		printf("    %#lx %s+%#lx\n", stack, symList.nodeArray[index].name, stack - symList.nodeArray[index].address);
	}

	// Get and print User stacktrace
	ret = bpf_map__lookup_elem(
		skel->maps.map_user_stack_traces,
		&e->user_stack_id,
		sizeof(unsigned int),
		&stacks,
		VALUESIZE,
		0);

	if (ret != 0)
	{
		printf("Error finding User stack trace\n");
		return 0;
	}
	// share lib
	const struct mmap_struct *curr;
	// get relavent files count
	int last_inode = -1;
	for (int i = 0; i < e->count; i++)
	{
		curr = &(e->mmap[i]);
		if ((curr->flags & VM_EXEC) && curr->ino != last_inode)
		{
			last_inode = curr->ino;
			file_count++;
		}
	}

	files = (struct RelaventFile *)malloc(sizeof(struct RelaventFile) * file_count);

	last_inode = -1;
	for (int i = 0, j = 0; i < e->count; i++)
	{
		curr = &(e->mmap[i]);
		if ((curr->flags & VM_EXEC) && curr->ino != last_inode)
		{
			files[j].segment_end = curr->end;
			files[j].segment_start = curr->start;
			int index = 0;
			for (int level = 0; level < MAX_LEVEL; level++)
			{
				if (curr->name[level][0] == '\0' || curr->name[level][0] == '/')
				{
					continue;
				}
				index += sprintf(files[j].exec_file_path + index, "/%s", curr->name[level]);
			}
			files[j].exec_file_path[index] = '\0';
			last_inode = curr->ino;
			j++;
		}
	}

	printf(YELLOW "User Stack Trace:\n" NONE);
	char stackFunctionName[NAMELIMIT] = {0};
	for (int i = 0; i < MAX_STACK_DEPTH; i++)
	{
		stack = stacks[i];
		if (stack == 0)
		{
			break;
		}
		int index = searchUserFile(stack, files, file_count);
		int searchResult = userstackNameSearch(stack - files[index].segment_start, (const char *)files[index].exec_file_path, stackFunctionName);
		fprintf(fp, "    0x%016lx %s\n", stack, stackFunctionName);
		printf("    0x%016lx %s\n", stack, stackFunctionName);
	}

	printf(YELLOW "[Dependencies] Dynamic Libs:" NONE "\n");
	fprintf(fp, "[Dependencies] Dynamic Libs:\n");
	for (int i = 0; i < e->count; i++)
	{
		curr = &(e->mmap[i]);
		fprintf(fp, "    0x%016lx-0x%016lx %c%c%c%c %08llx %02x:%02x %lu ",
				curr->start,
				curr->end,
				curr->flags & VM_READ ? 'r' : '-',
				curr->flags & VM_WRITE ? 'w' : '-',
				curr->flags & VM_EXEC ? 'x' : '-',
				curr->flags & VM_MAYSHARE ? 's' : 'p',
				curr->pgoff,
				MAJOR(curr->dev), MINOR(curr->dev), curr->ino);
		printf("    0x%016lx-0x%016lx %c%c%c%c %08llx %02x:%02x %lu ",
			   curr->start,
			   curr->end,
			   curr->flags & VM_READ ? 'r' : '-',
			   curr->flags & VM_WRITE ? 'w' : '-',
			   curr->flags & VM_EXEC ? 'x' : '-',
			   curr->flags & VM_MAYSHARE ? 's' : 'p',
			   curr->pgoff,
			   MAJOR(curr->dev), MINOR(curr->dev), curr->ino);
		for (int i = 0; i < MAX_LEVEL; i++)
		{
			if (curr->name[i][0] == '\0' || curr->name[i][0] == '/')
			{
				continue;
			}
			fprintf(fp, "/%s", curr->name[i]);
			printf("/%s", curr->name[i]);
		}

		fprintf(fp, "\n");
		printf("\n");
	}
	fprintf(fp, "\n");
	fclose(fp);
	free(files);
	return 0;
}

int main(int argc, char **argv)
{
	initializeSysInfo();
	initializeSym();

	printf(YELLOW ">>>>>>>Finished initializing...\n" NONE);
	// sudo mount -t debugfs none /sys/kernel/debug
	struct ring_buffer *rb = NULL;
	int err;

	if (argc > 2)
	{
		return -1;
	}

	if (argc == 2)
		strcpy(logpath, argv[1]);

	printf(BLUE "Log will be saved in: %s" NONE "\n", logpath);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = exitcatch_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = exitcatch_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = exitcatch_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */

	//
	mkdir(logpath, S_IRWXU);
	chdir(logpath);
	//
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	/* Process events */

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	exitcatch_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}