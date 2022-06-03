// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "exitcatch.h"
#include "exitcatch.skel.h"
#include "color.h"

struct exitcatch_bpf *skel;

static struct env
{
	bool verbose;
} env;

const char *argp_program_version = "exitcatch 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
	"BPF exitcatch demo application.\n"
	"\n"
	"It traces process exits unnormally and shows associated \n"
	"information (filename, process duration, PID and PPID, stacktrace,etc).\n"
	"\n"
	"USAGE: ./exitcatch [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	unsigned long stack = 0;
	unsigned long stacks[MAX_STACK_DEPTH] = {0};

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	int ret = bpf_map__lookup_elem(
		skel->maps.map_stack_traces,
		&e->stack_id,
		sizeof(unsigned int),
		&stacks,
		VALUESIZE,
		0);

	if (ret != 0)
	{
		printf("Error finding stack trace\n");
		return 0;
	}
	printf(LIGHT_GREEN"%-8s"NONE" %-16s %-7s %-7s %-7s %-9s %s\n",
		   "TIME", "COMM", "TID", "PID", "PPID", "EXIT CODE", "SIGNALS");
	printf(LIGHT_GREEN"%-8s"NONE" %-16s %-7d %-7d %-7d %-9d %d\n",
		   ts, e->comm, e->tid, e->pid, e->ppid, e->exit_code, e->sig);
	printf("stack trace:\n");
	for (int i = 0; i < MAX_STACK_DEPTH; i++)
	{
		stack = stacks[i];
		if (stack == 0)
		{
			break;
		}
		printf("    %#lx\n", stack);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

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