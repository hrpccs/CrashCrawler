#ifndef EXITCATCH_H
#define EXITCATCH_H

#define MAX_STACK_DEPTH 20
#define TASK_COMM_LEN 16
#define VALUESIZE  MAX_STACK_DEPTH * sizeof(size_t)

struct event{
		pid_t pid;
		pid_t tid;
		pid_t ppid;
		int sig;
		int exit_code;
		char comm[TASK_COMM_LEN];
		unsigned long stack_id;
};


#endif