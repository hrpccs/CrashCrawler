#ifndef HELLO_H
#define HELLO_H
#include "vmlinux.h"

#define TASK_COMM_LEN 16


struct event{
    u32 pid;
    char pcomm[TASK_COMM_LEN];
    u32 exitcode;
};


#endif