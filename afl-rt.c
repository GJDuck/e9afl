/*
 *        ___    _    _____ _     
 *   ___ / _ \  / \  |  ___| |    
 *  / _ \ (_) |/ _ \ | |_  | |    
 * |  __/\__, / ___ \|  _| | |___ 
 *  \___|  /_/_/   \_\_|   |_____|
 * 
 * american fuzzy lop - LLVM instrumentation bootstrap
 * ---------------------------------------------------
 *
 * Written by Laszlo Szekeres <lszekeres@google.com> and
 *            Michal Zalewski <lcamtuf@google.com>
 *
 * LLVM integration design comes from Laszlo Szekeres.
 *
 * Copyright 2015, 2016 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * This code is the rewrite of afl-as.h's main_payload.
 *
 * E9Patch adaption:
 * Xiang Gao
 * Gregory J. Duck
 */

#define double long
#define getenv __dummy_getenv
#define atoi   __dummy_atoi
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#undef getenv
#undef atoi

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#define FORKSRV_FD  198
#define AREA_BASE   ((uint8_t *)0x200000)
#define AREA_SIZE   ((size_t)1 << 16)

static const char *getenv(char *name, const char **envp)
{
    const char *entry;
    for (unsigned i = 0; (entry = envp[i]) != NULL; i++)
    {
        unsigned j;
        for (j = 0; name[j] == entry[j]; j++)
            ;
        if (name[j] == '\0' && entry[j] == '=')
            return entry + j + 1;
    }

    return NULL;
}

static int atoi(const char *str)
{
    bool neg = (str[0] == '-');
    str = (neg? str+1: str);
    int x = 0;
    while (*str >= '0' && *str <= '9')
    {
        x *= 10;
        x += (int)(*str++ - '0');
    }
    return (neg? -x: x);
}

/*
 * System call implementation.
 */
#define STRING(x)   STRING_2(x)
#define STRING_2(x) #x
asm
(
    ".globl syscall\n"
    "syscall:\n"

    // Disallow syscalls that MUST execute in the original context:
    "cmp $" STRING(SYS_rt_sigreturn) ",%eax\n"
    "je .Lno_sys\n"
    "cmp $" STRING(SYS_clone) ",%eax\n"
    "je .Lno_sys\n"

    // Convert SYSV -> SYSCALL ABI:
    "mov %edi,%eax\n"
    "mov %rsi,%rdi\n"
    "mov %rdx,%rsi\n"
    "mov %rcx,%rdx\n"
    "mov %r8,%r10\n"
    "mov %r9,%r8\n"
    "mov 0x8(%rsp),%r9\n"

    // Execute the system call:
    "syscall\n"

    "retq\n"

    // Handle errors:
    ".Lno_sys:\n"
    "mov $-" STRING(ENOSYS) ",%eax\n"
    "retq\n"
);

#define exit(...)      syscall(SYS_exit, ##__VA_ARGS__)
#define open(...)      syscall(SYS_open, ##__VA_ARGS__)
#define close(...)     syscall(SYS_close, ##__VA_ARGS__)
#define read(...)      syscall(SYS_read, ##__VA_ARGS__)
#define write(...)     syscall(SYS_write, ##__VA_ARGS__)
#define fork(...)      syscall(SYS_fork, ##__VA_ARGS__)
#define shmat(...)     syscall(SYS_shmat, ##__VA_ARGS__)
#define kill(...)      syscall(SYS_kill, ##__VA_ARGS__)
#define mmap(...)      syscall(SYS_mmap, ##__VA_ARGS__)
#define waitpid(pid, status, options)                               \
    syscall(SYS_wait4, (pid), (status), (options), NULL)

static void print_message(bool fatal, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    char buf[BUFSIZ+1];
    size_t i = 0;
    for (size_t len = 0; msg[len] != '\0'; len++)
    {
        if (msg[len] == '%')
        {
            len++;
            switch (msg[len])
            {
                case '\0':
                    break;
                case 'd':
                {
                    int x = va_arg(ap, int);
                    if (x == 0)
                    {
                        buf[i++] = '0';
                        break;
                    }
                    if (x < 0)
                        buf[i++] = '-';
                    x = (x < 0? -x: x);
                    bool seen = false;
                    int r = 1000000000;
                    while (r != 0)
                    {
                        char c = '0' + x / r;
                        x %= r;
                        r /= 10;
                        if (!seen && c == '0')
                            continue;
                        seen = true;
                        buf[i++] = c;
                    }
                    break;
                }
                case 's':
                {
                    const char *s = va_arg(ap, const char *);
                    if (s == NULL)
                        break;
                    while (*s)
                        buf[i++] = *s++;
                    break;
                }
                default:
                    buf[i++] = msg[len];
                    break;
            }
            continue;
        }
        buf[i++] = msg[len];
    }

    int fd = open("/tmp/e9afl.log", O_WRONLY | O_CREAT | O_APPEND,
        S_IRUSR | S_IWUSR);
    if (fd > 0)
    {
        write(fd, buf, i);
        close(fd);
    }

    if (fatal)
        asm("ud2");
}

#define error(msg, ...)                                             \
    print_message(true, "e9afl runtime error: " msg "\n", ## __VA_ARGS__)
#define log(msg, ...)                                               \
    print_message(false, "e9afl log: " msg "\n", ## __VA_ARGS__)

/* SHM setup. */
static void __afl_map_shm(const char **envp)
{
    const char *id_str = getenv("__AFL_SHM_ID", envp);

    /* 
     * If we're running under AFL, attach to the appropriate region,
     * replacing the early-stage __afl_area_initial region that is needed to
     * allow some really hacky .init code to work correctly in projects such
     * as OpenSSL.
     */
    intptr_t afl_area_ptr = 0x0;
    uint32_t shm_id = 0;
    if (id_str != NULL)
    {
        shm_id = (uint32_t)atoi(id_str);
        afl_area_ptr = shmat(shm_id, AREA_BASE, 0);
    }
    else
    {
        /* 
         * If there is no id_str then we are running the program normally
         * and not with afl-fuzz.  Create a dummy area so the program does
         * not crash.
         */
        afl_area_ptr = mmap(AREA_BASE, AREA_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }

    /* Whooooops. */
    if (afl_area_ptr != (intptr_t)AREA_BASE)
        error("failed to map AFL area (shm_id=%s, errno=%d)", id_str,
            (int)afl_area_ptr);
}

/* Fork server logic. */
static void __afl_start_forkserver(void)
{
    const uint8_t tmp[4] = {0};
    int child_pid;

    /* 
     * Phone home and tell the parent that we're OK. If parent isn't there,
     * assume we're not running in forkserver mode and just execute program.
     */
    if (write(FORKSRV_FD + 1, tmp, 4) != 4)
        return;

    while (true)
    {
        /*
         * Wait for parent by reading from the pipe. Abort if read fails.
         */
        uint32_t was_killed;
        int err;
        if ((err = read(FORKSRV_FD, &was_killed, sizeof(was_killed))) !=
                sizeof(was_killed))
            error("failed to read from the fork server pipe (errno=%d)", err);

        int status = 0;
        if (was_killed)
        {
            if ((err = waitpid(child_pid, &status, 0)) < 0)
                error("failed to wait for child process (errno=%d)", err);
        }

        /*
         * Once woken up, create a clone of our process.
         */
        child_pid = fork();
        if (child_pid < 0)
            error("failed to fork process (errno=%d)", child_pid);

        /*
         * In child process: close fds, resume execution.
         */
        if (!child_pid)
        {
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            return;
        }

        /*
         * In parent process: write PID to pipe, then wait for child.
         */
        if ((err = write(FORKSRV_FD + 1, &child_pid, sizeof(child_pid)))
                != sizeof(child_pid))
            error("failed to write child pid to the fork server pipe "
                "(errno=%d)", err);
        if ((err = waitpid(child_pid, &status, 0)) < 0)
            log("failed to wait for the child process (errno=%d)", err);

        /*
         * Relay wait status to pipe, then loop back.
         */
        if ((err = write(FORKSRV_FD + 1, &status, sizeof(status)))
                != sizeof(status)) 
            error("failed to write child status to the fork server pipe "
                "(errno=%d)", err);
    }
}

/*
 * Init.
 */
void init(int argc, const char **argv, const char **envp)
{
    __afl_map_shm(envp);
    __afl_start_forkserver();
}

/*
 * Entry.  This is a (slower) alternative to the plugin instrumentation.
 *
 * USAGE:
 *      E9AFL_NO_INSTRUMENT=1 ./e9tool -M 'plugin[e9afl]' \
 *               -A 'call entry(random)@"afl-rt"' \
 *               path/to/binary
 */
void entry(uint32_t curr_loc)
{
    uint32_t prev_loc = 0;
    asm ("mov %%fs:0x48,%0" : "=r"(prev_loc));
    uint16_t idx = prev_loc ^ curr_loc;
    AREA_BASE[idx]++;
    asm ("mov %0,%%fs:0x48" : : "r"(curr_loc >> 1));
}

