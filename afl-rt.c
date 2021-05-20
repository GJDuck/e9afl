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

#include "stdlib.c"

#define FORKSRV_FD  198
#define AREA_BASE   ((uint8_t *)0x200000)
#define AREA_SIZE   ((size_t)1 << 16)

static FILE *log = NULL;

static void print_message(bool fatal, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    if (log == NULL)
    {
        log = fopen("/tmp/e9afl.log", "a");
        if (log != NULL)
            setvbuf(log, NULL, _IONBF, 0);
    }
    if (log == NULL)
    {
        if (fatal)
            abort();
        return;
    }
    vfprintf(log, msg, ap);
    if (fatal)
        abort();
    va_end(ap);
}

#define error(msg, ...)                                             \
    print_message(true, "e9afl runtime error: " msg "\n", ## __VA_ARGS__)
#define log(msg, ...)                                               \
    print_message(false, "e9afl log: " msg "\n", ## __VA_ARGS__)

/* SHM setup. */
static void __afl_map_shm(void)
{
    const char *id_str = getenv("__AFL_SHM_ID");

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
        (void)munmap(AREA_BASE, AREA_SIZE);
        afl_area_ptr = (intptr_t)shmat(shm_id, AREA_BASE, 0);
    }
    else
    {
        /* 
         * If there is no id_str then we are running the program normally
         * and not with afl-fuzz.  Create a dummy area so the program does
         * not crash.
         */
        afl_area_ptr = (intptr_t)mmap(AREA_BASE, AREA_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }

    /* Whooooops. */
    if (afl_area_ptr != (intptr_t)AREA_BASE)
        error("failed to map AFL area (shm_id=%s): %s", id_str,
            strerror(errno));
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
        if (read(FORKSRV_FD, &was_killed, sizeof(was_killed))
                != sizeof(was_killed))
            error("failed to read from the fork server pipe: %s",
                strerror(errno));

        int status = 0;
        if (was_killed)
        {
            if (waitpid(child_pid, &status, 0) < 0)
                log("failed to wait for child process: %s", strerror(errno));
        }

        /*
         * Once woken up, create a clone of our process.
         */
        child_pid = fork();
        if (child_pid < 0)
            error("failed to fork process: %s", strerror(errno));

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
        if (write(FORKSRV_FD + 1, &child_pid, sizeof(child_pid))
                != sizeof(child_pid))
            error("failed to write child pid to the fork server pipe: %s",
                strerror(errno));
        if (waitpid(child_pid, &status, 0) < 0)
            log("failed to wait for the child process: %s", strerror(errno));

        /*
         * Relay wait status to pipe, then loop back.
         */
        if (write(FORKSRV_FD + 1, &status, sizeof(status)) != sizeof(status)) 
            error("failed to write child status to the fork server pipe: %s",
                strerror(errno));
    }
}

/*
 * Init.
 */
void init(int argc, const char **argv, char **envp)
{
    if (envp == NULL)
    {
        /*
         * This is a shared library.  For this, we set up a dummy area so the
         * instrumentation does not crash during program initialization.  The
         * main executable is repsonsible for setting up AFL proper.
         */
        (void)mmap(AREA_BASE, AREA_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        return;
    }

    log("fuzzing binary %s", argv[0]);
    environ = envp;
    __afl_map_shm();
    __afl_start_forkserver();
}

/*
 * Entry.  This is a (slower) alternative to the plugin instrumentation.
 *
 * USAGE:
 *      E9AFL_NO_INSTRUMENT=1 ./e9tool -M 'plugin(e9afl).match()' \
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

