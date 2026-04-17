#ifndef _CACHEUTILS_H_
#define _CACHEUTILS_H_

#include <assert.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <limits.h>
#include <setjmp.h>
#include <fcntl.h>

#include <pthread.h>

#ifdef __cplusplus

#include <cstdlib>
#include <cstring>

#endif // __cplusplus


#define ARM_PERF            1
#define ARM_CLOCK_MONOTONIC 2
#define ARM_TIMER           3

/* ============================================================
 *                    User configuration
 * ============================================================ */
#define DIRECT_PHYS_MAP_BASE ((uint64_t)0xffff888000000000)

/* ============================================================
 *                  User configuration End
 * ============================================================ */



// ---------------------------  Some useful macros  --------------------------
#define PAGESIZE 4096

#define speculation_start(label) asm goto ("call %l0" : : : "memory" : label##_retp);
#define speculation_end(label) asm goto("jmp %l0" : : : "memory" : label); label##_retp: asm goto("lea %l0(%%rip), %%rax\nmovq %%rax, (%%rsp)\nret\n" : : : "memory","rax" : label); label: asm volatile("nop");

// example usage: asm volatile(INTELASM("clflush [rax]\n\t"));
#define INTELASM(code) ".intel_syntax noprefix\n\t" code "\n\t.att_syntax prefix\n"

// ----------------------------- Fault Handling Stuff ------------------------
// NOTE: it is CRUCIAL to implement these as MACROS instead of functions!
// "If the function that called setjmp has exited (whether by return or by a different longjmp higher up the stack), the behavior is undefined. In other words, only long jumps up the call stack are allowed."
// src: https://en.cppreference.com/w/c/program/longjmp
// I've observed multiple faults or endless loop when wrapping them in normal functions
extern jmp_buf trycatch_buf;
#define sig_start() (!setjmp(trycatch_buf))


// ---------------------------------------------------------------------------
// requires root
uint64_t virtual_to_physical_address(void* virtual_address);

// ---------------------------------------------------------------------------
// requires root
char* get_kernel_address(void* vaddr);


// ---------------------------------------------------------------------------
int get_sibling_hyperthread(int logical_core);

// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
void perf_init();

#if defined(__i386__) || defined(__x86_64__)
// ---------------------------------------------------------------------------
uint64_t rdtsc();

// ---------------------------------------------------------------------------
void maccess(void *p);

// ---------------------------------------------------------------------------
void flush(void *p);

// ---------------------------------------------------------------------------
void mfence();

// ---------------------------------------------------------------------------
void cpuid_clear();

// ---------------------------------------------------------------------------
void nospec();

// ---------------------------------------------------------------------------
unsigned int xbegin();

// ---------------------------------------------------------------------------
void xend();

// ---------------------------------------------------------------------------
int has_tsx();

// ---------------------------------------------------------------------------
void maccess_tsx(void* ptr);

// ---------------------------------------------------------------------------
int flush_reload(void *ptr, int cache_miss);
// ---------------------------------------------------------------------------
int flush_reload_t(void *ptr);

// ---------------------------------------------------------------------------
int reload_t(void *ptr);

// ---------------------------------------------------------------------------
size_t detect_flush_reload_threshold();

// ---------------------------------------------------------------------------
void maccess_speculative(void* ptr);

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
void unblock_signal(int signum __attribute__((__unused__)));

// ---------------------------------------------------------------------------
void trycatch_segfault_handler([[maybe_unused]] int signum);

// ---------------------------------------------------------------------------
int try_start();

// ---------------------------------------------------------------------------
int tsx_start();

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
void try_end();

// ---------------------------------------------------------------------------
void try_abort();

void tsx_abort();

void sig_abort();

#endif

// ---------------------------------------------------------------------------
float median(int* arr, size_t n);

int average(int* arr, size_t n);

int min(int* arr, size_t n);

// ---------------------------------------------------------------------------
int is_kpti_enabled();

#endif