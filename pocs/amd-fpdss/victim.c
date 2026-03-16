#define _GNU_SOURCE
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <x86intrin.h>
#include <immintrin.h>

#include "cacheutils.h"

// works for SSE attacker
#define VICTIM_SSE_DIV

// works for AVX attacker
//#define VICTIM_AVX_DIV

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

__attribute__((naked, aligned(4096)))
void victim_code(
    char* data_page, 
    char* data_page_second_mapping, 
    char* probe_memory) {
  asm volatile(INTELASM(
        "push   rbx\n\t"
        "push   rbp\n\t"
        "mov    rbp, rsp\n\t"
        "sub    rsp, 0x2000\n\t"
        "mov    r8, rdi\n\t"
        "mov    r11, 0x186a0\n\t" // loop ctr
        "l1:nop\n\t"

#ifdef VICTIM_SSE_DIV
        "mov    rsi, QWORD PTR [r8]\n\t"
        "mov    rdi, 0x1\n\t"
        "movq   xmm1, rdi\n\t"
        "movq   xmm2, rsi\n\t"

        REP100("divsd  xmm1, xmm2\n\t")
#endif

#ifdef VICTIM_AVX_DIV
        "mov    rsi, QWORD PTR [r8]\n\t"
        "mov    rdi, 0x1\n\t"
        "movq   xmm1, rdi\n\t"
        "movq   xmm2, rsi\n\t"

        REP100("vdivss  xmm3, xmm1, xmm2\n\t")
#endif

        "dec    r11\n\t"
        "jne    l1\n\t"
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

int main(int argc, char* argv[]) {
  int single_core_mode = 0;
  if (argc != 2) {
    printf("Usage: %s <secret-to-encode>\n", argv[0]);
    exit(1);
  }
  init();

  memset(data_page, '\x00', 4096);

  char* secret = argv[1];
  size_t secret_len = strlen(secret);

  // spam secret all over the page
  for (int i = 0; i < 4096 - secret_len; i += secret_len) {
    strcpy(data_page + i, secret);
  }

  while(1) {
    if (!setjmp(trycatch_buf)) {
      victim_code(data_page, data_page_second_mapping, probe_memory);
    }
  }
}




