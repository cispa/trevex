// Copyright [2026] <Daniel Weber>

#include "utils.h"

#include <cstdint>
#include <thread>
#include <map>
#include <iostream>
#include <vector>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <x86intrin.h>
#include <immintrin.h>

#include "cacheutils/cacheutils.h"
#include "external/PTEditor/ptedit.h"
#include "external/magic_enum/magic_enum.hpp"
#include "logger/logger.h"
#include "utils.h"

#include "executor.h"

namespace trevex {

Executor::Executor() {
  // we keep track of which process creates these resources 
  // (to prevent cleanups by children)
  main_process_ = getpid();

  //
  // Pin Executor a fixed CPU core
  //
  PinToCpuCore(EXECUTOR_MAIN_CORE);

  // initialize PTEditor
  int err = ptedit_init();
  if (err) {
    throw std::runtime_error("PTEditor could not initialize. Is it installed and loaded?");
  }
  // PTEditor (upstream eb16069 and our old fork) has a bug in 
  // the TLB_INVALIDATION_CUSTOM implementation for newer kernels.
  ptedit_switch_tlb_invalidation(PTEDITOR_TLB_INVALIDATION_KERNEL);


  //
  // initialize our own runtime
  //

  // map LEAKAGE CODE
  leakage_code_page_ = static_cast<char*>(mmap(nullptr, kPageSize, 
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS, -1 , 0));
  
  if (leakage_code_page_ == MAP_FAILED) {
    throw std::runtime_error("Could not allocate memory for code page!");
  }

  // map PROBE MEMORY (attacker)
  probe_memory_ = static_cast<char*>(mmap(nullptr, 256 * SPACING, 
    PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1 , 0));
  
  if (probe_memory_ == MAP_FAILED) {
    throw std::runtime_error("Could not allocate memory for probe memory! "
      "Ensure you have enough huge pages available!");
  }

  CreateDataMappings();
  assert(data_page_ != nullptr);
  assert(data_page_second_mapping_ != nullptr);
  assert(data_mem_length_ > 0);

  // no idea why, gcc 9.4.0 doesn't compile this as it thinks the pointer 
  // goes out of bounds, which it isn't. hence we ignore the warning
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Warray-bounds"
  #pragma GCC diagnostic ignored "-Wstringop-overflow"
  // we initialize the data pages to make sure they're mapped
  memset(data_page_, DATA_PAGE_CONTENT, data_mem_length_);
  #pragma GCC diagnostic pop

  // we initialize the remaining pages to make sure they're mapped
  memset(probe_memory_, PROBE_PAGE_CONTENT, 256 * SPACING);
  memset(leakage_code_page_, HLT_INSTRUCTION, kPageSize);


  // TODO: this does not work on lab25 and lab33 atm
  // use the more performant variant of PTEditor
  //ptedit_use_implementation(PTEDIT_IMPL_USER);

  // store the encoding of the WB and UC memory type
  encoding_uncachable_memory_type_ = ptedit_find_first_mt(PTEDIT_MT_UC);
  if (encoding_uncachable_memory_type_ == -1) {
    throw std::runtime_error("Memory type 'Uncacheable' not available for this system!");
  }
  encoding_writeback_memory_type_ = ptedit_find_first_mt(PTEDIT_MT_WB);
  if (encoding_writeback_memory_type_ == -1) {
    throw std::runtime_error("Memory type 'Writeback' not available for this system!");
  }

  #ifndef DEBUGMODE
  RegisterSignalHandlers();
  #endif
}

Executor::~Executor() {
  LOG_DEBUG("Cleaning up Executor resources...");

  // this prevents the child from accidentally cleaning up shared resources with the main process
  if (getpid() == main_process_) {

    // the executor should do this on their own
    // ATTENTION: it's important to not do that in a child process
    // as the memory may still be unmapped after a fork
    //CleanupAllConditionsDataPage();

    #ifndef DEBUGMODE
    UnregisterSignalHandlers();
    #endif
  }

  ptedit_cleanup();
}

// TODO: this is a pure debug function
// (this prevents the write fault bug)
/*
void Executor::CreateDataMappings() {
  data_mem_length_ = 2 * kPageSize;

  data_page_ = static_cast<char*>(mmap(
    reinterpret_cast<void*>(kDataMemoryBegin), data_mem_length_,
    PROT_READ | PROT_WRITE,
    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0));
  if (data_page_ == MAP_FAILED || 
      reinterpret_cast<uint64_t>(data_page_) != kDataMemoryBegin) {
    throw std::runtime_error("Could not allocate memory for data page!");
  }


  data_page_second_mapping_ = data_page_;
}
*/

#ifdef DUPLICATE_MAPPING_IMPLEMENTATION_PTEDITOR
void Executor::CreateDataMappings() {
  // this uses the PTEditor functionality to create duplicate mappings
  data_mem_length_ = 2 * kPageSize;

  // ATTENTION: we map that as MAP_SHARED as otherwise Copy-on-Write 
  //   will split the mappings again when we fork()
  data_page_ = static_cast<char*>(mmap(
    reinterpret_cast<void*>(kDataMemoryBegin), data_mem_length_,
    PROT_READ | PROT_WRITE,
    MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, 0, 0));
  if (data_page_ == MAP_FAILED || 
      reinterpret_cast<uint64_t>(data_page_) != kDataMemoryBegin) {
    throw std::runtime_error("Could not allocate memory for data page!");
  }

  // memset with a dummy value to make sure the page exist
  memset(data_page_, 'Z', data_mem_length_);

  //
  // create a new page that maps to the same PFN
  //

  // get PFN
  size_t data_page_pfn = ptedit_pte_get_pfn(data_page_, 0);
  data_page_second_mapping_ = static_cast<char*>(ptedit_pmap(data_page_pfn << 12, data_mem_length_));
  if (data_page_second_mapping_ == MAP_FAILED) {
    throw std::runtime_error("Could not allocate memory for data page (second mapping): " 
        + std::string(strerror(errno)));
  } 

  //
  // test that the duplicate mapping works
  //
  data_page_second_mapping_[0] = 'A';
  data_page_[0] = 'B';

  if (data_page_second_mapping_[0] != 'B') {
    throw std::runtime_error("Duplicate mapping is not working correctly!");
  }
}
#endif  // DUPLICATE_MAPPING_IMPLEMENTATION_PTEDITOR

#ifdef DUPLICATE_MAPPING_IMPLEMENTATION_SHM
void Executor::CreateDataMappings() {
  // this uses SHM to create a duplicate mapping which does not work with 
  // faulting writes to kernel pages

  // NOTE: we map 2 pages to make sure we can do shenanigans at page boundaries
  data_mem_length_ = 2 * kPageSize;
  int shm_fd = shm_open(kShmName,
      O_CREAT | O_RDWR, 0666);
  if (shm_fd == -1) {
    throw std::runtime_error("Could not create SHM object!");
  }

  int err = ftruncate(shm_fd, data_mem_length_);
  if (err) {
    throw std::runtime_error("Could set size of SHM object!");
  }

  data_page_ = static_cast<char*>(mmap(
    reinterpret_cast<void*>(kDataMemoryBegin), data_mem_length_,
    PROT_READ | PROT_WRITE,
    MAP_FIXED | MAP_SHARED | MAP_POPULATE, shm_fd, 0));
  if (data_page_ == MAP_FAILED || 
      reinterpret_cast<uint64_t>(data_page_) != kDataMemoryBegin) {
    throw std::runtime_error("Could not allocate memory for data page!");
  }

  data_page_second_mapping_ = static_cast<char*>(mmap(
    nullptr, data_mem_length_,
    PROT_READ | PROT_WRITE,MAP_SHARED | MAP_POPULATE, shm_fd, 0));
  if (data_page_second_mapping_ == MAP_FAILED) {
    throw std::runtime_error("Could not allocate memory for data page (second mapping)!");
  }

  close(shm_fd);

  // test that it works
  data_page_second_mapping_[0] = 'A';
  data_page_[0] = 'B';
  if (data_page_second_mapping_[0] != 'B') {
    throw std::runtime_error("Duplicate mapping is not working correctly!");
  }
}
#endif  // DUPLICATE_MAPPING_IMPLEMENTATION_SHM

uint64_t Executor::ExecuteCode(const ByteArray& code) {
  memcpy(leakage_code_page_,
      code.data(), 
      code.size());

  // we prepare the data page (to make sure it's clean)
  memset(data_page_, DATA_PAGE_CONTENT, kPageSize);

  // NOTE: these arguments have to match the other calls to leakage_code_page_
  return ((uint64_t(*)(char*, char*, char*)) leakage_code_page_)(
      data_page_ + 0x80,
      data_page_second_mapping_ + 0x80,
      probe_memory_);
}

ExecutionResults Executor::ExecuteTestcase(
    const TestCase& test_case,
    bool single_core_mode) {
  return ExecuteTestcase(
      test_case, 
      single_core_mode, 
    DATA_PAGE_CONTENT);
}

ExecutionResults Executor::ExecuteTestcase(const TestCase& test_case, 
    bool single_core_mode,
    uint8_t data_page_content) {
  return ExecuteTestcase(test_case, 
      single_core_mode,
      data_page_content,
      TEST_EXECUTIONS);
}

// For performance reason, the core starts/stops the victim thread.
// This enables reusing the same victim thread for multiple testruns
ExecutionResults Executor::ExecuteTestcase(
    const TestCase& test_case,
    bool single_core_mode,
    uint8_t data_page_content,
    size_t number_of_executions) {

  // assert that the mapping is still correct
  size_t pfn_first_mapping = 
      ptedit_pte_get_pfn(data_page_, 0);
  size_t pfn_second_mapping = 
      ptedit_pte_get_pfn(data_page_second_mapping_, 0);
  if (pfn_first_mapping != pfn_second_mapping) {
    throw std::runtime_error("The two virtual mapping no longer map to the same page!");
  }

  // create faulting code and write it to memory
  assert(test_case.leakage_code.size() <= kPageSize);
  assert(test_case.leakage_code.data() != nullptr);
  memcpy(leakage_code_page_,
      test_case.leakage_code.data(), 
      test_case.leakage_code.size());

  // we prepare the data page with the requested values
  memset(data_page_, data_page_content, kPageSize);

  std::vector<ConditionDataPage> conditions = test_case.data_conditions;
  SetInitialConditionsDataPage(conditions);

  size_t cache_miss_threshold = test_case.cache_miss_threshold;

  // make sure memory is mapped
  probe_memory_[0] = PROBE_PAGE_CONTENT;
  mfence();

  // the initial cache flush of the probe array
  for (size_t i = 0; i < 256; i++) {
    flush(probe_memory_ + i * SPACING);
  }
  mfence();

  #ifdef DEBUGMODE
  RegisterSignalHandlers();
  #endif
  
  //sched_yield();


  // we set these vars to volatile to supress the setjmp clobbering warning
  volatile int cache_hits_for_idx[256] = {0};

  // init results
  ExecutionResults exec_results;
  exec_results.leakage = {};
  exec_results.observed_fault = false;
  exec_results.timeout_exceeded = false;
  exec_results.signal_number_caught = -1;

#ifdef ENABLE_FPVI_MITIGATION
  EnableFPVIMitigation();
#endif

  for (volatile size_t testrun = 0; testrun < number_of_executions; testrun++) {
    //sched_yield();

    if (EXECUTE_ATTACKER_ARCHITECTURALLY) {
      // when we execute architecturally, we need to make sure to not 
      // use modified data, hence reinitialize them
      // also make sure that we do not access an inaccessible mapping
      // TODO: possible optimization: using the second mapping
      CleanupConditionsDataPage(conditions);
      memset(data_page_, data_page_content, kPageSize);
      SetInitialConditionsDataPage(conditions);  // restore conds
    }

    if (single_core_mode) {
      // TODO(dwe): call victim?
    }

    // set timeout for execution, in case we get stuck
    alarm(EXECUTION_TIMEOUT_SECONDS);
    if (TimeoutStart()) {
      for (volatile size_t leakage_runs = 0; 
        leakage_runs < LEAKAGE_RUNS_PER_TEST_EXEC;
        leakage_runs++) {

        if (test_case.data_page_extra_conditions) {

          CleanupConditionsDataPage(conditions);  // temp. remove conds
          if (test_case.data_page_in_cache) {
            // access the first four cache lines of the data pages
            for (size_t i = 0; i < data_mem_length_; i += 4096) {
              maccess(data_page_ + i);
              //maccess(data_page_ + i + 64);
              //maccess(data_page_ + i + 128);
              //maccess(data_page_ + i + 192);
            }
          } else {
            // flush the first four cache lines of the data pages
            for (size_t i = 0; i < data_mem_length_; i += 4096) {
              flush(data_page_ + i);
              //flush(data_page_ + i + 64);
              //flush(data_page_ + i + 128);
              //flush(data_page_ + i + 192);
            }
          } 

          if (test_case.data_page_in_tlb) {
            // access the first four cache lines of the data pages
            for (size_t i = 0; i < data_mem_length_; i += 4096) {
              maccess(data_page_ + i + (4096 - 64));
              //maccess(data_page_ + i + (4096 - 64) + 64);
              //maccess(data_page_ + i + (4096 - 64) + 128);
              //maccess(data_page_ + i + (4096 - 64) + 192);
            }
          } else {
            // flush the first four cache lines of the data pages
            for (size_t i = 0; i < data_mem_length_; i += 4096) {
              ptedit_invalidate_tlb(data_page_ + i);
            }
          } 
          SetInitialConditionsDataPage(conditions);  // restore conds
        } // if (test_case.data_page_extra_conditions)

        SetShortTermConditionsDataPage(conditions);

        // access the end of the first probe_memory address
        // to make sure it's in the TLB
        // (works because we use huge pages for the probe_memory)
        maccess(probe_memory_ + (4096 - 64));
        mfence();

        if (FatalSignalStart()) {
          // NOTE: these arguments have to match the ones in ExecuteCode
          ((void(*)(char*, char*, char*)) leakage_code_page_)(
              data_page_ + 0x80,
              data_page_second_mapping_ + 0x80,
              probe_memory_);
        } else {
          exec_results.observed_fault = true;
          exec_results.signal_number_caught = RetrieveOccuredSignal();
#ifdef ENABLE_FPVI_MITIGATION
          // we need to re-enable the FPVI mitigation as linux' signal handler
          // logic resets the MXCSR bits (which is used for the mitigation)
          EnableFPVIMitigation();
#endif
        }
      }  // for (size_t leakage_runs = 0; 

    } else {
      // the execution hit the timeout, hence we skip the instruction

      #ifdef DEBUGMODE
      UnregisterSignalHandlers();
      #endif

      LOG_DEBUG("Execution timeout exceeded!");
      exec_results.timeout_exceeded = true;

      // ATTENTION: before returning, we need to cleanup the PTE edits
      CleanupConditionsDataPage(conditions);

      return exec_results;
    }
    alarm(0);  // stop timeout again

    // note: the length of this loop is a major bottle neck
    //for (size_t i = 'A'; i < 'Z'; i++) {
    for (size_t i = 0; i < 256; i++) {
      // randomize page order to prevent prefetches of 
      // HW prefetchers that can cross page-boundaries
      size_t idx = ((i * 167u) + 13u) & 255u;
      size_t delta = flush_reload_t(probe_memory_ + idx * SPACING);
      if (delta < cache_miss_threshold) {
        cache_hits_for_idx[idx]++;
      }
    }  // for (size_t i = 0; i < 256; i++)

    if (single_core_mode) {
      // when sharing the virtual core with the victim, 
      // we want to give the victim space to run
      sched_yield();
    }
  }  // for (size_t testrun = 0; testrun < TEST_EXECUTIONS; testrun++)

  #ifdef DEBUGMODE
  UnregisterSignalHandlers();
  #endif

  Leakage byte_to_leakage;
  for (size_t i = 0; i < 256; i++) {
#ifdef ZHAOXIN
        if (i == 0) continue; // zxaoxin reports false positives for 0x00
#endif
    if (cache_hits_for_idx[i] >= 1) {

      byte_to_leakage[i] = cache_hits_for_idx[i];
    }
  }
  exec_results.leakage = byte_to_leakage;

  CleanupConditionsDataPage(conditions);
  // timeout := false
  return exec_results;
}

void Executor::CleanupAllConditionsDataPage() {
  // this is called upon exiting (normal or abnormal)
  // we need to restore every possible condition

  constexpr auto& conditions = magic_enum::enum_values<ConditionDataPage>();
  for (const auto& condition: conditions) {
    CleanupConditionsDataPage(condition);
  }
}

void Executor::SetInitialConditionsDataPage(
    const std::vector<ConditionDataPage>& conditions) {
  for (const auto& condition: conditions) {
    SetInitialConditionsDataPage(condition);
  }
}

void Executor::SetShortTermConditionsDataPage(
    const std::vector<ConditionDataPage>& conditions) {
  for (const auto& condition: conditions) {
    SetShortTermConditionsDataPage(condition);
  }
}

void Executor::CleanupConditionsDataPage(
    const std::vector<ConditionDataPage>& conditions) {
  for (const auto& condition: conditions) {
    CleanupConditionsDataPage(condition);
  }
}

void Executor::SetInitialConditionsDataPage(ConditionDataPage condition) {
  // this function is called *once* for every testcase, hence we prepare
  // conditions that are not altered by the execution of the test itself,
  // e.g., page permissions

  switch (condition) {
    case ConditionDataPage::kDefault: {
      // default does not require changes
      break;
    }
    case ConditionDataPage::kNoUserBit: {
      ptedit_pte_clear_bit(data_page_, 0, PTEDIT_PAGE_BIT_USER);
      break;
    }
    case ConditionDataPage::kNoAccessBit: {
      // nothing to do here; we need to unset that later
      break;
    }
    case ConditionDataPage::kNoPresentBit: {
      // ATTENTION: only access speculatively if we use this
      ptedit_pte_clear_bit(data_page_, 0, PTEDIT_PAGE_BIT_PRESENT);
      break;
    }
    case ConditionDataPage::kSetDirtyBit: {
      ptedit_pte_set_bit(data_page_, 0, 
        PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case ConditionDataPage::kClearDirtyBit: {
      ptedit_pte_clear_bit(data_page_, 0,       
        PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case ConditionDataPage::kSetUncacheable: {
      ptedit_entry_t page_table_entry = ptedit_resolve(data_page_, 0);
      page_table_entry.pte = ptedit_apply_mt(page_table_entry.pte, 
          encoding_uncachable_memory_type_);
      // update only PTE (lowest level of page table)
      page_table_entry.valid = PTEDIT_VALID_MASK_PTE;
      ptedit_update(data_page_, 0, &page_table_entry);

      // before we flush the page, we need to make sure that we have access to it
      bool restore_user_bit = false;
      bool restore_present_bit = false;
      if (!IsPermissionBitSet(page_table_entry, PTEDIT_PAGE_BIT_USER)) {
        restore_user_bit = true;
        ptedit_pte_set_bit(data_page_, 0, PTEDIT_PAGE_BIT_USER);
      }
      if (!IsPermissionBitSet(page_table_entry, PTEDIT_PAGE_BIT_PRESENT)) {
        restore_present_bit= true;
        ptedit_pte_set_bit(data_page_, 0, PTEDIT_PAGE_BIT_PRESENT);
      }

      // we also need to remove remaining data from the CPU cache
      for (size_t i = 0; i < kPageSize; i += 64) {
        flush(data_page_ + i);
      }
      mfence();

      if (restore_user_bit) {
        ptedit_pte_clear_bit(data_page_, 0, PTEDIT_PAGE_BIT_USER);
      }
      if (restore_present_bit) {
        ptedit_pte_clear_bit(data_page_, 0, PTEDIT_PAGE_BIT_PRESENT);
      }

      break;
    }
    case ConditionDataPage::kUnmaskFpFaults: {
      // we unmask all potential floating point errors by clearing 
      // the masking bits in MXCSR. We further keep track of the prev. value
      // TODO(dwe): this currently leads to false positives in the executor, which we throw away 
      //  in the clustering.
      if (original_mxcsr_value_ == -1u) {
        original_mxcsr_value_ = _mm_getcsr();
      }
      // ~0x1f80 clears bits 7-12 (the Intel MXCSR fault masking bits)
      _mm_setcsr(original_mxcsr_value_ & ~0x1f80);
      break;
    }
    default:
      throw std::runtime_error("Unspecified data page condition used!");
  }
}

void Executor::SetShortTermConditionsDataPage(ConditionDataPage condition) {
  // this is called *before every* execution of the leakage_code;
  // we use it for volatile conditions, e.g., unsetting the ACCESS bit

  switch (condition) {
    case ConditionDataPage::kDefault: {
      // default does not require changes
      break;
    }
    case ConditionDataPage::kNoUserBit: {
      // nothing to do here
      break;
    }
    case ConditionDataPage::kNoAccessBit: {
      ptedit_pte_clear_bit(data_page_, 0, PTEDIT_PAGE_BIT_ACCESSED);
      break;
    }
    case ConditionDataPage::kNoPresentBit: {
      // nothing to do here
      break;
    }
    case ConditionDataPage::kSetDirtyBit: {
      ptedit_pte_set_bit(data_page_, 0,
        PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case ConditionDataPage::kClearDirtyBit: {
      ptedit_pte_clear_bit(data_page_, 0,
        PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case ConditionDataPage::kSetUncacheable: {
      // nothing to do here
      break;
    }
    case ConditionDataPage::kUnmaskFpFaults: {
      // nothing to do here
      break;
    }
    default:
      throw std::runtime_error("Unspecified data page condition used!");
  }
}

void Executor::CleanupConditionsDataPage(ConditionDataPage condition) {
  // this is called *after* the entire testcase;
  // we use it cleanup conditions, like page permissions, to not interfer
  // with further runs

  switch (condition) {
    case ConditionDataPage::kDefault: {
      // default does not require changes
      break;
    }
    case ConditionDataPage::kNoUserBit: {
      ptedit_pte_set_bit(data_page_, 0, PTEDIT_PAGE_BIT_USER);
      break;
    }
    case ConditionDataPage::kNoAccessBit: {
      // nothing to cleanup
      break;
    }
    case ConditionDataPage::kNoPresentBit: {
      ptedit_pte_set_bit(data_page_, 0, PTEDIT_PAGE_BIT_PRESENT);
      break;
    }
    case ConditionDataPage::kSetDirtyBit: {
      ptedit_pte_clear_bit(data_page_, 0, PTEDIT_PAGE_BIT_DIRTY);
      break;
    }
    case ConditionDataPage::kClearDirtyBit: {
      // nothing to cleanup
      break;
    }
    case ConditionDataPage::kSetUncacheable: {
      ptedit_entry_t page_table_entry = ptedit_resolve(data_page_, 0);
      page_table_entry.pte = ptedit_apply_mt(page_table_entry.pte, 
          encoding_writeback_memory_type_);
      // update only PTE (lowest level of page table)
      page_table_entry.valid = PTEDIT_VALID_MASK_PTE;
      ptedit_update(data_page_, 0, &page_table_entry);
      break;
    }
    case ConditionDataPage::kUnmaskFpFaults: {
      // we restore the original masking flags
      _mm_setcsr(original_mxcsr_value_);
      break;
    }
    default:
      throw std::runtime_error("Unspecified data page condition used!");
  }
}


}  // namespace trevex
