// Copyright [2026] <Daniel Weber>

#ifndef CONFIG_H
#define CONFIG_H

#include <cstdint>
#include <cassert>
#include <array>

#define HLT_INSTRUCTION '\xf4'
#define RET_INSTRUCTION '\xc3'
#define SPACING 4096
#define OFFSET_FOR_UNALIGNED_PTR 3
#define STACK_SIZE_VICTIM 8192

#define EXECUTOR_MAIN_CORE 1
#define EXECUTOR_FALLBACK_SIBLING_CORE 1

#define TEST_EXECUTIONS 100

#define EXECUTION_TIMEOUT_SECONDS 5

// used to switch between different implementations of the duplicate mapping
#define DUPLICATE_MAPPING_IMPLEMENTATION_PTEDITOR
//#define DUPLICATE_MAPPING_IMPLEMENTATION_SHM

// enables FPVI mitigation
//#define ENABLE_FPVI_MITIGATION

// turn on cross-core leakage testing
//#define ENABLE_CROSS_CORE_LEAKAGE_TESTING

// we always pick the *same* instruction for shadowing if enabled
#define STRICT_SIMILARITY_FOR_INSTR_SHADOWING

// enables Taint Dependency testing
#define ENABLE_TAINT_DEPENDENCY_TESTING
// define how many percent (80% -> 0.8) of the taints must be identifiable
// to confirm taint dependency
#define TAINT_DEPENDENCY_RATIO 0.8
static_assert(TAINT_DEPENDENCY_RATIO > 0.0 && TAINT_DEPENDENCY_RATIO <= 1.0, 
    "TAINT_DEPENDENCY_RATIO must be in (0.0, 1.0]!");

#define LEAKAGE_RUNS_PER_TEST_EXEC 100 

// we ignore leakage below this threshold as its likely just noise
#define NOISE_IGNORE_THRESHOLD (TEST_EXECUTIONS / 50)

// enable kernel victim
#define VICTIM_CONTEXT_KERNEL

// ATTENTION: with the need to check for faults, we cannot set this to false any longer
#define EXECUTE_ATTACKER_ARCHITECTURALLY true

// parameters for random test execution
#define RANDOM_VICTIMS 10
#define RANDOM_ATTACKERS_PER_VICTIM 10
#define NUMBER_OF_EMITTED_VICTIM_INSTRUCTIONS 1

#define TAINT_VALUE 'V'
#define DATA_PAGE_CONTENT 'D'
#define PROBE_PAGE_CONTENT 'P'

static constexpr std::array<uint8_t, 6> kInterestingInputsToTrace = {
  'P',
  'S',
  DATA_PAGE_CONTENT,
  TAINT_VALUE,
  'X',
  0x00
};

// how often do we test the same taint for the correlation check
#define CORRELATION_REPETITIONS_PER_TAINT 5

// how often we require a peak to be seen to be stable (in percent, e.g., 0.8 = 80%)
#define CORRELATION_STABLE_PEAK_TOLERENCE 0.8

//
// sanity checks
//

#ifdef DUPLICATE_MAPPING_IMPLEMENTATION_SHM
  #ifdef DUPLICATE_MAPPING_IMPLEMENTATION_PTEDITOR
    #error "You must not select both Duplicate Mapping implementations at the same time!"
  #endif
#endif

#ifndef DUPLICATE_MAPPING_IMPLEMENTATION_SHM
  #ifndef DUPLICATE_MAPPING_IMPLEMENTATION_PTEDITOR
    #error "You must select at least one Duplicate Mapping implementation!"
  #endif
#endif

#endif /* !CONFIG_H */
