// Copyright [2026] <Daniel Weber>

#ifndef EXECUTOR_H_
#define EXECUTOR_H_

#include <cstdint>
#include <atomic>
#include <mutex>
#include <thread>
#include <map>
#include <tuple>
#include <vector>

#include "signal.h"
#include "config.h"
#include "common.h"

#include "external/json.hpp"
#include "testcase_generator.h"

namespace trevex {

constexpr uint64_t kDataMemoryBegin = 0x13370000;
constexpr char kShmName[] = "/TVX_SHM_M4G1CNVM";

struct ExecutionResults {
  Leakage leakage;
  bool observed_fault;
  bool timeout_exceeded;
  int signal_number_caught;
};


class Executor {
 public:
  Executor();
  ~Executor();
  ExecutionResults ExecuteTestcase(const TestCase& test_case, 
      bool single_core_mode,
      uint8_t data_page_content,
      size_t number_of_executions);
  ExecutionResults ExecuteTestcase(const TestCase& test_case, 
      bool single_core_mode,
      uint8_t data_page_content);
  ExecutionResults ExecuteTestcase(const TestCase& test_case, 
      bool single_core_mode);
  // this just directly executes the given code and returns it result
  // we use this to extract the value of registers before any attacker shenanigans
  uint64_t ExecuteCode(const ByteArray& code);
 private:
  pid_t main_process_;
  void CreateDataMappings();

  void CleanupAllConditionsDataPage();
  void SetInitialConditionsDataPage(ConditionDataPage conditions);
  void SetInitialConditionsDataPage(
    const std::vector<ConditionDataPage>& conditions);
  void SetShortTermConditionsDataPage(ConditionDataPage condition);
  void SetShortTermConditionsDataPage(
    const std::vector<ConditionDataPage>& conditions);
  void CleanupConditionsDataPage(ConditionDataPage condition);
  void CleanupConditionsDataPage(
    const std::vector<ConditionDataPage>& conditions);

  // these two are used for PTEditor
  int encoding_uncachable_memory_type_;
  int encoding_writeback_memory_type_;


  char* leakage_code_page_;
  char* data_page_;
  char* data_page_second_mapping_;
  size_t data_mem_length_;
  size_t data_page_second_mapping_original_pfn_;
  unsigned int original_mxcsr_value_ = -1;
  char* victim_code_page_;
  char* victim_data_page_;

  char* probe_memory_;
};

}  // namespace trevex

#endif // EXECUTOR_H_
