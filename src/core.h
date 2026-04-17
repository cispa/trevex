// Copyright [2026] <Daniel Weber>

#ifndef CORE_H_
#define CORE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "common.h"
#include "utils.h"
#include "executor.h"
#include "testcase_generator.h"

namespace trevex {

#define RESULTS_FOLDER "./results"
#define PROGRESS_FILE "./.trevex.progress"

struct FuzzingConfig {
  std::string instruction_list;
};

struct TestTaintDependencyResult {
  TaintDependency taint_dependency;
  TaintToPeakLists taint_to_peaklists;
};

class Core {
 public:
  Core();
  void StartFuzzing(const FuzzingConfig& fuzzing_config);
  void ReproduceResult(const std::string& fname_result);
  void ReproduceTaintDependency(const std::string& fname_result);

 private:
  std::vector<uint8_t> ExtractUniquePeaks(std::vector<std::vector<uint8_t>> stable_peaks_per_taint, 
    size_t max_occurrence);
  std::vector<uint8_t> ExtractPeaks(const Leakage& leakage);
  std::vector<uint8_t> MergeIntoStablePeaks(
    std::vector<std::vector<uint8_t>>& list_of_peak_lists);
  TestTaintDependencyResult TestTaintDependency(const TestCase& test_case);
  bool IsInterestingLeakage(TestCase* test_case, const Leakage& leakage);
  uint64_t RetrieveOriginalRegisterValue(const TestCase& test_case);
  //bool IsInterestingLeakage(const InstrInputOutputMapping& leakage);
  void PrintLeakage(const Leakage& leakage);
  void PrintLeakage(const Leakage& leakage,
      const InstrInputOutputMapping& input_mapping);
  void SaveProgressToDisk(size_t tested_instructions);
  size_t LoadProgressFromDisk();
  std::vector<Instruction> ReadInstructionFile(const std::string& filename);
  Instruction ParseInstructionFileEntry(const std::string& entry);
  void WriteTestCaseToDisk(const std::string& filename,
      const TestCase& test_case, bool in_results_folder = true);
  InstrInputOutputMapping TraceLeakageInput(const TestCase& test_case, 
      const ByteArray& architecturally_executed_code);
  bool IsSameLeakage(const Leakage& leakage1, const Leakage& leakage2);
  void RunRandomTestsForInstruction(
    const Instruction& instruction,
    const std::vector<Instruction>& complete_instruction_list);
  ByteArray ExtractAssemblyCodeAndClear();
  void EmitPreconditionCode(const std::vector<Precondition>& preconditions);
  ByteArray CreateVictimCode(
      bool read_memory,
      bool write_memory,
      bool flush_memory,
      bool taint_registers_with_data,
      bool exec_instr_architecturally,
      const ByteArray& instruction_to_execute);
  // inner runtime
  int victim_cpu_core_;
  bool single_core_mode_;

  // inner fuzzing state
  Executor executor_;
  size_t cache_miss_threshold_;
  TestCaseGenerator testcase_generator_;

};

}  // namespace trevex

#endif // CORE_H_
