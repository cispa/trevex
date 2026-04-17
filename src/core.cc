// Copyright [2026] <Daniel Weber>

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <vector>

#include <sys/mman.h>

#include "external/magic_enum/magic_enum.hpp"
#include "cacheutils/cacheutils.h"
#include "logger/logger.h"
#include "utils.h"
#include "config.h"
#include "victims/victim.h"
#include "victims/kernel_victim.h"

#include "core.h"

namespace asm86 = asmjit::x86;

namespace trevex {


Core::Core() : single_core_mode_(false), cache_miss_threshold_(-1) {

  // create results directory
  if (!std::filesystem::exists(RESULTS_FOLDER)) {
    int created = std::filesystem::create_directory(RESULTS_FOLDER);
    if (!created) {
      throw std::runtime_error("Could not create results directory!");
    }
  }
#ifdef ENABLE_CROSS_CORE_LEAKAGE_TESTING
  if (EXECUTOR_MAIN_CORE == 0) {
    victim_cpu_core_ = 1;
  } else {
    victim_cpu_core_ = EXECUTOR_MAIN_CORE - 1;
  }
#else // ENABLE_CROSS_CORE_LEAKAGE_TESTING
  victim_cpu_core_ = GetSiblingHyperthread(EXECUTOR_MAIN_CORE);
  if (victim_cpu_core_ == -1) {
    LOG_WARNING("Could not determine sibling core for Core " 
        + std::to_string(EXECUTOR_MAIN_CORE) + ". Defaulting to Core "
        + std::to_string(EXECUTOR_FALLBACK_SIBLING_CORE) + "!");
    victim_cpu_core_ = EXECUTOR_FALLBACK_SIBLING_CORE;
    single_core_mode_ = true;
  }
#endif // ENABLE_CROSS_CORE_LEAKAGE_TESTING
  LOG_INFO("Executing attacker on " + std::to_string(EXECUTOR_MAIN_CORE));
  LOG_INFO("Executing victim on " + std::to_string(victim_cpu_core_));
}

void Core::StartFuzzing(const FuzzingConfig& fuzzing_config) {

#ifdef ENABLE_FPVI_MITIGATION
  // we enable the actual mitigation inside the executor 
  // as it requires restoring after signal handling
  LOG_INFO("Fuzzing with enabled FPVI mitigation.");
#endif

  std::vector<Instruction> instructions = ReadInstructionFile(
      fuzzing_config.instruction_list);
  

  size_t instructions_total = instructions.size();

  // load saved progress and remove already processed instructions
  size_t finished_instructions = LoadProgressFromDisk();
  if (finished_instructions > instructions.size()) {
    LOG_WARNING("Mismatch of stored progress and loaded instruction.");
    return;
  }
  
  // we remove everything that we already processed
  // note that the TestCaseGenerator requires *all* instructions
  instructions.erase(instructions.begin(),
      instructions.begin() + finished_instructions);

  // prepare testcase generator for the fuzzing run
  testcase_generator_.LoadInstructionList(instructions);

  int64_t last_timestamp = GetTimestampMS();
  uint64_t tests_executed = 0;
  for (const auto& instruction : instructions) {
    double progress = ((double)finished_instructions / (double)instructions_total)
         * 100;
    LOG_INFO(std::to_string(progress) + "% -> Testing " + instruction.mnemonic);

    RunRandomTestsForInstruction(instruction, instructions);

    // bookkeep progress
    finished_instructions++;
    tests_executed += RANDOM_VICTIMS * RANDOM_ATTACKERS_PER_VICTIM * TEST_EXECUTIONS;

    // calc + print throughput
    int64_t new_timestamp = GetTimestampMS();
    int64_t time_diff = new_timestamp - last_timestamp;
    if (tests_executed > 1000000) {
      // every 10mio tests, we reset our counters to prevent overflows
      last_timestamp = new_timestamp;
      tests_executed = 0;
    }
    double throughput = (double)tests_executed / ((double)time_diff / 1000.0);
    LOG_INFO("Running with " + std::to_string(throughput) + " tests/s");


    SaveProgressToDisk(finished_instructions);
  }
}

std::vector<uint8_t> Core::ExtractUniquePeaks(
    std::vector<std::vector<uint8_t>> stable_peaks_per_taint, size_t max_occurrence) {
  std::vector<uint8_t> unique_peaks;
  for (const auto& peak_list : stable_peaks_per_taint) {
    for (const auto& peak : peak_list) {
      // count in how many lists this peak occurs
      size_t count = 0;
      for (const auto& other_peak_list : stable_peaks_per_taint) {
        if (std::find(other_peak_list.begin(), other_peak_list.end(), peak) 
            != other_peak_list.end()) {
          count++;
        }
      }
      if (count <= max_occurrence) {
        // only contained in one list, so we can add it
        if (std::find(unique_peaks.begin(), unique_peaks.end(), peak) 
            == unique_peaks.end()) {
          unique_peaks.push_back(peak);
        }
      }
    }
  }
  return unique_peaks;
}

std::vector<uint8_t> Core::MergeIntoStablePeaks(
  std::vector<std::vector<uint8_t>>& list_of_peak_lists) {
  // allow for a stable peak if it occurs in at least N% of the lists
  size_t threshold = CORRELATION_STABLE_PEAK_TOLERENCE * list_of_peak_lists.size();
  std::vector<uint8_t> stable_peaks;
  for (const auto& peak_list : list_of_peak_lists) {
    for (const auto& peak : peak_list) {
      size_t count = 0;
      for (const auto& other_peak_list : list_of_peak_lists) {
        if (std::find(other_peak_list.begin(), other_peak_list.end(), peak) 
            != other_peak_list.end()) {
          count++;
        }
      }
      if (count >= threshold && 
          std::find(stable_peaks.begin(), stable_peaks.end(), peak) 
          == stable_peaks.end()) {
        stable_peaks.push_back(peak);
      }
    }
  }
  return stable_peaks;
}

std::vector<uint8_t> Core::ExtractPeaks(const Leakage& leakage) {
  std::vector<uint8_t> peaks;
  for (const auto& e : leakage) {
    if (e.second >= NOISE_IGNORE_THRESHOLD) {
      peaks.push_back(e.first);
    }
  }
  return peaks;
}

[[nodiscard]]
TestTaintDependencyResult Core::TestTaintDependency(const TestCase& test_case) {
  LOG_INFO("Starting taint dependency test...");
  // idea: 
  // - take N different taints, for each taint, execute M test cases
  // - check if leakage differs per taint but stays similar for the same taint
  std::vector<char> potential_taints = {'V', 'W', 'X', 'Y', 'Z'};

  // TODO: reordering these loops might lead to better results
  //       but kills our performance
  std::vector<std::vector<uint8_t>> stable_peaks_per_taint;
  
  // we use this structure to dump the results for additional analysis later on
  std::map<char, std::vector<std::vector<uint8_t>>> taint_to_peaklists;
  for (const char taint_value : potential_taints) {
    std::stringstream msg;
    msg << "Victim taint: 0x" << std::hex << (unsigned int)taint_value << std::dec;
    msg << " ('" << (char)taint_value << "')";
    LOG_INFO(msg.str());

#ifdef VICTIM_CONTEXT_KERNEL
    KernelVictim kernel_victim_context(test_case.victim_code, (char)taint_value);
    Victim& victim_context = kernel_victim_context;
#endif
    victim_context.Start(victim_cpu_core_);

    std::vector<std::vector<uint8_t>> list_of_peak_lists;
    for (size_t i = 0; i < CORRELATION_REPETITIONS_PER_TAINT; i++) {

      ExecutionResults exec_results = executor_.ExecuteTestcase(
          test_case, 
          single_core_mode_,
          DATA_PAGE_CONTENT,
          TEST_EXECUTIONS);
      if (exec_results.timeout_exceeded) {
        LOG_WARNING("Timeout exceeded during taint dependency test!");
        TestTaintDependencyResult empty_result;
        empty_result.taint_dependency = TaintDependency::kUnconfirmed;
        return empty_result;
      }
      std::vector<uint8_t> peak_list = ExtractPeaks(exec_results.leakage);
      list_of_peak_lists.push_back(peak_list);
      taint_to_peaklists[taint_value].push_back(peak_list);
    }
    victim_context.Shutdown();
    std::vector<uint8_t> stable_peaks = MergeIntoStablePeaks(list_of_peak_lists);
    stable_peaks_per_taint.push_back(stable_peaks);
  }  // for (const char taint_value : potential_taints)
  // TODO(dwe): the uniqueness constraint could be relaxed by allowing a peak to be in at most N lists
  std::vector<uint8_t> unique_peaks = ExtractUniquePeaks(stable_peaks_per_taint, 1);
  LOG_DEBUG("Unique peaks: ");
  for (const auto& e : unique_peaks) {
    LOG_DEBUG("Unique Peak: 0x" + std::to_string(e) + " ('" + std::string(1, e) + "')");
  }

  size_t identifiable_taints = 0;
  for (const auto& stable_peaks : stable_peaks_per_taint) {
    for (const auto& peak : stable_peaks) {
      if (std::find(unique_peaks.begin(), unique_peaks.end(), peak) 
          != unique_peaks.end()) {
        // we found the taint in unique peaks, thus it's identifiable
        identifiable_taints++;
        // do not further increase the count for this taint
        break;
      }
    }  // for (const auto& peak : stable_peaks)
  }  // for (const auto& stable_peaks : stable_peaks_per_taint)

  TestTaintDependencyResult result;
  result.taint_to_peaklists = taint_to_peaklists;
  if (identifiable_taints >= potential_taints.size() * TAINT_DEPENDENCY_RATIO) {
    result.taint_dependency = TaintDependency::kConfirmed;
  } else  {
    result.taint_dependency = TaintDependency::kUnconfirmed;
  }
  return result;
}

void Core::ReproduceResult(const std::string& fname_result) {
  std::ifstream fs(fname_result);
  if (!fs.is_open()) {
    throw std::runtime_error("Could not open testcase.");
    return;
  }

  // read testcase from file
  std::stringstream file_content;
  file_content << fs.rdbuf();
  TestCase test_case(file_content.str());
  fs.close();

#ifdef VICTIM_CONTEXT_KERNEL
  KernelVictim kernel_victim_context(test_case.victim_code);
  Victim& victim_context = kernel_victim_context;
#endif
  victim_context.Start(victim_cpu_core_);

  // we update the cache_miss threshold as it might be different now
  test_case.cache_miss_threshold = detect_flush_reload_threshold();
  LOG_INFO("Cache miss threshold: " 
      + std::to_string(test_case.cache_miss_threshold));

  ExecutionResults exec_results = executor_.ExecuteTestcase(test_case, 
      single_core_mode_);
  test_case.observed_fault = exec_results.observed_fault;
  test_case.observed_leakage = exec_results.leakage;
  test_case.signal_number_caught = exec_results.signal_number_caught;
  LOG_DEBUG("Testcase finished...");

  if (exec_results.timeout_exceeded) {
    LOG_INFO("Skipping instruction due to timeout exceedance.");
    victim_context.Shutdown();
    return;
  }

  if (IsInterestingLeakage(&test_case, exec_results.leakage)) {
    // before logging, we check whether we only forwarded zeroes.

    InstrInputOutputMapping input_mapping = 
        TraceLeakageInput(test_case, test_case.architectural_leakage_code);
    test_case.input_mapping = input_mapping;

    LOG_WARNING("FOUND LEAKAGE");
    PrintLeakage(exec_results.leakage, input_mapping);

#ifdef ENABLE_TAINT_DEPENDENCY_TESTING
    TestTaintDependencyResult taint_dependency_result = TestTaintDependency(test_case);
    test_case.taint_dependency = taint_dependency_result.taint_dependency;
    test_case.taint_to_peaklists = taint_dependency_result.taint_to_peaklists;
#endif

  } else { // if (IsInterestingLeakage(&test_case, exec_results.leakage))
    LOG_INFO("No interesting leakage observed for this instruction.");
  }

  WriteTestCaseToDisk(fname_result, test_case, false);
}

void Core::ReproduceTaintDependency(const std::string& fname_result) {
  std::ifstream fs(fname_result);
  if (!fs.is_open()) {
    throw std::runtime_error("Could not open testcase.");
    return;
  }

  // read testcase from file
  std::stringstream file_content;
  file_content << fs.rdbuf();
  TestCase test_case(file_content.str());
  fs.close();

  // we update the cache_miss threshold as it might be different now
  test_case.cache_miss_threshold = detect_flush_reload_threshold();
  LOG_INFO("Cache miss threshold: " 
      + std::to_string(test_case.cache_miss_threshold));

  TestTaintDependencyResult taint_dependency_result = TestTaintDependency(test_case);
  test_case.taint_dependency = taint_dependency_result.taint_dependency;
  test_case.taint_to_peaklists = taint_dependency_result.taint_to_peaklists;

  WriteTestCaseToDisk(fname_result, test_case, false);
}

uint64_t Core::RetrieveOriginalRegisterValue(const TestCase& test_case) {
  ByteArray recovery_code = testcase_generator_.CreateRegisterRecoveryCode(
      test_case);
  return executor_.ExecuteCode(recovery_code);
}

bool Core::IsInterestingLeakage(TestCase* test_case,
     const Leakage& leakage) {

  // basically, we test for one of the following conditions
  // - we see atleast *two* strong peaks
  //   -> this hints towards a transient path differing from an arch. path 
  // - we see a single peak 
  //   + a fault + the register holding the peak has changed its value

  if (leakage.empty()) {
    return false;
  }

  int number_of_peaks = 0;
  for (const auto& e : leakage) {
    if (e.second >= NOISE_IGNORE_THRESHOLD) {
      number_of_peaks++;
    }
  }
  LOG_DEBUG("Res: Number of peaks: " + std::to_string(number_of_peaks));
  LOG_DEBUG("Res: fault observed: " + std::to_string(test_case->observed_fault));

  // log the original value of the register for post processing
  uint64_t original_value = RetrieveOriginalRegisterValue(*test_case);
  test_case->original_register_value = original_value;

  if (number_of_peaks >= 2) {
    // at least 2 peaks -> hinting towards transient + arch. path
    // -> interesting
    return true;
  }

  if (number_of_peaks < 1) {
    // no peaks -> no leakage
    return false;
  }
  
  assert(EXECUTE_ATTACKER_ARCHITECTURALLY);
  if (test_case->observed_fault == false) {
    // early exit for performance reasons
    return false;
  }

  bool register_has_changed = false;
  for (const auto& e : leakage) {
    // note that we truncate the register down to a single byte
    if (e.second >= NOISE_IGNORE_THRESHOLD && e.first != (original_value & 0xff)) {
      LOG_DEBUG("Register content has changed from " + 
          std::to_string(original_value & 0xff) + 
          " to " + std::to_string(e.first));
      register_has_changed = true;
    }
  }

  return register_has_changed && test_case->observed_fault;
}

void Core::PrintLeakage(const Leakage& leakage) {
  InstrInputOutputMapping empty;
  PrintLeakage(leakage, empty);
}

void Core::PrintLeakage(const Leakage& leakage, 
    const InstrInputOutputMapping& input_mapping) {
  std::cout << " ============ Leakage =========== " << std::endl;
  for (const auto& e : leakage) {
    std::cout << " 0x" << std::hex << (int)e.first << std::dec
        << " ('" << e.first << "') ";
        
    // add traced value if found
    auto io_pair = input_mapping.find(e.first);
    // the number of hits
    std::cout << " -> " << e.second;

    if (io_pair != input_mapping.end()) {
      std::cout << "    <input: 0x" << std::hex << (int)io_pair->second << std::dec
          << " ('" << io_pair->second << "')>";
    }
    std::cout << std::endl;
  }
  std::cout << " ================================ " << std::endl;
}

void Core::SaveProgressToDisk(size_t tested_instructions) {
  std::ofstream fs(PROGRESS_FILE);
  if (!fs.is_open()) {
    LOG_WARNING("Could not save progress.");
  }
  fs << tested_instructions;
  fs.close();
}

size_t Core::LoadProgressFromDisk() {
  std::ifstream fs(PROGRESS_FILE);
  if (!fs.is_open()) {
    LOG_INFO("No progress loaded.");
    return 0;
  }
  size_t saved_progress = 0;
  fs >> saved_progress;
  LOG_INFO("Loaded progress: Skipping "
      + std::to_string(saved_progress) + " instructions.");
  fs.close();
  return saved_progress;
}


std::vector<Instruction> Core::ReadInstructionFile(
    const std::string& filename) {
  std::ifstream instruction_fstream(filename);
  if (!instruction_fstream.is_open()) {
    throw std::runtime_error("Could not open instruction file (" + filename + ")!");
  }

  std::string line;
  // check header for correctness
  std::getline(instruction_fstream, line);
  if (line != "byte_representation;assembly_code;category;extension;isa_set(;precondition)*") {
    LOG_ERROR("Got header: " + line);
    throw std::runtime_error("Header mismatch in instruction file.");
  }

  std::vector<Instruction> loaded_instructions;

  while (std::getline(instruction_fstream, line)) {
    Instruction instruction = ParseInstructionFileEntry(line);
    loaded_instructions.push_back(instruction);
  }

  return loaded_instructions;
}

Instruction Core::ParseInstructionFileEntry(const std::string& entry) {
  std::vector<std::string> line_splitted = 
      SplitString(entry, ';');
  if (line_splitted.size() < 5) {
    throw std::runtime_error("Mismatch of line format in instruction file.");
  }
  Instruction instruction;
  instruction.bytes = base64_decode(line_splitted[0]);
  instruction.mnemonic = line_splitted[1];

  // [2,3,4] are category;extension;isa_set
  instruction.category = line_splitted[2];
  instruction.extension = line_splitted[3];
  instruction.isa_set = line_splitted[4];
  // [5...] are the preconditions, we need to parse these again
  for (auto iter = line_splitted.begin() + 5; 
      iter != line_splitted.end(); iter++) {
    // TODO: think of a format and add it and test on LAB12
    // e.g., rax, 0xdeadbeef
    //std::cout << "precond: " << *iter << std::endl;
  }
  return instruction;
}


void Core::WriteTestCaseToDisk(const std::string& filename,
    const TestCase& test_case, bool in_results_folder) {
  std::stringstream fname;
  if (in_results_folder) {
    fname << RESULTS_FOLDER << "/" << filename << ".json";
  } else {
    fname << filename;
  }
  std::ofstream fstream(fname.str());
  
  if (!fstream.is_open()) {
    LOG_ERROR("Could not open file for writing: " + fname.str());
    throw std::runtime_error("Could not write test case to disk");
  }
  fstream << test_case.Serialize();
  fstream.close();
}

bool Core::IsSameLeakage(const Leakage& leakage1, const Leakage& leakage2) {
  // we check whether we always leak the same indices, if yes, the leakage 
  // pattern is the same (even though the leakage rate may not be)
  return leakage1.size() == leakage2.size() && std::equal(
    leakage1.begin(), leakage1.end(), leakage2.begin(),
    [] (auto l1, auto l2) {
      return l1.first == l2.first;
    }
  );
}

InstrInputOutputMapping Core::TraceLeakageInput(
    const TestCase& test_case,
    const ByteArray& architecturally_executed_code) {
  // the idea is that we execute the instruction architecturally with
  // a set of possible values. the one matching our original input is 
  // what we actually leaked during the fault
  
  // create the architecturally executable testcase
  TestCase arch_test_case = test_case;
  arch_test_case.leakage_code = architecturally_executed_code;

  InstrInputOutputMapping mapping;
  Leakage leakage = test_case.observed_leakage;
  for ([[maybe_unused]] const auto& entry : leakage) {
    for (uint8_t input_guess : kInterestingInputsToTrace) {
      // execute instruction with potential input
      ExecutionResults exec_results = executor_.ExecuteTestcase(
          arch_test_case, 
          single_core_mode_, 
          input_guess, 
          1);

      for (const auto& arch_res : exec_results.leakage) {
        uint8_t arch_val = arch_res.first;
        const auto& leakage_match = leakage.find(arch_val);
        if (leakage_match != leakage.end()) {
          // this value was leaked
          // needs to map output to input
          mapping.insert({leakage_match->first, input_guess});
        }
      }
    }
  }
  return mapping;
}

void Core::RunRandomTestsForInstruction(const Instruction& instruction,
    const std::vector<Instruction>& complete_instruction_list) {
  
  size_t reported_cases = 0;

  for (size_t tests_per_victim = 0; 
      tests_per_victim < RANDOM_VICTIMS; tests_per_victim++) {
    // startoff by picking a victim -> this allows to reuse the same victim

    TestCase test_case_victim_only = testcase_generator_.CreateNewTestcase(
        instruction, cache_miss_threshold_);

    // create the victim
    
#ifdef VICTIM_CONTEXT_KERNEL
    KernelVictim kernel_victim_context(test_case_victim_only.victim_code);
    Victim& victim_context = kernel_victim_context;
#endif
    victim_context.Start(victim_cpu_core_);

    // reason behind putting it here is that different victim loads lead to 
    // different thresholds
    cache_miss_threshold_ = detect_flush_reload_threshold() + 10;
    LOG_DEBUG("Cache threshold: " + std::to_string(cache_miss_threshold_));
    if (cache_miss_threshold_ > 250) {
      size_t adjusted_threshold = cache_miss_threshold_ - 50;
#ifdef ZHAOXIN
      adjusted_threshold = 150;
#endif
      LOG_INFO("Cache miss threshold is rather high (could lead to false positives): " 
          + std::to_string(cache_miss_threshold_)
          + ". Adjusted to " + std::to_string(adjusted_threshold));
      cache_miss_threshold_ = adjusted_threshold;
    }

    // generate random attackers and test them
    for (int attacker_try = 0; attacker_try < RANDOM_ATTACKERS_PER_VICTIM; 
        attacker_try++) {

      //
      // randomly generate the attacker
      //
      TestCase test_case = testcase_generator_.CreateNewTestcase(
        instruction, cache_miss_threshold_);
      test_case.cache_miss_threshold = cache_miss_threshold_;
      // copy over the victim code
      test_case.victim_code = test_case_victim_only.victim_code;

      // log for debugging purposes
      WriteTestCaseToDisk(std::string("current_testcase"), test_case);

      LOG_DEBUG("Executing Testcase...");
      ExecutionResults exec_results = executor_.ExecuteTestcase(test_case, 
          single_core_mode_);
      test_case.observed_fault = exec_results.observed_fault;
      test_case.observed_leakage = exec_results.leakage;
      test_case.signal_number_caught = exec_results.signal_number_caught;
      LOG_DEBUG("Testcase finished...");

      if (exec_results.timeout_exceeded) {
        LOG_INFO("Skipping instruction due to timeout exceedance.");
        victim_context.Shutdown();
        return;
      }

      if (IsInterestingLeakage(&test_case, exec_results.leakage)) {

        // before logging, we check whether we only forwarded zeroes.

        std::stringstream fname;
        fname << ReplaceChar(ReplaceChar(
            instruction.mnemonic, '/', '_'),
            ' ', '_');
        fname << "_" << std::to_string(reported_cases);

        InstrInputOutputMapping input_mapping = 
            TraceLeakageInput(test_case, test_case.architectural_leakage_code);
        test_case.input_mapping = input_mapping;

        LOG_WARNING("FOUND LEAKAGE for " + instruction.mnemonic);
        LOG_WARNING("File: \"" + fname.str() + ".json\"");
        PrintLeakage(exec_results.leakage, input_mapping);

#ifdef ENABLE_TAINT_DEPENDENCY_TESTING
        TestTaintDependencyResult taint_dependency_result = TestTaintDependency(test_case);
        test_case.taint_dependency = taint_dependency_result.taint_dependency;
        test_case.taint_to_peaklists = taint_dependency_result.taint_to_peaklists;
#endif

        WriteTestCaseToDisk(fname.str(), test_case);
        reported_cases++;

      }  // if (IsInterestingLeakage(&test_case, exec_results.leakage))

    } // for (int attacker_try = 0; attacker_try < ...
    victim_context.Shutdown();

  }  // for (size_t tests_per_victim = 0; number_of_tests ...
}

}  // namespace trevex
