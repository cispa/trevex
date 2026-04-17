// Copyright [2026] <Daniel Weber>

#ifndef TESTCASE_GENERATOR_H_
#define TESTCASE_GENERATOR_H_

// ignore pedantic warnings from AsmJit (they bloat our output)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <asmjit/asmjit.h>
#pragma GCC diagnostic pop

#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include <signal.h>

// ignore pedantic warnings from AsmJit (they bloat our output)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <asmjit/asmjit.h>
#pragma GCC diagnostic pop


#include "config.h"
#include "common.h"
#include "utils.h"
#include "common.h"
#include "external/json.hpp"


namespace asm86 = asmjit::x86;

namespace trevex {

using TaintToPeakLists = std::map<char, std::vector<std::vector<uint8_t>>>;

struct TestCase {
  ByteArray leakage_code;
  ByteArray architectural_leakage_code; // TODO: obsolete?
  ByteArray attacker_instruction;
  ByteArray state_before_load;
  ByteArray victim_code;
  asm86::Reg register_to_encode;  // attention: this is not in the JSON
  std::vector<ConditionDataPage> data_conditions;
  uint64_t original_register_value;
  size_t register_byte_position;
  bool data_page_extra_conditions;
  bool data_page_in_cache;
  bool data_page_in_tlb;

  // after execution
  size_t cache_miss_threshold;
  Leakage observed_leakage;
  Leakage observed_zero_leakage;
  InstrInputOutputMapping input_mapping;
  bool observed_fault;
  int signal_number_caught;
  TaintDependency taint_dependency;
  TaintToPeakLists taint_to_peaklists;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(TestCase,
    leakage_code,
    architectural_leakage_code,
    state_before_load,
    attacker_instruction,
    victim_code,
    //register_to_encode, 
    data_conditions,
    original_register_value,
    register_byte_position,
    data_page_extra_conditions,
    data_page_in_cache,
    data_page_in_tlb,

    cache_miss_threshold,
    observed_leakage,
    observed_zero_leakage,
    input_mapping,
    observed_fault,
    signal_number_caught,
    taint_dependency,
    taint_to_peaklists);
  
TestCase() = default;
explicit TestCase(const std::string& serialized_str) {
  nlohmann::json serialized = nlohmann::json::parse(serialized_str);
  from_json(serialized, *this);
}

[[nodiscard]] std::string Serialize() const {
  nlohmann::json serialized(*this);
  return serialized.dump();
}

};

struct TestCaseParams {
  ByteArray attacker_code;
  ByteArray state_before_load;
  asm86:: Reg register_to_encode;
  size_t register_byte_position;
  bool data_page_extra_conditions;
  bool data_page_in_cache;
  bool data_page_in_tlb;
};

class TestCaseGenerator {
 public:
  TestCaseGenerator();
  void LoadInstructionList(const std::vector<Instruction>& instruction_list);
  ByteArray CreateVictim(const Instruction& attacker_instruction);
  TestCaseParams CreateAttacker(
      const Instruction& attacker_instruction, 
      ByteArray* architectural_variant);
  TestCase CreateNewTestcase(
    const Instruction& attacker_instruction,
    size_t cache_miss_threshold);
  ByteArray CreateRegisterRecoveryCode(const TestCase& test_case);

 private:
 ByteArray CreateVictimCode(
  bool read_memory,
  bool write_memory,
  bool write_memory_variant2,
  bool flush_memory,
  bool taint_registers_with_data,
  bool exec_instr_architecturally,
  const ByteArray& instruction_to_execute);
  std::tuple<ByteArray, ByteArray> CreateAttackerCode(
      ByteArray load_instruction, 
      const asmjit::x86::Reg& register_to_encode,
      size_t register_byte_position,
      bool exec_load_architecturally,
      size_t number_of_nops_after_flush,
      bool flush_second_mapping,
      bool make_addr_non_canonical,
      bool trap_instruction,
      bool add_additional_instr_prefix,
      uint8_t inst_prefix_to_add,
      bool use_unaligned_ptr,
      const std::vector<Precondition>& preconditions);
  ByteArray ExtractAssemblyCode();
  ByteArray ExtractAssemblyCodeAndClear();
  void EmitPreconditionCode(
      const std::vector<Precondition>& preconditions);
  uint64_t CalculateEncodingBitmask(uint64_t register_byte_position);

  // positive values are left shifts; negative values are right shifts
  int64_t CalculateEncodingShift(uint64_t register_byte_position);
  std::string CreateInstructionSimilarityKey(const Instruction& instruction);
  Instruction GetRandomSimilarInstruction(const Instruction& instruction);

  std::vector<Instruction> instruction_list_;
  std::unordered_map<std::string, std::vector<Instruction>> instruction_similarity_map_;

  // asmjit
  asmjit::JitRuntime runtime_;
  asmjit::CodeHolder code_holder_;
  std::unique_ptr<asmjit::x86::Assembler> assembler_;
};

}  // namespace trevex

#endif // TESTCASE_GENERATOR_H_
