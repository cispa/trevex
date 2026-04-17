// Copyright [2026] <Daniel Weber>

#include "utils.h"

#include <cstdint>
#include <thread>
#include <iostream>
#include <vector>

#include <sys/mman.h>
#include <sys/wait.h>
#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "external/magic_enum/magic_enum.hpp"
#include "common.h"
#include "executor.h"
#include "logger/logger.h"
#include "utils.h"

#include "testcase_generator.h"

namespace asm86 = asmjit::x86;

namespace trevex {

TestCaseGenerator::TestCaseGenerator() {
  //
  // initialize the AsmJit runtime
  //
  code_holder_.init(runtime_.environment(), runtime_.cpuFeatures());
  assembler_ = std::make_unique<asm86::Assembler>(&code_holder_);
}

ByteArray TestCaseGenerator::ExtractAssemblyCode() {
  asmjit::CodeBuffer buffer = code_holder_.sectionById(0)->buffer();
  assert(buffer.size() != 0);
  ByteArray asm_code = CreateByteArray(
    buffer.begin(), buffer.size());

  // assert that the generated code still fits in a single page
  assert(asm_code.size() <= kPageSize);
  return asm_code;
}

ByteArray TestCaseGenerator::ExtractAssemblyCodeAndClear() {
  asmjit::CodeBuffer buffer = code_holder_.sectionById(0)->buffer();
  assert(buffer.size() != 0);
  ByteArray asm_code = CreateByteArray(
    buffer.begin(), buffer.size());

  // reset code_holder state
  code_holder_.reset();
  code_holder_.init(runtime_.environment(), runtime_.cpuFeatures());
  code_holder_.attach(assembler_.get());
  assert(code_holder_.sectionById(0)->buffer().size() == 0);
  
  // assert that the generated code still fits in a single page
  assert(asm_code.size() <= kPageSize);

  return asm_code;
}


void TestCaseGenerator::EmitPreconditionCode(
    const std::vector<Precondition>& preconditions) {
  // clobbers R9 register

  for (const Precondition& precondition : preconditions) {
    asm86::Reg reg_name = precondition.register_name;
    if (reg_name.isGp()) {
      // encode general-purpose register
      asm86::Gpq reg(reg_name.id());
      assembler_->mov(reg, precondition.register_value);

    } else if (reg_name.isVec()) {
      // encode vector register
      asm86::Xmm reg(reg_name.id());
      assembler_->mov(asm86::r9, precondition.register_value);
      assembler_->movq(reg, asm86::r9);

    } else if (reg_name.isKReg()) {
      // handle k registers, e.g., K3
      asm86::KReg reg (reg_name.id());
      assembler_->mov(asm86::r9, precondition.register_value);
      assembler_->kmovq(reg, asm86::r9);
    } else {
      throw std::runtime_error("Unimplemented register type in Precondition!");
    }
  }
}

uint64_t TestCaseGenerator::CalculateEncodingBitmask(
    uint64_t register_byte_position) {
  return (uint64_t)0xffu << (register_byte_position * 8);
}


// Calculates the shift to encode a register page aligned
// ret: positive values are left shifts; negative values are right shifts
int64_t TestCaseGenerator::CalculateEncodingShift(
    uint64_t register_byte_position) {
  // calculates the shift to encode a register in a page-aligned table
  static_assert(SPACING == 4096, "SPACING must be 4096 bytes for this function!");
  
  // we shift the byte to align with 4096 (our SPACING)
  // we calculate in blocks of 4 bit (1 hex digit)
  int64_t shifting_base = 3;  // as 4096 is *above* third 4bit block (0-indexed)
  int64_t reg_byte_pos_4block = (int64_t)register_byte_position * 2;
  if (reg_byte_pos_4block >= shifting_base) {
    // -1 as negative values encode right shifts
    return (int64_t)-1 * (reg_byte_pos_4block - shifting_base) * 4;
  } else {
    return (shifting_base - reg_byte_pos_4block) * 4;
  }
}

std::string TestCaseGenerator::CreateInstructionSimilarityKey(
    const Instruction& instruction) {
  // we consider a instruction as "similar" when it matches for the 
  // category, extension and isa_set
  return instruction.category + ";" + instruction.extension + ";" + instruction.isa_set;
}

void TestCaseGenerator::LoadInstructionList(
  const std::vector<Instruction>& instruction_list) {
    instruction_list_ = instruction_list;
  for (const Instruction& instruction : instruction_list) {
      auto key = CreateInstructionSimilarityKey(instruction);
      instruction_similarity_map_[key].push_back(instruction);
    }
}

Instruction TestCaseGenerator::GetRandomSimilarInstruction(
    const Instruction& instruction) {
  auto key = CreateInstructionSimilarityKey(instruction);
  auto similar_instructions = instruction_similarity_map_[key];
  if (similar_instructions.empty()) {
    // this should in theory never happen, as the instruction itself should 
    // be in the list of similar instructions
    return instruction;
  }
  // we just return the first one, as we currently do not use this function
  // for anything critical. in the future, we could e.g., return a random
  // similar instruction to increase diversity of our test cases
  return RandomPickElement(similar_instructions);
}

ByteArray TestCaseGenerator::CreateVictimCode(
    bool read_memory,
    bool write_memory,
    bool write_memory_variant2,
    bool flush_memory,
    bool taint_registers_with_data,
    bool exec_instr_architecturally,
    const ByteArray& instruction_to_execute) {
  // victim code gets called with the following arg:
  // RDI: accessible data page (RW permissions)
  assembler_->push(asm86::rbx);
  assembler_->push(asm86::rbp);
  assembler_->mov(asm86::rbp, asm86::rsp);
  assembler_->sub(asm86::rsp, STACK_SIZE_VICTIM);
  assembler_->mov(asm86::r8, asm86::rdi);

  // we loop everything besides initialization to reduce the 
  // impact of surrounding code
  asmjit::Label outer_loop = assembler_->newLabel();

  assembler_->mov(asm86::r11, 100000);

  assembler_->bind(outer_loop);
  if (read_memory) {
    // iterate over all cachelines of the page and LOAD them
    asmjit::Label inner_loop = assembler_->newLabel();
    assembler_->xor_(asm86::r10, asm86::r10);
    assembler_->bind(inner_loop);

    // mov r9, [rdi + r10]
    assembler_->mov(asm86::r9, asm86::ptr(asm86::rdi, asm86::r10));

    // inc loop counter
    assembler_->add(asm86::r10, 64);

    // clflush [rdi + r10 + 64]
    assembler_->clflush(asm86::ptr(asm86::rdi, asm86::r10));

    // check loop counter
    assembler_->cmp(asm86::r10, 4032);  // 4096 - 64 = 4032
    assembler_->jl(inner_loop);
  }
  if (write_memory) {
    // iterate over all cachelines of the page and WRITE them
    asmjit::Label inner_loop = assembler_->newLabel();
    assembler_->xor_(asm86::r10, asm86::r10);
    assembler_->bind(inner_loop);

    // load a byte from data page (target bytes) to r9
    assembler_->mov(asm86::r9, asm86::ptr(asm86::rdi));

    // mov [rdi + r10], r9
    assembler_->mov(asm86::ptr(asm86::rdi, asm86::r10), asm86::r9);

    // inc loop counter
    assembler_->add(asm86::r10, 64);

    // clflush [rdi + r10]
    assembler_->clflush(asm86::ptr(asm86::rdi, asm86::r10));

    assembler_->cmp(asm86::r10, 4032);  // 4096 - 64 = 4032
    assembler_->jl(inner_loop);
  }
  if (write_memory_variant2) {
    // load a byte from data page (target bytes) to r9
    assembler_->mov(asm86::r9, asm86::ptr(asm86::rdi));

    asmjit::Label inner_loop = assembler_->newLabel();
    assembler_->xor_(asm86::r10, asm86::r10);
    assembler_->bind(inner_loop);

    // write r9 to [rdi] and fence (4 times) then flush the cacheline
    assembler_->mov(asm86::ptr(asm86::rdi), asm86::r9);
    assembler_->mfence();
    assembler_->mov(asm86::ptr(asm86::rdi), asm86::r9);
    assembler_->mfence();
    assembler_->mov(asm86::ptr(asm86::rdi), asm86::r9);
    assembler_->mfence();
    assembler_->mov(asm86::ptr(asm86::rdi), asm86::r9);
    assembler_->mfence();
    assembler_->clflush(asm86::ptr(asm86::rdi));

    // inc loop counter
    assembler_->add(asm86::r10, 1);

    assembler_->cmp(asm86::r10, 10000);  // just a random number
    assembler_->jl(inner_loop);
  }
  if (flush_memory) {
    // iterate over all cachelines of the page and flush them
    asmjit::Label inner_loop = assembler_->newLabel();
    assembler_->xor_(asm86::r10, asm86::r10);
    assembler_->bind(inner_loop);

    // clflush [rdi + r10]
    assembler_->clflush(asm86::ptr(asm86::rdi, asm86::r10));

    // inc loop counter
    assembler_->add(asm86::r10, 64);
    assembler_->cmp(asm86::r10, 4032);  // 4096 - 64 = 4032
    assembler_->jle(inner_loop);
  }
  if (!instruction_to_execute.empty()) {

    // taint all data with data from the victim page
    // otherwise we taint with a ptr to that data

    // TODO: debug the following change (lines 976-998)
    //if (taint_registers_with_data) {
    //  assembler_->mov(asm86::rdi, asm86::ptr(asm86::rdi));
    //} 

    // most instructions use [r8] or [x- /y-/zmm0] so we just put ptr into there
    // and data into the rest
    assembler_->movq(asm86::xmm0, asm86::r8);
    assembler_->mov(asm86::rdi, asm86::ptr(asm86::r8));

    assembler_->mov(asm86::rsi, asm86::rdi);
    assembler_->mov(asm86::rdx, asm86::rdi);
    assembler_->mov(asm86::rcx, asm86::rdi);
    assembler_->mov(asm86::rbx, asm86::rdi);
    //assembler_->mov(asm86::r8, asm86::rdi);
    assembler_->mov(asm86::rax,asm86::rdi);
    //assembler_->movq(asm86::xmm0, asm86::rdi);
    assembler_->movq(asm86::xmm1, asm86::rdi);
    assembler_->movq(asm86::xmm2, asm86::rdi);
    assembler_->movq(asm86::xmm3, asm86::rdi);
    assembler_->movq(asm86::xmm4, asm86::rdi);
    assembler_->movq(asm86::xmm5, asm86::rdi);
    assembler_->movq(asm86::xmm6, asm86::rdi);

    if (exec_instr_architecturally) {
      for (int i = 0; i < 1; i++) {  // TODO: think about this; 
                                     // probably make it an argument
        assembler_->embed(instruction_to_execute.data(), 
            instruction_to_execute.size());
      }
    } else {  // !exec_instruction_architecturally

      // the custom instructions may fault hence we wrap them into speculation
      asmjit::Label stack_change = assembler_->newLabel();
      asmjit::Label end = assembler_->newLabel();
      asmjit::Label inside_speculation = assembler_->newLabel();

      assembler_->call(stack_change);
        // this will only execute speculatively
        assembler_->bind(inside_speculation);
        for (int i = 0; i < 10; i++) {
          assembler_->embed(instruction_to_execute.data(), 
              instruction_to_execute.size());
        }
        assembler_->jmp(inside_speculation);

      assembler_->bind(stack_change);
      assembler_->lea(asm86::rdi, asm86::ptr(end));
      assembler_->mov(asm86::ptr(asm86::rsp), asm86::rdi);

      // use heavy vector instructions to extend the transient window
      assembler_->pxor(asm86::xmm7, asm86::xmm7);
      for (size_t i = 0; i < 10; i++) {
        assembler_->sqrtpd(asm86::xmm7, asm86::xmm7);
      }
      assembler_->ret();  // mispredicts into embeded instructions

      assembler_->bind(end);

    }
  }

  // jump back to our loop (loop counter is in R11)
  assembler_->dec(asm86::r11);
  assembler_->jnz(outer_loop);

  // return from function
  assembler_->mov(asm86::rsp, asm86::rbp);
  assembler_->pop(asm86::rbp);
  assembler_->pop(asm86::rbx);
  assembler_->ret();

  return ExtractAssemblyCodeAndClear();
}


ByteArray TestCaseGenerator::CreateVictim(
    const Instruction& attacker_instruction) {
  if (instruction_list_.empty()) {
    throw std::runtime_error("No instruction list loaded!");
  }

  std::vector<int> victim_variants = {
    0,
    1,
    2
  };
  int victim_variant = RandomPickElement(victim_variants);

  ByteArray victim_instructions;
    for (size_t i = 0; i < NUMBER_OF_EMITTED_VICTIM_INSTRUCTIONS; i++) {

      // TODO: this add the current instruction, check whether that's a good idea
      for (int i = 0; i < 100; i++) {  // TODO: executing *the same inst* multiple times *should* work for most cases - update: but it breaks for POP, etc
#ifdef STRICT_SIMILARITY_FOR_INSTR_SHADOWING
      Instruction similar_instruction = attacker_instruction;
#else
      Instruction similar_instruction = GetRandomSimilarInstruction(attacker_instruction);
#endif
        victim_instructions.insert(victim_instructions.end(), 
            similar_instruction.bytes.begin(), 
            similar_instruction.bytes.end());
      }

    }

  ByteArray victim_code;
  switch (victim_variant) {
    case 0: {
      // victim code reads memory
      victim_code = CreateVictimCode(
            true,
            false,
            false,
            false, 
            false,
            false,
            {}
      );
      break;
    }
    case 1: {
      // victim code writes memory
      bool use_alternative_variant = RandomPickTrueFalse();
      victim_code = CreateVictimCode(
            false,
            !use_alternative_variant,
            use_alternative_variant, 
            false,
            false,
            false,
            {}
      );
      break;
    }
    case 2: {
      // victim code uses attacker code
      victim_code = CreateVictimCode(
            false,
            false,
            false,
            false, 
            RandomPickTrueFalse(),
            true,
            victim_instructions
      );
      break;
    }
    default:
      throw std::runtime_error("Unsupported victim variant! Aborting!");
  }
  return victim_code;
}

TestCaseParams TestCaseGenerator::CreateAttacker(
  const Instruction& attacker_instruction, ByteArray* architectural_variant) {

  std::vector<asm86::Reg> regs_to_check = {
      asm86::rax,
      asm86::rcx,
      asm86::rdx,
      asm86::xmm0,
      asm86::xmm1
  };


  std::vector<Precondition> preconditions = {
    Precondition(asm86::rax, 0x0),
    Precondition(asm86::rcx, 0x0),
    Precondition(asm86::rdi, 0x0),
    Precondition(asm86::r8, 0x0),
    Precondition(asm86::r8, kDataMemoryBegin + 0xffe),
    Precondition(asm86::xmm1, 0),
    Precondition(asm86::xmm2, 0),
    Precondition(asm86::xmm3, -1),
    Precondition(asm86::rax, 0x4),
    Precondition(asm86::rdx, 0x4),
    Precondition(asm86::rdx, 0x0),
    Precondition(asm86::xmm1, 0x10deadbeef), // DENORM value (see ./test-snippets/denorm-patched)
    Precondition(asm86::xmm2, 0x10deadbeef),
    Precondition(asm86::xmm3, 0x10deadbeef),
    Precondition(asm86::xmm1, 0x60000000000000), // NORMAL values (signbit == 0)
    Precondition(asm86::xmm2, 0x60000000000000),
    Precondition(asm86::xmm3, 0x60000000000000),
    Precondition(asm86::xmm1, 0x8060000000000000), // NORMAL values (signbit == 1)
    Precondition(asm86::xmm2, 0x8060000000000000),
    Precondition(asm86::xmm3, 0x8060000000000000),
    Precondition(asm86::rax, RandomNumber(1024)),
    Precondition(asm86::rdx, RandomNumber(1024)),
    Precondition(asm86::rcx, RandomNumber(1024))
  };


  std::vector<Precondition> precondition;
  for (int i = 0; i < 4; i++) {
    if (RandomOneInN(2)) {
      precondition.push_back(
          RandomPickElement<Precondition>(preconditions));
    }
  }

  if (CpuSupportsAvx512()) {
    std::vector<asmjit::x86::Reg> k_regs = {
      asm86::k0,
      asm86::k1,
      asm86::k2,
      asm86::k3,
      asm86::k4,
      asm86::k5,
      asm86::k6,
      asm86::k7,
    };

    for (const auto& k_reg : k_regs) {
      std::vector<Precondition> writemask_conditions;
      writemask_conditions.emplace_back(k_reg, -1);
      writemask_conditions.emplace_back(k_reg, 0);

      // 1010....
      writemask_conditions.emplace_back(k_reg, 0xAAAAAAAAAAAAAAAA);

      // 0101...
      writemask_conditions.emplace_back(k_reg, 0x5555555555555555);

      // pick one writemask at random
      precondition.push_back(
        RandomPickElement<Precondition>(writemask_conditions));
    }
  }

  std::vector<int> nop_counts = {
    0,
    31,
    64,
    130,
    233,
    400,
    600
  };

  std::vector<int> prefixes = {
    kInstrPrefix_Vex,
    kInstrPrefix_AddrSize,
    kInstrPrefix_BranchHint1,
    kInstrPrefix_Lock,
    kInstrPrefix_Repeat,
  };

  std::vector<int> register_byte_positions = {
    0,
    1,
    2,
    3
  };


  bool add_additional_prefix = RandomOneInN(16);
  int additional_prefix = RandomPickElement<int>(prefixes);
  bool make_addr_non_canonical = RandomOneInN(16);

  bool data_page_extra_conditions = RandomPickTrueFalse();
  bool data_page_in_cache = RandomPickTrueFalse();
  bool data_page_in_tlb = RandomPickTrueFalse();

  auto register_to_encode = RandomPickElement<asm86::Reg>(regs_to_check);
  int register_byte_position = RandomPickElement<int>(register_byte_positions);
  int nop_count = RandomPickElement<int>(nop_counts);
  bool flush_second_mapping = RandomPickTrueFalse();
  bool use_unaligned_ptr = RandomOneInN(6);
  bool trap_instruction = RandomOneInN(16);

  auto [default_attacker_code, state_before_load] = CreateAttackerCode(
      attacker_instruction.bytes, 
      register_to_encode,
      register_byte_position,
      EXECUTE_ATTACKER_ARCHITECTURALLY,
      nop_count,
      flush_second_mapping,
      make_addr_non_canonical,
      trap_instruction,
      add_additional_prefix,
      additional_prefix,
      use_unaligned_ptr,
      precondition);

  // we use this second variant to test:
  //    1) whether we fault at all
  //    2) whether we see zero-forwarding
  ByteArray architectural_attacker_code;
  if (!EXECUTE_ATTACKER_ARCHITECTURALLY) {
    auto [architectural_attacker_code, state_before_load2] = 
      CreateAttackerCode(
        attacker_instruction.bytes, 
        register_to_encode,
        register_byte_position,
        true,
        nop_count,
        flush_second_mapping,
        make_addr_non_canonical,
        trap_instruction,
        add_additional_prefix,
        additional_prefix,
        use_unaligned_ptr,
        precondition);
  } else {
    architectural_attacker_code = default_attacker_code;
  }

  *architectural_variant = architectural_attacker_code;
  TestCaseParams ret;
  ret.attacker_code = default_attacker_code;
  ret.state_before_load = state_before_load;
  ret.register_to_encode = register_to_encode;
  ret.register_byte_position = register_byte_position;
  ret.data_page_extra_conditions = data_page_extra_conditions;
  ret.data_page_in_cache = data_page_in_cache;
  ret.data_page_in_tlb = data_page_in_tlb;
  return ret;
}


std::tuple<ByteArray, ByteArray> TestCaseGenerator::CreateAttackerCode(
    ByteArray load_instruction,
    const asm86::Reg& register_to_encode,
    size_t register_byte_position,
    bool exec_load_architecturally,
    size_t number_of_nops_after_flush,
    bool flush_second_mapping,
    bool make_addr_non_canonical,
    bool trap_instruction,
    bool add_additional_instr_prefix,
    uint8_t inst_prefix_to_add,
    bool use_unaligned_ptr,
    const std::vector<Precondition>& preconditions) {
  // CAREFUL: obey the ABI, e.g., only use caller-saved registers!
  // the leakage coder gets called with the following arguments:
  // first arg (RDI) := data_page
  // second arg (RSI) := data_page (second virtual mapping)
  // third arg (RDX) := probe_memory
  
  // we also want to let RSI/RDX point to the data_page, 
  // hence move the second mapping to R10 and probe_memory to R11
  assembler_->push(asm86::rbx);
  assembler_->push(asm86::rbp);
  assembler_->mov(asm86::rbp, asm86::rsp);
  assembler_->mov(asm86::r10, asm86::rsi);
  assembler_->mov(asm86::r11, asm86::rdx);

  if (use_unaligned_ptr) {
    assembler_->add(asm86::rdi, OFFSET_FOR_UNALIGNED_PTR);
  }

  // load data address in a bunch of possible registers
  assembler_->mov(asm86::rsi, asm86::rdi);
  assembler_->mov(asm86::rdx, asm86::rdi);
  assembler_->mov(asm86::rcx, asm86::rdi);
  assembler_->mov(asm86::rbx, asm86::rdi);
  assembler_->mov(asm86::r8, asm86::rdi);
  assembler_->mov(asm86::r9, asm86::rdi);
  assembler_->mov(asm86::rax,asm86::rdi);
  assembler_->movq(asm86::xmm0, asm86::rdi);
  assembler_->movq(asm86::xmm1, asm86::rdi);
  assembler_->movq(asm86::xmm2, asm86::rdi);
  assembler_->movq(asm86::xmm3, asm86::rdi);
  assembler_->movq(asm86::xmm4, asm86::rdi);
  assembler_->movq(asm86::xmm5, asm86::rdi);
  assembler_->movq(asm86::xmm6, asm86::rdi);

  // ATTENTION: this clobbers R9
  EmitPreconditionCode(preconditions);

  // we either flush or we cache the memory
  if (flush_second_mapping) {
    assembler_->clflush(asm86::ptr(asm86::r10));
    for (size_t i = 0; i < number_of_nops_after_flush; i++) {
      assembler_->nop();
    }
  }  // other branch is disabled due to datapage_in_cache and datapage_in_tlb
  //else {
    //assembler_->mov(asm86::r10, asm86::ptr(asm86::r10));
    //assembler_->mfence();
  //}

  if (make_addr_non_canonical) {
    // make the address non-canonical (by flipping bit 62 to 1)
    assembler_->mov(asm86::rdx, 1);
    assembler_->shl(asm86::rdx, 62);
    assembler_->xor_(asm86::rdi, asm86::rdx);
    // update registers
    assembler_->mov(asm86::rsi, asm86::rdi);
    assembler_->mov(asm86::rdx, asm86::rdi);
    assembler_->mov(asm86::rcx, asm86::rdi);
    assembler_->mov(asm86::r8, asm86::rdi);
    assembler_->mov(asm86::r9, asm86::rdi);
    assembler_->mov(asm86::rax,asm86::rdi);
    assembler_->movq(asm86::xmm0, asm86::rdi);
    assembler_->movq(asm86::xmm1, asm86::rdi);
    assembler_->movq(asm86::xmm2, asm86::rdi);
    assembler_->movq(asm86::xmm3, asm86::rdi);
    assembler_->movq(asm86::xmm4, asm86::rdi);
    assembler_->movq(asm86::xmm5, asm86::rdi);
    assembler_->movq(asm86::xmm6, asm86::rdi);
  }

  // stall CPU to create a long transient execution window
  if (exec_load_architecturally) {
    // use heavy vector instructions
    assembler_->pxor(asm86::xmm7, asm86::xmm7);
    for (size_t i = 0; i < 10; i++) {
      assembler_->sqrtpd(asm86::xmm7, asm86::xmm7);
    }
  } else {
    // access a nullpointer
    assembler_->xor_(asm86::r9, asm86::r9);
    assembler_->mov(asm86::r9, asm86::ptr(asm86::r9));
  }

  if (trap_instruction) {
    // we prepare setting the trapflag to issue an interrupt 
    // on the next instruction
    assembler_->pushf();
    assembler_->pop(asm86::r9w);
    assembler_->or_(asm86::r9w, 0x100);
    assembler_->push(asm86::r9w);
  }

  // we extract the state before the attacking instruction is executed
  // this allows us to retrieve the register state at the time of the fault
  ByteArray state_before_load = ExtractAssemblyCode();

  if (trap_instruction) {
    // Note: we pop the flags here as the "state_before_load" 
    // must not fault.
    assembler_->popf();
  }

  // do the (potentially faulting) access to the data address
  if (add_additional_instr_prefix) {
    assembler_->embedUInt8(inst_prefix_to_add);
  }
  assembler_->embed(load_instruction.data(), load_instruction.size());

  // encode chosen register in probe array (R11)
  asm86::Gpq target_register;
  if (register_to_encode.isGp()) {
    // we can directly encode general-purpose registers
    target_register = asm86::Gpq(register_to_encode.id());

  } else if (register_to_encode.isVec()) {
    // for vector registers (XMM, YMM, ZMM), we move the value to RAX first
    
    // XMM is enough to encode the lowest bytes of YMM and ZMM
    assembler_->movq(asm86::rax, asm86::Xmm(register_to_encode.id()));
    target_register = asm86::Gpq(asm86::rax.id());
  } else {
    throw std::runtime_error("Unimplemented register type used. Aborting!!");
  }

  // note that if we want to change this to support other byte positions this also has to change in CreateRegisterRecoveryCode()

  uint64_t bitmask = CalculateEncodingBitmask(register_byte_position);
  int64_t shift_offset = CalculateEncodingShift(register_byte_position);
  
  if (bitmask > (uint32_t)-1) {
    // AND only supports 32 bit masks and asmjit silently errors.
    throw std::runtime_error("Bitmask is too large! Aborting!");
  }
  assembler_->and_(target_register, bitmask);  // single-out the target position

  // negative offsets encode right shifts
  if (shift_offset >= 0) {
    assembler_->shl(target_register,shift_offset);
  } else {
    assembler_->shr(target_register, -1u * shift_offset);
  }

  assembler_->add(asm86::r11, target_register);

  // actually encode as probe_array[r11 + chosen_reg * 4096]
  assembler_->mov(asm86::rdx, asm86::ptr(asm86::r11));

  if (!exec_load_architecturally) {
    // if we are in a transient window, we can just make an endless loop
    asmjit::Label endless_loop = assembler_->newLabel();
    assembler_->bind(endless_loop);
    assembler_->jmp(endless_loop);
  }

  // make sure to restore the stack and the caller's RBP
  assembler_->mov(asm86::rsp, asm86::rbp);
  assembler_->pop(asm86::rbp);
  assembler_->pop(asm86::rbx);
  assembler_->ret();

  ByteArray attacker_code = ExtractAssemblyCodeAndClear();
  return std::make_tuple(attacker_code, state_before_load);
}


TestCase TestCaseGenerator::CreateNewTestcase(
    const Instruction& attacker_instruction,
    size_t cache_miss_threshold) {

  TestCase test_case;
  test_case.cache_miss_threshold = cache_miss_threshold;
  test_case.signal_number_caught = -1;

  //
  // Create the victim code
  //
  test_case.victim_code = CreateVictim(attacker_instruction);

  std::vector<ConditionDataPage> conditions_to_check = {
      ConditionDataPage::kNoAccessBit,
      ConditionDataPage::kNoUserBit,
      ConditionDataPage::kSetUncacheable,
      ConditionDataPage::kSetDirtyBit, 
      ConditionDataPage::kDefault,  
#ifdef INTEL
      ConditionDataPage::kUnmaskFpFaults,
#endif
  };
  if (!EXECUTE_ATTACKER_ARCHITECTURALLY) {
    // architectural accesses to these conditions will be handled by the kernel
    conditions_to_check.push_back(ConditionDataPage::kNoPresentBit);
  }

  for (size_t i = 0; i < 3; i++) {
    if (RandomPickTrueFalse()) {
      auto new_condition = RandomPickElement<ConditionDataPage>(conditions_to_check);

      // delete the element to make sure we don't pick it again
      auto it = std::find(
          conditions_to_check.begin(), 
          conditions_to_check.end(), 
          new_condition);
      if (it != conditions_to_check.end()) {
        conditions_to_check.erase(it);
      }

      test_case.data_conditions.push_back(new_condition);
    }
  }

  //
  // Create the attacker code
  //
  ByteArray architecturally_executed_code;
  TestCaseParams params = CreateAttacker(
      attacker_instruction, &architecturally_executed_code);
  test_case.leakage_code = params.attacker_code;
  test_case.state_before_load = params.state_before_load;
  test_case.register_to_encode = params.register_to_encode;
  test_case.register_byte_position = params.register_byte_position;

  test_case.data_page_extra_conditions = params.data_page_extra_conditions;
  test_case.data_page_in_cache = params.data_page_in_cache;
  test_case.data_page_in_tlb = params.data_page_in_tlb;
  test_case.attacker_instruction = attacker_instruction.bytes;

  test_case.architectural_leakage_code = architecturally_executed_code;

  return test_case;
}

ByteArray TestCaseGenerator::CreateRegisterRecoveryCode(
    const TestCase& test_case) {
  // to recover the value of the register, we take the initial
  // state and return the value
  ByteArray recovery_code = test_case.state_before_load;
  asm86::Reg reg = test_case.register_to_encode;

  // encode chosen register in probe array (R11)
  if (reg.isGp()) {
    // we can directly encode general-purpose registers
    assembler_->mov(asm86::rax, asm86::Gpq(reg.id()));

  } else if (reg.isVec()) {
    // vector registers (XMM, YMM, ZMM)
    
    // XMM is enough to encode the lowest byte of YMM and ZMM
    assembler_->movq(asm86::rax, asm86::Xmm(reg.id()));
  } else {
    throw std::runtime_error("Unimplemented reg type in CreateRegRecCode");
  }

  // encode correct byte position
  uint64_t bitmask = CalculateEncodingBitmask(
      test_case.register_byte_position);
  int64_t shift_offset = CalculateEncodingShift(
      test_case.register_byte_position);

  assembler_->and_(asm86::rax, bitmask);
  // negative offsets encode right shifts
  if (shift_offset >= 0) {
    assembler_->shl(asm86::rax,shift_offset);
  } else {
    assembler_->shr(asm86::rax, -1u * shift_offset);
  }
  // encode in lowest byte instead of page aligned
  assembler_->shr(asm86::rax, 12);

  // make sure to restore the stack and the caller's RBP
  assembler_->mov(asm86::rsp, asm86::rbp);
  assembler_->pop(asm86::rbp);
  assembler_->pop(asm86::rbx);
  assembler_->ret();

  ByteArray recovery_code_remainder = 
      ExtractAssemblyCodeAndClear();
  recovery_code.insert(recovery_code.end(), 
      recovery_code_remainder.begin(), 
      recovery_code_remainder.end());

  return recovery_code;
}

}  // namespace trevex
