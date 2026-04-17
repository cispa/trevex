// Copyright [2026] <Daniel Weber>

#ifndef COMMON_H_
#define COMMON_H_

#include <algorithm>
#include <cstdint>
#include <string>
#include <map>
#include <vector>

// ignore pedantic warnings from AsmJit (they bloat our output)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <asmjit/asmjit.h>
#pragma GCC diagnostic pop

#include "utils.h"

namespace trevex {

constexpr size_t kPageSize = 4096;

// See Intel Manual Vol 2 - Section 2.1.1 (Instruction Prefixes)
constexpr uint8_t kInstrPrefix_Vex = 0x66;
constexpr uint8_t kInstrPrefix_AddrSize = 0x67;
constexpr uint8_t kInstrPrefix_Lock = 0xf0;
constexpr uint8_t kInstrPrefix_RepeatNe = 0xf2;
constexpr uint8_t kInstrPrefix_Repeat = 0xf3;
constexpr uint8_t kInstrPrefix_BranchHint1 = 0x2e;
constexpr uint8_t kInstrPrefix_BranchHint2 = 0x3e;
constexpr uint8_t kInstrPrefix_SegmentCs = 0x2e;
constexpr uint8_t kInstrPrefix_SegmentSs = 0x36;
constexpr uint8_t kInstrPrefix_SegmentDs = 0x3e;
constexpr uint8_t kInstrPrefix_SegmentEs = 0x26;
constexpr uint8_t kInstrPrefix_SegmentFs = 0x64;
constexpr uint8_t kInstrPrefix_SegmentGs = 0x65;

using Leakage = std::map<uint8_t, size_t>;

// maps output to input
using InstrInputOutputMapping = std::map<uint8_t, uint8_t>;

struct Precondition {
  asmjit::x86::Reg register_name;
  uint64_t register_value;
  Precondition(asmjit::x86::Reg reg_name, uint64_t reg_value) :
    register_name(reg_name), register_value(reg_value) {}
};

struct Instruction {
  std::string mnemonic;
  ByteArray bytes;
  std::vector<Precondition> preconditions_for_normal_execution;
  std::vector<Precondition> preconditions_for_fault;
  std::string category;
  std::string extension;
  std::string isa_set;
};

enum class ConditionVictimThread {
  kMemoryRead,
  kMemoryWrite,
  kShadowLeakInstruction,
  kFlush
};

enum class TaintDependency {
  kUntested,
  kUnconfirmed,
  kConfirmed,
};

enum class ConditionDataPage {
  kNoUserBit,
  kNoAccessBit,
  kNoPresentBit,
  kSetUncacheable,
  kSetDirtyBit,
  kClearDirtyBit,
  kUnmaskFpFaults,
  kDefault
};


}  // namespace trevex

#endif // COMMON_H_
