// Copyright [2026] <Daniel Weber>

#ifndef UTILS_H_
#define UTILS_H_

#include <algorithm>
#include <csetjmp>
#include <cstdint>
#include <string>
#include <vector>

#include "external/PTEditor/ptedit.h"

namespace trevex {

bool GotRootPrivileges();

bool IsPermissionBitSet(const ptedit_entry_t& pte, int bit);

void EnableFPVIMitigation();

void DumpMemoryContent(const char* page, 
    size_t len, 
    const std::string& output_filename);

int CpuSupportsAvx512();
int CpuSupportsAvx2();

int64_t GetTimestampMS();

void InitRandomness();

bool RandomPickTrueFalse();

uint64_t RandomNumber(uint64_t max_size);

bool RandomOneInN(size_t n);

template <typename T>
T RandomPickElement(const std::vector<T>& v) {
  // this has a bias towards some numbers, e.g. v.size() = 5 -> more often 0, 1
  // but it's probably good enough for what we do here (and fast!)
  int random_idx = std::rand() % v.size();
  return v[random_idx];
}

// ----------------------------- Fault Handling Stuff ------------------------
// NOTE: it is CRUCIAL to implement these as MACROS instead of functions!
// "If the function that called setjmp has exited (whether by return or by a different longjmp higher up the stack), the behavior is undefined. In other words, only long jumps up the call stack are allowed."
// src: https://en.cppreference.com/w/c/program/longjmp
// I've observed multiple faults or endless loop when wrapping them in normal functions
extern jmp_buf timeout_buf;
extern jmp_buf fatal_buf;

#define TimeoutStart() (!setjmp(timeout_buf))
#define FatalSignalStart() (!setjmp(fatal_buf))

int RetrieveOccuredSignal();

void RegisterSignalHandlers();

void UnregisterSignalHandlers();

void PinToCpuCore(int cpu_core);

int GetSiblingHyperthread(int logical_core);

///
/// represents ByteArrays
///
using ByteArray = std::vector<std::byte>;

/// Create ByteArray
/// \param byte_arr bytes as char array
/// \param arr_len char array length
/// \return created ByteArray
ByteArray CreateByteArray(uint8_t* byte_arr, size_t arr_len);

/// Converts ByteArray to String
/// \param bytes ByteArray to be converted
/// \return created String
std::string ByteArrayToString(const ByteArray& bytes);

/// Splits a string on a given delimiter
/// \param input_str string to split
/// \param delimiter delimiter character
/// \return vector of splitted strings
std::vector<std::string> SplitString(const std::string& input_str, char delimiter);

/// @brief Replaces all occurences of character in string
/// @param input_str 
/// @param char_to_replace 
/// @param substitution 
/// @return modified string
std::string ReplaceChar(const std::string& input_str, 
    char char_to_replace,
    char substitution);

/// Encodes a number in Little Endian format
/// \param number number
/// \param result_length byte length of the result
/// \return Little Endian bytes
ByteArray NumberToBytesLE(uint64_t number, size_t result_length);

/// Decodes base64 to ByteArray
/// \param encoded_string base64 string
/// \return ByteArray
ByteArray base64_decode(std::string const& encoded_string);

/// Encodes ByteArray as base64 string
/// \param bytes_to_encode ByteArray to encode
/// \return base64 string
std::string base64_encode(const ByteArray& bytes_to_encode);

/// Calculate the SHA256 hash of a given file
/// \param filename filename to calculate hash from
/// \return upon failure returns empty string
std::string CalculateFileHashSHA256(const std::string& filename);

/// Calculates the median of a given vector
/// \tparam T type of the vector elements
/// \param values list of values
/// \return median
template<class T>
double median(std::vector<T> values) {
  if (values.empty()) {
    return 0;
  }
  std::sort(values.begin(), values.end());
  if (values.size() % 2 == 0) {
    return static_cast<double>((values[(values.size() - 1) / 2] + values[values.size() / 2])) / 2;
  } else {
    return values[values.size() / 2];
  }
}

}  // namespace trevex

#endif // UTILS_H_
