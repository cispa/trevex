// Copyright [2026] <Daniel Weber>

#include "utils.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <csignal>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>

#include <dirent.h>
#include <cpuid.h>
#include <x86intrin.h>
#include <immintrin.h>

#include "cacheutils/cacheutils.h"
#include "logger/logger.h"

namespace trevex {

bool GotRootPrivileges() {
  return geteuid() == 0;
}

bool IsPermissionBitSet(const ptedit_entry_t& pte, int bit) {
  return !!(pte.pte & (1ull << bit));
}

void EnableFPVIMitigation() {
  // setting FTZ (flush to zero) and DAZ (denormals are zero) bits
  _mm_setcsr(_mm_getcsr() | 0x8040);  
}

void DumpMemoryContent(const char* page, 
    size_t len, 
    const std::string& output_filename) {
  
  std::ofstream fs(output_filename);
  if (!fs.is_open()) {
    throw std::runtime_error("Could not open file" + output_filename + "!");
  }

  for (size_t i = 0; i < len; i++) {
    fs << page[i];
  }

  fs.close();
}

int CpuSupportsAvx512() {
  unsigned int eax, ebx, ecx, edx;
  __cpuid(0x0, eax, ebx, ecx, edx); // Get highest supported cpuid input

  if (eax >= 7) { // Check if extended feature information is available
      __cpuid_count(7, 0, eax, ebx, ecx, edx); // Get extended feature flags
      if (ebx & (1 << 16)) {
          return 1;
      } else {
          return 0;
      }
  } else {
      return 0;
  }
}

int CpuSupportsAvx2() {
  unsigned int eax, ebx, ecx, edx;
  __cpuid(0x0, eax, ebx, ecx, edx); // Get highest supported cpuid input

  if (eax >= 7) { // Check if extended feature information is available
      __cpuid_count(7, 0, eax, ebx, ecx, edx); // Get extended feature flags
      if (ebx & (1 << 5)) {
          printf("AVX2 supported!\n");
          return 1;
      } else {
          printf("AVX2 not supported!\n");
          return 0;
      }
  } else {
      return 0;
  }
}

int64_t GetTimestampMS() {
  auto now = std::chrono::system_clock::now();
  auto ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
  return ms.time_since_epoch().count();
}

void InitRandomness() {
  std::srand(std::time(nullptr));
}

bool RandomPickTrueFalse() {
  return RandomPickElement<bool>(std::vector<bool>{true, false});
}

uint64_t RandomNumber(uint64_t max_size) {
  if (max_size == 0) return 0;
  return std::rand() % max_size;
}

bool RandomOneInN(size_t n) {
  return RandomNumber(n) == 0;
}



jmp_buf timeout_buf;
void timeout_handler([[maybe_unused]] int signum) {
  unblock_signal(SIGALRM);
  longjmp(timeout_buf, 1);
}

jmp_buf fatal_buf;
int signal_occured = -1;
void fatal_handler(int signum) {
  unblock_signal(SIGSEGV);
  unblock_signal(SIGFPE);
  unblock_signal(SIGILL);
  unblock_signal(SIGTRAP);

  signal_occured = signum;
  longjmp(fatal_buf, 1);
}

int RetrieveOccuredSignal() {
  int ret = signal_occured;
  signal_occured = -1;
  return ret;
}

void RegisterSignalHandlers() {
  std::signal(SIGSEGV, fatal_handler);
  std::signal(SIGFPE, fatal_handler);
  std::signal(SIGILL, fatal_handler);
  std::signal(SIGTRAP, fatal_handler);

  std::signal(SIGALRM, timeout_handler);
}

void UnregisterSignalHandlers() {
  // yes, we are lazy and just overwrite all with 
  // the initial handlers
  std::signal(SIGSEGV, SIG_DFL);
  std::signal(SIGFPE, SIG_DFL);
  std::signal(SIGILL, SIG_DFL);
  std::signal(SIGTRAP, SIG_DFL);

  std::signal(SIGALRM, SIG_DFL);
}

void PinToCpuCore(int cpu_core) {
  cpu_set_t cpuset;

  CPU_ZERO(&cpuset);
  CPU_SET(cpu_core, &cpuset);
  int err = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
  if (err != 0) {
    throw std::runtime_error("Could not pin to CPU core!");
  }
}

int GetSiblingHyperthreadVariant1(int logical_core) {
  std::stringstream fname;
  fname << "/sys/devices/system/cpu/cpu" << logical_core
    << "/topology/thread_siblings_list";
  std::ifstream fstream(fname.str());
  if (!fstream.is_open()) {
    return -1;
  }
  // the file content structure looks like this: "1,5"
  // (where 1 and 5 are the SMT siblings)
  std::string line;
  fstream >> line;
  fstream.close();

  char delimiter;
  if (find(line.begin(), line.end(), ',') != line.end()) {
    // file structure looks like this: "1,5"
    delimiter = ',';
  } else if (find(line.begin(), line.end(), '-') != line.end()) {
    // file structure looks like this: "0-1"
    // sometimes used if siblings are consecutive
    delimiter = '-';
  } else {
    // unknown/unsupport format
    return -1;
  }

  std::vector<std::string> siblings = SplitString(line, delimiter);
  for (const std::string& sibling : siblings) {
    int sibling_core = std::stoi(sibling);
    if (sibling_core != logical_core) {
      return sibling_core;
    }
  }
  return -1;
}

int GetSiblingHyperthreadVariant2(int logical_core) {
  // shamelessly stolen from libsc
  char cpu_id_path[300];
  char buffer[16];
  snprintf(cpu_id_path, 300, 
      "/sys/devices/system/cpu/cpu%d/topology/core_id", logical_core);

  FILE* f = fopen(cpu_id_path, "r");
  if (!f) {
    return -1;
  }
  volatile int dummy = fread(buffer, 16, 1, f);
  fclose(f);
  int phys = atoi(buffer);
  int hyper = -1;

  DIR* dir = opendir("/sys/devices/system/cpu/");
  if (!dir) {
    return -1;
  }
  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == 'c' && entry->d_name[1] == 'p' &&
        entry->d_name[2] == 'u' &&
        (entry->d_name[3] >= '0' && entry->d_name[3] <= '9')) {
      snprintf(cpu_id_path, 300, "/sys/devices/system/cpu/%s/topology/core_id",
               entry->d_name);
      FILE* f = fopen(cpu_id_path, "r");
      if (!f) {
        return -1;
      }
      dummy += fread(buffer, 16, 1, f);
      fclose(f);
      int logical = atoi(entry->d_name + 3);
      if (atoi(buffer) == phys && logical != logical_core) {
        hyper = logical;
        break;
      }
    }
  }
  closedir(dir);
  return hyper;
}

int GetSiblingHyperthread(int logical_core) {
  // variant 1 is more elegant and seems to work better in corner cases
  // e.g., on the Hygon CPU
  // for now, we keep the original implementation (v2) as a fallback,
  // which is useful if we counter odd formats in the thread_siblings_list
  int hyperthread = GetSiblingHyperthreadVariant1(logical_core);
  if (hyperthread == -1) {
    hyperthread = GetSiblingHyperthreadVariant2(logical_core);
  }
  return hyperthread;
}

ByteArray CreateByteArray(uint8_t* byte_arr, size_t arr_len) {
  ByteArray res;
  for (size_t i = 0; i < arr_len; i++) {
    res.push_back(std::byte{static_cast<unsigned char>(byte_arr[i])});
  }
  return res;
}

std::string ByteArrayToString(const ByteArray& bytes) {
  std::stringstream res;
  for (const std::byte& b : bytes) {
    res << static_cast<char>(std::to_integer<int>(b));
  }
  return res.str();
}

ByteArray NumberToBytesLE(uint64_t number, size_t result_length) {
  ByteArray bytes;
  for (size_t i = 0; i < result_length; i++) {
    uint8_t pos = number & 0xff;
    bytes.push_back(std::byte{pos});
    number >>= 8;
  }
  return bytes;
}

std::vector<std::string> SplitString(const std::string& input_str, char delimiter) {
  std::string delims;
  delims += delimiter;
  std::vector<std::string> results;

  // pre-reserve for performance reasons
  results.reserve(16);

  std::string::const_iterator start = input_str.begin();
  std::string::const_iterator end = input_str.end();
  std::string::const_iterator next = std::find(start, end, delimiter);
  while (next != end) {
    results.emplace_back(start, next);
    start = next + 1;
    next = std::find(start, end, delimiter);
  }
  results.emplace_back(start, next);
  return results;
}

std::string ReplaceChar(const std::string& input_str, 
  char char_to_replace,
  char substitution) {
  std::stringstream new_str;
  for (char c : input_str) {
    if (c == char_to_replace) {
      new_str << substitution;
    } else {
      new_str << c;
    }
  }
  return new_str.str();
}

/*
   base64.cpp and base64.h

   Copyright (C) 2004-2008 René Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch
   ------------------------------------------------------------------------------------------------
   src: https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp/
   NOTE: changed the return type to ByteArray
*/
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

ByteArray base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  ByteArray ret;

  while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_];
    in_++;
    if (i == 4) {
      for (i = 0; i < 4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret.push_back(std::byte{char_array_3[i]});
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 4; j++)
      char_array_4[j] = 0;

    for (j = 0; j < 4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) {
      ret.push_back(std::byte{char_array_3[j]});
    }
  }

  return ret;
}

std::string base64_encode(const ByteArray& bytes_to_encode) {
  size_t len_encoded = (bytes_to_encode.size() + 2) / 3 * 4;
  unsigned char trailing_char = '=';
  std::string ret;
  ret.reserve(len_encoded);

  unsigned int pos = 0;
  while (pos < bytes_to_encode.size()) {
    ret.push_back(base64_chars[(std::to_integer<int>(bytes_to_encode[pos + 0]) & 0xfc) >> 2]);

    if (pos + 1 < bytes_to_encode.size()) {
      ret.push_back(
          base64_chars[((std::to_integer<int>(bytes_to_encode[pos + 0]) & 0x03) << 4)
              + ((std::to_integer<int>(bytes_to_encode[pos + 1]) & 0xf0) >> 4)]);

      if (pos + 2 < bytes_to_encode.size()) {
        ret.push_back(
            base64_chars[((std::to_integer<int>(bytes_to_encode[pos + 1]) & 0x0f) << 2)
                + ((std::to_integer<int>(bytes_to_encode[pos + 2]) & 0xc0) >> 6)]);
        ret.push_back(base64_chars[std::to_integer<int>(bytes_to_encode[pos + 2]) & 0x3f]);
      } else {
        ret.push_back(
            base64_chars[(std::to_integer<int>(bytes_to_encode[pos + 1]) & 0x0f) << 2]);
        ret.push_back(trailing_char);
      }
    } else {
      ret.push_back(
          base64_chars[(std::to_integer<int>(bytes_to_encode[pos + 0]) & 0x03) << 4]);
      ret.push_back(trailing_char);
      ret.push_back(trailing_char);
    }
    pos += 3;
  }
  return ret;
}

}  // namespace trevex
