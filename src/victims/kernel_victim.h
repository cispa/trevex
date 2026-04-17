// Copyright [2026] <Daniel Weber>

#ifndef KERNEL_VICTIM_H_
#define KERNEL_VICTIM_H_

#include <cstdint>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <vector>

#include <signal.h>
#include <semaphore.h>

#include "common.h"
#include "config.h"
#include "victims/victim.h"
#include "external/json.hpp"

namespace trevex {

//
// Configuration
//
#define VICTIM_STARTED_SEMA_ID "/trevex-semaphore-9c6f9a88515c80"
constexpr uint64_t kVictimDataMemoryBegin = 0x13380000;

class KernelVictim : public Victim {
 public:
  explicit KernelVictim(const ByteArray& victim_code);
  explicit KernelVictim(const ByteArray& victim_code, char taint_value);
  ~KernelVictim();
  void Start(int victim_cpu_core);
  void Shutdown();

 private:
  void RegisterStopSignalHandler();
  void UnregisterAllSignalHandlers();
  void InitSynchronizationPrimitives();
  void InitChildProcess(int victim_cpu_core);
  char* victim_code_page_;
  char* victim_data_page_;
  char taint_value_;
  pid_t pid_;
  bool is_main_process_;
  sem_t* victim_started_semaphore_;

  // synchronization primitives
  pthread_cond_t victim_thread_should_run_;
  pthread_mutex_t victim_thread_mutex_;
};

}  // namespace trevex

#endif // KERNEL_VICTIM_H_
