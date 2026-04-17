// Copyright [2026] <Daniel Weber>

#ifndef VICTIM_H_
#define VICTIM_H_

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
#include "external/json.hpp"

namespace trevex {

class Victim {
 public:
  virtual ~Victim() = default;
  virtual void Start(int victim_cpu_core) = 0;
  virtual void Shutdown() = 0;
};

}  // namespace trevex

#endif // VICTIM_H_
