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

#include "logger/logger.h"
#include "utils.h"

#include "kernel_victim.h"

namespace trevex {


// this is global as we need to access it from within the signal handler
static volatile sig_atomic_t shutdown_victim;

KernelVictim::KernelVictim(const ByteArray& victim_code) : KernelVictim(victim_code, TAINT_VALUE) {}

KernelVictim::KernelVictim(const ByteArray& victim_code, char taint_value) : 
    taint_value_(taint_value), pid_(-1), is_main_process_(true){
  // initialize shared memory

  // map VICTIM CODE
  victim_code_page_ = static_cast<char*>(mmap(nullptr, kPageSize, 
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_SHARED | MAP_ANONYMOUS, -1 , 0));
  
  if (victim_code_page_ == MAP_FAILED) {
    throw std::runtime_error("Could not allocate memory for victim code page!");
  }

  // TODO: do we want to set this to MAP_PRIVATE
  //     and init in the victim process only?
  // map VICTIM DATA
  victim_data_page_ = static_cast<char*>(mmap(
    reinterpret_cast<void*>(kVictimDataMemoryBegin), kPageSize,
    PROT_READ | PROT_WRITE,
    MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0));
  if (victim_data_page_ == MAP_FAILED || 
      reinterpret_cast<uint64_t>(victim_data_page_) != kVictimDataMemoryBegin) {
    throw std::runtime_error("Could not allocate memory for victim data page!");
  }

  // initialize memory
  assert(victim_code.size() <= kPageSize);
  assert(victim_code.data() != nullptr);
  // code
  memcpy(victim_code_page_, victim_code.data(), victim_code.size());
  // data
  memset(victim_data_page_, taint_value_, kPageSize);

  InitSynchronizationPrimitives();

}

void KernelVictim::InitSynchronizationPrimitives() {
  //
  // Init Semaphore
  //

  victim_started_semaphore_ = sem_open(VICTIM_STARTED_SEMA_ID, 
      O_CREAT, 0644, 0);
  if (victim_started_semaphore_ == SEM_FAILED) {
    throw std::runtime_error("Could not open semaphore (in parent): " \
        + std::string(strerror(errno)));
  }

}

KernelVictim::~KernelVictim() {
  Shutdown();
  // the main process cleans up the semaphore
  // PID == -1 -> still main process, we never forked
  if (is_main_process_ \
      && victim_started_semaphore_ != nullptr \
      && victim_started_semaphore_ != SEM_FAILED) {
     sem_close(victim_started_semaphore_);
     sem_unlink(VICTIM_STARTED_SEMA_ID);
  }
  if (victim_code_page_ != nullptr && victim_code_page_ != MAP_FAILED) {
     munmap(victim_code_page_, kPageSize);
  }
  if (victim_data_page_ != nullptr && victim_data_page_ != MAP_FAILED) {
     munmap(victim_data_page_, kPageSize);
  }
}

static jmp_buf stop_signal_buf;
#define StopSignalStart() (!setjmp(stop_signal_buf))
static volatile bool stop_signal_ready = false;

void StopSignalHandler([[maybe_unused]] int signo) {
  shutdown_victim = true;
  if (stop_signal_ready) {
    longjmp(stop_signal_buf, 1);
  }
}

void KernelVictim::RegisterStopSignalHandler() {
  signal(SIGUSR1, StopSignalHandler);
}

void KernelVictim::UnregisterAllSignalHandlers() {
  signal(SIGINT, SIG_DFL);
  signal(SIGABRT, SIG_DFL);
  signal(SIGSEGV, SIG_DFL);
  signal(SIGFPE, SIG_DFL);
  signal(SIGILL, SIG_DFL);
  signal(SIGTRAP, SIG_DFL);
  signal(SIGUSR1, SIG_DFL);
  signal(SIGUSR2, SIG_DFL);
}

void KernelVictim::InitChildProcess(int victim_cpu_core) {
  is_main_process_ = false;
  // unset the main.cc handlers for the child process
  UnregisterAllSignalHandlers();

  // reopen the semaphore
  victim_started_semaphore_ = sem_open(VICTIM_STARTED_SEMA_ID, 0);
  if (victim_started_semaphore_ == SEM_FAILED) {
    throw std::runtime_error("Could not open semaphore (in child): " + std::string(strerror(errno)));
  }

  RegisterSignalHandlers();

  shutdown_victim = false;
  RegisterStopSignalHandler();

  PinToCpuCore(victim_cpu_core);
}

void KernelVictim::Start(int victim_cpu_core) {
  if (pid_ != -1) {
    // we already forked
    throw std::runtime_error("KernelVictim was started twice!");
  }

  LOG_DEBUG("Starting victim on core " + std::to_string(victim_cpu_core));

  pid_ = fork();
  if (pid_ == -1) {
    throw std::runtime_error("Creating child process failed: " + std::string(strerror(errno)));
  }

  // do this to get rid of Copy-on-write behavior
  memset(victim_data_page_, taint_value_, kPageSize);

  if (pid_ != 0) {
    memset(victim_data_page_, taint_value_, kPageSize);
    // main process returns when child is ready
    sem_wait(victim_started_semaphore_);
    return;
  }

  //
  // Child process
  //

  LOG_DEBUG("Child process starts...");
  InitChildProcess(victim_cpu_core);


  // double check that the victim data is still tainted
  if(victim_data_page_[0] != taint_value_ || 
      victim_data_page_[42] != taint_value_) {
    throw std::runtime_error("Data of child process is not correctly tainted!");
  }
  LOG_DEBUG("Child process initialized...");

  // signal main process that we are ready
  sem_post(victim_started_semaphore_);

  while(!shutdown_victim) {

    stop_signal_ready = true;
    if (StopSignalStart()) {
      if (FatalSignalStart()) {
        while (!shutdown_victim) {
          ((void(*)(char*))victim_code_page_)(victim_data_page_);
        }
      }
    }
  }  // while(!shutdown_victim)
  stop_signal_ready = false;


  LOG_DEBUG("Child shuts down.");
  // child process terminates after it's done
  std::exit(0);
}

void KernelVictim::Shutdown() {
  if (pid_ == -1) {
    // we never forked
    return;
  }

  if (pid_ == 0) {
    // the child can just exit
    LOG_DEBUG("Child exits...");
    std::exit(0);
  }

  // signal the child to stop
  // this triggers the childs SIGINT handler (registered in main())
  // and hence leads to a clean shutdown
  LOG_DEBUG("Signaling child " + std::to_string(pid_) + " to stop...");
  kill(pid_, SIGUSR1);

  // wait for child to finish (fallback to SIGKILL)
  bool child_stopped = false;
  int status = 0;
  for (size_t i = 0; i < 200; i++) {
    pid_t wait_result = waitpid(pid_, &status, WNOHANG);
    if (wait_result == pid_ || wait_result == -1) {
      child_stopped = true;
      break;
    }
    usleep(10000);  // 10ms
  }
  if (!child_stopped) {
    LOG_WARNING("KernelVictim did not stop in time. Sending SIGKILL.");
    kill(pid_, SIGKILL);
    waitpid(pid_, &status, 0);
  }
  LOG_DEBUG("Child stopped.");

  // reset PID to prevent accidental reuse of the victim object
  pid_ = -1;
}

}  // namespace trevex
