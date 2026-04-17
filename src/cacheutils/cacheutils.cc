#include <assert.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <limits.h>
#include <setjmp.h>
#include <fcntl.h>

#include <pthread.h>


#include "cacheutils.h"

#ifdef __cplusplus

using namespace std;
#include <cstdlib>
#include <cstring>

#endif // __cplusplus


#define ARM_PERF            1
#define ARM_CLOCK_MONOTONIC 2
#define ARM_TIMER           3

/* ============================================================
 *                    User configuration
 * ============================================================ */
size_t CACHE_MISS = 150;
int VICTIM_CORE = -1;
int ATTACKER_CORE = -1;
#define DIRECT_PHYS_MAP_BASE ((uint64_t)0xffff888000000000)


#define USE_RDTSC_BEGIN_END     0

#define USE_RDTSCP              0

#define ARM_CLOCK_SOURCE        ARM_CLOCK_MONOTONIC

/* ============================================================
 *                  User configuration End
 * ============================================================ */



// ---------------------------  Some useful macros  --------------------------
#define PAGESIZE 4096

#define speculation_start(label) asm goto ("call %l0" : : : "memory" : label##_retp);
#define speculation_end(label) asm goto("jmp %l0" : : : "memory" : label); label##_retp: asm goto("lea %l0(%%rip), %%rax\nmovq %%rax, (%%rsp)\nret\n" : : : "memory","rax" : label); label: asm volatile("nop");

// example usage: asm volatile(INTELASM("clflush [rax]\n\t"));
#define INTELASM(code) ".intel_syntax noprefix\n\t" code "\n\t.att_syntax prefix\n"

// ---------------------------------------------------------------------------
// requires root
uint64_t virtual_to_physical_address(void* virtual_address) {
  if (geteuid() != 0) {
    printf("[!] Error: virtual_to_physical_address() requires root privileges!\n");
    exit(-1);
  }
  static int pagemap = -1;
  if(pagemap == -1) {
    pagemap = open("/proc/self/pagemap", O_RDONLY);
    if(pagemap < 0) {
      printf("gimme root pls\n");
      exit(1);
    }
  }
  // Read the entry in the pagemap.
  uint64_t value;
  int got = pread(pagemap, &value, 8, ((size_t)(virtual_address) / 0x1000) * 8);
  if(got != 8) return 0;
  uint64_t page_frame_number = value & ((1ULL << 54) - 1);
  return page_frame_number * 0x1000 + ((size_t)virtual_address) % 0x1000;
} 

// ---------------------------------------------------------------------------
// requires root
char* get_kernel_address(void* vaddr) {
  // get_kernel_address() returns address of page in direct physical map
  uint64_t paddr = virtual_to_physical_address(vaddr);
  assert(paddr != 0);
  return (char*)(DIRECT_PHYS_MAP_BASE + paddr);
}


// ---------------------------------------------------------------------------
int get_sibling_hyperthread(int logical_core) {
  // shamelessly stolen from libsc
  char cpu_id_path[300];
  char buffer[16];
  snprintf(cpu_id_path, 300, "/sys/devices/system/cpu/cpu%d/topology/core_id", logical_core);

  FILE* f = fopen(cpu_id_path, "r");
  if(!f) return -1;
  volatile int dummy = fread(buffer, 16, 1, f);
  fclose(f);
  int phys = atoi(buffer);
  int hyper = -1;

  DIR* dir = opendir("/sys/devices/system/cpu/");
  if(!dir) return -1;
  struct dirent* entry;
  while((entry = readdir(dir)) != NULL) {
    if(entry->d_name[0] == 'c' && entry->d_name[1] == 'p' 
        && entry->d_name[2] == 'u' && (entry->d_name[3] >= '0' && entry->d_name[3] <= '9')) {
      snprintf(cpu_id_path, 300, "/sys/devices/system/cpu/%s/topology/core_id", entry->d_name);
      FILE* f = fopen(cpu_id_path, "r");
      if(!f) return -1;
      dummy += fread(buffer, 16, 1, f);
      fclose(f);
      int logical = atoi(entry->d_name + 3);
      if(atoi(buffer) == phys && logical != logical_core) {
        hyper = logical;
        break;
      }
    }
  }
  closedir(dir);
  return hyper;
}

// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
static size_t perf_fd;
void perf_init() {
  static struct perf_event_attr attr;
  attr.type = PERF_TYPE_HARDWARE;
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.size = sizeof(attr);
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.exclude_callchain_kernel = 1;

  perf_fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  //assert(perf_fd >= 0);

  // ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
}

#if defined(__i386__) || defined(__x86_64__)
// ---------------------------------------------------------------------------
//__attribute__((always_inline))
#ifdef AMD
inline uint64_t rdtsc() {
   uint64_t a, d;
  asm volatile("mfence");
  // rdpru from APERF
  asm volatile(".byte 0x0f,0x01,0xfd" : "=a"(a), "=d"(d) : "c"(1) : );
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

#else
inline uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  //asm volatile(".byte 0x0f,0x01,0xfd" : "=a"(a), "=d"(d) : "c"(1) : );
  asm volatile("mfence");
  a = (d << 32) | a;
  return a;
}
#endif

//#if defined(__x86_64__)
// ---------------------------------------------------------------------------
void maccess(void *p) {
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

// ---------------------------------------------------------------------------
void flush(void *p) {
  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}
//#else
//// ---------------------------------------------------------------------------
//inline void maccess(void *p) {
//  asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");
//}
//
//// ---------------------------------------------------------------------------
//void flush(void *p) {
//  asm volatile("clflush 0(%0)\n" : : "c"(p) : "eax");
//}
//#endif

// ---------------------------------------------------------------------------
void mfence() { asm volatile("mfence"); }

// ---------------------------------------------------------------------------
void cpuid_clear() { asm volatile("cpuid" :: "a"(0), "b"(0), "c"(0), "d"(0)); }

// ---------------------------------------------------------------------------
void nospec() { asm volatile("lfence"); }

#include <cpuid.h>
// ---------------------------------------------------------------------------
unsigned int xbegin() {
  unsigned status;
  asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00" : "=a"(status) : "a"(-1UL) : "memory");
  return status;
}

// ---------------------------------------------------------------------------
void xend() {
  asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");
}

// ---------------------------------------------------------------------------
int has_tsx() {
  if (__get_cpuid_max(0, NULL) >= 7) {
    unsigned a, b, c, d;
    __cpuid_count(7, 0, a, b, c, d);
    return (b & (1 << 11)) ? 1 : 0;
  } else {
    return 0;
  }
}

// ---------------------------------------------------------------------------
void maccess_tsx(void* ptr) {
    if (xbegin() == (~0u)) {
        maccess(ptr);
        xend();
    }
}

// ---------------------------------------------------------------------------
int flush_reload(void *ptr, int cache_miss) {
  uint64_t start = 0, end = 0;

#if USE_RDTSC_BEGIN_END
  start = rdtsc_begin();
#else
  start = rdtsc();
#endif
  maccess(ptr);
#if USE_RDTSC_BEGIN_END
  end = rdtsc_end();
#else
  end = rdtsc();
#endif

  mfence();

  flush(ptr);

  if (end - start < CACHE_MISS) {
    return 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
int flush_reload_t(void *ptr) {
  uint64_t start = 0, end = 0;

#if USE_RDTSC_BEGIN_END
  start = rdtsc_begin();
#else
  start = rdtsc();
#endif
  maccess(ptr);
#if USE_RDTSC_BEGIN_END
  end = rdtsc_end();
#else
  end = rdtsc();
#endif

  mfence();

  flush(ptr);

  return (int)(end - start);
}

// ---------------------------------------------------------------------------
int reload_t(void *ptr) {
  uint64_t start = 0, end = 0;

#if USE_RDTSC_BEGIN_END
  start = rdtsc_begin();
#else
  start = rdtsc();
#endif
  maccess(ptr);
#if USE_RDTSC_BEGIN_END
  end = rdtsc_end();
#else
  end = rdtsc();
#endif

  mfence();

  return (int)(end - start);
}


// ---------------------------------------------------------------------------
size_t detect_flush_reload_threshold() {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
  size_t dummy[16];
  size_t *ptr = dummy + 8;

  maccess(ptr);
  for (i = 0; i < count; i++) {
    reload_time += reload_t(ptr);
  }
  for (i = 0; i < count; i++) {
    flush_reload_time += flush_reload_t(ptr);
  }
  reload_time /= count;
  flush_reload_time /= count;

  return (flush_reload_time + reload_time * 2) / 3;
}

// ---------------------------------------------------------------------------
void maccess_speculative(void* ptr) {
    int i;
    size_t dummy = 0;
    void* addr;

    for(i = 0; i < 50; i++) {
        size_t c = ((i * 167) + 13) & 1;
        addr = (void*)(((size_t)&dummy) * c + ((size_t)ptr) * (1 - c));
        flush(&c);
        mfence();
        if(c / 0.5 > 1.1) maccess(addr);
    }
}


// ---------------------------------------------------------------------------
jmp_buf trycatch_buf;

// ---------------------------------------------------------------------------
void unblock_signal(int signum __attribute__((__unused__))) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, signum);
  sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

// ---------------------------------------------------------------------------
void trycatch_segfault_handler([[maybe_unused]] int signum) {
  unblock_signal(SIGSEGV);
  unblock_signal(SIGFPE);
  unblock_signal(SIGILL);
  unblock_signal(SIGTRAP);
  longjmp(trycatch_buf, 1);
}

// ---------------------------------------------------------------------------
int try_start() {
    if(has_tsx()) {
        unsigned status;
        // tsx begin
        asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00"
                 : "=a"(status)
                 : "a"(-1UL)
                 : "memory");
        return status == (~0u);
    } else {
        signal(SIGSEGV, trycatch_segfault_handler); 
        signal(SIGFPE, trycatch_segfault_handler); 
        return !setjmp(trycatch_buf);
    }
}

int tsx_start() {
  unsigned status;
  // tsx begin
  asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00"
           : "=a"(status)
           : "a"(-1UL)
           : "memory");
  return status == (~0u);
}

// ---------------------------------------------------------------------------
void try_abort() {
#if defined(__i386__) || defined(__x86_64__)
    if(has_tsx()) {
        asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");
    } else 
#endif
    {
        maccess(0);
    }
}

void tsx_abort() {
  asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");
}

void sig_abort() {
  maccess(0);
}


#endif

// ---------------------------------------------------------------------------
float median(int* arr, size_t n) {
  int temp;
  size_t i, j;
  // the following two loops sort the array x in ascending order
  for (i = 0; i < n - 1; i++) {
    for (j = i + 1; j < n; j++) {
      if (arr[j] < arr[i]) {
        // swap elements
        temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
      }
    }
  }

  if (n % 2 == 0) {
    // if there is an even number of elements, return mean of the two elements in the middle
    return ((arr[n / 2] + arr[n / 2 - 1]) / 2.0);
  } else {
    // else return the element in the middle
    return arr[n / 2];
  }
}

int average(int* arr, size_t n) {
  uint64_t sum = 0;
  for (size_t i = 0; i < n; i++) {
    sum += arr[i];
  }
  return sum / n;
}

int min(int* arr, size_t n) {
  int min_ele = INT_MAX;
  for (size_t i = 0; i < n; i++) {
    if (arr[i] < min_ele) {
      min_ele = arr[i];
    }
  }
  return min_ele;
}

// ---------------------------------------------------------------------------
int is_kpti_enabled() {
  char fname[] = "/sys/devices/system/cpu/vulnerabilities/meltdown";
  FILE* fd = fopen(fname, "r");
  if (fd == NULL) {
    printf("Couldn't open %s. Aborting!\n", fname);
    exit(0);
  }

  fseek(fd, 0, SEEK_END);
  size_t file_size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  char* file_content = (char*)malloc(file_size + 1);
  size_t nbytes = fread(file_content, 1, file_size, fd);
  if (nbytes != file_size) {
    printf("Couldn't read the content of %s. Aborting!\n", fname);
    exit(0);
  }
  file_content[file_size] = '\0';

  int kpti_enabled = strstr(file_content, "PTI") != NULL;
  fclose(fd);
  free(file_content);
  return kpti_enabled;
}
