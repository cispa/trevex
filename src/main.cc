// Copyright [2026] <Daniel Weber>

#include <iostream>
#include <vector>

#include <signal.h>
#include <setjmp.h>
#include <getopt.h>

#include "logger/logger.h"
#include "utils.h"
#include "core.h"

#include <asmjit/asmjit.h>

#define DEFAULT_INSTRUCTION_LIST "../src/external/x86-instructions/instructions.b64"

static jmp_buf sigint_jmpbuf;

void sigint_handler([[maybe_unused]] int sig_num) {
  longjmp(sigint_jmpbuf, 1);
}

struct CommandLineArguments {
  bool custom_instruction_list;
  std::string instruction_list;
  bool reproduce_testcase;
  bool reproduce_taint_dependency;
  std::string test_to_reproduce;
  bool verbose;
  CommandLineArguments() : custom_instruction_list(false),
      reproduce_testcase(false),
      reproduce_taint_dependency(false),
      verbose(false) {}
};

void PrintHelp(char** argv) {
  std::cout << "USAGE: " << argv[0] << std::endl
      << "-l <instruction-list>\tSpecify an alternative list of instructions "
      << std::endl
      << "-x <testcase>\t\tRerun given testcase" 
      << std::endl
      << "-t <testcase>\t\tRerun taint dependency test for given testcase"
      << std::endl
      << "-v \t\t\tVerbose mode" 
      << std::endl;
}

CommandLineArguments ParseArguments (int argc, char** argv) {
  CommandLineArguments command_line_arguments;
  const struct option long_options[] = {
      {"instruction_list", required_argument, nullptr, 'l'},
      {"reproduce", required_argument, nullptr, 'x'},
      {"taint_dependency", required_argument, nullptr, 't'},
      {"verbose", no_argument, nullptr, 'v'},
      {nullptr, 0, nullptr, 0}
  };

  int option_index;
  int c;
  while ((c = getopt_long(argc, argv, 
      "hvl:x:t:", long_options, &option_index)) != -1) {
    switch (c) {
      case '0':
        break;
      case 'l':
        command_line_arguments.custom_instruction_list = true;
        command_line_arguments.instruction_list = std::string(optarg);
        break;
      case 'x':
        command_line_arguments.reproduce_testcase = true;
        command_line_arguments.test_to_reproduce = std::string(optarg);
        break;
      case 't':
        command_line_arguments.reproduce_taint_dependency = true;
        command_line_arguments.test_to_reproduce = std::string(optarg);
        break;
      case 'v':
        command_line_arguments.verbose = true;
        break;
      case 'h':
      case '?':
      case ':':
        PrintHelp(argv);
        exit(0);
      default:
        std::cerr << "[-] Argument parsing failed. Aborting!" << std::endl;
        exit(1);
    }
  }
  return command_line_arguments;
}

void PrintBanner() {
  std::cout
    << "=================================================================" << std::endl
    << "        Trevex - Transient Execution Vulnerability Explorer      " << std::endl
    << "                                                                 " << std::endl
    << "             ############ ##        ##  ###    ###               " << std::endl
    << "  ===---          ##       ##      ##    ###  ###       --- ==== " << std::endl
    << "                  ##        ##    ##       ####                  " << std::endl
    << "  ==--- ---       ##         ##  ##       #####        ---  --== " << std::endl
    << "                  ##          ####      ###   ###                " << std::endl
    << "  ............                                  ###  ............" << std::endl
    << "=================================================================" << std::endl
    << "                                                                 " << std::endl
    << std::endl;
}


int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  CommandLineArguments args = ParseArguments(argc, argv);

  if (trevex::GotRootPrivileges() == false) {
    LOG_ERROR("Rerun with root privileges! Aborting!");
    return 1;
  }
  PrintBanner();

  trevex::InitRandomness();
  std::string instruction_list(DEFAULT_INSTRUCTION_LIST);
  if (args.custom_instruction_list) {
    LOG_INFO("Using custom instruction list " + args.instruction_list);
    instruction_list = args.instruction_list;
  }

  if (args.verbose) {
    trevex::SetLogLevel(trevex::DEBUG);
    LOG_INFO("Running in verbose mode.");
  } else {
    trevex::SetLogLevel(trevex::INFO);
  }

  try {
    trevex::Core core;
    signal(SIGINT, sigint_handler);  // handle CTRL+C
    signal(SIGABRT, sigint_handler);  // handle assertions

    if (!setjmp(sigint_jmpbuf)) {
      if (args.reproduce_testcase) {
        LOG_INFO("Reproducing given testcase");
        core.ReproduceResult(args.test_to_reproduce);
      } else if (args.reproduce_taint_dependency) {
        LOG_INFO("Reproducing taint dependency test for given testcase");
        core.ReproduceTaintDependency(args.test_to_reproduce);
      } else {
        LOG_INFO("Starting fuzzing run...");
        trevex::FuzzingConfig fuzzing_config;
        fuzzing_config.instruction_list = instruction_list;
        core.StartFuzzing(fuzzing_config);
      }
      LOG_INFO("Trevex finished.");

    } else {
      // we have to catch this signal to allow all destructors
      // to be called correctly
      LOG_DEBUG("Caught SIGINT.");
    }
  } catch(const std::exception& e) {
    LOG_ERROR(e.what());
    LOG_ERROR("Caught fatal exception. Aborting!");
  }

  return 0;
}
