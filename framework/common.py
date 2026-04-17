#! /usr/bin/env python3

import os
from pathlib import Path
import subprocess
from enum import IntEnum

SCRIPT_LOCATION = Path(__file__).resolve().parent
TREVEX_ROOT = SCRIPT_LOCATION.parent
# the folder created by 'run.sh'
TREVEX_BUILD_DIR = TREVEX_ROOT / "build"
TREVEX_OUTPUT_DIR = TREVEX_ROOT / "out"
RESULT_FOLDER = TREVEX_BUILD_DIR / "results"

TREVEX_TMUX_SESSION_NAME = "trevex"
TREVEX_PROGRESS_FNAME = ".trevex.progress"

TVX_VERBOSE_MODE = False


TAINT_VALUE = 'V'
DATA_PAGE_CONTENT = 'D'
PROBE_PAGE_CONTENT = 'P'

def set_verbose_mode(verbose):
    global TVX_VERBOSE_MODE
    TVX_VERBOSE_MODE = verbose

def in_verbose_mode():
    return TVX_VERBOSE_MODE

class CPUVendor(IntEnum):
    Intel = 0
    Amd = 1
    Zhaoxin = 2

def get_cpu_vendor():
    with open("/proc/cpuinfo", "r") as fd:
        for line in fd:
            if line.startswith("vendor_id"):
                vendor_id = line.split()[2]
                break
        else:
            raise RuntimeError("Failed to get CPU vendor from /proc/cpuinfo")
    if vendor_id == "GenuineIntel":
        return CPUVendor.Intel
    elif vendor_id == "AuthenticAMD":
        return CPUVendor.Amd
    elif vendor_id == "CentaurHauls":
        return CPUVendor.Zhaoxin
    else:
        raise RuntimeError(f"Unrecognized CPU vendor: {vendor_id}")
    

def is_zen_1_cpu():
    p_err, p_stdout, _ = run_cmd("cpuid -1")
    if p_err != 0:
        raise RuntimeError("Failed to run cpuid to check for Zen 1 CPU")
    for line in p_stdout.splitlines():
        if "Zen," in line or "Zen+," in line:
            return True
    return False


def run_cmd(cmd, working_dir=None, verbose=False, raw_mode=False, timeout=None):
    if verbose:
        print(f"{bcolors.VERBOSE}Running command: {cmd}{bcolors.ENDC}")
    if (isinstance(cmd, list)):
        cmd = " ".join(cmd)
    
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, check=False, cwd=working_dir, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        log_warning(f"Command timed out after {timeout} seconds: {cmd}")
        return -1, "", ""
    if raw_mode:
        return proc.returncode, proc.stdout, proc.stderr
    else:
        return proc.returncode, proc.stdout.decode('utf-8'), proc.stderr.decode('utf-8')


def get_all_results(folder=None):
    if folder == None:
        folder = RESULT_FOLDER
    all_results = list()
    for fname in os.listdir(folder):
        fpath = os.path.join(folder, fname)

        if os.path.isfile(fpath):
            all_results.append(fpath)
        else:
            print(f"skipping {fname}")
    return all_results


def list_of_tuples_to_dict(l):
    d = dict()
    for key, val in l:
        d[key] = val
    return d


def autocomplete_testcase_fname(testcase_fname):
    if testcase_fname[0] != "/" and testcase_fname[0] != "." \
        and testcase_fname[0] != "~":
        testcase_fname = f"{RESULT_FOLDER}/{testcase_fname}"
    return testcase_fname
    

# some colors
class bcolors:
   HEADER = '\033[95m'
   OKBLUE = '\033[94m'
   OKGREEN = '\033[92m'
   WARNING = '\033[93m'
   VERBOSE = '\033[96m'
   FAIL = '\033[91m'
   ENDC = '\033[0m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   GRAY = '\033[90m'

def log_error(message):
    print(f"{bcolors.FAIL}[-] {message}{bcolors.ENDC}")

def log_warning(message):
    print(f"{bcolors.WARNING}[-] {message}{bcolors.ENDC}")

def log_info(message):
    print(f"{bcolors.OKBLUE}[+] {message}{bcolors.ENDC}")

def log_verbose(message):
    if TVX_VERBOSE_MODE:
        print(f"{bcolors.OKBLUE}[+] {message}{bcolors.ENDC}")

def log_success(message):
    print(f"{bcolors.OKGREEN}[+] {message}{bcolors.ENDC}")

class TaintDependency(IntEnum):
    untested = 0
    unconfirmed = 1
    confirmed = 2

signo_to_str = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}

   
# this is a representation of the enum class ConditionDataPage (executor.h)
data_condition_to_raw_str = {
    0: "userbit",
    1: "accessbit",
    2: "presentbit",
    3: "uncachable",
    4: "set-dirtybit",
    5: "clear-dirtybit",
    6: "unmask-fp-faults",
    7: "default"
}

# this is a representation of the enum class ConditionDataPage (executor.h)
data_condition_to_enum_str = {
    0: "kNoUserBit",
    1: "kNoAccessBit",
    2: "kNoPresentBit",
    3: "kSetUncacheable",
    4: "kSetDirtyBit",
    5: "kClearDirtyBit",
    6: "kUnmaskFpFaults",
    7: "kDefault"
}

# this is a representation of the enum class ConditionDataPage (executor.h)
data_condition_to_str = {
    0: f"{bcolors.WARNING}kNoUserBit{bcolors.ENDC}",
    1: f"{bcolors.VERBOSE}kNoAccessBit{bcolors.ENDC}",
    2: f"{bcolors.FAIL}kNoPresentBit{bcolors.ENDC}",
    3: f"{bcolors.OKBLUE}kSetUncachable{bcolors.ENDC}",
    4: f"{bcolors.GRAY}kSetDirtyBit{bcolors.ENDC}",
    5: f"{bcolors.GRAY}kClearDirtyBit{bcolors.ENDC}",
    6: f"{bcolors.GRAY}kUnmaskFpFaults{bcolors.ENDC}",
    7: "kDefault",
}

# this is a representation of the enum class TaintDependency
taint_dependency_to_str = {
    0: f"{bcolors.GRAY}kUntested{bcolors.ENDC}",
    1: f"{bcolors.VERBOSE}kUnconfirmed{bcolors.ENDC}",
    2: f"{bcolors.WARNING}kConfirmed{bcolors.ENDC}",
}
