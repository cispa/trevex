import sys
import time
import os
import json
import shutil
import pwd
import grp
from collections import defaultdict
from pwn import *
from framework.common import *

from pygments.lexers import NasmLexer
from pygments.formatters import TerminalFormatter

MINIMAL_HITS_TO_REPORT = 5
# report the top N accuracy as well
MAX_RULES_TO_APPLY = 3

context.arch = 'amd64'

MOV_RCX_ZERO = asm("mov rcx, 0x0")
MOVQ_XMM2_ZERO = asm("mov r9, 0x0;movq xmm2, r9")
MOVQ_XMM3_ZERO = asm("mov r9, 0x0;movq xmm3, r9")


class FilterRule():
    def __init__(self):
        # defaults to 0
        self.rules_applied = defaultdict(int)
        self.lexer = NasmLexer()
        self.formatter = TerminalFormatter()

    def correlation_confirmed(self, testcase_json):
        if testcase_json['taint_dependency'] == TaintDependency.untested:
            print(f"{bcolors.WARNING}[!] Warning: correlation not tested for {testcase_json['filename']}{bcolors.ENDC}")
        return testcase_json['taint_dependency'] == TaintDependency.confirmed
        
    def create_stats_print(self):
        s = ""
        for rule, count in self.rules_applied.items():
            s += f"[+] Applied {rule:40s}: {count} times\n"
        return s

    def create_stats_numbers(self):
        l = []
        for rule, count in self.rules_applied.items():
            l.append((rule,count))
        return l
    
    def create_leakage_dict(self, testcase_json):
        leakage = list_of_tuples_to_dict(testcase_json['observed_leakage'])
        leakage_filtered = dict()
        for idx, hit_count in leakage.items():
            if hit_count >= MINIMAL_HITS_TO_REPORT:
                leakage_filtered[idx] = hit_count
        return leakage_filtered

    def update_classification_entry(self, testcase_json, classification_str):
        # reload the file from disk
        filepath = testcase_json['filepath']
        try:
            with open(filepath, "r") as fd:
                testcase_json = json.load(fd)
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"Error re-opening the file {testcase_json['filepath']}")
            exit(1)

        # updates the entries in the source json file
        class_field_name = 'classification-classes'
        if class_field_name in testcase_json:
            entries = len(testcase_json[class_field_name])
            if entries >= MAX_RULES_TO_APPLY:
                # we ignore further rules
                return
            testcase_json[class_field_name].append(classification_str)
        else:
            testcase_json[class_field_name] = [classification_str]
        
        # rewrite the file to disk
        with open(filepath, 'w') as fd:
            json.dump(testcase_json, fd, indent=4)
        
        

    def does_apply(self, testcase_json, increase_stats_counters):
        applied, folder_name = self._does_apply(testcase_json)

            
        if applied:
            try:
                if self.correlation_confirmed(testcase_json):
                    folder_name = f"correlation/{folder_name}"
                    name = self.__class__.__name__ + "-correlation"
                else:
                    folder_name = f"no-correlation/{folder_name}"
                    name = self.__class__.__name__ + "-no-correlation"
            except KeyError: # handle older result files
                folder_name = f"correlation-untested/{folder_name}"
                name = self.__class__.__name__ + "-untested-correlation"
            if increase_stats_counters:
                self.rules_applied[folder_name] += 1
                self.rules_applied[name] += 1

            return True, folder_name
        return False, ""
    
    def get_attacker_code_bytes(self, testcase_json):
        code = b"".join([(i).to_bytes(1, byteorder='big') \
            for i in testcase_json['leakage_code']])
        return code

    def get_attacker_instr_str(self, testcase_json):
        code = b"".join([(i).to_bytes(1, byteorder='big') \
            for i in testcase_json['attacker_instruction']])
        return disasm(code)

    def is_memory_instr(self, testcase_json):
        # TODO: we could improve this by checking the instruction in capstone
        if "LODS" in testcase_json['filename']:
            return True
        return "[" in testcase_json["filename"]

    def condition_is_set(self, testcase_json, condition):
        assert condition in data_condition_to_enum_str.values()

        for set_cond in testcase_json['data_conditions']:
            if data_condition_to_enum_str[set_cond] == condition:
                return True
        return False

    def get_condition_prefix(self, testcase_json):
        prefix = ""
        if self.is_memory_instr(testcase_json):
            for cond in sorted(testcase_json['data_conditions']):
                cond = data_condition_to_enum_str[cond]
                if cond == "kNoAccessBit":
                    prefix = "access-bit/"
                    break
                if cond == "kSetDirtyBit":
                    prefix = "dirty-bit/"
                    break
                if cond == "kSetUncacheable":
                    prefix = "uc/"
                    break
                if cond == "kDefault":
                    prefix = "default/"
                    break
        return prefix
    
#
# Rule Definitions
#

class FilterMeltdown(FilterRule):
    def confirm_meltdown(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        if ord(DATA_PAGE_CONTENT) not in leakage:
            return False
        peaks = 0
        for _, hit_count in leakage.items():
            if hit_count >= 60:
                peaks += 1
        
        kernel_leakage = leakage[ord(DATA_PAGE_CONTENT)]
        return kernel_leakage >= 60 and peaks <= 4

    def _does_apply(self, testcase_json):
        is_kernel_page = self.condition_is_set(testcase_json, "kNoUserBit")
        is_mem_instr = self.is_memory_instr(testcase_json)
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        leaked_kernel_mem = ord(DATA_PAGE_CONTENT) in leakage
        non_zero_leakage = any([c != 0 for c in leakage])

        if "taint_dependency" in testcase_json:
            if testcase_json["taint_dependency"] == TaintDependency.confirmed:
                # meltdown does not correlate with the taint dep. 
                # that's more likely MDS
                return False, ""

        if is_kernel_page and faulted and is_mem_instr and non_zero_leakage:
            #confirm_status = "-confirmed" if self.confirm_meltdown(testcase_json) \
            #    else "-unconfirmed"
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"fault/{sigstr}/meltdown"
        return False, ""

class FilterGds(FilterRule):
    def confirm_gds(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        if ord(TAINT_VALUE) not in leakage:
            return False
        peaks = 0
        for _, hit_count in leakage.items():
            if hit_count >= 60:
                peaks += 1
        victim_leakage = leakage[ord(TAINT_VALUE)]
        return victim_leakage >= 60 and peaks <= 15
    def _does_apply(self, testcase_json):
        #leakage = testcase_json['observed_leakage']
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        is_gather = "GATHER" in testcase_json['filename']
        #confirm_status = "-confirmed" if self.confirm_gds(testcase_json) \
        #    else "-unconfirmed"

        if faulted and is_gather:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"fault/{sigstr}/gds"
        if not faulted and is_gather:
            return True, f"gds"
        return False, ""

class FilterMds(FilterRule):
    def confirm_mds(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        if ord(TAINT_VALUE) not in leakage:
            return False
        peaks = 0
        for _, hit_count in leakage.items():
            if hit_count >= 60:
                peaks += 1
        victim_leakage = leakage[ord(TAINT_VALUE)]
        return victim_leakage >= 60 and peaks <= 15

    def _does_apply(self, testcase_json):
        #leakage = testcase_json['observed_leakage']
        leakage = self.create_leakage_dict(testcase_json)
        leakage_raw = list_of_tuples_to_dict(testcase_json['observed_leakage'])
        faulted = testcase_json['observed_fault']
        #confirm_status = "-confirmed" if self.confirm_mds(testcase_json) \
        #    else "-unconfirmed"
        #correlation = self.correlation_confirmed(testcase_json)
        #if correlation and faulted: and len(leakage) >= 4:
        if faulted and len(leakage_raw) >= 4:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            # if AVX reg used and no mem load -> prob vector register sampling
            if ("XMM" in testcase_json['filename'] \
                    or "YMM" in testcase_json['filename'] \
                    or "ZMM" in testcase_json['filename']) \
                and not self.is_memory_instr(testcase_json):
                return True, f"fault/{sigstr}/mds-xmm"
            return True, f"fault/{sigstr}/mds"
        if not faulted and len(leakage_raw) >= 4:
            if "XMM" in testcase_json['filename'] \
                or "YMM" in testcase_json['filename'] \
                or "ZMM" in testcase_json['filename']:
                return True, f"mds-xmm"
            else:
                return True, f"mds"
        return False, ""

class FilterDss(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        non_zero_leakage = any([c != 0 for c in leakage])
        is_div = "DIV" in testcase_json['filename']
        if faulted:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            if sigstr == "sigfpe" and non_zero_leakage and is_div:
                code = self.get_attacker_code_bytes(testcase_json)
                atk_instr = self.get_attacker_instr_str(testcase_json)
                # ensure that we divide by either RCX or 
                # XMM2 (when it's the last operand, i.e., there's no xmm3)
                # (divs only use rcx, xmm2, or xmm3 as operand)
                div_by_zero = \
                    MOV_RCX_ZERO in code and ("cx" in atk_instr or "cl" in atk_instr) \
                    or (MOVQ_XMM2_ZERO in code \
                        and ("xmm2" in atk_instr and "xmm3" not in atk_instr)) \
                    or MOVQ_XMM3_ZERO in code and "xmm3" in atk_instr

                if div_by_zero:
                    return True, f"fault/{sigstr}/dss"
        return False, ""

class FilterTriad(FilterRule):
    def _does_apply(self, testcase_json):
        #leakage = testcase_json['observed_leakage']
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        if len(leakage) == 3 and faulted:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"fault/{sigstr}/triad"

        prefix = self.get_condition_prefix(testcase_json)
        if len(leakage) == 3 and not faulted:
            return True, f"{prefix}triad"
        return False, ""

class FilterStaleForward(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        reg_org = testcase_json['original_register_value']
        stale_forward = reg_org in leakage and reg_org != 0
        not_zero = 0 not in leakage  # prevent applying to ZF cases
        if len(leakage) <= 2 and stale_forward and faulted and not_zero:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"fault/{sigstr}/staleforward"

        if len(leakage) <= 2 and stale_forward and not faulted and not_zero:
            return True, "staleforward"
        return False, ""

class FilterStaleForwardInitial(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']

        potential_initial_values = [0x80, 0x83, 0xef]
        reg_org = testcase_json['original_register_value']

        initial_forward = reg_org not in leakage \
            and any([val in leakage for val in potential_initial_values])
        
        not_zero = 0 not in leakage  # prevent applying to ZF cases
        if len(leakage) <= 2 and initial_forward and faulted and not_zero:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"fault/{sigstr}/staleforward-initial"

        if len(leakage) <= 2 and initial_forward and not faulted and not_zero:
            return True, "staleforward-initial"
        return False, ""

class FilterLviNull(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        found_zero = 0 in leakage
        is_mem_instr = self.is_memory_instr(testcase_json)
        is_avx_instr = any(reg in testcase_json['filename'] \
            for reg in ["XMM","YMM", "ZMM"])
        is_avx_instr |= testcase_json['filename'].startswith("V")
        

        prefix = self.get_condition_prefix(testcase_json)
        if faulted and len(leakage) == 1 and found_zero and is_mem_instr:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            if is_avx_instr:
                return True, f"fault/{sigstr}/avx-null"
            else:
                return True, f"fault/{sigstr}/lvi-null"

        if not faulted and len(leakage) in [1,2,3] and found_zero and is_mem_instr:
            if is_avx_instr:
                return True, f"{prefix}avx-null"
            else:
                return True, f"{prefix}lvi-null"
        return False, ""
    
class FilterZeroForward(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        reg_org = testcase_json['original_register_value']
        found_zero = 0 in leakage

        prefix = self.get_condition_prefix(testcase_json)
        if faulted and len(leakage) == 1 and found_zero:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"fault/{sigstr}/zeroforward"

        if not faulted and len(leakage) in [1,2,3] and found_zero:
            return True, f"{prefix}zeroforward"
        return False, ""

class FilterDyad(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        reg_org = testcase_json['original_register_value']
        found_zero = 0 in leakage
        found_reg_org = reg_org in leakage
        found_data_org = ord(DATA_PAGE_CONTENT) in leakage

        prefix = self.get_condition_prefix(testcase_json)
        if faulted and len(leakage) == 2 and not found_zero:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"fault/{sigstr}/dyad"
        if not faulted and len(leakage) == 2 and not found_zero:
            return True, f"{prefix}dyad"
        return False, ""

class FilterFpviNull(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        found_zero = 0 in leakage
        is_mem_instr = self.is_memory_instr(testcase_json)
        if not faulted and len(leakage) == 2 and found_zero and not is_mem_instr:
            if any(reg in testcase_json['filename'] \
                for reg in ["XMM","YMM", "ZMM", "V"]):
                # float instruction
                return True, f"fpvi-null"
        return False, ""

class FilterFpvi(FilterRule):
    def _does_apply(self, testcase_json):
        leakage = self.create_leakage_dict(testcase_json)
        faulted = testcase_json['observed_fault']
        is_mem_instr = self.is_memory_instr(testcase_json)
        if not faulted and len(leakage) == 2 and not is_mem_instr:
            if any(reg in testcase_json['filename'] \
                for reg in ["XMM","YMM", "ZMM", "V"]):
                # float instruction
                return True, f"fpvi"
        return False, ""

class FilterFma(FilterRule):
    def _does_apply(self, testcase_json):
        faulted = testcase_json['observed_fault']
        fma_instrs = [
            "FMADD",
            "FMSUB",
            "VFNM"]
        if any(instr in testcase_json['filename'] for instr in fma_instrs):
            if faulted:
                sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
                return True, f"fault/{sigstr}/fma"
            else:
                return True, "fma"
        return False, ""

class FilterUnclustered(FilterRule):
    def _does_apply(self, testcase_json):
        faulted = testcase_json['observed_fault']
        if faulted:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            return True, f"unclustered/{sigstr}"
        else:
            return True, "unclustered"

class FilterKnownFalsePositives(FilterRule):
    def _does_apply(self, testcase_json):
        # ignore instructions with known false positives
        flaky_instrs = ["AES", 
                        "RDTSC", 
                        "RDRAND", 
                        "RDSEED", 
                        "SCAS",
                        "XCHG"]
        if any(instr in testcase_json['filename'] for instr in flaky_instrs):
            return True, "false-positive-flaky-instr"
        
        # ignore the combination of a single value + SIGFPE + unmasked FP 
        # exceptions as it *can* be caused by a SIGFPE after the actual testcode
        unmasked_fp = False
        for data_condition in testcase_json['data_conditions']:
            if data_condition_to_enum_str[data_condition] == "kUnmaskFpFaults":
                unmasked_fp = True
        if testcase_json['observed_fault'] and \
            signo_to_str[testcase_json['signal_number_caught']] == "SIGFPE" and unmasked_fp and \
            len(testcase_json['observed_leakage']) == 1:
            return True, "false-positive-unmasked-fp"
        
        # we use raw events here for FP detection
        leakage = testcase_json['observed_leakage']
        if len(leakage) >= 50:
            return True, "false-positive-too-much-leakage"

        if "EBX" in testcase_json['filename'] or \
           "RBX" in testcase_json['filename']:
            # we don't prime ebx/rbx so it registers using these are likely FP
            return True, "false-positive-rbx"
        faulted = testcase_json['observed_fault']
        if faulted:
            sigstr = signo_to_str[testcase_json['signal_number_caught']].lower()
            if sigstr == "sigtrap" and len(leakage) == 1:
                return True, f"false-positive/{sigstr}/trap-single"
        return False, ""
        
        
#
# Register Rules Here
#
            
RULES_TO_APPLY = [FilterKnownFalsePositives(), # must be the first
                  FilterGds(), # must be applied before MDS
                  FilterMeltdown(), # must be applied before MDS
                  FilterDss(),
                  FilterMds(),
                  FilterFma(),
                  FilterFpviNull(),
                  FilterFpvi(),
                  FilterLviNull(),
                  #FilterStaleForward(),
                  #FilterStaleForwardInitial(),
                  FilterTriad(),
                  FilterDyad(),
                  FilterZeroForward(),
                  FilterUnclustered(), # must be the last entry
                 ]

#
# End of Rules
#

OUT_DIR = TREVEX_OUTPUT_DIR / "./results-classified/"
NOFAULT_UNCLUSTERED_DIR = "unclustered"
FAULT_UNCLUSTERED_DIR = "fault/unclustered"
NOFAULT_UNCLUSTERED_COUNT = 0
FAULT_UNCLUSTERED_COUNT = 0


def reset_dirs(target_dir):
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)

def create_folder_if_needed(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
def move_to_unclustered(result_fpath, parsed_file):
    global NOFAULT_UNCLUSTERED_COUNT
    global FAULT_UNCLUSTERED_COUNT

    if parsed_file['observed_fault']:
        rule_folder = OUT_DIR + "/" + FAULT_UNCLUSTERED_DIR
        FAULT_UNCLUSTERED_COUNT += 1
    else:
        rule_folder = OUT_DIR + "/" + NOFAULT_UNCLUSTERED_DIR
        NOFAULT_UNCLUSTERED_COUNT += 1
    create_folder_if_needed(rule_folder)
    dst = rule_folder + "/" + os.path.basename(result_fpath)
    shutil.copyfile(result_fpath, dst)

def apply_rules(result_fpath, parsed_file, target_folder):
    destination_folder = None
    top_n_rules = list()
    for rule in RULES_TO_APPLY:
        # apply rule and ensure that only the first match (applied_any==False) increases the stat counters
        applies, folder_name = rule.does_apply(parsed_file, 
                increase_stats_counters= destination_folder is None)
        if applies:  # only move for the first matching rule
            if destination_folder is None:
                # first matching rule
                log_verbose(f"{os.path.basename(result_fpath)} classified as {folder_name}")
                destination_folder = folder_name
            top_n_rules.append(folder_name)

    if destination_folder is None:
        # no rule could be applied
        print("[!] No rule could be applied to ")
        move_to_unclustered(result_fpath, parsed_file)
        return False

    rule_folder = target_folder / destination_folder
    create_folder_if_needed(rule_folder)
    destination_fpath = rule_folder / os.path.basename(result_fpath)

    # write out file to the destination folder with added meta data
    parsed_file['classification-classes'] = top_n_rules[:MAX_RULES_TO_APPLY]
    with open(destination_fpath, 'w') as fd:
        json.dump(parsed_file, fd, indent=4)
    return True
    

def update_folder_permissions(folder_path):
    username = pwd.getpwuid(os.getuid()).pw_name
    groupname = grp.getgrgid(os.getgid()).gr_name
    log_verbose(f"Updating permissions of {folder_path} to user: {username}, group: {groupname}")
    os.system(f"sudo chown -R {username}:{groupname} {folder_path}")
    

def classify_results(
    verbose=False,
    min_threshold=None,
    source_dir=None,
    destination_dir=None,
    confirm=False,
    filename=None
    ):

    if verbose:
        print("verbose activated")
    
    if min_threshold is not None:
        MINIMAL_HITS_TO_REPORT = int(min_threshold)

    if source_dir is not None:
        src_folder = os.path.realpath(source_dir)
        if not os.path.exists(src_folder):
            print(f"[!] Source folder '{src_folder}' does not exist.")
            exit(1)
        # just add a suffix to the folder
        assert src_folder[-1] != "/"
        target_folder = Path(src_folder + "_clustered_results/")
    else:
        src_folder = RESULT_FOLDER
        target_folder = OUT_DIR
    
    reset_dirs(target_folder)

    # make permissions in that folder more permissive
    update_folder_permissions(src_folder)

    unclustered = 0
    if filename is not None:
        # single file clustering
        files_to_cluster = [filename]
    else:
        files_to_cluster = get_all_results(src_folder)
    
    if destination_dir is not None:
        target_folder = Path(destination_dir)

    for result_fpath in files_to_cluster:
        if os.path.basename(result_fpath) == "current_testcase.json":
            continue
    
        try:
            with open(result_fpath) as fd:
                parsed_file = json.load(fd)
        except FileNotFoundError:
            print("Could not find file.")
            exit(1)
        except json.JSONDecodeError as e:
            print(f"{result_fpath}: Decoding error: {e}")
            continue
        if "classification-classes" in parsed_file:
            print("[!] Warning: The files to cluster already contain 'classification-classes' entries.")
            print("    Please remove these entries before re-clustering by running 'remove_json_entry.py classification-classes <folder>'")
            print("    Alternatively, add the --confirm flag to proceed anyway. ONLY DO THIS IF YOU KNOW WHAT YOU ARE DOING!")
            if not confirm:
                print("Aborting.")
                exit(1)
            else:
                print("Proceeding despite the warning as per user request (--confirm).")
                sleep(3)

        parsed_file["filename"] = os.path.basename(result_fpath)
        parsed_file["filepath"] = result_fpath
        got_any_rule_match = apply_rules(result_fpath, parsed_file, target_folder)
        if not got_any_rule_match:
            unclustered += 1

    output = ""
    output_machine_readable = []
    for rule in RULES_TO_APPLY:
        output += rule.create_stats_print()
        output_machine_readable.extend(rule.create_stats_numbers())
    
    # sort output alphabetically
    lines = output.split("\n")
    lines.sort()
    output_machine_readable.sort(key=lambda x: x[0])
    for line in lines:
        print(line)
    print("=" * 70)
    print(f"[!] unclustered{':':20s} {NOFAULT_UNCLUSTERED_COUNT}")
    print(f"[!] fault/unclustered{':':14s} {FAULT_UNCLUSTERED_COUNT}")

    with open(target_folder / "stats.csv", 'w') as fd:
        fd.write("rule;applied_count\n")
        for rule_name, count in output_machine_readable:
            fd.write(f"{rule_name};{count}\n")

    print(f"[+] Wrote clustered results to {os.path.realpath(target_folder)}")
