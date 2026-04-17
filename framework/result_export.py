#! /usr/bin/env python3

from pwn import *
import json
import shutil
import subprocess
from capstone import *
from framework.common import *

# for syntax highlighting
from pygments import highlight
from pygments.lexers import NasmLexer
from pygments.formatters import TerminalFormatter

context.arch = 'amd64'

TEMPLATE_DIR = TREVEX_ROOT / "framework" / "export_template"
OUTPUT_DIR_DEFAULT = TREVEX_OUTPUT_DIR / "reproducers"

MARKER_ATK_CODE = "REPLACEMENT_MARKER_ATTACKER_CODE"
MARKER_VICTIM_CODE = "REPLACEMENT_MARKER_VICTIM_CODE"
MARKER_DATA_CONDITION= "REPLACEMENT_MARKER_DATA_CONDITION"
MARKER_ARCHMACRO = "REPLACEMENT_MARKER_ARCHMACRO"
MARKER_DP_EXTRA = "REPLACEMENT_MARKER_DATA_PAGE_EXTRA_CONDITIONS"
MARKER_DP_TLB = "REPLACEMENT_MARKER_DATA_PAGE_IN_TLB"
MARKER_DP_CACHE = "REPLACEMENT_MARKER_DATA_PAGE_IN_CACHE"


def disassemble_bytes(binary_repr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    disasm_code = ""
    for i in md.disasm(binary_repr, 0x0):
        disasm_code += f'        "{i.mnemonic} {i.op_str}\\n\\t"\n'
    return disasm_code
    

def parse_testcase(testcase_fname):
    try:
        with open(testcase_fname) as fd:
            parsed_file = json.load(fd)
    except FileNotFoundError:
        raise RuntimeError(f"Could not find file {testcase_fname}.")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Decoding error: {e}")
    return parsed_file


def format_asm(code):
    code_fmt = ""
    for line in code.split("\n"):
        code_fmt += f'        "{line}\\n\\t"\n'
    return code_fmt


def disassemble_testcase(parsed_testcase):
    leakage_code_b = b"".join([(i).to_bytes(1, byteorder='big') \
        for i in parsed_testcase['leakage_code']])
    victim_code_b = b"".join([(i).to_bytes(1, byteorder='big') \
        for i in parsed_testcase['victim_code']])

    attacker_asm = format_asm(disasm(leakage_code_b, offset=False, byte=False))
    victim_asm = format_asm(disasm(victim_code_b, offset=False, byte=False))

    return attacker_asm, victim_asm


def copy_reproducer_template(reproducer_dir):
    src = f"{TEMPLATE_DIR}/"

    if os.path.exists(reproducer_dir):
        shutil.rmtree(reproducer_dir)
    print(f"Copying reproducer template from {src} to {reproducer_dir}")
    shutil.copytree(src, reproducer_dir)


def replace_marker(fpath, marker, replacement):
    with open(fpath, 'r') as fd:
        original_data = fd.read()
    
    with open(fpath, "w") as fd:
        for line in original_data.split("\n"):
            if marker in line:
                line = replacement
            fd.write(line + "\n")

    
def build_c_array_str(elements):
    if len(elements) == 0:
        return "{};"
    s = "{"
    for i in elements:
        s += f"{i}, "
    s = s[:-2] + "};"  # remove last comma and space, add };
    return s
    

def export_result_testcase(
    testcase_fname,
    output_dir=None
    ):
    
    testcase_fpath = autocomplete_testcase_fname(testcase_fname)
    parsed_testcase = parse_testcase(testcase_fpath) 

    if output_dir is None:
        output_dir = OUTPUT_DIR_DEFAULT
        reproducer_fname = os.path.basename(testcase_fpath).strip(".json")
        output_dir = f"{output_dir}/{reproducer_fname}/"


    #
    # init template
    #
    copy_reproducer_template(output_dir)

    #
    # insert parameters to template
    #
    attacker_asm, victim_asm = disassemble_testcase(parsed_testcase)
    replace_marker(f"{output_dir}/main.c", MARKER_ATK_CODE, attacker_asm)
    replace_marker(f"{output_dir}/main.c", MARKER_VICTIM_CODE, victim_asm)

    #
    # AMD macro
    #
    vendor = get_cpu_vendor()
    if vendor == CPUVendor.Amd and not is_zen_1_cpu():
        replace_marker(f"{output_dir}/main.c", MARKER_ARCHMACRO, "#define AMD")
    else:
        replace_marker(f"{output_dir}/main.c", MARKER_ARCHMACRO, "//#define AMD")

    #
    # data page extra conditions
    #
    if parsed_testcase['data_page_extra_conditions']:
        replace_marker(f"{output_dir}/main.c", MARKER_DP_EXTRA, "#define DAGE_PAGE_EXTRA_CONDITIONS")
    else:
        replace_marker(f"{output_dir}/main.c", MARKER_DP_EXTRA, "//#define DATA_PAGE_EXTRA_CONDITIONS")

    if parsed_testcase['data_page_in_cache']:
        replace_marker(f"{output_dir}/main.c", MARKER_DP_CACHE, "#define DAGE_PAGE_IN_CACHE")
    else:
        replace_marker(f"{output_dir}/main.c", MARKER_DP_CACHE, "//#define DATA_PAGE_IN_CACHE")

    if parsed_testcase['data_page_in_tlb']:
        replace_marker(f"{output_dir}/main.c", MARKER_DP_TLB, "#define DAGE_PAGE_IN_TLB")
    else:
        replace_marker(f"{output_dir}/main.c", MARKER_DP_TLB, "//#define DATA_PAGE_IN_TLB")


    data_conditions_numbers = parsed_testcase['data_conditions']
    data_conditions = [data_condition_to_enum_str[i] for i in data_conditions_numbers]
    data_conditions_cstr = build_c_array_str(data_conditions)
    replace_marker(f"{output_dir}/main.c", MARKER_DATA_CONDITION, data_conditions_cstr)
    log_success(f"Reproducer stored in \n  '{output_dir}'")
