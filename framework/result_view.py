#! /usr/bin/env python3

from pwn import *
import sys
import json
from framework.common import *

# for syntax highlighting
from pygments import highlight
from pygments.lexers import NasmLexer
from pygments.formatters import TerminalFormatter

context.arch = 'amd64'

def fold_nops_together(disasm_str):
    folded_lines = []
    nop_count = 0
    for line in disasm_str.splitlines():
        # lines look like this:
        #  1eb:   90                      nop
        if line.split()[-1] == "nop":
            nop_count += 1
            folded_lines.append(line)
        else:
            if nop_count > 10:
                # remove the last nops and replace them with an alias
                first_nop_line = folded_lines[-nop_count]
                last_nop_line = folded_lines[-1]
                folded_lines = folded_lines[:-nop_count]
                folded_lines.append(first_nop_line)
                folded_lines.append(f"... (folded {nop_count-2} nops) ...")
                folded_lines.append(last_nop_line)
            nop_count = 0
            folded_lines.append(line)
    return "\n".join(folded_lines)
    

def view_testcase(
    testcase_fname,
    display_taint_dependency_infos=False):
    
    testcase_fname = autocomplete_testcase_fname(testcase_fname)

    try:
        with open(testcase_fname) as fd:
            parsed_file = json.load(fd)
    except FileNotFoundError:
        print("Could not find file.")
    except json.JSONDecodeError as e:
        print(f"Decoding error: {e}")

    # Use pygments for syntax highlighting
    lexer = NasmLexer()
    formatter = TerminalFormatter()

    leakage_code_b = b"".join([(i).to_bytes(1, byteorder='big') for i in parsed_file['leakage_code']])
    victim_code_b = b"".join([(i).to_bytes(1, byteorder='big') for i in parsed_file['victim_code']])
    cache_threshold = parsed_file['cache_miss_threshold']

    print(f"Cache Threshold: {cache_threshold}")
    print("=" * 30 + " Victim Code " + "=" * 30 + "\n")
    print(highlight(fold_nops_together(disasm(victim_code_b)), lexer, formatter))
    print("=" * 29 + " Attacker Code " + "=" * 29 + "\n")
    print(highlight(fold_nops_together(disasm(leakage_code_b)), lexer, formatter))

    leakage = parsed_file['observed_leakage']
    print("=" * 29 + " Leakage " + "=" * 29 + "\n")
    original = parsed_file['original_register_value']
    printed_org_value_already = False
    for idx in leakage:
        char = idx[0]
        hit_cnt = idx[1]
        ascii_repr = chr(char) if 0x20 <= char <= 0x7E else ""
        if char == original:
            print(f"0x{char:02x} ('{ascii_repr}') -> {hit_cnt} (original value)")
            printed_org_value_already = True
        else:
            print(f"0x{char:02x} ('{ascii_repr}') -> {hit_cnt}")
    if not printed_org_value_already:
        print(f"Original value: {hex(original)}")
    print("=" * 67)
    data_conditions = parsed_file['data_conditions']
    print("Data Conditions:")
    for data_condition in data_conditions:
        print(f"  {data_condition} "
              f"({data_condition_to_str[data_condition]})")
    if parsed_file['data_page_extra_conditions']:
        print(f"Data in TLB: {parsed_file['data_page_in_tlb']}")
        print(f"Data in Cache: {parsed_file['data_page_in_cache']}")
    if parsed_file['signal_number_caught'] != -1:
        print(f"Signal Caught: {signo_to_str[parsed_file['signal_number_caught']]}")
    else:
        print("Signal Caught: None.")

    if "classification-classes" in parsed_file:
        print(f"Classification (picked): {parsed_file['classification-classes'][0]}")

    if "classification-classes" in parsed_file:
        print(f"Classification (top N): {','.join(parsed_file['classification-classes'])}")
    
    if "taint_dependency" in parsed_file:
        print(f"Taint_dependency: {taint_dependency_to_str[parsed_file['taint_dependency']]} ")

    if "taint_to_peaklists" in parsed_file and display_taint_dependency_infos:
        print("\nTaint to Peaklists:")
        taint_to_peaklists = parsed_file["taint_to_peaklists"]
        for item in taint_to_peaklists:
            taint, peaklistlist = item
            print(f"  Taint {chr(taint)}")
            for peaklist in peaklistlist:
                print("    Peaklist: ", end='')
                for peak in peaklist:
                    if peak >= 0x20 and peak <= 0x7e:
                        print(f"{hex(peak)} ('{chr(peak)}'), ", end='')
                    else:
                        print(f"{hex(peak)}, ", end='')
                print()

