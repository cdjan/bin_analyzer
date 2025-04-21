#!/usr/bin/env python3
import argparse
import sys

from elftools.common.exceptions import ELFError
from elf_parse.elf_header       import parse_elf_header
from elf_parse.program_header   import analyze_program_headers
from elf_parse.section_header   import analyze_section_headers
from elf_parse.symbols          import analyze_symbols

from pe_parse.pe_header   import parse_pe_header
from pe_parse.pe_sections import analyze_pe_sections
from pe_parse.pe_imports  import analyze_pe_imports

# CIRCL HashLookup integration
from hashing.checkCircl   import check_file_with_circl

def detect_file_type(path):
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
    except FileNotFoundError:
        print(f"[!] Error: File '{path}' not found.")
        sys.exit(1)

    if magic.startswith(b'\x7fELF'):
        return 'ELF'
    if magic[:2] == b'MZ':
        return 'PE'
    return None


def wait_for_next():
    while True:
        choice = input("\nPress 'n' for next, 'q' to quit: ").strip().lower()
        if choice == 'n':
            return True
        elif choice == 'q':
            return False
        print("Invalid input: please press 'n' or 'q'.")


def main():
    parser = argparse.ArgumentParser(description="Unified ELF & PE Analyzer CLI")
    parser.add_argument("file", help="Path to ELF or PE file")
    parser.add_argument("--headers", action="store_true",
                        help="Parse file header (ELF vs PE)")
    parser.add_argument("--sections", action="store_true",
                        help="Analyze sections/segments")
    parser.add_argument("--imports", action="store_true",
                        help="Analyze imports/symbols or export table")
    parser.add_argument("--circl", action="store_true",
                        help="Check file hash against CIRCL HashLookup public API")
    args = parser.parse_args()

    ftype = detect_file_type(args.file)
    if not ftype:
        print("[!] Unknown format: not ELF or PE.")
        sys.exit(1)

    any_flag = args.headers or args.sections or args.imports or args.circl

    # ----- HEADER ANALYSIS -----
    if args.headers or not any_flag:
        print("\n== Header Analysis ==")
        if ftype == 'ELF':
            try:
                parse_elf_header(args.file)
            except ELFError:
                print(f"[!] Error: '{args.file}' is not a valid ELF file.")
                return
        else:
            parse_pe_header(args.file)
        if not any_flag and not wait_for_next():
            return

    # ----- SECTION/SEGMENT ANALYSIS -----
    if args.sections or not any_flag:
        print("\n== Section Analysis ==")
        if ftype == 'ELF':
            analyze_program_headers(args.file)
            analyze_section_headers(args.file)
        else:
            analyze_pe_sections(args.file)
        if not any_flag and not wait_for_next():
            return

    # ----- IMPORT/SYMBOL ANALYSIS -----
    if args.imports or not any_flag:
        print("\n== Import/Symbol Analysis ==")
        if ftype == 'ELF':
            analyze_symbols(args.file)
        else:
            analyze_pe_imports(args.file)
        if not any_flag and not wait_for_next():
            return

    # ----- CIRCL HASHLOOKUP -----
    if args.circl:
        print("\n== CIRCL HashLookup ==")
        check_file_with_circl(args.file)

if __name__ == "__main__":
    main()
