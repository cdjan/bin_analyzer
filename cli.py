#!/usr/bin/env python3
import argparse
import sys

from elftools.common.exceptions import ELFError
from parser.elf_header       import parse_elf_header
from parser.program_header   import analyze_program_headers
from parser.section_header   import analyze_section_headers
from parser.symbols          import analyze_symbols

from pe_analyzer.pe_header   import parse_pe_header
from pe_analyzer.pe_sections import analyze_pe_sections
from pe_analyzer.pe_imports  import analyze_pe_imports


def detect_file_type(path):
    """
    Read the first few bytes to distinguish ELF vs PE.
    ELF files start with 0x7F 'E' 'L' 'F'
    PE files (DOS header) start with 'M' 'Z'
    """
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


def main():
    parser = argparse.ArgumentParser(
        description="Unified ELF & PE Analyzer CLI"
    )
    parser.add_argument("file", help="Path to ELF or PE file")

    # ELF flags
    parser.add_argument("--elf-header",   action="store_true", help="Parse ELF header")
    parser.add_argument("--elf-segments", action="store_true", help="Analyze ELF program headers")
    parser.add_argument("--elf-sections", action="store_true", help="Analyze ELF section headers")
    parser.add_argument("--elf-symbols",  action="store_true", help="Analyze ELF symbol tables")

    # PE flags
    parser.add_argument("--pe-header",   action="store_true", help="Parse PE header (DOS+NT)")
    parser.add_argument("--pe-sections", action="store_true", help="Analyze PE sections")
    parser.add_argument("--pe-imports",  action="store_true", help="Analyze PE import table")

    args = parser.parse_args()
    ftype = detect_file_type(args.file)
    if not ftype:
        print("[!] Unknown file format. Not ELF or PE.")
        sys.exit(1)

    # Helper to check if *any* module-flag was passed
    any_flag = any([
        args.elf_header, args.elf_segments, args.elf_sections, args.elf_symbols,
        args.pe_header,  args.pe_sections,  args.pe_imports
    ])

    # ---- ELF path ----
    if ftype == 'ELF':
        if args.elf_header or not any_flag:
            try:
                parse_elf_header(args.file)
            except ELFError:
                print(f"[!] Error: '{args.file}' is not a valid ELF file.")
                return
        if args.elf_segments or not any_flag:
            analyze_program_headers(args.file)
        if args.elf_sections or not any_flag:
            analyze_section_headers(args.file)
        if args.elf_symbols or not any_flag:
            analyze_symbols(args.file)

    # ---- PE path ----
    elif ftype == 'PE':
        if args.pe_header or not any_flag:
            parse_pe_header(args.file)
        if args.pe_sections or not any_flag:
            analyze_pe_sections(args.file)
        if args.pe_imports or not any_flag:
            analyze_pe_imports(args.file)


if __name__ == "__main__":
    main()
