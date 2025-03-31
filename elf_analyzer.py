import argparse
from parser.elf_header import parse_elf_header
from parser.program_header import analyze_program_headers
from parser.section_header import analyze_section_headers
from parser.symbols import analyze_symbols


def main():
    parser = argparse.ArgumentParser(description="ELF Analyzer CLI Tool")
    parser.add_argument("file", help="Path to ELF file")
    parser.add_argument("--header", action="store_true", help="Parse ELF header")
    parser.add_argument("--segments", action="store_true", help="Analyze program headers (segments)")
    parser.add_argument("--sections", action="store_true", help="Analyze section headers")

    args = parser.parse_args()

    if args.header:
        parse_elf_header(args.file)

    if args.segments:
        analyze_program_headers(args.file)

    if args.sections:
        analyze_section_headers(args.file)
    
    if args.symbols:
        analyze_symbols(args.file)

    # If no specific flags given, do everything
    if not (args.header or args.segments or args.sections):
        print("[*] No specific analysis selected. Running full analysis...\n")
        parse_elf_header(args.file)
        analyze_program_headers(args.file)
        analyze_section_headers(args.file)
        analyze_symbols(args.file)

if __name__ == "__main__":
    main()
