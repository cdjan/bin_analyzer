from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

def analyze_symbols(file_path):
    """Analyze ELF symbol tables (.symtab and .dynsym) and flag high-risk functions."""
    try:
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)
            print("\n== Symbol Tables ==")
            found = False

            # Iterate over all sections and look for symbol tables
            for section in elf.iter_sections():
                if section.name in ('.symtab', '.dynsym'):
                    found = True
                    print(f"\n-- {section.name} --")

                    # Iterate through all symbols in the table
                    for symbol in section.iter_symbols():
                        name = symbol.name
                        addr = symbol['st_value']
                        size = symbol['st_size']
                        bind = symbol['st_info']['bind']
                        typ = symbol['st_info']['type']
                        vis = symbol['st_other']['visibility']

                        print(f"  Symbol: {name}")
                        print(f"    Type: {typ}, Bind: {bind}, Visibility: {vis}")
                        print(f"    Address: 0x{addr:x}, Size: {size}")

                        # Flag known high-risk functions
                        if name in ('system', 'execve', 'dlopen', 'mprotect', 'ptrace'):
                            print(f"    [!] Warning: High-risk function '{name}'")

            if not found:
                print("  No symbol tables (.symtab or .dynsym) found.")

    except ELFError:
        print(f"[!] Error: '{file_path}' is not a valid ELF file.")
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"[!] Unexpected error analyzing symbols: {e}")