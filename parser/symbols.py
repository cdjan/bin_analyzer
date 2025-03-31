from elftools.elf.elffile import ELFFile

def analyze_symbols(file_path):
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        print("\n== Symbol Table ==")

        found_any = False

        for section in elf.iter_sections():
            if not isinstance(section, (
                # Static and dynamic symbols
                elf.structs.Elf_SymTableSectionClass, 
                elf.structs.Elf_DynSymSectionClass
            )) and section.name not in ['.symtab', '.dynsym']:
                continue

            print(f"\n-- Section: {section.name} --")
            found_any = True

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

                # Flag high-risk functions
                if name in ('system', 'execve', 'dlopen', 'mprotect', 'ptrace'):
                    print(f"    [!] Warning: High-risk function '{name}'")

        if not found_any:
            print("  No symbol table found.")
