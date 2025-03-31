from elftools.elf.elffile import ELFFile

def analyze_section_headers(file_path):
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        print("\n== Section Headers ==")

        for section in elf.iter_sections():
            name = section.name
            addr = section['sh_addr']
            size = section['sh_size']
            flags = section['sh_flags']

            print(f"\n-- Section: {name} --")
            print(f"  Address:  0x{addr:x}")
            print(f"  Size:     {size} bytes")
            print(f"  Flags:    {flags:#x}")

            # Flag suspicious RWX (Read/Write/Execute) combos
            is_writable = flags & 0x1
            is_alloc    = flags & 0x2
            is_executable = flags & 0x4

            if is_writable and is_executable:
                print("  [!] Suspicious: Section is both writable and executable")

            # Flag unusually large sections (e.g., embedded payloads)
            if size > 10 * 1024 * 1024:  # >10 MB
                print("  [!] Suspicious: Section is unusually large")
