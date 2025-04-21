from elftools.elf.elffile import ELFFile

def analyze_program_headers(file_path):
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        print("\n== Program Headers ==")
        lowest_vaddr = None

        for idx, segment in enumerate(elf.iter_segments()):
            print(f"\n-- Segment {idx} --")
            print(f"  Type:     {segment['p_type']}")
            print(f"  Offset:   0x{segment['p_offset']:x}")
            print(f"  Vaddr:    0x{segment['p_vaddr']:x}")
            print(f"  MemSize:  0x{segment['p_memsz']:x}")
            print(f"  Flags:    {segment['p_flags']}")

            flags = segment['p_flags']
            if flags & 4 and flags & 2 and flags & 1:  # R/W/E
                print("  [!] Suspicious: R/W/E permissions")

            if segment['p_type'] == 'PT_LOAD':
                vaddr = segment['p_vaddr']
                if lowest_vaddr is None or vaddr < lowest_vaddr:
                    lowest_vaddr = vaddr

        if lowest_vaddr is not None:
            print(f"\n[+] Base Address (lowest PT_LOAD): 0x{lowest_vaddr:x}")
        else:
            print("\n[!] No PT_LOAD segments found.")
