import pefile

def analyze_pe_sections(file_path):
    pe = pefile.PE(file_path)

    print("\n== PE Sections ==")
    for sec in pe.sections:
        # Decode the raw name (padded with nulls)
        name = sec.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
        va   = sec.VirtualAddress
        vsz  = sec.Misc_VirtualSize
        rsz  = sec.SizeOfRawData
        ch   = sec.Characteristics

        print(f"\n-- {name} --")
        print(f"  VA:    0x{va:x}   VirtSize: {vsz}   RawSize: {rsz}")
        print(f"  Chars: 0x{ch:x}")

        # IMAGE_SCN_MEM_EXECUTE (0x20000000) & IMAGE_SCN_MEM_WRITE (0x80000000)
        if (ch & 0x20000000) and (ch & 0x80000000):
            print("  [!] Suspicious: Section is both WRITABLE & EXECUTABLE")
