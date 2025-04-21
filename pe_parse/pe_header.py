import pefile

def parse_pe_header(file_path):
    pe = pefile.PE(file_path)

    print("== PE Header ==")

    # ─── DOS HEADER ─────────────────────────────────────────────
    # e_magic should be 0x5A4D (“MZ”)
    print(f"  DOS Signature: {hex(pe.DOS_HEADER.e_magic)}")
    # Offset from file start to the NT Headers
    print(f"  DOS Stub Size (e_lfanew): {pe.DOS_HEADER.e_lfanew} bytes")

    # ─── NT HEADERS (PE Signature + File & Optional Headers) ────
    print(f"  NT Signature: {hex(pe.NT_HEADERS.Signature)}")  # “PE\0\0”

    # ─── FILE HEADER ────────────────────────────────────────────
    fh = pe.FILE_HEADER
    print(f"  Machine: 0x{fh.Machine:x}     (# of Sections: {fh.NumberOfSections})")
    print(f"  TimeDateStamp: {fh.TimeDateStamp}     Characteristics: 0x{fh.Characteristics:x}")

    # ─── OPTIONAL HEADER ────────────────────────────────────────
    oh = pe.OPTIONAL_HEADER
    print(f"  Magic:                0x{oh.Magic:x}      Subsystem: {oh.Subsystem}")
    print(f"  AddressOfEntryPoint:  0x{oh.AddressOfEntryPoint:x}")
    print(f"  ImageBase:            0x{oh.ImageBase:x}")
