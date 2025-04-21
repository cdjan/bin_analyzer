from elftools.elf.elffile import ELFFile

def parse_elf_header(file_path):
    """Parses the ELF header and prints basic info."""
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)

        print("== ELF Header ==")
        print(f"  Class:       {elf.elfclass}-bit")
        print(f"  Machine:     {elf['e_machine']}")
        print(f"  File Type:   {elf['e_type']}")
        print(f"  Entry Point: 0x{elf.header['e_entry']:x}")
