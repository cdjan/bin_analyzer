import pefile

def analyze_pe_imports(file_path):
    """
    Parse the PE import table and print each DLL and its imported functions.
    """
    pe = pefile.PE(file_path)
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("\n[!] No import table found.")
        return

    print("\n== PE Import Table ==")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('utf-8', errors='ignore')
        print(f"\n-- DLL: {dll} --")
        for imp in entry.imports:
            name    = imp.name.decode('utf-8', errors='ignore') if imp.name else "<ordinal>"
            addr    = imp.address
            ordinal = imp.ordinal
            print(f"  {name:30} @0x{addr:x}  (ord {ordinal})")
