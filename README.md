# bin_analyzer

`bin_analyzer` is a unified command-line tool for **static analysis** of both **ELF** (Linux) and **PE** (Windows) binaries. It parses headers, sections, imports/symbols, and can optionally check file hashes against the public CIRCL HashLookup database.

---

## Features

- **ELF & PE autodetection** based on file magic (`\x7fELF` vs `MZ`).
- **Modular analysis stages** (run one or all):
  - `--headers`  → ELF header or DOS+NT headers
  - `--sections` → ELF program & section headers or PE section analysis
  - `--imports`  → ELF symbol tables or PE import/export tables
  - `--circl`    → SHA256 hash lookup via CIRCL HashLookup (no API key required)
- **Interactive mode**: if no flags are provided, runs each stage in turn and prompts **`n`** (next) or **`q`** (quit).
- **Local and public threat intelligence**: integrate hash-based reputation checks without registration.

---

## Installation

```bash
git clone https://github.com/yourusername/bin_analyzer.git
cd bin_analyzer
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

```bash
./cli.py <path_to_binary> [options]
```

| Flag       | Description                                             |
|------------|---------------------------------------------------------|
| `--headers`  | Parse file header (ELF vs PE)                           |
| `--sections` | Analyze sections/segments (ELF prog+sect or PE secs)    |
| `--imports`  | Inspect imports/symbols (ELF symtab or PE import table)|
| `--circl`    | Lookup SHA256 hash in CIRCL HashLookup                  |

**Interactive full run** (no flags):
```bash
./cli.py /bin/ls
# -> run headers, sections, imports, prompt between each
```

**Selective run**:
```bash
./cli.py sample.exe --headers --imports --circl
```

---

## Project Layout

```
bin_analyzer/                 # project root
├── cli.py                    # main CLI entrypoint
├── elf_parse/                   # ELF parsing modules
│   ├── elf_header.py
│   ├── program_header.py
│   ├── section_header.py
│   └── symbols.py
├── pe_parse/              # PE parsing modules
│   ├── pe_header.py
│   ├── pe_sections.py
│   └── pe_imports.py
├── hashing/                  # hash & lookup modules
│   └── circl_lookup.py       # hash & CIRCL API integration
├── requirements.txt          # dependencies
└── .gitignore
```

---



---

## License

Licensed under MIT.
