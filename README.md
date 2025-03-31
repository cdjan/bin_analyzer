# elf_analyzer
# ELF Analyzer CLI Tool

The **ELF Analyzer** is a command-line tool designed to perform static analysis on ELF binaries (Linux executables and shared libraries). It helps engineers, security analysts, and reverse engineers inspect and understand various properties of ELF files, identify anomalies, and flag potentially malicious behavior.

## Features

- ✅ Parse and display the ELF header (architecture, file type, entry point)
- ✅ Analyze program headers (segments) and detect suspicious memory mappings
- ✅ Analyze section headers for obfuscation, RWX permissions, and large sections
- ✅ Inspect symbol tables to list function names, types, and high-risk APIs
- 🚧 Modular architecture to expand analysis with entropy checks, YARA rules, etc.

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/elf-analyzer.git
cd elf-analyzer
```

### 2. Create and Activate a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

## Usage

Run the script and specify an ELF file along with one or more analysis options:

```bash
python elf_analyzer.py <path_to_elf_file> [options]
```

### Options:
| Option        | Description                                       |
|---------------|---------------------------------------------------|
| `--header`    | Display ELF header information                    |
| `--segments`  | Analyze program headers (loadable segments)       |
| `--sections`  | Analyze section headers                           |
| `--symbols`   | Inspect the symbol table                          |

If no options are provided, the tool will run **all available analyses** by default.

### Example:
```bash
python elf_analyzer.py /bin/ls --header --symbols
```

## Project Structure
```
elf_analyzer/
├── elf_analyzer.py          # Main CLI script
├── parser/
│   ├── elf_header.py        # ELF header parsing
│   ├── program_header.py    # Segment analysis
│   ├── section_header.py    # Section analysis
│   └── symbols.py           # Symbol table analysis
├── venv/                    # Virtual environment (not committed)
└── .gitignore               # Git ignore file
```

## Contributing
Feel free to fork the repo and submit pull requests with new analysis modules, bug fixes, or improvements.

## License
MIT License

---



