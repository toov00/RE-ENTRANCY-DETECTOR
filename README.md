# RE-ENTRANCY DETECTOR

A static analysis tool that scans Solidity smart contracts for re-entrancy vulnerabilities.

## Getting Started

### Prerequisites

* Python 3.8+
```sh
  python --version
```
* (Optional) pytest for running tests
```sh
  pip install pytest
```

### Installation

1. Clone the repo
```sh
   git clone https://github.com/toov00/reentrancy-detector.git
```
2. Navigate to project directory
```sh
   cd reentrancy-detector
```
3. (Optional) Install as package
```sh
   pip install -e .
```

## Usage

1. Scan a single Solidity file
```sh
   python -m src.cli scan examples/vulnerable_bank.sol
```
2. Scan an entire directory
```sh
   python -m src.cli scan ./contracts/
```
3. Output as JSON
```sh
   python -m src.cli scan contract.sol --format json -o report.json
```
4. Verbose mode (shows code snippets)
```sh
   python -m src.cli scan contract.sol --verbose
```
5. Example output
```
   [CRITICAL] State Change After External Call
   ├── Contract: VulnerableBank
   ├── Function: withdraw()
   ├── Line: 25
   └── Remediation: Apply Checks-Effects-Interactions pattern
   
   Summary: 2 Critical, 1 High, 0 Medium, 0 Low
```

## Detection Rules

| Pattern | Severity | Description |
|---------|----------|-------------|
| State change after call | Critical | State modified after external call |
| External call in loop | High | `.call()` inside for/while loops |
| Delegatecall usage | High | Executes foreign code in your context |
| Missing reentrancy guard | Medium | No `nonReentrant` modifier |
| Cross-function reentrancy | Medium | Shared state across functions |

## Roadmap

- [x] Detect classic reentrancy (state change after call)
- [x] Detect external calls in loops
- [x] Detect delegatecall risks
- [x] Detect missing reentrancy guards
- [x] Detect cross-function reentrancy
- [x] JSON/Markdown/Text output formats
- [x] VS Code extension (see `vscode-extension/` directory for manual installation)
- [ ] Support for Vyper contracts
- [ ] GitHub Actions integration

## VS Code Extension

A VSCode extension is available in the `vscode-extension/` directory. To use it:

1. Install the Python package: `pip install -e .`
2. Build the extension: `cd vscode-extension && npm install && npm run compile && npm run package`
3. Install: `code --install-extension reentrancy-detector-1.0.0.vsix`
4. Configure Python path in VSCode settings if needed

See `vscode-extension/README.md` for detailed instructions.
