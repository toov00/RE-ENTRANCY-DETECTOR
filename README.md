# Re-entrancy Detector

A static analysis tool for detecting re-entrancy vulnerabilities in Solidity smart contracts. This tool scans your contract code and identifies patterns that could lead to re-entrancy attacks, one of the most common and dangerous security issues in smart contract development.

## Overview

Re-entrancy attacks occur when an external contract calls back into your contract before the current execution completes, potentially draining funds or manipulating state. This detector identifies several re-entrancy patterns:

- State changes after external calls (classic re-entrancy)
- External calls within loops
- Missing reentrancy guards
- Cross-function re-entrancy patterns
- Delegatecall risks

The tool provides detailed reports with line numbers, severity levels, and remediation suggestions to help you secure your contracts.

## Installation

### Requirements

- Python 3.8 or higher
- pip (Python package manager)

Verify your Python version:

```bash
python --version
```

### Setup

1. Clone the repository:

```bash
git clone https://github.com/toov00/reentrancy-detector.git
cd reentrancy-detector
```

2. Install the package (optional but recommended):

```bash
pip install -e .
```

This installs the detector as a Python package, making it available from anywhere on your system.

### Running Tests

To run the test suite, install pytest and execute:

```bash
pip install pytest
pytest tests/
```

## Usage

### Command Line Interface

The detector can be used via the command line to scan individual files or entire directories.

#### Scan a Single File

```bash
python -m src.cli scan examples/vulnerable_bank.sol
```

#### Scan a Directory

```bash
python -m src.cli scan ./contracts/
```

Recursive directory scanning is enabled by default. The tool will process all `.sol` files found in the specified directory and subdirectories.

#### Output Formats

The detector supports multiple output formats for integration with other tools:

**JSON output:**

```bash
python -m src.cli scan contract.sol --format json -o report.json
```

**Markdown output:**

```bash
python -m src.cli scan contract.sol --format markdown -o report.md
```

**Verbose mode (includes code snippets):**

```bash
python -m src.cli scan contract.sol --verbose
```

#### Severity Filtering

Filter results by minimum severity level:

```bash
python -m src.cli scan contract.sol --severity high
```

Available severity levels: `critical`, `high`, `medium`, `low`, `info`

### Example Output

```
[CRITICAL] State Change After External Call
├── Contract: VulnerableBank
├── Function: withdraw()
├── Location: Line 31
├── External call: call at line 31
├── State change: balances at line 34
├── Remediation: Apply the Checks-Effects-Interactions pattern: 
│   1) Check conditions, 2) Update state variables, 3) Make external calls.
│   Alternatively, use OpenZeppelin's ReentrancyGuard with the nonReentrant modifier.
└── Confidence: high

Summary: 2 Critical, 1 High, 0 Medium, 0 Low
```

## Detection Patterns

The detector identifies the following re-entrancy patterns:

| Pattern | Severity | Description |
|---------|----------|-------------|
| State change after call | Critical | State variable modified after an external call, allowing re-entrancy before state update |
| External call in loop | High | External calls (`.call()`, `.transfer()`, etc.) executed inside loops, increasing attack surface |
| Delegatecall usage | High | Delegatecall patterns that execute foreign code in your contract's context |
| Missing reentrancy guard | Medium | Functions making external calls without `nonReentrant` modifier or equivalent protection |
| Cross-function reentrancy | Medium | Shared state accessed across multiple functions, enabling cross-function re-entrancy attacks |

### Pattern Details

**State Change After Call (Critical)**

This is the classic re-entrancy vulnerability. When state is modified after an external call, an attacker can call back into your function before the state update completes, potentially draining funds.

**External Call in Loop (High)**

External calls within loops are dangerous because they can be exploited multiple times in a single transaction. If one call fails or is exploited, the entire loop execution can be compromised.

**Missing Reentrancy Guard (Medium)**

While not always a vulnerability, functions that make external calls should typically use reentrancy guards as a defense-in-depth measure.

## Integration

### VS Code Extension

A VS Code extension is available for real-time analysis as you code. See the `vscode-extension/` directory for installation and configuration instructions.

The extension provides:
- Real-time vulnerability detection
- Inline diagnostics in the Problems panel
- Automatic analysis on file save
- Workspace-wide scanning

### CI/CD Integration

The JSON output format makes it easy to integrate the detector into your CI/CD pipeline:

```bash
python -m src.cli scan ./contracts/ --format json -o results.json
```

Parse the JSON output in your CI scripts to fail builds when critical vulnerabilities are detected.

## Project Structure

```
reentrancy-detector/
├── src/
│   ├── cli.py           # Command-line interface
│   ├── detector.py       # Main detection engine
│   ├── parser.py         # Solidity parser
│   ├── patterns.py       # Re-entrancy pattern definitions
│   ├── models.py         # Data models
│   └── reporter.py       # Output formatting
├── examples/             # Example contracts (vulnerable and safe)
├── tests/                # Test suite
├── vscode-extension/     # VS Code extension (see README in that directory)
└── README.md
```

## Examples

The `examples/` directory contains sample contracts demonstrating various re-entrancy patterns:

- `vulnerable_bank.sol`: Classic re-entrancy vulnerability
- `safe_bank.sol`: Secure implementation using checks-effects-interactions pattern
- `cross_function.sol`: Cross-function re-entrancy example

These examples can be used to understand the patterns the detector identifies and to verify the tool is working correctly.

## Roadmap

Completed features:
- Classic re-entrancy detection (state change after call)
- External calls in loops detection
- Delegatecall risk detection
- Missing reentrancy guard detection
- Cross-function re-entrancy detection
- Multiple output formats (JSON, Markdown, Text)
- VS Code extension

Planned features:
- Support for Vyper contracts
- GitHub Actions integration
- Additional pattern detection
- Performance optimizations for large codebases

## Contributing

Contributions are welcome. Please ensure your code follows the existing style and includes appropriate tests.

## License

MIT License. See LICENSE file for details.

## References

The detector is based on established security best practices and references:

- SWC-107: Reentrancy vulnerability
- SWC-113: DoS with Failed Call
- Consensys Smart Contract Best Practices
- OpenZeppelin ReentrancyGuard documentation
