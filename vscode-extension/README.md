# Re-entrancy Detector VSCode Extension

A VSCode extension that analyzes Solidity code to find re-entrancy patterns. It reads your code and shows potential issues in the Problems panel.

## Prerequisites

Before building this extension, you must:

1. **Install the Python analyzer** (from the repository root):
   ```bash
   cd /path/to/reentrancy-detector
   pip install -e .
   ```

2. **Install Node.js 20+** (required for building):
   ```bash
   node --version  # Should be v20 or higher
   ```

## Installation

### Step 1: Install Dependencies

```bash
cd vscode-extension
npm install
```

### Step 2: Build the Extension

```bash
npm run compile
```

### Step 3: Package the Extension

```bash
npm install -g @vscode/vsce
npm run package
```

This creates `reentrancy-detector-1.0.0.vsix` in the current directory.

### Step 4: Install the Extension

```bash
code --install-extension reentrancy-detector-1.0.0.vsix
```

## Configuration

After installation, configure the extension in VSCode Settings:

1. Open Settings (`Ctrl+,` or `Cmd+,`)
2. Search for "reentrancy-detector"
3. Configure:
   - **Python Path**: Path to your Python 3 interpreter (default: `python3`)
   - **Analyzer Path**: Full path to `analyzer_server.py` if the default doesn't work
   - **Enable**: Turn the extension on/off
   - **Run On Save**: Check files automatically on save
   - **Severity Threshold**: Minimum severity to show (critical, high, medium, low, info)

## Usage

### Automatic Analysis

The extension automatically analyzes Solidity files when:
- A file is opened
- A file is saved (if `reentrancy-detector.runOnSave` is enabled)

### Manual Commands

- **Check Current File**: Run `Re-entrancy Detector: Check for Re-entrancy` from the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
- **Check Workspace**: Run `Re-entrancy Detector: Check Workspace for Re-entrancy` to scan all `.sol` files in the workspace

## Detection Patterns

The extension detects the following re-entrancy patterns:

| Pattern | Severity | Description |
|---------|----------|-------------|
| State change after call | Critical | State modified after external call |
| External call in loop | High | `.call()` inside for/while loops |
| Delegatecall usage | High | Delegatecall patterns detected |
| Missing reentrancy guard | Medium | No `nonReentrant` modifier |
| Cross-function reentrancy | Medium | Shared state across functions |

## Output

Code issues are displayed in the VSCode Problems panel with:
- Severity level (Error/Warning/Info)
- Line number and location
- Description and remediation suggestions
- Issue type code

## Troubleshooting

### Extension Not Working

1. Ensure the Python analyzer is installed: `pip install -e .` (from repo root)
2. Check that Python 3.8+ is installed and accessible
3. Verify the analyzer can be imported (check Output panel → "Re-entrancy Detector")
4. If using a virtual environment, ensure VSCode is using the correct Python interpreter
5. Set `reentrancy-detector.pythonPath` in settings to point to your Python executable
6. Set `reentrancy-detector.analyzerPath` to the full path of `analyzer_server.py` if needed

### No Results Showing

1. Check the severity threshold setting
2. Verify the file is a valid Solidity file (`.sol` extension)
3. Check the Output panel for error messages

## Development

### Project Structure

```
vscode-extension/
├── src/
│   └── extension.ts      # Main extension code
├── analyzer_server.py     # Python server script
├── package.json           # Extension manifest
├── tsconfig.json         # TypeScript configuration
└── README.md
```

### Building

```bash
# Compile TypeScript
npm run compile

# Watch mode for development
npm run watch
```

### Running in Development

1. Open the `vscode-extension` folder in VSCode
2. Press `F5` to launch Extension Development Host
3. The extension will be active in the new window

## License

MIT License: see LICENSE file for details.
