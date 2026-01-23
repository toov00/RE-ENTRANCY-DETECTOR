# Re-entrancy Detector for Solidity

A VSCode extension that analyzes Solidity code to find re-entrancy patterns and displays results in the Problems panel.

## What It Does

Automatically scans Solidity files for re-entrancy vulnerabilities. Shows findings directly in the Problems panel with severity levels and remediation suggestions.

**Features:**
- Real-time analysis on file open and save
- Visual diagnostics in Problems panel
- Workspace-wide scanning
- Configurable severity thresholds

## Installation

**Requirements:** Python 3.8+, Node.js 20+

1. Install Python analyzer (from repository root):
```bash
pip install -e .
```

2. Navigate to extension directory:
```bash
cd vscode-extension
```

3. Install dependencies and build:
```bash
npm install
npm run compile
```

4. Package the extension:
```bash
npm install -g @vscode/vsce
npm run package
```

5. Install in VS Code:
```bash
code --install-extension reentrancy-detector-1.0.0.vsix
```

## Usage

### Quick Start

The extension automatically analyzes `.sol` files on open and save. Results appear in the Problems panel.

**Manual commands** (Command Palette: `Ctrl+Shift+P` / `Cmd+Shift+P`):

- `Re-entrancy Detector: Check for Re-entrancy` - Analyze current file
- `Re-entrancy Detector: Check Workspace for Re-entrancy` - Scan all `.sol` files

### Configuration

Configure in VS Code Settings (search for "reentrancy-detector"):

- `reentrancy-detector.enable`: Enable/disable extension (default: `true`)
- `reentrancy-detector.runOnSave`: Auto-analyze on save (default: `true`)
- `reentrancy-detector.severityThreshold`: Minimum severity to show (default: `low`)
- `reentrancy-detector.pythonPath`: Python interpreter path (default: `python3`)
- `reentrancy-detector.analyzerPath`: Custom analyzer script path (optional)

## Detection Patterns

1. **State Change After Call** (Critical): State modified after external call
2. **External Call in Loop** (High): `.call()` invoked inside for/while loops
3. **Delegatecall Usage** (High): Delegatecall patterns detected
4. **Missing Re-entrancy Guard** (Medium): Absence of `nonReentrant` modifier
5. **Cross-Function Re-entrancy** (Medium): Shared state across functions

## Troubleshooting

**Extension not working?** Verify Python 3.8+ is installed, analyzer package is installed (`pip install -e .`), and check Output panel for errors.

**No results showing?** Lower `severityThreshold` setting, verify file has `.sol` extension, check Output panel for error messages.

**Import errors?** Make sure Python analyzer is installed from repository root and Python path is correctly configured.

## Development

```bash
npm install
npm run compile    # Compile TypeScript
npm run watch      # Watch mode for development
```

Press `F5` in VS Code to launch Extension Development Host.

## License

MIT License
