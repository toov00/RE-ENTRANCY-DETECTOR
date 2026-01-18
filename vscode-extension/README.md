# Re-entrancy Detector VS Code Extension

A VS Code extension that provides real-time re-entrancy vulnerability detection for Solidity smart contracts. The extension integrates the re-entrancy detector analyzer directly into your VS Code workflow, displaying findings in the Problems panel as you write code.

## Features

- Real-time analysis of Solidity files
- Automatic scanning on file save
- Inline diagnostics with severity levels
- Detailed vulnerability descriptions and remediation suggestions
- Workspace-wide scanning capability
- Configurable severity thresholds

## Prerequisites

Before building and installing this extension, ensure you have:

1. **Python 3.8 or higher** installed and accessible from your command line
2. **The Python analyzer package** installed (see Installation section)
3. **Node.js 20 or higher** for building the extension

Verify your installations:

```bash
python --version  # Should be 3.8+
node --version    # Should be v20+
```

## Installation

### Step 1: Install the Python Analyzer

The extension requires the Python analyzer package to be installed. From the repository root directory:

```bash
cd /path/to/reentrancy-detector
pip install -e .
```

This installs the core analyzer that the extension uses to perform the actual analysis.

### Step 2: Install Extension Dependencies

Navigate to the extension directory and install Node.js dependencies:

```bash
cd vscode-extension
npm install
```

### Step 3: Build the Extension

Compile the TypeScript source code:

```bash
npm run compile
```

This generates the JavaScript files in the `out/` directory.

### Step 4: Package the Extension

Install the VS Code extension packaging tool globally (if not already installed):

```bash
npm install -g @vscode/vsce
```

Then package the extension:

```bash
npm run package
```

This creates `reentrancy-detector-1.0.0.vsix` in the current directory.

### Step 5: Install the Extension

Install the packaged extension in VS Code:

```bash
code --install-extension reentrancy-detector-1.0.0.vsix
```

Alternatively, you can install it through VS Code's Extensions view by clicking "Install from VSIX..." and selecting the `.vsix` file.

## Configuration

After installation, configure the extension through VS Code Settings:

1. Open Settings: `Ctrl+,` (Windows/Linux) or `Cmd+,` (Mac)
2. Search for "reentrancy-detector"
3. Adjust the following settings:

**reentrancy-detector.enable**

Enable or disable the extension. Default: `true`

**reentrancy-detector.runOnSave**

Automatically analyze files when saved. Default: `true`

**reentrancy-detector.severityThreshold**

Minimum severity level to display. Options: `critical`, `high`, `medium`, `low`, `info`. Default: `low`

**reentrancy-detector.pythonPath**

Path to your Python 3 interpreter. Default: `python3`

On Windows, you may need to specify the full path, such as `C:\Python39\python.exe` or use `py -3`.

**reentrancy-detector.analyzerPath**

Full path to `analyzer_server.py` if the default location doesn't work. Leave empty to use the default path relative to the extension directory.

## Usage

### Automatic Analysis

The extension automatically analyzes Solidity files when:

- A `.sol` file is opened in the editor
- A `.sol` file is saved (if `runOnSave` is enabled)

Results appear in the Problems panel with severity indicators:
- Red squiggles for Critical and High severity issues
- Yellow squiggles for Medium severity issues
- Blue squiggles for Low and Info severity issues

### Manual Commands

Access manual commands through the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

**Check for Re-entrancy**

Analyzes the currently active Solidity file and displays results in the Problems panel.

**Check Workspace for Re-entrancy**

Scans all `.sol` files in the workspace and displays all findings. Useful for getting a complete overview of your project's security status.

### Viewing Results

1. Open the Problems panel: `Ctrl+Shift+M` (Windows/Linux) or `Cmd+Shift+M` (Mac)
2. Results are grouped by file and severity
3. Click on any issue to jump to the relevant line in your code
4. Hover over the highlighted code to see the full description and remediation suggestions

## Detection Patterns

The extension detects the following re-entrancy patterns:

| Pattern | Severity | Description |
|---------|----------|-------------|
| State change after call | Critical | State variable modified after external call, enabling classic re-entrancy attack |
| External call in loop | High | External calls executed within loops, increasing attack surface |
| Delegatecall usage | High | Delegatecall patterns that execute foreign code in contract context |
| Missing reentrancy guard | Medium | Functions making external calls without reentrancy protection |
| Cross-function reentrancy | Medium | Shared state accessed across functions, enabling cross-function attacks |

Each finding includes:
- Exact line number and location
- Severity level
- Detailed description of the issue
- Remediation suggestions
- References to security best practices

## Troubleshooting

### Extension Not Working

If the extension doesn't appear to be working:

1. **Verify Python installation**: Ensure Python 3.8+ is installed and accessible
   ```bash
   python --version
   ```

2. **Check analyzer installation**: The Python package must be installed
   ```bash
   pip install -e .  # From repository root
   ```

3. **Check Output panel**: Open View → Output, then select "Re-entrancy Detector" from the dropdown. Look for error messages that indicate what's wrong.

4. **Verify Python path**: If Python isn't found, set `reentrancy-detector.pythonPath` in settings to the full path of your Python executable.

5. **Check analyzer path**: If the analyzer script isn't found, set `reentrancy-detector.analyzerPath` to the full path of `analyzer_server.py`.

6. **Virtual environments**: If using a virtual environment, ensure VS Code is configured to use the correct Python interpreter. You may need to set `reentrancy-detector.pythonPath` to point to the virtual environment's Python.

### No Results Showing

If no vulnerabilities are displayed:

1. **Check severity threshold**: Lower the `severityThreshold` setting to see more results
2. **Verify file type**: Ensure the file has a `.sol` extension
3. **Check for errors**: Review the Output panel for any error messages
4. **Manual trigger**: Try running the "Check for Re-entrancy" command manually

### False Positives

The detector uses pattern matching and may occasionally flag code that is actually safe. Review each finding carefully and consider:

- Whether the external call is to a trusted contract
- Whether additional safeguards exist outside the detected pattern
- Whether the state change order is intentional and safe

## Development

### Project Structure

```
vscode-extension/
├── src/
│   └── extension.ts          # Main extension logic
├── analyzer_server.py         # Python server interface
├── package.json              # Extension manifest
├── tsconfig.json             # TypeScript configuration
└── README.md
```

### Building for Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Compile TypeScript:
   ```bash
   npm run compile
   ```

3. Watch mode (auto-compile on changes):
   ```bash
   npm run watch
   ```

### Running in Development Mode

1. Open the `vscode-extension` folder in VS Code
2. Press `F5` to launch the Extension Development Host
3. A new VS Code window opens with the extension loaded
4. Make changes to the TypeScript code and reload the extension window to test

### Debugging

- Set breakpoints in `src/extension.ts`
- Use the Debug Console in VS Code to inspect variables
- Check the Output panel for extension logs
- Review the Developer Tools console for runtime errors

## How It Works

1. The extension monitors for Solidity file events (open, save)
2. When triggered, it spawns a Python process running `analyzer_server.py`
3. The source code is sent to the analyzer via stdin as JSON
4. The analyzer processes the code and returns results as JSON
5. The extension converts results into VS Code diagnostics
6. Diagnostics are displayed in the Problems panel with appropriate severity levels

The analyzer runs in a separate process to avoid blocking the editor, and includes timeout protection to prevent hanging on problematic code.

## License

MIT License. See LICENSE file for details.
