# Change Log

All notable changes to the Re-entrancy Detector extension will be documented in this file.

## [1.0.0] - 2024-01-16

### Added
- Initial release of Re-entrancy Detector VSCode extension
- Real-time analysis of Solidity files on open and save
- Visual diagnostics in Problems panel with severity levels
- Workspace scanning capability
- Configurable severity thresholds
- Support for all re-entrancy detection patterns:
  - State change after external call (Critical)
  - External call in loop (High)
  - Delegatecall usage (High)
  - Missing reentrancy guard (Medium)
  - Cross-function reentrancy (Medium)
- Process timeout handling
- Input validation
- Debouncing for performance
- Progress indicators for workspace scans

### Improvements
- Input validation
- File size limits
- Process timeout limits
