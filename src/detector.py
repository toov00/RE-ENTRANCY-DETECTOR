"""
Main reentrancy detection engine.
Orchestrates parsing and pattern detection.
"""

import os
import time
from pathlib import Path
from typing import List, Optional, Union

from .models import (
    Contract, Vulnerability, AnalysisResult, ScanResult,
    Severity, CodeSnippet
)
from .parser import SolidityParser
from .patterns import ReentrancyPatterns


class ReentrancyDetector:
    """
    Main detector class for finding reentrancy vulnerabilities in Solidity contracts.

    Usage:
        detector = ReentrancyDetector()
        result = detector.analyze_file("contract.sol")
        for vuln in result.vulnerabilities:
            print(f"{vuln.severity}: {vuln.description}")
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize the detector.

        Args:
            config: Optional configuration dictionary with keys:
                - severity_threshold: Minimum severity to report (default: LOW)
                - include_info: Include informational findings (default: False)
                - max_file_size: Maximum file size to analyze in bytes (default: 1MB)
        """
        self.config = config or {}
        self.severity_threshold = self.config.get('severity_threshold', Severity.LOW)
        self.include_info = self.config.get('include_info', False)
        self.max_file_size = self.config.get('max_file_size', 1024 * 1024)  # 1MB

        self.parser = SolidityParser()

    def analyze_file(self, file_path: Union[str, Path]) -> AnalysisResult:
        """
        Analyze a single Solidity file for reentrancy vulnerabilities.

        Args:
            file_path: Path to the Solidity file

        Returns:
            AnalysisResult containing detected vulnerabilities
        """
        file_path = Path(file_path)
        result = AnalysisResult(file_path=str(file_path))

        start_time = time.time()

        # Validate file
        if not file_path.exists():
            result.parse_errors.append(f"File not found: {file_path}")
            return result

        if not file_path.suffix == '.sol':
            result.parse_errors.append(f"Not a Solidity file: {file_path}")
            return result

        if file_path.stat().st_size > self.max_file_size:
            result.parse_errors.append(f"File too large: {file_path}")
            return result

        # Read and parse file
        try:
            source_code = file_path.read_text(encoding='utf-8')
        except Exception as e:
            result.parse_errors.append(f"Error reading file: {e}")
            return result

        # Parse contracts
        try:
            contracts = self.parser.parse(source_code)
            result.contracts = contracts
        except Exception as e:
            result.parse_errors.append(f"Parse error: {e}")
            return result

        # Run detection on each contract
        for contract in contracts:
            vulnerabilities = self._analyze_contract(contract)
            result.vulnerabilities.extend(vulnerabilities)

        # Filter by severity threshold
        result.vulnerabilities = [
            v for v in result.vulnerabilities
            if v.severity >= self.severity_threshold or
               (v.severity == Severity.INFO and self.include_info)
        ]

        # Sort by severity (most severe first)
        result.vulnerabilities.sort(key=lambda v: v.severity, reverse=True)

        result.analysis_time_ms = (time.time() - start_time) * 1000
        return result

    def analyze_source(self, source_code: str, filename: str = "contract.sol") -> AnalysisResult:
        """
        Analyze Solidity source code directly.

        Args:
            source_code: Solidity source code string
            filename: Optional filename for reporting

        Returns:
            AnalysisResult containing detected vulnerabilities
        """
        result = AnalysisResult(file_path=filename)
        start_time = time.time()

        # Parse contracts
        try:
            contracts = self.parser.parse(source_code)
            result.contracts = contracts
        except Exception as e:
            result.parse_errors.append(f"Parse error: {e}")
            return result

        # Run detection on each contract
        for contract in contracts:
            vulnerabilities = self._analyze_contract(contract)
            result.vulnerabilities.extend(vulnerabilities)

        # Filter and sort
        result.vulnerabilities = [
            v for v in result.vulnerabilities
            if v.severity >= self.severity_threshold
        ]
        result.vulnerabilities.sort(key=lambda v: v.severity, reverse=True)

        result.analysis_time_ms = (time.time() - start_time) * 1000
        return result

    def scan_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
        exclude_patterns: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Scan a directory for Solidity files and analyze them.

        Args:
            directory: Path to directory
            recursive: Whether to scan subdirectories
            exclude_patterns: List of patterns to exclude (e.g., ['test', 'mock'])

        Returns:
            ScanResult with results from all files
        """
        directory = Path(directory)
        exclude_patterns = exclude_patterns or ['node_modules', 'test', 'mock', 'Mock']

        scan_result = ScanResult()
        start_time = time.time()

        # Find all .sol files
        if recursive:
            sol_files = list(directory.rglob('*.sol'))
        else:
            sol_files = list(directory.glob('*.sol'))

        # Filter excluded patterns
        def should_exclude(path: Path) -> bool:
            path_str = str(path)
            return any(pattern in path_str for pattern in exclude_patterns)

        sol_files = [f for f in sol_files if not should_exclude(f)]

        # Analyze each file
        for sol_file in sol_files:
            result = self.analyze_file(sol_file)
            scan_result.results.append(result)
            scan_result.files_scanned += 1
            scan_result.total_contracts += len(result.contracts)

        scan_result.total_analysis_time_ms = (time.time() - start_time) * 1000
        return scan_result

    def _analyze_contract(self, contract: Contract) -> List[Vulnerability]:
        """
        Run all detection patterns on a contract.

        Args:
            contract: Parsed contract to analyze

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Helper to get code snippets
        def get_snippet(line: int, context: int = 3) -> CodeSnippet:
            return self.parser.get_code_snippet(line, context)

        # Check each function
        for function in contract.functions:
            # Pattern 1: State change after external call (Critical)
            vulns = ReentrancyPatterns.detect_state_change_after_call(
                function, contract, get_snippet
            )
            vulnerabilities.extend(vulns)

            # Pattern 2: External call in loop (High)
            vulns = ReentrancyPatterns.detect_external_call_in_loop(
                function, contract, get_snippet
            )
            vulnerabilities.extend(vulns)

            # Pattern 3: Missing reentrancy guard (Medium)
            vulns = ReentrancyPatterns.detect_missing_reentrancy_guard(
                function, contract, self.parser.has_reentrancy_modifier, get_snippet
            )
            vulnerabilities.extend(vulns)

            # Pattern 4: Delegatecall risks (High)
            vulns = ReentrancyPatterns.detect_delegatecall_reentrancy(
                function, contract, get_snippet
            )
            vulnerabilities.extend(vulns)

        # Contract-level patterns
        # Pattern 5: Cross-function reentrancy (Medium)
        vulns = ReentrancyPatterns.detect_cross_function_reentrancy(
            contract, get_snippet
        )
        vulnerabilities.extend(vulns)

        return vulnerabilities

    def get_stats(self, result: Union[AnalysisResult, ScanResult]) -> dict:
        """
        Get statistics from analysis results.

        Args:
            result: Analysis or scan result

        Returns:
            Dictionary with statistics
        """
        if isinstance(result, AnalysisResult):
            return {
                'files': 1,
                'contracts': len(result.contracts),
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': result.medium_count,
                'low': result.low_count,
                'total': len(result.vulnerabilities),
                'time_ms': result.analysis_time_ms
            }
        else:
            return {
                'files': result.files_scanned,
                'contracts': result.total_contracts,
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': result.medium_count,
                'low': result.low_count,
                'total': len(result.all_vulnerabilities),
                'time_ms': result.total_analysis_time_ms
            }


# Convenience function for quick analysis
def analyze(source: str) -> List[Vulnerability]:
    """
    Quick analysis of Solidity source code.

    Args:
        source: Solidity source code or file path

    Returns:
        List of vulnerabilities found
    """
    detector = ReentrancyDetector()

    # Check if it's a file path
    if os.path.exists(source) and source.endswith('.sol'):
        result = detector.analyze_file(source)
    else:
        result = detector.analyze_source(source)

    return result.vulnerabilities
