"""
Report formatting and output generation.
"""

import json
from datetime import datetime
from typing import Union, TextIO, Optional
from pathlib import Path

from .models import (
    AnalysisResult, ScanResult, Vulnerability, Severity
)

class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Severity colors
    CRITICAL = '\033[91m'  # Bright red
    HIGH = '\033[31m'      # Red
    MEDIUM = '\033[33m'    # Yellow
    LOW = '\033[36m'       # Cyan
    INFO = '\033[37m'      # White

    # Other colors
    GREEN = '\033[32m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    WHITE = '\033[97m'

    @classmethod
    def severity_color(cls, severity: Severity) -> str:
        """Get the color for a severity level."""
        colors = {
            Severity.CRITICAL: cls.CRITICAL,
            Severity.HIGH: cls.HIGH,
            Severity.MEDIUM: cls.MEDIUM,
            Severity.LOW: cls.LOW,
            Severity.INFO: cls.INFO
        }
        return colors.get(severity, cls.RESET)


class Reporter:
    """Formats and outputs analysis results."""

    def __init__(self, use_colors: bool = True, verbose: bool = False):
        """
        Initialize reporter.

        Args:
            use_colors: Whether to use ANSI colors in output
            verbose: Whether to include code snippets and extra details
        """
        self.use_colors = use_colors
        self.verbose = verbose

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text

    def format_text(self, result: Union[AnalysisResult, ScanResult]) -> str:
        """
        Format results as human-readable text.

        Args:
            result: Analysis or scan result

        Returns:
            Formatted text string
        """
        lines = []

        # Header
        lines.append(self._format_header(result))
        lines.append("")

        # Handle both single file and directory scan results
        if isinstance(result, ScanResult):
            for file_result in result.results:
                if file_result.vulnerabilities:
                    lines.append(self._color(f"File: {file_result.file_path}", Colors.BLUE))
                    lines.append("-" * 60)
                    for vuln in file_result.vulnerabilities:
                        lines.append(self._format_vulnerability(vuln))
                        lines.append("")
        else:
            if result.parse_errors:
                lines.append(self._color("Parse Errors:", Colors.HIGH))
                for error in result.parse_errors:
                    lines.append(f"  • {error}")
                lines.append("")

            for vuln in result.vulnerabilities:
                lines.append(self._format_vulnerability(vuln))
                lines.append("")

        # Summary
        lines.append(self._format_summary(result))

        return "\n".join(lines)

    def _format_header(self, result: Union[AnalysisResult, ScanResult]) -> str:
        """Format the report header."""
        width = 64
        border = "═" * width

        header_lines = [
            self._color(f"╔{border}╗", Colors.BOLD),
            self._color(f"║{'REENTRANCY VULNERABILITY REPORT':^{width}}║", Colors.BOLD),
            self._color(f"╠{border}╣", Colors.BOLD),
        ]

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if isinstance(result, ScanResult):
            header_lines.append(
                self._color(f"║ {'Files Scanned:':<20}{result.files_scanned:>{width-22}} ║", Colors.DIM)
            )
            header_lines.append(
                self._color(f"║ {'Contracts Found:':<20}{result.total_contracts:>{width-22}} ║", Colors.DIM)
            )
        else:
            header_lines.append(
                self._color(f"║ {'File:':<10}{result.file_path:>{width-12}} ║", Colors.DIM)
            )
            header_lines.append(
                self._color(f"║ {'Contracts:':<10}{len(result.contracts):>{width-12}} ║", Colors.DIM)
            )

        header_lines.append(
            self._color(f"║ {'Scanned:':<10}{timestamp:>{width-12}} ║", Colors.DIM)
        )
        header_lines.append(self._color(f"╚{border}╝", Colors.BOLD))

        return "\n".join(header_lines)

    def _format_vulnerability(self, vuln: Vulnerability) -> str:
        """Format a single vulnerability."""
        lines = []

        # Severity badge and title
        severity_color = Colors.severity_color(vuln.severity)
        badge = self._color(f"[{vuln.severity.value}]", severity_color + Colors.BOLD)
        lines.append(f"{badge} {vuln.title}")

        # Details with tree structure
        lines.append(f"├── Contract: {vuln.contract_name}")
        lines.append(f"├── Function: {vuln.function_name}()")
        lines.append(f"├── Location: {vuln.location}")

        if vuln.external_call:
            lines.append(f"├── External call: {vuln.external_call.call_type} at line {vuln.external_call.location.line}")

        if vuln.state_change:
            lines.append(f"├── State change: {vuln.state_change.variable} at line {vuln.state_change.location.line}")

        # Code snippet (if verbose)
        if self.verbose and vuln.code_snippet:
            lines.append("├── Code:")
            for snippet_line in vuln.code_snippet.formatted().split('\n'):
                lines.append(f"│   {snippet_line}")

        # Remediation
        if vuln.remediation:
            # Word wrap remediation text
            wrapped = self._word_wrap(vuln.remediation, 55)
            lines.append(f"├── Remediation: {wrapped[0]}")
            for wrap_line in wrapped[1:]:
                lines.append(f"│   {wrap_line}")

        # Confidence
        lines.append(f"└── Confidence: {vuln.confidence}")

        return "\n".join(lines)

    def _format_summary(self, result: Union[AnalysisResult, ScanResult]) -> str:
        """Format the summary section."""
        width = 64
        border = "═" * width

        if isinstance(result, ScanResult):
            critical = result.critical_count
            high = result.high_count
            medium = result.medium_count
            low = result.low_count
            total = len(result.all_vulnerabilities)
            time_ms = result.total_analysis_time_ms
        else:
            critical = result.critical_count
            high = result.high_count
            medium = result.medium_count
            low = result.low_count
            total = len(result.vulnerabilities)
            time_ms = result.analysis_time_ms

        summary_parts = []

        if critical > 0:
            summary_parts.append(self._color(f"{critical} Critical", Colors.CRITICAL))
        if high > 0:
            summary_parts.append(self._color(f"{high} High", Colors.HIGH))
        if medium > 0:
            summary_parts.append(self._color(f"{medium} Medium", Colors.MEDIUM))
        if low > 0:
            summary_parts.append(self._color(f"{low} Low", Colors.LOW))

        if not summary_parts:
            summary_parts.append(self._color("No vulnerabilities found!", Colors.GREEN))

        summary_text = ", ".join(summary_parts)

        lines = [
            border,
            f"Summary: {summary_text}",
            f"Total: {total} vulnerabilities | Analysis time: {time_ms:.2f}ms",
            border
        ]

        return "\n".join(lines)

    def _word_wrap(self, text: str, width: int) -> list:
        """Wrap text to specified width."""
        words = text.split()
        lines = []
        current_line = []
        current_length = 0

        for word in words:
            if current_length + len(word) + 1 <= width:
                current_line.append(word)
                current_length += len(word) + 1
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [word]
                current_length = len(word)

        if current_line:
            lines.append(" ".join(current_line))

        return lines or [""]

    def format_json(self, result: Union[AnalysisResult, ScanResult], indent: int = 2) -> str:
        """
        Format results as JSON.

        Args:
            result: Analysis or scan result
            indent: JSON indentation level

        Returns:
            JSON string
        """
        data = result.to_dict()
        data['report_timestamp'] = datetime.now().isoformat()
        data['tool'] = 'reentrancy-detector'
        data['version'] = '1.0.0'

        return json.dumps(data, indent=indent)

    def format_markdown(self, result: Union[AnalysisResult, ScanResult]) -> str:
        """
        Format results as Markdown.

        Args:
            result: Analysis or scan result

        Returns:
            Markdown string
        """
        lines = []

        # Header
        lines.append("# Reentrancy Vulnerability Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Summary table
        if isinstance(result, ScanResult):
            lines.append("## Summary")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| Files Scanned | {result.files_scanned} |")
            lines.append(f"| Contracts | {result.total_contracts} |")
            lines.append(f"| Critical | {result.critical_count} |")
            lines.append(f"| High | {result.high_count} |")
            lines.append(f"| Medium | {result.medium_count} |")
            lines.append(f"| Low | {result.low_count} |")
            lines.append("")

            all_vulns = result.all_vulnerabilities
        else:
            lines.append(f"**File:** `{result.file_path}`")
            lines.append("")
            lines.append("## Summary")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            lines.append(f"| Critical | {result.critical_count} |")
            lines.append(f"| High | {result.high_count} |")
            lines.append(f"| Medium | {result.medium_count} |")
            lines.append(f"| Low | {result.low_count} |")
            lines.append("")

            all_vulns = result.vulnerabilities

        # Vulnerabilities
        if all_vulns:
            lines.append("## Findings")
            lines.append("")

            for i, vuln in enumerate(all_vulns, 1):
                severity_emoji = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                    Severity.INFO: "⚪"
                }

                lines.append(f"### {i}. {severity_emoji.get(vuln.severity, '')} {vuln.title}")
                lines.append("")
                lines.append(f"**Severity:** {vuln.severity.value}  ")
                lines.append(f"**Contract:** `{vuln.contract_name}`  ")
                lines.append(f"**Function:** `{vuln.function_name}()`  ")
                lines.append(f"**Line:** {vuln.location.line}")
                lines.append("")
                lines.append(f"**Description:** {vuln.description}")
                lines.append("")

                if vuln.code_snippet and self.verbose:
                    lines.append("**Code:**")
                    lines.append("```solidity")
                    lines.append(vuln.code_snippet.code)
                    lines.append("```")
                    lines.append("")

                lines.append(f"**Remediation:** {vuln.remediation}")
                lines.append("")

                if vuln.references:
                    lines.append("**References:**")
                    for ref in vuln.references:
                        lines.append(f"- {ref}")
                    lines.append("")

                lines.append("---")
                lines.append("")
        else:
            lines.append("## Findings")
            lines.append("")
            lines.append("✅ No reentrancy vulnerabilities detected.")
            lines.append("")

        return "\n".join(lines)

    def write_to_file(
        self,
        result: Union[AnalysisResult, ScanResult],
        output_path: Union[str, Path],
        format: str = 'text'
    ) -> None:
        """
        Write results to a file.

        Args:
            result: Analysis or scan result
            output_path: Path to output file
            format: Output format ('text', 'json', 'markdown')
        """
        output_path = Path(output_path)

        if format == 'json':
            content = self.format_json(result)
        elif format == 'markdown':
            content = self.format_markdown(result)
        else:
            # Disable colors for file output
            original_colors = self.use_colors
            self.use_colors = False
            content = self.format_text(result)
            self.use_colors = original_colors

        output_path.write_text(content, encoding='utf-8')

    def print_result(
        self,
        result: Union[AnalysisResult, ScanResult],
        format: str = 'text',
        file: Optional[TextIO] = None
    ) -> None:
        """
        Print results to stdout or a file handle.

        Args:
            result: Analysis or scan result
            format: Output format ('text', 'json', 'markdown')
            file: Optional file handle (defaults to stdout)
        """
        if format == 'json':
            content = self.format_json(result)
        elif format == 'markdown':
            content = self.format_markdown(result)
        else:
            content = self.format_text(result)

        print(content, file=file)
        