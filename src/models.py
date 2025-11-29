"""
Data models for the reentrancy detector.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __ge__(self, other):
        return not self.__lt__(other)


class VulnerabilityType(Enum):
    """Types of reentrancy vulnerabilities."""
    STATE_CHANGE_AFTER_CALL = "state_change_after_call"
    EXTERNAL_CALL_IN_LOOP = "external_call_in_loop"
    MISSING_REENTRANCY_GUARD = "missing_reentrancy_guard"
    CROSS_FUNCTION_REENTRANCY = "cross_function_reentrancy"
    DELEGATECALL_REENTRANCY = "delegatecall_reentrancy"
    CREATE_REENTRANCY = "create_reentrancy"


@dataclass
class SourceLocation:
    """Represents a location in the source code."""
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def __str__(self):
        if self.end_line and self.end_line != self.line:
            return f"lines {self.line}-{self.end_line}"
        return f"line {self.line}"


@dataclass
class CodeSnippet:
    """A snippet of source code with context."""
    code: str
    start_line: int
    highlight_lines: List[int] = field(default_factory=list)

    def formatted(self, context_lines: int = 2) -> str:
        """Format the snippet with line numbers."""
        lines = self.code.split('\n')
        result = []
        for i, line in enumerate(lines):
            line_num = self.start_line + i
            marker = ">>> " if line_num in self.highlight_lines else "    "
            result.append(f"{marker}{line_num:4d} | {line}")
        return '\n'.join(result)


@dataclass
class ExternalCall:
    """Represents an external call in the contract."""
    location: SourceLocation
    call_type: str  # 'call', 'delegatecall', 'staticcall', 'transfer', 'send'
    target: str
    code: str
    in_loop: bool = False
    loop_location: Optional[SourceLocation] = None


@dataclass
class StateChange:
    """Represents a state variable modification."""
    location: SourceLocation
    variable: str
    code: str
    change_type: str  # 'assignment', 'increment', 'decrement', 'delete', 'mapping_update'


@dataclass
class Function:
    """Represents a function in the contract."""
    name: str
    location: SourceLocation
    visibility: str  # 'public', 'external', 'internal', 'private'
    modifiers: List[str] = field(default_factory=list)
    external_calls: List[ExternalCall] = field(default_factory=list)
    state_changes: List[StateChange] = field(default_factory=list)
    state_reads: List[str] = field(default_factory=list)
    is_payable: bool = False
    body_start_line: int = 0
    body_end_line: int = 0


@dataclass
class Contract:
    """Represents a Solidity contract."""
    name: str
    location: SourceLocation
    functions: List[Function] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    has_reentrancy_guard: bool = False
    inherits: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    vuln_type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    location: SourceLocation
    function_name: str
    contract_name: str
    code_snippet: Optional[CodeSnippet] = None
    external_call: Optional[ExternalCall] = None
    state_change: Optional[StateChange] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: str = "high"  # 'high', 'medium', 'low'

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.vuln_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": {
                "line": self.location.line,
                "column": self.location.column
            },
            "function": self.function_name,
            "contract": self.contract_name,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "references": self.references
        }


@dataclass
class AnalysisResult:
    """Results of analyzing a single file."""
    file_path: str
    contracts: List[Contract] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)
    analysis_time_ms: float = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file": self.file_path,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.vulnerabilities)
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "contracts": [c.name for c in self.contracts],
            "parse_errors": self.parse_errors,
            "analysis_time_ms": self.analysis_time_ms
        }


@dataclass
class ScanResult:
    """Results of scanning multiple files."""
    files_scanned: int = 0
    total_contracts: int = 0
    results: List[AnalysisResult] = field(default_factory=list)
    total_analysis_time_ms: float = 0

    @property
    def all_vulnerabilities(self) -> List[Vulnerability]:
        vulns = []
        for result in self.results:
            vulns.extend(result.vulnerabilities)
        return vulns

    @property
    def critical_count(self) -> int:
        return sum(r.critical_count for r in self.results)

    @property
    def high_count(self) -> int:
        return sum(r.high_count for r in self.results)

    @property
    def medium_count(self) -> int:
        return sum(r.medium_count for r in self.results)

    @property
    def low_count(self) -> int:
        return sum(r.low_count for r in self.results)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "files_scanned": self.files_scanned,
                "total_contracts": self.total_contracts,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total_vulnerabilities": len(self.all_vulnerabilities),
                "analysis_time_ms": self.total_analysis_time_ms
            },
            "files": [r.to_dict() for r in self.results]
        }
        