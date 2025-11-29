#!/usr/bin/env python3
"""
Command-line interface for the reentrancy detector.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .detector import ReentrancyDetector
from .reporter import Reporter
from .models import Severity


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='reentrancy-detector',
        description='Static analysis tool for detecting reentrancy vulnerabilities in Solidity contracts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s scan contract.sol                     Scan a single file
  %(prog)s scan ./contracts/                     Scan a directory
  %(prog)s scan contract.sol --format json       Output as JSON
  %(prog)s scan contract.sol --verbose           Include code snippets
  %(prog)s scan ./contracts/ --exclude test mock Exclude test files

Exit codes:
  0 - No vulnerabilities found
  1 - Vulnerabilities found
  2 - Error during analysis
        '''
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan Solidity files for reentrancy vulnerabilities'
    )

    scan_parser.add_argument(
        'target',
        type=str,
        help='File or directory to scan'
    )

    scan_parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'markdown'],
        default='text',
        help='Output format (default: text)'
    )

    scan_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Write output to file instead of stdout'
    )

    scan_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Include code snippets and additional details'
    )

    scan_parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    scan_parser.add_argument(
        '-s', '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='low',
        help='Minimum severity level to report (default: low)'
    )

    scan_parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        default=True,
        help='Recursively scan directories (default: true)'
    )

    scan_parser.add_argument(
        '--no-recursive',
        action='store_false',
        dest='recursive',
        help='Do not recursively scan directories'
    )

    scan_parser.add_argument(
        '-e', '--exclude',
        nargs='+',
        default=['node_modules', 'test', 'mock', 'Mock'],
        help='Patterns to exclude from directory scans'
    )

    scan_parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Only output vulnerabilities, no header/summary'
    )

    # Version command
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser


def severity_from_string(s: str) -> Severity:
    """Convert string to Severity enum."""
    mapping = {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'info': Severity.INFO
    }
    return mapping.get(s.lower(), Severity.LOW)


def run_scan(args: argparse.Namespace) -> int:
    """
    Execute the scan command.

    Returns:
        Exit code (0 = no vulns, 1 = vulns found, 2 = error)
    """
    target = Path(args.target)

    # Configure detector
    config = {
        'severity_threshold': severity_from_string(args.severity),
        'include_info': args.severity == 'info'
    }

    detector = ReentrancyDetector(config)

    # Configure reporter
    use_colors = not args.no_color and args.output is None and sys.stdout.isatty()
    reporter = Reporter(use_colors=use_colors, verbose=args.verbose)

    # Run analysis
    try:
        if target.is_file():
            result = detector.analyze_file(target)

            if result.parse_errors and not args.quiet:
                for error in result.parse_errors:
                    print(f"Warning: {error}", file=sys.stderr)
        elif target.is_dir():
            result = detector.scan_directory(
                target,
                recursive=args.recursive,
                exclude_patterns=args.exclude
            )
        else:
            print(f"Error: Target not found: {target}", file=sys.stderr)
            return 2

    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 2

    # Output results
    if args.output:
        reporter.write_to_file(result, args.output, format=args.format)
        if not args.quiet:
            print(f"Report written to: {args.output}")
    else:
        reporter.print_result(result, format=args.format)

    # Return exit code based on findings
    stats = detector.get_stats(result)

    if stats['critical'] > 0 or stats['high'] > 0:
        return 1
    elif stats['total'] > 0:
        return 1

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == 'scan':
        return run_scan(args)

    return 0


if __name__ == '__main__':
    sys.exit(main())
    