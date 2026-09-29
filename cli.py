"""
Command-Line Interface and Interactive Terminal Investigation Shell for LogSentinel.

Python Essentials Demonstrated:
- Standard library argparse with sub-commands and typed flags
- Interactive CLI / REPL using while loops, match/case, and input()
- ANSI terminal formatting and status colors
- Exit codes and error handling in CLI entry points
- Atomic persistence invocation for file exports
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from sentinel.detectors import (
    BruteForceDetector,
    ErrorSpikeDetector,
    PerformanceDetector,
    SecurityThreatDetector,
)
from sentinel.engine import SentinelEngine
from sentinel.exceptions import LogSentinelError
from sentinel.parsers import CombinedLogParser, JsonLogParser
from sentinel.reporter import ReportGenerator
from sentinel.storage import atomic_write_text


def build_parser() -> argparse.ArgumentParser:
    """
    Constructs the argparse CLI parser with subcommands.

    Demonstrates:
    - argparse.ArgumentParser, subparsers
    - Choices validation, default values, help texts
    """
    parser = argparse.ArgumentParser(
        prog="LogSentinel",
        description="Automated Server Log Incident Diagnostics & Threat Detection Engine",
        epilog="Zero external dependencies - 100% Pure Standard Library Python.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # Command: SCAN
    scan_parser = subparsers.add_parser("scan", help="Run full incident and threat detection analysis")
    scan_parser.add_argument("logfile", type=str, help="Path to the log file to analyze")
    scan_parser.add_argument(
        "--parser",
        type=str,
        default="combined",
        choices=["combined", "json"],
        help="Log format parser (default: combined)",
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        default="terminal",
        choices=["terminal", "markdown", "json", "all"],
        help="Output report format (default: terminal)",
    )
    scan_parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output destination path for file reports (e.g. report.md or report.json)",
    )
    scan_parser.add_argument(
        "--bf-threshold",
        type=int,
        default=5,
        help="Threshold of failed attempts for brute-force alert (default: 5)",
    )

    # Command: STATS
    stats_parser = subparsers.add_parser("stats", help="Display traffic volume and reliability statistics")
    stats_parser.add_argument("logfile", type=str, help="Path to the log file")
    stats_parser.add_argument(
        "--parser",
        type=str,
        default="combined",
        choices=["combined", "json"],
        help="Log format parser",
    )

    # Command: THREATS
    threats_parser = subparsers.add_parser("threats", help="Scan strictly for cyberattack signatures and probes")
    threats_parser.add_argument("logfile", type=str, help="Path to the log file")

    # Command: INTERACTIVE
    subparsers.add_parser("interactive", help="Launch interactive terminal investigation menu")

    return parser


def handle_scan_command(args: argparse.Namespace) -> int:
    """Handles the 'scan' subcommand."""
    log_path = Path(args.logfile)
    if not log_path.exists():
        print(f"\033[91mError: Log file '{log_path}' does not exist.\033[0m", file=sys.stderr)
        return 1

    # Instantiate chosen parser
    log_parser = JsonLogParser() if args.parser == "json" else CombinedLogParser()

    # Configure detectors
    detectors = [
        BruteForceDetector(threshold_attempts=args.bf_threshold),
        ErrorSpikeDetector(),
        SecurityThreatDetector(),
        PerformanceDetector(),
    ]

    engine = SentinelEngine(parser=log_parser, detectors=detectors)
    try:
        summary, incidents = engine.analyze_file(log_path)
    except LogSentinelError as err:
        print(f"\033[91mScan Failed: {err}\033[0m", file=sys.stderr)
        return 2

    # Render terminal dashboard
    if args.format in ("terminal", "all"):
        dashboard = ReportGenerator.render_terminal_dashboard(
            summary=summary,
            incidents=incidents.sorted_by_severity(),
            log_source=str(log_path.name),
            execution_time=engine.last_execution_time,
        )
        print(dashboard)

    # Export Markdown
    if args.format in ("markdown", "all"):
        if args.out:
            out_path = Path(args.out).with_suffix(".md")
        else:
            out_path = Path(f"{log_path.stem}_incident_report.md")
        md_content = ReportGenerator.render_markdown(summary, incidents.sorted_by_severity(), str(log_path.name))
        saved = atomic_write_text(out_path, md_content)
        print(f"\033[92m[+] Markdown report saved to: {saved.resolve()}\033[0m")

    # Export JSON
    if args.format in ("json", "all"):
        if args.out:
            out_path = Path(args.out).with_suffix(".json")
        else:
            out_path = Path(f"{log_path.stem}_alerts.json")
        json_content = ReportGenerator.render_json(summary, incidents.sorted_by_severity(), str(log_path.name))
        saved = atomic_write_text(out_path, json_content)
        print(f"\033[92m[+] JSON alert payload saved to: {saved.resolve()}\033[0m")

    return 0 if len(incidents) == 0 else 1


def handle_stats_command(args: argparse.Namespace) -> int:
    """Handles the 'stats' subcommand."""
    log_path = Path(args.logfile)
    if not log_path.exists():
        print(f"\033[91mError: Log file '{log_path}' does not exist.\033[0m", file=sys.stderr)
        return 1

    parser = JsonLogParser() if args.parser == "json" else CombinedLogParser()
    engine = SentinelEngine(parser=parser, detectors=[])  # No detectors for pure stats
    summary, _ = engine.analyze_file(log_path)

    dashboard = ReportGenerator.render_terminal_dashboard(
        summary=summary,
        incidents=[],
        log_source=str(log_path.name),
        execution_time=engine.last_execution_time,
    )
    print(dashboard)
    return 0


def handle_threats_command(args: argparse.Namespace) -> int:
    """Handles the 'threats' subcommand."""
    log_path = Path(args.logfile)
    if not log_path.exists():
        print(f"\033[91mError: Log file '{log_path}' does not exist.\033[0m", file=sys.stderr)
        return 1

    engine = SentinelEngine(
        parser=CombinedLogParser(),
        detectors=[SecurityThreatDetector(), BruteForceDetector()],
    )
    summary, incidents = engine.analyze_file(log_path)
    dashboard = ReportGenerator.render_terminal_dashboard(
        summary=summary,
        incidents=incidents.sorted_by_severity(),
        log_source=str(log_path.name),
        execution_time=engine.last_execution_time,
    )
    print(dashboard)
    return 0 if len(incidents) == 0 else 1


def launch_interactive_shell() -> None:
    """
    Launches an interactive menu-driven investigation shell.
    Demonstrates while loops, match/case dispatch, user prompts, and ANSI formatting.
    """
    print("\n\033[1;96m====================================================\033[0m")
    print("\033[1;96m    LogSentinel - Interactive Investigation Shell   \033[0m")
    print("\033[1;96m====================================================\033[0m")

    sample_dir = Path(__file__).resolve().parent.parent / "sample_data"

    while True:
        print("\n\033[1mSelect an action:\033[0m")
        print("  [1] Scan Web Access Log (Normal & Mixed Traffic)")
        print("  [2] Scan Security Incident Log (Attacks & Brute Force)")
        print("  [3] Scan Cloud Microservice JSON Log")
        print("  [4] Scan Custom File Path")
        print("  [5] Exit")

        choice = input("\n\033[93mEnter option (1-5): \033[0m").strip()

        match choice:
            case "1":
                target = sample_dir / "web_access.log"
                dummy_args = argparse.Namespace(
                    logfile=str(target), parser="combined", format="terminal", out=None, bf_threshold=5
                )
                handle_scan_command(dummy_args)
            case "2":
                target = sample_dir / "security_incident.log"
                dummy_args = argparse.Namespace(
                    logfile=str(target), parser="combined", format="terminal", out=None, bf_threshold=5
                )
                handle_scan_command(dummy_args)
            case "3":
                target = sample_dir / "microservice.json"
                dummy_args = argparse.Namespace(
                    logfile=str(target), parser="json", format="terminal", out=None, bf_threshold=5
                )
                handle_scan_command(dummy_args)
            case "4":
                custom_file = input("Enter full path to log file: ").strip()
                p_choice = input("Select parser (combined/json) [default: combined]: ").strip() or "combined"
                dummy_args = argparse.Namespace(
                    logfile=custom_file, parser=p_choice, format="all", out=None, bf_threshold=5
                )
                handle_scan_command(dummy_args)
            case "5" | "q" | "exit":
                print("\033[92mExiting LogSentinel. Stay secure!\033[0m\n")
                break
            case _:
                print("\033[91mInvalid choice. Please enter 1, 2, 3, 4, or 5.\033[0m")


def main(argv: Optional[List[str]] = None) -> int:
    """Top-level CLI dispatcher."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        # Default to interactive mode if no arguments provided
        launch_interactive_shell()
        return 0

    match args.command:
        case "scan":
            return handle_scan_command(args)
        case "stats":
            return handle_stats_command(args)
        case "threats":
            return handle_threats_command(args)
        case "interactive":
            launch_interactive_shell()
            return 0
        case _:
            parser.print_help()
            return 1
