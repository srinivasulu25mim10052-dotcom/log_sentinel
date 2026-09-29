"""
Incident & Analytics Reporting Subsystem for LogSentinel.

Python Essentials Demonstrated:
- Advanced f-string formatting (alignment, padding, numeric precision)
- Multi-line templates with string join operations
- Native JSON serialization with custom object converters
- ANSI escape sequences for vibrant terminal dashboards
- List and dictionary comprehensions for tabular data formatting
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Sequence

from sentinel.models import Incident, MetricSummary, Severity


class ReportGenerator:
    """
    Renders incident investigations and traffic diagnostics into multiple formats:
    - ANSI-colored terminal dashboard
    - Markdown post-mortem document
    - Structured JSON alert payload
    """

    RESET_COLOR = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    GRAY = "\033[90m"

    @classmethod
    def render_terminal_dashboard(
        cls,
        summary: MetricSummary,
        incidents: Sequence[Incident],
        log_source: str,
        execution_time: float,
    ) -> str:
        """
        Builds a rich terminal dashboard with tables, metric boxes, and incident summaries.
        Demonstrates advanced f-string alignment and ANSI formatting.
        """
        lines: List[str] = []
        width = 78

        # Header banner
        lines.append(f"{cls.BOLD}{cls.CYAN}{'=' * width}{cls.RESET_COLOR}")
        title = "LOGSENTINEL INCIDENT & SECURITY INVESTIGATION REPORT"
        lines.append(f"{cls.BOLD}{cls.CYAN}{title.center(width)}{cls.RESET_COLOR}")
        lines.append(f"{cls.BOLD}{cls.CYAN}{'=' * width}{cls.RESET_COLOR}")

        # Metadata section
        lines.append(f" {cls.BOLD}Log Source:{cls.RESET_COLOR}      {log_source}")
        lines.append(f" {cls.BOLD}Analysis Time:{cls.RESET_COLOR}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f" {cls.BOLD}Execution Time:{cls.RESET_COLOR}  {execution_time * 1000:.2f} ms ({execution_time:.4f} s)")
        lines.append(f"{cls.GRAY}{'-' * width}{cls.RESET_COLOR}")

        # Metrics Table
        lines.append(f" {cls.BOLD}TRAFFIC & RELIABILITY METRICS{cls.RESET_COLOR}")
        lines.append(
            f"  * Total Requests Processed: {cls.BOLD}{summary.total_requests:,}{cls.RESET_COLOR}  "
            f"(Malformed lines: {summary.malformed_lines})"
        )
        lines.append(f"  * Total Bandwidth Served:   {cls.BOLD}{summary.total_bytes / (1024 * 1024):.2f} MB{cls.RESET_COLOR}")

        # Status code breakdown using dict comprehension
        status_strs = [f"{code}: {count}" for code, count in sorted(summary.status_counts.items())]
        lines.append(f"  * Status Code Distribution:  {', '.join(status_strs) if status_strs else 'None'}")

        # Error rate highlight
        err_pct = summary.error_rate_percentage
        err_color = cls.RED if err_pct > 10 else (cls.YELLOW if err_pct > 1 else cls.GREEN)
        lines.append(f"  * Overall Error Rate:       {err_color}{cls.BOLD}{err_pct:.2f}%{cls.RESET_COLOR}")

        # Performance percentiles if available
        if summary.response_times_ms:
            lines.append(
                f"  * Latency Profile:          Avg: {summary.avg_response_time_ms:.1f}ms | "
                f"Median: {summary.median_response_time_ms:.1f}ms | "
                f"P95: {summary.p95_response_time_ms:.1f}ms"
            )

        lines.append(f"{cls.GRAY}{'-' * width}{cls.RESET_COLOR}")

        # Incident Section
        incident_count = len(incidents)
        inc_color = cls.RED if incident_count > 0 else cls.GREEN
        lines.append(f" {cls.BOLD}DETECTED INCIDENTS & SECURITY EVENTS ({inc_color}{incident_count} FOUND{cls.RESET_COLOR}){cls.RESET_COLOR}")

        if not incidents:
            lines.append(f"  {cls.GREEN}[+] No anomalous security threats or outages detected!{cls.RESET_COLOR}")
        else:
            for inc in incidents:
                sev_tag = f"{inc.severity.ansi_color}[{inc.severity.value}]{cls.RESET_COLOR}"
                lines.append(f"\n  {sev_tag} {cls.BOLD}{inc.id}: {inc.title}{cls.RESET_COLOR}")
                lines.append(f"    {cls.GRAY}Rule:{cls.RESET_COLOR} {inc.rule_name} | {cls.GRAY}Timestamp:{cls.RESET_COLOR} {inc.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"    {cls.GRAY}Impact:{cls.RESET_COLOR} {inc.description}")
                if inc.evidence:
                    lines.append(f"    {cls.GRAY}Evidence Trace:{cls.RESET_COLOR}")
                    for ev in inc.evidence[:4]:
                        lines.append(f"      - {ev}")
                lines.append(f"    {cls.YELLOW}Remediation:{cls.RESET_COLOR} {inc.remediation}")

        lines.append(f"\n{cls.BOLD}{cls.CYAN}{'=' * width}{cls.RESET_COLOR}\n")
        return "\n".join(lines)

    @classmethod
    def render_markdown(
        cls,
        summary: MetricSummary,
        incidents: Sequence[Incident],
        log_source: str,
    ) -> str:
        """
        Renders a comprehensive GitHub-flavored Markdown post-mortem document.
        """
        md: List[str] = []
        md.append("# LogSentinel Security & Incident Diagnostic Report\n")
        md.append(f"**Analyzed Source:** `{log_source}`  ")
        md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        md.append(f"**Overall Status:** {'⚠️ **Incidents Detected**' if incidents else '✅ **Healthy**'}\n")

        # Executive Summary Table
        md.append("## Executive Traffic Summary\n")
        md.append("| Metric | Value |")
        md.append("| :--- | :--- |")
        md.append(f"| **Total Requests** | {summary.total_requests:,} |")
        md.append(f"| **Total Data Transferred** | {summary.total_bytes / (1024 * 1024):.2f} MB |")
        md.append(f"| **Error Rate (4xx/5xx)** | {summary.error_rate_percentage:.2f}% |")
        if summary.response_times_ms:
            md.append(f"| **Average Latency** | {summary.avg_response_time_ms:.1f} ms |")
            md.append(f"| **P95 Latency** | {summary.p95_response_time_ms:.1f} ms |")
        md.append(f"| **Corrupt / Malformed Lines** | {summary.malformed_lines} |\n")

        # Status Code Breakdown
        md.append("### HTTP Status Code Breakdown\n")
        md.append("| Status Code | Description | Count | Share |")
        md.append("| :--- | :--- | :--- | :--- |")
        for code, count in sorted(summary.status_counts.items()):
            share = (count / summary.total_requests * 100.0) if summary.total_requests else 0.0
            desc = "Success" if code < 300 else ("Redirect" if code < 400 else ("Client Error" if code < 500 else "Server Error"))
            md.append(f"| `{code}` | {desc} | {count:,} | {share:.1f}% |")
        md.append("\n")

        # Incident List
        md.append("## Incident Investigation Details\n")
        if not incidents:
            md.append("> **Clean Bill of Health**: No security threats, brute-force bursts, or outages detected.\n")
        else:
            for inc in incidents:
                md.append(f"### {inc.id}: {inc.title}")
                md.append(f"- **Severity**: `{inc.severity.value}`")
                md.append(f"- **Detection Rule**: `{inc.rule_name}`")
                md.append(f"- **Timestamp**: `{inc.timestamp.isoformat()}`")
                if inc.source_ip:
                    md.append(f"- **Attacker / Source IP**: `{inc.source_ip}`")
                if inc.affected_path:
                    md.append(f"- **Target Endpoint**: `{inc.affected_path}`")
                md.append(f"- **Description**: {inc.description}\n")

                if inc.evidence:
                    md.append("**Evidence Log Samples:**")
                    md.append("```text")
                    for ev in inc.evidence:
                        md.append(ev)
                    md.append("```\n")

                md.append(f"**Recommended Remediation:**  \n> {inc.remediation}\n")
                md.append("---\n")

        return "\n".join(md)

    @classmethod
    def render_json(
        cls,
        summary: MetricSummary,
        incidents: Sequence[Incident],
        log_source: str,
    ) -> str:
        """
        Renders structured JSON report for downstream automation (SIEM, Slack webhook, etc.).
        """
        payload: Dict[str, Any] = {
            "meta": {
                "source": log_source,
                "generated_at": datetime.now().isoformat(),
                "engine": "LogSentinel v1.0.0",
            },
            "metrics": {
                "total_requests": summary.total_requests,
                "total_bytes": summary.total_bytes,
                "error_rate_pct": round(summary.error_rate_percentage, 2),
                "status_counts": summary.status_counts,
                "malformed_lines": summary.malformed_lines,
                "latency_ms": {
                    "avg": round(summary.avg_response_time_ms, 2),
                    "median": round(summary.median_response_time_ms, 2),
                    "p95": round(summary.p95_response_time_ms, 2),
                } if summary.response_times_ms else None,
            },
            "incidents": [inc.to_dict() for inc in incidents],
        }
        return json.dumps(payload, indent=2)
