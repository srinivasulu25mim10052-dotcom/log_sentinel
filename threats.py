"""
Web Security Exploit & Threat Signature Detector.

Python Essentials Demonstrated:
- Set data structures and set operations (membership, union)
- Regular expression signature scanning with re.search
- for ... else loop constructs (executing code when loop completes without break)
- List and set comprehensions
- String unquoting and sanitization checks
"""

import re
from typing import Dict, List, Set, Tuple
from urllib.parse import unquote

from sentinel.models import Incident, LogEntry, Severity
from .base import BaseDetector


class SecurityThreatDetector(BaseDetector):
    """
    Scans request paths, queries, and user-agent strings for known cyberattack vectors:
    - Path Traversal & Local File Inclusion (LFI)
    - SQL Injection (SQLi)
    - Malicious Vulnerability Scanners (sqlmap, nikto, dirbuster)
    - Remote Code Execution (RCE) probes

    Demonstrates:
    - Compiled regex signature dictionaries
    - for / else loop syntax
    - Set deduplication of identified attackers
    """

    # Signature patterns mapped to (Category, Severity, Remediation)
    THREAT_SIGNATURES: List[Tuple[str, re.Pattern, Severity, str]] = [
        (
            "Directory Traversal / LFI Probe",
            re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\/etc\/passwd|\/windows\/win\.ini)", re.IGNORECASE),
            Severity.CRITICAL,
            "Block path traversal sequences at WAF or reverse-proxy level and restrict file system permissions.",
        ),
        (
            "SQL Injection (SQLi) Pattern",
            re.compile(
                r"(?:union\s+(?:all\s+)?select|'\s*or\s*['\d\w\s]*=|\b(?:drop|truncate|alter)\s+table|;\s*exec\s*\(|--\s*$|information_schema)",
                re.IGNORECASE,
            ),
            Severity.CRITICAL,
            "Ensure all database queries use parameterized prepared statements; block suspicious SQL tokens in WAF.",
        ),
        (
            "Automated Vulnerability Scanner",
            re.compile(r"(?:nikto|sqlmap|acunetix|masscan|zgrab|nmap|dirbuster|gobuster)", re.IGNORECASE),
            Severity.HIGH,
            "Immediately blackhole or challenge requests originating from automated vulnerability scanning tools.",
        ),
        (
            "Sensitive File Exposure Probe",
            re.compile(r"(?:\.env|\.git\/config|web\.config|\.aws\/credentials|wp-config\.php)", re.IGNORECASE),
            Severity.HIGH,
            "Disallow public access to hidden and configuration files in web server rules.",
        ),
    ]

    def __init__(self) -> None:
        super().__init__("SecurityThreatDetector")
        # Track unique signatures tripped per IP to prevent spamming
        self._ip_threat_records: Dict[str, Set[str]] = {}

    def process(self, entry: LogEntry) -> None:
        """
        Inspects each log entry against regex threat signatures.
        Uses for / else loop construct to record threat matches.
        """
        # Decode URL-encoded attacks (e.g. %2e%2e%2f -> ../)
        decoded_path = unquote(entry.path)
        scan_target = f"{decoded_path} | UA: {entry.user_agent}"

        # Evaluate against each threat signature
        for threat_name, pattern, severity, remediation in self.THREAT_SIGNATURES:
            match = pattern.search(scan_target)
            if match:
                matched_token = match.group(0)
                ip = entry.ip

                # Initialize set for IP if new
                if ip not in self._ip_threat_records:
                    self._ip_threat_records[ip] = set()

                threat_key = f"{threat_name}:{matched_token}"
                # Deduplicate repeated matches from same IP
                if threat_key not in self._ip_threat_records[ip]:
                    self._ip_threat_records[ip].add(threat_key)

                    incident = Incident(
                        id=f"INC-SEC-{len(self._incidents) + 1:03d}",
                        rule_name=self.name,
                        severity=severity,
                        title=f"{threat_name} from {ip}",
                        description=(
                            f"Host {ip} targeted '{entry.path}' matching attack signature '{matched_token}'."
                        ),
                        timestamp=entry.timestamp,
                        source_ip=ip,
                        affected_path=entry.path,
                        evidence=[
                            f"HTTP Method: {entry.method}",
                            f"Target URL: {entry.path}",
                            f"Matched Token: {matched_token}",
                            f"User-Agent: {entry.user_agent or 'None'}",
                            f"Status Code: {entry.status_code}",
                        ],
                        remediation=remediation,
                    )
                    self._incidents.append(incident)
                break
        else:
            # Demonstrates Python's for ... else statement!
            # Executes ONLY if the loop finished without triggering any 'break'
            pass

    def finalize(self) -> List[Incident]:
        """Returns all detected threat incidents."""
        return list(self._incidents)

    def reset(self) -> None:
        super().reset()
        self._ip_threat_records.clear()
