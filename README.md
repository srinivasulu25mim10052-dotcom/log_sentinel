# LogSentinel 🛡️

**Automated Server Log Incident Diagnostics & Threat Detection Engine**  
*Built with 100% Pure Standard Library Python 3.10+ (Zero External Dependencies)*

---

## 📌 The Real-World Problem

Every web server, microservice, and cloud workload continuously generates gigabytes of access and application logs. When systems suffer outages, 5xx error spikes, or cyberattacks (brute force credential stuffing, directory traversal, SQL injection, malicious vulnerability bots):
1. **Manual Combing is Impractical**: Sifting through thousands or millions of lines by hand delays incident response.
2. **Memory Overflows**: Naively loading large log files into memory using `file.read()` or `file.readlines()` causes `MemoryError` crashes.
3. **No Heavy Footprint**: In air-gapped, production, or restricted container environments, engineers cannot install heavy third-party packages or spin up complex monitoring infrastructure on the fly.

**LogSentinel** solves this as a lightweight, lightning-fast incident detection engine built entirely with native Python.

---

## 🚀 Key Capabilities

- **Constant $O(1)$ Memory Footprint**: Uses Python generators (`yield`) to stream multi-gigabyte log files line-by-line.
- **Multi-Format Parsers**:
  - Apache & Nginx Combined/Common Log Format with named regex groups.
  - Cloud-native structured JSON microservice logs.
- **Automated Security & Reliability Anomaly Detectors**:
  - **Brute-Force & Credential Stuffing**: Tracks repeated 401/403 failure bursts in a sliding time window (`collections.deque`).
  - **HTTP 5xx Server Outage Spikes**: Detects outage surges in rolling 1-minute time buckets (`collections.defaultdict`).
  - **Security Exploit Signatures**: Detects directory traversal (`../../etc/passwd`), SQL injection fragments (`UNION SELECT`), and vulnerability scanners (`nikto`, `sqlmap`).
  - **Latency SLA Bottlenecks**: Computes latency percentiles (P50, P90, P95) using the built-in `statistics` module.
- **Multi-Channel Incident Reporting**:
  - Vibrant ANSI-colored terminal executive dashboard.
  - Exportable Markdown post-mortem document.
  - Machine-readable JSON alerts for webhook/SIEM integration.
- **Interactive Terminal Investigation Shell**: Menu-driven interface for ad-hoc log forensics.

---

## 📂 Project Architecture

```
log_sentinel/
│
├── sentinel/
│   ├── __init__.py           # Package exports & public API
│   ├── exceptions.py        # Custom exception hierarchy & chaining
│   ├── context.py           # Context managers (__enter__, __exit__, contextlib)
│   ├── decorators.py        # Metaprogramming (@timing, @audit_log, @safe_parse)
│   ├── models.py            # Dataclasses, properties, enums & dunder methods
│   ├── parsers/             # Extensible parser subsystem (abc.ABC)
│   │   ├── base.py          # Abstract Base Parser
│   │   ├── combined.py      # Apache/Nginx combined regex parser
│   │   └── json_parser.py   # Cloud JSON microservice parser
│   ├── detectors/           # Anomaly & security threat detection rules
│   │   ├── base.py          # Abstract Base Detector
│   │   ├── brute_force.py   # Sliding-window rate tracker (collections.deque)
│   │   ├── error_spikes.py  # Rolling 5xx outage detector (collections.defaultdict)
│   │   ├── threats.py       # Regex signature & set matching (for-else loop)
│   │   └── performance.py   # Latency SLA percentiles (statistics module)
│   ├── storage.py           # Generators (yield) & atomic file persistence
│   ├── reporter.py          # ANSI dashboard, Markdown & JSON reports
│   ├── engine.py            # SentinelEngine orchestrating streaming & detection
│   └── cli.py               # argparse CLI and interactive REPL
│
├── tests/
│   ├── test_models.py       # Dunder methods, operators & property tests
│   ├── test_parsers.py      # Regex parsing, edge cases & malformed lines
│   ├── test_detectors.py    # Anomaly thresholds, sliding windows & signatures
│   └── test_engine.py       # End-to-end integration & streaming verification
│
├── sample_data/
│   ├── web_access.log       # Clean web traffic log
│   ├── security_incident.log# Attack log (brute force, SQLi, traversal, 5xx outage)
│   └── microservice.json    # Modern cloud JSON log
│
├── main.py                  # CLI executable entrypoint
├── PYTHON_CONCEPTS.md       # Comprehensive Python Essentials concept guide
└── README.md                # Project documentation
```

---

## ⚡ Quick Start & Usage

Because LogSentinel uses 100% Python standard library, there are **no external requirements to install**.

### 1. Run Interactive Investigation Shell
Launch the interactive terminal investigation menu:
```powershell
python main.py
```
*(or explicitly: `python main.py interactive`)*

---

### 2. Scan a Log File for Incidents & Threats
Run full forensic analysis across all detection rules:
```powershell
python main.py scan sample_data/security_incident.log --format all --out incident_report.md
```
- Outputs a terminal dashboard with status codes, error rate, and incident details.
- Saves an executive Markdown post-mortem to `incident_report.md`.
- Saves a machine-readable JSON payload to `incident_report.json`.

---

### 3. Analyze Structured JSON Microservice Logs
```powershell
python main.py scan sample_data/microservice.json --parser json
```

---

### 4. Display Traffic Volume & Performance Statistics
```powershell
python main.py stats sample_data/web_access.log
```

---

### 5. Focused Security Threat Scan
```powershell
python main.py threats sample_data/security_incident.log
```

---

## 🧪 Running Automated Unit Tests

Run the complete test suite with Python's built-in `unittest` runner:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

All 22 unit and integration tests run in under 100 milliseconds with zero external test runners needed.

---

## 📚 Python Essentials Reference

For an in-depth breakdown of every Python language feature used in this project (complete with file references and code examples), see **[`PYTHON_CONCEPTS.md`](file:///C:/Users/srinivas/.gemini/antigravity/scratch/log_sentinel/PYTHON_CONCEPTS.md)**.
