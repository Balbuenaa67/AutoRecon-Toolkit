# AutoRecon Toolkit

A Python-based network reconnaissance toolkit built around Nmap. It automates TCP port scanning, parses Nmap XML results, analyzes discovered services, and generates structured reconnaissance reports.

Designed for cybersecurity learning, penetration testing labs, and authorized security assessments.

## Features

- **Nmap integration:** TCP connect scans with service and version detection.
- **Three scan profiles:** Quick, Standard, and Full.
- **XML import:** Analyze existing Nmap XML files without repeating scans.
- **Service analysis:** Recommendations for enumerating common services, including SSH, HTTP, SMB, FTP, and RDP.
- **Report generation:** Export reconnaissance results as Markdown, JSON, or both.
- **Command-line interface:** Configure targets, profiles, output directories, and export formats.
- **Automated testing:** Unit tests with pytest and continuous integration using GitHub Actions.

## Requirements

- Python 3.10 or newer
- Nmap installed and available in your system PATH
- Windows or Linux

Nmap is only required when performing new scans. Importing existing XML files does not require executing Nmap.

## Installation

Clone the repository:

```bash
git clone https://github.com/Balbuenaa67/AutoRecon-Toolkit.git
cd AutoRecon-Toolkit
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

Or on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the project:

```bash
python -m pip install -e .
```

For development and testing:

```bash
python -m pip install -e ".[dev]"
```

## Usage

### Quick scan

```bash
autorecon --target 127.0.0.1 --profile quick
```

### Standard scan

```bash
autorecon --target 127.0.0.1 --profile standard
```

### Full TCP scan

```bash
autorecon --target 127.0.0.1 --profile full
```

### Analyze an existing Nmap XML file

```bash
autorecon --xml tests/sample_nmap.xml
```

### Export Markdown and JSON

```bash
autorecon --xml tests/sample_nmap.xml --format both
```

### Specify an output directory

```bash
autorecon --xml tests/sample_nmap.xml --format both --output reports/lab1
```

## Scan Profiles

| Profile | TCP Ports | Detection |
|---|---|---|
| Quick | Top 100 | Service/version detection |
| Standard | Top 1,000 | Service/version detection |
| Full | All 65,535 | Service/version detection |

Scanning currently accepts a single private or loopback IP address per execution. This restriction is not a substitute for obtaining authorization.

## Reports

AutoRecon Toolkit generates structured reports containing:

- Scan metadata
- Discovered hosts and open TCP ports
- Identified services, products, and versions
- Summary statistics
- Service-specific enumeration recommendations

An open port or an exposed service does not necessarily represent a vulnerability. Recommendations are informational and require further verification.

Generated results are stored in the selected output directory and excluded from Git tracking by default.

## Testing

Run the automated test suite:

```bash
python -m pytest -v
```

The project also uses GitHub Actions to run tests automatically on pushes and pull requests targeting the main branch.

## Project Structure

```text
AutoRecon-Toolkit/
├── .github/workflows/
├── autorecon/
│   ├── analyzer.py
│   ├── exporter.py
│   ├── parser.py
│   ├── reporter.py
│   └── scanner.py
├── tests/
├── main.py
├── pyproject.toml
└── README.md
```

## Security and Scope

AutoRecon Toolkit is intended exclusively for systems and networks where explicit authorization has been granted.

The toolkit performs reconnaissance and provides enumeration guidance. It does not automatically exploit vulnerabilities or establish that detected services are insecure.

## Release Status

**Version 1.0.0 — Stable Release**

AutoRecon Toolkit supports Nmap scanning, XML import, service analysis,
Markdown and JSON reporting, and automated testing on Windows and Ubuntu.

The project will continue receiving improvements and new features.