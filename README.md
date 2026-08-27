# MS SharePoint Scanner

A single-file, dependency-free **defensive** tool for Microsoft SharePoint that combines **service discovery** (single or bulk) with **CVE assessment** for two critical on-premises vulnerabilities:

- **CVE-2026-55040** (Critical 9.1) — JWT token authentication bypass
- **CVE-2026-63520** (High 8.1) — Remote Code Execution via BDC model / unsafe .NET type instantiation

All in one source file — no separate scripts needed.

## Features

### 1. Service Discovery
Find SharePoint servers across single targets or large networks:

| Input type | Example |
|------------|---------|
| Domain | `sharepoint.example.com` |
| Single IP | `192.168.1.10` |
| CIDR block | `192.168.1.0/24` |
| IP range | `10.0.0.10-10.0.0.50` or `10.0.0.10-50` |
| Target file | one per line, mixed types |

- Multi-port probing (default `80,443`)
- Threaded for speed (`--threads`)
- Live progress bar
- Auto-detects SharePoint presence via HTTP body/headers

### 2. CVE Assessment
Evaluate a discovered/known server against the two CVEs:

- **CVE-2026-55040** — authentication bypass (CWE-1390), CVSS 9.1
- **CVE-2026-63520** — RCE (CWE-20), CVSS 8.1

Three modes:
- `--local` — read build version from `Microsoft.SharePoint.dll` (Windows server)
- `--remote` — detect version/build via HTTP
- `--version` — supply the build version directly

### 3. Reports
- Terminal output
- `--json` — machine-readable
- `--html` — visual report

## Usage

### Discovery (bulk or single)

```bash
# Single domain
python3 sharepoint-cve-scanner.py --discover --targets sharepoint.example.com

# CIDR block (mass)
python3 sharepoint-cve-scanner.py --discover --targets 192.168.1.0/24

# IP range (mass)
python3 sharepoint-cve-scanner.py --discover --targets 10.0.0.10-10.0.0.50

# From a file (mixed targets, one per line)
python3 sharepoint-cve-scanner.py --discover --file targets.txt

# Custom ports + more threads
python3 sharepoint-cve-scanner.py --discover --targets 10.0.0.0/24 --ports 80,443,4443 --threads 100
```

### CVE assessment

```bash
# Local (Windows): read build from DLL
python3 sharepoint-cve-scanner.py --local C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.dll

# Remote
python3 sharepoint-cve-scanner.py --remote https://sharepoint.example.com

# Manual build version
python3 sharepoint-cve-scanner.py --version 16.0.19725.20434

# HTML + JSON report
python3 sharepoint-cve-scanner.py --local <dll> --html report.html --json report.json
```

## Affected versions

| CVE | Edition | Fixed build |
|-----|---------|-------------|
| CVE-2026-55040 | Enterprise 2016 | 16.0.5561.1001 |
| CVE-2026-55040 | Server 2019 | 16.0.10417.20175 |
| CVE-2026-55040 | Subscription Edition | 16.0.19725.20434 |
| CVE-2026-63520 | Enterprise 2016 | 16.0.5565.1001 |
| CVE-2026-63520 | Server 2019 | 16.0.10417.20198 |
| CVE-2026-63520 | Subscription Edition | 16.0.19725.20522 |

**Note:** CVE-2026-55040 (auth bypass) chains with CVE-2026-63520 (RCE) to form an **unauthenticated RCE**. Apply both Microsoft updates.

## Important disclaimers

- This is a **defensive/non-destructive** tool. Discovery only detects SharePoint presence via HTTP — it does not attack.
- **Use only on infrastructure you are authorized to test** (your own systems or an in-scope bug bounty program). Scanning public IP ranges without permission may be illegal.
- Edition detection from build number is **heuristic**. For an authoritative assessment, run `--local` on the actual server.
- Remote mode may not always extract the build version depending on server configuration.
