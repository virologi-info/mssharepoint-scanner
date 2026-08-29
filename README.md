# Microsoft SharePoint CVE Scanner

A **defensive, version-based** SharePoint assessment tool for the CVEs configured in `sharepoint-cve-scanner.py`.

## Three-state verdict

The scanner deliberately returns one of:

- `VULNERABLE`
- `NOT_VULNERABLE`
- `UNKNOWN`

An unknown build or product edition is **never defaulted to Subscription Edition and never treated as safe**.

## Usage

```bash
# Manual build
python3 sharepoint-cve-scanner.py --version 16.0.19725.20522

# Specify edition explicitly when known
python3 sharepoint-cve-scanner.py \
  --version 16.0.10417.20198 \
  --edition "Server 2019"

# Best-effort local DLL version extraction
python3 sharepoint-cve-scanner.py --local /path/to/Microsoft.SharePoint.dll

# Non-destructive remote version discovery
python3 sharepoint-cve-scanner.py --remote https://sharepoint.example.com

# Authorized bounded discovery
python3 sharepoint-cve-scanner.py --discover 192.0.2.0/28 --ports 80,443
```

TLS certificates are verified by default. `--insecure` is available only as an explicit opt-in for controlled labs/self-signed environments.

## Hardening controls

- Unknown build/edition -> `UNKNOWN`.
- Discovery is capped at 4096 targets per invocation.
- Worker threads are capped at 64.
- Remote URLs require an explicit `http://` or `https://` scheme.
- HTML report values are escaped.

## Limitations

This is a **version assessment**, not exploitation or vulnerability proof. Remote SharePoint servers do not always disclose an accurate build number. When the build cannot be determined, use an authenticated/local inventory method and treat the result as `UNKNOWN` until verified.

Always compare the configured fixed builds with the current Microsoft security advisory before operational use.
