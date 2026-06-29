# vuln_scan — Puppet/Bolt module

Two things in one module:

1. **`vuln_scan` class** — installs the Trivy binary on Linux and Windows.
2. **`vuln_scan::trivy` task** — runs Trivy and returns its JSON report, which PVS
   triggers across your fleet through the PE Orchestrator and normalizes for VR.

No external module dependencies.

## Install Trivy (the `vuln_scan` class)

Classify the nodes you want PVS to scan with the `vuln_scan` class so Trivy is
present before the task runs.

```puppet
# Latest Trivy
include vuln_scan

# Pin a version and let the module install the curl prerequisite on Linux
class { 'vuln_scan':
  version             => '0.58.1',
  manage_dependencies => true,
}
```

Hiera equivalent:

```yaml
vuln_scan::version: '0.58.1'
vuln_scan::manage_dependencies: true
```

Key parameters: `version` ('latest' or pinned), `linux_install_dir`
(default `/usr/local/bin`), `windows_install_dir` (default `C:\Program Files\trivy`,
added to the system PATH), `manage_dependencies`, and `linux_install_script_url` /
`windows_download_base` for air-gapped mirrors. The install is idempotent — with a
pinned version it re-runs only when the installed version differs.

- **Linux** uses the official Trivy install script to place the binary in `linux_install_dir`.
- **Windows** downloads the release zip, extracts `trivy.exe` to `windows_install_dir`, and adds it to PATH.

## Scan task (`vuln_scan::trivy`)

Runs the installed Trivy binary and returns a **compact** vulnerability report;
PVS collects the per-node output and normalizes it for Puppet VR.

It's a single cross-platform Ruby task (runs via the Puppet agent's bundled Ruby
on Linux and Windows). Rather than returning Trivy's full JSON — which includes
long descriptions, reference-URL lists, and multi-source CVSS, and can exceed the
orchestrator/PCP message-size limit (64 MiB) — the task trims the output on the
node to just the fields PVS needs: `id`, `pkg`, `installed`, `fixed`, `type`,
`severity`, `title` (truncated), and CVSS `score`. In testing this cut a realistic
report by ~96%.

Parameters: `scan_type` (rootfs|fs|image), `target`, `severities`, `trivy_path`,
`timeout`. To shrink further, pass `severities` (e.g. `CRITICAL,HIGH`) to scan
fewer findings.

Output schema (`format: pvs-trivy-compact`):

```json
{
  "format": "pvs-trivy-compact",
  "version": 1,
  "os": { "family": "ubuntu", "name": "22.04" },
  "findings": [
    { "id": "CVE-2023-4911", "pkg": "libc6", "installed": "2.35-0ubuntu3.1",
      "fixed": "2.35-0ubuntu3.4", "type": "ubuntu", "severity": "HIGH",
      "title": "glibc: buffer overflow…", "score": 7.8 }
  ]
}
```

## Task: `vuln_scan::trivy`

Parameters: `scan_type` (rootfs|fs|image), `target`, `severities`, `trivy_path`, `timeout`.
Implementations: `trivy.sh` (Linux/shell) and `trivy.ps1` (Windows/PowerShell).

> Trivy install is **not** handled by this task — install it via your own Puppet
> manifest/class (or a separate Bolt task). If Trivy is missing, the task returns a
> structured `_error` so PVS can surface it.

## Deploy to PE

Add the module to your control repo so Code Manager syncs it to environments:

```ruby
# Puppetfile
mod 'vuln_scan', local: true   # or point at your git source
```

Then `puppet code deploy production --wait`. Confirm it is available:

```
GET https://<primary>:8143/orchestrator/v1/tasks   # look for vuln_scan::trivy
```

## What PVS sends (reference)

```
POST https://<primary>:8143/orchestrator/v1/command/task
{
  "environment": "production",
  "task": "vuln_scan::trivy",
  "params": { "scan_type": "rootfs", "target": "/" },
  "scope": { "node_group": "<group-id>" }      // or {"query": "<PQL>"} or {"nodes": [...]}
}
```
