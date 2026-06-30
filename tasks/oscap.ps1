# vuln_scan::oscap (Windows) -- OpenSCAP/OVAL is Linux-only. Return a structured
# error so PSM surfaces it cleanly per node rather than failing opaquely.
Write-Output (@{ _error = @{ kind = "vuln_scan/unsupported-os"; msg = "OpenSCAP (oscap) is not available on Windows; use the Trivy source for Windows nodes."; details = @{} } } | ConvertTo-Json -Compress)
exit 1
