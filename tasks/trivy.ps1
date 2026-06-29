# vuln_scan::trivy (Windows) -- run Trivy and emit its JSON report on stdout.
# Params arrive as environment variables (input_method: environment).
$ErrorActionPreference = 'Stop'

$scanType   = if ($env:PT_scan_type) { $env:PT_scan_type } else { 'rootfs' }
$target     = if ($env:PT_target)    { $env:PT_target }    else { 'C:\' }
$severities = $env:PT_severities
$trivyBin   = if ($env:PT_trivy_path) { $env:PT_trivy_path } else { 'trivy' }
$timeout    = if ($env:PT_timeout)   { $env:PT_timeout }   else { '10m' }

function Resolve-Trivy($bin) {
  $cmd = Get-Command $bin -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  foreach ($cand in @("$env:ProgramFiles\trivy\trivy.exe", "C:\ProgramData\chocolatey\bin\trivy.exe")) {
    if (Test-Path $cand) { return $cand }
  }
  return $null
}

$trivy = Resolve-Trivy $trivyBin
if (-not $trivy) {
  Write-Output '{"_error":{"kind":"vuln_scan/trivy-missing","msg":"Trivy not found on this node. Install it (e.g. via your Puppet class) or pass trivy_path.","details":{}}}'
  exit 1
}

$args = @($scanType, '--format', 'json', '--quiet', '--scanners', 'vuln', '--timeout', $timeout)
if ($severities) { $args += @('--severity', $severities) }
$args += $target

try {
  $out = & $trivy @args 2>$null
  if ($LASTEXITCODE -ne 0 -and -not $out) {
    Write-Output ('{"_error":{"kind":"vuln_scan/trivy-failed","msg":"Trivy exited ' + $LASTEXITCODE + '","details":{}}}')
    exit $LASTEXITCODE
  }
  # Trivy JSON report -> stdout, parsed by Bolt into the task result.
  $out -join "`n" | Write-Output
} catch {
  $msg = ($_.Exception.Message -replace '"','\"')
  Write-Output ('{"_error":{"kind":"vuln_scan/trivy-failed","msg":"' + $msg + '","details":{}}}')
  exit 1
}
