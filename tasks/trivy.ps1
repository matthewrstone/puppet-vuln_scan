# vuln_scan::trivy (Windows) -- run Trivy, then trim its JSON to a compact report
# using the Puppet agent's bundled Ruby (no dependency on a system ruby/PATH).
$ErrorActionPreference = 'Stop'

function Emit-Error($kind, $msg) {
  Write-Output (@{ _error = @{ kind = $kind; msg = $msg; details = @{} } } | ConvertTo-Json -Compress)
  exit 1
}

$scanType   = if ($env:PT_scan_type) { $env:PT_scan_type } else { 'rootfs' }
$target     = if ($env:PT_target)    { $env:PT_target }    else { 'C:\' }
$severities = $env:PT_severities
$trivyBin   = $env:PT_trivy_path
$timeout    = if ($env:PT_timeout)   { $env:PT_timeout }   else { '10m' }

# Locate trivy.
if (-not $trivyBin -or -not (Test-Path $trivyBin)) {
  $cmd = Get-Command trivy -ErrorAction SilentlyContinue
  if ($cmd) {
    $trivyBin = $cmd.Source
  } else {
    foreach ($c in @("$env:ProgramFiles\trivy\trivy.exe", 'C:\ProgramData\chocolatey\bin\trivy.exe')) {
      if (Test-Path $c) { $trivyBin = $c; break }
    }
  }
}
if (-not $trivyBin) { Emit-Error 'vuln_scan/trivy-missing' 'Trivy not found. Install via the vuln_scan class or pass trivy_path.' }

# Locate the Puppet agent ruby (guaranteed on managed nodes), else PATH ruby.
$rubyBin = $null
foreach ($c in @("$env:ProgramFiles\Puppet Labs\Puppet\puppet\bin\ruby.exe", "$env:ProgramFiles\Puppet Labs\Puppet\bin\ruby.exe")) {
  if (Test-Path $c) { $rubyBin = $c; break }
}
if (-not $rubyBin) { $rubyBin = (Get-Command ruby -ErrorAction SilentlyContinue).Source }
if (-not $rubyBin) { Emit-Error 'vuln_scan/ruby-missing' 'No Ruby available to process results.' }

$trim = Join-Path $env:PT__installdir 'vuln_scan\files\trim.rb'
if (-not (Test-Path $trim)) { Emit-Error 'vuln_scan/trim-missing' "Helper trim.rb not found at $trim." }

$tmpJson = [System.IO.Path]::GetTempFileName()
try {
  $args = @($scanType, '--format', 'json', '--quiet', '--scanners', 'vuln', '--timeout', $timeout)
  if ($severities) { $args += @('--severity', $severities) }
  $args += $target

  & $trivyBin @args 1> $tmpJson 2> "$tmpJson.err"
  if ($LASTEXITCODE -ne 0 -and -not (Get-Item $tmpJson).Length) {
    $msg = (Get-Content "$tmpJson.err" -Raw) -replace '"', '\"' -replace "`r?`n", ' '
    Emit-Error 'vuln_scan/trivy-failed' "Trivy failed: $msg"
  }

  # Trim on the node so only a compact report crosses the task engine.
  & $rubyBin $trim $tmpJson
} finally {
  Remove-Item $tmpJson, "$tmpJson.err" -Force -ErrorAction SilentlyContinue
}
