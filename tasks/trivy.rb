#!/usr/bin/env ruby
# frozen_string_literal: true

# vuln_scan::trivy -- run Trivy and return a COMPACT vulnerability report.
#
# Trivy's native JSON is huge (full descriptions, reference URLs, multi-source
# CVSS, datasource metadata...) and can exceed the orchestrator/PCP message-size
# limit. This task trims the output on the node to just the fields PVS needs to
# build the normalized VR report, keeping the payload small.
#
# Runs cross-platform via the Puppet agent's bundled Ruby (Linux and Windows).
# Params are read as JSON on stdin (input_method: stdin), with PT_* env fallback.

require 'json'
require 'open3'
require 'rbconfig'

def windows?
  (RbConfig::CONFIG['host_os'] =~ /mswin|mingw|cygwin/) ? true : false
end

def emit_error(kind, msg)
  puts({ '_error' => { 'kind' => kind, 'msg' => msg, 'details' => {} } }.to_json)
  exit 1
end

# ---- parameters ------------------------------------------------------------
params = {}
begin
  raw = $stdin.read
  params = JSON.parse(raw) unless raw.nil? || raw.empty?
rescue StandardError
  params = {}
end

def param(params, key, default = nil)
  v = params[key]
  v = ENV["PT_#{key}"] if v.nil?
  (v.nil? || v == '') ? default : v
end

scan_type  = param(params, 'scan_type', 'rootfs')
target     = param(params, 'target', windows? ? 'C:\\' : '/')
severities = param(params, 'severities')
trivy_path = param(params, 'trivy_path')
timeout    = param(params, 'timeout', '10m')

# ---- locate trivy ----------------------------------------------------------
def find_trivy(explicit)
  return explicit if explicit && File.file?(explicit)

  exe = windows? ? 'trivy.exe' : 'trivy'
  candidates = (ENV['PATH'] || '').split(File::PATH_SEPARATOR).map { |d| File.join(d, exe) }
  candidates += ['/usr/local/bin/trivy', '/usr/bin/trivy', '/opt/trivy/trivy',
                 'C:\\Program Files\\trivy\\trivy.exe']
  candidates.find { |c| File.file?(c) } || exe # fall back to bare name on PATH
end

trivy = find_trivy(trivy_path)

# ---- run trivy -------------------------------------------------------------
cmd = [trivy, scan_type, '--format', 'json', '--quiet', '--scanners', 'vuln',
       '--timeout', timeout]
cmd += ['--severity', severities] if severities
cmd << target

begin
  out, err, status = Open3.capture3(*cmd)
rescue Errno::ENOENT
  emit_error('vuln_scan/trivy-missing',
             'Trivy not found on this node. Install it (e.g. via the vuln_scan class) or pass trivy_path.')
end

if !status.success? && (out.nil? || out.empty?)
  emit_error('vuln_scan/trivy-failed', "Trivy exited #{status.exitstatus}: #{err.to_s[0, 300]}")
end

begin
  report = JSON.parse(out)
rescue StandardError => e
  emit_error('vuln_scan/parse-failed', "Could not parse Trivy JSON: #{e.message[0, 200]}")
end

# ---- trim to compact schema ------------------------------------------------
def best_score(cvss)
  return nil unless cvss.is_a?(Hash) && !cvss.empty?

  %w[nvd redhat ghsa].each do |src|
    next unless cvss[src]

    return cvss[src]['V3Score'] || cvss[src]['V2Score']
  end
  first = cvss.values.first
  first['V3Score'] || first['V2Score']
end

findings = []
(report['Results'] || []).each do |res|
  pkg_type = res['Type']
  (res['Vulnerabilities'] || []).each do |v|
    title = v['Title']
    title = title[0, 300] if title.is_a?(String)
    findings << {
      'id'        => v['VulnerabilityID'],
      'pkg'       => v['PkgName'],
      'installed' => v['InstalledVersion'],
      'fixed'     => v['FixedVersion'],
      'type'      => pkg_type,
      'severity'  => v['Severity'],
      'title'     => title,
      'score'     => best_score(v['CVSS']),
    }
  end
end

os = (report['Metadata'] || {})['OS'] || {}
puts({
  'format'    => 'pvs-trivy-compact',
  'version'   => 1,
  'os'        => { 'family' => os['Family'], 'name' => os['Name'] },
  'findings'  => findings,
}.to_json)
