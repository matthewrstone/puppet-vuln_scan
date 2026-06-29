# frozen_string_literal: true
#
# Shared helper for the vuln_scan::trivy task. Reads a Trivy JSON report from the
# file path given as ARGV[0] and prints a COMPACT report on stdout — only the
# fields PVS needs — so the payload stays well under the orchestrator/PCP
# message-size limit.
#
# Run with the Puppet agent's bundled Ruby (guaranteed present on managed nodes):
#   /opt/puppetlabs/puppet/bin/ruby trim.rb <trivy.json>

require 'json'

def emit_error(kind, msg)
  puts({ '_error' => { 'kind' => kind, 'msg' => msg, 'details' => {} } }.to_json)
  exit 1
end

begin
  report = JSON.parse(File.read(ARGV[0]))
rescue StandardError => e
  emit_error('vuln_scan/parse-failed', "Could not parse Trivy JSON: #{e.message[0, 200]}")
end

def best_score(cvss)
  return nil unless cvss.is_a?(Hash) && !cvss.empty?

  %w[nvd redhat ghsa].each do |src|
    return (cvss[src]['V3Score'] || cvss[src]['V2Score']) if cvss[src]
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
  'format'   => 'pvs-trivy-compact',
  'version'  => 1,
  'os'       => { 'family' => os['Family'], 'name' => os['Name'] },
  'findings' => findings,
}.to_json)
