# frozen_string_literal: true
#
# Shared helper for vuln_scan::oscap. Reads an OpenSCAP OVAL results file
# (ARGV[0]) plus the OVAL definitions file (ARGV[1]) and prints a COMPACT CVE
# report on stdout — the same field shape PSM's Trivy task emits.
#
# Run with the Puppet agent's bundled Ruby (stdlib REXML/JSON, no gems).

require 'rexml/document'
require 'json'

def emit_error(kind, msg)
  puts({ '_error' => { 'kind' => kind, 'msg' => msg, 'details' => {} } }.to_json)
  exit 1
end

begin
  results = REXML::Document.new(File.read(ARGV[0]))
  definitions = REXML::Document.new(File.read(ARGV[1]))
rescue StandardError => e
  emit_error('vuln_scan/parse-failed', "Could not parse OVAL XML: #{e.message[0, 200]}")
end

# Which definitions evaluated true (vulnerable) on this host.
true_ids = {}
results.each_element('//*[local-name()="definition"]') do |d|
  id = d.attributes['definition_id']
  true_ids[id] = true if id && d.attributes['result'] == 'true'
end

# Map RedHat-style advisory severities onto the canonical ladder.
SEV = { 'Critical' => 'CRITICAL', 'Important' => 'HIGH',
        'Moderate' => 'MEDIUM', 'Low' => 'LOW' }.freeze

findings = []
definitions.each_element('//*[local-name()="definition"]') do |d|
  id = d.attributes['id']
  next unless id && true_ids[id]

  title = nil
  severity = nil
  cves = []
  d.each_element('.//*[local-name()="title"]') { |t| title ||= t.text }
  d.each_element('.//*[local-name()="severity"]') { |s| severity ||= s.text }
  d.each_element('.//*[local-name()="reference"]') do |ref|
    if (ref.attributes['source'] || '').upcase == 'CVE' && ref.attributes['ref_id']
      cves << ref.attributes['ref_id']
    end
  end

  sev = SEV[severity] || 'UNKNOWN'
  ids = cves.empty? ? [id] : cves.uniq
  ids.each do |cve|
    findings << {
      'id'       => cve,
      'title'    => title ? title[0, 300] : cve,
      'severity' => sev,
      'pkg'      => nil,   # package/fixed-version extraction is a future enhancement
      'fixed'    => nil,
    }
  end
end

os = {}
if File.exist?('/etc/os-release')
  data = File.read('/etc/os-release')
  os = {
    'family' => data[/^ID=\"?([a-zA-Z]+)/, 1],
    'name'   => data[/^VERSION_ID=\"?([0-9.]+)/, 1],
  }
end

puts({ 'format' => 'psm-oscap-compact', 'version' => 1, 'os' => os,
       'findings' => findings }.to_json)
