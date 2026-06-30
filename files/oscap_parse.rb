# frozen_string_literal: true
#
# Shared helper for vuln_scan::oscap. Reads an OpenSCAP OVAL results file
# (ARGV[0]) plus the OVAL definitions file (ARGV[1]) and prints a COMPACT CVE
# report on stdout — the same field shape PSM's Trivy task emits.
#
# Extracts, per vulnerable definition: CVE reference(s), title, advisory severity,
# and the affected package + fixed version (from the dpkginfo tests/objects/states).
#
# Run with the Puppet agent's bundled Ruby (stdlib REXML/JSON, no gems).

require 'rexml/document'
require 'json'

def emit_error(kind, msg)
  puts({ '_error' => { 'kind' => kind, 'msg' => msg, 'details' => {} } }.to_json)
  exit 1
end

def strip_epoch(evr)
  return nil unless evr && !evr.empty?
  evr.sub(/\A\d+:/, '')
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

# Installed package versions actually collected from the node (system characteristics
# in the results file) -> {package => installed evr}, so findings carry the real
# installed version, not just the fixed-version target.
installed = {}
results.each_element('//*[local-name()="dpkginfo_item"]') do |it|
  name = nil
  evr = nil
  it.each_element('./*[local-name()="name"]') { |n| name ||= n.text }
  it.each_element('./*[local-name()="evr"]') { |e| evr ||= e.text }
  installed[name] ||= strip_epoch(evr) if name && evr && !evr.strip.empty?
end

# Index dpkginfo tests -> object/state, objects -> package name, states -> fixed evr.
test_obj = {}
test_states = {}
definitions.each_element('//*[local-name()="dpkginfo_test"]') do |t|
  tid = t.attributes['id']
  next unless tid
  t.each_element('./*[local-name()="object"]') { |o| test_obj[tid] = o.attributes['object_ref'] }
  states = []
  t.each_element('./*[local-name()="state"]') { |s| states << s.attributes['state_ref'] }
  test_states[tid] = states
end

# Ubuntu OVAL lists affected binary packages in OVAL *variables*; dpkginfo objects
# reference them by var_ref rather than carrying a literal package name.
var_values = {}
%w[constant_variable local_variable variable external_variable].each do |vt|
  definitions.each_element(%(//*[local-name()="#{vt}"])) do |v|
    vid = v.attributes['id']
    next unless vid
    vals = []
    v.each_element('.//*[local-name()="value"]') { |val| vals << val.text.strip if val.text && !val.text.strip.empty? }
    var_values[vid] = vals.uniq unless vals.empty?
  end
end

# dpkginfo object -> list of package names (literal text and/or resolved var_ref).
obj_pkgs = {}
definitions.each_element('//*[local-name()="dpkginfo_object"]') do |o|
  oid = o.attributes['id']
  next unless oid
  names = []
  o.each_element('./*[local-name()="name"]') do |n|
    if n.text && !n.text.strip.empty?
      names << n.text.strip
    elsif (ref = n.attributes['var_ref']) && var_values[ref]
      names.concat(var_values[ref])
    end
  end
  obj_pkgs[oid] = names.uniq unless names.empty?
end

state_fixed = {}
definitions.each_element('//*[local-name()="dpkginfo_state"]') do |s|
  sid = s.attributes['id']
  next unless sid
  s.each_element('./*[local-name()="evr"]') { |e| state_fixed[sid] ||= strip_epoch(e.text) }
end

# Advisory severities across distros -> canonical ladder (case-insensitive).
SEV = {
  'critical' => 'CRITICAL', 'high' => 'HIGH', 'important' => 'HIGH',
  'medium' => 'MEDIUM', 'moderate' => 'MEDIUM',
  'low' => 'LOW', 'negligible' => 'LOW'
}.freeze

findings = []
seen = {}
definitions.each_element('//*[local-name()="definition"]') do |d|
  id = d.attributes['id']
  next unless id && true_ids[id]
  # Skip non-vulnerability definitions (inventory/compliance/miscellaneous noise).
  klass = d.attributes['class']
  next if klass && !%w[vulnerability patch].include?(klass)

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

  # Affected package(s) + fixed version from the definition's dpkginfo criteria.
  pkgs = []
  d.each_element('.//*[local-name()="criterion"]') do |c|
    tref = c.attributes['test_ref']
    next unless tref && test_obj.key?(tref)
    names = obj_pkgs[test_obj[tref]]
    next unless names
    fixed = nil
    (test_states[tref] || []).each { |sid| fixed ||= state_fixed[sid] }
    names.each { |name| pkgs << [name, fixed] }
  end
  pkgs.uniq!

  sev = SEV[(severity || '').downcase] || 'UNKNOWN'
  ids = cves.empty? ? [id] : cves.uniq
  ids.each do |cve|
    rows = pkgs.empty? ? [[nil, nil]] : pkgs
    rows.each do |(name, fixed)|
      key = "#{cve}|#{name}|#{fixed}"
      next if seen[key]
      seen[key] = true
      findings << {
        'id'        => cve,
        'title'     => title ? title[0, 300] : cve,
        'severity'  => sev,
        'pkg'       => name,
        'installed' => name ? installed[name] : nil,
        'fixed'     => fixed,
      }
    end
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
