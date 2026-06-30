# frozen_string_literal: true
#
# Helper for vuln_scan::oscap_xccdf. Reads an XCCDF results file (ARGV[0]) and,
# optionally, the SSG datastream (ARGV[1]) for rule titles + framework references,
# and prints a COMPACT compliance result on stdout.
#
# Run with the Puppet agent's bundled Ruby (stdlib REXML/JSON, no gems).

require 'rexml/document'
require 'json'

def emit_error(kind, msg)
  puts({ '_error' => { 'kind' => kind, 'msg' => msg, 'details' => {} } }.to_json)
  exit 1
end

def humanize(idref)
  base = idref.to_s.split('content_rule_').last || idref.to_s
  base.tr('_', ' ')
end

begin
  results = REXML::Document.new(File.read(ARGV[0]))
  ds = (ARGV[1] && File.exist?(ARGV[1])) ? REXML::Document.new(File.read(ARGV[1])) : nil
rescue StandardError => e
  emit_error('vuln_scan/parse-failed', "Could not parse XCCDF XML: #{e.message[0, 200]}")
end

# Rule metadata (title + framework references) from the datastream, if provided.
meta = {}
benchmark_title = nil
if ds
  ds.each_element('//*[local-name()="Benchmark"]') do |b|
    b.each_element('./*[local-name()="title"]') { |t| benchmark_title ||= t.text }
  end
  ds.each_element('//*[local-name()="Rule"]') do |r|
    rid = r.attributes['id']
    next unless rid
    title = nil
    refs = []
    r.each_element('./*[local-name()="title"]') { |t| title ||= t.text }
    r.each_element('.//*[local-name()="reference"]') { |x| refs << x.text.strip if x.text && !x.text.strip.empty? }
    r.each_element('.//*[local-name()="ident"]') { |x| refs << x.text.strip if x.text && !x.text.strip.empty? }
    meta[rid] = { 'title' => title, 'refs' => refs.uniq }
  end
end

tr = nil
results.each_element('//*[local-name()="TestResult"]') { |t| tr ||= t }
emit_error('vuln_scan/no-result', 'No XCCDF TestResult in the results file.') unless tr

profile = tr.attributes['profile']
benchmark = nil
tr.each_element('./*[local-name()="benchmark"]') { |b| benchmark ||= (b.attributes['id'] || b.attributes['href']) }
score = nil
tr.each_element('./*[local-name()="score"]') { |s| score ||= s.text&.to_f }

passed = failed = errored = na = 0
rules = []
tr.each_element('./*[local-name()="rule-result"]') do |rr|
  idref = rr.attributes['idref']
  sev = rr.attributes['severity'] || 'unknown'
  res = nil
  rr.each_element('./*[local-name()="result"]') { |x| res ||= x.text }
  res = (res || '').downcase
  case res
  when 'pass', 'fixed' then passed += 1
  when 'fail' then failed += 1
  when 'error' then errored += 1
  else na += 1
  end
  m = meta[idref] || {}
  rules << {
    'id'       => idref,
    'title'    => m['title'] || humanize(idref),
    'result'   => res,
    'severity' => sev,
    'refs'     => m['refs'] || [],
  }
end

# Score: prefer the benchmark's own score; else compute pass-rate.
if score.nil?
  denom = passed + failed
  score = denom.zero? ? nil : (passed.to_f / denom * 100).round(1)
end

os = {}
if File.exist?('/etc/os-release')
  data = File.read('/etc/os-release')
  os = { 'family' => data[/^ID=\"?([a-zA-Z]+)/, 1], 'name' => data[/^VERSION_ID=\"?([0-9.]+)/, 1] }
end

puts({
  'format' => 'psm-xccdf-compact', 'version' => 1,
  'benchmark' => benchmark, 'benchmark_title' => benchmark_title,
  'profile' => profile, 'score' => score,
  'passed' => passed, 'failed' => failed, 'error' => errored, 'notapplicable' => na,
  'os' => os, 'rules' => rules,
}.to_json)
