#!/usr/bin/env bash
# vuln_scan::oscap_xccdf (Linux) -- run an XCCDF profile eval (CIS/STIG/PCI/HIPAA)
# against the node's SCAP Security Guide datastream and emit a compact compliance
# result. Parsing is done by the Puppet agent's bundled Ruby via xccdf_parse.rb.
set -o pipefail

oscap_bin="${PT_oscap_path:-oscap}"
profile="${PT_profile:-}"
datastream="${PT_datastream:-}"

emit_error() { printf '{"_error":{"kind":"%s","msg":"%s","details":{}}}\n' "$1" "$2"; exit 1; }

command -v "$oscap_bin" >/dev/null 2>&1 || emit_error "vuln_scan/oscap-missing" \
  "oscap not found. Install OpenSCAP (openscap-scanner)."
[ -n "$profile" ] || emit_error "vuln_scan/profile-missing" "A profile id is required."

ruby_bin="/opt/puppetlabs/puppet/bin/ruby"
[ -x "$ruby_bin" ] || ruby_bin="$(command -v ruby 2>/dev/null)"
[ -n "$ruby_bin" ] || emit_error "vuln_scan/ruby-missing" "No Ruby available to process results."
parser="${PT__installdir}/vuln_scan/files/xccdf_parse.rb"
[ -f "$parser" ] || emit_error "vuln_scan/parser-missing" "xccdf_parse.rb not found at ${parser}."

# Auto-detect the SSG datastream for this OS if not supplied.
if [ -z "$datastream" ]; then
  ssg_dir="/usr/share/xml/scap/ssg/content"
  [ -r /etc/os-release ] && . /etc/os-release 2>/dev/null
  ver_major="${VERSION_ID%%.*}"
  ver_nodot="${VERSION_ID//./}"
  # SSG filenames drop the dot in the version, e.g. ssg-ubuntu2404-ds.xml,
  # ssg-rhel9-ds.xml. Try nodot (Ubuntu), full, major (RHEL), then bare.
  for cand in \
    "${ssg_dir}/ssg-${ID}${ver_nodot}-ds.xml" \
    "${ssg_dir}/ssg-${ID}${VERSION_ID}-ds.xml" \
    "${ssg_dir}/ssg-${ID}${ver_major}-ds.xml" \
    "${ssg_dir}/ssg-${ID}-ds.xml"; do
    [ -f "$cand" ] && datastream="$cand" && break
  done
  if [ -z "$datastream" ]; then
    first="$(ls "${ssg_dir}"/ssg-*-ds.xml 2>/dev/null | head -1)"
    [ -n "$first" ] && datastream="$first"
  fi
fi
[ -n "$datastream" ] && [ -f "$datastream" ] || emit_error "vuln_scan/ssg-missing" \
  "No SCAP Security Guide datastream found (install the 'ssg-*' / scap-security-guide package, or pass datastream). OS ID='${ID:-unknown}'."

# Accept a short profile name or a full xccdf_org.ssgproject id.
case "$profile" in
  xccdf_org.ssgproject.content_profile_*) prof="$profile" ;;
  *) prof="xccdf_org.ssgproject.content_profile_${profile}" ;;
esac

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
results="$tmp/xccdf-results.xml"
# oscap returns 2 when rules fail; that's expected — rely on the results file.
"$oscap_bin" xccdf eval --profile "$prof" --results "$results" "$datastream" >/dev/null 2>"$tmp/err" || true
if [ ! -f "$results" ]; then
  msg="$(tr -d '\n' <"$tmp/err" | sed 's/"/\\"/g')"
  emit_error "vuln_scan/oscap-failed" "oscap xccdf eval produced no results: ${msg}"
fi

"$ruby_bin" "$parser" "$results" "$datastream"
