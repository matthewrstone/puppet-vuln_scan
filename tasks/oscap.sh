#!/usr/bin/env bash
# vuln_scan::oscap (Linux) -- run an OpenSCAP OVAL eval and emit a compact CVE
# report (same shape as the Trivy task). Trimming/parsing is done by the Puppet
# agent's bundled Ruby via files/oscap_parse.rb.
set -o pipefail

oscap_bin="${PT_oscap_path:-oscap}"
oval_file="${PT_oval_file:-}"
oval_url="${PT_oval_url:-}"

emit_error() { printf '{"_error":{"kind":"%s","msg":"%s","details":{}}}\n' "$1" "$2"; exit 1; }

command -v "$oscap_bin" >/dev/null 2>&1 || emit_error "vuln_scan/oscap-missing" \
  "oscap not found. Install OpenSCAP (e.g. the openscap-scanner package)."

ruby_bin="/opt/puppetlabs/puppet/bin/ruby"
[ -x "$ruby_bin" ] || ruby_bin="$(command -v ruby 2>/dev/null)"
[ -n "$ruby_bin" ] || emit_error "vuln_scan/ruby-missing" "No Ruby available to process results."

parser="${PT__installdir}/vuln_scan/files/oscap_parse.rb"
[ -f "$parser" ] || emit_error "vuln_scan/parser-missing" "oscap_parse.rb not found at ${parser}."

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# No feed given? Derive the distro OVAL feed from the node's own /etc/os-release.
if [ -z "$oval_file" ] && [ -z "$oval_url" ] && [ -r /etc/os-release ]; then
  . /etc/os-release 2>/dev/null
  case "$ID" in
    ubuntu)
      code="${VERSION_CODENAME:-$UBUNTU_CODENAME}"
      [ -n "$code" ] && oval_url="https://security-metadata.canonical.com/oval/com.ubuntu.${code}.usn.oval.xml.bz2" ;;
    debian)
      [ -n "$VERSION_CODENAME" ] && oval_url="https://www.debian.org/security/oval/oval-definitions-${VERSION_CODENAME}.xml.bz2" ;;
    rhel|centos|rocky|almalinux|ol|fedora)
      major="${VERSION_ID%%.*}"
      [ -n "$major" ] && oval_url="https://www.redhat.com/security/data/oval/v2/RHEL${major}/rhel-${major}.oval.xml.bz2" ;;
    *)
      case " $ID_LIKE " in
        *rhel*|*fedora*) major="${VERSION_ID%%.*}"; [ -n "$major" ] && oval_url="https://www.redhat.com/security/data/oval/v2/RHEL${major}/rhel-${major}.oval.xml.bz2" ;;
        *debian*) [ -n "$VERSION_CODENAME" ] && oval_url="https://www.debian.org/security/oval/oval-definitions-${VERSION_CODENAME}.xml.bz2" ;;
      esac ;;
  esac
fi

# Obtain the OVAL definitions file (param path, or download the feed).
if [ -z "$oval_file" ]; then
  [ -n "$oval_url" ] || emit_error "vuln_scan/oval-missing" \
    "No OVAL feed for this node (ID='${ID:-unknown}', VERSION_ID='${VERSION_ID:-?}'). Pass oval_url for this distro, or oval_file."
  if printf '%s' "$oval_url" | grep -q '\.bz2$'; then
    curl -sfL "$oval_url" -o "$tmp/oval.xml.bz2" || emit_error "vuln_scan/download-failed" "Could not download OVAL feed."
    bunzip2 "$tmp/oval.xml.bz2" || emit_error "vuln_scan/decompress-failed" "Could not decompress OVAL feed."
    oval_file="$tmp/oval.xml"
  else
    curl -sfL "$oval_url" -o "$tmp/oval.xml" || emit_error "vuln_scan/download-failed" "Could not download OVAL feed."
    oval_file="$tmp/oval.xml"
  fi
fi

results="$tmp/results.xml"
# oscap returns non-zero when definitions evaluate true; rely on the results file.
"$oscap_bin" oval eval --results "$results" "$oval_file" >/dev/null 2>"$tmp/err" || true
if [ ! -f "$results" ]; then
  msg="$(tr -d '\n' <"$tmp/err" | sed 's/"/\\"/g')"
  emit_error "vuln_scan/oscap-failed" "oscap eval produced no results: ${msg}"
fi

"$ruby_bin" "$parser" "$results" "$oval_file"
