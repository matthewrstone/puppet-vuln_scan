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

# Obtain the OVAL definitions file (param path, or download + decompress the feed).
if [ -z "$oval_file" ]; then
  [ -n "$oval_url" ] || emit_error "vuln_scan/oval-missing" \
    "No OVAL feed for this node (ID='${ID:-unknown}', VERSION_ID='${VERSION_ID:-?}'). Pass oval_url for this distro, or oval_file."

  dl="$tmp/oval.dl"
  curl -sfL "$oval_url" -o "$dl" || emit_error "vuln_scan/download-failed" \
    "Could not download OVAL feed from ${oval_url}."
  [ -s "$dl" ] || emit_error "vuln_scan/download-failed" \
    "Downloaded OVAL feed is empty (check the URL / proxy / outbound access)."

  # Detect the real compression by magic bytes, not the file extension.
  magic="$(head -c 6 "$dl" | od -An -tx1 | tr -d ' \n')"
  oval_file="$tmp/oval.xml"
  case "$magic" in
    425a68*)  # "BZh" -> bzip2
      command -v bunzip2 >/dev/null 2>&1 || emit_error "vuln_scan/decompress-failed" \
        "OVAL feed is bzip2 but 'bzip2' is not installed on this node (install the bzip2 package)."
      bunzip2 -c "$dl" > "$oval_file" 2>/dev/null || emit_error "vuln_scan/decompress-failed" "bunzip2 failed on the OVAL feed." ;;
    1f8b*)    # gzip
      command -v gunzip >/dev/null 2>&1 || emit_error "vuln_scan/decompress-failed" \
        "OVAL feed is gzip but 'gzip' is not installed on this node."
      gunzip -c "$dl" > "$oval_file" 2>/dev/null || emit_error "vuln_scan/decompress-failed" "gunzip failed on the OVAL feed." ;;
    fd377a585a*)  # xz
      if command -v unxz >/dev/null 2>&1; then unxz -c "$dl" > "$oval_file" 2>/dev/null
      elif command -v xz >/dev/null 2>&1; then xz -dc "$dl" > "$oval_file" 2>/dev/null
      else emit_error "vuln_scan/decompress-failed" "OVAL feed is xz but 'xz' is not installed on this node."; fi
      [ -s "$oval_file" ] || emit_error "vuln_scan/decompress-failed" "xz decompress failed on the OVAL feed." ;;
    3c3f786d*|3c4f5641*|efbbbf*|2020*|0a*|3c*)  # "<?xm", "<OVA", BOM, or leading whitespace/"<" -> plain XML
      cp "$dl" "$oval_file" ;;
    *)
      # Unknown magic: if it looks like text/XML, use as-is; else fail clearly.
      if head -c 512 "$dl" | grep -qi "<oval\|<?xml"; then cp "$dl" "$oval_file";
      else emit_error "vuln_scan/decompress-failed" "Unrecognized OVAL feed format (magic=${magic}); expected bzip2/gzip/xz/xml."; fi ;;
  esac
fi

results="$tmp/results.xml"
# oscap returns non-zero when definitions evaluate true; rely on the results file.
"$oscap_bin" oval eval --results "$results" "$oval_file" >/dev/null 2>"$tmp/err" || true
if [ ! -f "$results" ]; then
  msg="$(tr -d '\n' <"$tmp/err" | sed 's/"/\\"/g')"
  emit_error "vuln_scan/oscap-failed" "oscap eval produced no results: ${msg}"
fi

"$ruby_bin" "$parser" "$results" "$oval_file"
