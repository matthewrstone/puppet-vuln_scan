#!/usr/bin/env bash
# vuln_scan::trivy (Linux) -- run Trivy, then trim its JSON to a compact report
# using the Puppet agent's bundled Ruby (no dependency on a system ruby/PATH).
set -o pipefail

scan_type="${PT_scan_type:-rootfs}"
target="${PT_target:-/}"
severities="${PT_severities:-}"
trivy_bin="${PT_trivy_path:-}"
timeout="${PT_timeout:-10m}"

emit_error() { printf '{"_error":{"kind":"%s","msg":"%s","details":{}}}\n' "$1" "$2"; exit 1; }

# Locate trivy (param -> PATH -> common locations).
if [ -z "$trivy_bin" ] || [ ! -x "$trivy_bin" ]; then
  if command -v trivy >/dev/null 2>&1; then
    trivy_bin="$(command -v trivy)"
  else
    for c in /usr/local/bin/trivy /usr/bin/trivy /opt/trivy/trivy; do
      [ -x "$c" ] && trivy_bin="$c" && break
    done
  fi
fi
[ -n "$trivy_bin" ] || emit_error "vuln_scan/trivy-missing" \
  "Trivy not found. Install via the vuln_scan class or pass trivy_path."

# Locate the Puppet agent ruby (guaranteed on managed nodes), else PATH ruby.
ruby_bin="/opt/puppetlabs/puppet/bin/ruby"
[ -x "$ruby_bin" ] || ruby_bin="$(command -v ruby 2>/dev/null)"
[ -n "$ruby_bin" ] || emit_error "vuln_scan/ruby-missing" "No Ruby available to process results."

trim="${PT__installdir}/vuln_scan/files/trim.rb"
[ -f "$trim" ] || emit_error "vuln_scan/trim-missing" "Helper trim.rb not found at ${trim}."

tmp_json="$(mktemp)"; tmp_err="$(mktemp)"
trap 'rm -f "$tmp_json" "$tmp_err"' EXIT

args=("$scan_type" --format json --quiet --scanners vuln --timeout "$timeout")
[ -n "$severities" ] && args+=(--severity "$severities")
args+=("$target")

if ! "$trivy_bin" "${args[@]}" >"$tmp_json" 2>"$tmp_err"; then
  if [ ! -s "$tmp_json" ]; then
    msg="$(tr -d '\n' <"$tmp_err" | sed 's/"/\\"/g')"
    emit_error "vuln_scan/trivy-failed" "Trivy failed: ${msg}"
  fi
fi

# Trim on the node so only a compact report crosses the task engine.
"$ruby_bin" "$trim" "$tmp_json"
