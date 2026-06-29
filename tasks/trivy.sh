#!/usr/bin/env bash
# vuln_scan::trivy (Linux) -- run Trivy and emit its JSON report on stdout.
# Params arrive as environment variables (input_method: environment).
set -o pipefail

scan_type="${PT_scan_type:-rootfs}"
target="${PT_target:-/}"
severities="${PT_severities:-}"
trivy_bin="${PT_trivy_path:-trivy}"
timeout="${PT_timeout:-10m}"

# Resolve the trivy binary (param path, PATH, or common locations).
if ! command -v "$trivy_bin" >/dev/null 2>&1; then
  for cand in /usr/local/bin/trivy /usr/bin/trivy /opt/trivy/trivy; do
    if [ -x "$cand" ]; then trivy_bin="$cand"; break; fi
  done
fi

if ! command -v "$trivy_bin" >/dev/null 2>&1 && [ ! -x "$trivy_bin" ]; then
  printf '{"_error":{"kind":"vuln_scan/trivy-missing","msg":"Trivy not found on this node. Install it (e.g. via your Puppet class) or pass trivy_path.","details":{}}}\n'
  exit 1
fi

args=("$scan_type" "--format" "json" "--quiet" "--scanners" "vuln" "--timeout" "$timeout")
if [ -n "$severities" ]; then
  args+=("--severity" "$severities")
fi
args+=("$target")

# Trivy writes the JSON report to stdout; Bolt parses it into the task result.
out="$("$trivy_bin" "${args[@]}" 2>/tmp/trivy_err.$$)"
rc=$?
if [ $rc -ne 0 ] && [ -z "$out" ]; then
  err="$(tr -d '\n' </tmp/trivy_err.$$ 2>/dev/null | sed 's/"/\\"/g')"
  rm -f /tmp/trivy_err.$$
  printf '{"_error":{"kind":"vuln_scan/trivy-failed","msg":"Trivy exited %s: %s","details":{}}}\n' "$rc" "$err"
  exit $rc
fi
rm -f /tmp/trivy_err.$$
printf '%s\n' "$out"
