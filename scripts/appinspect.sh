#!/usr/bin/env bash
# Build the package and run Splunk AppInspect the way Splunkbase and Splunk
# Cloud vetting do: precert mode, cloud tag. Prints only what is not a pass and
# exits non-zero on any failure, error or warning.
#
#   pip install splunk-appinspect     # in a Python 3.9 to 3.12 virtualenv
#   scripts/appinspect.sh
#
# splunk-appinspect needs libmagic (macOS: brew install libmagic; on Apple
# silicon set DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
package="$("$root/scripts/build.sh")"
report="$(mktemp -t appinspect.XXXXXX.json)"

splunk-appinspect inspect "$package" \
  --mode precert --included-tags cloud \
  --output-file "$report" --data-format json >/dev/null || true

python3 - "$report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
summary = report["summary"]
print({k: v for k, v in summary.items() if v})
bad = 0
for group in report["reports"][0]["groups"]:
    for check in group["checks"]:
        if check["result"] in ("success", "not_applicable", "skipped"):
            continue
        bad += 1
        print(f'{check["result"]}: {check["name"]}')
        for message in check["messages"]:
            print("  ", message["message"], message.get("message_filename") or "")
sys.exit(1 if bad else 0)
PY
