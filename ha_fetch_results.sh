#!/bin/bash

# ha_fetch_results.sh — Fetch Hybrid Analysis dynamic analysis results
# Usage: ./ha_fetch_results.sh <sha256_hash_or_meta_file>
#
# Requires: HA_API_KEY environment variable set
#           curl installed
#           jq recommended for pretty output

set -euo pipefail

# ─── Resolve SHA-256 from argument ────────────────────────────────────────────

if [ $# -lt 1 ]; then
    echo "Usage: $0 <sha256_hash_or_meta_file>"
    echo ""
    echo "  sha256_hash_or_meta_file:"
    echo "    - A 64-character SHA-256 hash directly, OR"
    echo "    - Path to a .meta file created by trigun.sh (e.g. ./ha_results/<sha256>.meta)"
    exit 1
fi

input="$1"

# If the argument is a file, read sha256 from it
if [ -f "$input" ]; then
    sha256=$(grep '^sha256=' "$input" | cut -d'=' -f2)
    if [ -z "$sha256" ]; then
        echo "[ERROR] Could not find sha256= line in file: $input"
        exit 1
    fi
    echo "Read SHA-256 from meta file: $input"
else
    sha256="$input"
fi

echo "SHA-256: $sha256"
echo ""

# ─── Validate API key ────────────────────────────────────────────────────────

if [ -z "${HA_API_KEY:-}" ]; then
    echo "[ERROR] HA_API_KEY environment variable is not set."
    echo "  Set it with: export HA_API_KEY=\"your_api_key\""
    exit 1
fi

# ─── Fetch report summary ────────────────────────────────────────────────────

echo "======================= Hybrid Analysis Report ==============================="
echo "Fetching report for SHA-256: $sha256 ..."
echo ""

response=$(curl -L -s -X GET \
  -H "api-key: $HA_API_KEY" \
  -H "Accept: application/json" \
  -H "User-Agent: Falcon Sandbox" \
  "https://hybrid-analysis.com/api/v2/report/${sha256}/summary")

if command -v jq &> /dev/null; then
    # Check if the response indicates an error
    msg=$(echo "$response" | jq -r '.message // empty')
    if [ -n "$msg" ]; then
        echo "[API] $msg"
        echo ""
        echo "Raw response:"
        echo "$response" | jq '.'
        exit 1
    fi

    norm_res=$(echo "$response" | jq 'if type=="array" then (if length > 0 then .[0] else {} end) else . end')

    echo "── Overview ──────────────────────────────────────────────────────────────"
    echo "  Verdict       : $(echo "$norm_res" | jq -r '.verdict // "N/A"')"
    echo "  Threat Score  : $(echo "$norm_res" | jq -r '.threat_score // "N/A"')"
    echo "  Threat Level  : $(echo "$norm_res" | jq -r '.threat_level // "N/A"')"
    echo "  AV Detect     : $(echo "$norm_res" | jq -r '.av_detect // "N/A"')%"
    echo "  VX Family     : $(echo "$norm_res" | jq -r '.vx_family // "N/A"')"
    echo "  Submit Name   : $(echo "$norm_res" | jq -r '.submit_name // "N/A"')"
    echo "  Analysis Time : $(echo "$norm_res" | jq -r '.analysis_start_time // "N/A"')"
    echo "  Environment   : $(echo "$norm_res" | jq -r '.environment_description // "N/A"')"
    echo ""

    echo "── Classification Tags ───────────────────────────────────────────────────"
    echo "$norm_res" | jq -r '.classification_tags // [] | if length == 0 then "  None" else .[] | "  - " + . end'
    echo ""

    echo "── MITRE ATT&CK Techniques ─────────────────────────────────────────────"
    echo "$norm_res" | jq -r '.mitre_attcks // [] | if length == 0 then "  None detected" else .[] | "  - " + (.tactic // "N/A") + " / " + (.technique // "N/A") + " (" + (.attck_id // "N/A") + ")" end'
    echo ""

    echo "── Extracted Files ───────────────────────────────────────────────────────"
    echo "$norm_res" | jq -r '.extracted_files // [] | if length == 0 then "  None" else .[] | "  - " + (.name // "unnamed") + " (threat_level: " + (.threat_level_readable // "N/A") + ", av_matched: " + ((.av_matched // 0) | tostring) + "/" + ((.av_total // 0) | tostring) + ")" end'
    echo ""

    echo "── Processes ─────────────────────────────────────────────────────────────"
    echo "$norm_res" | jq -r '.processes // [] | if length == 0 then "  None" else .[] | "  [PID " + ((.uid // "?") | tostring) + "] " + (.name // "unnamed") end'
    echo ""

    echo "── Full JSON Response ────────────────────────────────────────────────────"
    echo "$response" | jq '.'
else
    echo "$response"
fi

echo ""
echo "==============================================================================="
echo "Full report available at: https://hybrid-analysis.com/sample/${sha256}"
