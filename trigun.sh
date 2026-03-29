#!/bin/bash

source "$(pwd)/venv/bin/activate"

echo "TRIGUN"
echo "=============================================================================="
echo "File-Type 	:$(file $1 | awk -F ':' '{print $2}') "
echo "MD5 Hash	: $(md5sum $1 | awk '{print $1}') "
echo "SHA-256 Hash 	: $(sha256sum $1 | awk '{print $1}') "
echo "IMPHash		: $(python ./scripts/imphash.py $1) "
echo ""
echo "=========================== Fuzzy Hashing ===================================="
echo "$(ssdeep $1)"
echo ""
echo "========================== Section Hashing ==================================="
echo "$(python ./scripts/section_hashing.py $1)"
echo ""
echo "========================== Entropy Analysis =================================="
echo "$(python ./scripts/shannon_entropy.py $1)"
echo ""
echo "Section-wise entropy:"
echo ""
echo "$(python ./scripts/section_entropy.py --file $1)"
echo ""
echo "============================== Strings ======================================="
echo "Potential URLS"
echo "$(python ./scripts/strings_analyzer.py $1 url)"
echo ""
echo "Potential IPv4 addresses"
echo "$(python ./scripts/strings_analyzer.py $1 ipv4)"
echo ""
echo "Potential IPv6 addresses"
echo "$(python ./scripts/strings_analyzer.py $1 ipv6)"
echo ""
echo "Potential MAC addresses"
echo "$(python ./scripts/strings_analyzer.py $1 mac)"
echo ""
echo "Potential Mail addresses"
echo "$(python ./scripts/strings_analyzer.py $1 email)"
echo ""
echo "==================== Detecting Packers and Cryptors =========================="
echo "$(python ./scripts/packer_detection.py $1 ./rulesets/)"
echo ""
echo "======================= Known Malware Signatures ============================="
echo "$(python ./scripts/windows_signature.py $1 ./rulesets/)"
echo ""
echo "================================= Imports ===================================="
echo "$(python ./scripts/getimports.py $1)"
echo ""
echo "================================= Exports ===================================="
echo "$(python ./scripts/getexports.py $1)"
echo ""
echo "======================= Hybrid Analysis Submission ==========================="

if [ -z "$HA_API_KEY" ]; then
    echo "[WARNING] HA_API_KEY environment variable is not set. Skipping Hybrid Analysis submission."
    echo "  Set it with: export HA_API_KEY=\"your_api_key\""
else
    # Environment ID 100 = Windows 7 64-bit
    HA_ENV_ID="100"

    echo "Submitting file to Hybrid Analysis..."

    response=$(curl -L -s -X POST \
      -H "api-key: $HA_API_KEY" \
      -H "Accept: application/json" \
      -H "User-Agent: Falcon Sandbox" \
      -F "file=@$1" \
      -F "environment_id=$HA_ENV_ID" \
      https://hybrid-analysis.com/api/v2/submit/file)

    # Extract job_id and sha256 from the response
    if command -v jq &> /dev/null; then
        ha_job_id=$(echo "$response" | jq -r '.job_id // .id // empty')
        ha_sha256=$(echo "$response" | jq -r '.sha256 // empty')
        echo "$response" | jq '.'
    else
        ha_job_id=$(echo "$response" | grep -o '\"\(\(job_\)\?id\)\"\s*:\s*\"[^"]*\"' | head -1 | sed 's/.*: *"//;s/"//')
        ha_sha256=$(echo "$response" | grep -o '"sha256"\s*:\s*"[^"]*"' | head -1 | sed 's/.*: *"//;s/"//')
        echo "$response"
    fi

    # Persist job_id and sha256 to a metadata file
    if [ -n "$ha_job_id" ] && [ -n "$ha_sha256" ]; then
        mkdir -p ./ha_results
        meta_file="./ha_results/${ha_sha256}.meta"
        echo "job_id=${ha_job_id}" > "$meta_file"
        echo "sha256=${ha_sha256}" >> "$meta_file"
        echo "submitted_at=$(date -Iseconds)" >> "$meta_file"
        echo "file=$(basename $1)" >> "$meta_file"
        echo ""
        echo "Metadata saved to: $meta_file"
        echo "  job_id : $ha_job_id"
        echo "  sha256 : $ha_sha256"
    else
        echo ""
        echo "[ERROR] Could not extract job_id/sha256 from response. Metadata not saved."
    fi

    echo ""
    echo "Note: Full dynamic analysis takes time."
    echo "Use './ha_fetch_results.sh $ha_sha256' to fetch results later."
fi
echo ""
