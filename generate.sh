#!/bin/bash

[ "x${1}x" == "xx" ] && echo "Usage: $0 <bundle_name>" && exit 0

input_template="templates/$1.json"
[ ! -f "$input_template" ] && echo "input template '$1' not found" && exit 1

export bundle="$1-$(date +%s)"
echo "Generating bundle: $bundle"

# change to script directory
cd "$(dirname "$0")"

echo -e "\nReading policies"
policy_ids=$(jq -r '.policies[].id' $input_template)
policy_files=$(for p in $policy_ids; do echo policies/$p.json; done)
echo "$policy_files"
policy_json=$(jq -s '.' $policy_files)

echo -e "\nReading whitelists"
whitelist_ids=$(jq -r '.whitelists[].id' $input_template)
whitelist_files=$(for w in $whitelist_ids; do echo whitelists/$w.json; done)
echo "$whitelist_files"
whitelist_json=$(jq -s '.' $whitelist_files)

echo -e "\nMerging policy bundle"
jq --arg b "$bundle" --argjson p "$policy_json" --argjson w "$whitelist_json" '.id |= $b | .policies |= $p | .whitelists |= $w' $input_template > bundle.json && echo "wrote bundle.json"
echo $bundle > bundle_id && echo "wrote bundle_id"
