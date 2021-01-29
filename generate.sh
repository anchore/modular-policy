#!/bin/bash

[ "x${1}x" == "xx" ] && echo "Usage: $0 <bundle_dir>" && exit 0
bundle_dir=$1
[ -d $1 ] && cd $1 || exit 1

jq --version >/dev/null
[ "$?" != "0" ] && echo "jq not found, exiting" && exit 1

template="template.json"
[ ! -f $template ] && echo "$template not found" && exit 1

bundle="$1-$(date +%s)"
echo "Generating bundle: $bundle"

echo -e "\nReading policies"
policy_ids=$(jq -r '.policies[].id' $template)
policy_files=$(for p in $policy_ids; do echo policies/$p.json; done)
echo "$policy_files"
policy_json=$(jq -s '.' $policy_files)

echo -e "\nReading whitelists"
whitelist_ids=$(jq -r '.whitelists[].id' $template)
whitelist_files=$(for w in $whitelist_ids; do echo whitelists/$w.json; done)
echo "$whitelist_files"
whitelist_json=$(jq -s '.' $whitelist_files)

echo -e "\nMerging policy bundle"
jq --arg b "$bundle" --argjson p "$policy_json" --argjson w "$whitelist_json" \
  '.id |= $b | .policies |= $p | .whitelists |= $w' \
  $template > bundle.json && echo "wrote bundle.json"

echo $bundle > bundle_id && echo "wrote bundle_id"
