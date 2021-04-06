#!/bin/bash

jq --version >/dev/null
[ "$?" != "0" ] && echo "jq not found, exiting" && exit 1

cwd=$(pwd)
template="template.json"

[ "x${1}x" == "xx" ] && echo "Usage: $0 <bundle_dir> [<bundle_id>]" && exit 0
bundle_dir=$1
[ -d $bundle_dir ] && cd $bundle_dir || exit 1
[ ! -f $template ] && echo "$template not found" && exit 1

[ "x${2}x" != "xx" ] && bundle_id=$2 || bundle_id=$(jq -r '.id' $template)
echo "Generating bundle: $bundle_id"

echo -e "\nReading mappings"
mapping_ids=$(jq -r '.mappings[].id' $template)
if [ "x${mapping_ids}x" != "xx" ]; then
  mapping_files=$(for i in $mapping_ids; do echo mappings/$i.json; done)
  echo "$mapping_files"
  mapping_json=$(jq -s '.' $mapping_files)
else
  mapping_json='[]'
fi

echo -e "\nReading policies"
policy_ids=$(jq -r '.policies[].id' $template)
if [ "x${policy_ids}x" != "xx" ]; then
  policy_files=$(for i in $policy_ids; do echo policies/$i.json; done)
  echo "$policy_files"
  policy_json=$(jq -s '.' $policy_files)
else
  echo '(none)'
  policy_json='[]'
fi

echo -e "\nReading whitelists"
allowlist_ids=$(jq -r '.whitelists[].id' $template)
if [ "x${allowlist_ids}x" != "xx" ]; then
  allowlist_files=$(for i in $allowlist_ids; do echo whitelists/$i.json; done)
  echo "$allowlist_files"
  allowlist_json=$(jq -s '.' $allowlist_files)
else
  echo '(none)'
  allowlist_json='[]'
fi

echo -e "\nReading whitelisted_images"
allowimg_ids=$(jq -r '.whitelisted_images[].id' $template)
if [ "x${allowimg_ids}x" != "xx" ]; then
  allowimg_files=$(for i in $allowimg_ids; do echo whitelisted_images/$i.json; done)
  echo "$allowlist_files"
  allowimg_json=$(jq -s '.' $allowlist_files)
else
  echo '(none)'
  allowimg_json='[]'
fi

echo -e "\nReading blacklisted_images"
denyimg_ids=$(jq -r '.blacklisted_images[].id' $template)
if [ "x${denyimg_ids}x" != "xx" ]; then
  denyimg_files=$(for i in $denyimg_ids; do echo blacklisted_images/$i.json; done)
  echo "$denylist_files"
  denyimg_json=$(jq -s '.' $denylist_files)
else
  echo '(none)'
  denyimg_json='[]'
fi

echo -e "\nMerging policy bundle"
jq --arg b "$bundle_id"          \
  --argjson m "$mapping_json"    \
  --argjson p "$policy_json"     \
  --argjson al "$allowlist_json" \
  --argjson ai "$allowimg_json"  \
  --argjson di "$denyimg_json"   \
  '.id |= $b | .mappings |= $m | .policies |= $p | .whitelists |= $al | .whitelisted_images |= $ai | .blacklisted_images |= $di'    \
  $template > $cwd/bundle.json && echo "wrote bundle.json"

echo $bundle_id > $cwd/bundle_id && echo "wrote bundle_id"
