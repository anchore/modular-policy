#!/bin/bash

# Bundle top-level schema:
#{
#  "blacklisted_images": [],
#  "description": "Anchore DoD Iron Bank Security Docker image content checks v5.2.4 (c) Copyright Anchore Inc 2020. All Rights Reserved.",
#  "id": "63a52530-d974-42af-9527-65515cb2a86e",
#  "mappings": [],
#  "name": "anchore_dod_iron_bank_security_policies_v5.2.4",
#  "policies": [],
#  "version": "1_0",
#  "whitelisted_images": [],
#  "whitelists": []
#}

[ "x${1}x" == "xx" ] && echo "Usage: $0 <bundle_name>  (leave off .json extension)" && exit 0

jq --version >/dev/null
[ "$?" != "0" ] && echo "jq not found, exiting" && exit 1

input_bundle=base_bundles/$1.json
[ ! -f "$input_bundle" ] && echo "input bundle '$input_bundle' not found" && exit 1
output_template=templates/$1.json

echo "Extracting policies"
for policy_id in $(jq '.policies[].id' $input_bundle); do
  jq -r ".policies[] | select(.id==$policy_id)" $input_bundle > policies/$(echo $policy_id | tr -d '"').json && echo "  extracted $policy_id" || echo "  error extracting $policy_id"
done

echo "Extracting whitelists"
for allowlist_id in $(jq '.whitelists[].id' $input_bundle); do
  jq -r ".whitelists[] | select(.id==$allowlist_id)" $input_bundle > whitelists/$(echo $allowlist_id | tr -d '"').json && echo "  extracted $allowlist_id" || echo "  error extracting $allowlist_id"
done

echo "Extracting whitelisted_images"
for allowimg_id in $(jq '.whitelisted_images[].id' $input_bundle); do
  jq -r ".whitelisted_images[] | select(.id==$allowimg_id)" $input_bundle > whitelisted_images/$(echo $allowimg_id | tr -d '"').json && echo "  extracted $allowimg_id" || echo "  error extracting $allowimg_id"
done

echo "Extracting blacklisted_images"
for denyimg_id in $(jq '.blacklisted_images[].id' $input_bundle); do
  jq -r ".blacklisted_images[] | select(.id==$denyimg_id)" $input_bundle > blacklisted_images/$(echo $denyimg_id | tr -d '"').json && echo "  extracted $denyimg_id" || echo "  error extracting $denyimg_id"
done

echo "Extracting mappings"
for mapping_id in $(jq '.mappings[].id' $input_bundle); do
  jq -r ".mappings[] | select(.id==$mapping_id)" $input_bundle > mappings/$(echo $mapping_id | tr -d '"').json && echo "  extracted $mapping_id" || echo "  error extracting $mapping_id"
done

echo "Extracting bundle template"
jq 'del(.whitelists?[].items, .whitelists?[].name, .whitelists?[].comment, .whitelists?[].version, .policies?[].rules, .policies?[].name, .policies?[].version, .policies?[].comment)' $input_bundle > $output_template && echo "  saved to $output_template"
