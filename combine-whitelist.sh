#!/bin/bash

new_whitelist_items=$1
whitelist_file=$2

#whitelist_file=~/anchore/anchore-policy/components/whitelists/AnchoreEngineWhitelist.json

jq -s '{ id: .[1].id, comment: .[1].comment, gate: .[1].gate, items: [ .[1].items + .[0] ] }' $new_whitelist_items $whitelist_file 
