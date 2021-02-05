#!/bin/bash

[ "x${1}x" == "xx" ] && echo "Usage: $0 <custom_whitelist_file> <image_id>" && exit 0
[ "x${2}x" == "xx" ] && echo "Usage: $0 <custom_whitelist_file> <image_id>" && exit 0

# Inputs
CUSTOM_WHITELIST_FILE=$1
IMAGE_ID=$2
[ ! -f $CUSTOM_WHITELIST_FILE ] && echo "Custom whitelist file $CUSTOM_WHITELIST_FILE not found" && exit 1

# identify default bundle id
BUNDLE_ID=$(anchore-cli policy list | grep '.*\s*True\s*.*' | awk '{print $1}')
if [ $? != 0 ]; then
  echo "Error identifying default bundle"
  exit 1
fi

# download default bundle
anchore-cli policy get --detail $BUNDLE_ID > $BUNDLE_ID.json

# extract bundle components
echo -n "Extracting $BUNDLE_ID... "
./extract.sh $BUNDLE_ID.json >/dev/null && echo "done" || (echo "error" && exit 1)

# identify custom whitelist id
WHITELIST_ID=$(jq -r .id $CUSTOM_WHITELIST_FILE)
if [ $? != 0 ]; then
  echo "Error identifying custom whitelist id"
  exit 1
else
  echo -e "Overriding whitelist $WHITELIST_ID\n"
fi

# display differences between original whitelist and override
diff -u <(jq -rcS .items[] bundle/whitelists/$WHITELIST_ID.json) <(jq -rcS .items[] $CUSTOM_WHITELIST_FILE)
echo ''

# copy custom whitelist into bundle dir
cp $CUSTOM_WHITELIST_FILE bundle/whitelists/$WHITELIST_ID.json

# generate custom bundle
CUSTOM_BUNDLE_ID=$BUNDLE_ID-$(date +%s)
./generate.sh bundle $CUSTOM_BUNDLE_ID

# add custom bundle to Anchore
anchore-cli policy add bundle.json

# evaluate image using generated bundle
anchore-cli evaluate check $IMAGE_ID --detail --policy $CUSTOM_BUNDLE_ID

# delete custom bundle
anchore-cli policy delete $CUSTOM_BUNDLE_ID
