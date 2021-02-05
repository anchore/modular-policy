# Anchore Policy Bundle Whitelist Override

This utility provides a convenient way to override a whitelist in an Anchore Engine policy bundle.

Running this within an **anchore/engine-cli container** requires adding **packages jq & diffutils**. A sample image with these modifications is available at [thinkmassive/anchore-cli-jqdiff](https://hub.docker.com/repository/docker/thinkmassive/anchore-cli-jqdiff) ([Dockerfile](https://github.com/thinkmassive/anchore-cli/blob/master/Dockerfile))

## Quickstart
``` bash
./scan_with_custom_whitelist.sh <custom_whitelist>.json <image_id>
```

----

## Output files:
  - `bundle.json` is the generated policy bundle
  - `bundle_id` contains the generated bundle id

## Usage

The new whitelist must be stored as a JSON object with the `id` field matching that of the whitelist to be overridden. Here is an example taken from [trivial_bundle.json](https://github.com/anchore/anchore-engine/blob/master/tests/data/test_data_env/bundles/trivial_bundle.json) used in anchore-engine tests.

``` json
{
  "comment": "Default Global Whitelist",
  "items": [
    {
      "id": "SOMEITEM",
      "gate": "DOCKERFILECHECK",
      "trigger_id": "NOFROM"
    }
  ],
  "version": "1_0",
  "name": "Global Whitelist",
  "id": "912937b6-05fb-472f-bfbe-834c3562f32d"
}
```

Here is an example of usage in a build pipeline, with the above whitelist stored in `custom_whitelist.json`:

``` bash
CUSTOM_WHITELIST_FILE=custom_whitelist.json
IMAGE_ID='docker.io/myrepo@sha256:<digest>'

# identify default bundle id
BUNDLE_ID=$(anchore-cli policy list | grep '.*\s*True\s*.*' | awk '{print $1}')

# download default bundle
anchore-cli policy get --detail $BUNDLE_ID > $BUNDLE_ID.json

# extract bundle components
./extract.sh $BUNDLE_ID.json

# identify custom whitelist id
WHITELIST_ID=$(jq -r .id $CUSTOM_WHITELIST_FILE)

# display differences between original and override
diff -u $BUNDLE_ID/whitelists/$WHITELIST_ID.json $CUSTOM_WHITELIST_FILE

# copy custom whitelist into bundle dir
cp $CUSTOM_WHTIELIST_FILE $BUNDLE_ID/whitelists/$WHITELIST_ID.json

# generate custom bundle
CUSTOM_BUNDLE_ID=$BUNDLE_ID-$(date +%s)
./generate.sh $BUNDLE_ID $CUSTOM_BUNDLE_ID

# add custom bundle to Anchore
anchore-cli policy add bundle.json

# evaluate image using generated bundle
anchore-cli evaluate check --detail --policy $CUSTOM_BUNDLE_ID $IMAGE_ID

# delete custom bundle
anchore-cli policy delete $CUSTOM_BUNDLE_ID
```
