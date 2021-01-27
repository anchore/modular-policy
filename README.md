# Modular Policy Bundler

This utility provides a convenient way to maintain Anchore Engine bundle components stored in a git repo, which can be combined into a policy bundle for use with anchore-cli in CI pipelines.

The idea is to maintain a base policy bundle (for example ironbank.json) and allow an authorizing official (AO) to update image-specific whitelists stored in version control instead of manually editing through the Anchore Enterprise UI.

## Usage

Note that the bundle name (`ironbank` in the below examples) is used to determine the following:
  - base_bundle filename
  - input template filename
  - bundle_id

### Extract base bundle

When a new base bundle is added, or an existing one is updated, extract it into components:
``` bash
cp ~/Downloads/ironbank.sh base_bundles/
./extract.sh ironbank
```

### Evaluate image using generated bundle

To run a compliance check, first a bundle is generated and added to Anchore, then the container is evaluated using anchore-cli:
``` bash
img_registry=docker.io
img_repo=nginx
img_digest=<set during build>

./generate.sh ironbank
bundle_id=$(cat bundle_id)

anchore-cli policy add bundle.json
anchore-cli evaluate check $img_registry/$img_repo@sha256:$img_digest --detail --policy $bundle_id

# optionally delete the bundle when complete:
anchore-cli policy del $bundle_id
```

#### Output files:
  - `bundle.json` is a policy bundle suitable for use with Anchore
  - `bundle_id` contains the bundle id (format: `<bundle_name>-<unix_timestamp>`)

---

## TODO

### Allowed & blocked images
Currently `whitelisted_images` & `blacklisted_images` are unmanaged. This should be easy enough to implement using the same patterns as the policies & whitelists.

### Updating whitelists

When the Anchore gates file is updated in Iron Bank it should be downloaded then converted to a whitelist:
``` bash
./convert_gate_to_whitelist.sh gates/anchore_gates.csv
```

