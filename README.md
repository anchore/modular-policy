# Modular Policy Bundler

This utility provides a convenient way to maintain Anchore Engine policy bundles stored in a git repo.

## Usage

The following examples assume a directory structure with 2 git repos inside a project dir:
``` bash
project_dir/
    modular-policy/
        bundle.json (generated)
        bundle_id   (generated)
        extract.sh
        generate.sh
        README.md   (this file)
    custom-bundle/
        template.json
        mappings/
            custom_mapping.json
        policies/
            custom_policy.json
        whitelists/
            custom_whitelist.json
```

### Extract base bundle

Download an existing policy bundle from anchore-engine, then extract its components into a dir 'custom-bundle/':
``` bash
cp  ~/Downloads/anchore_policy_bundle.json  ./
./extract.sh  anchore_policy_bundle.json  custom_bundle
```

### Generate bundle from components

From this repo, run the generate script pointed at the custom bundle dir:
``` bash
./generate.sh ../custom-bundle
```

#### Output files:
  - `bundle.json` is a policy bundle suitable for use with Anchore
  - `bundle_id` contains the bundle id (format: `<bundle_name>-<unix_timestamp>`)

### Evaluate image using generated bundle

To run a compliance check, first add the generated bundle then evaluate the image against it:
``` bash
anchore-cli policy add bundle.json
anchore-cli evaluate check $reg/$repo@sha256:$digest --detail --policy $(cat bundle_id)
```

---

## TODO

### Allowed & blocked images
Currently `whitelisted_images` & `blacklisted_images` are unmanaged. This should be easy enough to implement using the same patterns as the policies & whitelists.

### Updating whitelists

When the Anchore gates file is updated in Iron Bank it should be downloaded then converted to a whitelist:
``` bash
./convert_gate_to_whitelist.sh gates/anchore_gates.csv
```

