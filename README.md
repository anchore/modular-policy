# Modular Policy Bundle Generator

This utility provides a convenient way to manage an Anchore policy bundle as individual components. 

## Usage

```bash
./anchore-bundle --help
```

## Modular Policy Demo

This demo requires a working Anchore deployment. Refer to the docker-compose [Quickstart](https://docs.anchore.com/current/docs/quickstart/) if you need to provision one.

### Demo Setup
All files used in this demo, including the [Anchore CIS bundle](https://github.com/anchore/hub/blob/master/sources/bundles/anchore_cis_1.13.0_base.json), are contained in the `sample_input` dir. These files are copied into `/anchore-cli/` during the following container build:
```bash
docker build -t anchore-bundle:demo .

# Modify variables as needed to work in your environment
docker run -it --rm --network=host \
  -e ANCHORE_CLI_USER=admin \
  -e ANCHORE_CLI_PASS=foobar \
  -e ANCHORE_CLI_URL=http://localhost:8228/v1 \
  anchore-bundle:demo -- bash

# Add the original CIS bundle to Anchore and activate it:
anchore-cli policy add anchore_cis_1.13.0_base.json
anchore-cli policy activate anchore_cis_1.13.0_base

# Define the image to use for this demo
export IMG=docker.io/thinkmassive/hello-world:alpine-3.13

# Add the demo image to Anchore:
anchore-cli image add $IMG

# Analyze the demo image w/CIS bundle:
#  (the process should succeed, but 'Final action: stop' is expected)
anchore-cli evaluate check $IMG --detail | tee eval-1.out

# Enable tab-completion for anchore-bundle (optional)
eval "$(_ANCHORE_BUNDLE_COMPLETE=source_bash anchore-bundle)"
```

All of the following steps should be run in the container created in Demo Setup.

### Policy Management Demo

1. Extract original bundle into components and review the output.

```bash
# Extract the CIS bundle into components:
anchore-bundle extract anchore_cis_1.13.0_base.json

# Review the extracted components:
ls -R bundle

# Review the bundle template, notice how each component item only has an id field:
python -m json.tool bundle/template.json
```

2. Modify the bundle and review changes.

```bash
# Backup the policy file before editing:
cp bundle/policies/cb417967-266b-4453-bfb6-9acf67b0bee5.json{,.bak}

# Change the bundle_id for easy comparison:
sed -i 's/"id": "anchore_cis_1.13.0_base"/"id": "demo_1"/' bundle/template.json

# Modify the example to always allow our base image:
sed -i 's/example_trusted_base1,example_trusted_base2/alpine:3.13,scratch/' \
  bundle/policies/cb417967-266b-4453-bfb6-9acf67b0bee5.json

# Review the change:
diff bundle/policies/cb417967-266b-4453-bfb6-9acf67b0bee5.json{,.bak}
```

3. Generate a new bundle with our modifications, and review the output.

```bash
# Generate a new bundle:
anchore-bundle generate

# Display the generated bundle_id
cat bundle_id ; echo

# Review the generated bundle, notice how component items are merged back into the template:
python -m json.tool bundle.json | more

# Compare the generated bundle with the original:
diff <(python -m json.tool --sort-keys bundle.json) \
  <(python -m json.tool --sort-keys anchore_cis_1.13.0_base.json)

# Push the bundle to Anchore and set as active:
anchore-cli policy add bundle.json && anchore-cli policy activate $(cat bundle_id)
```

4. Scan images using the modified policy bundle. The result should now be `Final action: warn` instead of `stop`, because the `Dockerfile directive 'FROM' check` is gone.

```bash
anchore-cli evaluate check $IMG --detail | tee eval-2.out

diff eval-1.out eval-2.out
```

Repeat steps 2-4 with your own modifications on an ongoing basis. Step 3 can be automated with a CI tool to always keep your active policy up to date with a branch of this repo.

### Auto-whitelist Demo

NOT YET IMPLEMENTED

The `anchore-bundle allow` subcommand can be run during step 2 above. The following demo assumes a bundle was extracted according to the steps above, and it uses example policy evaluation output for the ubi8-minimal image from Iron Bank, found in the `sample_inputs` dir of this repo.

---

## Runbook

### Use environment variables for configuration
```bash
```

### Extract bundle into components

```bash
anchore-bundle extract $SOURCE
```

### Generate bundle from components

```bash
anchore-bundle generate
```

  - `bundle.json` is the generated policy bundle
  - `bundle_id` contains the generated bundle id

### Allow all stop actions

Generates a new allowlist for a specified repo:tag for all "stop" actions in a compliance report.

```bash
GATES=gates.csv
SECURITY=security.csv
COMPLIANCE=compliance_report.json

anchore-bundle allow -g $GATES -s $SECURITY -c $COMPLIANCE
```

### Map new allowlist 
```bash
IMG='docker.io/MyImage:*'
ALLOWLIST=MyImageAllowlist
MAPPING=MyImageMapping

anchore-bundle map -p $IMG $ALLOWLIST $MAPPING
```

---

## Continuous Integration

You may choose to fork this repo and use it to store your bundle components, in which case a CI build job can be used to keep the active bundle up to date.

The sample files and docs for this are still in progress.
