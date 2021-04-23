# Modular Policy Bundle Generator

This utility provides a convenient way to manage an Anchore policy bundle as individual components. 

**This is alpha software with no official support.**

In its current state it is meant to augment a manual policy management process. The `extract` and `generate` commands are relatively stable and can be used in a CI pipeline. The `allow` and `map` commands are not yet suitable for a fully automated solution.

## Usage

```bash
./anchore-bundle --help
```

## Modular Policy Demo

This demo requires a working Anchore deployment. Refer to the docker-compose [Quickstart](https://docs.anchore.com/current/docs/quickstart/) if you need to provision one.

### Demo Setup

To run this demo you will need to download anchore_gates.csv and anchore_security.csv for `ubi8-minimal:8.3` from [Iron Bank](https://ironbank.dso.mil/repomap/redhat/ubi). These files are copied into `/anchore-cli/` during the container build.

```bash
docker build -t anchore-bundle:demo .

# Modify variables as needed to work in your environment
docker run -it --rm --network=host \
  -e ANCHORE_CLI_USER=admin \
  -e ANCHORE_CLI_PASS=foobar \
  -e ANCHORE_CLI_URL=http://localhost:8228/v1 \
  --name=anchore-bundle \
  anchore-bundle:demo -- bash

# Make sure the original Default Bundle is active
anchore-cli policy activate 2c53a13c-1765-11e8-82ef-23527761d060

# Define the image to use for this demo
export IMG=registry.access.redhat.com/ubi8/ubi-minimal:8.3

# Add the image to Anchore, wait until result is available:
anchore-cli image add $IMG
anchore-cli image get $IMG
```

All of the following steps should be run in the container created in Demo Setup.

### Policy Management Demo

1. Evaluate the image w/Default Bundle. The process should succeed, but 'Final action: stop' is expected. Output is tee'd to a file for later comparison.

```bash
anchore-cli evaluate check $IMG --detail | tee eval-1.out
```

2. Extract original bundle into components and review the output.

```bash
# Extract the Default Bundle into components
anchore-bundle extract anchore_default_bundle.json

# Initialize new git repo in bundle dir
cd bundle
git init
git remote add origin http://localhost:3200/alex/demo-bundle.git

# Prepare to save in git, review extracted components
git add ./*
git status

# Commit and push
git commit -m 'initial commit'
git push -u origin HEAD

# Review the bundle template, notice how each component item only has an id field:
less template.json
```

3. Modify the bundle and review changes.

```bash
# Change the bundle name & id for easy comparison
sed -i 's/"id": "2c53a13c-1765-11e8-82ef-23527761d060"/"id": "demo_1"/' template.json
sed -i 's/"name": "Default bundle"/"name": "Custom bundle"/' template.json

# Review the change
git diff

# Commit and push
git add template.json
git commit -m 'set bundle id & name'
git push
```

4. Generate a new bundle with our modifications, and review the output.

```bash
# Return to parent dir (containing bundle/)
cd ..

# Generate a new bundle:
anchore-bundle generate

# Display the generated bundle_id
cat bundle_id ; echo

# Review the generated bundle, notice how component items are merged back into the template:
less bundle.json

# Compare the generated bundle with the original:
diff <(python -m json.tool --sort-keys bundle.json) \
  <(python -m json.tool --sort-keys anchore_default_bundle.json)

# Push the bundle to Anchore and set as active:
anchore-cli policy add bundle.json && anchore-cli policy activate $(cat bundle_id)
```

### Auto-whitelist Demo

The `anchore-bundle allow` subcommand can be run during step 3 above. The following demo assumes a bundle was extracted according to the steps above, and it uses example policy evaluation output for the ubi8-minimal image from Iron Bank.

Download `Compliance_Report.json` from web UI, and copy into container:
```bash
# From host machine (not inside container)
docker cp ~/Downloads/Compliance_Report_*.json anchore-bundle:/anchore-cli/
```

Resume the demo inside the container...

```bash
# Confirm compliance report is available
ls -l

# Generate new allowlist, based on eval output (compliance report, gates.csv, security.csv)
anchore-bundle allow \
    -c Compliance_Report_*.json \
    -g anchore_gates.csv \
    -s anchore_security.csv

# Generate mapping to include new allowlist in bundle
anchore-bundle map ubi8-minimal ubi8-ubi-minimal --repo 'ubi8/ubi-minimal'

# Stage new mapping & allowlist to git; review changes, then commit
cd bundle
git status
git add template.json mappings/ubi8-minimal.json whitelists/ubi8-ubi-minimal.json
git diff HEAD
git commit -m 'add mapping: ubi8-minimal'

# Generate bundle with new components added
cd ..
anchore-bundle generate

# Compare the generated bundle with the original:
diff <(python -m json.tool --sort-keys bundle.json) \
  <(python -m json.tool --sort-keys anchore_default_bundle.json)

# Update active bundle (this will FAIL)
anchore-cli policy add bundle.json && anchore-cli policy activate $(cat bundle_id)

# Update policy_id in new mapping (copy from default mapping); regenerate bundle
grep policy_id bundle/mappings/c*
vi bundle/mappings/ubi8-minimal.json
anchore-bundle generate

# Update active bundle (should succeed this time)
anchore-cli policy add bundle.json && anchore-cli policy activate $(cat bundle_id)

```

9. Scan images using the modified policy bundle. The result should now be `Final action: warn` instead of `stop`, because the `Dockerfile directive 'FROM' check` is gone.

```bash
anchore-cli evaluate check $IMG --detail | tee eval-2.out

diff eval-1.out eval-2.out
```

Repeat steps 2-4 with your own modifications on an ongoing basis. Step 3 can be automated with a CI tool to always keep your active policy up to date with a branch of this repo.

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

### Tab completion
```bash
eval "$(_ANCHORE_BUNDLE_COMPLETE=source_bash anchore-bundle)"
```

---

## Continuous Integration

You may choose to fork this repo and use it to store your bundle components, in which case a CI build job can be used to keep the active bundle up to date.

The sample files and docs for this are still in progress.
