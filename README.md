# Modular Policy Bundle Generator

This utility provides a convenient way to manage an Anchore policy bundle as individual components. 

**This is alpha software with no official support.**

In its current state it is meant to augment a manual policy management process. The `extract` and `generate` commands are relatively stable and can be used in a CI pipeline. The `allow` and `map` commands are not yet suitable for a fully automated solution.

For `anchore-cli` usage, refer to [CLI Usage: Policies](https://docs.anchore.com/current/docs/using/cli_usage/policies).

## Config

The following config options must be placed before the subcommand:

```bash
anchore-bundle [OPTIONS] <subcommand>
```

CLI param      | Env var                 | Description
---------------|-------------------------|-------------
`--bundle-dir` | `$ANCHORE_BUNDLE_DIR`   | Path to policy bundle component directory
`--debug`      | `$ANCHORE_BUNDLE_DEBUG` | Display verbose output for debugging

### Tab completion
```bash
eval "$(_ANCHORE_BUNDLE_COMPLETE=source_bash anchore-bundle)"
```

## Commands

In general you can find the usage of any command by passing the `--help` option:

```bash
anchore-bundle [<command>] --help
```

### Command: generate

The `generate` command creates a complete policy bundle, suitable for adding to Anchore. The output file is `bundle.json` and the bundle identifier is saved in `bundle_id`.

It parses `template.json` (in `$ANCHORE_BUNDLE_DIR`), and each component item in the template is replaced by the contents of the file matching the item `id`.

For example, the single item in the list `mappings: [ {'id': 'default_mapping'} ]` would be replaced by the contents of file `mappings/default_mapping.json`

All components are validated, and all JSON must be valid to produce the output file.

```bash
# Generate a new bundle from the contents of ./bundle/:
anchore-bundle generate

# Display the generated bundle_id
cat bundle_id ; echo
```

### Command: extract

The `extract` command generates `template.json` and component item files from a complete policy bundle JSON file. The input file can be downloaded with `anchore-cli policy get <policy> --detail`, or from Anchore Enterprise UI.

```bash
anchore-bundle extract [--no-backup] [--strategy=replace] SOURCE


# Example: remove all existing components and restore Default Bundle
BUNDLE_URL=https://raw.githubusercontent.com/anchore/anchore-engine/master/anchore_engine/conf/bundles/anchore_default_bundle.json

curl -o anchore_default_bundle.json $BUNDLE_URL

anchore-bundle extract --strategy=replace anchore_default_bundle.json
```

### Command: map

The `map` command generates a file `mappings/<MAPPING>.json` that maps `ALLOWLIST` and `POLICY` to an image pattern: `<registry>/<repo>:tag` (wildcards allowed, refer to [Policy Mappings](https://docs.anchore.com/current/docs/using/ui_usage/policies/mappings/) for details).

This mapping is added to `template.json`. By default, an existing mapping will maintain its position in the template, and **new mappings will be inserted at the top**. To override the default behavior, set the desired position in the mappings list with `--position=<number>` where 0 is highest priority.

ATTENTION: **ordering of mappings is important!**

When an image is evaluated, the first mapping with a matching image pattern will be used to determine the policies, allowlists, etc that will be applied.

Components are expected to already exist in `policies/<POLICY>.json` and `whitelists/<ALLOWLIST>.json`. By default these files are validated. To override this, if the files will be created or changed in the future (before bundle generation), use the `--no-validate` option.

```bash
anchore-bundle map [--position=0] [--registry='*'] [--repo='*'] [--tag='*'] [--no-validate] MAPPING ALLOWLIST POLICY

# Example: image-specific mapping (w/policy+allowlist) for all ubuntu:20.04 images
anchore-bundle map --repo=ubuntu --tag=20.04 \
    ubuntu_20_04_mapping  ubuntu_20_04_allowlist  ubuntu_20_04_policy

# Example: default mapping to use as a catch-all
anchore-bundle map --position=999999 \
    default_mapping  default_allowlist  default_policy
```

### Command: allow

The `allow` command generates an allowlist with exceptions for all stop gates from a Compliance Report (JSON file). In addition to the Compilance Report, it attempts to obtain justifications from `anchore_gates.csv` and `anchore_security.csv` files.

Gates CSV format:
```
image_id,repo_tag,trigger_id,gate,trigger,check_output,gate_action,policy_id,matched_rule_id,whitelist_id,whitelist_name,inherited,Justification
```

Security CSV format:
```
tag,cve,severity,feed,feed_group,package,package_path,package_type,package_version,fix,url,inherited,description,nvd_cvss_v2_vector,nvd_cvss_v3_vector,vendor_cvss_v2_vector,vendor_cvss_v3_vector,Justification
```

Usage:
```bash
anchore-bundle allow --compliance=<compliance_report>.json --gates=<gates>.csv --security=<security>.csv
```

---

## Modular Policy Demo

This demo requires a working Anchore deployment. Refer to the docker-compose [Quickstart](https://docs.anchore.com/current/docs/quickstart/) if you need to provision one.

### Demo Setup

To run this demo you will need to download anchore_gates.csv and anchore_security.csv for `ubi8-minimal:8.3` from [Iron Bank](https://ironbank.dso.mil/repomap/redhat/ubi). These files are copied into `/anchore-cli/` during the container build.

```bash
docker build -t anchore-bundle:demo .

# Modify variables as needed to work in your environment
docker run -it --rm --network=host \
  -v $(pwd):/anchore-cli/ \
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
anchore-bundle map --repo 'ubi8/ubi-minimal' ubi8-minimal 48e6f7d6-1765-11e8-b5f9-8b6f228548b6 thinkmassive-ubi8-minimal

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

## Continuous Integration

You may choose to fork this repo and use it to store your bundle components, in which case a CI build job can be used to keep the active bundle up to date.

The sample files and docs for this are still in progress.
