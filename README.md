# Modular Policy Bundle Generator

This utility provides a convenient way to manage an Anchore policy bundle as individual components. 

**WORK IN PROGRESS** - This branch contains a 100% Python implementation of functionality previously accomplished by an assortment of bash and python scripts. **Do not attempt to use until this notice is removed.**

## Runbook

### Extract Bundle into Components
```bash
SOURCE=input_bundle.json
anchore-bundle extract $SOURCE
```

### Allow all stop actions
```bash
GATES=gates.csv
SECURITY=security.csv
COMPLIANCE=compliance_report.json

anchore-bundle allow-from-eval -g $GATES -s $SECURITY $COMPLIANCE
```

### Map new allowlist 
```bash
IMG='docker.io/MyImage:*'
ALLOWLIST=MyImageAllowlist
MAPPING=MyImageMapping

anchore-bundle map -p $IMG $ALLOWLIST $MAPPING
```

### Generate Bundle from Components
```bash
anchore-bundle generate
```

## Modular Policy Demo

1. Clone this repo and cd into it
2. Download the [Anchore CIS bundle](https://github.com/anchore/hub/blob/master/sources/bundles/anchore_cis_1.13.0_base.json) into this dir
3. Extract the bundle into components: `anchore-bundle extract anchore_cis_1.13.0_base.json`
    - Review the extracted components: `tree bundle`
4. Modify the example to check for your own base image:
    ```bash
    sed -i .bak \
      's/example_trusted_base1,example_trusted_base2/debian:stable-slim,debian:stretch-slim/' \
      bundle/policies/cb417967-266b-4453-bfb6-9acf67b0bee5.json
    ```
5. Generate a new bundle: `anchore-bundle generate`
    - Review the generated files, and compare the generated bundle with the original:
        ```bash
        cat bundle_id
        jq . bundle.json | less
        diff <(jq --sort-keys . bundle.json) <(jq --sort-keys . anchore_cis_1.13.0_base.json)
        ```
6. Push bundle to Anchore and set as active:
    ```bash
    anchore-cli policy add bundle.json && anchore-cli policy activate $(cat bundle_id)
    ```
7. Scan images using your new policy bundle!

Repeat steps 4-7 with your own modifications on an ongoing basis. Steps 5 & 6 can be automated with a CI tool to always keep your active policy up to date with a branch of this repo.

### Auto-whitelist Demo

The `allow-stopped.py` script can be run as step 4 above. The following demo assumes a bundle was extracted according to the steps above, and it uses example policy evaluation output for the ubi8-minimal image from Iron Bank, found in the `sample_inputs` dir of this repo.

```bash
# make the script executable
chmod +x allow-stopped.py

# review the input files
tree sample_input/

# generate a whitelist from the sample ubi8-minimal data
./allow-stopped.py \
  sample_input/compliance_reports/ubi8-minimal_8.3_2021-03-24T23_59_55.843Z.json \
  sample_input/gates/ubi8-minimal_8.3.csv \
  sample_input/security/ubi8-minimal_8.3.csv \
  bundle/whitelists

# review the output
jq . bundle/whitelists/demo-ubi8-minimal.json | less
```

---

## Utilities

### extract.sh

Extracts an existing bundle into components.

```bash
myBundle=anchore_cis_1.13.0_base.json
componentDir=bundle

./extract.sh $mybundle $componentDir

tree $componentDir
```
### generate.sh

Generates a new bundle from components.

```bash
componentDir=bundle

./generate.sh $componentDir

cat bundle_id
less bundle.json
```

#### generate.sh output files
  - `bundle.json` is the generated policy bundle
  - `bundle_id` contains the generated bundle id

### allow-stopped.py

Generates a new whitelist for a specified repo:tag for all "stop" actions in a compliance report.

Integrating the new whitelist into the bundle dir is still in progress.

```bash
report=Compliance_Report_2021-01-07T21_46_39.535Z.csv
output_dir=new_whitelist

python allow-stopped.py  $report  $output_dir

ls -l $output_dir
```
