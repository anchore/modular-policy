# Modular Policy Bundle Generator

This utility provides a convenient way to manage an Anchore policy bundle as individual components. 

Running this within an anchore/engine-cli container requires adding packages `jq` & `diffutils`. A sample Dockerfile with these modifications is available in `tools/modular-bundle/Dockerfile`

## Modular Policy Demo

1. Clone this repo and cd into it
2. Download the [Anchore CIS bundle](https://github.com/anchore/hub/blob/master/sources/bundles/anchore_cis_1.13.0_base.json)
3. Extract the bundle into components: `./extract.sh anchore_cis_1.13.0_base.json`
4. Add the components to git: `git add bundle/ && git commit -m 'initial bundle'`
5. Modify the example to check for your own base image: `sed -i 's/example_trusted_base1,example_trusted_base2/debian:stable-slim,debian:stretch-slim/'`
6. Generate a new bundle: `./generate.sh bundle`
7. Push bundle to Anchore and set as active: `anchore-cli policy add bundle.json && anchore-cli policy activate $(cat bundle_id)`
8. Scan images using your new policy bundle!

Repeat steps 5-8 with your own modifications on an ongoing basis. Steps 6 & 7 can be automated with a CI tool to always keep your active policy up to date with a branch of this repo.

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
