## Modular Policy Bundle Generator

This utility provides a convenient way to manage an Anchore policy bundle as individual components. 

Running this within an anchore/engine-cli container requires adding packages `jq` & `diffutils`. A sample Dockerfile with these modifications is available in `tools/modular-bundle/Dockerfile`

### Modular Policy Quickstart

``` bash
# Clone this repo and enter the dir
cd anchore-policy

# Copy the Jenkinsfile into top-level dir
cp tools/modular-bundle/Jenkinsfile.sample Jenkinsfile

# Customize Jenkinsfile to your environment (docker params, etc)
# Push to your own repo (accessible by your CI server)
# Create new CI job
# Ensure CI server has permissions to update policy in Anchore
# Now your active policy bundle is managed through the git repo
```
---

### Extract an existing bundle into components

```bash
myBundle=platform-one/anchore_dod_iron_bank_security_policies_v5.2.5.json
componentDir=mybundle_components

tools/modular-bundle/extract.sh $mybundle $componentDir

ls -l $componentDir
```

---

### Generate a new bundle from components

```bash
componentDir=mybundle_components

tools/modular-bundle/generate.sh $componentDir

less bundle.json
```

#### generate.sh output files
  - `bundle.json` is the generated policy bundle
  - `bundle_id` contains the generated bundle id

---

### Generate potential whitelist entries for all "stop" actions in a compliance report

```bash
report=Compliance_Report_2021-01-07T21_46_39.535Z.csv
output_dir=new_whitelist

tools/modular-bundle/allow-stopped.sh  $report  $output_dir

ls -l $output_dir

# Copy desired item(s) from the per-policy files
# Paste into the appropriate file in components/whitelists/
# Commit changes, run CI job to update policy
```
