#!/usr/bin/env python3
#
# Reads an Anchore compliance report in JSON format. Outputs all items
# with 'gateAction: stop' as a new whitelist named according to the image
# name, and suitable for copying into bundle/whitelists/ to generate a 
# new modular policy with generate.sh

import sys
import csv
import json
import hashlib
import os

verbose = False

# Parse CLI arguments
if len(sys.argv) < 5:
    print('Not enough arguments')
    print(f'Usage: {sys.argv[0]} <compliance_report>.json <gates>.csv <security>.csv <output_dir>')
    exit()

compliance_report = sys.argv[1]
gates_file = sys.argv[2]
security_file = sys.argv[3]
output_dir = sys.argv[4]

if verbose:
    print(f'Script: {sys.argv[0]}')
    print(f'Compliance report: {compliance_report}')
    print(f'Gates file: {gates_file}')
    print(f'Security file: {security_file}')
    print(f'Output dir: {output_dir}')

# Verify output_dir exists
if not os.path.isdir(output_dir):
    print(f'output_dir {output_dir} not found')
    exit()

# Read compliance report (json)
with open(compliance_report, "r") as json_file:
    compliance = json.load(json_file)

# Container image name will be used to determine whitelist filename
container_image = compliance['metadata']['repository']

# Read gates file (csv)
gates = []
# image_id,repo_tag,trigger_id,gate,trigger,check_output,gate_action,policy_id,matched_rule_id,whitelist_id,whitelist_name,inherited,Justification
with open(gates_file, "r") as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            if verbose:
                print(f'Column names are {", ".join(row)}')
        else:
            gates.append({
              'trigger_id': row[2],
              'gate': row[3],
              'gate_action': row[6],
              'policy_id': row[7],
              'whitelist_id': row[9],
              'justification': row[12]
              })
        line_count += 1
    if verbose:
        print(f'Processed {line_count} lines.')

# Read security file (csv)
cves = []
# tag,cve,severity,feed,feed_group,package,package_path,package_type,package_version,fix,url,inherited,description,nvd_cvss_v2_vector,nvd_cvss_v3_vector,vendor_cvss_v2_vector,vendor_cvss_v3_vector,Justification
with open(security_file, "r") as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    security = {}
    for row in csv_reader:
        if line_count == 0:
            if verbose:
                print(f'Column names are {", ".join(row)}')
        else:
            cves.append({
                'cve': row[1],
                'severity': row[2],
                'package': row[5],
                'justification': row[17]
                })
        line_count += 1
    if verbose:
        print(f'Processed {line_count} lines.')

# Function to find an existing whitelist_id, otherwise returns md5 hash of trigger_id+container_image name
# TODO: determine if this is compatible with existing policy handling
def getWhitelistId (trigger_id):
    default_whitelist_id = hashlib.md5(str(trigger_id + container_image).encode()).hexdigest()
    for gates_item in gates:
        if gates_item['trigger_id'] == trigger_id:
            if (gates_item['whitelist_id'] == None) or (gates_item['whitelist_id'] == ''):
                return default_whitelist_id
            else:
                return gates_item['whitelist_id']
    return default_whitelist_id

# Function to find an existing justification, otherwise returns "new"
def getJustification (trigger_id):
    justification = ''
    for gates_item in gates:
        if gates_item['trigger_id'] == trigger_id:
            if gates_item['justification'] == 'See Anchore CVE Results sheet':
                trigger_split = gates_item['trigger_id'].split('+')
                trigger_cve = trigger_split[0]
                trigger_pkg = trigger_split[1]
                for cves_item in cves:
                    if (cves_item['cve'] == trigger_cve) and (cves_item['package'].startswith(trigger_pkg)):
                        justification = cves_item['justification']
            else:
                justification = gates_item['justification']

    if (justification != None) and (justification != ''):
        return justification
    else:
        return 'new'

# Generate new whitelist from items in compliance report
whitelist = []
for item in compliance['policyEvaluation']:
    if item['gateAction'] in ['stop', 'warn']:
        whitelist_item = {
            'id': getWhitelistId(item['triggerId']),
            'trigger_id': item['triggerId'],
            'gate': item['gate'],
            'comment': getJustification(item['triggerId'])
        }
        whitelist.append(whitelist_item)

# whitelist filename based on container image name
whitelist_name = container_image.replace('/','-')
whitelist_file = output_dir + '/' + whitelist_name + '.json'
with open(whitelist_file, "w") as w_file:
    whitelist_json = {
        "comment": whitelist_name + " whitelist",
        "id": whitelist_name + "Whitelist",
        "items": whitelist,
        "name": whitelist_name + " Whitelist",
        "version": "1_0"
    }
    w_file.write(json.dumps(whitelist_json))
    w_file.close()
    print(f'wrote {whitelist_file}')

if verbose:
    for item in whitelist:
        print(item)

# Add new whitelist to template.json
