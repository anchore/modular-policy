#!/usr/bin/env python3
#
# Reads an Anchore compliance report in JSON format. Outputs all items
# with 'gateAction: stop' as a list suitable for copying into a whitelist
# 'items' array.

import sys
import csv
import json
import hashlib

if len(sys.argv) != 4:
    raise ValueError('Usage: autoallow.py <compliance_report>.json <gates>.csv <security>.csv [<output_dir>]')

compliance_report = sys.argv[1]
gates_file = sys.argv[2]
security_file = sys.argv[3]
output_dir = 'new_whitelist'

verbose = False

if verbose:
    print(f'Script: {sys.argv[0]}')
    print(f'Compliance report: {compliance_report}')
    print(f'Gates file: {gates_file}')
    print(f'Security file: {security_file}')
    print(f'Output dir: {output_dir}')

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

def getWhitelistId (trigger_id):
    # use existing whitelist id if one exists, otherwise generate
    #   whitelist_id as md5 hash of trigger_id+container_image name
    default_whitelist_id = hashlib.md5(str(trigger_id + container_image).encode()).hexdigest()
    for gates_item in gates:
        if gates_item['trigger_id'] == trigger_id:
            if (gates_item['whitelist_id'] == None) or (gates_item['whitelist_id'] == ''):
                return default_whitelist_id
            else:
                return gates_item['whitelist_id']
    return default_whitelist_id

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

whitelist_name = container_image.replace('/','-')
whitelist_file = whitelist_name + '.json' 
with open(whitelist_file, "w") as whitelist_file:
    whitelist_json = {
        "comment": whitelist_name + " whitelist",
        "id": whitelist_name + "Whitelist",
        "items": whitelist,
        "name": whitelist_name + " Whitelist",
        "version": "1_0"
    }
    whitelist_file.write(json.dumps(whitelist_json))
    whitelist_file.close()

#for item in whitelist:
#    print(item)
