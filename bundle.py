import csv
import hashlib
import json
import sys


verbose = True


# allow_from_eval
def allowlist_json_from_eval(compliance_file, gates_file, security_file, bundle_dir):
    if verbose:
        print('generating allowlist')
        print(f'bundle_dir: {bundle_dir}')
        print(f'compliance report: {compliance_file}')
        print(f'gates report: {gates_file.name}')
        print(f'security (CVEs) report: {security_file.name}')

    try:
        with open(compliance_file, "r") as json_file:
            compliance_json = json.load(json_file)
    except:
        e = sys.exc_info()[0]
        print(f'error opening compliance report file: {e}')

    # Container image name will be used to determine allowlist filename
    container_image = compliance_json['metadata']['repository']

    # Read gates file (csv)
    gates = []
    # image_id,repo_tag,trigger_id,gate,trigger,check_output,gate_action,policy_id,matched_rule_id,whitelist_id,whitelist_name,inherited,Justification
    try:
        with open(gates_file.name, "r") as csv_file:
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
    except:
        e = sys.exc_info()[0]
        print(f'error processing gates report file: {e}')

    # Read security file (csv)
    cves = []
    # tag,cve,severity,feed,feed_group,package,package_path,package_type,package_version,fix,url,inherited,description,nvd_cvss_v2_vector,nvd_cvss_v3_vector,vendor_cvss_v2_vector,vendor_cvss_v3_vector,Justification
    try:
        with open(security_file.name, "r") as csv_file:
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
    except:
        e = sys.exc_info()[0]
        print(f'error processing security (CVEs) report file: {e}')

    # Function to find an existing allowlist_id, otherwise returns md5 hash of trigger_id+container_image name
    # TODO: determine if this is compatible with existing policy handling
    def getAllowlistId (trigger_id):
        default_allowlist_id = hashlib.md5(str(trigger_id + container_image).encode()).hexdigest()
        for gates_item in gates:
            if gates_item['trigger_id'] == trigger_id:
                if (gates_item['whitelist_id'] == None) or (gates_item['whitelist_id'] == ''):
                    return default_allowlist_id
                else:
                    return gates_item['whitelist_id']
        return default_allowlist_id
    
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

    # Generate new allowlist from items in compliance report
    allowlist = []
    for item in compliance_json['policyEvaluation']:
        if item['gateAction'] in ['stop', 'warn']:
            allowlist_item = {
                'id': getAllowlistId(item['triggerId']),
                'trigger_id': item['triggerId'],
                'gate': item['gate'],
                'comment': getJustification(item['triggerId'])
            }
            allowlist.append(allowlist_item)

    # allowlist filename based on container image name
    #allowlist_name = container_image.replace('/','-')
    allowlist_name = 'demo'
    allowlist_file = bundle_dir + '/whitelists/' + allowlist_name + '.json'
    allowlist = []

    # write new allowlist to file
    try:
        if verbose:
            print(f'writing allowlist_file: {allowlist_file}')
        with open(allowlist_file, "w") as w_file:
            allowlist_json = {
                "comment": allowlist_name + " allowlist",
                "id": allowlist_name + "Allowlist",
                "items": allowlist,
                "name": allowlist_name + " Allowlist",
                "version": "1_0"
            }
            w_file.write(json.dumps(allowlist_json))
            w_file.close()
            print(f'wrote {allowlist_file}')
            if verbose:
                for item in allowlist:
                    print(item)
    except:
        e = sys.exc_info()[0]
        print(e)


# extract subcommand
def extract_bundle(input_file, bundle_dir):
    print(f'Extracting bundle {input_file} into {bundle_dir}')


# generate subcommand
def generate_bundle(bundle_dir):
    print(f'Generating bundle from {bundle_dir}')


# map subcommand
def map_allow(allowlist, mapping, map_pattern, bundle_dir):
    print(f'Mapping {allowlist} to {map_pattern} in mapping {mapping}')

