import csv
import hashlib
import json
import os
import sys

#------------------
# shared functions

def json_dump_formatted (json_obj, json_file):
   with open(json_file, "w") as w_file:
       w_file.write(json.dumps(json_obj, indent = 2, separators=(',', ': ')))
       w_file.close()
       print(f'wrote {json_file}')

def dump_json_array(json_array, json_name, bundle_dir):
    for json_item in json_array:
        json_file = bundle_dir + '/' + json_name + '/' + json_item['id'] + '.json'
        try:
            json_dump_formatted(json_item, json_file)
        except:
            e = sys.exc_info()[0]
            print(f"error writing {json_item['id']}: {e}")


#------------------
# subcommand: allow

def allowlist_json_from_eval(ctx, compliance_file, gates_file, security_file):
    bundle_dir = ctx.obj['bundle_dir']
    debug = ctx.obj['debug']
    if debug:
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
                    if debug:
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
            if debug:
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
                    if debug:
                        print(f'Column names are {", ".join(row)}')
                else:
                    cves.append({
                        'cve': row[1],
                        'severity': row[2],
                        'package': row[5],
                        'justification': row[17]
                        })
                line_count += 1
            if debug:
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
        if debug:
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
            if debug:
                for item in allowlist:
                    print(item)
    except:
        e = sys.exc_info()[0]
        print(e)


#------------------
# subcommand: extract

def extract_bundle(ctx, input_file):
    bundle_dir = ctx.obj['bundle_dir']
    debug = ctx.obj['debug']
    print(f'Extracting bundle {input_file.name} into dir {bundle_dir}')

    # Read original bundle JSON file
    try:
        bundle_json = json.load(input_file)
    except:
        e = sys.exc_info()[0]
        print(f'error opening bundle JSON file: {e}')

    # Create bundle directory structure
    try:
        os.makedirs(bundle_dir, exist_ok=True)
        for d in ['blacklisted_images','mappings','policies','whitelisted_images','whitelists']:
            os.makedirs(bundle_dir + '/' + d, exist_ok=True)
    except:
        e = sys.exc_info()[0]
        print(f'error creating bundle directory or its subdirectories: {e}')

    # Create template.json
    template_json = {
            'id': bundle_json['id'],
            'name': bundle_json['name'],
            'version': bundle_json['version'],
            'mappings': [],
            'policies': [],
            'whitelists': [],
            'whitelisted_images': [],
            'blacklisted_images': [],
    }
    template_file = bundle_dir + '/template.json'
    for i in bundle_json['mappings']:
        template_json['mappings'].append({ 'id': i['id'] })
    for i in bundle_json['policies']:
        template_json['policies'].append({ 'id': i['id'] })
    for i in bundle_json['whitelists']:
        template_json['whitelists'].append({ 'id': i['id'] })
    for i in bundle_json['whitelisted_images']:
        template_json['whitelisted_images'].append({ 'id': i['id'] })
    for i in bundle_json['blacklisted_images']:
        template_json['blacklisted_images'].append({ 'id': i['id'] })

    try:
        if debug:
            print(f'writing template file: {template_file}')
        with open(template_file, "w") as w_file:
            w_file.write(json.dumps(template_json))
            w_file.close()
            print(f'wrote {template_file}')
    except:
        e = sys.exc_info()[0]
        print(f'error writing template file: {e}')

    # Extract mappings
    dump_json_array(bundle_json['mappings'], 'mappings', bundle_dir)

    # Extract policies
    dump_json_array(bundle_json['policies'], 'policies', bundle_dir)

    # Extract allowlists
    dump_json_array(bundle_json['whitelists'], 'whitelists', bundle_dir)

    # Extract whitelisted_images
    dump_json_array(bundle_json['whitelisted_images'], 'whitelisted_images', bundle_dir)

    # Extract blacklisted_images
    dump_json_array(bundle_json['blacklisted_images'], 'blacklisted_images', bundle_dir)

    print('Bundle extraction complete')


#------------------
# subcommand: generate

def generate_bundle(ctx, bundle_dir):
    bundle_dir = ctx.obj['bundle_dir']
    debug = ctx.obj['debug']
    print(f'Generating bundle from {bundle_dir}')


#------------------
# subcommand: map

def map_allow(ctx, allowlist, mapping, map_pattern):
    bundle_dir = ctx.obj['bundle_dir']
    debug = ctx.obj['debug']
    print(f'Mapping {allowlist} to {map_pattern} in mapping {mapping}')

