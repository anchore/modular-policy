import csv
import hashlib
import json
import os

# ----------
# constants
# ----------
BUNDLE_COMPONENTS = [
        'mappings',
        'policies',
        'whitelists',
        'whitelisted_images',
        'blacklisted_images'
]

GATES_CSV_FIELDS = {
    'trigger_id': 2,
    'gate': 3,
    'gate_action': 6,
    'policy_id': 7,
    'whitelist_id': 9,
    'justification': 12
}

SECURITY_CSV_FIELDS = {
    'cve': 1,
    'severity': 2,
    'package': 5,
    'justification': 17
}

# -----------------
# shared functions
# -----------------


def read_json_file(json_file):
    try:
        with open(json_file, "r") as r_file:
            return json.load(r_file)
    except OSError as e:
        print(f'error opening JSON file: {e}')


def write_json_file(json_obj, json_file, formatted=True):
    try:
        with open(json_file, "w") as w_file:
            if formatted:
                w_file.write(
                        json.dumps(json_obj, indent=2, separators=(',', ': ')))
            else:
                w_file.write(json.dumps(json_obj))
            w_file.close()
            print(f'wrote {json_file}')
    except OSError as e:
        print(f"error writing {json_file}: {e}")


def write_text_file(txt, txt_file):
    try:
        with open(txt_file, 'w') as w_file:
            w_file.write(txt)
            w_file.close()
            print(f'wrote {txt_file}')
    except OSError as e:
        print(f"error writing {txt_file}: {e}")


def read_bundle_array(json_array, array_name, bundle_dir):
    bundle_array = []
    if len(json_array) == 0:
        print(f'(no {array_name})')
    for json_item in json_array:
        json_file = os.path.join(
                bundle_dir,
                array_name,
                json_item['id'] + '.json'
        )
        bundle_item_json = read_json_file(json_file)
        bundle_array.append(bundle_item_json)
        print(f'read {json_file}')
    return bundle_array


def dump_json_array(json_array, json_name, bundle_dir):
    for json_item in json_array:
        json_file = os.path.join(
                bundle_dir,
                json_name,
                json_item['id'] + '.json'
        )
        write_json_file(json_item, json_file)


def read_csv_file(csv_file, csv_fields, debug=False):
    csv_list = []
    try:
        with open(csv_file, "r") as r_file:
            csv_reader = csv.reader(r_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                if line_count == 0:
                    if debug:
                        print(f'Column names are {", ".join(row)}')
                else:
                    csv_row = {}
                    for key, value in csv_fields.items():
                        csv_row[key] = row[value]
                        print(f'csv_row[{key}] = {row[value]}')
                    csv_list.append(csv_row)
                line_count += 1
            if debug:
                print(f'Processed {line_count} CSV rows.')
            return csv_list
    except OSError as e:
        print(f'error processing CSV file {csv_file}: {e}')


# ---------------------
# subcommand: generate
# ---------------------
def generate_bundle(ctx):
    bundle_dir = ctx.obj['bundle_dir']

    template_file = bundle_dir + '/template.json'
    print(f'Generating bundle from {bundle_dir}')
    template_json = read_json_file(template_file)

    bundle_id = template_json['id']
    bundle_json = template_json
    print(f'Bundle id: {bundle_id}')
    for component in BUNDLE_COMPONENTS:
        bundle_json[component] = read_bundle_array(
                template_json[component], component, bundle_dir)

    bundle_json_file = 'bundle.json'
    bundle_id_file = 'bundle_id'
    write_json_file(bundle_json, bundle_json_file)
    write_text_file(bundle_id, bundle_id_file)


# --------------------
# subcommand: extract
# --------------------
def extract_bundle(ctx, input_file):
    bundle_dir = ctx.obj['bundle_dir']
    print(f'Extracting bundle {input_file.name} into dir {bundle_dir}')

    # Read original bundle JSON file
    bundle_json = read_json_file(input_file.name)

    # Create bundle directory structure
    try:
        os.makedirs(bundle_dir, exist_ok=True)
        for component in BUNDLE_COMPONENTS:
            bundle_dir_path = os.path.join(bundle_dir, component)
            os.makedirs(bundle_dir_path, exist_ok=True)
    except OSError as e:
        print(f'error creating bundle directory or its subdirectories: {e}')

    # Populate template json
    template_file = os.path.join(bundle_dir, 'template.json')
    template_json = {
            'id': bundle_json['id'],
            'name': bundle_json['name'],
            'version': bundle_json['version'],
            'description': bundle_json['description'],
            'mappings': [],
            'policies': [],
            'whitelists': [],
            'whitelisted_images': [],
            'blacklisted_images': [],
    }
    for component in BUNDLE_COMPONENTS:
        for i in bundle_json[component]:
            template_json[component].append({'id': i['id']})

    # Write template file
    write_json_file(template_json, template_file, False)

    # Write components files
    for component in BUNDLE_COMPONENTS:
        dump_json_array(bundle_json[component], component, bundle_dir)

    print('Bundle extraction complete')


# ------------------
# subcommand: allow
# ------------------
def allowlist_json_from_eval(ctx, compliance_file, gates_file, security_file):
    bundle_dir = ctx.obj['bundle_dir']
    debug = ctx.obj['debug']
    if debug:
        print('generating allowlist')
        print(f'bundle_dir: {bundle_dir}')
        print(f'compliance report: {compliance_file}')
        print(f'gates report: {gates_file.name}')
        print(f'security (CVEs) report: {security_file.name}')

    compliance_json = read_json_file(compliance_file.name)

    # Container image name will be used to determine allowlist filename
    container_image = compliance_json['metadata']['repository']

    # Read gates file (csv)
    # image_id,repo_tag,trigger_id,gate,trigger,check_output,gate_action,policy_id,matched_rule_id,whitelist_id,whitelist_name,inherited,Justification
    gates = read_csv_file(gates_file.name, GATES_CSV_FIELDS)

    # Read security file (csv)
    # tag,cve,severity,feed,feed_group,package,package_path,package_type,package_version,fix,url,inherited,description,nvd_cvss_v2_vector,nvd_cvss_v3_vector,vendor_cvss_v2_vector,vendor_cvss_v3_vector,Justification
    cves = read_csv_file(security_file.name, SECURITY_CSV_FIELDS)

    # Find an existing allowlist_id, otherwise return md5 hash of
    #  trigger_id+container_image name
    # TODO: determine if this is compatible with existing policy handling
    def getAllowlistId(trigger_id):
        default_allowlist_id = hashlib.md5(
                str(trigger_id + container_image).encode()).hexdigest()
        for gates_item in gates:
            if gates_item['trigger_id'] == trigger_id:
                if (gates_item['whitelist_id'] is None) or \
                        (gates_item['whitelist_id'] == ''):
                    return default_allowlist_id
                else:
                    return gates_item['whitelist_id']
        return default_allowlist_id

    # Find an existing justification, otherwise return "new"
    def getJustification(trigger_id):
        refer_to_cve = 'See Anchore CVE Results sheet'
        justification = ''
        for gates_item in gates:
            if gates_item['trigger_id'] == trigger_id:
                if gates_item['justification'] == refer_to_cve:
                    trigger_split = gates_item['trigger_id'].split('+')
                    trigger_cve = trigger_split[0]
                    trigger_pkg = trigger_split[1]
                    for cves_item in cves:
                        if (cves_item['cve'] == trigger_cve) and \
                                (cves_item['package'].startswith(trigger_pkg)):
                            justification = cves_item['justification']
                else:
                    justification = gates_item['justification']

        if justification:
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
    allowlist_name = container_image.replace('/', '-')
    allowlist_file = bundle_dir + '/whitelists/' + allowlist_name + '.json'
    allowlist_file = os.path.join(
            bundle_dir,
            'whitelists',
            allowlist_name + '.json'
    )

    # write new allowlist to file
    if debug:
        print(f'writing allowlist_file: {allowlist_file}')
    allowlist_json = {
        "comment": allowlist_name + " allowlist",
        "id": allowlist_name + "Allowlist",
        "items": allowlist,
        "name": allowlist_name + " Allowlist",
        "version": "1_0"
    }
    write_json_file(allowlist_json, allowlist_file, False)
    if debug:
        for item in allowlist:
            print(item)


# ----------------
# subcommand: map
# ----------------
def map_allow(ctx, allowlist, mapping, map_pattern):
    debug = ctx.obj['debug']
    if debug:
        print(f'Mapping {allowlist} to {map_pattern} in mapping {mapping}')
    print('NOT YET IMPLEMENTED')
