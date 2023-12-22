import json

def get_workloads():
    with open('workloads.json', 'r') as f:
        return json.load(f)

def get_labels():
    with open('labels.json', 'r') as f:
        return json.load(f)


def get_services():
    with open('services.json', 'r') as f:
        return json.load(f)

def get_iplists():
    with open('iplists.json', 'r') as f:
        return json.load(f)

def get_rulesets():
    with open('rulesets.json', 'r') as f:
        return json.load(f)

def get_labelgroups():
    with open('labelgroups.json', 'r') as f:
        return json.load(f)
