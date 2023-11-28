#PCE Rule Tuning

disclaimer = '''
#No support for Label Group, Process Based Services, Virtual Services, IPv6
#Services covering the exact port range 49152-65535 will be counted as 1 rule_score_service
#Multiple traffic for the same rule with any number of ports between 49152-65535 will count as 1 traffic score
#Workloads generating traffic with multiple IP addresses may skew results.
    #They count as 1 score for rules regardless of number of IPs but each IP is 1 score on traffic score
#IP Lists with FQDN may skew results.
    #Each FQDN entry counts as 1 rule score. FQDNs may resolve to multiple IPs over time. Each IP is 1 traffic score.
'''

import json, requests, time, pce_ld, pce_auth, csv, time
from datetime import datetime, timedelta
import code
from io import StringIO
from itertools import product
#code.interact(local=dict(globals(),**locals()))

def login():
    global auth_creds, server,base_url_orgid,base_url
    auth_creds,base_url_orgid,base_url = pce_auth.connect()
    pce_ld.auth_creds = auth_creds
    pce_ld.base_url_orgid = base_url_orgid
    pce_ld.base_url = base_url


def save_file(filename,filecontent):
    with open(filename, "wb") as file:
        file.write(filecontent)

def content_to_csv(content):
    csv_data = StringIO(content.decode('utf-8'))
    reader = csv.DictReader(csv_data)
    data = list(reader)
    return data


def explorer_result_dedup(data):
    consumer_ips = []
    provider_ips = []
    services = []
    high_port_tcp = 0
    high_port_udp = 0
    for i in data:
        if i['Consumer IP'] not in consumer_ips:
            consumer_ips.append(i['Consumer IP'])
        if i['Provider IP'] not in provider_ips:
            provider_ips.append(i['Provider IP'])
        service = {'Port':i['Port'],'Protocol':i['Protocol']}
        if service not in services:
            if int(service['Port']) > 49152:
                if service['Protocol'].lower == 'udp' and high_port_udp == 0:
                    services.append(service)
                    high_port_udp = 1
                if service['Protocol'].lower == 'tcp' and high_port_udp == 0:
                    services.append(service)
                    high_port_tcp = 1
            else:
                services.append(service)
    consumer_score = len(consumer_ips)
    provider_score = len(provider_ips)
    service_score = len(services)
    total_score = consumer_score * provider_score * service_score
    scores = {'consumer_score':consumer_score,'provider_score':provider_score,'service_score':service_score,'total_score':total_score}
    return scores


def get_all_results(query_index,obj):
    score_comparison = []
    query_count = 0
    for i in query_index.queries:
        query_count += 1
        print(f'Query {str(query_count)} of {len(query_index.queries)}')
        rule = obj.get_rule_by('href',i.rule_href)[0]
        results = download_result(i)
        #save_file('q' + str(query_count) + '.csv',results)
        results = content_to_csv(results)
        ts = explorer_result_dedup(results) #ts is traffic score
        score_report = {}
        score_report['ruleset'] = i.ruleset
        #code.interact(local=dict(globals(),**locals()))
        score_report['source'] = rule.consumer
        score_report['destination'] = rule.provider
        score_report['services'] = rule.services
        score_report['intrascope'] = rule.intrascope
        score_report['rule_total_score'] = rule.rule_total_score
        score_report['traffic_total_score'] = ts['total_score']
        score_report['rule_consumer_score'] = rule.consumer_total_score
        score_report['rule_provider_score'] = rule.provider_total_score
        score_report['rule_service_score'] = rule.service_score
        score_report['traffic_consumer_score'] = ts['consumer_score']
        score_report['traffic_provider_score'] = ts['provider_score']
        score_report['traffic_service_score'] = ts['service_score']
        score_comparison.append(score_report)
    return score_comparison
        
            

class Query():
    def __init__(self,ruleset_name,rule_href,async_href):
        self.ruleset = ruleset_name
        self.rule_href = rule_href
        self.async_href = async_href
        self.result_url = ''

    def add_result_url(self,url):
        self.result_url = url

    def __repr__(self):
        return f'ruleset = {self.ruleset}, rule_href = {self.rule_href}, async_href = {self.async_href}'

   
class PostQueryIndex():
    def __init__(self):
        self.queries = []
    def add(self,obj):
        self.queries.append(obj)
    def __repr__(self):
        return f'queries = {self.queries}'


def download_result(query):
    url = base_url + query.async_href
    r = requests.get(url,auth=auth_creds,verify=True)
    r = json.loads(r.text)
    while r['status'] != 'completed':
        time.sleep(3)
        r = requests.get(url,auth=auth_creds,verify=True)
        r = json.loads(r.text)
    if r['status'] == 'completed':
        download_url = base_url + r['result']
        result = requests.get(download_url,auth=auth_creds,verify=True)
        result = result.content
        return result
    else:
        return 'Query queued'
            

def ruleset_query(ruleset,obj,query_index):
    for rule in ruleset.rules:
        source, destination, service = rule_query_data(rule,obj)
        start_time,end_time = create_day_interval()
        query_name = ruleset.name + 'query'
        query = base_query_data(start_time,end_time,source,destination,service,query_name)
        r = explorer_post_query(query)
        try:
            query_index.add(Query(ruleset.name,rule.href,r['href']))
        except:
            code.interact(local=dict(globals(),**locals()))




def rule_query_data(rule,obj):
    source = rule.consumer
    destination = rule.provider
    service = rule.services
    source_list = []
    destination_list = []
    service_list = []
    icmp_proto = [1,58]
    for i in service:
        if isinstance(i, dict):
            if i['proto'] not in icmp_proto:
                service_list.append(i)
            else:
                service_list.append(i['proto'])
        elif i != 'All Services':
            service_list += obj.get('name',i).services
    for i in service_list:
        if 'icmp_type' in i:
            del i['icmp_type']
        if 'icmp_code' in i:
            del i['icmp_code']
    labels_objects = []
    for i in source:
        if isinstance(obj.get('name',i), pce_obj.IPList):
            source_list.append([{"ip_list":{"href":obj.get('name',i).href}}])
        elif i == 'All Workloads':
            source_list.append([{"actors":"ams"}])
        elif isinstance(obj.get('name',i), pce_obj.Label):
            #source_list.append([{"label":{"href":obj.get('name',i).href}}])
            labels_objects.append(i)
    combination_labels = group_labels_by_type(labels_objects,obj)
    source_list += combination_labels
    labels_objects = []
    for i in destination:
        if isinstance(obj.get('name',i), pce_obj.IPList):
            destination_list.append([{"ip_list":{"href":obj.get('name',i).href}}])
        elif i == 'All Workloads':
            destination_list.append([{"actors":"ams"}])
        elif isinstance(obj.get('name',i), pce_obj.Label):
            labels_objects.append(i)
    combination_labels = group_labels_by_type(labels_objects,obj)
    destination_list += combination_labels
    return source_list,destination_list,service_list


def group_labels_by_type(labels,obj):
    label_type_grouping = {}
    for i in labels:
        label_types = list({obj.get('name', i).type for i in labels})
        for label_type in label_types:
            label_type_grouping[label_type] = []
            for ind_label in labels:
                label = obj.get('name',ind_label)
                if label.type == label_type:
                    label_type_grouping[label_type].append(label.href)
    values = list(label_type_grouping.values())
    combinations = product(*values)
    combined_lists = []
    for combination in combinations:
        formatted_combination = [{'label': {'href': href}} for href in combination]
        combined_lists.append(formatted_combination)
    return combined_lists
    


def base_query_data(start_time,end_time,source,destination,service,query_name):
    base_query = {
    "sources": {
    "include": source,
    "exclude": []
    },
    "destinations": {
    "include": destination,
    "exclude": []
    },
    "services": {
    "include": service,
    "exclude": []
    },
    "sources_destinations_query_op": "and",
    "start_date": start_time,
    "end_date": end_time,
    "policy_decisions": [],
    "max_results": 10000,
    "query_name": query_name
    }
    base_query = json.dumps(base_query)
    return base_query


def explorer_post_query(query):
    url = base_url_orgid + '/traffic_flows/async_queries'
    data = query
    r = requests.post(url,data=data,auth=auth_creds,verify=True)
    if r.status_code in [200,201,202]:
        response = json.loads(r.text)
    elif r.status_code in [429]:
        print('Too many requests, script paused for 30 seconds')
        time.sleep(30)
        r = requests.post(url,data=data,auth=auth_creds,verify=True)
        #r = requests.post(url,data=data,auth=auth_creds,verify=True)
        if r.status_code in [200,201,202]:
            response = json.loads(r.text)
        else:
            response = r
    elif r.status_code in [401]:
        login()
        explorer_post_query(query)
    else:
        response = r
    return response


def create_day_interval():
    current_time = datetime.now()
    hours_before = current_time - timedelta(hours=168)
    start_datetime = hours_before.isoformat()
    end_datetime = current_time.isoformat()
    return(start_datetime,end_datetime)


def save_report(data):
    import file_handling
    file_handling.save_file(data)

def rule_count(ruleset_list):
    rule_count = 0
    for ruleset in ruleset_list:
        ruleset_rule_count = len(ruleset.rules)
        rule_count += ruleset_rule_count
    return rule_count

def query_ruleset_name(ruleset):
    global obj
    index_temp = PostQueryIndex()
    ruleset_query(obj.get('name',ruleset,pce_obj.Ruleset),obj,index_temp)
    r = get_all_results(index_temp, obj)
    save_report(r)


def query_ruleset_range():
    ruleset_list = rs
    global obj
    index_temp = PostQueryIndex()
    range_start = int(input('Enter range start position: '))
    range_end = int(input('Enter range end position: '))
    for i in range(range_start,range_end):
        print(f'Creating query for ruleset {i}')
        ruleset_query(ruleset_list[i],obj,index_temp)
    r = get_all_results(index_temp, obj)
    save_report(r)

    

def help():
    print('')
    print('Available modules:')
    print(f'{"help()":<35} prints this menu')
    print(f'{"query_ruleset_range()":<35} Queries a range of rulesets in a ruleset list')
    ruleset_string = 'query_ruleset_name(\"ruleset_name\")'
    print(f'{ruleset_string:<35} Queries 1 ruleset by name')
    print(f'{"login()":<35} After 30 idle minutes, you have to login again')
    print('')



print(disclaimer)
login()
import pce_obj
index1 = PostQueryIndex()
obj = pce_obj.obj
rs = obj.get_by_type(pce_obj.Ruleset)
print('')
print(f'Loaded {len(rs)} rulesets')
print(f'Loaded {rule_count(rs)} rules')
help()
#pce_auth.load_host()
#ruleset_query(rs[10],obj,query_index)
#
