from ip_check import ipv4,ips_inrange,ips_incidr
import code

def iplist_num_ips(ip_ranges):
    num_ips = 0
    for i in ip_ranges:
        range_size = 0
        if 'to_ip' in i and ipv4(i['from_ip']):
            start_ip = i['from_ip']
            end_ip = i['to_ip']
            range_size = ips_inrange(start_ip,end_ip)
        elif ipv4(i['from_ip']):
            start_ip = i['from_ip']
            range_size = ips_incidr(start_ip)
        if i['exclusion'] == False:
            num_ips = num_ips + range_size
        else:
            num_ips = num_ips - range_size
    return num_ips




def rule_builder(scopes,rule_list,obj):
    rule_built = []
    for i in scopes:
        for j in rule_list:
            if j['unscoped_consumers'] == False:
                intrascope = True
            else:
                intrascope = False
            href = j['href']
            scope = i
            provider_labels = [obj.get('href', provider['label']['href']).name for provider in j['providers'] if 'label' in provider]
            provider_iplists = [obj.get('href', provider['ip_list']['href']).name for provider in j['providers'] if 'ip_list' in provider]
            consumer_labels = [obj.get('href', consumer['label']['href']).name for consumer in j['consumers'] if 'label' in consumer]
            consumer_iplists = [obj.get('href', consumer['ip_list']['href']).name for consumer in j['consumers'] if 'ip_list' in consumer]
            
            if {'actors':'ams'} in j['providers']:
                if scope == []:
                    provider_labels = ['All Workloads']
                else:
                    provider_labels = scope
            elif provider_labels != []:
                provider_labels = provider_labels + scope
                    
            if {'actors':'ams'} in j['consumers']:
                if scope == []:
                    consumer_labels = ['All Workloads']
                if intrascope == False:
                    consumer_labels = ['All Workloads']
                else:
                    consumer_labels = scope
            elif intrascope == True and consumer_labels != []:
                    consumer_labels = consumer_labels + scope
                    
            providers = provider_labels + provider_iplists
            consumers = consumer_labels + consumer_iplists
            services = []
            for service in j['ingress_services']:
                if 'href' in service:
                    services.append(obj.get('href',service['href']).name)
                if 'port' in service:
                    services.append(service)

            rule_built.append({'href':href,'intrascope':intrascope,'consumers':consumers,'providers':providers,'services':services})
    return rule_built
            
                    
            

def scope_parser(scopes,obj):
    scopes_parsed = [[obj.get('href', label['label']['href']).name for label in group if 'label' in label] for group in scopes]
    return scopes_parsed
    
                               
            
#def service_parser(services,obj):
    
    
    
    
    
