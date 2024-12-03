import re
from collections import defaultdict
def log_file(log_file_path):
    analyze={
        'ip_requests':defaultdict(int),
        'error_codes':defaultdict(int),
        'failed_login_attempt':defaultdict(int),
        'endpoint_count':defaultdict(int),
        'patterns':{
            'error_rate':{},
            'admin_probes':defaultdict(int),
            'rapid_req':defaultdict(list)
        }
    }
    ip_time=defaultdict(list)
    with open(log_file_path,'r') as file:
        for rows in file:
            #matching the ip address
            ip_found=re.search(r'(\d+\.\d+\.\d+\.\d+)',rows)
            if not ip_found:
                continue

            ip_address=ip_found.group(1)
            analyze['ip_requests'][ip_address]+=1

            #time
            time=re.search(r'\[([^\]]+)\]',rows)
            time_gr=time.group(1) if time else None
            #endpoint
            endpoint=re.search(r'\"[A-Z]+ (/\w+[/\w]*)',rows)
            endpoint_gr=endpoint.group(1) if endpoint else 'unknown'
            analyze['endpoint_count'][endpoint_gr]+=1
            #error_codes
            error=re.search(r'\b(\d{3})\b',rows)
            if error:
                error_found=error.group(1)
                analyze['error_codes'][error_found]+=1
            
            #failed login attempt
            if error_found=='401' or 'Invalid credentials' in rows:
                analyze['failed_login_attempt'][ip_address]+=1
            if '/admin' in endpoint_gr or '/config' in endpoint_gr:
                analyze['patterns']['admin_probes'][ip_address]+=1
            if time_gr:
                ip_time[ip_address].append(time_gr)
    #rapid request
    for ip,time in ip_time.items():
        #more than 10 req
        if len(time)>10:
            analyze['patterns']['rapid_req'][ip]=time


    
    # error rate
    for ip in analyze['ip_requests']:
        total_ip=analyze['ip_requests'][ip]
        error_req=analyze['failed_login_attempt'].get(ip,0)
        error_percent=error_req/total_ip*100
        analyze['patterns']['error_rate'][ip]=error_percent

    return analyze

            