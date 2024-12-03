from log_analyzer import log_file
def display_report(log_path,max_error_rate=30):
    log_analyze=log_file(log_path)
    print("++++++ANALYSIS_REPORT++++++")
    # request count
    print("------Requests per IP Address------")
    sort_ip=sorted(log_analyze['ip_requests'].items(),key=lambda x:x[1],reverse=True)
    for ip,count in sort_ip[:]:
        print(f"{ip:<15}      {count} requests")
    #endpoints
    print("..................................")
    print("----Most Frequently Accessed Endpoint----")
    sorted_endpoint=sorted(log_analyze['endpoint_count'].items(),key=lambda x:x[1],reverse=True)
    for endpoint,count in sorted_endpoint[:]:
        print(f"{endpoint:<15}{count} accesses")

    print("..................................")
    print("----Suspicious activity----")
    suspicious_activity=[]
    #maximum failed attempt=3
    failed_login={ip:count for ip,count in log_analyze['failed_login_attempt'].items() if count>3}
    if failed_login:
        print("--Suspicious multiple failed logins--")
        for ip,count in failed_login.items():
            print(f"{ip:<20} {count} failed attempts")
            suspicious_activity.append(f"failed login :    {ip}")

        #admin endpoint
        admin_probes=log_analyze['patterns']['admin_probes']
        if admin_probes:
            print("--Suspicious: Admin Endpoint Probing--")
            for ip,count in admin_probes.items():
                print(f"{ip:<20} {count} admin endpoint probes")
                suspicious_activity.append(f"Admin endpoint probes :{ip}")
        
        print("..................................")
        print("----High error rate----")
        high_error_rate_ip={
            ip:rate for ip,rate in log_analyze['patterns']['error_rate'].items()
            if rate>max_error_rate
        }
        if high_error_rate_ip:
            print("---Suspicious High error rates---")
            for ip,rate in high_error_rate_ip.items():
                print(f"{ip:<15} {rate:.2f}% error rate")
                suspicious_activity.append(f"High error rate : {ip}")
        
        rapid_request_ip=log_analyze['patterns']['rapid_req']
        if rapid_request_ip:
            print("---Suspicious Rapid Request---")
            for ip, t in rapid_request_ip.items():
                print(f"{ip:<20} {len(t)} rapid requests")
                suspicious_activity.append(f"Rapid requests: {ip}")

        #final
        print("SUMMARY")
        if suspicious_activity:
            print("---(POTENTIAL THREATS DETECTED)---")
            for activity in suspicious_activity:
                print(f"- {activity}")
        else:
            print("No significant suspicious activity")
        return log_analyze
