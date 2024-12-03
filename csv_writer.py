import csv
def save_to_csv(log_analyze,file_name):
    with open(file_name,'w',newline='') as csvfile:
        writer=csv.writer(csvfile)
        writer.writerow(["Request per IP"])
        writer.writerow(["IP Address","Request Count"])
        for ip,count in sorted(log_analyze['ip_requests'].items(),key=lambda x:x[1],reverse=True):
            writer.writerow([ip,count])
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint","Access Count"])
        for endpoint,count in sorted(log_analyze['endpoint_count'].items(),key=lambda x:x[1],reverse=True):
            writer.writerow([endpoint,count])
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address","Failed Login Count"])
        for ip,count in log_analyze['failed_login_attempt'].items():
            if count>3:
                writer.writerow([ip,count])
        
