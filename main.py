import re
from collections import Counter
import csv


CSV_FILE="log_analysis_results.csv"
LOG_FILE="sample.log"

# read the log file
def parse_log(filepath):
    try:
        with open(filepath, 'r') as f:
            return f.readlines()
    except FileNotFoundError:
        print("Log file not found!")
        return []
    
# count request ipAdress
def count_req_ip(log_entries):
    ip_pattern= r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ip_counts = Counter(re.search(ip_pattern, entry).group() for entry in log_entries if re.search(ip_pattern, entry))
   
    return ip_counts.most_common()

#most access endpoints
def most_access_endpoint(log_entries):
    endpoint_pattern = r'"(?:GET|POST) (\S+)'
    endpoints=[re.search(endpoint_pattern,entry).group(1) for entry in log_entries if re.search(endpoint_pattern,entry)]
    count_endpoints=Counter(endpoints)
    
    return count_endpoints.most_common(1)[0]if count_endpoints else None
 
 #detect the suspicious activity
def detect_suspicious_activity(log_entries): 
    threshold=10
    ip_pattern= r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    suspicious_pattern = r'^\S+.*"(?:GET|POST) \S+ HTTP/1.1" (401|403)'
    faild_ip=[re.match(ip_pattern,entry).group() for entry in log_entries if re.search(suspicious_pattern,entry)]
    faild_ip_counts=Counter(faild_ip)
    return [(ip,count) for ip,count in faild_ip_counts.items() if count>threshold]

#save and write of csv file
def save_to_csv(ip_request_counts,access_endpoint,suspicious_detect):
    
    csv_path = CSV_FILE
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_request_counts)
        writer.writerow([])

        # Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if access_endpoint:
            writer.writerow(access_endpoint)
        writer.writerow([])

        # Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_detect)


if __name__=="__main__":
    filepath=LOG_FILE
    csvpath=CSV_FILE     
    log_entries=parse_log(filepath)
    ip_request_counts=count_req_ip(log_entries)
    # print(counts)
    access_endpoint=most_access_endpoint(log_entries)
    # print(endpoint)
    suspicious_detect=detect_suspicious_activity(log_entries)
    # print(detect)
    save_to_csv(ip_request_counts,access_endpoint,suspicious_detect)
    result=open(csvpath,"r")
    print(result.read())
      

    
