import os
import re
import pandas as pd
import requests
import time
import ipaddress

# --- Configuration ---
LOG_DIRECTORY = 'logs'
API_KEY = 'ENTER_YOUR_API_KEY'
VT_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
# Defining sensitive paths that attackers often target
SENSITIVE_PATHS = ['/etc/shadow', '/.env', '/config.php', '/wp-login.php', '/admin', '/backup.zip', '/id_rsa']
THRESHOLD = 5  # Number of requests to trigger investigation

# Captures: IP, Timestamp, Method (GET/POST), Path, and Status Code
LOG_PATTERN = r'(?P<ip>[\d\.]+) - - \[(?P<time>.*?)\] "(?P<method>\w+) (?P<path>.*?) HTTP.*?" (?P<status>\d{3})'


def validate_public_ip(ip_str):
    """Checks if the string is a valid public IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_global
    except ValueError:
        return False


def get_vt_reputation(ip):
    """Queries VirusTotal API for IP reputation."""
    if API_KEY == 'YOUR_VIRUSTOTAL_API_KEY':
        return "No API Key"

    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(f"{VT_URL}{ip}", headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return f"{stats['malicious']} engines flagged"
        elif response.status_code == 429:
            return "Quota Exceeded"
        return "Clean/Unknown"
    except Exception as e:
        return f"Error: {str(e)}"


def analyze_logs():

    pd.set_option('display.max_columns', None)
    pd.set_option('display.expand_frame_repr', False)
    pd.set_option('display.max_colwidth', None)
    all_logs = []


    if not os.path.exists(LOG_DIRECTORY):
        print(f"Directory {LOG_DIRECTORY} not found.")
        return

    for filename in os.listdir(LOG_DIRECTORY):
        if filename.endswith(('.log', '.txt')):
            with open(os.path.join(LOG_DIRECTORY, filename), 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    match = re.search(LOG_PATTERN, line)
                    if match:
                        data = match.groupdict()
                        data['source_file'] = filename
                        all_logs.append(data)

    if not all_logs:
        print("No valid logs found.")
        return

    df = pd.DataFrame(all_logs)

    # Grouping by IP to see their behavior
    analysis = df.groupby('ip').agg(
        total_requests=('ip', 'count'),
        unique_paths=('path', 'nunique'),
        status_404_count=('status', lambda x: (x == '404').sum()),
        status_200_count=('status', lambda x: (x == '200').sum()),
        accessed_sensitive_path=('path', lambda x: any(p in ' '.join(x) for p in SENSITIVE_PATHS)),
        source_files = ('source_file', lambda x: ', '.join(set(x)))
    ).reset_index()

    # Filter suspicious candidates (over threshold OR accessed sensitive path)
    suspicious = analysis[
        (analysis['total_requests'] > THRESHOLD) | (analysis['accessed_sensitive_path'] == True)].copy()

    # Validate IPs (Remove local/private/invalid IPs)
    suspicious['is_public'] = suspicious['ip'].apply(validate_public_ip)
    suspicious = suspicious[suspicious['is_public'] == True]

    if suspicious.empty:
        print("No suspicious public activity detected.")
        return

    print(f"Enriching {len(suspicious)} suspicious IPs with VirusTotal...")
    results = []
    for ip in suspicious['ip']:
        results.append(get_vt_reputation(ip))
        time.sleep(15)  # Rate limiting for free API

    suspicious['VT_Reputation'] = results

    # --- 5. Final Report Export & Formatted Print ---
    output_file = 'final_opsec_report.csv'
    suspicious.to_csv(output_file, index=False)

    print("\n" + "╔" + "═" * 118 + "╗")
    print(f"║ {'LOG ANALYSIS SUMMARY':^116} ║")  
    print("╠" + "═" * 20 + "╦" + "═" * 12 + "╦" + "═" * 16 + "╦" + "═" * 35 + "╦" + "═" * 31 + "╣")

    header = f"║ {'IP Address':^18} ║ {'Requests':^10} ║ {'Sens. Path':^14} ║ {'Source Files':^33} ║ {'VT Reputation':^29} ║"
    print(header)
    print("╠" + "═" * 20 + "╬" + "═" * 12 + "╬" + "═" * 16 + "╬" + "═" * 35 + "╬" + "═" * 31 + "╣")

    for _, row in suspicious.iterrows():
        files = (row['source_files'][:30] + '..') if len(row['source_files']) > 30 else row['source_files']

        line = f"║ {row['ip']:<18} ║ {str(row['total_requests']):^10} ║ {str(row['accessed_sensitive_path']):^14} ║ {files:<33} ║ {row['VT_Reputation']:<29} ║"
        print(line)

    print("╚" + "═" * 20 + "╩" + "═" * 12 + "╩" + "═" * 16 + "╩" + "═" * 35 + "╩" + "═" * 31 + "╝")
    print(f"[*] Full report saved to: {output_file}\n")


if __name__ == "__main__":
    analyze_logs()
