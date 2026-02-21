import pandas as pd
import re
import os
import requests
import time

# Configurations
VT_API_KEY = 'aeb406f76639644e45b6c0485fdd1990cdbb68e0d4f3afa97779611db12d86f5'
LOGS_FOLDER = 'logs'


def check_ip_reputation(ip_address):
    """
    Queries VirusTotal API v3 for IP address reputation.
    """
    if not VT_API_KEY or VT_API_KEY == 'YOUR_API_KEY_HERE':
        return "No API Key"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            # Extract malicious count from the analysis results
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return f"{stats['malicious']} engines flagged"
        elif response.status_code == 429:
            return "Rate limit (Waiting...)"
        return "Unknown"
    except Exception:
        return "Request failed"


def run_full_investigation():
    """
    Main execution flow: Scan, Parse, Analyze, and Enrich.
    """
    # Define Regex pattern to capture IP and Timestamp from standard log format
    log_pattern = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[(?P<timestamp>.*?)\]'
    all_data = []

    # Check if the logs directory exists
    if not os.path.exists(LOGS_FOLDER):
        print(f"Error: Folder '{LOGS_FOLDER}' not found.")
        return

    # 1. Directory Scanning (using os library)
    print(f"[*] Scanning logs in: {LOGS_FOLDER}")
    for filename in os.listdir(LOGS_FOLDER):
        if filename.endswith(".txt") or filename.endswith(".log"):
            file_path = os.path.join(LOGS_FOLDER, filename)
            with open(file_path, 'r') as f:
                for line in f:
                    match = re.search(log_pattern, line)
                    if match:
                        all_data.append(match.groupdict())

    if not all_data:
        print("No log entries identified.")
        return

    # 2. Data Processing (using Pandas)
    df = pd.DataFrame(all_data)
    ip_counts = df['ip'].value_counts().reset_index()
    ip_counts.columns = ['IP Address', 'Request Count']

    # Filter suspicious IPs based on request volume
    min_counts =10
    suspicious = ip_counts[ip_counts['Request Count'] > min_counts].copy()

    # 3. External Intelligence Enrichment (VirusTotal API)
    if suspicious.empty:
        print("[*] No suspicious activity detected above threshold.")
        return

    print(f"[*] Found {len(suspicious)} suspicious IPs. Starting VirusTotal enrichment...")
    vt_results = []
    for ip in suspicious['IP Address']:
        print(f"   - Investigating {ip}...")
        res = check_ip_reputation(ip)
        vt_results.append(res)
        # Sleep to respect VirusTotal free tier rate limits (4 requests/min)
        time.sleep(15)

    suspicious['VT_Status'] = vt_results

    # 4. Final Output Generation
    print("\n" + "=" * 60)
    print("             FINAL OPSEC INTELLIGENCE REPORT")
    print("=" * 60)
    print(suspicious.to_string(index=False))
    print("=" * 60)

    # Save findings to CSV for further triage
    output_filename = 'final_threat_report.csv'
    suspicious.to_csv(output_filename, index=False)
    print(f"\n[!] Success: Investigation saved to {output_filename}")


if __name__ == "__main__":
    run_full_investigation()