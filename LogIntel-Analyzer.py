import pandas as pd
import re
import os


def analyze_folder_to_table(folder_path):
    # Professional Regex for IP and Timestamp
    log_pattern = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[(?P<timestamp>.*?)\]'
    all_data = []

    if not os.path.exists(folder_path):
        print(f"Error: Folder '{folder_path}' not found.")
        return

    for filename in os.listdir(folder_path):
        if filename.endswith(".txt") or filename.endswith(".log"):
            file_path = os.path.join(folder_path, filename)
            with open(file_path, 'r') as f:
                for line in f:
                    match = re.search(log_pattern, line)
                    if match:
                        entry = match.groupdict()
                        all_data.append(entry)

    if not all_data:
        print("No data found.")
        return

    # Create DataFrame
    df = pd.DataFrame(all_data)

    # Aggregate and count
    ip_counts = df['ip'].value_counts().reset_index()
    ip_counts.columns = ['IP Address', 'Request Count']

    min_counts = 10
    # Filter suspicious
    suspicious = ip_counts[ip_counts['Request Count'] >= min_counts]


    print("\n" + "+" + "-" * 40 + "+")
    print("| {:<20} | {:<15} |".format("IP Address", "Total Requests"))
    print("+" + "-" * 40 + "+")
    for _, row in suspicious.iterrows():
        print("| {:<20} | {:<15} |".format(row['IP Address'], row['Request Count']))
    print("+" + "-" * 40 + "+")

    # --- 2. Export to CSV
    output_file = 'threat_report.csv'
    suspicious.to_csv(output_file, index=False)
    print(f"\n[!] Success: Report saved as '{output_file}' ")


if __name__ == "__main__":
    analyze_folder_to_table('logs')