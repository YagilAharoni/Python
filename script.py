import pandas as pd
import re
import os


def run_investigation(file_path):
    """
    Analyzes server logs to identify potential scanners/threat actors.
    """
    # Professional Regex to capture IP and Timestamp from standard logs
    log_pattern = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[(?P<timestamp>.*?)\]'

    parsed_data = []

    # Check if file exists before starting
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' was not found in the directory.")
        print(f"Current Directory: {os.getcwd()}")
        return

    print(f"Starting analysis on: {file_path}...")

    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = re.search(log_pattern, line)
                if match:
                    # Storing each hit in a list of dictionaries
                    parsed_data.append(match.groupdict())

        if not parsed_data:
            print("No data found. Please check if the log format matches the regex.")
            return

        # Using Pandas for efficient data manipulation
        df = pd.DataFrame(parsed_data)

        # Calculate frequency of each IP address
        ip_counts = df['ip'].value_counts().reset_index()
        ip_counts.columns = ['IP Address', 'Request Count']

        # Threshold: Show IPs with more than 5 requests
        suspicious_ips = ip_counts[ip_counts['Request Count'] > 5]

        print("\n" + "=" * 30)
        print("   THREAT ANALYSIS REPORT")
        print("=" * 30)

        if suspicious_ips.empty:
            print("No suspicious activity detected based on the current threshold.")
        else:
            print("Potential Scanners Detected:")
            print(suspicious_ips.to_string(index=False))
        print("=" * 30)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Specify the log file name here
    log_filename = 'TempIps.txt'
    run_investigation(log_filename)