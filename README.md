LogIntel-Analyzer: Automated Threat Intelligence Suite
A professional Python-based toolset built for Operational Security (OpSec) teams. This suite automates the process of parsing, normalizing, and analyzing security logs to identify potential threats using behavioral analysis and external threat intelligence.

Core Capabilities
Behavioral Analysis: Beyond simple counting, the tool analyzes HTTP Status Codes to detect Directory Brute Force attacks.

Sensitive Path Monitoring: Monitors access to critical assets and flags unauthorized successful access.

Log Forensics & Attribution: Tracks the Source File for every suspicious IP, enabling analysts to identify Lateral Movement across different servers.

Automated Enrichment: Integrated with VirusTotal API (v3) to cross-reference public IPs with 70+ global threat engines.

Data Validation: Uses the ipaddress library to filter out internal/private traffic, ensuring the analysis focuses strictly on external threats.

Professional Dashboard: Features a formatted CLI Dashboard for immediate triage directly from the terminal.

How the Investigation Logic Works
The suite follows a Multi-Stage Triage process:

Parsing: Extracting structured data (IP, Path, Status) from raw text logs.

Validation: Filtering out non-public IPs and malformed data.

Heuristics: Identifying suspicious behavior based on request volume (Thresholds) or access to sensitive files.

Enrichment: Querying Threat Intel only for high-confidence suspicious candidates.

Reporting: Generating a localized summary and a detailed CSV for deeper investigation.

How to Use
Place log files into the /logs directory.

Add your VirusTotal API key in the API_KEY variable.

Execute the analyzer:

Bash
python opsec_final_analyzer.py
Review the CLI Summary on your screen or the detailed report in final_opsec_report.csv.

Developed by Yagil Aharoni.
