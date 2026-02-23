# LOGINTEL-ANALYZER: AUTOMATED THREAT INTELLIGENCE SUITE

LogIntel-Analyzer is a professional Python-based security tool designed for **Operational Security (OpSec)** teams. It automates the end-to-end process of log parsing, behavioral analysis, and threat intelligence enrichment to identify potential security incidents.

---

## CORE CAPABILITIES

* **ADVANCED LOG PARSING:** Utilizes Regular Expressions with Named Groups to normalize unstructured data from multiple log sources into a structured format.
* **BEHAVIORAL HEURISTICS:** Identifies suspicious activity by analyzing HTTP Status Code distributions, specifically targeting **Directory Brute Force** and scanning patterns.
* **SENSITIVE ASSET MONITORING:** Flags interactions with critical files and directories such as `/.env`, `config.php`, and `/admin`, with specific focus on successful unauthorized access.
* **THREAT INTELLIGENCE INTEGRATION:** Fully integrated with the **VirusTotal API (v3)** to cross-reference suspicious indicators with over 70 global security vendors.
* **FORENSIC SOURCE ATTRIBUTION:** Tracks the source file for every event, enabling the detection of **Lateral Movement** and multi-vector attack patterns.
* **DATA VALIDATION:** Implements the `ipaddress` library to filter internal or malformed traffic, ensuring analysis remains focused on external threats.

---

## INVESTIGATION WORKFLOW

The analyzer follows a standard **Incident Response Pipeline**:

1.  **DATA INGESTION:** Scans specified directories and performs initial log parsing.
2.  **LOGIC VALIDATION:** Cleans data and ensures only valid Public IP addresses are processed.
3.  **TRIAGE & ANALYSIS:** Applies behavioral thresholds and sensitive path detection to identify high-confidence threats.
4.  **THREAT ENRICHMENT:** Performs automated reputation lookups for identified suspicious candidates.
5.  **REPORTING:** Generates a structured CLI dashboard for immediate triage and exports a detailed CSV report for long-term forensics.



---

## INSTALLATION AND USAGE

### PREREQUISITES
* Python 3.10+
* Pandas library
* Requests library

### EXECUTION
1.  Place log files into the `/logs` directory.
2.  Configure your VirusTotal API key in the `API_KEY` variable.
3.  Run the analyzer:

```bash
python opsec_final_analyzer.py
