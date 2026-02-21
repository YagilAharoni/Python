# **LogIntel-Analyzer: Automated Threat Intelligence Suite**

---

A professional Python-based toolset built for **Operational Security (OpSec)** teams. This suite automates the process of parsing, normalizing, and analyzing large volumes of security logs to identify potential threats and suspicious patterns.

### **Core Capabilities**
* **Log Aggregation:** Automatically scans directories for `.log` and `.txt` files.
* **Pattern Detection:** Uses **Regular Expressions (Regex)** to extract IPs and timestamps from unstructured data.
* **Data Analytics:** Leverages **Pandas** for frequency analysis and identifying anomalies (e.g., brute force attempts).
* **Structured Reporting:** Exports findings directly to **CSV** for rapid incident response and triage.

### **How to Use**
1.  Place log files into the `/logs` directory.
2.  Execute the analyzer:
    ```bash
    python LogIntel-Analyzer.py
    ```
3.  Review the generated report in `threat_report.csv`.

---
*Developed by Yagil Aharoni.*
