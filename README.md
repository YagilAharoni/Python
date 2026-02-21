# **LogIntel-Analyzer: Automated Threat Intelligence Suite**

---

A professional Python-based toolset built for **Operational Security (OpSec)** teams. This suite automates the process of parsing, normalizing, and analyzing large volumes of security logs to identify potential threats and suspicious patterns.

### **Core Capabilities**
* **Log Aggregation:** Automatically scans directories for `.log` and `.txt` files using the `os` library.
* **Pattern Detection:** Uses **Regular Expressions (Regex)** to extract IPs and timestamps from unstructured data.
* **Data Analytics:** Leverages **Pandas** for frequency analysis and identifying anomalies.
* **Advanced Enrichment (Dev Branch):** Integrated with the **VirusTotal API** to automatically cross-reference suspicious IPs with global threat intelligence databases.
* **Structured Reporting:** Exports findings directly to **CSV** for rapid incident response and triage.

### **Branching Strategy**
* **`main`**: Stable version with core parsing and analysis features.
* **`dev`**: Development branch featuring external API integrations and advanced enrichment logic.

### **Tech Stack**
* **Language:** Python 3.x
* **Key Libraries:** `Pandas`, `requests` (API calls), `re` (Regex), `os`

### **How to Use**
1.  Place log files into the `/logs` directory.
2.  Add your VirusTotal API key in the configuration section.
3.  Execute the analyzer:
    ```bash
    python opsec_final_analyzer.py
    ```
4.  Review the generated report in `final_threat_report.csv`.

---
*Developed by Yagil Aharoni.*
