# **Windows-Threat-Detection-using-Sysmon-Logs
**
A Python-based threat detection system that analyzes Windows Event Logs  (Sysmon) to identify suspicious activities such as persistence,  privilege escalation, and malware behaviour.

**Features**
- Parse Windows Event Logs (XML)
- Detect suspicious Event IDs
- Rule-based threat detection
- Generate structured alerts (JSON)

**Tech Stack**
- Python
- Sysmon Logs
- XML Parsing

**How to Run**
python src/main.py

**Sample Output**
{
  "event_id": 1,
  "alert": "Suspicious process creation"
}

**Future Improvements**
- Integrate with SIEM tools
- Add ML-based anomaly detection
- Real-time log monitoring
