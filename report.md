# 🛡️ Windows Threat Detection Report (Sysmon Logs)

## 📌 Summary
This project analyzes Sysmon logs to detect suspicious activities such as malicious PowerShell execution, registry persistence, and suspicious file creation.

The detection engine uses rule-based logic to identify potential threats and maps them to MITRE ATT&CK techniques.

---

## 📂 Logs Analyzed
- Source: Sysmon logs (XML format)
- Total Events: 3

---

## 🚨 Detected Threats

### 1. Suspicious PowerShell Execution
- Severity: HIGH
- MITRE Technique: T1059 (Command and Scripting Interpreter)
- Description: Encoded PowerShell command detected

---

### 2. Registry Persistence Mechanism
- Severity: HIGH
- MITRE Technique: T1547 (Boot or Logon Autostart Execution)
- Description: Suspicious Run key added in registry

---

### 3. Suspicious File Creation
- Severity: MEDIUM
- MITRE Technique: T1105 (Ingress Tool Transfer)
- Description: Executable dropped in temp directory

---

## 🔍 Indicators of Compromise (IOCs)
- Encoded PowerShell command usage
- Registry modification in Run keys
- Suspicious executable in temp folder

---

## 🛡️ Mitigation Recommendations
- Disable or restrict PowerShell encoded commands
- Monitor registry changes for persistence
- Block execution from temp directories
- Implement endpoint detection and response (EDR)

---

## 🧠 Conclusion
This project demonstrates how Sysmon logs can be used to detect real-world attack techniques using structured rule-based detection aligned with MITRE ATT&CK.

It simulates a basic SOC detection workflow.
