def detect_suspicious_powershell(event):
    if event.get("event_id") == "1":
        image = event.get("Image", "").lower()
        cmd = event.get("CommandLine", "").lower()

        if "powershell.exe" in image and "encodedcommand" in cmd:
            return {
                "alert": "Suspicious PowerShell Execution",
                "severity": "HIGH",
                "mitre_technique": "T1059",  # Command & Scripting Interpreter
                "description": "Encoded PowerShell command execution"
            }


def detect_registry_persistence(event):
    if event.get("event_id") == "13":
        target = event.get("TargetObject", "").lower()

        if "run" in target or "runonce" in target:
            return {
                "alert": "Registry Persistence Detected",
                "severity": "HIGH",
                "mitre_technique": "T1547",  # Boot or Logon Autostart Execution
                "description": "Registry Run key persistence mechanism"
            }


def detect_suspicious_file(event):
    if event.get("event_id") == "11":
        filename = event.get("TargetFilename", "").lower()

        if "temp" in filename:
            return {
                "alert": "Suspicious File Created in Temp",
                "severity": "MEDIUM",
                "mitre_technique": "T1105",  # Ingress Tool Transfer
                "description": "Suspicious executable dropped in temp directory"
            }
