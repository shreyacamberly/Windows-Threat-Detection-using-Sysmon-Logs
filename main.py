from parser import parse_sysmon_log
from rules import (
    detect_suspicious_powershell,
    detect_registry_persistence,
    detect_suspicious_file
)
import json

def main():
    print("Program started")

    logs = parse_sysmon_log("sample_logs.xml")

    print("\nRunning Detection...\n")

    alerts = []

    for event in logs:
        for rule in [
            detect_suspicious_powershell,
            detect_registry_persistence,
            detect_suspicious_file
        ]:
            result = rule(event)
            if result:
                alert_data = {
                    "type": result["alert"],
                    "severity": result["severity"],
                    "timestamp": event.get("timestamp"),
                    "mitre_technique": result["mitre_technique"],   # ADD
                    "description": result["description"],
                    "event": event
                }

                alerts.append(alert_data)

                print("[ALERT]")
                print("Type:", alert_data["type"])
                print("Severity:", alert_data["severity"])
                print("MITRE:", alert_data["mitre_technique"])     # ADD
                print("Description:", alert_data["description"])
                print("Time:", alert_data["timestamp"])
                print("-" * 40)

    # 🔥 SAVE TO FILE
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"\nTotal Alerts: {len(alerts)}")
    print("Alerts saved to alerts.json")


if __name__ == "__main__":
    main()

