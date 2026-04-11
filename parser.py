import xml.etree.ElementTree as ET

def parse_sysmon_log(file_path):
    print("Parsing started")

    tree = ET.parse(file_path)
    root = tree.getroot()

    events = []

    for event in root.findall(".//Event"):
        event_data = {}

        # Event ID
        event_id = event.find(".//EventID")
        if event_id is not None:
            event_data["event_id"] = event_id.text

        # Timestamp
        time = event.find(".//TimeCreated")
        if time is not None:
            event_data["timestamp"] = time.attrib.get("SystemTime")

        # Event Data
        for data in event.findall(".//Data"):
            name = data.attrib.get("Name")
            if name:
                event_data[name] = data.text

        events.append(event_data)

    print("Parsing done")
    return events
