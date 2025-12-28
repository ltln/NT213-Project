import json
import uuid

objects = []

# Read input from file.txt
with open("a.txt", "r", encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        obj = {
            "id": str(uuid.uuid4()),
            "payload": line,
            "endpoints": ["stored"],
            "notes": ""
        }

        objects.append(obj)

# Build output structure
output = {
    "payloads": objects
}

# Write to payloads.json
with open("payloads-2-stored.json", "w") as f:
    json.dump(output, f, indent=4)

print("payloads.json has been created successfully.")
