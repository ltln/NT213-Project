import json

INPUT_FILE = "waf-bypass.json"
OUTPUT_FILE = "waf-bypass-input.json"

def transform_schema(input_data):
    return {
        "payloads": [
            {
                "id": item.get("id"),
                "payload": item.get("payload"),
                "endpoints": [item.get("endpoint")] if item.get("endpoint") else [],
                "notes": item.get("signal_type")
            }
            for item in input_data
        ]
    }

def main():
    # Read input file
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        input_data = json.load(f)

    # Transform data
    output_data = transform_schema(input_data)

    # Write output file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4)

    print(f"Transformed data written to {OUTPUT_FILE}. Total payloads: {len(output_data['payloads'])}")

if __name__ == "__main__":
    main()
