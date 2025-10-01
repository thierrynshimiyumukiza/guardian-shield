import re
import json

input_path = "../datasets/WEB_APPLICATION_PAYLOADS.jsonl"
output_path = "../datasets/WEB_APPLICATION_PAYLOADS_FIXED.json"

with open(input_path, "r", encoding="utf-8") as f:
    text = f.read()

# Extract all JSON objects using regex, even if array is broken
objects = re.findall(r'\{.*?\}', text, flags=re.DOTALL)
print(f"Found {len(objects)} potential objects")

cleaned = []
for i, obj_str in enumerate(objects):
    try:
        obj = json.loads(obj_str)
        cleaned.append(obj)
    except Exception as e:
        print(f"Invalid JSON object at index {i}: {e}")

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(cleaned, f, indent=2)

print(f"Wrote {len(cleaned)} valid objects to {output_path}")
