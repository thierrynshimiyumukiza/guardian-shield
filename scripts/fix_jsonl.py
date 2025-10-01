import os
import json
import re

script_dir = os.path.dirname(os.path.abspath(__file__))
input_path = os.path.join(script_dir, "../datasets/WEB_APPLICATION_PAYLOADS.jsonl")
output_path = os.path.join(script_dir, "../datasets/WEB_APPLICATION_PAYLOADS_clean.jsonl")

with open(input_path, "r", encoding="utf-8") as infile, open(output_path, "w", encoding="utf-8") as outfile:
    for i, line in enumerate(infile):
        line = line.strip()
        matches = re.findall(r'\{.*?\}(?=,|\]|\[|$)', line)
        if not matches:
            matches = [line]
        for match in matches:
            try:
                obj = json.loads(match)
                json.dump(obj, outfile)
                outfile.write("\n")
            except Exception as e:
                # print(f"Line {i+1}: {e}")
                continue
print("Done! Cleaned lines written to", output_path)