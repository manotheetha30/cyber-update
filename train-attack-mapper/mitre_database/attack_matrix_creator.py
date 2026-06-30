import pandas as pd
import json

# Read Excel
df = pd.read_excel("./mitre_database/attack_dataset.xlsx")

result = {}

for _, row in df.iterrows():
    tactic = row["Tactic_Name"]          # column name
    techid = row["Technique_ID"]    # column name
    techname = row["Technique_Name"]# column name
    tech_ids_seen={}
    if tactic not in result:
        result[tactic] = {}
    parent_id=techid.split(".")[0]
    if parent_id not in result[tactic]:
        result[tactic][parent_id]={
        "tech_id": parent_id,
        "tech_name": techname if "." not in techid else "",
        "subtechniques": []
    }
    if "." not in techid:
        result[tactic][parent_id]["tech_name"] = techname
    else:
        result[tactic][parent_id]["subtechniques"].append({
            "tech_id": techid,
            "tech_name": techname
        })


# Save JSON
with open("attack-matrix.json", "w") as f:
    json.dump(result, f, indent=4)

print("JSON created!")