import json
import pickle
import numpy as np
import requests

STIX_FILE = "attack_stix.json"

def get_embedding(text: str):

    r = requests.post(
    "http://localhost:11434/api/embed",
    json={
        "model": "nomic-embed-text",
        "input": text
    }
)

    r.raise_for_status()

    emb = np.array(
        r.json()["embeddings"],
        dtype=np.float32,
    )

    emb /= np.linalg.norm(emb)

    return emb


with open(STIX_FILE, encoding="utf-8") as f:
    stix = json.load(f)

techniques = []
embeddings = []

for obj in stix["objects"]:

    if obj.get("type") != "attack-pattern":
        continue

    attack_id = None

    for ref in obj.get(
        "external_references",
        []
    ):
        if ref.get("source_name") == "mitre-attack":
            attack_id = ref.get("external_id")
            break

    if not attack_id:
        continue

    text = f"""
Technique: {obj.get('name','')}

Description:
{obj.get('description','')}
"""

    emb = get_embedding(text)

    techniques.append({
        "attack_id": attack_id,
        "name": obj.get("name", ""),
        "description": obj.get(
            "description",
            ""
        ),
    })

    embeddings.append(emb)

    print(
        attack_id,
        obj.get("name", "")
    )

with open(
    "attack_embeddings.pkl",
    "wb"
) as f:

    pickle.dump(
        {
            "techniques": techniques,
            "embeddings": np.array(
                embeddings,
                dtype=np.float32
            ),
        },
        f,
    )

print(
    f"Saved {len(techniques)} techniques"
)