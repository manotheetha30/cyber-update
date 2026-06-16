import pickle

with open("attack_embeddings.pkl", "rb") as f:
    db = pickle.load(f)

print(db.keys())
print(len(db["techniques"]))
print(db["techniques"][0])
print(db["embeddings"].shape)