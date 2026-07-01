from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")

db = client["hunt_generation_dashboard"]

print(db.list_collection_names())

""" record retention- until delete by user/ maybe once in a week..whichever is best"""