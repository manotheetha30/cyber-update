from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017")
db = client["hunt_generation_dashboard"]
report_collection = db["hunt_reports"]
ioc_collection=db["iocs"]