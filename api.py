from fastapi import FastAPI
from bson import ObjectId
from database import ioc_collection
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/iocs")
def get_iocs():

    docs = list(ioc_collection.find())

    for doc in docs:
        doc["_id"] = str(doc["_id"])
    return docs