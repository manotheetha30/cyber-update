from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import your existing backend functions
from main import run_pipeline

app = FastAPI(title="Hunt Hypothesis Generation API")

# Allow React frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Request Models ----------

class URLRequest(BaseModel):
    url: str


class PipelineRequest(BaseModel):
    lookback_days: int
    sources: list[str]


# ---------- Endpoints ----------

@app.get("/")
def home():
    return {"message": "API is running"}


@app.post("/process-url")
def process_single_url(request: URLRequest):

    result = run_pipeline(url=request.url)

    return {
        "status": "success",
        "result": result
    }


@app.post("/run-pipeline")
def run_pipeline_endpoint(request: PipelineRequest):

    result = run_pipeline(
        lookback_days=request.lookback_days,
        sources=request.sources
    )

    return {
        "status": "success",
        "result": result
    }