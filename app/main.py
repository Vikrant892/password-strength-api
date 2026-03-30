from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.models import (
    AnalyzeRequest, AnalyzeResponse,
    GenerateRequest, GenerateResponse,
    HealthResponse,
)
from app.analyzer import analyze_password
from app.breach_check import check_breach
from app.generator import generate_password

app = FastAPI(
    title="Password Strength Analyzer",
    description="Analyze password strength, check breaches, generate secure passwords",
    version="0.1.0",
)

# cors - wide open for now since it's a demo
# TODO: lock this down for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse()


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    result = analyze_password(req.password)

    # optionally check HIBP - off by default since it makes a network call
    if req.check_breach:
        breach_result = await check_breach(req.password)
        result.update(breach_result)

    return AnalyzeResponse(**result)


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest):
    password = generate_password(
        length=req.length,
        uppercase=req.uppercase,
        lowercase=req.lowercase,
        digits=req.digits,
        symbols=req.symbols,
        exclude_ambiguous=req.exclude_ambiguous,
    )

    # run the analyzer on the generated password so we can show the score
    analysis = analyze_password(password)

    return GenerateResponse(
        password=password,
        score=analysis["score"],
        entropy_bits=analysis["entropy_bits"],
    )


# serve the demo frontend
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Password Strength API - see /docs for API documentation"}
