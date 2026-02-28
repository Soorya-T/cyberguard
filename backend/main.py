from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.analyze import router as analyze_router

app = FastAPI(
    title="CyberGuard Pod B - Threat Intelligence Engine",
    version="1.0.0",
    description="Pod B: Heuristic + ML powered phishing detection engine"
)

# CORS (safe default for internal microservices)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Pod B routes
app.include_router(analyze_router, prefix="", tags=["Threat Analysis"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "pod_b"}