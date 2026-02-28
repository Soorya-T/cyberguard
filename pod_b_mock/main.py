from fastapi import FastAPI

app = FastAPI()

@app.post("/analyze")
async def analyze(payload: dict):
    return {
        "risk_score": 85,
        "classification": "Phishing",
        "explanation": "Suspicious email pattern detected."
    }