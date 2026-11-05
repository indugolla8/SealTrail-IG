from fastapi import FastAPI

app = FastAPI(title="SealTrail-IG")

@app.get("/health")
def health():
    return {"status": "ok"}