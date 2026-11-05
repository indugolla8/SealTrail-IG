from fastapi import FastAPI
from .database import Base, engine
from . import models
from .auth import router as auth_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SealTrail-IG")
app.include_router(auth_router)

@app.get("/health")
def health():
    return {"status": "ok"}