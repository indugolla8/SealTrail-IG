import os

from fastapi import FastAPI
from fastapi.responses import FileResponse
from .database import Base, engine
from . import models
from .auth import router as auth_router
from .admin import router as admin_router
from .documents import router as documents_router
from .sharing import router as sharing_router
from .lifecycle import router as lifecycle_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SealTrail-IG")
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(documents_router)
app.include_router(sharing_router)
app.include_router(lifecycle_router)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/health")
def health():
    return {"status": "ok"}