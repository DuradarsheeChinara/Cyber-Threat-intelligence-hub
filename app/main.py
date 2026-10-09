from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routers import auth, dashboard, scans, threats

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Cyber Threat Intelligence Hub API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(threats.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")

@app.get("/")
def root():
    return {"message": "CTI Hub backend running", "docs": "/docs", "api": "/api/v1"}
