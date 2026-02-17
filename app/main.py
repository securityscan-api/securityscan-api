from fastapi import FastAPI
from app.db.database import engine, Base
from app.api.auth import router as auth_router
from app.api.scan import router as scan_router

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SkillShield API",
    description="Security scanning API for OpenClaw skills and PentAGI configurations",
    version="1.0.0"
)


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/")
def root():
    return {
        "service": "SkillShield API",
        "version": "1.0.0",
        "docs": "/docs"
    }


# Include routers
app.include_router(auth_router)
app.include_router(scan_router)
