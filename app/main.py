from backend.app.main import app, lifespan, ensure_schema, SessionLocal, engine

__all__ = ["app", "lifespan", "ensure_schema", "SessionLocal", "engine"]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8001, reload=True)
