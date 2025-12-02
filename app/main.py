from fastapi import FastAPI

app = FastAPI(
    title="QWitty P1 – PQC JWT Sign & Verify",
    version="0.1.0",
)


@app.get("/health")
def health():
    return {"status": "ok", "component": "P1"}
