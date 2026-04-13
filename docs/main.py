from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import audit

app = FastAPI(title="Public Repo Security Audit")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for testing
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    owner: str
    repo: str
    branch: str = "main"
    path: str = "/docs"

@app.get("/")
async def root():
    return {
        "message": "Public repo security audit API",
        "warning": "This tool is for public repositories only. Private repository scanning should be discussed separately with platform admins."
    }

@app.post("/audit")
async def audit(req: AuditRequest):
    repo_url = f"https://github.com/{req.owner}/{req.repo}.git"
    
    with TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir) / "repo"
        cmd = ["git", "clone", "--depth", "1", "--branch", req.branch, repo_url, str(repo_root)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Clone failed: {result.stderr.strip()}")
        
        target, files = audit.scan_repo(repo_root, req.path)
        if target is None:
            raise HTTPException(status_code=404, detail=f"Path not found: {req.path}")
        
        counts = {
            "red": sum(1 for f in files if f["status"] == "red"),
            "green": sum(1 for f in files if f["status"] == "green"),
            "grey": 0
        }
        
        return {
            "warning": "This tool is for public repositories only. Private repository scanning should be discussed separately with platform admins.",
            "repo": f"{req.owner}/{req.repo}",
            "branch": req.branch,
            "path": req.path,
            "counts": counts,
            "files": files
        }
