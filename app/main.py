import sys
import os
from pathlib import Path

# ─── Critical: ensure the project ROOT is always the working directory ──────────
# This ensures all relative paths (app/static, app/templates, app/ml) resolve
# correctly no matter which directory the user runs `python app/main.py` from.
root_path = Path(__file__).resolve().parent.parent
os.chdir(root_path)
if str(root_path) not in sys.path:
    sys.path.insert(0, str(root_path))

# ─── Python Version Guard ───────────────────────────────────────────────────────
# ZeroPhish AI requires Python 3.12. Python 3.14 (pre-release) has known
# asyncio/uvicorn incompatibilities and must NOT be used.
#
# Strategy:
#   1. If the .venv exists and we are NOT inside it, silently re-launch with
#      the .venv Python 3.12 interpreter (handles `python app/main.py` case).
#   2. After re-launch, perform a hard version check to catch any edge case.

_venv_python = root_path / ".venv" / "Scripts" / "python.exe"

# Step 1 — Auto-redirect to venv if running under system Python
if _venv_python.exists():
    _running_venv = str(root_path / ".venv").lower() in sys.executable.lower()
    if not _running_venv:
        py_ver = sys.executable.replace("\\", "/").split("/")[-2]
        print(f"[ZeroPhish] System Python ({py_ver}) detected. Switching to .venv Python 3.12...")
        import subprocess
        result = subprocess.run([str(_venv_python)] + sys.argv, cwd=str(root_path))
        sys.exit(result.returncode)

# Step 2 — Hard version check (runs only when inside the venv or if .venv missing)
_major, _minor = sys.version_info.major, sys.version_info.minor
if not (_major == 3 and _minor == 12):
    print(f"[ZeroPhish] ERROR: This app requires Python 3.12.")
    print(f"[ZeroPhish] Currently running: Python {_major}.{_minor} ({sys.executable})")
    print(f"[ZeroPhish] Please activate the virtual environment: .venv\\Scripts\\activate")
    sys.exit(1)

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from app.core.database import create_db_and_tables
from app.core.middleware import RateLimitMiddleware
from app.core.config import settings
from app.api import auth as auth_router
from app.api import scans as scans_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

app.add_middleware(RateLimitMiddleware)

# Register API routers
app.include_router(auth_router.router)
app.include_router(scans_router.router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

print("--- ZeroPhish AI: App Initialized ---")

@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/dashboard")
def read_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"active_page": "dashboard"})

@app.get("/scan")
def read_scan(request: Request):
    return templates.TemplateResponse(request=request, name="scan.html", context={"active_page": "scan"})

@app.get("/url-scan")
def read_url_scan(request: Request):
    return templates.TemplateResponse(request=request, name="url_scan.html", context={"active_page": "url_scan"})

@app.get("/history")
def read_history(request: Request):
    return templates.TemplateResponse(request=request, name="history.html", context={"active_page": "history"})

@app.get("/threat-intelligence")
def read_threat_intelligence(request: Request):
    return templates.TemplateResponse(request=request, name="threat_intelligence.html", context={"active_page": "threat-intelligence"})

@app.get("/reports")
def read_reports(request: Request):
    return templates.TemplateResponse(request=request, name="reports.html", context={"active_page": "reports"})

@app.get("/settings")
def read_settings(request: Request):
    return templates.TemplateResponse(request=request, name="settings.html", context={"active_page": "settings"})

@app.get("/login")
def read_login(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.get("/register")
def read_register(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.get("/info/{page_id}")
def read_info(request: Request, page_id: str):
    # Mapping for dynamic content
    titles = {
        "about": "About ZeroPhish",
        "contact": "Contact Us",
        "careers": "Careers at ZeroPhish",
        "privacy": "Privacy Policy",
        "terms": "Terms of Service",
        "cookies": "Cookie Policy",
        "faq": "Frequently Asked Questions",
        "docs": "API Documentation"
    }
    title = titles.get(page_id, "Information")
    return templates.TemplateResponse(request=request, name="info.html", context={"page_id": page_id, "title": title})

if __name__ == "__main__":
    # ─── Windows multiprocessing guard ────────────────────────────────────────
    # On Windows, multiprocessing uses 'spawn' which re-imports this module.
    # We MUST use freeze_support() and pass the app as a STRING to uvicorn
    # so that worker processes import cleanly without recursive crashes.
    import multiprocessing
    multiprocessing.freeze_support()

    import uvicorn
    print("--- ZeroPhish AI: Starting Server on http://127.0.0.1:8000 ---")
    uvicorn.run(
        "app.main:app",      # string reference — workers import cleanly
        host="127.0.0.1",
        port=8000,
        log_level="info",
        workers=1,           # single worker avoids all multiprocessing on Windows
    )
