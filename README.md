# VerdictLab

VerdictLab demonstrates how file-reputation signals can be turned into an explainable security verdict.

Current status: backend MVP implemented with synthetic data only.

## Backend Setup (FastAPI + Pytest)

1. Open a terminal in `backend`.
2. Create and activate a virtual environment.
3. Install dependencies from `requirements.txt`.
4. Run tests.
5. Start the API server.

### Windows PowerShell

```powershell
cd backend
./scripts/setup_venv.ps1
pytest
uvicorn app.main:app --reload
```

### Manual setup (all platforms)

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pytest
uvicorn app.main:app --reload
```

## API Endpoints

- `GET /health`
- `GET /api/v1/files/{sha256}`

## Important MVP Limits

- SHA-256 lookup only (no file uploads).
- All bundled results are synthetic fixtures.
- Zero detections do not prove a file is safe.
