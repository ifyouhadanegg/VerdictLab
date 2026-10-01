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

## VirusTotal Lookups

Bundled synthetic examples continue to use local fixtures. Other valid SHA-256 hashes are looked up against VirusTotal's existing file reports; VerdictLab does not upload files. The VirusTotal API key stays on the backend.

On Windows, set your key in the backend PowerShell terminal and start the API:

```powershell
$env:VIRUSTOTAL_API_KEY = "your-virustotal-api-key"
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

If the backend is already running, stop it with `Ctrl+C` before setting the variable and restarting it. Without a key, synthetic lookups still work; other hashes return a configuration error. A hash is sent to VirusTotal when queried, so only check hashes you are authorized to share and follow VirusTotal's terms and rate limits.

## Important MVP Limits

- SHA-256 lookup only (no file uploads).
- All bundled results are synthetic fixtures.
- Zero detections do not prove a file is safe.
