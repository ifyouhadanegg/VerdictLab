param(
    [string]$VenvDir = ".venv"
)

python -m venv $VenvDir

$activatePath = Join-Path $VenvDir "Scripts\Activate.ps1"
& $activatePath

python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "Backend virtual environment is ready."
