# Run Scanner → Update JSON → (optionally) Launch Dashboard
# PowerShell equivalent of run_pipeline.sh for Windows environments

param(
    [string]$ScanRoot = "."
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shield  Security Vulnerability & Technical Debt Pipeline" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 1 — verify Python
$python = $null
foreach ($cmd in @("python", "python3")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) { $python = $cmd; break }
}
if (-not $python) {
    Write-Error "[ERROR] Python not found. Install Python 3.9+."
    exit 1
}
Write-Host "[1/3] Using: $(& $python --version)" -ForegroundColor Green

# Step 2 — install dependencies
Write-Host "[2/3] Ensuring dependencies are installed..." -ForegroundColor Green
& $python -m pip install --quiet --upgrade streamlit plotly pandas | Select-Object -Last 3

# Step 3 — run scanner
Write-Host "[3/3] Running scanner on: $ScanRoot" -ForegroundColor Green
& $python scanner.py $ScanRoot

# Summary
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DONE. Pipeline complete." -ForegroundColor Green
if (Test-Path "security_debt_log.json") {
    $count = (& $python -c "import json; d=json.load(open('security_debt_log.json')); print(len(d))")
    Write-Host "  security_debt_log.json contains $count records." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Launch dashboard with:" -ForegroundColor White
Write-Host "       streamlit run app.py" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
