#!/usr/bin/env bash
# =============================================================================
#  run_pipeline.sh — Security Debt Tracking Pipeline
#  Usage:   ./run_pipeline.sh [scan_root]
#  Default scan root is the current working directory.
# =============================================================================
set -euo pipefail

SCAN_ROOT="${1:-.}"
SCANNER="scanner.py"
DASHBOARD="app.py"
DB_FILE="security_debt_log.json"

echo "============================================================"
echo "  🛡️  Security Vulnerability & Technical Debt Pipeline"
echo "============================================================"

# ── Step 1: Validate Python ───────────────────────────────────────────────────
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
  echo "[ERROR] Python not found. Install Python 3.9+." >&2
  exit 1
fi
PYTHON=$(command -v python3 2>/dev/null || command -v python)
echo "[1/3] Using interpreter: $($PYTHON --version)"

# ── Step 2: Install dashboard dependencies (idempotent) ───────────────────────
echo "[2/3] Ensuring dependencies are installed..."
$PYTHON -m pip install --quiet --upgrade streamlit plotly pandas 2>&1 | tail -3

# ── Step 3: Run scanner ───────────────────────────────────────────────────────
echo "[3/3] Running scanner on: $SCAN_ROOT"
$PYTHON "$SCANNER" "$SCAN_ROOT"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  ✅  Pipeline complete."
if [[ -f "$DB_FILE" ]]; then
  RECORD_COUNT=$(python3 -c "import json; d=json.load(open('$DB_FILE')); print(len(d))" 2>/dev/null || echo "?")
  echo "  📄  $DB_FILE contains $RECORD_COUNT records."
fi
echo ""
echo "  ▶  Launch dashboard:"
echo "       streamlit run $DASHBOARD"
echo "============================================================"
