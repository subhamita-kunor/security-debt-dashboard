## Security Debt Tracking System

Automated local security vulnerability and technical debt tracker for any codebase.

### Components

| File | Purpose |
|------|---------|
| `scanner.py` | Regex-based scanner — detects 30+ anti-patterns across 15+ file types |
| `app.py` | Streamlit interactive dashboard |
| `security_debt_log.json` | Append-only JSON findings database (auto-generated) |
| `run_pipeline.sh` | Linux/macOS orchestration script |
| `run_pipeline.ps1` | Windows PowerShell orchestration script |
| `sample_app/` | Demo source files with intentional vulnerabilities |

---

### Quick Start

#### Windows (PowerShell)
```powershell
# Install dependencies & run scanner
python -m pip install streamlit plotly pandas
python scanner.py .

# Launch dashboard
streamlit run app.py
```

#### Linux / macOS
```bash
chmod +x run_pipeline.sh
./run_pipeline.sh .
streamlit run app.py
```

---

### Detection Rules (30+ patterns)

| Category | Severity | Examples |
|----------|----------|---------|
| Hardcoded Secret | High | passwords, API keys, AWS keys, private keys, GitHub tokens |
| Injection | High | SQL via string concat, eval(), shell=True, exec() |
| Cryptography | High/Medium | MD5, SHA1, DES, SSL verify=False, ECB mode |
| Insecure Deserialization | High | pickle.loads(), yaml.load() without SafeLoader |
| Path Traversal | High/Medium | open() / os.path.join with user input |
| Security Misconfiguration | High/Medium | debug=True, CORS *, HTTP non-TLS, root user |
| Code Smell | Low | TODO/FIXME/HACK, bare except, print() logging |
| Deprecated API | Medium/Low | os.popen, imp module |

---

### Dashboard Features

- **Metric cards** — total / High / Medium / Low vulnerability counts  
- **Treemap** — visual hotspot map by directory → file → severity  
- **Horizontal bar chart** — defect category breakdown by severity  
- **Trend line** — severity over time (multi-scan)  
- **Filterable table** — search by text, filter by severity & category  
- **CSV export** — download filtered results  

---

### Re-scanning

Run `python scanner.py` at any time. Findings are **upserted by stable ID** — re-running the scanner on unchanged files will not create duplicate entries. New or changed findings are added/updated automatically.
