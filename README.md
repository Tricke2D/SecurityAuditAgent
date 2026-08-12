# 🤖 Autonomous Security Audit Agent

**Static Analysis + Taint Tracking + LLM Verification — Fully Local**

**Status:** Complete — End-to-end security audit pipeline untuk mendeteksi kerentanan kode secara otomatis, tanpa mengirim kode ke cloud.

---

## 📌 TL;DR

| Aspek | Deskripsi |
|-------|-----------|
| **Apa** | Autonomous Security Audit Agent adalah sistem yang secara otomatis memindai kode sumber, melacak aliran data berbahaya, dan memverifikasi temuan menggunakan AI lokal. |
| **Untuk Siapa** | Developer, Security Engineer, dan tim yang ingin melakukan security review kode secara otomatis dan auditable. |
| **Masalah Apa** | Security review manual lambat, mahal, dan tidak scalable. Static scanner tradisional menghasilkan banyak false positive. |
| **Bagaimana Solusi Bekerja** | Gabungkan static pattern matching, taint analysis (pelacakan aliran data lintas file), dan LLM verification untuk menghasilkan laporan yang akurat dan dapat diaudit. |
| **Output Utama** | Laporan kerentanan dengan severity scoring, reasoning trace lengkap, dan remediation suggestion. |

---

## 🎯 Problem

### Current Problem

Tim engineering sering kesulitan mengidentifikasi kerentanan keamanan di kode karena:

- **Codebase besar** — ribuan file, sulit di-review manual
- **False positive** — static scanner tradisional terlalu banyak alarm palsu
- **Aliran data lintas file** — kerentanan sering tersembunyi di balik 3-4 file yang saling memanggil
- **Biaya** — security review oleh ahli mahal dan lambat

### Impact

- Kerentanan lolos ke production
- Waktu developer terbuang untuk memverifikasi false positive
- Security debt menumpuk

### Why Manual Process Is Difficult

Manusia sulit melacak aliran data dari input user (source) ke fungsi berbahaya (sink) yang melewati banyak file. Sistem ini melakukannya secara otomatis.

---

## 💡 Solution

### Simple Flow

```
📁 Upload Codebase
    ↓
🔍 Static Analysis (Fase 1)
    ↓
🔗 Taint Analysis (Fase 2)
    ↓
🤖 LLM Verification (Fase 3)
    ↓
📊 Final Report
```

### What Makes This Different

| Aspek | Traditional Scanner | Autonomous Security Audit Agent |
|-------|-------------------|----------------------------------|
| Pendekatan | Hanya pattern matching | Pattern matching + taint tracking + LLM verification |
| False Positive | Banyak | False positive difilter oleh taint analysis + LLM |
| Lintas File | Tidak bisa | Melacak aliran data lintas 3+ file |
| Transparansi | Black box | Reasoning trace lengkap, auditable |
| Keamanan Data | Kirim kode ke cloud | Fully local (Ollama + PostgreSQL) |

---

## 🔧 How It Works

### Simple View 

Bayangkan sistem ini seperti detektif keamanan yang:

1. **Membaca seluruh kode** — memindai setiap file
2. **Mencari pola berbahaya** — seperti eval(), execute(), password hardcoded
3. **Melacak asal-usul data** — dari input user sampai ke fungsi berbahaya
4. **Memverifikasi dengan AI** — menanyakan ke AI lokal apakah temuan benar-benar berbahaya
5. **Memberi laporan** — dengan penjelasan lengkap dan saran perbaikan

### Technical View 

Sistem terdiri dari 3 fase utama:

#### 🟢 Fase 1 — Static Analysis (Go)

- Parse source code menjadi AST menggunakan tree-sitter
- Jalankan 4 pattern matcher:
  - **SQL Injection** (string concatenation ke query)
  - **Hardcoded Secret** (password, API key, token)
  - **Dangerous Eval** (eval, exec, Function constructor)
  - **Insecure Deserialization** (pickle.load, yaml.load tanpa SafeLoader)
- Simpan temuan ke PostgreSQL

#### 🟡 Fase 2 — Call Graph & Taint Analysis (Go)

- Bangun call graph (siapa memanggil siapa) lintas file
- Identifikasi source (input user, request.GET, input())
- Identifikasi sink (cursor.execute, eval, os.system)
- Jalankan worklist algorithm untuk melacak aliran data dari source ke sink
- Deteksi sanitization (parameterized query, escape function)
- Simpan taint flow ke PostgreSQL

#### 🔵 Fase 3 — LLM Verification (Python)

- Ambil taint flow yang belum disanitasi
- Bangun context minimal (hanya file-file relevan)
- Kirim ke Ollama (qwen2.5-coder:7b) untuk verifikasi
- Simpan hasil reasoning trace lengkap
- Generate final report dengan severity scoring

---

## ✨ Key Features

### User-Facing Features

| Feature | Description |
|---------|-------------|
| 🔍 **Automatic Code Scan** | Scan entire codebase dengan satu perintah |
| 📊 **Vulnerability Report** | Laporan dengan severity, reasoning trace, dan remediation |
| 🤖 **AI Verification** | LLM lokal memverifikasi setiap temuan |
| 📝 **Auditable Trace** | Setiap keputusan memiliki reasoning trace lengkap |
| 🔒 **Fully Local** | Tidak ada kode yang dikirim ke cloud |

### Technical Capabilities

| Capability | Implementation |
|-----------|-----------------|
| Multi-language AST Parsing | tree-sitter (Python, JavaScript) |
| Cross-file Taint Tracking | Worklist algorithm + call graph |
| Source-Sink Detection | Pattern-based + configurable |
| Sanitization Detection | Parameterized query + escape function detection |
| LLM Verification | Ollama + qwen2.5-coder (structured JSON output) |
| Context Reduction | Hanya file relevan yang dikirim ke LLM |
| Severity Scoring | Gabungan static severity + LLM confidence + CVE reference |

---

## 📊 Example Output

### Vulnerability Report

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                          Vulnerability Report                                        │
├──────────────┬───────────────────────────┬──────────────────┬────────────┬───────────┤
│ Severity     │ File:Line                 │ Pattern          │ Exploitable│ Confidence│
├──────────────┼───────────────────────────┼──────────────────┼────────────┼───────────┤
│ HIGH         │ vulnerable_query.py:9     │ sql_injection    │ ✅ Yes     │ 100.0%    │    
│ HIGH         │ taint_flow_demo.py:11     │ sql_injection    │ ✅ Yes     │ 100.0%    │
└──────────────┴───────────────────────────┴──────────────────┴────────────┴───────────┘
```

### Reasoning Trace

> "The code directly concatenates user input (user_id) into an SQL query without any sanitization or parameterized queries, which makes it vulnerable to SQL injection attacks. An attacker could manipulate the id parameter in the request to execute arbitrary SQL commands."

---

## 🏗️ Architecture

### Simple Architecture Explanation

1. User menjalankan command scan → Go service memproses semua file
2. Hasil static analysis disimpan ke PostgreSQL
3. Taint analysis melacak aliran data lintas file menggunakan call graph
4. Python orchestrator mengambil taint flow yang belum aman
5. Ollama (LLM lokal) memverifikasi temuan
6. Report di-generate dan ditampilkan di terminal

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Autonomous Security Audit Agent                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      ast-engine (Go)                                │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐     │    │
│  │  │  Parser   │  │  Pattern  │  │  Call     │  │  Taint        │     │    │
│  │  │ (tree-    │  │  Matcher  │  │  Graph    │  │  Propagator   │     │    │
│  │  │  sitter)  │  │           │  │  Builder  │  │               │     │    │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────────┘     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         PostgreSQL                                  │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ codebase_files │ static_findings │ functions │ call_edges   │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ taint_flows │ llm_verifications │ vulnerability_report      │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                   orchestrator (Python)                             │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐     │    │
│  │  │  Ollama   │  │  Prompt   │  │  CVE      │  │  Report       │     │    │
│  │  │  Client   │  │  Template │  │  Matcher  │  │  Generator    │     │    │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────────┘     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Ollama                                      │    │
│  │                    (qwen2.5-coder:7b)                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
security-audit-agent/
├── services/
│   ├── ast-engine/                    # Go service 
│   │   ├── cmd/
│   │   │   └── scanner/
│   │   │       └── main.go            # CLI entry point
│   │   ├── internal/
│   │   │   ├── parser/                # tree-sitter wrapper
│   │   │   ├── patterns/              # 4 pattern matchers
│   │   │   ├── callgraph/             # Call graph builder
│   │   │   ├── taint/                 # Taint propagation engine
│   │   │   ├── scanner/               # Scan orchestrator
│   │   │   └── storage/               # PostgreSQL repository
│   │   └── db/
│   │       ├── migrations/            # SQL migrations
│   │       └── queries/               # sqlc queries
│   │
│   └── orchestrator/                  # Python service 
│       ├── src/
│       │   └── orchestrator/
│       │       ├── config.py          # Configuration
│       │       ├── db/                # Database connection
│       │       ├── llm/               # Ollama client + prompts
│       │       ├── cve/               # CVE reference
│       │       ├── scoring/           # Severity calculation
│       │       └── report/            # Report generator
│       └── tests/
│
├── testdata/                          # Sample vulnerable code
│   ├── python/
│   └── javascript/
│
└── docs/
    └── architecture/
```

---

## 🛠️ Tech Stack

| Technology | Role | Why It Is Used |
|-----------|------|-----------------|
| Go 1.22+ | AST parsing & analysis engine | Performa tinggi, concurrent processing |
| Python 3.11+ | LLM orchestration layer | Ekosistem AI/LLM yang matang |
| tree-sitter | AST parsing | Multi-bahasa, incremental parsing |
| PostgreSQL 15+ | Database | Menyimpan findings, taint flows, verifications |
| Ollama | Local LLM runtime | Menjalankan model AI secara lokal tanpa cloud |
| qwen2.5-coder:7b | LLM Model | Code-specialized, reasoning kuat |
| gonum | Graph library | Build directed graph untuk call graph |
| psycopg | Python PostgreSQL driver | Koneksi database yang aman dan cepat |
| Jinja2 | Template engine | Prompt template yang terpisah dari kode |
| Pydantic | Data validation | Validasi structured output dari LLM |
| Rich | CLI output | Tabel dan formatting yang readable |
| Docker | Containerization | Easy setup PostgreSQL + services |

---

## 📋 Requirements

### Required

| Requirement | Version |
|-----------|---------|
| Go | 1.22+ |
| Python | 3.11+ |
| PostgreSQL | 15+ |
| Docker | 24+ |
| Ollama | Latest |
| Git | Latest |

### Recommended

| Requirement | Spec |
|-----------|------|
| RAM | 16GB+ (8GB minimal) |
| Disk Space | 10GB+ (untuk model Ollama) |
| GPU | NVIDIA GPU (opsional, untuk LLM acceleration) |
| OS | Linux, macOS, atau Windows (dengan Docker) |

---

## 🚀 Quick Start

### Option A — Quick Start (Docker)

```bash
# 1. Clone repository
git clone https://github.com/your-org/security-audit-agent.git
cd security-audit-agent

# 2. Start PostgreSQL with Docker
docker-compose up -d

# 3. Run database migrations
cd services/ast-engine
migrate -database "postgres://postgres:postgres@localhost:5432/security_audit?sslmode=disable" -path db/migrations up

# 4. Pull Ollama model
ollama pull qwen2.5-coder:7b

# 5. Scan codebase
go run ./cmd/scanner scan --path ../../testdata

# 6. Run taint analysis
go run ./cmd/scanner taint --path ../../testdata

# 7. LLM verification (Python)
cd ../orchestrator
uv sync
$env:DATABASE_URL="postgres://postgres:postgres@localhost:5432/security_audit?sslmode=disable"
uv run python -m orchestrator.cli

# 8. Generate report
uv run python -c "from orchestrator.config import load_config; from orchestrator.db.connection import Database; from orchestrator.report.generator import ReportGenerator; config = load_config(); db = Database(config); ReportGenerator(db).generate()"
```

### Option B — Manual Setup

#### 1. Setup PostgreSQL

```bash
# Start PostgreSQL via Docker
docker-compose up -d

# Or install locally
sudo apt-get install postgresql-15
sudo -u postgres psql -c "CREATE DATABASE security_audit;"
sudo -u postgres psql -c "CREATE USER postgres WITH PASSWORD 'postgres';"
```

#### 2. Setup Go Service (ast-engine)

```bash
cd services/ast-engine

# Install dependencies
go mod tidy

# Run migrations
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
migrate -database "postgres://postgres:postgres@localhost:5432/security_audit?sslmode=disable" -path db/migrations up

# Build
go build ./...
```

#### 3. Setup Python Service (orchestrator)

```bash
cd services/orchestrator

# Install uv
pip install uv

# Install dependencies
uv sync

# Set environment
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/security_audit?sslmode=disable"
export OLLAMA_HOST="http://localhost:11434"
```

#### 4. Setup Ollama

```bash
# Install Ollama
# Download from https://ollama.com/download

# Pull model
ollama pull qwen2.5-coder:7b

# Start Ollama
ollama serve
```

---

## 📖 Usage

### 1. Scan Codebase (Fase 1)

```bash
cd services/ast-engine
go run ./cmd/scanner scan --path /path/to/your/codebase
```

**What happens:**

- Parses all files in the codebase
- Runs 4 static pattern matchers
- Saves findings to PostgreSQL

**Output:**

```
Scan selesai: 156 file diproses, 23 finding ditemukan (raw, belum difilter).
```

### 2. Taint Analysis (Fase 2)

```bash
go run ./cmd/scanner taint --path /path/to/your/codebase
```

**What happens:**

- Builds call graph of all functions
- Identifies sources (input user, request.GET, etc.)
- Identifies sinks (cursor.execute, eval, etc.)
- Traces data flow from source to sink
- Detects sanitization (parameterized queries, etc.)

**Output:**

```
✅ Found taint flow!
  Source: handlers/user.py:12 (user_id)
  Sink: db/query.py:45
  Path length: 4 steps
    → handlers/user.py:12 [source]
    → services/lookup.py:23 [assignment]
    → db/query.py:38 [parameter_pass]
    → db/query.py:45 [sink:sql_injection]
  💾 Taint flow saved to database
```

### 3. LLM Verification (Fase 3)

```bash
cd ../orchestrator
uv run python -m orchestrator.cli
```

**What happens:**

- Fetches unverified taint flows from database
- Builds minimal context (only relevant files)
- Sends to Ollama for verification
- Saves reasoning trace

**Output:**

```
=== FASE 3: LLM Verification ===
Model: qwen2.5-coder:7b
Pending verification: 5 flows

Verifying taint_flow_id=1...
  ✅ Verified: exploitable=True, confidence=0.95
Verifying taint_flow_id=2...
  ✅ Verified: exploitable=False, confidence=0.80
...
✅ Verified 5 flows
```

### 4. Generate Report

```bash
uv run python -c "
from orchestrator.config import load_config
from orchestrator.db.connection import Database
from orchestrator.report.generator import ReportGenerator
config = load_config()
db = Database(config)
ReportGenerator(db).generate()
"
```

**Output:** Table dengan severity, file:line, pattern, exploitable status, dan confidence.

---

## ⚠️ Limitations

| Limitation | Current State | Impact | Planned Solution |
|-----------|--------------|--------|-----------------|
| Bahasa yang didukung | Hanya Python dan JavaScript (extensible) | Tidak bisa scan Go, Java, C++ | Tambah grammar tree-sitter |
| Taint precision | Intra-procedural + call graph (tanpa SSA) | Ada false positive pada alias analysis | Implementasi SSA form |
| LLM context | Hanya file di flow path | Flow path > 10 file bisa overflow | Implementasi chunking strategy |
| Sanitization detection | Parameterized query + escape function | Deteksi sanitasi custom terbatas | Tambah pattern sanitasi |
| CVE reference | Local dump manual (15-20 entries) | Referensi terbatas | Sync dengan NVD API |
| Performance | Single-threaded scan | Lambat untuk 1000+ file | Parallel processing |
| LLM lokal | qwen2.5-coder:7b (7B parameters) | Reasoning terbatas untuk kasus kompleks | Opsional ganti ke model 14B/70B |

---

## 🗺️ Roadmap

### ✅ Completed

- ☑ Phase 1: Static Analysis (AST + Pattern Matching)
- ☑ Phase 2: Call Graph & Taint Analysis
- ☑ Phase 3: LLM Verification & Reporting

### 📋 Planned

- □ Multi-language support: Go, Java, TypeScript
- □ Web UI Dashboard
- □ CI/CD Integration (GitHub Actions, GitLab CI)
- □ Incremental scan (cache AST)
- □ SSA (Static Single Assignment) form for better taint precision
- □ Parallel processing for large codebases

### 🔮 Future

- □ RAG (Retrieval-Augmented Generation) with security knowledge base
- □ Automatic fix suggestion (patch generation)
- □ Integration with Jira/Linear for issue tracking
- □ Custom security rules (YARA-like)

---

## 🐛 Troubleshooting

### Problem: Database connection refused

**Why:** PostgreSQL not running or wrong credentials

**Solution:**

```bash
# Check Docker container
docker ps | grep security_audit_db

# Start if not running
docker-compose up -d

# Or check connection string
echo $DATABASE_URL
```

### Problem: Ollama timeout

**Why:** Model not loaded or timeout too short

**Solution:**

```bash
# Check Ollama status
ollama list

# Pull model if missing
ollama pull qwen2.5-coder:7b

# Increase timeout
export OLLAMA_TIMEOUT_SECONDS=300
```

### Problem: Build error in Go

**Why:** Missing dependencies or wrong Go version

**Solution:**

```bash
# Clean cache
go clean -modcache

# Re-download dependencies
go mod tidy

# Check Go version
go version  # Should be 1.22+
```

### Problem: No taint flows found

**Why:** Codebase doesn't have source → sink pattern

**Solution:**

```bash
# Check static findings
docker exec -it security_audit_db psql -U postgres -d security_audit -c "SELECT * FROM static_findings;"

# Add test files with known patterns
cp testdata/python/vulnerable_query.py /path/to/your/codebase/
```

---

## 👥 Contributing

### Development Workflow

```bash
# 1. Fork and clone
git clone https://github.com/your-org/security-audit-agent.git
cd security-audit-agent

# 2. Create branch
git checkout -b feature/your-feature

# 3. Make changes
# Add tests for new features

# 4. Run tests
cd services/ast-engine
go test ./...

cd ../orchestrator
pytest tests/

# 5. Commit and push
git add .
git commit -m "feat: your feature description"
git push origin feature/your-feature

# 6. Create Pull Request
```

### Coding Standards

- **Go:** golangci-lint enforced
- **Python:** ruff and mypy for type checking
- **Commits:** Conventional Commits (feat, fix, docs, test, etc.)

---

## 📄 License & Credits

### License

MIT License — see LICENSE file for details.

### Credits

- **Tree-sitter** — AST parsing
- **Ollama** — Local LLM runtime
- **Qwen2.5-Coder** — Model for code understanding
- **Gonum** — Graph algorithms
- **PostgreSQL** — Database

### Authors

- **Project Lead:** Muhamad Syukron Zakka

---

## 🔗 Quick Links

| Component | Tech Stack | Status |
|-----------|-----------|--------|
| AST Engine | Go + tree-sitter | ✅ Complete |
| Pattern Matcher | Go (AST walker) | ✅ Complete |
| Call Graph | Go + gonum | ✅ Complete |
| Taint Analysis | Go (worklist algorithm) | ✅ Complete |
| LLM Verification | Python + Ollama | ✅ Complete |
| Report Generator | Python + Rich | ✅ Complete |
| Database | PostgreSQL 15+ | ✅ Complete |
