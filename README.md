# 🔒 PII Anonymizer for LLMs

A local-first, **ACID-compliant** privacy layer that anonymizes PII/PHI before sending queries to ChatGPT, Claude, or other LLMs — then restores the original values in responses.

**Built for HIPAA, GDPR, and PCI compliance use cases.**

## Key Features

- ✅ **ACID-Compliant Storage** — SQLite with WAL mode, proper transactions, crash recovery
- ✅ **Deterministic Mappings** — Same SSN always maps to same token, even across sessions
- ✅ **Immutable Audit Trail** — Mappings never change once created, full history for compliance
- ✅ **File Processing** — Supports PDF, DOCX, TXT, CSV, JSON, Markdown
- ✅ **REST API** — FastAPI server for integration with Claude Code
- ✅ **CLI Tool** — Process files from command line
- ✅ **100% Local** — No PII leaves your machine during analysis

## Why ACID-Compliant?

| Problem | Our Solution |
|---------|--------------|
| Random tokens break context | **Deterministic**: Same value → same token always |
| Mappings lost on restart | **Persistent**: SQLite survives crashes |
| Can't audit who saw what | **Immutable**: Full audit log, nothing deleted |
| Concurrent access issues | **WAL mode**: Safe concurrent reads/writes |

## Supported Entity Types

| Entity | Examples |
|--------|----------|
| PERSON | John Smith, Dr. Jane Doe |
| PHONE_NUMBER | 410-555-1234, (555) 123-4567 |
| EMAIL_ADDRESS | patient@email.com |
| US_SSN | 123-45-6789 |
| CREDIT_CARD | 4111-1111-1111-1111 |
| DATE_TIME | 03/15/1982, DOB: 1990-01-01 |
| LOCATION | Boston, MA, 123 Main St |
| MEDICAL_RECORD_NUMBER | MRN: 12345678 |
| NPI | NPI: 1234567890 |
| IP_ADDRESS | 192.168.1.1 |

## Quick Start

### 1. Clone and install

```bash
git clone <your-repo>
cd pii-anonymizer

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy model (required)
python -m spacy download en_core_web_lg
```

### 2. Choose your mode

#### Option A: CLI Mode (Best for Claude Code integration)

```bash
# Anonymize a document
python cli.py anonymize patient_record.pdf -o safe_record.txt

# Send safe_record.txt to Claude Code, get response...

# Deanonymize the response
python cli.py deanonymize claude_response.txt -o final_response.txt
```

#### Option B: API Server Mode (Best for automation)

```bash
# Start the server
python cli.py serve --port 8000

# API docs at http://localhost:8000/docs
```

```bash
# Example API call
curl -X POST http://localhost:8000/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "Patient John Smith, SSN 123-45-6789"}'
```

#### Option C: Web UI Mode (Best for exploration)

```bash
streamlit run app.py
# Open http://localhost:8501
```

### 3. Configure API keys (optional, for LLM features)

```bash
cp .env.example .env
# Edit .env with your API keys
```

## Usage

### Web Interface

1. Enter your query containing PII in the left panel
2. Click "Analyze PII" to see what will be detected
3. Click "Anonymize & Send to LLM" to:
   - Anonymize your input
   - Send to the selected LLM
   - De-anonymize the response
4. View the final response with original names/values restored

### Python API

```python
from anonymizer import PIIAnonymizer

# Initialize with ACID-compliant persistent storage
anonymizer = PIIAnonymizer(
    persistent=True,          # Use SQLite store
    db_path="pii_mappings.db" # Database file
)

# Your query with sensitive data
query = """
Patient John Smith (SSN: 123-45-6789) needs a prescription refill.
Contact: john.smith@email.com
"""

# Anonymize - same value always produces same token!
safe_query, mapping = anonymizer.anonymize(query, source_file="intake_form.pdf")
# safe_query = "Patient [PERSON_A1B2C3D4] (SSN: [US_SSN_E5F6G7H8])..."

# Send to LLM (no PII transmitted!)
# response = client.chat(safe_query)

# Later, even in a different session:
restored = anonymizer.deanonymize(response_from_llm)
print(restored)  # Original names restored!

# Verify database integrity
is_valid, issues = anonymizer.verify_integrity()
```

### CLI Mode

```bash
# Quick test without running the full app
python anonymizer.py
```

## Architecture

```
┌─────────────────┐     ┌───────────────────────────────────┐     ┌─────────────┐
│   User Input    │────▶│        PII Anonymizer             │────▶│   LLM API   │
│   (PDF, DOCX,   │     │                                   │     │   (Claude)  │
│    TXT, etc.)   │     │  ┌─────────────┐ ┌─────────────┐  │     └─────────────┘
└─────────────────┘     │  │  Presidio   │ │   SQLite    │  │            │
                        │  │  Engine     │ │   Store     │  │            │
                        │  │             │ │   (ACID)    │  │            │
                        │  │  • NER      │ │             │  │            │
                        │  │  • Regex    │ │  hash →     │  │            │
                        │  │  • HIPAA    │ │  token      │  │            │
                        │  └─────────────┘ └─────────────┘  │            │
                        └───────────────────────────────────┘            │
                                          │                              │
                                          └──────────────┬───────────────┘
                                                         ▼
                                          ┌───────────────────────┐
                                          │   De-anonymized       │
                                          │   Response            │
                                          └───────────────────────┘
```

### Deterministic Token Generation

```python
# Same PII value ALWAYS produces same token (content-addressable)
"222-333-4444" → SHA256("US_SSN:222-333-4444")[:16] → "[US_SSN_A1B2C3D4]"

# Even across sessions, machines, years later:
"222-333-4444" → "[US_SSN_A1B2C3D4]"  # Guaranteed same!
```

This prevents:
- Context drift (same patient = same token in all documents)
- Mapping loss on restart
- Inconsistent anonymization across files

## Configuration

### Persistent vs Session Mode

```python
# Session mode (in-memory, resets on restart)
anonymizer = PIIAnonymizer(persistent=False)

# Persistent mode (ACID-compliant SQLite)
anonymizer = PIIAnonymizer(
    persistent=True,
    db_path="pii_mappings.db"
)
```

### Confidence Threshold

Adjust detection sensitivity:

```python
anonymizer = PIIAnonymizer(confidence_threshold=0.8)  # Higher = fewer false positives
```

### Environment Variables

```bash
PII_DB_PATH=pii_mappings.db  # Database location
PII_CONFIDENCE=0.7           # Detection threshold
ANTHROPIC_API_KEY=sk-...     # For Claude API (optional)
```

### Custom Recognizers

Add industry-specific patterns in `anonymizer.py`:

```python
from presidio_analyzer import Pattern, PatternRecognizer

# Example: Custom patient ID format
patient_id_recognizer = PatternRecognizer(
    supported_entity="PATIENT_ID",
    patterns=[
        Pattern(name="patient_id", regex=r"\bPT-\d{8}\b", score=0.9)
    ]
)
anonymizer.analyzer.registry.add_recognizer(patient_id_recognizer)
```

## Security Considerations

- ✅ PII mappings stored in encrypted SQLite with WAL mode
- ✅ Audit log tracks all access for compliance
- ⚠️ API keys should be stored in `.env` (never commit to git)
- ⚠️ Presidio uses automated detection — always review results for sensitive use cases
- ⚠️ This tool reduces but does not eliminate compliance risk
- ⚠️ Database file (`pii_mappings.db`) contains original PII — secure appropriately

## CLI Reference

```bash
# Anonymize file
python cli.py anonymize document.pdf -o safe.txt

# Deanonymize text
python cli.py deanonymize response.txt -o final.txt

# Analyze without changing
python cli.py analyze document.pdf

# View stored mappings
python cli.py mappings -v

# Export mappings to JSON (for backup)
python cli.py export mappings_backup.json

# Verify database integrity
python cli.py verify

# Start API server
python cli.py serve --port 8000
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/anonymize` | Anonymize text |
| POST | `/anonymize/file` | Anonymize uploaded file |
| POST | `/deanonymize` | Restore original PII |
| POST | `/analyze` | Detect PII without anonymizing |
| GET | `/mappings` | List stored tokens |
| GET | `/stats` | Database statistics |
| GET | `/health` | Health check + integrity |

## Roadmap

- [x] ~~FastAPI endpoint mode for programmatic access~~
- [x] ~~Audit logging for compliance~~
- [x] ~~ACID-compliant persistent storage~~
- [x] ~~Batch file processing~~
- [ ] Browser extension (Chrome/Firefox)
- [ ] Local LLM support (Ollama/llama.cpp)
- [ ] Multi-language support
- [ ] Encryption at rest for database

## License

MIT

## Credits

- [Microsoft Presidio](https://github.com/microsoft/presidio) — PII detection engine
- [spaCy](https://spacy.io/) — NLP backbone
- [Streamlit](https://streamlit.io/) — Web interface
