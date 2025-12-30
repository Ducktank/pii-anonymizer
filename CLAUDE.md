# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Local-first, ACID-compliant PII/PHI anonymization service for LLM queries. Sanitizes user input before sending to Claude/ChatGPT, then de-anonymizes responses. Built for HIPAA/GDPR compliance.

## Commands

```bash
# Setup
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# CLI usage
python cli.py anonymize document.pdf -o safe.txt   # Anonymize file
python cli.py deanonymize response.txt -o final.txt # Restore PII
python cli.py analyze document.pdf                  # Detect PII without changing
python cli.py mappings -v                           # View stored tokens
python cli.py export backup.json                    # Backup mappings
python cli.py verify                                # Check DB integrity

# Run servers
python cli.py serve --port 8000    # API server (docs at /docs)
streamlit run app.py               # Web UI at :8501

# Quick test
python anonymizer.py               # Run built-in tests
python db_store.py                 # Test ACID compliance
```

## Architecture

```
User Input → PIIAnonymizer (Presidio) → PIIMappingStore (SQLite/WAL) → LLM API
                    ↓                           ↓
            [PERSON_A1B2C3D4]          content_hash → token
                    ↓                           ↓
            LLM Response ← deanonymize ← persistent mapping lookup
```

**Core flow:**
1. `anonymizer.py:PIIAnonymizer.anonymize()` - Detects PII via Presidio, generates tokens
2. `db_store.py:PIIMappingStore.get_or_create_mapping()` - Content-addressable storage
3. Same PII value → same token (deterministic via SHA-256 hash)
4. `deanonymize()` - Replaces tokens with original values from store

**Key classes:**
- `PIIAnonymizer` (anonymizer.py:17) - Main interface, wraps Presidio
- `PIIMappingStore` (db_store.py:23) - ACID SQLite store with WAL mode
- `FileProcessorFactory` (file_processor.py:160) - PDF/DOCX/TXT extraction

## Key Design Decisions

**Deterministic tokens**: `hash(entity_type + value)[:16]` → `[US_SSN_A1B2C3D4]`
- Same SSN always produces same token, even across sessions/machines
- Enables context consistency across documents

**Two modes:**
- `persistent=False` (session): In-memory, resets on restart
- `persistent=True` (ACID): SQLite with WAL, survives crashes

**Immutability**: Mappings never change once created. `audit_log` table tracks all access.

## Database

SQLite with `PRAGMA journal_mode=WAL` and `synchronous=FULL`.

**Tables:**
- `pii_mappings` - content_hash (unique), entity_type, original_value, token
- `audit_log` - operation, mapping_id, timestamp
- `document_history` - file processing records

**Thread safety:** Thread-local connections via `threading.local()` in db_store.py:36

## Environment Variables

```bash
PII_DB_PATH=pii_mappings.db   # Database location
PII_CONFIDENCE=0.7            # Detection threshold (0.0-1.0)
ANTHROPIC_API_KEY=sk-...      # For Claude API (optional)
OPENAI_API_KEY=sk-...         # For OpenAI API (optional)
```

## Custom Recognizers

Added in `anonymizer.py:69-107`:
- `MEDICAL_RECORD_NUMBER` - MRN patterns
- `NPI` - National Provider Identifier (10 digits)
- `DATE_TIME` - DOB patterns with context

To add custom recognizers:
```python
from presidio_analyzer import Pattern, PatternRecognizer
recognizer = PatternRecognizer(
    supported_entity="CUSTOM_TYPE",
    patterns=[Pattern(name="id", regex=r"\bPATTERN\b", score=0.9)]
)
anonymizer.analyzer.registry.add_recognizer(recognizer)
```

## File Processing

`FileProcessorFactory` supports: `.txt`, `.pdf`, `.docx`, `.md`, `.csv`, `.json`

Each processor implements:
- `extract_text(bytes) → str`
- `reconstruct(original_bytes, anonymized_text) → bytes`

Note: PDF reconstruction outputs plain text (layout preservation not implemented).
