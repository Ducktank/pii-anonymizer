"""
PII Anonymizer API Server
REST API for integrating with Claude Code and other LLM tools.

Endpoints:
    POST /anonymize       - Anonymize text
    POST /anonymize/file  - Anonymize uploaded file
    POST /deanonymize     - Restore original PII values
    GET  /mappings        - View stored mappings
    GET  /stats           - Get statistics
    GET  /health          - Health check
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from collections import defaultdict
import os
import tempfile
import time
import secrets
from pathlib import Path

from anonymizer import PIIAnonymizer
from file_processor import process_file, FileProcessorFactory
from db_store import PIIMappingStore

# Configuration
DB_PATH = os.getenv("PII_DB_PATH", "pii_mappings.db")
CONFIDENCE_THRESHOLD = float(os.getenv("PII_CONFIDENCE", "0.7"))
API_KEY = os.getenv("PII_API_KEY")
CORS_ORIGINS = os.getenv("PII_CORS_ORIGINS", "http://localhost:8501").split(",")
MAX_UPLOAD_SIZE = int(os.getenv("PII_MAX_UPLOAD_MB", "10")) * 1024 * 1024
RATE_LIMIT_REQUESTS = int(os.getenv("PII_RATE_LIMIT", "100"))
RATE_LIMIT_WINDOW = 60

# Initialize
app = FastAPI(
    title="PII Anonymizer API",
    description="Protect sensitive data before sending to LLMs like Claude",
    version="1.0.0"
)

# CORS - restricted to configured origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

# API Key Authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if not API_KEY:
        return None
    if not api_key or not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key

# Rate limiting
_rate_limit_store: Dict[str, List[float]] = defaultdict(list)

async def rate_limit(request: Request):
    client_ip = request.client.host
    now = time.time()
    _rate_limit_store[client_ip] = [t for t in _rate_limit_store[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _rate_limit_store[client_ip].append(now)


# Request/Response models
class AnonymizeRequest(BaseModel):
    text: str = Field(..., description="Text to anonymize")
    source: Optional[str] = Field(None, description="Source identifier for audit")
    entities: Optional[List[str]] = Field(None, description="Entity types to detect")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence threshold")


class AnonymizeResponse(BaseModel):
    anonymized_text: str
    mapping: Dict[str, str]
    entities_found: int
    

class DeanonymizeRequest(BaseModel):
    text: str = Field(..., description="Text with tokens to restore")


class DeanonymizeResponse(BaseModel):
    restored_text: str


class AnalyzeResponse(BaseModel):
    entities: List[Dict]
    count: int


class MappingInfo(BaseModel):
    token: str
    entity_type: str
    created_at: str
    source_file: Optional[str]


class StatsResponse(BaseModel):
    total_mappings: int
    by_entity_type: Dict[str, int]
    total_documents_processed: int
    database_path: str


# Helper to get anonymizer
def get_anonymizer(confidence: Optional[float] = None) -> PIIAnonymizer:
    return PIIAnonymizer(
        persistent=True,
        db_path=DB_PATH,
        confidence_threshold=confidence or CONFIDENCE_THRESHOLD
    )


# Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    store = PIIMappingStore(DB_PATH)
    is_valid, issues = store.verify_integrity()
    store.close()
    
    return {
        "status": "healthy" if is_valid else "degraded",
        "database": DB_PATH,
        "integrity": is_valid,
        "issues": issues if not is_valid else None
    }


@app.post("/anonymize", response_model=AnonymizeResponse, dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def anonymize_text(request: AnonymizeRequest):
    """
    Anonymize text by replacing PII with deterministic tokens.

    Same PII value always produces the same token (deterministic, ACID-compliant).
    """
    anonymizer = get_anonymizer(request.confidence)
    
    try:
        anonymized_text, mapping = anonymizer.anonymize(
            text=request.text,
            entities=request.entities,
            source_file=request.source
        )
        
        return AnonymizeResponse(
            anonymized_text=anonymized_text,
            mapping=mapping,
            entities_found=len(mapping)
        )
    finally:
        anonymizer.close()


@app.post("/anonymize/file", response_model=AnonymizeResponse, dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def anonymize_file(
    file: UploadFile = File(...),
    confidence: Optional[float] = Query(None, ge=0.0, le=1.0)
):
    """
    Anonymize an uploaded file (PDF, DOCX, TXT, etc.).

    Supported formats: .txt, .pdf, .docx, .md, .csv, .json
    """
    # Check file type
    suffix = Path(file.filename).suffix.lower()
    if not FileProcessorFactory.is_supported(file.filename):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {suffix}. Supported: {FileProcessorFactory.supported_types()}"
        )

    # Check file size
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size: {MAX_UPLOAD_SIZE // (1024*1024)}MB"
        )

    # Save to temp file
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        # Process file
        text, file_type, _ = process_file(tmp_path)

        # Anonymize
        anonymizer = get_anonymizer(confidence)
        anonymized_text, mapping = anonymizer.anonymize(
            text=text,
            source_file=file.filename
        )
        anonymizer.close()

        return AnonymizeResponse(
            anonymized_text=anonymized_text,
            mapping=mapping,
            entities_found=len(mapping)
        )
    finally:
        os.unlink(tmp_path)


@app.post("/deanonymize", response_model=DeanonymizeResponse, dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def deanonymize_text(request: DeanonymizeRequest):
    """
    Restore original PII values by replacing tokens.

    Uses the persistent mapping store - works across sessions.
    """
    anonymizer = get_anonymizer()
    
    try:
        restored_text = anonymizer.deanonymize(request.text)
        return DeanonymizeResponse(restored_text=restored_text)
    finally:
        anonymizer.close()


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def analyze_text(request: AnonymizeRequest):
    """
    Analyze text for PII without anonymizing.

    Returns list of detected entities with positions and confidence scores.
    """
    anonymizer = get_anonymizer(request.confidence)
    
    try:
        entities = anonymizer.analyze(request.text, request.entities)
        return AnalyzeResponse(entities=entities, count=len(entities))
    finally:
        anonymizer.close()


@app.get("/mappings", response_model=List[MappingInfo], dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def list_mappings(
    limit: int = Query(100, ge=1, le=1000),
    entity_type: Optional[str] = Query(None)
):
    """
    List stored PII mappings.

    Note: Original values are not returned for security.
    """
    store = PIIMappingStore(DB_PATH)
    
    try:
        conn = store._get_connection()
        
        if entity_type:
            results = conn.execute(
                """SELECT token, entity_type, created_at, source_file 
                   FROM pii_mappings 
                   WHERE entity_type = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (entity_type, limit)
            ).fetchall()
        else:
            results = conn.execute(
                """SELECT token, entity_type, created_at, source_file 
                   FROM pii_mappings 
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
        
        return [
            MappingInfo(
                token=r['token'],
                entity_type=r['entity_type'],
                created_at=r['created_at'],
                source_file=r['source_file']
            )
            for r in results
        ]
    finally:
        store.close()


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get statistics about the mapping store."""
    store = PIIMappingStore(DB_PATH)
    
    try:
        stats = store.get_stats()
        return StatsResponse(
            total_mappings=stats['total_mappings'],
            by_entity_type=stats['by_entity_type'],
            total_documents_processed=stats['total_documents_processed'],
            database_path=DB_PATH
        )
    finally:
        store.close()


@app.get("/entities")
async def list_supported_entities():
    """List all supported PII entity types."""
    anonymizer = get_anonymizer()
    try:
        return {
            "default_entities": anonymizer.DEFAULT_ENTITIES,
            "all_supported": anonymizer.get_supported_entities()
        }
    finally:
        anonymizer.close()


# Startup/shutdown events
@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    store = PIIMappingStore(DB_PATH)
    is_valid, issues = store.verify_integrity()
    store.close()
    
    if not is_valid:
        print(f"WARNING: Database integrity issues: {issues}")
    else:
        print(f"PII Anonymizer API started. Database: {DB_PATH}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
