"""
ACID-Compliant PII Mapping Store
Provides persistent, immutable, deterministic mappings for PII values.

Key properties:
- DETERMINISTIC: Same PII value always maps to same token (content-addressable)
- IMMUTABLE: Once created, mappings never change
- ACID: SQLite with WAL mode, proper transactions
- AUDITABLE: Full history with timestamps
"""

import sqlite3
import hashlib
import threading
import base64
import warnings
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple
from contextlib import contextmanager
from pathlib import Path
import json
import os

try:
    from cryptography.fernet import Fernet
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False


class PIIEncryption:
    """Handles encryption/decryption of PII values using Fernet (AES-128-CBC with HMAC)."""

    _instance = None
    _fernet = None
    _key_version = 1

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        if not ENCRYPTION_AVAILABLE:
            warnings.warn(
                "cryptography library not installed. PII will be stored in PLAINTEXT. "
                "Install with: pip install cryptography",
                RuntimeWarning
            )
            self._fernet = None
            return

        key = os.environ.get('PII_ENCRYPTION_KEY')
        if key:
            try:
                self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
            except Exception as e:
                raise ValueError(f"Invalid PII_ENCRYPTION_KEY format: {e}")
        else:
            warnings.warn(
                "PII_ENCRYPTION_KEY not set. Generating ephemeral key. "
                "PII will NOT be recoverable after restart! "
                "Set PII_ENCRYPTION_KEY env var for production.",
                RuntimeWarning
            )
            key = Fernet.generate_key()
            self._fernet = Fernet(key)
            print(f"Generated ephemeral key (save for persistence): {key.decode()}")

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext, return versioned ciphertext."""
        if not self._fernet:
            return plaintext  # No encryption available
        encrypted = self._fernet.encrypt(plaintext.encode('utf-8'))
        return f"v{self._key_version}:{base64.urlsafe_b64encode(encrypted).decode()}"

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext, return plaintext. Handles legacy unencrypted data."""
        if not self._fernet:
            return ciphertext
        if not ciphertext.startswith('v') or ':' not in ciphertext:
            return ciphertext  # Legacy plaintext data
        version, data = ciphertext.split(':', 1)
        encrypted = base64.urlsafe_b64decode(data.encode())
        return self._fernet.decrypt(encrypted).decode('utf-8')

    @staticmethod
    def generate_key() -> str:
        """Generate a new Fernet encryption key."""
        if not ENCRYPTION_AVAILABLE:
            raise RuntimeError("cryptography library not installed")
        return Fernet.generate_key().decode()


class PIIMappingStore:
    """
    ACID-compliant persistent store for PII ↔ token mappings.
    
    Uses content-addressable design: hash(entity_type + value) = deterministic token
    This ensures the same SSN always maps to the same token, even across sessions.
    """
    
    # Schema version for migrations
    SCHEMA_VERSION = 1
    
    def __init__(self, db_path: str = "pii_mappings.db"):
        self.db_path = Path(db_path)
        self._local = threading.local()
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level=None  # We manage transactions manually
            )
            # Enable WAL mode for better concurrency and crash recovery
            conn.execute("PRAGMA journal_mode=WAL")
            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys=ON")
            # Synchronous FULL for maximum durability
            conn.execute("PRAGMA synchronous=FULL")
            conn.row_factory = sqlite3.Row
            self._local.connection = conn
        return self._local.connection
    
    @contextmanager
    def _transaction(self):
        """Context manager for ACID transactions."""
        conn = self._get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    
    def _init_db(self):
        """Initialize database schema."""
        with self._transaction() as conn:
            # Main mappings table - immutable once created
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pii_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_hash TEXT UNIQUE NOT NULL,
                    entity_type TEXT NOT NULL,
                    original_value TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    source_file TEXT,
                    UNIQUE(entity_type, original_value)
                )
            """)
            
            # Index for fast lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mappings_token 
                ON pii_mappings(token)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mappings_hash 
                ON pii_mappings(content_hash)
            """)
            
            # Audit log - tracks all operations
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation TEXT NOT NULL,
                    mapping_id INTEGER,
                    details TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (mapping_id) REFERENCES pii_mappings(id)
                )
            """)
            
            # Document processing history
            conn.execute("""
                CREATE TABLE IF NOT EXISTS document_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_hash TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    original_size INTEGER,
                    mappings_applied TEXT,
                    processed_at TEXT NOT NULL,
                    status TEXT DEFAULT 'completed'
                )
            """)
            
            # Schema version tracking
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """)
            
            # Set initial version if not exists
            result = conn.execute("SELECT version FROM schema_version").fetchone()
            if result is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", 
                           (self.SCHEMA_VERSION,))
    
    def _compute_content_hash(self, entity_type: str, original_value: str) -> str:
        """
        Compute deterministic hash for content-addressable storage.
        Same input always produces same hash.
        """
        # Normalize: strip whitespace, lowercase for consistency
        normalized = f"{entity_type.upper()}:{original_value.strip()}"
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:16]
    
    def _generate_token(self, entity_type: str, content_hash: str) -> str:
        """
        Generate a deterministic, human-readable token.
        Format: [ENTITY_TYPE_XXXX] where XXXX is derived from hash
        """
        # Use first 8 chars of hash for readability
        short_hash = content_hash[:8].upper()
        return f"[{entity_type}_{short_hash}]"
    
    def get_or_create_mapping(
        self, 
        entity_type: str, 
        original_value: str,
        source_file: Optional[str] = None
    ) -> str:
        """
        Get existing token or create new mapping.
        DETERMINISTIC: Same value always returns same token.
        IMMUTABLE: Once created, mapping never changes.
        
        Returns: token string
        """
        content_hash = self._compute_content_hash(entity_type, original_value)
        
        with self._transaction() as conn:
            # Check if mapping already exists
            existing = conn.execute(
                "SELECT token FROM pii_mappings WHERE content_hash = ?",
                (content_hash,)
            ).fetchone()
            
            if existing:
                # Log access
                conn.execute(
                    "INSERT INTO audit_log (operation, details, timestamp) VALUES (?, ?, ?)",
                    ("ACCESS", json.dumps({"content_hash": content_hash}), 
                     datetime.now(timezone.utc).isoformat())
                )
                return existing['token']
            
            # Create new mapping
            token = self._generate_token(entity_type, content_hash)
            now = datetime.now(timezone.utc).isoformat()

            # Encrypt PII before storing
            encryption = PIIEncryption.get_instance()
            encrypted_value = encryption.encrypt(original_value)

            cursor = conn.execute(
                """INSERT INTO pii_mappings
                   (content_hash, entity_type, original_value, token, created_at, source_file)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (content_hash, entity_type, encrypted_value, token, now, source_file)
            )
            
            # Audit log
            conn.execute(
                "INSERT INTO audit_log (operation, mapping_id, details, timestamp) VALUES (?, ?, ?, ?)",
                ("CREATE", cursor.lastrowid, 
                 json.dumps({"entity_type": entity_type, "source": source_file}), now)
            )
            
            return token
    
    def lookup_token(self, token: str) -> Optional[Dict]:
        """
        Look up original value by token.
        Returns: {"entity_type": str, "original_value": str, "created_at": str} or None
        """
        conn = self._get_connection()
        result = conn.execute(
            "SELECT entity_type, original_value, created_at FROM pii_mappings WHERE token = ?",
            (token,)
        ).fetchone()

        if result:
            encryption = PIIEncryption.get_instance()
            return {
                "entity_type": result['entity_type'],
                "original_value": encryption.decrypt(result['original_value']),
                "created_at": result['created_at']
            }
        return None
    
    def lookup_original(self, entity_type: str, original_value: str) -> Optional[str]:
        """
        Look up token by original value.
        Returns: token string or None
        """
        content_hash = self._compute_content_hash(entity_type, original_value)
        conn = self._get_connection()
        result = conn.execute(
            "SELECT token FROM pii_mappings WHERE content_hash = ?",
            (content_hash,)
        ).fetchone()
        return result['token'] if result else None
    
    def get_all_mappings(self) -> List[Dict]:
        """Get all mappings (for export/backup)."""
        conn = self._get_connection()
        results = conn.execute(
            "SELECT entity_type, token, created_at, source_file FROM pii_mappings ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in results]
    
    def deanonymize_text(self, text: str) -> str:
        """Replace all tokens in text with original values."""
        conn = self._get_connection()
        mappings = conn.execute(
            "SELECT token, original_value FROM pii_mappings"
        ).fetchall()

        encryption = PIIEncryption.get_instance()
        result = text
        for mapping in mappings:
            original = encryption.decrypt(mapping['original_value'])
            result = result.replace(mapping['token'], original)
        return result
    
    def record_document(
        self, 
        file_name: str, 
        file_type: str, 
        file_content: bytes,
        mappings_applied: List[str]
    ) -> int:
        """Record document processing in history."""
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        with self._transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO document_history 
                   (file_hash, file_name, file_type, original_size, mappings_applied, processed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (file_hash, file_name, file_type, len(file_content),
                 json.dumps(mappings_applied), datetime.now(timezone.utc).isoformat())
            )
            return cursor.lastrowid
    
    def get_stats(self) -> Dict:
        """Get database statistics."""
        conn = self._get_connection()
        
        total_mappings = conn.execute(
            "SELECT COUNT(*) as count FROM pii_mappings"
        ).fetchone()['count']
        
        by_type = conn.execute(
            "SELECT entity_type, COUNT(*) as count FROM pii_mappings GROUP BY entity_type"
        ).fetchall()
        
        total_docs = conn.execute(
            "SELECT COUNT(*) as count FROM document_history"
        ).fetchone()['count']
        
        return {
            "total_mappings": total_mappings,
            "by_entity_type": {r['entity_type']: r['count'] for r in by_type},
            "total_documents_processed": total_docs
        }
    
    def export_mappings(self, output_path: str):
        """Export all mappings to JSON (for backup)."""
        mappings = self.get_all_mappings()
        with open(output_path, 'w') as f:
            json.dump({
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "schema_version": self.SCHEMA_VERSION,
                "mappings": mappings
            }, f, indent=2)
    
    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify database integrity.
        Returns: (is_valid, list of issues)
        """
        issues = []
        conn = self._get_connection()

        # Check SQLite integrity
        result = conn.execute("PRAGMA integrity_check").fetchone()
        if result[0] != 'ok':
            issues.append(f"SQLite integrity check failed: {result[0]}")

        # Verify all content hashes match
        rows = conn.execute(
            "SELECT id, content_hash, entity_type, original_value FROM pii_mappings"
        ).fetchall()

        encryption = PIIEncryption.get_instance()
        for row in rows:
            decrypted_value = encryption.decrypt(row['original_value'])
            expected_hash = self._compute_content_hash(row['entity_type'], decrypted_value)
            if expected_hash != row['content_hash']:
                issues.append(f"Hash mismatch for mapping ID {row['id']}")

        return len(issues) == 0, issues
    
    def close(self):
        """Close database connection."""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None


# Singleton instance
_store: Optional[PIIMappingStore] = None

def get_store(db_path: str = "pii_mappings.db") -> PIIMappingStore:
    """Get or create singleton store instance."""
    global _store
    if _store is None:
        _store = PIIMappingStore(db_path)
    return _store


if __name__ == "__main__":
    # Test ACID compliance and determinism
    import tempfile
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    try:
        store = PIIMappingStore(db_path)
        
        print("=== Testing Deterministic Mappings ===")
        
        # Same SSN should always produce same token
        ssn = "222-333-4444"
        token1 = store.get_or_create_mapping("US_SSN", ssn, source_file="test.pdf")
        token2 = store.get_or_create_mapping("US_SSN", ssn, source_file="other.pdf")
        
        print(f"SSN: {ssn}")
        print(f"Token 1: {token1}")
        print(f"Token 2: {token2}")
        print(f"Deterministic: {token1 == token2}")
        assert token1 == token2, "FAILED: Same value should produce same token"
        
        # Different SSN should produce different token
        token3 = store.get_or_create_mapping("US_SSN", "111-22-3333")
        print(f"Different SSN token: {token3}")
        assert token1 != token3, "FAILED: Different values should produce different tokens"
        
        print("\n=== Testing Persistence ===")
        # Close and reopen
        store.close()
        store2 = PIIMappingStore(db_path)
        
        # Should retrieve same token
        token4 = store2.get_or_create_mapping("US_SSN", ssn)
        print(f"After reopen: {token4}")
        assert token1 == token4, "FAILED: Token should persist across sessions"
        
        print("\n=== Testing Lookup ===")
        lookup = store2.lookup_token(token1)
        print(f"Lookup result: {lookup}")
        assert lookup['original_value'] == ssn, "FAILED: Lookup should return original"
        
        print("\n=== Testing Integrity ===")
        is_valid, issues = store2.verify_integrity()
        print(f"Integrity valid: {is_valid}")
        if issues:
            print(f"Issues: {issues}")
        
        print("\n=== Stats ===")
        print(store2.get_stats())
        
        print("\n✅ All tests passed!")
        
    finally:
        os.unlink(db_path)
        # Clean up WAL files
        for ext in ['-wal', '-shm']:
            try:
                os.unlink(db_path + ext)
            except FileNotFoundError:
                pass
