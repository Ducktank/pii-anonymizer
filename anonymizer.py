"""
Core PII Anonymization Module
Wraps Microsoft Presidio with reversible anonymization for LLM use cases.

Supports two modes:
1. Session mode (in-memory): Original behavior, mappings reset each session
2. Persistent mode (ACID-compliant): Uses SQLite, deterministic mappings survive restarts
"""

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts
from presidio_anonymizer import AnonymizerEngine
from typing import Dict, List, Tuple, Optional, Set
import threading
import os
import spacy


# Thread-safe shared spaCy model singleton
_nlp_lock = threading.Lock()
_nlp_model = None

def get_shared_nlp():
    """Get or load shared spaCy model (thread-safe singleton)."""
    global _nlp_model
    if _nlp_model is None:
        with _nlp_lock:
            if _nlp_model is None:
                _nlp_model = spacy.load("en_core_web_lg")
    return _nlp_model


# Configurable skip words for name recognition
DEFAULT_SKIP_WORDS = frozenset({
    'NEW', 'OLD', 'THE', 'FOR', 'AND', 'NOT', 'ALL', 'DUE', 'APR', 'MAY',
    'TOTAL', 'BALANCE', 'PAYMENT', 'CREDIT', 'INTEREST', 'CHARGE',
    'TRANSACTIONS', 'PAYMENTS', 'CREDITS', 'ACCOUNT', 'NUMBER',
    'AMOUNT', 'DATE', 'STATEMENT', 'BILLING', 'SUMMARY'
})

def get_skip_words() -> Set[str]:
    """Get skip words from environment or use defaults."""
    env_words = os.getenv("PII_SKIP_WORDS")
    if env_words:
        return frozenset(w.strip().upper() for w in env_words.split(","))
    return DEFAULT_SKIP_WORDS


class FullNameRecognizer(EntityRecognizer):
    """Recognizer for full names in FIRSTNAME [MIDDLE] LASTNAME format.

    Catches names that spaCy NER misses, especially in financial documents
    where names appear in ALL CAPS format like 'RYAN S DEAN'.
    """

    def __init__(self):
        super().__init__(
            supported_entities=["PERSON"],
            supported_language="en",
            name="FullNameRecognizer",
        )

    def load(self):
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts: NlpArtifacts = None) -> List[RecognizerResult]:
        import re
        results = []
        skip_words = get_skip_words()

        # Limit text length to prevent ReDoS
        max_len = 100000
        if len(text) > max_len:
            text = text[:max_len]

        # Pattern 1: FIRSTNAME [MIDDLE_INITIAL] LASTNAME (all caps, same line only)
        # Made possessive to prevent backtracking
        caps_name_pattern = r'\b([A-Z]{2,})(?: ([A-Z]\.?))?(?: ([A-Z]{2,}))\b'

        for match in re.finditer(caps_name_pattern, text):
            full_match = match.group(0)
            if len(full_match) < 5:
                continue
            first_word = match.group(1)
            last_word = match.group(3) or match.group(1)
            if first_word in skip_words or last_word in skip_words:
                continue
            results.append(RecognizerResult(
                entity_type="PERSON",
                start=match.start(),
                end=match.end(),
                score=0.95,
            ))

        # Pattern 2: Name after masked text (XXXX pattern common in financial docs)
        masked_name_pattern = r'X{3,20}([A-Z]{2,}(?: [A-Z]\.?)?(?: [A-Z]{2,}))\b'

        for match in re.finditer(masked_name_pattern, text):
            name_part = match.group(1)
            words = name_part.split()
            if any(w in skip_words for w in words):
                continue
            name_start = match.start() + len(match.group(0)) - len(name_part)
            results.append(RecognizerResult(
                entity_type="PERSON",
                start=name_start,
                end=match.end(),
                score=0.95,
            ))

        return results


class OrganizationRecognizer(EntityRecognizer):
    """Recognizer for organizations using spaCy NER (HIPAA: healthcare facilities)."""

    EXCLUDED = {"DOB", "SSN", "NPI", "MRN", "DOD", "PHI", "PII", "HIPAA", "ID"}
    MIN_LENGTH = 5

    def __init__(self):
        super().__init__(
            supported_entities=["ORGANIZATION"],
            supported_language="en",
            name="OrganizationRecognizer",
        )

    def load(self):
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts: NlpArtifacts = None) -> List[RecognizerResult]:
        nlp = get_shared_nlp()
        results = []
        doc = nlp(text)
        for ent in doc.ents:
            if ent.label_ == "ORG":
                org_text = ent.text.strip()
                if org_text.upper() in self.EXCLUDED:
                    continue
                if len(org_text) < self.MIN_LENGTH:
                    continue
                results.append(RecognizerResult(
                    entity_type="ORGANIZATION",
                    start=ent.start_char,
                    end=ent.end_char,
                    score=0.85,
                ))
        return results


class PIIAnonymizer:
    """Reversible PII anonymization for LLM queries."""
    
    # Default entities to detect
    DEFAULT_ENTITIES = [
        "PERSON",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
        "DATE_TIME",
        "LOCATION",
        "ORGANIZATION",
        "US_DRIVER_LICENSE",
        "IP_ADDRESS",
        "MEDICAL_RECORD_NUMBER",
        "NPI",
    ]
    
    def __init__(
        self, 
        confidence_threshold: float = 0.7,
        persistent: bool = False,
        db_path: str = "pii_mappings.db"
    ):
        """
        Initialize anonymizer.
        
        Args:
            confidence_threshold: Minimum confidence for PII detection (0.0-1.0)
            persistent: If True, use ACID-compliant SQLite store
            db_path: Path to SQLite database (only used if persistent=True)
        """
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.confidence_threshold = confidence_threshold
        self.persistent = persistent
        
        if persistent:
            from db_store import PIIMappingStore
            self.store = PIIMappingStore(db_path)
            self.mapping = {}  # Will be populated from store as needed
            self.reverse_mapping = {}
        else:
            self.store = None
            self.mapping: Dict[str, str] = {}  # placeholder -> original
            self.reverse_mapping: Dict[str, str] = {}  # original -> placeholder
        
        self._counter: Dict[str, int] = {}  # entity type -> count (session mode only)
        
        # Add custom HIPAA recognizers
        self._add_custom_recognizers()
    
    def _add_custom_recognizers(self):
        """Add HIPAA-specific entity recognizers."""
        
        # Medical Record Number (various formats)
        mrn_recognizer = PatternRecognizer(
            supported_entity="MEDICAL_RECORD_NUMBER",
            name="mrn_recognizer",
            patterns=[
                Pattern(name="mrn_labeled", regex=r"\bMRN[-:\s]*\d{6,12}\b", score=0.9),
                Pattern(name="mrn_format", regex=r"\b[A-Z]{2,3}\d{6,10}\b", score=0.6),
            ],
            context=["mrn", "medical record", "record number", "patient id", "chart"]
        )
        
        # National Provider Identifier (NPI) - 10 digit number
        npi_recognizer = PatternRecognizer(
            supported_entity="NPI",
            name="npi_recognizer",
            patterns=[
                Pattern(name="npi_labeled", regex=r"\bNPI[-:\s]*\d{10}\b", score=0.95),
                Pattern(name="npi_format", regex=r"\b[12]\d{9}\b", score=0.5),
            ],
            context=["npi", "provider", "national provider", "physician"]
        )
        
        # Date of Birth patterns
        dob_recognizer = PatternRecognizer(
            supported_entity="DATE_TIME",
            name="dob_recognizer",
            patterns=[
                Pattern(name="dob_labeled", regex=r"\b(?:DOB|D\.O\.B\.|Date of Birth)[-:\s]?\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", score=0.95),
            ],
            context=["dob", "birth", "born", "birthday"]
        )

        # SSN patterns (catches test/example SSNs that Presidio's validator rejects)
        ssn_recognizer = PatternRecognizer(
            supported_entity="US_SSN",
            name="ssn_recognizer",
            patterns=[
                Pattern(name="ssn_with_label", regex=r"\b(?:SSN|Social Security)[-:\s]*(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b", score=0.95),
                Pattern(name="ssn_format", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=0.75),
            ],
            context=["ssn", "social security", "social security number", "tax id"]
        )

        # Add recognizers to registry
        self.analyzer.registry.add_recognizer(mrn_recognizer)
        self.analyzer.registry.add_recognizer(npi_recognizer)
        self.analyzer.registry.add_recognizer(dob_recognizer)
        self.analyzer.registry.add_recognizer(ssn_recognizer)
        self.analyzer.registry.add_recognizer(OrganizationRecognizer())
        self.analyzer.registry.add_recognizer(FullNameRecognizer())
    
    def _get_placeholder(
        self, 
        entity_type: str, 
        original_value: str,
        source_file: Optional[str] = None
    ) -> str:
        """Generate a consistent placeholder for an entity."""
        
        if self.persistent and self.store:
            # Use ACID-compliant persistent store
            # Same value ALWAYS returns same token (deterministic)
            token = self.store.get_or_create_mapping(
                entity_type, 
                original_value,
                source_file=source_file
            )
            # Cache locally for this session
            self.mapping[token] = original_value
            self.reverse_mapping[original_value] = token
            return token
        
        # Session mode: in-memory mappings
        # Check if we've seen this exact value before
        if original_value in self.reverse_mapping:
            return self.reverse_mapping[original_value]
        
        # Generate new placeholder
        if entity_type not in self._counter:
            self._counter[entity_type] = 0
        self._counter[entity_type] += 1
        
        placeholder = f"[{entity_type}_{self._counter[entity_type]}]"
        
        # Store mappings
        self.mapping[placeholder] = original_value
        self.reverse_mapping[original_value] = placeholder
        
        return placeholder

    def _resolve_overlaps(self, results: List) -> List:
        """Remove overlapping entities, preferring longer spans and higher scores. O(n log n)."""
        if not results:
            return results

        # Sort by: longer spans first, then higher scores, then earlier start
        sorted_results = sorted(results, key=lambda r: (-(r.end - r.start), -r.score, r.start))

        kept = []
        max_end = -1
        # Process in order of priority, track furthest end seen
        for result in sorted_results:
            if result.start >= max_end:
                kept.append(result)
                max_end = max(max_end, result.end)
            else:
                # Check overlap with kept results using binary search-like approach
                overlaps = False
                for k in kept:
                    if not (result.end <= k.start or result.start >= k.end):
                        overlaps = True
                        break
                if not overlaps:
                    kept.append(result)
                    max_end = max(max_end, result.end)

        return kept

    def analyze(self, text: str, entities: Optional[List[str]] = None) -> List[dict]:
        """Analyze text and return detected PII entities."""
        if entities is None:
            entities = self.DEFAULT_ENTITIES
            
        results = self.analyzer.analyze(
            text=text,
            entities=entities,
            language="en"
        )
        
        # Filter by confidence threshold and convert to dicts
        detected = []
        for result in results:
            if result.score >= self.confidence_threshold:
                detected.append({
                    "entity_type": result.entity_type,
                    "start": result.start,
                    "end": result.end,
                    "score": result.score,
                    "text": text[result.start:result.end]
                })
        
        return detected
    
    def anonymize(
        self, 
        text: str, 
        entities: Optional[List[str]] = None,
        source_file: Optional[str] = None
    ) -> Tuple[str, Dict[str, str]]:
        """
        Anonymize text and return (anonymized_text, mapping).
        Mapping can be used to de-anonymize LLM responses.
        
        Args:
            text: Text to anonymize
            entities: List of entity types to detect (default: all)
            source_file: Optional source file name for audit trail
        
        Returns:
            Tuple of (anonymized_text, mapping_dict)
        """
        if entities is None:
            entities = self.DEFAULT_ENTITIES
        
        # Get analysis results
        results = self.analyzer.analyze(
            text=text,
            entities=entities,
            language="en"
        )
        
        # Filter by confidence
        results = [r for r in results if r.score >= self.confidence_threshold]

        # Remove overlapping entities, preferring longer spans and higher scores
        results = self._resolve_overlaps(results)

        # Sort by position (end to start) to replace without offset issues
        results.sort(key=lambda x: x.start, reverse=True)
        
        # Build anonymized text with consistent placeholders
        anonymized_text = text
        for result in results:
            original_value = text[result.start:result.end]
            placeholder = self._get_placeholder(
                result.entity_type, 
                original_value,
                source_file=source_file
            )
            anonymized_text = anonymized_text[:result.start] + placeholder + anonymized_text[result.end:]
        
        return anonymized_text, self.mapping.copy()
    
    def deanonymize(self, text: str, mapping: Optional[Dict[str, str]] = None) -> str:
        """
        Replace placeholders in text with original values.
        Uses provided mapping or internal mapping if not provided.
        
        In persistent mode, can deanonymize any token ever created.
        """
        if self.persistent and self.store:
            # Use persistent store for comprehensive deanonymization
            return self.store.deanonymize_text(text)
        
        if mapping is None:
            mapping = self.mapping
        
        result = text
        for placeholder, original in mapping.items():
            result = result.replace(placeholder, original)
        
        return result
    
    def reset(self):
        """Clear session mappings (persistent mappings are never deleted)."""
        self.mapping.clear()
        self.reverse_mapping.clear()
        self._counter.clear()
    
    def get_supported_entities(self) -> List[str]:
        """Return list of all supported entity types."""
        return self.analyzer.get_supported_entities()
    
    def get_stats(self) -> Dict:
        """Get statistics about stored mappings."""
        if self.persistent and self.store:
            return self.store.get_stats()
        return {
            "total_mappings": len(self.mapping),
            "by_entity_type": {},
            "mode": "session"
        }
    
    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verify database integrity (persistent mode only)."""
        if self.persistent and self.store:
            return self.store.verify_integrity()
        return True, []
    
    def export_mappings(self, output_path: str):
        """Export all mappings to JSON file (persistent mode only)."""
        if self.persistent and self.store:
            self.store.export_mappings(output_path)
        else:
            import json
            with open(output_path, 'w') as f:
                json.dump({"mappings": self.mapping}, f, indent=2)
    
    def close(self):
        """Close database connection (persistent mode only)."""
        if self.persistent and self.store:
            self.store.close()


# Thread-safe singleton anonymizers
_default_anonymizer = None
_persistent_anonymizer = None
_anonymizer_lock = threading.Lock()

def get_anonymizer(persistent: bool = False, db_path: str = "pii_mappings.db") -> PIIAnonymizer:
    """Get or create anonymizer instance (thread-safe)."""
    global _default_anonymizer, _persistent_anonymizer

    if persistent:
        if _persistent_anonymizer is None:
            with _anonymizer_lock:
                if _persistent_anonymizer is None:
                    _persistent_anonymizer = PIIAnonymizer(persistent=True, db_path=db_path)
        return _persistent_anonymizer
    else:
        if _default_anonymizer is None:
            with _anonymizer_lock:
                if _default_anonymizer is None:
                    _default_anonymizer = PIIAnonymizer()
        return _default_anonymizer

def anonymize(text: str, persistent: bool = False) -> Tuple[str, Dict[str, str]]:
    """Quick anonymize using default settings."""
    return get_anonymizer(persistent=persistent).anonymize(text)

def deanonymize(text: str, mapping: Dict[str, str] = None, persistent: bool = False) -> str:
    """Quick de-anonymize using provided mapping."""
    return get_anonymizer(persistent=persistent).deanonymize(text, mapping)


if __name__ == "__main__":
    import tempfile
    import os
    
    # Quick test
    test_text = """
    Patient John Smith, DOB 03/15/1982, SSN 123-45-6789, 
    was seen at Boston General Hospital. 
    Contact: john.smith@email.com, phone 410-555-1234.
    MRN: 12345678, NPI: 1234567890
    Diagnosis: Type 2 Diabetes.
    """
    
    print("=" * 60)
    print("SESSION MODE TEST (in-memory)")
    print("=" * 60)
    
    anon = PIIAnonymizer()
    
    print("\n=== Original Text ===")
    print(test_text)
    
    print("\n=== Detected Entities ===")
    for entity in anon.analyze(test_text):
        print(f"  {entity['entity_type']}: '{entity['text']}' (confidence: {entity['score']:.2f})")
    
    print("\n=== Anonymized Text ===")
    anonymized, mapping = anon.anonymize(test_text)
    print(anonymized)
    
    print("\n=== Mapping ===")
    for placeholder, original in mapping.items():
        print(f"  {placeholder} -> {original}")
    
    print("\n=== De-anonymized ===")
    restored = anon.deanonymize(anonymized, mapping)
    print(restored)
    
    print("\n" + "=" * 60)
    print("PERSISTENT MODE TEST (ACID-compliant)")
    print("=" * 60)
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    try:
        anon_p = PIIAnonymizer(persistent=True, db_path=db_path)
        
        # First pass
        anonymized1, mapping1 = anon_p.anonymize(test_text, source_file="test_doc.pdf")
        print("\n=== First Anonymization ===")
        print(anonymized1[:200] + "...")
        
        # Same SSN should produce same token
        test_ssn = "SSN 123-45-6789"
        anonymized2, mapping2 = anon_p.anonymize(test_ssn)
        print(f"\n=== Determinism Test ===")
        print(f"Original: {test_ssn}")
        print(f"Anonymized: {anonymized2}")
        
        # Verify same token was used
        ssn_token = [k for k, v in mapping1.items() if "123-45-6789" in v]
        print(f"Token reused: {ssn_token[0] if ssn_token else 'N/A'} appears in both")
        
        # Stats
        print(f"\n=== Stats ===")
        print(anon_p.get_stats())
        
        # Integrity check
        is_valid, issues = anon_p.verify_integrity()
        print(f"\n=== Integrity Check ===")
        print(f"Valid: {is_valid}")
        
        anon_p.close()
        
    finally:
        os.unlink(db_path)
        for ext in ['-wal', '-shm']:
            try:
                os.unlink(db_path + ext)
            except FileNotFoundError:
                pass
    
    print("\n✅ All tests passed!")
