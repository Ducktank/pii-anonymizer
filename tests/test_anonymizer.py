"""Tests for PII Anonymizer core functionality."""

import pytest
import tempfile
import os
from anonymizer import PIIAnonymizer


class TestPIIAnonymizer:
    """Test PIIAnonymizer class."""

    @pytest.fixture
    def anonymizer(self):
        return PIIAnonymizer(confidence_threshold=0.7)

    @pytest.fixture
    def persistent_anonymizer(self, tmp_path):
        db_path = tmp_path / "test_pii.db"
        return PIIAnonymizer(persistent=True, db_path=str(db_path))

    def test_detect_person(self, anonymizer):
        text = "Patient John Smith needs assistance"
        entities = anonymizer.analyze(text)
        types = [e["entity_type"] for e in entities]
        assert "PERSON" in types

    def test_detect_ssn(self, anonymizer):
        text = "SSN 123-45-6789"
        entities = anonymizer.analyze(text)
        types = [e["entity_type"] for e in entities]
        assert "US_SSN" in types

    def test_detect_email(self, anonymizer):
        text = "Contact: john@example.com"
        entities = anonymizer.analyze(text)
        types = [e["entity_type"] for e in entities]
        assert "EMAIL_ADDRESS" in types

    def test_detect_phone(self, anonymizer):
        text = "Contact phone number: 410-555-1234 for assistance"
        entities = anonymizer.analyze(text)
        types = [e["entity_type"] for e in entities]
        assert "PHONE_NUMBER" in types

    def test_detect_mrn(self, anonymizer):
        text = "MRN: 12345678"
        entities = anonymizer.analyze(text)
        types = [e["entity_type"] for e in entities]
        assert "MEDICAL_RECORD_NUMBER" in types

    def test_detect_npi(self, anonymizer):
        text = "NPI: 1234567890"
        entities = anonymizer.analyze(text)
        types = [e["entity_type"] for e in entities]
        assert "NPI" in types

    def test_detect_organization(self, anonymizer):
        text = "Seen at Boston General Hospital"
        entities = anonymizer.analyze(text)
        types = [e["entity_type"] for e in entities]
        assert "ORGANIZATION" in types

    def test_anonymize_returns_mapping(self, anonymizer):
        text = "Patient John Smith"
        anonymized, mapping = anonymizer.anonymize(text)
        assert len(mapping) > 0
        assert "[PERSON_" in anonymized

    def test_deanonymize_restores_original(self, anonymizer):
        original = "Patient John Smith, SSN 123-45-6789"
        anonymized, mapping = anonymizer.anonymize(original)
        restored = anonymizer.deanonymize(anonymized, mapping)
        assert "John Smith" in restored
        assert "123-45-6789" in restored

    def test_persistent_deterministic_tokens(self, persistent_anonymizer):
        text1 = "SSN 123-45-6789"
        text2 = "SSN 123-45-6789"
        _, mapping1 = persistent_anonymizer.anonymize(text1)
        _, mapping2 = persistent_anonymizer.anonymize(text2)
        tokens1 = set(mapping1.keys())
        tokens2 = set(mapping2.keys())
        assert tokens1 == tokens2

    def test_persistent_survives_restart(self, tmp_path):
        db_path = tmp_path / "test_pii.db"
        anon1 = PIIAnonymizer(persistent=True, db_path=str(db_path))
        text = "SSN 222-33-4444"
        _, mapping1 = anon1.anonymize(text)
        token1 = list(mapping1.keys())[0]
        anon1.close()

        anon2 = PIIAnonymizer(persistent=True, db_path=str(db_path))
        _, mapping2 = anon2.anonymize(text)
        token2 = list(mapping2.keys())[0]
        anon2.close()
        assert token1 == token2

    def test_integrity_check_passes(self, persistent_anonymizer):
        persistent_anonymizer.anonymize("Test data with SSN 111-22-3333")
        is_valid, issues = persistent_anonymizer.verify_integrity()
        assert is_valid
        assert len(issues) == 0

    def test_reset_clears_session_mappings(self, anonymizer):
        anonymizer.anonymize("Patient John Smith")
        assert len(anonymizer.mapping) > 0
        anonymizer.reset()
        assert len(anonymizer.mapping) == 0
