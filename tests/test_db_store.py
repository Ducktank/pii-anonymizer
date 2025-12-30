"""Tests for ACID-compliant PII Mapping Store."""

import pytest
from db_store import PIIMappingStore


class TestPIIMappingStore:
    """Test PIIMappingStore class."""

    @pytest.fixture
    def store(self, tmp_path):
        db_path = tmp_path / "test_store.db"
        s = PIIMappingStore(str(db_path))
        yield s
        s.close()

    def test_create_mapping(self, store):
        token = store.get_or_create_mapping("US_SSN", "123-45-6789")
        assert token.startswith("[US_SSN_")
        assert token.endswith("]")

    def test_deterministic_mapping(self, store):
        token1 = store.get_or_create_mapping("US_SSN", "123-45-6789")
        token2 = store.get_or_create_mapping("US_SSN", "123-45-6789")
        assert token1 == token2

    def test_different_values_different_tokens(self, store):
        token1 = store.get_or_create_mapping("US_SSN", "111-22-3333")
        token2 = store.get_or_create_mapping("US_SSN", "444-55-6666")
        assert token1 != token2

    def test_lookup_token(self, store):
        token = store.get_or_create_mapping("PERSON", "John Smith")
        result = store.lookup_token(token)
        assert result["original_value"] == "John Smith"
        assert result["entity_type"] == "PERSON"

    def test_lookup_original(self, store):
        token = store.get_or_create_mapping("EMAIL_ADDRESS", "test@example.com")
        found = store.lookup_original("EMAIL_ADDRESS", "test@example.com")
        assert found == token

    def test_deanonymize_text(self, store):
        token = store.get_or_create_mapping("PERSON", "Jane Doe")
        text = f"Patient {token} arrived"
        restored = store.deanonymize_text(text)
        assert "Jane Doe" in restored

    def test_get_all_mappings(self, store):
        store.get_or_create_mapping("PERSON", "Alice")
        store.get_or_create_mapping("PERSON", "Bob")
        mappings = store.get_all_mappings()
        assert len(mappings) == 2

    def test_get_stats(self, store):
        store.get_or_create_mapping("PERSON", "Alice")
        store.get_or_create_mapping("US_SSN", "123-45-6789")
        stats = store.get_stats()
        assert stats["total_mappings"] == 2
        assert "PERSON" in stats["by_entity_type"]
        assert "US_SSN" in stats["by_entity_type"]

    def test_verify_integrity_passes(self, store):
        store.get_or_create_mapping("PERSON", "Test Person")
        is_valid, issues = store.verify_integrity()
        assert is_valid
        assert len(issues) == 0

    def test_export_mappings(self, store, tmp_path):
        store.get_or_create_mapping("PERSON", "Export Test")
        export_path = tmp_path / "export.json"
        store.export_mappings(str(export_path))
        assert export_path.exists()

    def test_persistence_across_connections(self, tmp_path):
        db_path = tmp_path / "persist.db"
        store1 = PIIMappingStore(str(db_path))
        token1 = store1.get_or_create_mapping("PERSON", "Persistent Person")
        store1.close()

        store2 = PIIMappingStore(str(db_path))
        token2 = store2.get_or_create_mapping("PERSON", "Persistent Person")
        store2.close()
        assert token1 == token2

    def test_source_file_tracking(self, store):
        store.get_or_create_mapping("PERSON", "Source Test", source_file="test.pdf")
        mappings = store.get_all_mappings()
        assert any(m.get("source_file") == "test.pdf" for m in mappings)
