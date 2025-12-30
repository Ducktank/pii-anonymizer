"""Tests for file processing functionality."""

import pytest
from file_processor import (
    FileProcessorFactory,
    TextProcessor,
    process_file,
)


class TestFileProcessorFactory:
    """Test FileProcessorFactory class."""

    def test_get_processor_txt(self):
        processor = FileProcessorFactory.get_processor("test.txt")
        assert isinstance(processor, TextProcessor)

    def test_get_processor_md(self):
        processor = FileProcessorFactory.get_processor("readme.md")
        assert processor is not None

    def test_is_supported_txt(self):
        assert FileProcessorFactory.is_supported("doc.txt")

    def test_is_supported_pdf(self):
        assert FileProcessorFactory.is_supported("doc.pdf")

    def test_is_not_supported(self):
        assert not FileProcessorFactory.is_supported("doc.xyz")

    def test_supported_types(self):
        types = FileProcessorFactory.supported_types()
        assert ".txt" in types
        assert ".pdf" in types
        assert ".docx" in types

    def test_unsupported_raises(self):
        with pytest.raises(ValueError):
            FileProcessorFactory.get_processor("test.xyz")


class TestTextProcessor:
    """Test TextProcessor class."""

    def test_extract_text_utf8(self):
        processor = TextProcessor()
        content = "Hello world".encode("utf-8")
        text = processor.extract_text(content)
        assert text == "Hello world"

    def test_extract_text_cp1252(self):
        processor = TextProcessor()
        content = "Hello world with special chars".encode("cp1252")
        text = processor.extract_text(content)
        assert "Hello world" in text

    def test_reconstruct(self):
        processor = TextProcessor()
        result = processor.reconstruct(b"original", "anonymized")
        assert result == b"anonymized"


class TestProcessFile:
    """Test process_file function."""

    def test_process_text_file(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("Patient John Smith, SSN 123-45-6789")
        text, file_type, content = process_file(test_file)
        assert "John Smith" in text
        assert file_type == ".txt"
        assert len(content) > 0

    def test_process_nonexistent_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            process_file(tmp_path / "nonexistent.txt")
