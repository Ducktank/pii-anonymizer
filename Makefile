# PII Anonymizer Makefile
PYTHON := /Library/Frameworks/Python.framework/Versions/3.12/bin/python3
PIP := /Library/Frameworks/Python.framework/Versions/3.12/bin/pip

.PHONY: install setup test run-api run-web run-test clean lint help

help:
	@echo "PII Anonymizer Commands:"
	@echo "  make install    - Install Python dependencies"
	@echo "  make setup      - Full setup (install + spaCy model)"
	@echo "  make test       - Run pytest suite"
	@echo "  make run-api    - Start FastAPI server on port 8000"
	@echo "  make run-web    - Start Streamlit web UI"
	@echo "  make run-test   - Run built-in anonymizer tests"
	@echo "  make verify     - Verify database integrity"
	@echo "  make clean      - Remove cache files and test DBs"
	@echo "  make lint       - Run ruff linter (if installed)"

install:
	$(PIP) install -r requirements.txt

setup: install
	$(PYTHON) -m spacy download en_core_web_lg

test:
	$(PYTHON) -m pytest tests/ -v

test-quick:
	$(PYTHON) -m pytest tests/ -v -x --tb=short

run-api:
	$(PYTHON) cli.py serve --port 8000

run-web:
	$(PYTHON) -m streamlit run app.py

run-test:
	$(PYTHON) anonymizer.py

verify:
	$(PYTHON) cli.py verify

clean:
	rm -rf __pycache__ .pytest_cache tests/__pycache__
	rm -f *.db *.db-wal *.db-shm
	find . -name "*.pyc" -delete

lint:
	$(PYTHON) -m ruff check . || true
