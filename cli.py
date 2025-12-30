#!/usr/bin/env python3
"""
PII Anonymizer CLI
Command-line tool for anonymizing files before sending to LLMs like Claude Code.

Usage:
    # Anonymize a file
    python cli.py anonymize document.pdf -o document_safe.txt
    
    # Deanonymize LLM response
    python cli.py deanonymize response.txt -o response_final.txt
    
    # Check what PII would be detected
    python cli.py analyze document.pdf
    
    # View stored mappings
    python cli.py mappings
    
    # Export mappings to JSON
    python cli.py export mappings.json
    
    # Verify database integrity
    python cli.py verify
"""

import argparse
import sys
from pathlib import Path
from typing import Optional
import json

from anonymizer import PIIAnonymizer
from file_processor import process_file, FileProcessorFactory, save_anonymized_file
from db_store import PIIMappingStore


def cmd_anonymize(args):
    """Anonymize a file or text input."""
    anonymizer = PIIAnonymizer(
        persistent=True,
        db_path=args.db,
        confidence_threshold=args.confidence
    )
    
    if args.input:
        # File input
        if not Path(args.input).exists():
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            return 1
        
        print(f"Processing: {args.input}")
        text, file_type, original_bytes = process_file(args.input)
        source_file = Path(args.input).name
    else:
        # Stdin input
        print("Reading from stdin (Ctrl+D to finish)...")
        text = sys.stdin.read()
        source_file = "stdin"
        file_type = ".txt"
    
    # Anonymize
    anonymized_text, mapping = anonymizer.anonymize(text, source_file=source_file)
    
    # Output
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(anonymized_text)
        print(f"Anonymized output written to: {output_path}")
    else:
        print("\n" + "=" * 60)
        print("ANONYMIZED OUTPUT:")
        print("=" * 60)
        print(anonymized_text)
    
    # Show summary
    print(f"\n--- Summary ---")
    print(f"PII items replaced: {len(mapping)}")
    for token, original in mapping.items():
        entity_type = token.split('_')[0].replace('[', '')
        print(f"  {entity_type}: {original[:20]}{'...' if len(original) > 20 else ''} → {token}")
    
    anonymizer.close()
    return 0


def cmd_deanonymize(args):
    """Deanonymize text (restore original PII values)."""
    anonymizer = PIIAnonymizer(
        persistent=True,
        db_path=args.db
    )
    
    if args.input:
        with open(args.input, 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        print("Reading from stdin (Ctrl+D to finish)...")
        text = sys.stdin.read()
    
    # Deanonymize
    restored_text = anonymizer.deanonymize(text)
    
    # Output
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(restored_text)
        print(f"Restored output written to: {args.output}")
    else:
        print("\n" + "=" * 60)
        print("RESTORED OUTPUT:")
        print("=" * 60)
        print(restored_text)
    
    anonymizer.close()
    return 0


def cmd_analyze(args):
    """Analyze a file for PII without anonymizing."""
    anonymizer = PIIAnonymizer(confidence_threshold=args.confidence)
    
    if args.input:
        text, file_type, _ = process_file(args.input)
        print(f"Analyzing: {args.input} ({file_type})")
    else:
        print("Reading from stdin (Ctrl+D to finish)...")
        text = sys.stdin.read()
    
    # Analyze
    entities = anonymizer.analyze(text)
    
    print(f"\n--- Detected PII ({len(entities)} items) ---")
    
    if not entities:
        print("No PII detected.")
        return 0
    
    # Group by type
    by_type = {}
    for entity in entities:
        etype = entity['entity_type']
        if etype not in by_type:
            by_type[etype] = []
        by_type[etype].append(entity)
    
    for etype, items in sorted(by_type.items()):
        print(f"\n{etype} ({len(items)} found):")
        for item in items:
            print(f"  • \"{item['text']}\" (confidence: {item['score']:.0%})")
    
    return 0


def cmd_mappings(args):
    """View stored mappings."""
    store = PIIMappingStore(args.db)
    
    mappings = store.get_all_mappings()
    stats = store.get_stats()
    
    print(f"--- Mapping Store: {args.db} ---")
    print(f"Total mappings: {stats['total_mappings']}")
    print(f"Documents processed: {stats['total_documents_processed']}")
    
    if stats['by_entity_type']:
        print("\nBy entity type:")
        for etype, count in sorted(stats['by_entity_type'].items()):
            print(f"  {etype}: {count}")
    
    if args.verbose and mappings:
        print("\n--- All Mappings ---")
        for m in mappings:
            print(f"  {m['token']} (created: {m['created_at'][:10]})")
    
    store.close()
    return 0


def cmd_export(args):
    """Export mappings to JSON file."""
    store = PIIMappingStore(args.db)
    
    output_path = args.output or "pii_mappings_export.json"
    store.export_mappings(output_path)
    
    print(f"Mappings exported to: {output_path}")
    store.close()
    return 0


def cmd_verify(args):
    """Verify database integrity."""
    store = PIIMappingStore(args.db)
    
    print(f"Verifying database: {args.db}")
    is_valid, issues = store.verify_integrity()
    
    if is_valid:
        print("✅ Database integrity verified - all checks passed")
    else:
        print("❌ Database integrity issues found:")
        for issue in issues:
            print(f"  • {issue}")
    
    store.close()
    return 0 if is_valid else 1


def cmd_serve(args):
    """Start the API server (requires FastAPI)."""
    try:
        import uvicorn
        from api_server import app
        
        print(f"Starting PII Anonymizer API server on {args.host}:{args.port}")
        print(f"Database: {args.db}")
        print(f"API docs: http://{args.host}:{args.port}/docs")
        
        uvicorn.run(app, host=args.host, port=args.port)
    except ImportError as e:
        print(f"Error: {e}")
        print("Install required packages: pip install fastapi uvicorn")
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="PII Anonymizer - Protect sensitive data before sending to LLMs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Anonymize a PDF and save as text
  %(prog)s anonymize patient_record.pdf -o safe_record.txt
  
  # Pipe text through anonymizer
  cat document.txt | %(prog)s anonymize > safe_document.txt
  
  # Deanonymize Claude's response
  %(prog)s deanonymize claude_response.txt -o final_response.txt
  
  # Start API server for Claude Code integration
  %(prog)s serve --port 8000
        """
    )
    
    parser.add_argument(
        "--db", 
        default="pii_mappings.db",
        help="Path to SQLite database (default: pii_mappings.db)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # anonymize command
    p_anon = subparsers.add_parser("anonymize", help="Anonymize a file or text")
    p_anon.add_argument("input", nargs="?", help="Input file (or stdin if not provided)")
    p_anon.add_argument("-o", "--output", help="Output file (or stdout if not provided)")
    p_anon.add_argument("-c", "--confidence", type=float, default=0.7,
                        help="Confidence threshold 0.0-1.0 (default: 0.7)")
    p_anon.set_defaults(func=cmd_anonymize)
    
    # deanonymize command
    p_deanon = subparsers.add_parser("deanonymize", help="Restore original PII values")
    p_deanon.add_argument("input", nargs="?", help="Input file (or stdin if not provided)")
    p_deanon.add_argument("-o", "--output", help="Output file (or stdout if not provided)")
    p_deanon.set_defaults(func=cmd_deanonymize)
    
    # analyze command
    p_analyze = subparsers.add_parser("analyze", help="Analyze file for PII without changing it")
    p_analyze.add_argument("input", nargs="?", help="Input file (or stdin if not provided)")
    p_analyze.add_argument("-c", "--confidence", type=float, default=0.7,
                           help="Confidence threshold 0.0-1.0 (default: 0.7)")
    p_analyze.set_defaults(func=cmd_analyze)
    
    # mappings command
    p_mappings = subparsers.add_parser("mappings", help="View stored PII mappings")
    p_mappings.add_argument("-v", "--verbose", action="store_true",
                            help="Show all mapping tokens")
    p_mappings.set_defaults(func=cmd_mappings)
    
    # export command
    p_export = subparsers.add_parser("export", help="Export mappings to JSON")
    p_export.add_argument("output", nargs="?", help="Output JSON file")
    p_export.set_defaults(func=cmd_export)
    
    # verify command
    p_verify = subparsers.add_parser("verify", help="Verify database integrity")
    p_verify.set_defaults(func=cmd_verify)
    
    # serve command
    p_serve = subparsers.add_parser("serve", help="Start API server")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    p_serve.set_defaults(func=cmd_serve)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
