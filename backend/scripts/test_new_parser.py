#!/usr/bin/env python3
"""
Test script for new parser architecture
Demonstrates parsing, normalization, and enrichment
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.parsers.parser_factory import ParserFactory
from app.parsers.zscaler_parser_v2 import ZscalerParserV2
from app.services.enrichment_service import EnrichmentService
import json


def test_zscaler_csv_parsing():
    """Test Zscaler CSV format parsing"""
    print("=" * 80)
    print("TEST: Zscaler CSV Format Parsing")
    print("=" * 80)
    
    # Sample Zscaler log line (CSV format)
    sample_log = '"Mon Oct 31 09:22:55 2025","privilege.escalation@company.com","HTTP","company-portal.com/admin/users","Blocked","Web Browsing","Internet Services","384","0","192","0","Security Threat","Privilege Escalation","Hacking","PrivEsc","Attack","Privilege.Escalation.Attempt","91","None","new-york","Support","192.168.1.215","203.0.113.10","POST","403","Mozilla/5.0 (Windows NT 10.0; Win64; x64)","None","Block_PrivEsc","ThreatFilter","None","None","None","privilege.escalation@company.com","LAPTOP-PE001"'
    
    # Create parser
    parser = ZscalerParserV2()
    
    # Process line (full pipeline)
    normalized_event = parser.process_line(sample_log)
    
    if normalized_event:
        print("\n✅ Parsing successful!")
        print(f"\nObserver: {normalized_event.observer_vendor} - {normalized_event.observer_product}")
        print(f"Timestamp: {normalized_event.timestamp}")
        print(f"Event Category: {normalized_event.event.category}")
        print(f"Event Action: {normalized_event.event.action}")
        print(f"Event Outcome: {normalized_event.event.outcome}")
        print(f"Severity: {normalized_event.event.severity}")
        
        if normalized_event.user:
            print(f"\nUser: {normalized_event.user.name}")
            print(f"Department: {normalized_event.user.department}")
        
        if normalized_event.source:
            print(f"\nSource IP: {normalized_event.source.ip}")
            print(f"Source Bytes: {normalized_event.source.bytes}")
        
        if normalized_event.destination:
            print(f"\nDestination IP: {normalized_event.destination.ip}")
            print(f"Destination Domain: {normalized_event.destination.domain}")
        
        if normalized_event.url:
            print(f"\nURL: {normalized_event.url.original}")
            print(f"Domain: {normalized_event.url.domain}")
        
        if normalized_event.http:
            print(f"\nHTTP Method: {normalized_event.http.request_method}")
            print(f"HTTP Status: {normalized_event.http.response_status_code}")
        
        print(f"\nRisk Score: {normalized_event.risk_score}")
        
        # Convert to dict
        print("\n" + "=" * 80)
        print("Normalized Event as JSON:")
        print("=" * 80)
        print(json.dumps(normalized_event.to_dict(), indent=2, default=str))
        
    else:
        print("\n❌ Parsing failed!")
    
    return normalized_event


def test_enrichment():
    """Test enrichment service"""
    print("\n\n" + "=" * 80)
    print("TEST: Enrichment Service")
    print("=" * 80)
    
    # First parse a log
    sample_log = '"Mon Oct 31 09:22:55 2025","test.user@company.com","HTTP","malicious-site.com/payload","Blocked","Web Browsing","Internet Services","384","0","192","0","Security Threat","Malware","Hacking","Trojan","Attack","Trojan.Generic","95","None","new-york","IT","192.168.1.100","203.0.113.50","GET","403","Mozilla/5.0","None","Block_Malware","ThreatFilter","None","None","None","test.user@company.com","DESKTOP-001"'
    
    parser = ZscalerParserV2()
    event = parser.process_line(sample_log)
    
    if event:
        print(f"\n📊 Before Enrichment:")
        print(f"Risk Score: {event.risk_score}")
        print(f"Source Country: {event.source.geo_country if event.source else 'None'}")
        
        # Enrich
        enrichment_service = EnrichmentService()
        enriched_event = enrichment_service.enrich_event(event)
        
        print(f"\n✨ After Enrichment:")
        print(f"Risk Score: {enriched_event.risk_score}")
        print(f"Risk Score (normalized): {enriched_event.risk_score_norm}")
        print(f"Source Country: {enriched_event.source.geo_country if enriched_event.source else 'None'}")


def test_parser_factory():
    """Test parser factory auto-detection"""
    print("\n\n" + "=" * 80)
    print("TEST: Parser Factory Auto-Detection")
    print("=" * 80)
    
    # Get available parsers
    parsers = ParserFactory.get_available_parsers()
    print(f"\n📋 Available Parsers: {len(parsers)}")
    for parser_info in parsers:
        print(f"  - {parser_info['name']}: {parser_info['vendor']} {parser_info['product']} ({parser_info['log_type']})")
    
    # Get parser by name
    print("\n🔍 Get parser by name (zscaler):")
    parser = ParserFactory.get_parser_by_name('zscaler')
    if parser:
        print(f"  ✅ Got parser: {parser.__class__.__name__}")
    else:
        print(f"  ❌ Parser not found")
    
    # Test auto-detection
    print("\n🔍 Test auto-detection:")
    sample_lines = [
        '"Mon Oct 31 09:22:55 2025","user@company.com","HTTP","example.com","Allowed","Web Browsing","Internet Services","384","0","192","0","Business","None","None","None","None","UNKNOWN","10","None","new-york","IT","192.168.1.100","203.0.113.50","GET","200","Mozilla/5.0","None","Allow_All","Default","None","None","None","user@company.com","DESKTOP-001"'
    ]
    
    for parser_class in ParserFactory._parsers:
        parser = parser_class()
        detected = parser.detect_format(sample_lines)
        print(f"  {parser.__class__.__name__}: {'✅ Detected' if detected else '❌ Not detected'}")


def test_correlation_keys():
    """Test correlation key extraction"""
    print("\n\n" + "=" * 80)
    print("TEST: Correlation Keys")
    print("=" * 80)
    
    sample_log = '"Mon Oct 31 09:22:55 2025","john.doe@company.com","HTTP","example.com","Allowed","Web Browsing","Internet Services","384","0","192","0","Business","None","None","None","None","UNKNOWN","10","None","new-york","IT","192.168.1.100","203.0.113.50","GET","200","Mozilla/5.0","None","Allow_All","Default","None","None","None","john.doe@company.com","DESKTOP-JD001"'
    
    parser = ZscalerParserV2()
    event = parser.process_line(sample_log)
    
    if event:
        correlation_keys = event.get_correlation_keys()
        print("\n🔗 Correlation Keys (for UEBA and lateral movement detection):")
        for key, value in correlation_keys.items():
            print(f"  {key}: {value}")


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("CyberDucky Mini SIEM - New Parser Architecture Tests")
    print("=" * 80)
    
    try:
        # Test 1: Basic parsing
        test_zscaler_csv_parsing()
        
        # Test 2: Enrichment
        test_enrichment()
        
        # Test 3: Parser factory
        test_parser_factory()
        
        # Test 4: Correlation keys
        test_correlation_keys()
        
        print("\n\n" + "=" * 80)
        print("✅ All tests completed!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

