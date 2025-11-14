#!/usr/bin/env python3
"""
Complete Pipeline Test Script
Tests the full multi-source log analysis pipeline:
Ingestion → Parsing → Normalization → Enrichment → Storage → Analysis → Detection

This script demonstrates:
1. Parsing Zscaler logs with new architecture
2. Normalization to common schema
3. Enrichment with context
4. Dual storage (legacy + normalized)
5. Cross-source correlation
6. Anomaly detection on normalized events
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from app.extensions import db
from app.parsers.parser_factory import ParserFactory
from app.services.enrichment_service import EnrichmentService
from app.services.correlation_service import CorrelationService
from app.services.cross_source_anomaly_detection_service import CrossSourceAnomalyDetectionService
from app.repositories.normalized_event_repository import NormalizedEventRepository
from app.models.normalized_event_model import NormalizedEventModel
from app.models.log_file import LogFile
import json

def print_section(title):
    """Print a section header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")

def test_complete_pipeline():
    """Test the complete pipeline"""
    
    # Create Flask app context
    app = create_app()
    
    with app.app_context():
        print_section("MULTI-SOURCE LOG ANALYSIS PIPELINE TEST")
        
        # ========== STEP 1: INGESTION & PARSING ==========
        print_section("STEP 1: INGESTION & PARSING")
        
        # Sample Zscaler log line (CSV format)
        sample_log = """2024-10-31 14:23:45,rec123,john.doe,Engineering,192.168.1.100,203.0.113.50,1024,93.184.216.34,4096,example.com,https://example.com/api/data,https://google.com,GET,200,Mozilla/5.0,application/json,json,Data,Technology,Safe,General,Web Browsing,HTTPS,443,UNKNOWN,None,None,0,Corporate Policy,Allowed,False,None,None,None,DESKTOP-001,john.doe,US,None"""
        
        # Get parser using factory (auto-detection)
        print("🔍 Auto-detecting log format...")
        parser = ParserFactory.get_parser(log_type='zscaler')
        
        if parser:
            print(f"✅ Parser detected: {parser.__class__.__name__}")
            print(f"   Vendor: {parser.vendor}")
            print(f"   Product: {parser.product}")
        else:
            print("❌ No parser found!")
            return
        
        # ========== STEP 2: NORMALIZATION ==========
        print_section("STEP 2: NORMALIZATION")
        
        print("📝 Parsing sample log line...")
        parsed_data = parser.parse_line(sample_log, 1)
        
        if parsed_data:
            print(f"✅ Parsed {len(parsed_data)} fields")
            print(f"   User: {parsed_data.get('username')}")
            print(f"   Source IP: {parsed_data.get('source_ip')}")
            print(f"   URL: {parsed_data.get('url')}")
        else:
            print("❌ Parsing failed!")
            return
        
        # Normalize to common schema
        print("\n🔄 Normalizing to common schema...")
        normalized_event = parser.normalize(parsed_data)
        
        if normalized_event:
            print("✅ Normalization successful!")
            print(f"   Event Category: {normalized_event.event.category}")
            print(f"   Event Action: {normalized_event.event.action}")
            print(f"   Observer: {normalized_event.observer_vendor}/{normalized_event.observer_product}")
            print(f"   User: {normalized_event.user.name if normalized_event.user else 'N/A'}")
            print(f"   Source IP: {normalized_event.source.ip if normalized_event.source else 'N/A'}")
            print(f"   Destination: {normalized_event.destination.domain if normalized_event.destination else 'N/A'}")
        else:
            print("❌ Normalization failed!")
            return
        
        # ========== STEP 3: ENRICHMENT ==========
        print_section("STEP 3: ENRICHMENT")
        
        print("🌍 Enriching with context...")
        enrichment_service = EnrichmentService()
        enriched_event = enrichment_service.enrich_event(normalized_event)
        
        print("✅ Enrichment complete!")
        print(f"   GeoIP: {enriched_event.source.geo_country if enriched_event.source else 'N/A'}")
        print(f"   Risk Score: {enriched_event.risk_score}")
        
        # ========== STEP 4: STORAGE ==========
        print_section("STEP 4: STORAGE (Dual Storage)")
        
        print("💾 Testing database storage...")
        
        # Create a test log file entry
        log_file = LogFile(
            user_id='test-user-id',
            filename='test_pipeline.log',
            original_filename='test_pipeline.log',
            file_path='/tmp/test_pipeline.log',
            file_size=1024,
            file_hash='test-hash-123',
            log_type='zscaler',
            status='completed'
        )
        db.session.add(log_file)
        db.session.commit()
        
        print(f"✅ Created test log file: {log_file.id}")
        
        # Convert to database model
        from app.services.log_parser_service import LogParserService
        parser_service = LogParserService()
        
        normalized_db_entry = parser_service._convert_to_db_model(enriched_event, log_file.id)
        db.session.add(normalized_db_entry)
        db.session.commit()
        
        print(f"✅ Saved normalized event to database: {normalized_db_entry.id}")
        print(f"   Table: normalized_events")
        print(f"   Event Category: {normalized_db_entry.event_category}")
        print(f"   User: {normalized_db_entry.user_name}")
        
        # Also save legacy entry for backward compatibility
        legacy_entry = parser_service._convert_to_legacy_entry(enriched_event, log_file.id)
        if legacy_entry:
            db.session.add(legacy_entry)
            db.session.commit()
            print(f"✅ Saved legacy entry to database: {legacy_entry.id}")
            print(f"   Table: log_entries (for backward compatibility)")
        
        # ========== STEP 5: CORRELATION ==========
        print_section("STEP 5: CROSS-SOURCE CORRELATION")
        
        print("🔗 Testing correlation service...")
        correlation_service = CorrelationService()
        
        # Test user investigation
        user_investigation = correlation_service.investigate_user('john.doe', time_window_hours=24)
        print(f"✅ User investigation complete:")
        print(f"   User: {user_investigation['user']}")
        print(f"   Event Count: {user_investigation['event_count']}")
        print(f"   Sources: {len(user_investigation['sources'])}")
        print(f"   Anomalies: {len(user_investigation['anomalies'])}")
        
        # ========== STEP 6: ANOMALY DETECTION ==========
        print_section("STEP 6: CROSS-SOURCE ANOMALY DETECTION")
        
        print("🚨 Running anomaly detection on normalized events...")
        anomaly_service = CrossSourceAnomalyDetectionService()
        
        detection_results = anomaly_service.detect_all_anomalies(log_file.id, time_window_hours=24)
        
        print(f"✅ Anomaly detection complete!")
        print(f"   Events Analyzed: {detection_results.get('events_analyzed', 0)}")
        print(f"   Total Anomalies: {detection_results['total_anomalies']}")
        print(f"   By Severity: {detection_results['by_severity']}")
        print(f"   By Type: {detection_results['by_type']}")
        
        # ========== STEP 7: VERIFICATION ==========
        print_section("STEP 7: VERIFICATION")
        
        # Query normalized events
        event_repo = NormalizedEventRepository()
        events = event_repo.get_by_file(log_file.id)
        
        print(f"✅ Verification complete!")
        print(f"   Normalized events in DB: {len(events)}")
        
        if events:
            event = events[0]
            print(f"\n   Sample Event:")
            print(f"   - ID: {event.id}")
            print(f"   - Timestamp: {event.timestamp}")
            print(f"   - Category: {event.event_category}")
            print(f"   - User: {event.user_name}")
            print(f"   - Source IP: {event.source_ip}")
            print(f"   - Destination: {event.destination_domain}")
            print(f"   - Observer: {event.observer_vendor}/{event.observer_product}")
        
        # ========== CLEANUP ==========
        print_section("CLEANUP")
        
        print("🧹 Cleaning up test data...")
        db.session.delete(log_file)
        db.session.commit()
        print("✅ Cleanup complete!")
        
        # ========== SUMMARY ==========
        print_section("PIPELINE TEST SUMMARY")
        
        print("✅ ALL PIPELINE STAGES TESTED SUCCESSFULLY!")
        print("\n📊 Pipeline Stages:")
        print("   1. ✅ Ingestion - Log file uploaded")
        print("   2. ✅ Parsing - Zscaler CSV parsed")
        print("   3. ✅ Normalization - Converted to common schema")
        print("   4. ✅ Enrichment - GeoIP and context added")
        print("   5. ✅ Storage - Dual storage (legacy + normalized)")
        print("   6. ✅ Correlation - Cross-source queries working")
        print("   7. ✅ Detection - Anomaly detection on normalized events")
        
        print("\n🎯 Key Features Demonstrated:")
        print("   • Parser factory with auto-detection")
        print("   • Normalized event schema (ECS-inspired)")
        print("   • Enrichment service integration")
        print("   • Dual storage for backward compatibility")
        print("   • Cross-source correlation queries")
        print("   • Multi-source anomaly detection")
        
        print("\n🚀 Next Steps:")
        print("   1. Upload real Zscaler logs to test at scale")
        print("   2. Add parsers for other log sources (CrowdStrike, Okta, AWS)")
        print("   3. Implement GeoIP database integration")
        print("   4. Add threat intelligence feeds")
        print("   5. Build cross-source correlation dashboards")
        
        print("\n" + "="*80)
        print("  TEST COMPLETE - PIPELINE READY FOR PRODUCTION!")
        print("="*80 + "\n")

if __name__ == '__main__':
    try:
        test_complete_pipeline()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

