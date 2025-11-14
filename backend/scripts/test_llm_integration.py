#!/usr/bin/env python3
"""
Test LLM Integration
Tests Ollama service, LLM analysis service, and all LLM features
"""
import sys
import os
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.ollama_service import OllamaService
from app.services.llm_analysis_service import LLMAnalysisService
from app.models.log_entry import LogEntry
from app.models.anomaly import Anomaly

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MockLogEntry:
    """Mock LogEntry for testing"""
    def __init__(self):
        self.id = "test-log-entry-1"
        self.username = "john.doe"
        self.url = "http://malware-site.com/payload.exe"
        self.hostname = "malware-site.com"
        self.url_category = "Malware"
        self.action = "blocked"
        self.threat_name = "Trojan.Generic"
        self.risk_score = 85
        self.response_code = 403
        self.destination_bytes = 1024000
        self.timestamp = datetime.utcnow()


class MockAnomaly:
    """Mock Anomaly for testing"""
    def __init__(self):
        self.id = "test-anomaly-1"
        self.anomaly_type = "data_exfiltration"
        self.severity = "high"
        self.title = "Unusual Data Upload Detected"
        self.description = "User uploaded 500MB to external cloud storage, 10x normal behavior"
        self.affected_user = "john.doe"
        self.affected_ip = "192.168.1.100"
        self.detection_method = "statistical"
        self.log_entry_id = "test-log-entry-1"


def test_ollama_service():
    """Test Ollama service connectivity and basic operations"""
    logger.info("\n" + "="*60)
    logger.info("TEST 1: Ollama Service")
    logger.info("="*60)
    
    ollama = OllamaService()
    
    # Test 1: Check availability
    logger.info("\n1.1 Testing Ollama availability...")
    is_available = ollama.is_available()
    if is_available:
        logger.info("✅ Ollama service is available")
    else:
        logger.error("❌ Ollama service is NOT available")
        return False
    
    # Test 2: List models
    logger.info("\n1.2 Listing available models...")
    try:
        models = ollama.list_models()
        if models:
            logger.info(f"✅ Found {len(models)} models:")
            for model in models:
                logger.info(f"   - {model.get('name', 'unknown')}")
        else:
            logger.warning("⚠️  No models found")
            return False
    except Exception as e:
        logger.error(f"❌ Error listing models: {e}")
        return False
    
    # Test 3: Simple generation
    logger.info("\n1.3 Testing text generation...")
    try:
        result = ollama.generate(
            prompt="Say 'Hello from CyberDucky!' in one sentence.",
            temperature=0.1,
            max_tokens=50
        )
        if result.get('success'):
            logger.info(f"✅ Generation successful")
            logger.info(f"   Response: {result.get('response', '')[:100]}")
        else:
            logger.error(f"❌ Generation failed: {result.get('message')}")
            return False
    except Exception as e:
        logger.error(f"❌ Error in generation: {e}")
        return False
    
    # Test 4: JSON generation
    logger.info("\n1.4 Testing JSON generation...")
    try:
        result = ollama.generate_json(
            prompt='Respond with JSON: {"status": "ok", "message": "test"}',
            temperature=0.1
        )
        if result.get('success'):
            logger.info(f"✅ JSON generation successful")
            logger.info(f"   Data: {result.get('data')}")
        else:
            logger.error(f"❌ JSON generation failed: {result.get('message')}")
            return False
    except Exception as e:
        logger.error(f"❌ Error in JSON generation: {e}")
        return False
    
    logger.info("\n✅ All Ollama service tests passed!")
    return True


def test_llm_analysis_service():
    """Test LLM Analysis Service features"""
    logger.info("\n" + "="*60)
    logger.info("TEST 2: LLM Analysis Service")
    logger.info("="*60)
    
    llm = LLMAnalysisService()
    
    # Test 1: Check availability
    logger.info("\n2.1 Testing LLM service availability...")
    if llm.is_available():
        logger.info("✅ LLM service is available")
    else:
        logger.error("❌ LLM service is NOT available")
        return False
    
    # Test 2: Classification
    logger.info("\n2.2 Testing log event classification...")
    try:
        mock_entry = MockLogEntry()
        result = llm.classify_log_event(mock_entry)
        
        if result.get('error'):
            logger.error(f"❌ Classification failed: {result.get('reason')}")
            return False
        
        logger.info(f"✅ Classification successful")
        logger.info(f"   Category: {result.get('category')}")
        logger.info(f"   Confidence: {result.get('confidence')}")
        logger.info(f"   Reason: {result.get('reason')}")
        
        # Validate response
        if result.get('category') not in ['normal', 'suspicious', 'malicious', 'unknown']:
            logger.warning(f"⚠️  Unexpected category: {result.get('category')}")
        
    except Exception as e:
        logger.error(f"❌ Error in classification: {e}")
        return False
    
    # Test 3: Risk Scoring
    logger.info("\n2.3 Testing risk scoring...")
    try:
        mock_entry = MockLogEntry()
        context = {
            "request_count": 100,
            "blocked_count": 25,
            "unique_domains": 50
        }
        result = llm.score_risk(mock_entry, context)
        
        if result.get('error'):
            logger.error(f"❌ Risk scoring failed: {result.get('reason')}")
            return False
        
        logger.info(f"✅ Risk scoring successful")
        logger.info(f"   Risk Score: {result.get('risk_score')}/100")
        logger.info(f"   Severity: {result.get('severity')}")
        logger.info(f"   Reason: {result.get('reason')}")
        logger.info(f"   Indicators: {result.get('indicators')}")
        
        # Validate response
        risk_score = result.get('risk_score', 0)
        if not (0 <= risk_score <= 100):
            logger.warning(f"⚠️  Risk score out of range: {risk_score}")
        
    except Exception as e:
        logger.error(f"❌ Error in risk scoring: {e}")
        return False
    
    # Test 4: Summarization
    logger.info("\n2.4 Testing event summarization...")
    try:
        mock_entries = [MockLogEntry() for _ in range(5)]
        result = llm.summarize_events(mock_entries, max_entries=5)
        
        if result.get('error'):
            logger.error(f"❌ Summarization failed: {result.get('summary')}")
            return False
        
        logger.info(f"✅ Summarization successful")
        logger.info(f"   Summary: {result.get('summary')[:200]}...")
        logger.info(f"   Key Findings: {result.get('key_findings')}")
        logger.info(f"   Threat Level: {result.get('threat_level')}")
        logger.info(f"   Events Analyzed: {result.get('events_analyzed')}")
        
    except Exception as e:
        logger.error(f"❌ Error in summarization: {e}")
        return False
    
    # Test 5: Anomaly Analysis
    logger.info("\n2.5 Testing anomaly analysis...")
    try:
        mock_anomaly = MockAnomaly()
        mock_entry = MockLogEntry()
        result = llm.analyze_anomaly(mock_anomaly, mock_entry)
        
        if result.get('error'):
            logger.error(f"❌ Anomaly analysis failed: {result.get('explanation')}")
            return False
        
        logger.info(f"✅ Anomaly analysis successful")
        logger.info(f"   Explanation: {result.get('explanation')[:200]}...")
        logger.info(f"   Recommendations: {result.get('recommendations')}")
        logger.info(f"   Urgency: {result.get('urgency')}")
        logger.info(f"   Next Steps: {result.get('next_steps')}")
        
    except Exception as e:
        logger.error(f"❌ Error in anomaly analysis: {e}")
        return False
    
    # Test 6: Pattern Detection
    logger.info("\n2.6 Testing attack pattern detection...")
    try:
        mock_entries = [MockLogEntry() for _ in range(10)]
        result = llm.detect_attack_pattern(mock_entries)
        
        if result.get('error'):
            logger.error(f"❌ Pattern detection failed: {result.get('description')}")
            return False
        
        logger.info(f"✅ Pattern detection successful")
        logger.info(f"   Pattern: {result.get('pattern')}")
        logger.info(f"   Confidence: {result.get('confidence')}")
        logger.info(f"   Description: {result.get('description')}")
        logger.info(f"   IOCs: {result.get('iocs')}")
        
    except Exception as e:
        logger.error(f"❌ Error in pattern detection: {e}")
        return False
    
    # Test 7: Investigation Report
    logger.info("\n2.7 Testing investigation report generation...")
    try:
        mock_anomalies = [MockAnomaly() for _ in range(3)]
        mock_entries = [MockLogEntry() for _ in range(20)]
        result = llm.generate_investigation_report(
            anomalies=mock_anomalies,
            log_entries=mock_entries,
            user="john.doe"
        )
        
        if result.get('error'):
            logger.error(f"❌ Report generation failed: {result.get('executive_summary')}")
            return False
        
        logger.info(f"✅ Investigation report successful")
        logger.info(f"   Subject: {result.get('subject')}")
        logger.info(f"   Executive Summary: {result.get('executive_summary')[:200]}...")
        logger.info(f"   Threat Assessment: {result.get('threat_assessment')}")
        logger.info(f"   Key Findings: {result.get('key_findings')}")
        logger.info(f"   Requires Escalation: {result.get('requires_escalation')}")
        
    except Exception as e:
        logger.error(f"❌ Error in report generation: {e}")
        return False
    
    logger.info("\n✅ All LLM Analysis Service tests passed!")
    return True


def main():
    """Run all tests"""
    logger.info("=" * 60)
    logger.info("🦆 CyberDucky SIEM - LLM Integration Tests")
    logger.info("=" * 60)
    
    results = []
    
    # Test 1: Ollama Service
    results.append(("Ollama Service", test_ollama_service()))
    
    # Test 2: LLM Analysis Service
    results.append(("LLM Analysis Service", test_llm_analysis_service()))
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{status} - {test_name}")
    
    logger.info("\n" + "=" * 60)
    logger.info(f"Results: {passed}/{total} tests passed")
    logger.info("=" * 60)
    
    if passed == total:
        logger.info("🎉 All tests passed!")
        sys.exit(0)
    else:
        logger.error(f"❌ {total - passed} test(s) failed")
        sys.exit(1)


if __name__ == '__main__':
    main()

