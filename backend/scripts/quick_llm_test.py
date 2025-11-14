#!/usr/bin/env python3
"""
Quick LLM Test - Simple test to verify Ollama is working
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.ollama_service import OllamaService
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    print("=" * 60)
    print("🦆 Quick LLM Test")
    print("=" * 60)
    
    # Initialize service
    ollama = OllamaService()
    
    # Test 1: Check availability
    print("\n1. Checking Ollama availability...")
    if not ollama.is_available():
        print("❌ Ollama is not available")
        return 1
    print("✅ Ollama is available")
    
    # Test 2: List models
    print("\n2. Listing models...")
    models = ollama.list_models()
    if not models:
        print("❌ No models found")
        return 1
    print(f"✅ Found {len(models)} model(s):")
    for model in models:
        print(f"   - {model['name']}")
    
    # Test 3: Simple generation
    print("\n3. Testing text generation...")
    print("   Prompt: 'Classify this as normal, suspicious, or malicious: User accessed google.com'")
    
    try:
        result = ollama.generate(
            prompt="Classify this as normal, suspicious, or malicious: User accessed google.com. Answer in one word only.",
            temperature=0.1
        )
        
        if result.get('error'):
            print(f"❌ Generation failed: {result['error']}")
            return 1
        
        response = result.get('response', '').strip()
        print(f"✅ Response: {response}")
        
    except Exception as e:
        print(f"❌ Exception: {e}")
        return 1
    
    # Test 4: JSON generation
    print("\n4. Testing JSON generation...")
    print("   Prompt: 'Return JSON with risk_score (0-100) and reason for: Multiple failed login attempts'")
    
    try:
        result = ollama.generate_json(
            prompt='Return JSON with fields: risk_score (number 0-100) and reason (string) for this event: Multiple failed login attempts from same IP',
            temperature=0.1
        )
        
        if result.get('error'):
            print(f"❌ JSON generation failed: {result['error']}")
            return 1
        
        data = result.get('data', {})
        print(f"✅ JSON Response:")
        print(f"   - risk_score: {data.get('risk_score')}")
        print(f"   - reason: {data.get('reason')}")
        
    except Exception as e:
        print(f"❌ Exception: {e}")
        return 1
    
    print("\n" + "=" * 60)
    print("✅ All tests passed!")
    print("=" * 60)
    return 0

if __name__ == '__main__':
    sys.exit(main())

