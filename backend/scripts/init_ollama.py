#!/usr/bin/env python3
"""
Initialize Ollama with default model
Downloads phi3:mini model if not already present
"""
import sys
import os
import time
import logging

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.ollama_service import OllamaService

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def wait_for_ollama(max_retries=30, retry_delay=2):
    """Wait for Ollama service to be available"""
    ollama = OllamaService()
    
    for i in range(max_retries):
        if ollama.is_available():
            logger.info("✅ Ollama service is available")
            return True
        
        logger.info(f"⏳ Waiting for Ollama service... ({i+1}/{max_retries})")
        time.sleep(retry_delay)
    
    logger.error("❌ Ollama service not available after maximum retries")
    return False


def check_model_exists(ollama, model_name):
    """Check if model is already downloaded"""
    try:
        models = ollama.list_models()
        for model in models:
            if model.get('name', '').startswith(model_name):
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking models: {e}")
        return False


def pull_model(ollama, model_name):
    """Pull model from Ollama library"""
    logger.info(f"📥 Downloading model: {model_name}")
    logger.info("This may take several minutes depending on your internet connection...")
    
    try:
        success = ollama.pull_model(model_name)
        if success:
            logger.info(f"✅ Successfully downloaded {model_name}")
            return True
        else:
            logger.error(f"❌ Failed to download {model_name}")
            return False
    except Exception as e:
        logger.error(f"❌ Error downloading model: {e}")
        return False


def test_model(ollama, model_name):
    """Test model with a simple prompt"""
    logger.info(f"🧪 Testing model: {model_name}")
    
    try:
        result = ollama.generate(
            prompt="Say 'Hello from CyberDucky SIEM!' in one sentence.",
            model=model_name,
            temperature=0.1,
            max_tokens=50
        )
        
        if result.get('success'):
            response = result.get('response', '')
            logger.info(f"✅ Model test successful!")
            logger.info(f"Response: {response}")
            return True
        else:
            logger.error(f"❌ Model test failed: {result.get('message')}")
            return False
    except Exception as e:
        logger.error(f"❌ Error testing model: {e}")
        return False


def main():
    """Main initialization function"""
    logger.info("=" * 60)
    logger.info("🦆 CyberDucky SIEM - Ollama Initialization")
    logger.info("=" * 60)
    
    # Step 1: Wait for Ollama service
    logger.info("\n📡 Step 1: Checking Ollama service availability...")
    if not wait_for_ollama():
        logger.error("Failed to connect to Ollama service")
        sys.exit(1)
    
    # Step 2: Initialize Ollama service
    ollama = OllamaService()
    
    # Step 3: Check available models
    logger.info("\n📋 Step 2: Checking available models...")
    try:
        models = ollama.list_models()
        if models:
            logger.info(f"Found {len(models)} existing models:")
            for model in models:
                logger.info(f"  - {model.get('name', 'unknown')}")
        else:
            logger.info("No models found")
    except Exception as e:
        logger.warning(f"Could not list models: {e}")
    
    # Step 4: Download default model if needed
    default_model = os.getenv('OLLAMA_DEFAULT_MODEL', 'phi3:mini')
    logger.info(f"\n📥 Step 3: Ensuring default model is available: {default_model}")
    
    if check_model_exists(ollama, default_model.split(':')[0]):
        logger.info(f"✅ Model {default_model} already exists")
    else:
        logger.info(f"Model {default_model} not found, downloading...")
        if not pull_model(ollama, default_model):
            logger.error("Failed to download default model")
            sys.exit(1)
    
    # Step 5: Test model
    logger.info(f"\n🧪 Step 4: Testing model...")
    if not test_model(ollama, default_model):
        logger.warning("Model test failed, but model is downloaded")
    
    # Step 6: Summary
    logger.info("\n" + "=" * 60)
    logger.info("✅ Ollama initialization complete!")
    logger.info("=" * 60)
    logger.info(f"Default model: {default_model}")
    logger.info(f"Ollama URL: {ollama.base_url}")
    logger.info("\nYou can now use LLM features in CyberDucky SIEM!")
    logger.info("\nRecommended models for SOC analysis:")
    logger.info("  - phi3:mini (default, fast, good for classification)")
    logger.info("  - gemma:2b (lightweight, good for structured output)")
    logger.info("  - llama3:instruct (larger, better reasoning)")
    logger.info("  - mistral:tiny (very fast, good for simple tasks)")
    logger.info("\nTo download additional models:")
    logger.info("  docker exec cyberducky_ollama ollama pull <model_name>")
    logger.info("=" * 60)


if __name__ == '__main__':
    main()

