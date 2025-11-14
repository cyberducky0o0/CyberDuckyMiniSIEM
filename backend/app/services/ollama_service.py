"""
Ollama Service - Interface to local LLM via Ollama API
Provides low-level communication with Ollama for LLM inference
Supports multiple models: phi3:mini, gemma:2b, llama3:instruct, mistral:tiny
"""
import logging
import requests
import json
from typing import Dict, Any, Optional, List
import os

logger = logging.getLogger(__name__)


class OllamaService:
    """
    Service for communicating with Ollama API
    Handles model management, inference, and error handling
    """
    
    def __init__(self, base_url: Optional[str] = None, default_model: str = "phi3:mini"):
        """
        Initialize Ollama service
        
        Args:
            base_url: Ollama API base URL (default: http://ollama:11434)
            default_model: Default model to use (default: phi3:mini)
        """
        self.base_url = base_url or os.getenv('OLLAMA_URL', 'http://ollama:11434')
        self.default_model = default_model
        self.timeout = int(os.getenv('OLLAMA_TIMEOUT', '120'))  # seconds - increased for first inference

        logger.info(f"Initialized Ollama service: {self.base_url}, model: {self.default_model}")
    
    def is_available(self) -> bool:
        """
        Check if Ollama service is available
        
        Returns:
            True if Ollama is reachable, False otherwise
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Ollama service not available: {e}")
            return False
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List available models in Ollama
        
        Returns:
            List of model information dictionaries
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()
            data = response.json()
            return data.get('models', [])
        except Exception as e:
            logger.error(f"Error listing models: {e}")
            return []
    
    def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        stream: bool = False
    ) -> Dict[str, Any]:
        """
        Generate text using Ollama
        
        Args:
            prompt: User prompt
            model: Model name (default: self.default_model)
            system: System prompt for context
            temperature: Sampling temperature (0.0-1.0, lower = more deterministic)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream response
            
        Returns:
            Response dictionary with 'response', 'model', 'done', etc.
        """
        model = model or self.default_model
        
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": temperature,
            }
        }
        
        if system:
            payload["system"] = system
        
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens
        
        try:
            logger.debug(f"Generating with model {model}: {prompt[:100]}...")
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"Generated response: {result.get('response', '')[:100]}...")
            
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"Ollama request timed out after {self.timeout}s")
            return {
                "error": "timeout",
                "message": f"Request timed out after {self.timeout} seconds"
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama request failed: {e}")
            return {
                "error": "request_failed",
                "message": str(e)
            }
        except Exception as e:
            logger.error(f"Unexpected error in Ollama generate: {e}")
            return {
                "error": "unexpected_error",
                "message": str(e)
            }
    
    def generate_json(
        self,
        prompt: str,
        model: Optional[str] = None,
        system: Optional[str] = None,
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        """
        Generate JSON output using Ollama
        Automatically adds JSON formatting instructions
        
        Args:
            prompt: User prompt (should request JSON output)
            model: Model name
            system: System prompt
            temperature: Sampling temperature
            
        Returns:
            Parsed JSON response or error dict
        """
        # Add JSON formatting instruction if not present
        if "json" not in prompt.lower():
            prompt = f"{prompt}\n\nRespond with valid JSON only, no additional text."
        
        result = self.generate(
            prompt=prompt,
            model=model,
            system=system,
            temperature=temperature
        )
        
        if "error" in result:
            return result
        
        # Try to parse JSON from response
        response_text = result.get('response', '').strip()
        
        try:
            # Try to extract JSON if wrapped in markdown code blocks
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            elif "```" in response_text:
                json_start = response_text.find("```") + 3
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            
            parsed_json = json.loads(response_text)
            return {
                "success": True,
                "data": parsed_json,
                "raw_response": result.get('response', '')
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from LLM response: {e}")
            logger.error(f"Raw response: {response_text}")
            return {
                "error": "json_parse_error",
                "message": str(e),
                "raw_response": response_text
            }
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        """
        Chat completion using Ollama
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name
            temperature: Sampling temperature
            
        Returns:
            Response dictionary
        """
        model = model or self.default_model
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Ollama chat failed: {e}")
            return {
                "error": "chat_failed",
                "message": str(e)
            }
    
    def pull_model(self, model_name: str) -> bool:
        """
        Pull a model from Ollama library
        
        Args:
            model_name: Name of model to pull (e.g., 'phi3:mini')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Pulling model: {model_name}")
            
            response = requests.post(
                f"{self.base_url}/api/pull",
                json={"name": model_name},
                timeout=300  # 5 minutes for model download
            )
            response.raise_for_status()
            
            logger.info(f"Successfully pulled model: {model_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to pull model {model_name}: {e}")
            return False
    
    def get_model_info(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get information about a specific model
        
        Args:
            model_name: Model name (default: self.default_model)
            
        Returns:
            Model information dictionary
        """
        model_name = model_name or self.default_model
        
        try:
            response = requests.post(
                f"{self.base_url}/api/show",
                json={"name": model_name},
                timeout=5
            )
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to get model info for {model_name}: {e}")
            return {"error": str(e)}

