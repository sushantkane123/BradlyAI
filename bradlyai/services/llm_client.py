"""Optimized BradlyAI Unified LLM Client — shared persistent connection pooling & Ollama local-first.

Gains:
- Persistent TCP Connection Pooling: Instantiates a single, shared httpx.AsyncClient 
  reused across all requests, eliminating DNS, TCP, and TLS handshake latency overhead.
- Ollama Local-First Integration: Native support for Ollama local servers allowing complete
  air-gapped and local-first LLM security analysis.
- Graceful Connection Lifecycle: Supports manual client closure and custom session timeouts.
"""

import logging
import httpx
from bradlyai.config import settings

logger = logging.getLogger("bradlyai.llm_optimized")

class LLMClientOptimized:
    def __init__(self):
        self.provider = settings.LLM_PROVIDER.lower()
        self.api_key = settings.GROQ_API_KEY if self.provider == "groq" else settings.OPENAI_API_KEY
        
        # Instantiate a single persistent client with connection pooling enabled
        # Re-using this client saves ~150ms-300ms on every subsequent API call!
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=5.0, read=25.0),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=20)
        )

    async def close(self):
        """Close the persistent connection pool on application shutdown."""
        await self._client.aclose()
        logger.info("LLM Client connection pool closed.")

    async def generate_response(self, prompt: str, system_prompt: str = "You are a professional SOC Analyst.") -> str:
        # Ollama local provider operates completely without external cloud API Keys
        if self.provider != "ollama" and not self.api_key:
            return "No API key configured. Add GROQ_API_KEY or OPENAI_API_KEY to your .env file."
        try:
            if self.provider == "groq":
                return await self._call_groq(prompt, system_prompt)
            elif self.provider == "openai":
                return await self._call_openai(prompt, system_prompt)
            elif self.provider == "ollama":
                return await self._call_ollama(prompt, system_prompt)
            return f"Unsupported provider: {self.provider}"
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return f"LLM Error: {str(e)}"

    async def _call_groq(self, prompt: str, system_prompt: str) -> str:
        model = settings.DEFAULT_AI_MODEL if "llama" in settings.DEFAULT_AI_MODEL.lower() or "mixtral" in settings.DEFAULT_AI_MODEL.lower() or "gemma" in settings.DEFAULT_AI_MODEL.lower() else "llama-3.3-70b-versatile"
        
        deprecated_map = {
            "llama3-70b-8192": "llama-3.3-70b-versatile",
            "mixtral-8x7b-32768": "mixtral-8x7b-32768",
            "gpt-4-turbo-preview": "llama-3.3-70b-versatile",
        }
        model = deprecated_map.get(model, model)

        response = await self._client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": model, 
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ], 
                "temperature": 0.2, 
                "max_tokens": 1024
            },
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    async def _call_openai(self, prompt: str, system_prompt: str) -> str:
        response = await self._client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": settings.DEFAULT_AI_MODEL, 
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ], 
                "temperature": 0.2
            },
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    async def _call_ollama(self, prompt: str, system_prompt: str) -> str:
        # Queries a local Ollama server running on port 11434
        response = await self._client.post(
            "http://localhost:11434/api/chat",
            json={
                "model": settings.DEFAULT_AI_MODEL or "llama3",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "options": {"temperature": 0.2},
                "stream": False
            }
        )
        response.raise_for_status()
        return response.json()["message"]["content"]

# Global singleton (must be named llm_client for backwards compatibility)
llm_client = LLMClientOptimized()
