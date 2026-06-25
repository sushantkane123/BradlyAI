"""BradlyAI Unified LLM Client — async HTTP via httpx"""
import logging
from bradlyai.config import settings

logger = logging.getLogger("bradlyai.llm")


class LLMClient:
    def __init__(self):
        self.provider = settings.LLM_PROVIDER.lower()
        self.api_key = settings.GROQ_API_KEY if self.provider == "groq" else settings.OPENAI_API_KEY

    async def generate_response(self, prompt: str, system_prompt: str = "You are a professional SOC Analyst.") -> str:
        if not self.api_key:
            return "No API key configured. Add GROQ_API_KEY or OPENAI_API_KEY to your .env file."
        try:
            if self.provider == "groq":
                return await self._call_groq(prompt, system_prompt)
            elif self.provider == "openai":
                return await self._call_openai(prompt, system_prompt)
            return f"Unsupported provider: {self.provider}"
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return f"LLM Error: {str(e)}"

    async def _call_groq(self, prompt: str, system_prompt: str) -> str:
        import httpx
        # Use settings.DEFAULT_AI_MODEL if it looks like a Groq model, else fall back
        # to current Groq models (llama3-70b-8192 is deprecated → llama-3.3-70b-versatile)
        model = settings.DEFAULT_AI_MODEL if "llama" in settings.DEFAULT_AI_MODEL.lower() or "mixtral" in settings.DEFAULT_AI_MODEL.lower() or "gemma" in settings.DEFAULT_AI_MODEL.lower() else "llama-3.3-70b-versatile"
        # Map deprecated model names
        deprecated_map = {
            "llama3-70b-8192": "llama-3.3-70b-versatile",
            "mixtral-8x7b-32768": "mixtral-8x7b-32768",
            "gpt-4-turbo-preview": "llama-3.3-70b-versatile",
        }
        model = deprecated_map.get(model, model)
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}], "temperature": 0.2, "max_tokens": 1024},
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]

    async def _call_openai(self, prompt: str, system_prompt: str) -> str:
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": settings.DEFAULT_AI_MODEL, "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}], "temperature": 0.2},
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]


llm_client = LLMClient()
