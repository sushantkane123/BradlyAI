"""
CyCraft AI Configuration & Advanced Enterprise Settings
"""

from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "CyCraft AI - Driverless SOC & Automated Incident Response"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = "production"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "info"
    
    # Persistent SQLite Database Setting
    DATABASE_URL: str = "sqlite:///./cycraft_soc.db"

    # Active AI LLM Provider Settings for Live Generative Analysis
    OPENAI_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    DEFAULT_AI_MODEL: str = "gpt-4o-mini" # or custom Llama 3 / Claude

    # Driverless SOC Behavioral Control Parameters
    AUTO_CONTAINMENT_THRESHOLD: float = 95.0 # AI confidence minimum to execute zero-touch network lockdown
    LIVE_SIMULATION_WORKER_ACTIVE: bool = True
    SIMULATION_INTERVAL_SECONDS: int = 15
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()
