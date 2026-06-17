#!/usr/bin/env python3
"""
Top-level development runner for CyCraft AI - Driverless SOC Application
"""

import uvicorn
from cycraft.config import settings

if __name__ == "__main__":
    print(f"\n🛡️  Starting {settings.APP_NAME} ({settings.ENVIRONMENT} mode)...")
    print(f"⚡ Live Swagger UI Documentation: http://{settings.HOST}:{settings.PORT}/docs")
    print(f"🌐 Full Autonomous Frontend Portal: http://{settings.HOST}:{settings.PORT}/\n")
    
    uvicorn.run(
        "cycraft.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENVIRONMENT.lower() in ["development", "dev"]
    )
