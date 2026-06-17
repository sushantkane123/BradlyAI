#!/usr/bin/env python3
"""
Top-level development runner for CyCraft AI - Driverless SOC Application

Usage examples:
    python run.py
    python run.py --port 8001
    python run.py --port 8080 --host 127.0.0.1
"""

import argparse
import sys
import uvicorn
from cycraft.config import settings

def main():
    parser = argparse.ArgumentParser(description="Start CyCraft AI L1 SOC Agent")
    parser.add_argument("--host", default=settings.HOST, help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=settings.PORT, help="Port to bind (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (dev mode)")
    args = parser.parse_args()

    print(f"\n🛡️  Starting {settings.APP_NAME} ({settings.ENVIRONMENT} mode)...")
    print(f"⚡ Live Swagger UI Documentation: http://{args.host}:{args.port}/docs")
    print(f"🌐 Full Autonomous Frontend Portal: http://{args.host}:{args.port}/\n")

    try:
        uvicorn.run(
            "cycraft.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload or (settings.ENVIRONMENT.lower() in ["development", "dev"]),
        )
    except OSError as e:
        if "10048" in str(e) or "address already in use" in str(e).lower():
            print("\n" + "="*60)
            print("❌ ERROR: Port {} is already in use.".format(args.port))
            print("="*60)
            print("\nOn Windows, run these commands to free the port:\n")
            print("   1. Find the process:")
            print(f"      netstat -ano | findstr :{args.port}")
            print("\n   2. Kill it (replace PID with the number from above):")
            print("      taskkill /PID <PID> /F")
            print("\n   3. Then try again:")
            print(f"      python run.py --port {args.port}")
            print("\nQuick workaround - start on a different port:")
            print(f"      python run.py --port 8001")
            print("="*60 + "\n")
        else:
            print(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
