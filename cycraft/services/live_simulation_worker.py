"""
CyCraft Live Telemetry Background Simulation Worker
Continuously ingests realistic enterprise logs, runs multi-model anomaly detection, and streams to WebSockets
"""

import asyncio
import random
import datetime
from sqlalchemy.orm import Session
from cycraft.database import SessionLocal
from cycraft.models.alert import AlertModel, AlertStorylineModel
from cycraft.services.ai_engine import ai_engine

class LiveSimulationWorker:
    def __init__(self):
        self.is_running = False
        self.task = None

    def start(self, ws_manager, interval=15):
        if not self.is_running:
            self.is_running = True
            self.task = asyncio.create_task(self._worker_loop(ws_manager, interval))
            print(f"⚡ CyCraft Live Continuous Telemetry Simulation Worker started (Interval: {interval}s).")

    def stop(self):
        if self.is_running:
            self.is_running = False
            if self.task:
                self.task.cancel()
            print("🛑 CyCraft Live Telemetry Worker stopped.")

    async def _worker_loop(self, ws_manager, interval):
        endpoints = [
            ("DEV-WIN-SRV09", "45.33.12.9", "Reflective DLL Kernel Injection"),
            ("FIN-WRK-102", "192.168.20.12", "Anomalous Lateral SMB Enumeration"),
            ("ENG-MAC-404", "192.168.15.88", "Encrypted DNS Tunnel Establishment"),
            ("AWS-IAM-US-EAST", "54.210.85.12", "Anomalous AdministratorAccess Attachment"),
            ("IDENTITY-IDP", "185.220.101.5", "15 Failed Okta Push Authentications"),
            ("DB-PROD-SQL01", "192.168.5.10", "Unexpected Scheduled Task Registration"),
            ("K8S-CLUSTER-EU", "10.240.0.1", "Privileged Container Shell Escape Attempt")
        ]

        while self.is_running:
            try:
                # Random interval variation for organic enterprise jitter
                sleep_time = interval + random.randint(-3, 5)
                await asyncio.sleep(sleep_time)

                # Generate anomaly
                ep, ip, behavior = random.choice(endpoints)
                new_alert = ai_engine.analyze_anomaly(endpoint=ep, ip=ip, raw_behavior=behavior)

                # Persist to SQLite
                db: Session = SessionLocal()
                try:
                    db_alert = AlertModel(
                        id=new_alert["id"],
                        severity=new_alert["severity"],
                        title=new_alert["title"],
                        endpoint=new_alert["endpoint"],
                        ip=new_alert["ip"],
                        timestamp="Just now",
                        mitre=new_alert["mitre"],
                        status=new_alert["status"],
                        ai_confidence=new_alert["ai_confidence"]
                    )
                    for st in new_alert["storyline"]:
                        db_alert.storyline.append(AlertStorylineModel(time=st["time"], event=st["event"]))
                    db.add(db_alert)
                    db.commit()
                except Exception as e:
                    print(f"Error persisting simulated alert: {e}")
                finally:
                    db.close()

                # Broadcast live real-time update over WebSockets
                ws_item = {
                    "type": "TICKER_UPDATE",
                    "id": new_alert["id"],
                    "endpoint": new_alert["endpoint"],
                    "title": new_alert["title"],
                    "severity": new_alert["severity"],
                    "status": new_alert["status"],
                    "timestamp": "Just now"
                }
                await ws_manager.broadcast(ws_item)

            except asyncio.CancelledError:
                break
            except Exception as err:
                print(f"Live Simulation Worker Error: {err}")
                await asyncio.sleep(5)

live_worker = LiveSimulationWorker()
