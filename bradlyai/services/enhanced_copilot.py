"""BradlyAI - Enhanced Real-World Copilot — analyzes actual ingested logs"""
import asyncio
import logging
from typing import AsyncGenerator
from bradlyai.services.llm_client import llm_client
from .log_ingestion import log_ingestion

logger = logging.getLogger("bradlyai.enhanced_copilot")


class RealWorldCyberCopilot:
    SYSTEM_PROMPT = "You are an elite BradlyAI Cyber-AI Security Analyst. Analyze the REAL security logs and alerts ingested by the user. Be precise and actionable."

    def _get_real_context(self) -> str:
        alerts = log_ingestion.get_alerts(5)
        events = log_ingestion.get_events(8)
        ctx = "=== REAL DATA IN SYSTEM ===\n\n"
        if alerts:
            ctx += "DETECTED ALERTS:\n" + "\n".join([f"- [{a['severity']}] {a['title']} on {a['endpoint']} (Rule: {a['rule_id']})" for a in alerts]) + "\n\n"
        if events:
            ctx += "RECENT EVENTS:\n" + "\n".join([f"- {e['source']}: {e['message'][:120]}" for e in events]) + "\n"
        if not alerts and not events:
            ctx += "No real logs ingested yet.\n"
        return ctx

    def get_reply(self, query: str) -> str:
        q = query.lower()
        alerts = log_ingestion.get_alerts(5)
        if ("summary" in q or "what happened" in q) and alerts:
            return "Real alerts from your logs:\n" + "\n".join([f"  {a['title']} on {a['endpoint']} (Rule {a['rule_id']})" for a in alerts])
        if "yara" in q and alerts:
            a = alerts[0]
            return f"rule BradlyAI_{a['rule_id']} {{\n    meta:\n        description = \"Auto-generated from {a['title']}\"\n        author = \"BradlyAI Enhanced Copilot\"\n    strings:\n        $s = /powershell|VirtualAllocEx|CreateRemoteThread/i\n    condition:\n        $s\n}}"
        if not alerts:
            return "No real data ingested yet. Use /api/v1/ingest/logs/text to upload logs, or upload a file via /api/v1/ingest/logs/upload."
        context = self._get_real_context()
        return f"Analyzed your real data:\n{context}\nQuery: {query}"

    async def get_reply_async(self, query: str) -> str:
        if llm_client.api_key:
            try:
                context = self._get_real_context()
                return await llm_client.generate_response(f"{self.SYSTEM_PROMPT}\n{context}\n\nUser: {query}", self.SYSTEM_PROMPT)
            except Exception as e:
                logger.warning(f"LLM failed, offline: {e}")
        return self.get_reply(query)



real_copilot = RealWorldCyberCopilot()
