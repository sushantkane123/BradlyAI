# Real SIEM / XDR / EDR data mode

BradlyAI can now run without seeded showcase alerts and accept normalized real events from multiple sources.

## Safety-first configuration

Use these settings in `.env` for local replay and client pilots:

```dotenv
DEMO_DATA_ENABLED=false
LIVE_SIMULATION_WORKER_ACTIVE=false
INGESTION_DEFAULT_MODE=shadow
WAZUH_ENABLED=false
```

`shadow` persists the alert and records the L1 decision/audit result but does not trigger a configured external close/archive action. Move to `active` only after customer approval, source validation, and action-policy review.

## Generic ingestion API

```text
POST /api/v1/ingest/events
POST /api/v1/ingest/events/batch
GET  /api/v1/ingest/sources
```

The single-event envelope is:

```json
{
  "source": "sentinel",
  "mode": "shadow",
  "payload": { "source-specific": "original event" }
}
```

Supported adapters:

- Wazuh
- Splunk
- Microsoft Sentinel
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- Elastic / Elasticsearch / ELK
- Generic SIEM, XDR, EDR, and custom webhook envelopes

The original source payload is retained as `raw_event` with the normalized alert for evidence review in the dashboard.

## Authentication and perimeter controls

Set `INGESTION_SHARED_SECRET` to require an `X-Ingestion-Key` header. This is an additional application-level control, not a replacement for TLS, IP allow-listing, rate limits, an API gateway, webhook signature validation, or mTLS.

## Replay fixtures

Sanitized fixtures are in [`examples/real-data`](examples/real-data/README.md). Start with:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/sentinel-powershell.json
```

To test all three generic SIEM/XDR/EDR categories:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events/batch \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/batch.json
```
