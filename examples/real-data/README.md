# Real-data replay fixtures

These fixtures are sanitized examples for validating BradlyAI against SIEM, XDR, EDR, and custom event schemas. They are **not** demo alerts inserted by the application. They should be replayed only into a local/lab database or a client-approved shadow-mode pilot.

## Safe local mode

In `.env`, use:

```dotenv
DEMO_DATA_ENABLED=false
LIVE_SIMULATION_WORKER_ACTIVE=false
INGESTION_DEFAULT_MODE=shadow
WAZUH_ENABLED=false
```

Start the application, then replay an individual fixture:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/sentinel-powershell.json
```

Replay all fixtures as a batch:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events/batch \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/batch.json
```

Then inspect the result in the dashboard, or with:

```bash
curl http://127.0.0.1:8000/api/v1/alerts
curl 'http://127.0.0.1:8000/api/v1/l1/audit?since_hours=1'
```

## Supported adapters

- Wazuh
- Splunk
- Microsoft Sentinel
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- Elastic / Elasticsearch / ELK
- Generic SIEM, XDR, EDR, and custom webhook envelopes

For a production/client sender, set `INGESTION_SHARED_SECRET` and send its value in `X-Ingestion-Key`; also place the endpoint behind TLS, IP allow-lists, and preferably mTLS or an API gateway.
