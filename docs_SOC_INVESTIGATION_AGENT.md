# Evidence-first SOC investigation agent

BradlyAI's investigation agent is designed to follow an auditable human SOC workflow, not to make an unexplained autonomous containment decision.

## Workflow

1. Validate and normalize the retained source event.
2. Formulate evidence requirements: endpoint, identity, network, history, and policy.
3. Correlate matching signatures and asset activity from the prior 24 hours.
4. Record observed evidence separately from missing connector evidence.
5. Produce hypotheses, a policy-constrained recommendation, and a full evidence record.

## Safety behavior

- The agent **never contains, isolates, disables, or closes an external asset**.
- Critical/high severity alerts and alerts containing high-risk behavior terms result in `ESCALATE`.
- Low-severity operational activity can only become `AUTO_CLOSE_CANDIDATE`; it still requires a future analyst-approved resolution-memory and policy match.
- Every plan item identifies whether evidence was completed, missing, or requires an approved connector query.

## API

The caller must have `alerts:read` permission.

```text
POST /api/v1/agent/alerts/{alert_id}/investigate
GET  /api/v1/agent/alerts/{alert_id}/investigations
GET  /api/v1/agent/investigations/{investigation_id}
```

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/agent/alerts/MDE-agent-test-001/investigate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

The response includes:

```json
{
  "recommendation": "ESCALATE",
  "confidence": "84%",
  "summary": "Escalate for analyst review...",
  "plan": [],
  "evidence": [],
  "hypotheses": [],
  "policy": {}
}
```

## Next connector work

The agent currently uses retained source evidence and local alert history. The next iteration should add read-only, tenant-scoped collectors for:

- EDR process tree and endpoint telemetry
- Identity sign-in and directory events
- DNS, proxy, firewall, and flow telemetry
- Cloud IAM and audit logs
- File/hash and IP threat intelligence
- Ticketing and prior-case context

Every collector should return structured evidence with source, query time, tenant, and raw-evidence reference.
