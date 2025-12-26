# API Reference

## Base URL

```
http://localhost:4000/api/v1
```

## Authentication

All API requests require authentication using Bearer tokens in the Authorization header.

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:4000/api/v1/analyze/transaction
```

## Rate Limiting

- 100 requests per 15 minutes per IP address
- Rate limit headers included in responses:
  - `X-RateLimit-Limit`: Request limit
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Reset timestamp

## Error Responses

All errors follow this format:

```json
{
  "error": "Error message",
  "path": "/api/v1/endpoint",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

HTTP Status Codes:
- `400` - Bad Request (validation error)
- `401` - Unauthorized
- `404` - Not Found
- `429` - Too Many Requests
- `500` - Internal Server Error

## Endpoints

### Health Check

Check API server health status.

```
GET /health
```

**Response**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 3600
}
```

### Analyze Transaction

Analyze a Solana transaction for security exploits.

```
POST /api/v1/analyze/transaction
```

**Request Body**

```json
{
  "signature": "5j7s6NiJS3JAkvgkoc18WVAsiSaci2pxB2A6ueCJP4tprA2TFg9wSyTLeYouxPBJEMzJinENTkpA52YStRW5Dia7",
  "network": "mainnet-beta"
}
```

**Parameters**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| signature | string | Yes | Transaction signature |
| network | enum | No | Network (mainnet-beta, devnet, testnet). Default: mainnet-beta |

**Response**

```json
{
  "risk_score": 75.5,
  "exploits": [
    {
      "exploit_type": "reentrancy",
      "severity": "critical",
      "description": "Detected: Reentrancy Attack",
      "location": "transaction",
      "confidence": 0.85,
      "remediation": "Implement checks-effects-interactions pattern"
    }
  ],
  "state_changes": [
    {
      "account": "account_0",
      "field": "lamports",
      "before": "1000000000",
      "after": "0",
      "suspicious": true
    }
  ],
  "simulation_result": {
    "success": true,
    "error": null,
    "compute_units_consumed": 150000,
    "logs": ["Program log: Transfer complete"],
    "accounts_accessed": ["3vZ4..."]
  },
  "aiAnalysis": {
    "confidence": 0.92,
    "patterns": ["potential_reentrancy_vulnerability"],
    "recommendations": ["Implement reentrancy guards"],
    "clusterScore": 78.2
  },
  "metadata": {
    "timestamp": 1704067200,
    "analysis_duration_ms": 450,
    "analyzer_version": "1.0.0",
    "network": "mainnet-beta"
  }
}
```

### Analyze Address

Analyze all transactions for a given address.

```
POST /api/v1/analyze/address
```

**Request Body**

```json
{
  "address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
  "network": "mainnet-beta",
  "depth": 10
}
```

**Parameters**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| address | string | Yes | Solana address |
| network | enum | No | Network. Default: mainnet-beta |
| depth | number | No | Number of transactions to analyze (1-100). Default: 10 |

**Response**

```json
{
  "address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
  "network": "mainnet-beta",
  "transactionCount": 10,
  "aggregatedRiskScore": 45.3,
  "analyses": [
    {
      "risk_score": 75.5,
      "exploits": [],
      "aiAnalysis": {}
    }
  ],
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 4,
    "low": 1
  }
}
```

### Audit Contract

Perform comprehensive security audit on a smart contract.

```
POST /api/v1/audit/contract
```

**Request Body**

```json
{
  "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "network": "mainnet-beta",
  "depth": "deep"
}
```

**Parameters**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| programId | string | Yes | Program ID to audit |
| network | enum | No | Network. Default: mainnet-beta |
| depth | enum | No | Audit depth (shallow, deep). Default: shallow |

**Response**

```json
{
  "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "risk_score": 25.0,
  "vulnerabilities": [
    {
      "vulnerability_type": "missing_owner_check",
      "severity": "high",
      "description": "Potential missing owner validation detected",
      "affected_instructions": ["transfer"],
      "confidence": 0.72
    }
  ],
  "code_quality": {
    "score": 0.78,
    "metrics": {
      "complexity": 0.75,
      "maintainability": 0.82,
      "security": 0.68
    }
  },
  "recommendations": [
    "Add owner validation checks before privileged operations",
    "Use checked arithmetic operations"
  ],
  "aiEnhancement": {
    "additionalVulnerabilities": [],
    "patternMatches": ["static_analysis_pattern"],
    "riskAssessment": "moderate",
    "recommendations": []
  },
  "metadata": {
    "timestamp": 1704067200,
    "audit_duration_ms": 2500,
    "instructions_analyzed": 45,
    "depth": "shallow"
  }
}
```

### Monitor Address

Start monitoring an address for suspicious activity.

```
POST /api/v1/monitor/address
```

**Request Body**

```json
{
  "address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
  "network": "mainnet-beta",
  "webhookUrl": "https://your-server.com/webhook"
}
```

**Parameters**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| address | string | Yes | Address to monitor |
| network | enum | No | Network. Default: mainnet-beta |
| webhookUrl | string | No | Webhook URL for alerts |

**Response**

```json
{
  "monitorId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
  "network": "mainnet-beta",
  "status": "active",
  "startedAt": "2024-01-01T00:00:00.000Z"
}
```

### Get Monitor Status

Get status of an active monitor.

```
GET /api/v1/monitor/status/:monitorId
```

**Response**

```json
{
  "monitorId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
  "network": "mainnet-beta",
  "status": "active",
  "lastCheck": "2024-01-01T00:05:00.000Z"
}
```

### Stop Monitoring

Stop monitoring an address.

```
DELETE /api/v1/monitor/:monitorId
```

**Response**

```json
{
  "monitorId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "stopped",
  "stoppedAt": "2024-01-01T00:10:00.000Z"
}
```

## WebSocket API

Connect to WebSocket for real-time updates:

```
ws://localhost:4000
```

### Connection

```javascript
const ws = new WebSocket('ws://localhost:4000');

ws.onopen = () => {
  console.log('Connected');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
```

### Subscribe to Channel

```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'security-alert'
}));
```

### Unsubscribe from Channel

```javascript
ws.send(JSON.stringify({
  type: 'unsubscribe',
  channel: 'security-alert'
}));
```

### Event: security-alert

Received when a high-risk transaction is detected.

```json
{
  "type": "security-alert",
  "data": {
    "monitorId": "550e8400-e29b-41d4-a716-446655440000",
    "address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
    "timestamp": "2024-01-01T00:00:00.000Z",
    "riskScore": 85.5,
    "exploits": [
      {
        "exploit_type": "flash_loan_attack",
        "severity": "critical"
      }
    ],
    "message": "Security alert: High-risk transaction detected"
  }
}
```

## Webhook Format

When a webhook URL is provided for monitoring, alerts are sent as POST requests:

```http
POST https://your-server.com/webhook
Content-Type: application/json

{
  "monitorId": "550e8400-e29b-41d4-a716-446655440000",
  "address": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "riskScore": 85.5,
  "exploits": [],
  "message": "Security alert: High-risk transaction detected"
}
```

## Code Examples

### cURL

```bash
# Analyze transaction
curl -X POST http://localhost:4000/api/v1/analyze/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "5j7s6NiJS3JAkvgkoc18WVAsiSaci2pxB2A6ueCJP4tprA2TFg9wSyTLeYouxPBJEMzJinENTkpA52YStRW5Dia7",
    "network": "mainnet-beta"
  }'
```

### JavaScript/TypeScript (SDK)

```typescript
import { DynamoClient } from '@dynamo/sdk';

const client = new DynamoClient({
  endpoint: 'http://localhost:4000',
});

const result = await client.analyzeTransaction({
  signature: '5j7s6...',
  network: 'mainnet-beta',
});
```

### Python

```python
import requests

response = requests.post(
    'http://localhost:4000/api/v1/analyze/transaction',
    json={
        'signature': '5j7s6...',
        'network': 'mainnet-beta'
    }
)

data = response.json()
print(f"Risk Score: {data['risk_score']}")
```

