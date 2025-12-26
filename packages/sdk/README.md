# Dynamo SDK

TypeScript/JavaScript SDK for the Dynamo security audit platform.

## Installation

```bash
npm install @dynamo/sdk
```

## Quick Start

```typescript
import { DynamoClient } from '@dynamo/sdk';

const client = new DynamoClient({
  endpoint: 'http://localhost:4000',
  apiKey: 'your-api-key', // optional
});

// Analyze a transaction
const result = await client.analyzeTransaction({
  signature: 'transaction-signature-here',
  network: 'mainnet-beta',
});

console.log('Risk Score:', result.risk_score);
console.log('Exploits Found:', result.exploits.length);
```

## API Reference

### Transaction Analysis

```typescript
const analysis = await client.analyzeTransaction({
  signature: string,
  network?: 'mainnet-beta' | 'devnet' | 'testnet',
});
```

Response includes:
- `risk_score`: Overall risk score (0-100)
- `exploits`: Array of detected exploits
- `state_changes`: Account state modifications
- `simulation_result`: Transaction simulation data
- `aiAnalysis`: AI cluster analysis results

### Address Analysis

Analyze all transactions for a given address:

```typescript
const analysis = await client.analyzeAddress({
  address: string,
  network?: 'mainnet-beta' | 'devnet' | 'testnet',
  depth?: number, // Number of transactions to analyze
});
```

### Contract Audit

Audit a smart contract:

```typescript
const audit = await client.auditContract({
  programId: string,
  network?: 'mainnet-beta' | 'devnet' | 'testnet',
  depth?: 'shallow' | 'deep',
});
```

### Real-time Monitoring

Monitor an address for suspicious activity:

```typescript
const monitor = await client.monitorAddress({
  address: string,
  network?: 'mainnet-beta' | 'devnet' | 'testnet',
  webhookUrl?: string,
  callback?: (alert) => {
    console.log('Security Alert:', alert);
  },
});

// Check monitor status
const status = await client.getMonitorStatus(monitor.monitorId);

// Stop monitoring
await client.stopMonitoring(monitor.monitorId);
```

### WebSocket Subscriptions

Subscribe to real-time security alerts:

```typescript
const unsubscribe = client.subscribeToAlerts((alert) => {
  console.log('Alert:', alert.message);
  console.log('Risk Score:', alert.riskScore);
  console.log('Exploits:', alert.exploits);
});

// Later, to unsubscribe
unsubscribe();
```

## Types

All TypeScript types are exported from the SDK:

```typescript
import {
  TransactionAnalysisRequest,
  TransactionAnalysisResponse,
  Exploit,
  SecurityAlert,
  // ... and more
} from '@dynamo/sdk';
```

## Error Handling

```typescript
try {
  const result = await client.analyzeTransaction({
    signature: 'invalid-signature',
  });
} catch (error) {
  if (error.response) {
    console.error('API Error:', error.response.data);
  } else {
    console.error('Network Error:', error.message);
  }
}
```

## Configuration

```typescript
const client = new DynamoClient({
  endpoint: 'http://localhost:4000',
  apiKey: 'your-api-key',
  timeout: 30000, // Request timeout in ms
});
```

## WebSocket Management

```typescript
// SDK automatically manages WebSocket connections
// Manually close when done
client.disconnect();
```

## Examples

### Batch Analysis

```typescript
const signatures = ['sig1', 'sig2', 'sig3'];

const results = await Promise.all(
  signatures.map((signature) =>
    client.analyzeTransaction({ signature, network: 'mainnet-beta' })
  )
);

const highRiskTransactions = results.filter((r) => r.risk_score > 70);
```

### Monitor with Webhook

```typescript
await client.monitorAddress({
  address: 'your-address',
  network: 'mainnet-beta',
  webhookUrl: 'https://your-server.com/webhook',
});
```

### Deep Contract Audit

```typescript
const audit = await client.auditContract({
  programId: 'program-id',
  network: 'mainnet-beta',
  depth: 'deep',
});

const criticalVulns = audit.vulnerabilities.filter(
  (v) => v.severity === 'critical'
);

console.log('Critical Vulnerabilities:', criticalVulns.length);
audit.recommendations.forEach((rec) => console.log('-', rec));
```

## License

MIT

