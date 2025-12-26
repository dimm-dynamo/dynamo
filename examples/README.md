# Dynamo SDK Examples

Practical examples demonstrating various Dynamo SDK features.

## Setup

```bash
cd examples
npm install
```

## Examples

### 1. Basic Usage

Simple transaction analysis, contract auditing, and monitoring.

```bash
npm run basic
```

**Features:**
- Transaction analysis
- Smart contract auditing
- Address monitoring with callbacks

### 2. Advanced Usage

Advanced patterns including batch processing and custom alerts.

```bash
npm run advanced
```

**Features:**
- Batch transaction analysis
- Deep contract audits with reporting
- Real-time monitoring with custom alert handling
- Historical address analysis
- WebSocket subscriptions

### 3. Webhook Server

Example webhook server for receiving security alerts.

```bash
npm run webhook
```

**Features:**
- Express server for webhook endpoints
- Alert processing and routing
- Integration examples (PagerDuty, Slack)
- Severity-based alert handling

## Use Cases

### Monitoring DeFi Protocol

```typescript
import { DynamoClient } from '@dynamo/sdk';

const client = new DynamoClient({ endpoint: 'http://localhost:4000' });

// Monitor protocol treasury
await client.monitorAddress({
  address: 'treasury-address',
  network: 'mainnet-beta',
  webhookUrl: 'https://your-server.com/alerts',
});

// Monitor key program accounts
const programAccounts = [
  'vault-address',
  'pool-address',
  'fee-account',
];

for (const account of programAccounts) {
  await client.monitorAddress({
    address: account,
    network: 'mainnet-beta',
    callback: (alert) => {
      if (alert.riskScore > 70) {
        pauseProtocol();
        notifyTeam(alert);
      }
    },
  });
}
```

### Automated Security Scanning

```typescript
// Scan new programs before interaction
async function scanProgram(programId: string) {
  const audit = await client.auditContract({
    programId,
    network: 'mainnet-beta',
    depth: 'deep',
  });

  const criticalVulns = audit.vulnerabilities.filter(
    v => v.severity === 'critical'
  );

  if (criticalVulns.length > 0 || audit.risk_score > 70) {
    return {
      safe: false,
      reason: 'Critical vulnerabilities detected',
      audit,
    };
  }

  return { safe: true, audit };
}
```

### Transaction Pre-flight Checks

```typescript
// Analyze transaction before signing
async function preflight(transaction: Transaction) {
  const simulation = await connection.simulateTransaction(transaction);
  const signature = simulation.value.logs?.[0] || '';

  const analysis = await client.analyzeTransaction({
    signature,
    network: 'mainnet-beta',
  });

  if (analysis.risk_score > 50) {
    throw new Error(
      `Transaction failed security check: ${analysis.exploits[0]?.description}`
    );
  }

  return analysis;
}
```

### Portfolio Security Monitoring

```typescript
// Monitor all wallet addresses
async function monitorWallet(addresses: string[]) {
  const monitors = await Promise.all(
    addresses.map(address =>
      client.monitorAddress({
        address,
        network: 'mainnet-beta',
        callback: (alert) => {
          console.log(`Alert for ${address}:`, alert.message);
          
          // Check specific exploit types
          const hasFlashLoan = alert.exploits.some(
            e => e.exploit_type === 'flash_loan_attack'
          );

          if (hasFlashLoan) {
            emergencyWithdraw(address);
          }
        },
      })
    )
  );

  console.log(`Monitoring ${monitors.length} addresses`);
  return monitors;
}
```

### Batch Audit for Token Launch

```typescript
// Audit all program accounts before token launch
async function auditTokenLaunch(config: {
  tokenProgram: string;
  mintAuthority: string;
  poolProgram: string;
}) {
  const results = await Promise.all([
    client.auditContract({
      programId: config.tokenProgram,
      depth: 'deep',
    }),
    client.auditContract({
      programId: config.poolProgram,
      depth: 'deep',
    }),
  ]);

  const issues = results.flatMap(r => r.vulnerabilities);
  const highRisk = issues.filter(i => 
    i.severity === 'critical' || i.severity === 'high'
  );

  if (highRisk.length > 0) {
    return {
      approved: false,
      issues: highRisk,
      message: 'Critical security issues detected',
    };
  }

  return { approved: true, results };
}
```

## Error Handling

```typescript
try {
  const result = await client.analyzeTransaction({
    signature: 'invalid-signature',
  });
} catch (error: any) {
  if (error.response?.status === 429) {
    console.error('Rate limit exceeded');
    // Implement backoff strategy
  } else if (error.response?.status === 404) {
    console.error('Transaction not found');
  } else {
    console.error('Analysis failed:', error.message);
  }
}
```

## Best Practices

1. **Rate Limiting**: Implement exponential backoff for rate limit errors
2. **Caching**: Cache analysis results to reduce API calls
3. **Webhooks**: Use webhooks for long-running monitors instead of callbacks
4. **Error Handling**: Always handle network and API errors gracefully
5. **Timeouts**: Set appropriate timeouts for deep audits
6. **Logging**: Log all security events for audit trails

## Integration Examples

See the `integrations/` directory for examples with:
- Discord bots
- Telegram bots
- CI/CD pipelines
- Monitoring dashboards

