# Quick Start Guide

Get Dynamo running in 5 minutes.

## Prerequisites

- Docker 24.0+
- Docker Compose 2.20+

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/dynamo/dynamo.git
cd dynamo
```

### 2. Start Services

```bash
docker-compose up -d
```

This will start:
- PostgreSQL (port 5432)
- Redis (port 6379)
- Rust Analyzer (port 8080)
- API Server (port 4000)
- Frontend (port 3000)

### 3. Verify Services

```bash
# Check all services are running
docker-compose ps

# Check API health
curl http://localhost:4000/health

# Check Rust analyzer health
curl http://localhost:8080/health
```

### 4. Access Dashboard

Open your browser to:
```
http://localhost:3000
```

## First Analysis

### Using the Dashboard

1. Navigate to the "Analyze" tab
2. Enter a Solana transaction signature
3. Select network (mainnet-beta, devnet, or testnet)
4. Click "Analyze Transaction"
5. View risk score and detected exploits

### Using the SDK

```bash
npm install @dynamo/sdk
```

```typescript
import { DynamoClient } from '@dynamo/sdk';

const client = new DynamoClient({
  endpoint: 'http://localhost:4000'
});

// Analyze a transaction
const result = await client.analyzeTransaction({
  signature: 'your-transaction-signature',
  network: 'mainnet-beta'
});

console.log('Risk Score:', result.risk_score);
console.log('Exploits:', result.exploits);
```

### Using cURL

```bash
curl -X POST http://localhost:4000/api/v1/analyze/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "your-transaction-signature",
    "network": "mainnet-beta"
  }'
```

## Common Use Cases

### 1. Audit a Smart Contract

```typescript
const audit = await client.auditContract({
  programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  network: 'mainnet-beta',
  depth: 'deep'
});

console.log('Vulnerabilities:', audit.vulnerabilities);
console.log('Code Quality Score:', audit.code_quality.score);
```

### 2. Monitor an Address

```typescript
const monitor = await client.monitorAddress({
  address: 'your-solana-address',
  network: 'mainnet-beta',
  callback: (alert) => {
    console.log('Alert:', alert.message);
    console.log('Risk Score:', alert.riskScore);
  }
});

console.log('Monitoring started:', monitor.monitorId);
```

### 3. Real-time Alerts

```typescript
client.subscribeToAlerts((alert) => {
  if (alert.riskScore > 70) {
    console.warn('High risk transaction detected!');
    console.log('Address:', alert.address);
    console.log('Exploits:', alert.exploits);
  }
});
```

## Configuration

### Environment Variables

Create `.env` file in `packages/api-server/`:

```env
PORT=4000
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
RUST_ANALYZER_URL=http://rust-analyzer:8080
DATABASE_URL=postgresql://dynamo:dynamo_password@postgres:5432/dynamo
REDIS_URL=redis://redis:6379
LOG_LEVEL=info
```

### Custom Solana RPC

For better performance, use a dedicated RPC endpoint:

```env
SOLANA_RPC_URL=https://your-rpc-endpoint.com
```

Recommended providers:
- QuickNode
- Alchemy
- Helius
- Triton

## Troubleshooting

### Services Not Starting

```bash
# Check logs
docker-compose logs api-server
docker-compose logs rust-analyzer

# Restart services
docker-compose restart
```

### Port Already in Use

Edit `docker-compose.yml` to change ports:

```yaml
services:
  frontend:
    ports:
      - "3001:80"  # Change 3000 to 3001
```

### Database Connection Failed

```bash
# Reset database
docker-compose down -v
docker-compose up -d
```

### High Memory Usage

```bash
# Limit container memory
docker-compose up -d --scale rust-analyzer=1
```

## Next Steps

- Read [Architecture Documentation](docs/ARCHITECTURE.md)
- Explore [API Reference](docs/API_REFERENCE.md)
- Check [Deployment Guide](docs/DEPLOYMENT.md) for production setup
- Join our Discord community

## Development Mode

### Running Locally Without Docker

#### Terminal 1: Database Services
```bash
docker-compose up postgres redis
```

#### Terminal 2: Rust Analyzer
```bash
cd packages/rust-analyzer
cargo run
```

#### Terminal 3: API Server
```bash
cd packages/api-server
npm install
npm run dev
```

#### Terminal 4: Frontend
```bash
cd packages/frontend
npm install
npm run dev
```

Access frontend at http://localhost:3000

## Performance Tips

1. Use private Solana RPC for lower latency
2. Increase Rust analyzer workers: `WORKER_THREADS=8`
3. Enable Redis persistence in production
4. Use connection pooling for database
5. Scale API server horizontally for high traffic

## Support

- GitHub Issues: Bug reports and feature requests
- Documentation: Complete guides in `/docs`
- Discord: Real-time community support
- Email: support@dynamo.security

