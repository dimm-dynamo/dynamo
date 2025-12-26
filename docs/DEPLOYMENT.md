# Deployment Guide

## Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- 4GB+ available RAM
- 10GB+ available disk space

For production:
- Kubernetes 1.28+
- kubectl configured
- Helm 3.0+

## Local Development Deployment

### 1. Clone Repository

```bash
git clone https://github.com/dynamo/dynamo.git
cd dynamo
```

### 2. Environment Configuration

Create environment files:

```bash
cp packages/api-server/.env.example packages/api-server/.env
```

Edit `packages/api-server/.env`:

```env
PORT=4000
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
RUST_ANALYZER_URL=http://rust-analyzer:8080
DATABASE_URL=postgresql://dynamo:dynamo_password@postgres:5432/dynamo
REDIS_URL=redis://redis:6379
AI_CLUSTER_NODES=
LOG_LEVEL=info
```

### 3. Start Services

```bash
docker-compose up -d
```

### 4. Verify Deployment

```bash
# Check service health
curl http://localhost:4000/health
curl http://localhost:8080/health

# Check logs
docker-compose logs -f api-server
docker-compose logs -f rust-analyzer
```

### 5. Access Dashboard

Open browser to `http://localhost:3000`

## Production Deployment

### Option 1: Docker Swarm

#### 1. Initialize Swarm

```bash
docker swarm init
```

#### 2. Create Secrets

```bash
echo "your-database-password" | docker secret create db_password -
echo "your-api-key" | docker secret create api_key -
```

#### 3. Deploy Stack

```bash
docker stack deploy -c docker-compose.prod.yml dynamo
```

#### 4. Scale Services

```bash
docker service scale dynamo_api-server=5
docker service scale dynamo_rust-analyzer=3
```

### Option 2: Kubernetes

#### 1. Create Namespace

```bash
kubectl create namespace dynamo
```

#### 2. Create Secrets

```bash
kubectl create secret generic dynamo-secrets \
  --from-literal=database-url='postgresql://user:pass@postgres:5432/dynamo' \
  --from-literal=redis-url='redis://redis:6379' \
  -n dynamo
```

#### 3. Deploy PostgreSQL

```yaml
# postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: dynamo
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:16-alpine
        env:
        - name: POSTGRES_DB
          value: dynamo
        - name: POSTGRES_USER
          value: dynamo
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: dynamo-secrets
              key: postgres-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 50Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: dynamo
spec:
  ports:
  - port: 5432
  selector:
    app: postgres
  clusterIP: None
```

#### 4. Deploy Redis

```yaml
# redis.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: dynamo
spec:
  serviceName: redis
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-storage
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: redis-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: dynamo
spec:
  ports:
  - port: 6379
  selector:
    app: redis
  clusterIP: None
```

#### 5. Deploy Rust Analyzer

```yaml
# rust-analyzer.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rust-analyzer
  namespace: dynamo
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rust-analyzer
  template:
    metadata:
      labels:
        app: rust-analyzer
    spec:
      containers:
      - name: rust-analyzer
        image: dynamo/rust-analyzer:latest
        env:
        - name: RUST_LOG
          value: info
        - name: BIND_ADDRESS
          value: "0.0.0.0:8080"
        - name: SOLANA_RPC_URL
          value: "https://api.mainnet-beta.solana.com"
        ports:
        - containerPort: 8080
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: rust-analyzer
  namespace: dynamo
spec:
  selector:
    app: rust-analyzer
  ports:
  - port: 8080
    targetPort: 8080
```

#### 6. Deploy API Server

```yaml
# api-server.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: dynamo
spec:
  replicas: 5
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
    spec:
      containers:
      - name: api-server
        image: dynamo/api-server:latest
        env:
        - name: PORT
          value: "4000"
        - name: NODE_ENV
          value: production
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: dynamo-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: dynamo-secrets
              key: redis-url
        - name: RUST_ANALYZER_URL
          value: "http://rust-analyzer:8080"
        ports:
        - containerPort: 4000
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 4000
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: api-server
  namespace: dynamo
spec:
  selector:
    app: api-server
  ports:
  - port: 4000
    targetPort: 4000
```

#### 7. Deploy Frontend

```yaml
# frontend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: dynamo
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        image: dynamo/frontend:latest
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: dynamo
spec:
  selector:
    app: frontend
  ports:
  - port: 80
    targetPort: 80
```

#### 8. Setup Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dynamo-ingress
  namespace: dynamo
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - dynamo.example.com
    secretName: dynamo-tls
  rules:
  - host: dynamo.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-server
            port:
              number: 4000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

#### 9. Apply Configurations

```bash
kubectl apply -f postgres.yaml
kubectl apply -f redis.yaml
kubectl apply -f rust-analyzer.yaml
kubectl apply -f api-server.yaml
kubectl apply -f frontend.yaml
kubectl apply -f ingress.yaml
```

#### 10. Verify Deployment

```bash
kubectl get pods -n dynamo
kubectl get services -n dynamo
kubectl logs -f deployment/api-server -n dynamo
```

## Environment Variables Reference

### API Server

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| PORT | No | 4000 | Server port |
| NODE_ENV | No | development | Environment |
| SOLANA_RPC_URL | Yes | - | Solana RPC endpoint |
| RUST_ANALYZER_URL | Yes | - | Rust analyzer URL |
| DATABASE_URL | Yes | - | PostgreSQL connection |
| REDIS_URL | Yes | - | Redis connection |
| AI_CLUSTER_NODES | No | - | Comma-separated AI node URLs |
| LOG_LEVEL | No | info | Log level |

### Rust Analyzer

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| RUST_LOG | No | info | Log level |
| BIND_ADDRESS | No | 0.0.0.0:8080 | Bind address |
| SOLANA_RPC_URL | Yes | - | Solana RPC endpoint |
| WORKER_THREADS | No | 4 | Worker thread count |

## Performance Tuning

### Database

```sql
-- Increase connection pool
ALTER SYSTEM SET max_connections = 200;

-- Enable query optimization
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';

-- Reload configuration
SELECT pg_reload_conf();
```

### Redis

```conf
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
tcp-backlog 511
timeout 300
```

### API Server

```env
# Increase BullMQ concurrency
BULLMQ_CONCURRENCY=20

# Increase rate limits
RATE_LIMIT_MAX=200
RATE_LIMIT_WINDOW=900000
```

## Monitoring

### Prometheus Metrics

```yaml
# prometheus-config.yaml
scrape_configs:
  - job_name: 'api-server'
    static_configs:
      - targets: ['api-server:4000']
  
  - job_name: 'rust-analyzer'
    static_configs:
      - targets: ['rust-analyzer:8080']
```

### Grafana Dashboard

Import dashboard from `docs/grafana-dashboard.json`

Key metrics:
- Request rate (requests/second)
- Response time (p50, p95, p99)
- Error rate
- Active monitors
- Analysis throughput

## Backup and Recovery

### Database Backup

```bash
# Daily backup
docker exec postgres pg_dump -U dynamo dynamo > backup-$(date +%Y%m%d).sql

# Restore
docker exec -i postgres psql -U dynamo dynamo < backup.sql
```

### Kubernetes Backup

```bash
# Using Velero
velero backup create dynamo-backup --include-namespaces dynamo
velero restore create --from-backup dynamo-backup
```

## Troubleshooting

### Service Not Starting

```bash
# Check logs
docker-compose logs api-server
kubectl logs -f deployment/api-server -n dynamo

# Check database connection
docker exec -it postgres psql -U dynamo -d dynamo -c "SELECT NOW();"
```

### High Memory Usage

```bash
# Restart service
docker-compose restart api-server
kubectl rollout restart deployment/api-server -n dynamo

# Increase resources
docker-compose up -d --scale api-server=3
kubectl scale deployment/api-server --replicas=5 -n dynamo
```

### Slow Analysis

Check Solana RPC latency, increase Rust analyzer replicas, verify AI cluster health.

