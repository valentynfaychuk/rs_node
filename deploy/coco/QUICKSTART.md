# Amadeus Node on Confidential Containers - Quick Start

This guide will get you running in 5 minutes.

## Prerequisites

- Kubernetes cluster with TEE-capable nodes (TDX/SEV/SGX)
- kubectl configured
- Docker installed
- Container registry accessible

## 1-Minute Setup

```bash
# Clone and navigate
cd deploy/coco

# Deploy everything
./deploy.sh
```

That's it! The script will:
1. Install CoCo operator
2. Configure TEE runtime
3. Build Docker image
4. Deploy Amadeus node

## Verify Deployment

```bash
# Check status
kubectl get pods -n amadeus

# View logs
kubectl logs -n amadeus -l app=amadeus-node -f

# Access dashboard
kubectl port-forward -n amadeus svc/amadeus-node 3000:3000
# Open http://localhost:3000
```

## Configuration Options

### Use Different TEE Platform

```bash
# Intel TDX (default)
./deploy.sh

# AMD SEV
RUNTIME_CLASS=kata-qemu-sev ./deploy.sh

# No TEE (testing)
RUNTIME_CLASS=kata ./deploy.sh
```

### Custom Docker Registry

```bash
DOCKER_REGISTRY=myregistry.com IMAGE_TAG=v1.0 ./deploy.sh
```

### Skip Image Build

```bash
SKIP_BUILD=true ./deploy.sh
```

## Test Locally (Without Kubernetes)

```bash
# Build and run in Docker
./test-local.sh

# Access at http://localhost:3000
```

## Common Commands

```bash
# View logs
kubectl logs -n amadeus -l app=amadeus-node -f

# Shell access
kubectl exec -n amadeus -it deployment/amadeus-node -- /bin/bash

# Restart node
kubectl rollout restart -n amadeus deployment/amadeus-node

# Check TEE status
kubectl exec -n amadeus deployment/amadeus-node -- \
  cat /proc/cpuinfo | grep -E 'tdx|sev'

# Delete everything
kubectl delete namespace amadeus
```

## Troubleshooting

### Pod Not Starting

```bash
# Check events
kubectl describe pod -n amadeus -l app=amadeus-node

# Check runtime class exists
kubectl get runtimeclass
```

### Can't Access Dashboard

```bash
# Port forward
kubectl port-forward -n amadeus svc/amadeus-node 3000:3000

# Check service
kubectl get svc -n amadeus
```

### Image Pull Errors

```bash
# Check image exists
docker images | grep amadeus-node

# Rebuild and push
SKIP_BUILD=false ./deploy.sh
```

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Configure [attestation](README.md#attestation) for production
- Set up [monitoring](README.md#monitoring)
- Review [security considerations](README.md#security-considerations)

## Architecture

```
Your Kubernetes Cluster
└── amadeus namespace
    ├── amadeus-node pod (runs in TDX/SEV VM)
    │   └── amadeus container
    │       └── amadeusd binary
    └── Services (HTTP API + P2P)
```

## Files Overview

- `deploy.sh` - Automated deployment script
- `test-local.sh` - Local Docker testing
- `deployment.yaml` - Kubernetes deployment
- `service.yaml` - Network services
- `ccruntime.yaml` - CoCo runtime config
- `README.md` - Full documentation

## Support

- Amadeus Issues: GitHub repository
- CoCo Issues: [Slack #confidential-containers](https://cloud-native.slack.com/)
- Hardware Issues: Vendor documentation
