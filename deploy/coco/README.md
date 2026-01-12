# Amadeus Node - Confidential Containers Deployment

This directory contains deployment configurations for running Amadeus blockchain node on Confidential Containers (CoCo) with trusted execution environment (TEE) support.

## Overview

Confidential Containers is a CNCF Sandbox Project that enables cloud-native confidential computing by leveraging hardware security technologies:
- **Intel TDX** (Trust Domain Extensions)
- **AMD SEV** (Secure Encrypted Virtualization)
- **Intel SGX** (Software Guard Extensions)
- **IBM Z Secure Execution**

## Architecture

```
┌─────────────────────────────────────────────┐
│         Kubernetes Cluster                  │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │   Amadeus Node Pod                   │  │
│  │   (runtimeClass: kata-qemu-tdx)      │  │
│  │                                      │  │
│  │  ┌────────────────────────────────┐ │  │
│  │  │  Amadeus Container             │ │  │
│  │  │  - amadeusd binary             │ │  │
│  │  │  - Configuration               │ │  │
│  │  │  - Persistent storage          │ │  │
│  │  └────────────────────────────────┘ │  │
│  │         ▲                           │  │
│  │         │ Kata Runtime              │  │
│  │         ▼                           │  │
│  │  ┌────────────────────────────────┐ │  │
│  │  │  TEE-Protected VM (TDX/SEV)    │ │  │
│  │  │  - Hardware memory encryption  │ │  │
│  │  │  - Attestation support         │ │  │
│  │  └────────────────────────────────┘ │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │   CoCo Operator                      │  │
│  │   - Manages runtime configuration    │  │
│  │   - Creates runtime classes          │  │
│  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
           ▲
           │ Hardware TEE Support
           ▼
┌─────────────────────────────────────────────┐
│         Physical Node                       │
│  - Intel TDX / AMD SEV enabled CPU         │
│  - BIOS configuration for TEE              │
└─────────────────────────────────────────────┘
```

## Prerequisites

### Hardware Requirements
- CPU with TEE support:
  - Intel TDX (4th Gen Xeon or newer)
  - AMD SEV-SNP (EPYC Milan or newer)
  - Intel SGX (for process-based isolation)
- Minimum 8GB RAM per node
- 100GB storage for blockchain data

### Software Requirements
- Kubernetes cluster (1.24+)
- kubectl CLI tool
- Docker or compatible container runtime
- Container registry (for custom images)

### BIOS/Firmware Configuration
For TDX:
```bash
# Check TDX support
cat /sys/firmware/tdx_seam/tdx_module_version
```

For SEV:
```bash
# Check SEV support
dmesg | grep -i sev
```

## Quick Start

### 1. Install CoCo Operator

```bash
# Install the operator (latest version)
kubectl apply -k "github.com/confidential-containers/operator/config/release?ref=v0.17.0"

# Wait for operator to be ready
kubectl wait --for=condition=Ready \
  --namespace confidential-containers-system \
  pod -l app.kubernetes.io/name=cc-operator-controller-manager \
  --timeout=300s
```

### 2. Configure Runtime

Apply the CcRuntime custom resource for your hardware:

```bash
# Deploy runtime configuration
kubectl apply -f ccruntime.yaml

# Verify runtime classes are created
kubectl get runtimeclass
```

### 3. Build and Deploy Amadeus Node

**Option A: Automated deployment (recommended)**

```bash
# Run the deployment script
./deploy.sh
```

**Option B: Manual deployment**

```bash
# Build Docker image
cd ../..
docker build -t localhost:5000/amadeus-node:latest .
docker push localhost:5000/amadeus-node:latest

# Deploy using kubectl
cd deploy/coco
kubectl apply -k .
```

**Option C: Using kustomize**

```bash
kubectl apply -k .
```

### 4. Verify Deployment

```bash
# Check pod status
kubectl get pods -n amadeus

# View logs
kubectl logs -n amadeus -l app=amadeus-node -f

# Check if running in TEE
kubectl exec -n amadeus deployment/amadeus-node -- \
  cat /proc/cpuinfo | grep -E 'tdx|sev'
```

## Configuration

### Environment Variables

Configure the node via ConfigMap (`configmap.yaml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `UDP_ADDR` | `0.0.0.0:36969` | P2P network address |
| `HTTP_PORT` | `3000` | API/Dashboard port |
| `RUST_LOG` | `info` | Log level (debug, info, warn, error) |
| `WORKFOLDER` | `/home/amadeus/.amadeusd-rs` | Data directory |

### Runtime Classes

Choose the appropriate runtime class in `deployment.yaml`:

| Runtime Class | Hardware | Use Case |
|---------------|----------|----------|
| `kata-qemu-tdx` | Intel TDX | Production with TDX |
| `kata-qemu-sev` | AMD SEV | Production with SEV |
| `kata-clh-tdx` | Intel TDX | Cloud Hypervisor backend |
| `kata` | Generic | Testing without TEE |

### Storage Configuration

Adjust storage size in `pvc.yaml`:

```yaml
resources:
  requests:
    storage: 100Gi  # Adjust based on blockchain size
```

### Resource Limits

Modify resources in `deployment.yaml`:

```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "8Gi"
    cpu: "4000m"
```

## Deployment Script Options

The `deploy.sh` script supports several environment variables:

```bash
# Deploy with AMD SEV
RUNTIME_CLASS=kata-qemu-sev ./deploy.sh

# Deploy with custom registry
DOCKER_REGISTRY=myregistry.com IMAGE_TAG=v1.0.0 ./deploy.sh

# Skip image rebuild (use existing image)
SKIP_BUILD=true ./deploy.sh

# Use specific CoCo version
COCO_VERSION=v0.16.0 ./deploy.sh
```

## Accessing the Node

### Port Forwarding

```bash
# Access HTTP API
kubectl port-forward -n amadeus svc/amadeus-node 3000:3000

# Access dashboard
open http://localhost:3000
```

### Shell Access

```bash
# Get a shell inside the container
kubectl exec -n amadeus -it deployment/amadeus-node -- /bin/bash
```

### View Logs

```bash
# Follow logs
kubectl logs -n amadeus -l app=amadeus-node -f

# Get recent logs
kubectl logs -n amadeus -l app=amadeus-node --tail=100
```

## Attestation

CoCo supports remote attestation to verify the node is running in a genuine TEE:

```bash
# The pod annotation enables attestation
io.katacontainers.config.hypervisor.kernel_params: "agent.aa_kbc_params=cc_kbc::http://127.0.0.1:8006"
```

For production deployments, configure attestation service (KBS - Key Broker Service).

## Security Considerations

1. **Image Verification**: Use signed container images
2. **Secret Management**: Use encrypted secrets with attestation
3. **Network Policies**: Restrict pod network access
4. **RBAC**: Limit access to confidential workloads
5. **Audit Logging**: Enable Kubernetes audit logs
6. **Node Isolation**: Use dedicated nodes for confidential workloads

### Example Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: amadeus-node-policy
  namespace: amadeus
spec:
  podSelector:
    matchLabels:
      app: amadeus-node
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: amadeus
    ports:
    - protocol: TCP
      port: 3000
    - protocol: UDP
      port: 36969
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 53  # DNS
    - protocol: UDP
      port: 53  # DNS
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod -n amadeus -l app=amadeus-node

# Check runtime class
kubectl get runtimeclass

# Verify node has TEE support
kubectl get nodes -o json | jq '.items[].status.allocatable'
```

### Performance Issues

```bash
# Check resource usage
kubectl top pod -n amadeus

# Increase resource limits
kubectl edit deployment -n amadeus amadeus-node
```

### Networking Issues

```bash
# Check service endpoints
kubectl get endpoints -n amadeus

# Test connectivity
kubectl run -n amadeus test --rm -it --image=busybox -- wget -O- http://amadeus-node:3000/health
```

### TEE Verification

```bash
# Check if running in TEE
kubectl exec -n amadeus deployment/amadeus-node -- dmesg | grep -i tdx

# Verify attestation
kubectl logs -n amadeus -l app=amadeus-node | grep attestation
```

## Monitoring

### Prometheus Integration

Add ServiceMonitor for metrics collection:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: amadeus-node
  namespace: amadeus
spec:
  selector:
    matchLabels:
      app: amadeus-node
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

### Health Checks

The deployment includes:
- **Liveness probe**: Restarts pod if unhealthy
- **Readiness probe**: Removes from service if not ready

```bash
# Check health endpoint
kubectl exec -n amadeus deployment/amadeus-node -- \
  curl -f http://localhost:3000/health
```

## Cleanup

Remove all resources:

```bash
# Delete Amadeus node
kubectl delete -k .

# Remove CoCo operator (optional)
kubectl delete -k "github.com/confidential-containers/operator/config/release?ref=v0.17.0"
```

## Additional Resources

- [Confidential Containers Documentation](https://github.com/confidential-containers/documentation)
- [CoCo Operator Guide](https://github.com/confidential-containers/operator/blob/main/docs/INSTALL.md)
- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [AMD SEV Documentation](https://www.amd.com/en/developer/sev.html)
- [Kata Containers](https://katacontainers.io/)

## Support

For issues related to:
- **Amadeus Node**: Open issue in Amadeus repository
- **CoCo Deployment**: Check [CoCo Slack](https://cloud-native.slack.com/archives/C04APEKQWT9)
- **TEE Hardware**: Consult hardware vendor documentation
