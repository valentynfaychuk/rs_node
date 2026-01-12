# Deploy Amadeus Node to Remote SGX Server with CoCo

This guide shows how to deploy the pre-built Amadeus container package to your remote SGX server running Confidential Containers.

## Package Built

- **File**: `amadeus-node-coco.tar`
- **Size**: 39MB
- **Contents**: Amadeus node with all runtime dependencies
- **Platform**: linux/arm64 (rebuild for linux/amd64 if needed)

## Prerequisites on Remote Server

### Hardware
- Intel SGX-capable CPU (or TDX/SEV for other TEE options)
- SGX drivers and BIOS configuration enabled
- Minimum 4GB RAM, 50GB disk

### Software
- Kubernetes cluster running (1.24+)
- Confidential Containers operator installed
- Docker or containerd runtime
- kubectl configured

## Step 1: Transfer Package to Remote Server

```bash
# From your local machine
scp amadeus-node-coco.tar user@remote-sgx-server:~/

# Or use rsync for better transfer
rsync -avz --progress amadeus-node-coco.tar user@remote-sgx-server:~/
```

## Step 2: Load Image on Remote Server

SSH into your remote server and load the image:

```bash
ssh user@remote-sgx-server

# Load the Docker image
docker load -i amadeus-node-coco.tar

# Verify image loaded
docker images | grep amadeus-node
# Should show: amadeus-node   latest   <image-id>   <size>
```

## Step 3: Tag and Push to Local Registry (Optional)

If using Kubernetes, push to a registry accessible to your cluster:

```bash
# Tag for your registry
docker tag amadeus-node:latest localhost:5000/amadeus-node:latest

# Or for a remote registry
docker tag amadeus-node:latest myregistry.com/amadeus-node:latest

# Push to registry
docker push localhost:5000/amadeus-node:latest
```

## Step 4: Install Confidential Containers Operator

If not already installed:

```bash
# Install CoCo operator (latest version)
kubectl apply -k "github.com/confidential-containers/operator/config/release?ref=v0.17.0"

# Wait for operator to be ready
kubectl wait --for=condition=Ready \
  --namespace confidential-containers-system \
  pod -l app.kubernetes.io/name=cc-operator-controller-manager \
  --timeout=300s
```

## Step 5: Deploy CcRuntime Configuration

Transfer the deployment files to your server:

```bash
# From local machine, copy deployment configs
scp -r deploy/coco user@remote-sgx-server:~/amadeus-deploy/
```

On the remote server:

```bash
cd ~/amadeus-deploy

# Apply CcRuntime for SGX
kubectl apply -f ccruntime.yaml

# Wait for runtime classes to be created
sleep 10
kubectl get runtimeclass
```

You should see runtime classes like:
- `kata-qemu-tdx`
- `kata-qemu-sev`
- `kata` (generic)

## Step 6: Deploy Amadeus Node

### Update deployment manifest

Edit `deployment.yaml` to use your image:

```bash
# Update image reference if using registry
sed -i 's|image: amadeus-node:latest|image: localhost:5000/amadeus-node:latest|g' deployment.yaml

# For SGX, ensure correct runtime class
# Options: kata-qemu-tdx, kata-qemu-sev, kata (for SGX use kata-qemu-tdx or kata)
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Create ConfigMap
kubectl apply -f configmap.yaml

# Create persistent volume claim
kubectl apply -f pvc.yaml

# Deploy the node
kubectl apply -f deployment.yaml

# Create services
kubectl apply -f service.yaml
```

### Or use kustomize

```bash
# One command deployment
kubectl apply -k .
```

## Step 7: Verify Deployment

```bash
# Check pod status
kubectl get pods -n amadeus -w

# Should show:
# NAME                            READY   STATUS    RESTARTS   AGE
# amadeus-node-xxxxxxxxxx-xxxxx   1/1     Running   0          30s

# View logs
kubectl logs -n amadeus -l app=amadeus-node -f

# Check if running in TEE
kubectl exec -n amadeus deployment/amadeus-node -- cat /proc/cpuinfo | grep -E 'sgx|tdx'
```

## Step 8: Access the Node

### Port Forwarding

```bash
# Forward HTTP API port
kubectl port-forward -n amadeus svc/amadeus-node 3000:3000 &

# Test health endpoint
curl http://localhost:3000/health
```

### External Access

If using LoadBalancer service:

```bash
# Get external IP
kubectl get svc -n amadeus amadeus-node

# Access via external IP
curl http://<EXTERNAL-IP>:3000/health
```

## SGX-Specific Configuration

### Verify SGX Support

```bash
# Check SGX is enabled
cat /sys/firmware/sgx/attestation/keys/qe_id

# Check DCAP libraries
ls -la /usr/lib/x86_64-linux-gnu/libdcap*
```

### Configure SGX Runtime Class

For SGX, you may need to adjust the deployment to use SGX-specific runtime:

```yaml
# In deployment.yaml
spec:
  runtimeClassName: kata-clh  # or kata-qemu with SGX support

  # Add SGX device resources
  containers:
  - name: amadeus
    resources:
      limits:
        sgx.intel.com/epc: "512Mi"  # Enclave Page Cache size
```

### Enable SGX Device Plugin (if needed)

```bash
# Deploy Intel SGX device plugin
kubectl apply -k https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/sgx_plugin/overlays/epc-nfd/
```

## Attestation Configuration

For production, enable remote attestation:

### 1. Deploy Key Broker Service (KBS)

```bash
# This is platform-specific, example for Intel TDX/SGX:
kubectl apply -f https://raw.githubusercontent.com/confidential-containers/trustee/main/kbs/deploy/kbs.yaml
```

### 2. Update Pod Annotation

Add to `deployment.yaml`:

```yaml
metadata:
  annotations:
    io.katacontainers.config.hypervisor.kernel_params: "agent.aa_kbc_params=cc_kbc::http://kbs-service:8080"
```

### 3. Configure Attestation Policy

Create attestation policy for your workload (see CoCo documentation).

## Monitoring

### View Metrics

```bash
# If metrics are enabled
kubectl port-forward -n amadeus svc/amadeus-node 3000:3000
curl http://localhost:3000/metrics
```

### Check Resource Usage

```bash
kubectl top pod -n amadeus
```

### View Events

```bash
kubectl get events -n amadeus --sort-by='.lastTimestamp'
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod -n amadeus -l app=amadeus-node

# Common issues:
# 1. Image not found - ensure image is in accessible registry
# 2. Runtime class not found - check CoCo operator installed
# 3. SGX resources not available - verify SGX device plugin
```

### Check Runtime Class

```bash
# Verify runtime class exists
kubectl get runtimeclass

# Check nodes with TEE support
kubectl get nodes -o json | jq '.items[].metadata.labels' | grep -i sgx
```

### Check CoCo Operator Logs

```bash
kubectl logs -n confidential-containers-system \
  -l app.kubernetes.io/name=cc-operator-controller-manager -f
```

### Test Without TEE First

For debugging, use generic runtime:

```yaml
# In deployment.yaml
runtimeClassName: kata  # Generic, no TEE
```

## Performance Tuning

### Adjust Resource Limits

```yaml
resources:
  requests:
    memory: "4Gi"
    cpu: "2000m"
  limits:
    memory: "16Gi"
    cpu: "8000m"
```

### Increase EPC Size (SGX)

```yaml
resources:
  limits:
    sgx.intel.com/epc: "2Gi"  # Increase from default 512Mi
```

### Enable Huge Pages

```yaml
volumes:
- name: hugepage
  emptyDir:
    medium: HugePages-2Mi
volumeMounts:
- name: hugepage
  mountPath: /dev/hugepages
```

## Updating the Image

To update with a new version:

```bash
# 1. Build new package locally
cargo build --release -p amadeusd
docker build -t amadeus-node:v1.3.6 -f Dockerfile.minimal .
docker save amadeus-node:v1.3.6 -o amadeus-node-v1.3.6.tar

# 2. Transfer to server
scp amadeus-node-v1.3.6.tar user@remote-sgx-server:~/

# 3. Load and deploy
ssh user@remote-sgx-server
docker load -i amadeus-node-v1.3.6.tar
kubectl set image deployment/amadeus-node amadeus=amadeus-node:v1.3.6 -n amadeus

# 4. Watch rollout
kubectl rollout status deployment/amadeus-node -n amadeus
```

## Cleanup

To remove the deployment:

```bash
# Delete namespace (removes all resources)
kubectl delete namespace amadeus

# Or delete individual resources
kubectl delete -k .
```

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│         Remote SGX Server                   │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │   Kubernetes Cluster                 │  │
│  │                                      │  │
│  │  ┌────────────────────────────────┐ │  │
│  │  │  amadeus namespace             │ │  │
│  │  │                                │ │  │
│  │  │  ┌──────────────────────────┐ │ │  │
│  │  │  │  amadeus-node Pod        │ │ │  │
│  │  │  │  runtimeClass: kata      │ │ │  │
│  │  │  │                          │ │ │  │
│  │  │  │  Container:              │ │ │  │
│  │  │  │  └─ amadeusd (17MB)     │ │ │  │
│  │  │  │                          │ │ │  │
│  │  │  │  Kata Runtime            │ │ │  │
│  │  │  │  └─ TEE-protected VM     │ │ │  │
│  │  │  │     └─ SGX Enclave       │ │ │  │
│  │  │  └──────────────────────────┘ │ │  │
│  │  │                                │ │  │
│  │  │  Services:                    │ │  │
│  │  │  - HTTP: :3000                │ │  │
│  │  │  - P2P: :36969/udp            │ │  │
│  │  └────────────────────────────────┘ │  │
│  │                                      │  │
│  │  CoCo Operator                       │  │
│  │  └─ Manages runtime classes          │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  Docker/containerd                          │
│  └─ amadeus-node:latest (loaded)           │
│                                             │
│  Hardware: Intel SGX CPU                    │
└─────────────────────────────────────────────┘
```

## Security Best Practices

1. **Image Verification**: Use signed images in production
2. **Network Policies**: Restrict pod network access
3. **Secrets Management**: Use sealed secrets with attestation
4. **RBAC**: Limit access to confidential workloads
5. **Audit Logging**: Enable Kubernetes audit logs
6. **Regular Updates**: Keep CoCo operator and images updated

## Next Steps

- Configure attestation for production
- Set up monitoring and alerting
- Implement backup strategy for blockchain data
- Configure high availability (multiple replicas)
- Set up CI/CD pipeline for automated deployments

## Support

- **CoCo Issues**: [GitHub - confidential-containers/operator](https://github.com/confidential-containers/operator/issues)
- **Intel SGX**: [Intel SGX Documentation](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
- **Kubernetes**: [Kubernetes Documentation](https://kubernetes.io/docs/)
