#!/usr/bin/env bash
# Deployment script for Amadeus Node on Confidential Containers
set -euo pipefail

# Configuration
NAMESPACE="amadeus"
COCO_VERSION="${COCO_VERSION:-v0.17.0}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-localhost:5000}"
IMAGE_NAME="${IMAGE_NAME:-amadeus-node}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
RUNTIME_CLASS="${RUNTIME_CLASS:-kata-qemu-tdx}"
SKIP_BUILD="${SKIP_BUILD:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for required commands
    for cmd in kubectl docker; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd is not installed. Please install it first."
            exit 1
        fi
    done

    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi

    log_info "Prerequisites check passed"
}

install_coco_operator() {
    log_info "Installing Confidential Containers Operator..."

    # Check if operator is already installed
    if kubectl get namespace confidential-containers-system &> /dev/null; then
        log_warn "CoCo operator namespace already exists. Skipping installation."
        return 0
    fi

    # Install the operator using kustomize
    kubectl apply -k "github.com/confidential-containers/operator/config/release?ref=${COCO_VERSION}"

    # Wait for operator to be ready
    log_info "Waiting for CoCo operator to be ready..."
    kubectl wait --for=condition=Ready \
        --namespace confidential-containers-system \
        pod -l app.kubernetes.io/name=cc-operator-controller-manager \
        --timeout=300s

    log_info "CoCo operator installed successfully"
}

deploy_ccruntime() {
    log_info "Deploying CcRuntime custom resource..."

    # Apply the CcRuntime configuration
    kubectl apply -f ccruntime.yaml

    # Wait for runtime classes to be created
    log_info "Waiting for runtime classes to be created..."
    sleep 10

    # Check if runtime class exists
    if kubectl get runtimeclass ${RUNTIME_CLASS} &> /dev/null; then
        log_info "Runtime class ${RUNTIME_CLASS} created successfully"
    else
        log_warn "Runtime class ${RUNTIME_CLASS} not found. You may need to adjust the deployment."
    fi
}

build_and_push_image() {
    if [ "$SKIP_BUILD" = "true" ]; then
        log_warn "Skipping image build (SKIP_BUILD=true)"
        return 0
    fi

    log_info "Building Docker image..."

    # Build the image
    cd ../..
    docker build -t ${DOCKER_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} -f Dockerfile .

    log_info "Pushing Docker image to registry..."
    docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}

    log_info "Docker image pushed successfully"
    cd deploy/coco
}

update_deployment_manifest() {
    log_info "Updating deployment manifest with image and runtime class..."

    # Create a temporary deployment file with substitutions
    sed -e "s|image: amadeus-node:latest|image: ${DOCKER_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}|g" \
        -e "s|runtimeClassName: kata-qemu-tdx|runtimeClassName: ${RUNTIME_CLASS}|g" \
        deployment.yaml > deployment-generated.yaml

    log_info "Deployment manifest updated"
}

deploy_amadeus_node() {
    log_info "Deploying Amadeus Node..."

    # Create namespace
    kubectl apply -f namespace.yaml

    # Create ConfigMap
    kubectl apply -f configmap.yaml

    # Create PVC
    kubectl apply -f pvc.yaml

    # Deploy the node
    kubectl apply -f deployment-generated.yaml

    # Create services
    kubectl apply -f service.yaml

    log_info "Amadeus Node deployed successfully"

    # Wait for pod to be ready
    log_info "Waiting for Amadeus Node to be ready..."
    kubectl wait --for=condition=Ready \
        --namespace ${NAMESPACE} \
        pod -l app=amadeus-node \
        --timeout=600s || {
            log_error "Timeout waiting for Amadeus Node to be ready"
            log_info "Checking pod status..."
            kubectl get pods -n ${NAMESPACE}
            log_info "Checking pod logs..."
            kubectl logs -n ${NAMESPACE} -l app=amadeus-node --tail=50
            exit 1
        }

    log_info "Amadeus Node is ready!"
}

show_status() {
    log_info "Deployment Status:"
    echo ""

    log_info "Runtime Classes:"
    kubectl get runtimeclass
    echo ""

    log_info "Amadeus Namespace Resources:"
    kubectl get all -n ${NAMESPACE}
    echo ""

    log_info "Service Endpoints:"
    kubectl get svc -n ${NAMESPACE}
    echo ""

    log_info "Pod Details:"
    kubectl describe pod -n ${NAMESPACE} -l app=amadeus-node
}

cleanup() {
    log_info "Cleaning up..."
    rm -f deployment-generated.yaml
}

main() {
    log_info "Starting Amadeus Node deployment on Confidential Containers"
    log_info "Configuration:"
    log_info "  CoCo Version: ${COCO_VERSION}"
    log_info "  Docker Registry: ${DOCKER_REGISTRY}"
    log_info "  Image: ${IMAGE_NAME}:${IMAGE_TAG}"
    log_info "  Runtime Class: ${RUNTIME_CLASS}"
    echo ""

    # Trap cleanup on exit
    trap cleanup EXIT

    check_prerequisites
    install_coco_operator
    deploy_ccruntime
    build_and_push_image
    update_deployment_manifest
    deploy_amadeus_node
    show_status

    log_info "Deployment completed successfully!"
    log_info ""
    log_info "To access the node:"
    log_info "  HTTP API: kubectl port-forward -n ${NAMESPACE} svc/amadeus-node 3000:3000"
    log_info "  View logs: kubectl logs -n ${NAMESPACE} -l app=amadeus-node -f"
    log_info "  Shell access: kubectl exec -n ${NAMESPACE} -it deployment/amadeus-node -- /bin/bash"
}

# Show usage if help requested
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    cat << EOF
Usage: $0 [OPTIONS]

Deploy Amadeus Node on Confidential Containers

Environment Variables:
  COCO_VERSION       CoCo operator version (default: v0.17.0)
  DOCKER_REGISTRY    Docker registry to push images (default: localhost:5000)
  IMAGE_NAME         Docker image name (default: amadeus-node)
  IMAGE_TAG          Docker image tag (default: latest)
  RUNTIME_CLASS      Kubernetes runtime class (default: kata-qemu-tdx)
                     Options: kata-qemu-tdx, kata-qemu-sev, kata
  SKIP_BUILD         Skip building Docker image (default: false)

Examples:
  # Deploy with default settings
  $0

  # Deploy using AMD SEV runtime
  RUNTIME_CLASS=kata-qemu-sev $0

  # Deploy with custom registry
  DOCKER_REGISTRY=myregistry.com IMAGE_TAG=v1.0.0 $0

  # Deploy without rebuilding image
  SKIP_BUILD=true $0
EOF
    exit 0
fi

main
