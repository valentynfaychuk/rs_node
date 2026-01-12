#!/usr/bin/env bash
# Local testing script for Amadeus Node container
# Tests the Docker image without Kubernetes/CoCo
set -euo pipefail

# Configuration
IMAGE_NAME="${IMAGE_NAME:-amadeus-node}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-amadeus-test}"
HTTP_PORT="${HTTP_PORT:-3000}"
UDP_PORT="${UDP_PORT:-36969}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."
    if docker ps -a | grep -q ${CONTAINER_NAME}; then
        docker stop ${CONTAINER_NAME} 2>/dev/null || true
        docker rm ${CONTAINER_NAME} 2>/dev/null || true
    fi
}

build_image() {
    log_info "Building Docker image..."
    cd ../..
    docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -f Dockerfile .
    cd deploy/coco
    log_info "Image built successfully"
}

run_container() {
    log_info "Starting container..."

    docker run -d \
        --name ${CONTAINER_NAME} \
        -p ${HTTP_PORT}:3000 \
        -p ${UDP_PORT}:36969/udp \
        -e RUST_LOG=info \
        -e UDP_ADDR=0.0.0.0:36969 \
        -e HTTP_PORT=3000 \
        -v amadeus-data:/home/amadeus/.amadeusd-rs \
        ${IMAGE_NAME}:${IMAGE_TAG}

    log_info "Container started: ${CONTAINER_NAME}"
}

wait_for_health() {
    log_info "Waiting for node to be ready..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sf http://localhost:${HTTP_PORT}/health > /dev/null 2>&1; then
            log_info "Node is healthy!"
            return 0
        fi

        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done

    log_error "Node failed to become healthy"
    docker logs ${CONTAINER_NAME}
    return 1
}

show_status() {
    log_info "Container Status:"
    docker ps -a | grep ${CONTAINER_NAME}
    echo ""

    log_info "Container Logs:"
    docker logs ${CONTAINER_NAME} --tail=20
    echo ""

    log_info "Access the node:"
    log_info "  HTTP API: http://localhost:${HTTP_PORT}"
    log_info "  Dashboard: http://localhost:${HTTP_PORT}"
    log_info "  View logs: docker logs -f ${CONTAINER_NAME}"
    log_info "  Shell: docker exec -it ${CONTAINER_NAME} /bin/bash"
    echo ""

    log_info "To stop the container:"
    log_info "  docker stop ${CONTAINER_NAME}"
    log_info "  docker rm ${CONTAINER_NAME}"
}

main() {
    log_info "Testing Amadeus Node Docker image locally"
    echo ""

    # Trap cleanup on script exit
    trap cleanup EXIT SIGINT SIGTERM

    # Clean up any existing container
    cleanup

    # Build and run
    build_image
    run_container
    wait_for_health
    show_status

    log_info "Test completed successfully!"
    log_info "Container is running. Press Ctrl+C to stop and cleanup."

    # Wait for interrupt
    read -r -d '' _ </dev/tty
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    cat << EOF
Usage: $0

Test Amadeus Node Docker image locally without Kubernetes

Environment Variables:
  IMAGE_NAME      Docker image name (default: amadeus-node)
  IMAGE_TAG       Docker image tag (default: latest)
  CONTAINER_NAME  Container name (default: amadeus-test)
  HTTP_PORT       HTTP port mapping (default: 3000)
  UDP_PORT        UDP port mapping (default: 36969)

Examples:
  # Run with defaults
  $0

  # Use custom ports
  HTTP_PORT=8080 UDP_PORT=9000 $0
EOF
    exit 0
fi

main
