# Building Amadeus CoCo Package

Quick guide to build the container package for Confidential Containers deployment.

## Quick Build

```bash
# 1. Build the binary
cargo build --release -p amadeusd --bin amadeusd

# 2. Copy to build directory (for Docker)
mkdir -p build
cp target/release/amadeusd build/

# 3. Build minimal container image
docker build -t amadeus-node:latest -f Dockerfile.minimal .

# 4. Export as portable package
docker save amadeus-node:latest -o amadeus-node-coco.tar

# 5. Check package
ls -lh amadeus-node-coco.tar
```

## What You Get

- **Package**: `amadeus-node-coco.tar` (~39MB)
- **Contents**: Amadeus node + runtime dependencies
- **Base**: Debian bookworm-slim
- **User**: Non-root (uid 1000)
- **Ports**: 3000/tcp (HTTP), 36969/udp (P2P)

## Deploy to Remote Server

See [DEPLOY_REMOTE_SGX.md](deploy/coco/DEPLOY_REMOTE_SGX.md) for complete deployment instructions.

### Quick Deploy

```bash
# Transfer package
scp amadeus-node-coco.tar user@remote-server:~/

# On remote server
docker load -i amadeus-node-coco.tar
kubectl apply -k deploy/coco/
```

## Dockerfile Options

### Dockerfile.minimal (Recommended for Fast Builds)
- Uses pre-built binary from local target/
- Build time: ~5 seconds
- Requires: `cargo build --release` first
- Best for: Development, quick iterations

### Dockerfile (Full Build)
- Compiles from source in container
- Build time: ~10-15 minutes
- Requires: Nothing pre-built
- Best for: CI/CD, reproducible builds

## Build for Different Architectures

### Build for AMD64 (x86_64)

If your server is amd64 but you're building on arm64:

```bash
# Cross-compile binary
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu -p amadeusd

# Copy to build directory
mkdir -p build
cp target/x86_64-unknown-linux-gnu/release/amadeusd build/

# Build for amd64
docker buildx build --platform linux/amd64 \
  -t amadeus-node:latest -f Dockerfile.minimal .

# Export
docker save amadeus-node:latest -o amadeus-node-coco-amd64.tar
```

### Build for ARM64 (aarch64)

```bash
# Build binary
cargo build --release -p amadeusd

# Copy to build directory
mkdir -p build
cp target/release/amadeusd build/

# Build for arm64
docker buildx build --platform linux/arm64 \
  -t amadeus-node:latest -f Dockerfile.minimal .

# Export
docker save amadeus-node:latest -o amadeus-node-coco-arm64.tar
```

## Version Tagging

```bash
# Get version from Cargo.toml
VERSION=$(grep '^version' amadeusd/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Build with version tag
docker build -t amadeus-node:${VERSION} -t amadeus-node:latest -f Dockerfile.minimal .

# Export with version
docker save amadeus-node:${VERSION} -o amadeus-node-coco-${VERSION}.tar
```

## Automated Build Script

```bash
#!/bin/bash
set -e

echo "Building Amadeus CoCo Package..."

# Build binary
echo "1. Building binary..."
cargo build --release -p amadeusd --bin amadeusd

# Copy to build dir
echo "2. Copying binary..."
mkdir -p build
cp target/release/amadeusd build/

# Build image
echo "3. Building Docker image..."
docker build -t amadeus-node:latest -f Dockerfile.minimal .

# Export package
echo "4. Exporting package..."
docker save amadeus-node:latest -o amadeus-node-coco.tar

# Show result
echo "✓ Package ready:"
ls -lh amadeus-node-coco.tar
echo ""
echo "Transfer to server:"
echo "  scp amadeus-node-coco.tar user@remote-server:~/"
echo ""
echo "Deploy on server:"
echo "  docker load -i amadeus-node-coco.tar"
echo "  kubectl apply -k deploy/coco/"
```

Save as `build-coco-package.sh` and run:

```bash
chmod +x build-coco-package.sh
./build-coco-package.sh
```

## Package Contents

The package includes:

```
amadeus-node:latest
├── /usr/local/bin/amadeusd          # Node binary (17MB)
├── /usr/lib/x86_64-linux-gnu/
│   ├── libssl.so.3                   # OpenSSL
│   ├── libzstd.so.1                  # Compression
│   └── ...other runtime libs
├── /etc/ssl/certs/                   # CA certificates
└── /home/amadeus/.amadeusd-rs/       # Data directory
```

## Image Layers

```bash
# View image layers
docker history amadeus-node:latest

# Expected output:
# - Base debian:bookworm-slim    ~28MB
# - Runtime dependencies         ~10MB
# - Amadeus binary              ~17MB
# - Configuration                ~1MB
# Total:                        ~56MB (compressed to ~39MB in tar)
```

## Troubleshooting

### Binary not found

```bash
# Ensure binary exists
ls -lh target/release/amadeusd

# Rebuild if needed
cargo clean
cargo build --release -p amadeusd
```

### Wrong architecture

```bash
# Check binary architecture
file target/release/amadeusd

# Should match your target server
# amd64: ELF 64-bit LSB... x86-64
# arm64: ELF 64-bit LSB... aarch64
```

### Build directory excluded

The build/ directory is intentionally NOT in .dockerignore. If you see errors about missing files, verify:

```bash
# Check build directory exists and contains binary
ls -lh build/amadeusd

# Should show 17MB binary
```

## Clean Up

```bash
# Remove build artifacts
rm -rf build/
rm -f amadeus-node-coco.tar

# Clean Docker
docker rmi amadeus-node:latest
```

## Next Steps

1. **Test Locally**: `docker run -it amadeus-node:latest`
2. **Deploy**: See [DEPLOY_REMOTE_SGX.md](deploy/coco/DEPLOY_REMOTE_SGX.md)
3. **Verify**: Check logs and metrics after deployment
