# debug-toolbox

Alpine-based Docker image with networking, Kubernetes, and Istio debugging tools.

## Tools

| Category | Tools |
|---|---|
| DNS | `dig`, `nslookup`, `host` |
| TCP/UDP | `tcpdump`, `nc`, `ncat`, `socat`, `nmap` |
| Connectivity | `ping`, `traceroute`, `tracepath`, `mtr` |
| HTTP | `curl`, `wget` |
| Sockets/Routes | `ss`, `ip` |
| Bandwidth | `iperf3` |
| TLS | `openssl s_client` |
| Kubernetes | `kubectl` |
| Istio | `istioctl` |
| gRPC | `grpcurl` |
| System | `strace`, `htop`, `procps` |
| Utils | `jq`, `yq`, `vim`, `bash`, `grep` |

## Usage

### Pull from GHCR

```bash
docker pull ghcr.io/awbait/debug-toolbox:latest
```

### Run standalone

```bash
docker run --rm -it ghcr.io/awbait/debug-toolbox:latest bash
```

### Run in Kubernetes

```bash
# One-off debug pod
kubectl run debug --rm -it --image=ghcr.io/awbait/debug-toolbox:latest -- bash

# Debug pod in specific namespace
kubectl run debug --rm -it -n <namespace> --image=ghcr.io/awbait/debug-toolbox:latest -- bash

# Attach to existing pod's network
kubectl debug <pod-name> -it --image=ghcr.io/awbait/debug-toolbox:latest -- bash

# Debug node
kubectl debug node/<node-name> -it --image=ghcr.io/awbait/debug-toolbox:latest -- bash
```

### Istio sidecar debugging

```bash
# Check proxy status
kubectl run debug --rm -it --image=ghcr.io/awbait/debug-toolbox:latest -- \
  istioctl proxy-status

# Inspect Envoy config of a pod
kubectl run debug --rm -it --image=ghcr.io/awbait/debug-toolbox:latest -- \
  istioctl proxy-config clusters <pod-name>.<namespace>

# Test mTLS connectivity between services
kubectl run debug --rm -it -n <namespace> --image=ghcr.io/awbait/debug-toolbox:latest -- \
  curl -v http://<service>.<namespace>.svc.cluster.local:<port>
```

### Load from archive (air-gapped)

```bash
# Download from GitHub Releases, then:
docker load -i debug-toolbox-v1.0.0-amd64.tar.gz
```

## Build

```bash
docker build -t debug-toolbox:latest .

# Override tool versions
docker build \
  --build-arg KUBECTL_VERSION=1.35.3 \
  --build-arg ISTIOCTL_VERSION=1.29.1 \
  --build-arg GRPCURL_VERSION=1.9.3 \
  -t debug-toolbox:latest .
```

## Security

Every release is scanned with [Trivy](https://trivy.dev). Results are available in the [Security tab](../../security/code-scanning) and as a SARIF artifact in [Releases](../../releases).
