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

### Istio Ambient mesh debugging

```bash
# Check which pods are enrolled in ambient mesh
kubectl get pods -n <namespace> -l istio.io/dataplane-mode=ambient

# Check namespace enrollment
kubectl get ns -L istio.io/dataplane-mode

# ztunnel status and workloads
istioctl ztunnel-config workloads
istioctl ztunnel-config services
istioctl ztunnel-config policies

# ztunnel logs (L4 issues, mTLS, HBONE)
kubectl logs -n istio-system -l app=ztunnel -f

# Waypoint proxy status
istioctl waypoint list -n <namespace>
istioctl proxy-status | grep waypoint

# Waypoint Envoy config
istioctl proxy-config listeners <waypoint-pod>.<namespace>
istioctl proxy-config routes <waypoint-pod>.<namespace>
istioctl proxy-config clusters <waypoint-pod>.<namespace>

# Test L4 connectivity (through ztunnel)
kubectl run debug --rm -it -n <namespace> --image=ghcr.io/awbait/debug-toolbox:latest -- \
  curl -v http://<service>.<namespace>.svc.cluster.local:<port>

# Check HBONE tunnel (port 15008)
kubectl run debug --rm -it -n <namespace> --image=ghcr.io/awbait/debug-toolbox:latest -- \
  curl -kv https://<pod-ip>:15008 --connect-to ::<pod-ip>:15008

# Capture ztunnel traffic on node
kubectl debug node/<node-name> -it --image=ghcr.io/awbait/debug-toolbox:latest -- \
  tcpdump -i any port 15008 -nn

# Verify mTLS certs from ztunnel
kubectl debug node/<node-name> -it --image=ghcr.io/awbait/debug-toolbox:latest -- \
  openssl s_client -connect <pod-ip>:15008 -alpn h2

# Check iptables rules (ztunnel redirect)
kubectl debug node/<node-name> -it --image=ghcr.io/awbait/debug-toolbox:latest -- \
  iptables-save | grep -i ztunnel

# AuthorizationPolicy debugging
istioctl ztunnel-config policies <pod-name>.<namespace>
kubectl logs -n istio-system -l app=ztunnel | grep -i "rbac\|denied\|authorization"
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
