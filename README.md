# debug-toolbox

Alpine-based Docker image with networking, Kubernetes, and Istio debugging tools.
Built for **Istio ambient mode** (ztunnel, L4). No sidecars are used, so there are
no sidecar-specific recipes here.

## Tools

| Category | Tools |
|---|---|
| DNS | `dig`, `nslookup`, `host` |
| TCP/UDP | `tcpdump`, `tcpflow`, `nc`, `ncat`, `socat`, `nmap` |
| Connectivity | `ping`, `traceroute`, `tracepath`, `mtr` |
| HTTP/2, gRPC | `curl`, `wget`, `nghttp`, `grpcurl` |
| TLS | `openssl s_client` |
| Sockets/Routes | `ss`, `ip`, `netstat`, `route`, `lsof`, `ethtool` |
| Packet filtering | `iptables`, `ip6tables`, `iptables-legacy`, `ip6tables-legacy`, `nft`, `conntrack` |
| Namespaces | `nsenter`, `lsns`, `unshare` (util-linux) |
| Bandwidth | `iperf3` |
| Kubernetes | `kubectl`, `kubectl-ko` (kube-ovn), `helm`, `stern` |
| Istio | `istioctl` |
| Scripting | `python3`, `jq`, `yq` |
| System | `strace`, `htop`, `procps` |
| Utils | `vim`, `bash`, `grep` |
| Helpers | `ambient-check`, `kubeconfig-from-sa`, bash completion |

### Why some of these are in here

- **`iptables-legacy` / `ip6tables-legacy`** - istio-cni writes its redirection rules
  into the *legacy* tables. The `nft` view can look completely empty and send you
  down the wrong path.
- **`conntrack`** - to check whether there is a NAT translation for the ztunnel
  link-local address `169.254.7.127`.
- **`nsenter`** (util-linux-misc) - enter the netns of any pod straight from the node.
- **`python3`** - `python3 -m http.server` is a real server. A hand-rolled `socat`
  stub can accept the connection and then stay silent, which looks exactly like a
  mesh problem and is not one.
- **`nghttp`** - HBONE and gRPC are HTTP/2; a plain `curl` tells you little.
- **`kubectl-ko`** - the kube-ovn plugin. It finds the `ovn-central` leader itself,
  so there is no need to exec into pods and guess.
- **`helm`** - to see what actually rendered from a chart.
- **`stern`** - logs from a whole group of pods at once.

## Permissions - read this before the first `tcpdump`

`tcpdump`, `iptables*`, `nsenter` and `conntrack` need capabilities a plain debug
pod does **not** have. Without the right profile these commands are silent or
return empty output, which is easy to misread as "no traffic" or "no rules".

```bash
# pod's network namespace, with NET_ADMIN + NET_RAW
kubectl debug -it <pod> -n <ns> --profile=netadmin \
  --image=$TOOLBOX_IMAGE -- bash

# node level: host netns, host pid, full privileges
kubectl debug node/<node> -it --profile=sysadmin \
  --image=$TOOLBOX_IMAGE -- bash
```

On a node shell the host filesystem is under `/host`:

```bash
chroot /host
# or
nsenter -t 1 -m -u -n -i bash
```

## kubeconfig

`kubectl`, `istioctl`, `helm`, `stern` and `kubectl ko` all read the same
kubeconfig. Without one `kubectl` goes to `localhost:8080` and fails - it does
**not** pick up the in-cluster config the way a controller does.

### Inside the cluster: from the ServiceAccount token

The image handles this itself. On an interactive shell (`/etc/bash/bashrc`) it builds
a kubeconfig out of `/var/run/secrets/kubernetes.io/serviceaccount` and prints:

```
[debug-toolbox] kubeconfig generated from the ServiceAccount token
```

To do it by hand (non-interactive shell, `KUBECONFIG` set to another path):

```bash
kubeconfig-from-sa
```

The token carries the rights of the pod's ServiceAccount. The namespace `default`
one usually has none at all, so every command answers `Forbidden`. `debug-rbac.yaml`
in this repo creates a `debug-toolbox` ServiceAccount, binds it, and defines a
long-lived pod to exec into:

```bash
kubectl apply -f debug-rbac.yaml
kubectl exec -it debug-toolbox -- bash
kubectl delete -f debug-rbac.yaml     # when the investigation is over
```

It binds `cluster-admin`, because `istioctl ztunnel-config` needs `pods/exec` and
`pods/portforward` in `istio-system` and `kubectl ko` needs exec into the kube-ovn
pods. It is a debugging account - create it for the investigation, delete it after.

The pod carries `istio.io/dataplane-mode: none` so the toolbox itself stays out of
the mesh and sees the network as it is, not through ztunnel redirection.

For a one-off `kubectl run`, pass the ServiceAccount explicitly - `run` uses
`default` otherwise:

```bash
kubectl run debug --rm -it --image=$TOOLBOX_IMAGE   --overrides='{"spec":{"serviceAccountName":"debug-toolbox"}}' -- bash
```

`kubectl debug` (ephemeral container or node pod) inherits the ServiceAccount of
the target pod, which is usually the application's own and just as restricted.
For node-level work exec into the `debug-toolbox` pod instead, or mount a kubeconfig.

### Outside the cluster: mount your own

```bash
docker run --rm -it   -v "$HOME/.kube:/root/.kube:ro"   -e KUBECONFIG=/root/.kube/config   $TOOLBOX_IMAGE bash
```

A mounted kubeconfig or an explicit `KUBECONFIG` always wins over the generated one.

## `ambient-check` - the cheat sheet

The image ships `/usr/local/bin/ambient-check`: the troubleshooting steps in the
order that actually works.

```bash
ambient-check
ambient-check | less
```

The order is: `curl 127.0.0.1` -> `ambient.istio.io/redirection` ->
`istioctl ztunnel-config workloads` -> policy -> `tcpdump` in the pod netns and on
the node. Going the other way round costs hours.

## Shell

An interactive shell (`kubectl exec -it ... -- bash`, `docker run -it ... bash`) gets:

- **completion** for `kubectl`, `istioctl`, `helm`, `stern` and `yq`, plus everything
  `bash-completion` ships for `iptables`, `ss`, `lsof`, `traceroute`, `nmap`, `openssl`
  and friends. Generated at build time, loaded on demand, so shell startup is unchanged.
- **`k`** as an alias for `kubectl`, completing like `kubectl` itself.
- **`ko`** as an alias for `kubectl ko` with a static list of subcommands - `kubectl-ko`
  is a plain script and kubectl cannot complete it. Refresh the list in `bashrc`
  when kube-ovn is upgraded.
- a kubeconfig built from the ServiceAccount token, see above.

Setup lives in `/etc/bash/bashrc`, not `~/.bashrc`: Alpine's bash reads it for login
shells (`bash -l`) and under a non-root UID too, both of which skip `~/.bashrc`.
`-t` is required - without a TTY the shell is not interactive and nothing above loads.

Completing **flags and subcommands** is offline. Completing **resource names**
(`kubectl get pod <TAB>`) is a live API call: it needs a kubeconfig and RBAC, and
without them Tab silently offers nothing.

## Usage

The examples use `$TOOLBOX_IMAGE`. Set it once to whatever registry you pull from -
GHCR outside, the internal registry in an isolated cluster:

```bash
export TOOLBOX_IMAGE=ghcr.io/awbait/debug-toolbox:latest
# export TOOLBOX_IMAGE=registry.internal/debug-toolbox:v1.1.0
```

### Pull

```bash
docker pull $TOOLBOX_IMAGE
```

### Run standalone

```bash
docker run --rm -it $TOOLBOX_IMAGE bash
```

### Run in Kubernetes

```bash
# One-off debug pod
kubectl run debug --rm -it --image=$TOOLBOX_IMAGE -- bash

# Debug pod in specific namespace
kubectl run debug --rm -it -n <namespace> --image=$TOOLBOX_IMAGE -- bash

# Attach to existing pod's network (add --profile=netadmin for tcpdump/iptables)
kubectl debug <pod-name> -it --image=$TOOLBOX_IMAGE -- bash

# Debug node (add --profile=sysadmin for host netns/pid)
kubectl debug node/<node-name> -it --image=$TOOLBOX_IMAGE -- bash
```

### Istio Ambient mesh debugging

```bash
# 1. Does the app listen at all? Loopback bypasses redirection.
kubectl exec -it <pod> -n <namespace> -- curl -sv http://127.0.0.1:<port>/
kubectl exec -it <pod> -n <namespace> -- ss -ltnp

# 2. Is the pod really redirected? istio-cni sets this after programming it.
kubectl get pod <pod> -n <namespace> \
  -o jsonpath='{.metadata.annotations.ambient\.istio\.io/redirection}{"\n"}'
kubectl get ns <namespace> -L istio.io/dataplane-mode
kubectl get pods -n <namespace> -l istio.io/dataplane-mode=ambient

# 3. What does ztunnel see?
istioctl ztunnel-config workloads | grep <pod-or-ip>
istioctl ztunnel-config services -n <namespace>
istioctl ztunnel-config policies -n <namespace>
istioctl ztunnel-config certificates | grep <namespace>

# ztunnel logs (L4, mTLS, HBONE, RBAC verdicts)
stern -n istio-system -l app=ztunnel
kubectl logs -n istio-system -l app=ztunnel | grep -iE "rbac|denied|authorization"

# istio-cni logs when the redirection annotation is missing
stern -n istio-system -l k8s-app=istio-cni-node

# 4. Packets: pod netns first, then the node
PID=$(chroot /host crictl inspect --output go-template --template '{{.info.pid}}' <container-id>)
nsenter -t $PID -n tcpdump -i any -nn port <port>
tcpdump -i any -nn port 15008          # HBONE between ztunnels
tcpflow -i any -c port <port>          # whole streams, not single packets

# HBONE is HTTP/2
nghttp -nv https://<pod-ip>:15008
openssl s_client -connect <pod-ip>:15008 -alpn h2

# 5. Redirection rules live in the LEGACY tables
iptables-legacy-save | grep -i istio
ip6tables-legacy-save | grep -i istio
nft list ruleset | head -50

# NAT translation for the ztunnel link-local address
conntrack -L | grep 169.254.7.127
conntrack -S
```

ztunnel ports: `15008` HBONE (mTLS, HTTP/2), `15006` inbound, `15001` outbound,
`15053` DNS, `15021` health.

At L4 an `AuthorizationPolicy` can match ports, principals and namespaces. HTTP-level
rules (paths, methods, headers) require a waypoint and are simply not enforced
without one.

### kube-ovn (CNI layer)

```bash
kubectl ko diagnose all
kubectl ko nbctl show
kubectl ko nbctl lr-policy-list ovn-cluster
kubectl ko trace <namespace>/<pod> <dst-ip> <proto> <dst-port>
```

### Control plane / install

```bash
istioctl version
istioctl analyze -n <namespace>
kubectl get istiorevision,istiocni,ztunnel -A
helm -n istio-system list
helm -n istio-system get manifest <release> | less   # what really rendered
stern -n istio-system -l app=istiod
```

## Air-gapped clusters

The image is designed to be self-contained: nothing is downloaded at runtime.
Everything is pulled at **build** time, which happens in CI where the internet is
available. Inside an isolated cluster `apk add` will not work, so anything you
might need has to be in the image already - that is the reason the package list
is as long as it is.

```bash
# 1. Outside: download the archive from GitHub Releases (or docker save yourself)
docker load -i debug-toolbox-v1.1.0-amd64.tar.gz

# 2. Retag into the internal registry and push
docker tag debug-toolbox:v1.1.0 registry.internal/debug-toolbox:v1.1.0
docker push registry.internal/debug-toolbox:v1.1.0
```

`ambient-check` prints the image reference in its examples - point it at your
registry:

```bash
export TOOLBOX_IMAGE=registry.internal/debug-toolbox:v1.1.0
ambient-check
```

What to keep in mind in an isolated environment:

- **`apk add` is not available.** If a tool is missing, it means a new image build
  and a new import, so pin the versions you actually run against.
- **`python3` has no `pip`** (deliberately: `pip install` would not work anyway).
  The standard library is enough for `http.server`, `json.tool`, `ssl`, `socket`.
- **`kubectl ko` works offline.** `nbctl`, `sbctl`, `trace`, `diagnose`, `tcpdump`
  and `log` all run via `kubectl exec` into the existing kube-ovn pods, and the
  registry for helper pods is taken from the running `kube-ovn-cni` image, i.e.
  your internal one. The single exception is `kubectl ko perf`, which defaults to
  `docker.io/kubeovn/test:<version>` - pass a locally available image as its
  argument, or do not use that subcommand.
- **Pin `KUBE_OVN_REF` to the kube-ovn version running in the cluster.** The script
  is fetched from a branch, and a newer one can expect labels and components your
  cluster does not have.
- Keep `KUBECTL_VERSION` and `ISTIOCTL_VERSION` aligned with the cluster as well.

## Build

```bash
docker build -t debug-toolbox:latest .

# Override tool versions
docker build \
  --build-arg KUBECTL_VERSION=1.35.3 \
  --build-arg ISTIOCTL_VERSION=1.29.1 \
  --build-arg GRPCURL_VERSION=1.9.3 \
  --build-arg STERN_VERSION=1.34.0 \
  --build-arg KUBE_OVN_REF=v1.15.24 \
  -t debug-toolbox:latest .
```

## Security

Every release is scanned with [Trivy](https://trivy.dev). Results are available in the [Security tab](../../security/code-scanning) and as a SARIF artifact in [Releases](../../releases).
