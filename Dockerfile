FROM alpine:3.21

ARG TARGETARCH
ARG KUBECTL_VERSION=1.35.4
ARG GRPCURL_VERSION=1.9.3
ARG ISTIOCTL_VERSION=1.29.2
ARG STERN_VERSION=1.34.0
ARG KUBE_OVN_REF=master

RUN apk add --no-cache \
    # Network diagnostics
    tcpdump \
    bind-tools \
    iputils \
    busybox-extras \
    mtr \
    traceroute \
    curl \
    wget \
    socat \
    iperf3 \
    openssl \
    nghttp2 \
    iproute2 \
    net-tools \
    ethtool \
    tcpflow \
    nmap \
    nmap-ncat \
    # Packet filtering: istio-cni writes its rules into the legacy tables,
    # the nft view can look empty. iptables-legacy also ships ip6tables-legacy.
    iptables \
    ip6tables \
    iptables-legacy \
    nftables \
    conntrack-tools \
    # General
    strace \
    lsof \
    htop \
    jq \
    yq \
    python3 \
    vim \
    bash \
    bash-completion \
    coreutils \
    procps \
    # nsenter: enter the netns of any pod straight from the node
    util-linux \
    util-linux-misc \
    # Kubernetes
    helm

# kubectl
RUN curl -fsSL "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

# grpcurl
RUN case "${TARGETARCH}" in \
      amd64) GRPCURL_ARCH=x86_64 ;; \
      *)     GRPCURL_ARCH="${TARGETARCH}" ;; \
    esac \
    && curl -fsSL "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_${GRPCURL_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin grpcurl

# istioctl
RUN curl -fsSL "https://github.com/istio/istio/releases/download/${ISTIOCTL_VERSION}/istioctl-${ISTIOCTL_VERSION}-linux-${TARGETARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin istioctl

# stern - logs from a group of pods at once
RUN curl -fsSL "https://github.com/stern/stern/releases/download/v${STERN_VERSION}/stern_${STERN_VERSION}_linux_${TARGETARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin stern \
    && chmod +x /usr/local/bin/stern

# kubectl-ko - kube-ovn plugin (kubectl ko nbctl / trace / diagnose)
RUN curl -fsSL "https://raw.githubusercontent.com/kubeovn/kube-ovn/${KUBE_OVN_REF}/dist/images/kubectl-ko" \
      -o /usr/local/bin/kubectl-ko \
    && chmod +x /usr/local/bin/kubectl-ko

# ambient-check - troubleshooting order cheat sheet
# kubeconfig-from-sa - kubeconfig out of the in-cluster ServiceAccount token
COPY ambient-check kubeconfig-from-sa /usr/local/bin/
RUN chmod +x /usr/local/bin/ambient-check /usr/local/bin/kubeconfig-from-sa

# Shell completion. Generated at build time, loaded on demand at runtime.
RUN COMP=/usr/share/bash-completion/completions \
    && mkdir -p "$COMP" \
    && kubectl completion bash  > "$COMP/kubectl" \
    && istioctl completion bash > "$COMP/istioctl" \
    && helm completion bash     > "$COMP/helm" \
    && stern --completion=bash  > "$COMP/stern" \
    && yq shell-completion bash > "$COMP/yq"

# /etc/bash/bashrc, not ~/.bashrc: Alpine's bash reads it for login shells and
# under a non-root UID too, where ~/.bashrc would be skipped.
COPY bashrc /etc/bash/bashrc

SHELL ["/bin/bash", "-c"]

CMD ["sleep", "infinity"]
