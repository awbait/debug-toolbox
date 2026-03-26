FROM alpine:3.21

ARG KUBECTL_VERSION=1.35.3
ARG GRPCURL_VERSION=1.9.3
ARG ISTIOCTL_VERSION=1.29.1

RUN apk add --no-cache \
    # Network diagnostics
    tcpdump \
    bind-tools \
    iputils \
    busybox-extras \
    mtr \
    curl \
    wget \
    socat \
    iperf3 \
    openssl \
    iproute2 \
    nmap \
    nmap-ncat \
    # General
    strace \
    htop \
    jq \
    yq \
    vim \
    bash \
    coreutils \
    procps

# kubectl
RUN curl -fsSL "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

# grpcurl
RUN curl -fsSL "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz" \
    | tar -xz -C /usr/local/bin grpcurl

# istioctl
RUN curl -fsSL "https://github.com/istio/istio/releases/download/${ISTIOCTL_VERSION}/istioctl-${ISTIOCTL_VERSION}-linux-amd64.tar.gz" \
    | tar -xz -C /usr/local/bin istioctl

SHELL ["/bin/bash", "-c"]

CMD ["sleep", "infinity"]
