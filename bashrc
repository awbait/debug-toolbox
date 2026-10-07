# debug-toolbox shell setup
#
# Installed as /etc/bash/bashrc (Alpine's SYS_BASHRC): unlike ~/.bashrc it is read
# by login shells (`bash -l`) and by shells running under a non-root UID as well.

# Interactive shells only.
case $- in
  *i*) ;;
  *) return ;;
esac

# kubectl does not pick up the in-cluster config on its own: with no kubeconfig
# it goes to localhost:8080 and fails. Build one from the ServiceAccount token.
# A mounted kubeconfig or an explicit KUBECONFIG wins over this.
if [ -z "${KUBECONFIG:-}" ] && [ ! -s "$HOME/.kube/config" ] \
   && [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  if kubeconfig-from-sa >/dev/null 2>&1; then
    echo "[debug-toolbox] kubeconfig generated from the ServiceAccount token"
  fi
fi

# Runtime CAs. PEM files mounted (or kubectl cp'd) into $EXTRA_CA_DIR are appended
# to the system bundle in a writable copy, and every TLS client is pointed at it:
# OpenSSL (curl, wget, openssl, python3) and Go (kubectl, istioctl, helm, grpcurl,
# stern) read SSL_CERT_FILE. No root and no writable /etc needed.
# Run `ca-reload` again after copying a new file in.
EXTRA_CA_DIR="${EXTRA_CA_DIR:-/etc/debug-toolbox/ca.d}"
ca-reload() {
  local sys=/etc/ssl/certs/ca-certificates.crt
  local out="${TMPDIR:-/tmp}/debug-toolbox-ca-bundle.crt"
  local f n=0
  local files=()
  for f in "$EXTRA_CA_DIR"/*.crt "$EXTRA_CA_DIR"/*.pem; do
    [ -f "$f" ] || continue
    if ! openssl x509 -noout -in "$f" >/dev/null 2>&1; then
      echo "[debug-toolbox] skipped $f: not a PEM certificate" >&2
      continue
    fi
    files+=("$f")
  done
  if [ ${#files[@]} -eq 0 ]; then
    # Drop only our own bundle, an SSL_CERT_FILE passed with -e stays.
    [ "${SSL_CERT_FILE:-}" = "$out" ] && unset SSL_CERT_FILE CURL_CA_BUNDLE
    return 0
  fi
  # `echo` after each file: a PEM without a trailing newline would glue its END
  # line to the next BEGIN and break the whole bundle.
  if ! { cat "$sys"; for f in "${files[@]}"; do cat "$f"; echo; done; } > "$out" 2>/dev/null; then
    echo "[debug-toolbox] cannot write $out, extra CAs not loaded" >&2
    return 1
  fi
  export SSL_CERT_FILE="$out" CURL_CA_BUNDLE="$out"
  for f in "${files[@]}"; do
    n=$((n + $(grep -c 'BEGIN CERTIFICATE' "$f")))
  done
  echo "[debug-toolbox] $n extra CA certificate(s) from $EXTRA_CA_DIR trusted"
}
ca-reload

# Completion. The loader pulls /usr/share/bash-completion/completions/<cmd> on
# demand, so this costs nothing at startup.
if [ -r /usr/share/bash-completion/bash_completion ]; then
  . /usr/share/bash-completion/bash_completion
fi

alias k=kubectl
complete -o default -F __start_kubectl k 2>/dev/null

# kubectl-ko is a plain script, so kubectl cannot complete it. Static list of
# subcommands on an alias instead - refresh it when kube-ovn is upgraded.
alias ko='kubectl ko'
complete -W "nb sb nbctl sbctl vsctl ofctl dpctl appctl tcpdump trace ovn-trace \
diagnose env-check reload log perf icnbctl icsbctl acl-sample" ko

# ambient-check prints this image reference in its examples
export TOOLBOX_IMAGE="${TOOLBOX_IMAGE:-<registry>/debug-toolbox:latest}"
