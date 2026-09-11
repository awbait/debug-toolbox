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
