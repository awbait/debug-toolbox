package common

import (
	"context"
	"fmt"
	"strings"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

// CheckControlPlane verifies core Istio Ambient & platform components.
func CheckControlPlane(ctx context.Context, c *k8s.Client, r *report.Report, fullCluster bool) (ztunnelNS string, ztunnelPods []k8s.Pod) {
	const layer = "Control Plane"

	// 1. istiod
	istiodPods, err := c.ListPods(ctx, "istio-system", "app=istiod")
	if err != nil {
		r.Fail("cp-istiod", layer, "istio-system/istiod", "istiod control plane",
			fmt.Sprintf("failed to list istiod pods: %v", err),
			"Verify kubectl access and permissions in istio-system")
	} else {
		ready := countReady(istiodPods)
		if len(istiodPods) == 0 || ready == 0 {
			r.Fail("cp-istiod", layer, "istio-system/istiod", "istiod control plane",
				fmt.Sprintf("%d/%d istiod pods Ready", ready, len(istiodPods)),
				"Check istiod deployment and events in namespace istio-system")
		} else if ready < len(istiodPods) {
			r.Warn("cp-istiod", layer, "istio-system/istiod", "istiod control plane",
				fmt.Sprintf("%d/%d istiod pods Ready", ready, len(istiodPods)),
				"Inspect non-ready istiod pods in istio-system")
		} else {
			r.Pass("cp-istiod", layer, "istio-system/istiod", "istiod control plane",
				fmt.Sprintf("%d/%d pods Ready", ready, len(istiodPods)))
		}
	}

	// 2. ztunnel (auto-detect namespace: ztunnel vs istio-system)
	ztunnelNS, ztunnelPods, err = c.DetectZtunnelNamespace(ctx)
	if err != nil {
		r.Fail("cp-ztunnel", layer, "ztunnel", "ztunnel DaemonSet",
			fmt.Sprintf("failed to find ztunnel pods: %v", err),
			"Check ztunnel DaemonSet in namespace ztunnel or istio-system (or pass --ztunnel-ns)")
	} else {
		r.Metadata["ztunnel_namespace"] = ztunnelNS
		ready := countReady(ztunnelPods)
		if ready == 0 {
			r.Fail("cp-ztunnel", layer, ztunnelNS+"/ztunnel", "ztunnel DaemonSet",
				fmt.Sprintf("0/%d ztunnel pods Ready in namespace %s", len(ztunnelPods), ztunnelNS),
				fmt.Sprintf("Check ztunnel DaemonSet and pod logs in namespace %s", ztunnelNS))
		} else if ready < len(ztunnelPods) {
			r.Warn("cp-ztunnel", layer, ztunnelNS+"/ztunnel", "ztunnel DaemonSet",
				fmt.Sprintf("%d/%d ztunnel pods Ready in namespace %s", ready, len(ztunnelPods), ztunnelNS),
				fmt.Sprintf("Inspect non-ready ztunnel pods in namespace %s", ztunnelNS))
		} else {
			r.Pass("cp-ztunnel", layer, ztunnelNS+"/ztunnel", "ztunnel DaemonSet",
				fmt.Sprintf("%d/%d pods Ready (namespace: %s)", ready, len(ztunnelPods), ztunnelNS))
		}
	}

	// 3. istio-cni-node (may live in istio-cni or istio-system)
	cniPods, err := c.ListPods(ctx, "", "k8s-app=istio-cni-node")
	if err != nil {
		if k8s.IsForbidden(err) {
			r.Skip("cp-istio-cni", layer, "istio-cni-node", "istio-cni DaemonSet", "skipped: RBAC forbidden to list pods cluster-wide")
		} else {
			r.Warn("cp-istio-cni", layer, "istio-cni-node", "istio-cni DaemonSet",
				fmt.Sprintf("could not list istio-cni-node pods: %v", err),
				"Check istio-cni DaemonSet in istio-cni / istio-system")
		}
	} else if len(cniPods) == 0 {
		r.Fail("cp-istio-cni", layer, "istio-cni-node", "istio-cni DaemonSet",
			"no istio-cni-node pods found in cluster",
			"Verify IstioCNI CR and istio-cni DaemonSet installation")
	} else {
		ready := countReady(cniPods)
		ns := cniPods[0].Metadata.Namespace
		r.Metadata["istio_cni_namespace"] = ns
		if ready < len(cniPods) {
			r.Warn("cp-istio-cni", layer, ns+"/istio-cni-node", "istio-cni DaemonSet",
				fmt.Sprintf("%d/%d pods Ready (namespace: %s)", ready, len(cniPods), ns),
				fmt.Sprintf("Inspect non-ready istio-cni-node pods in %s", ns))
		} else {
			r.Pass("cp-istio-cni", layer, ns+"/istio-cni-node", "istio-cni DaemonSet",
				fmt.Sprintf("%d/%d pods Ready (namespace: %s)", ready, len(cniPods), ns))
		}
	}

	if !fullCluster {
		return ztunnelNS, ztunnelPods
	}

	// 4. Mesh-wide PeerAuthentication
	pas, err := c.ListPeerAuthentications(ctx, "istio-system")
	if err == nil {
		if len(pas) == 0 {
			r.Info("cp-peer-auth", layer, "istio-system", "Mesh-wide PeerAuthentication", "no PeerAuthentication in istio-system (default PERMISSIVE)")
		} else {
			var modes []string
			for _, pa := range pas {
				mode := "UNSET"
				if pa.Spec.MTLS != nil && pa.Spec.MTLS.Mode != "" {
					mode = pa.Spec.MTLS.Mode
				}
				modes = append(modes, fmt.Sprintf("%s=%s", pa.Metadata.Name, mode))
			}
			r.Info("cp-peer-auth", layer, "istio-system", "Mesh-wide PeerAuthentication", strings.Join(modes, ", "))
		}
	}

	// 5. Kube-OVN leader
	leader, err := c.DetectOVNLeader(ctx)
	if err != nil {
		r.Warn("cp-kube-ovn", layer, "kube-system/ovn-central", "Kube-OVN NB leader",
			fmt.Sprintf("not detected: %v", err),
			"Check ovn-central pods in kube-system")
	} else {
		r.Pass("cp-kube-ovn", layer, "kube-system/"+leader, "Kube-OVN NB leader",
			fmt.Sprintf("active leader pod: %s", leader))
	}

	// 6. Kyverno guard policy for VEG pods
	res, err := c.Kubectl(ctx, "get", "clusterpolicy", "-o", "jsonpath={.items[*].metadata.name}")
	if err == nil {
		names := strings.Fields(res.Stdout)
		hasVegGuard := false
		for _, n := range names {
			if strings.Contains(n, "veg") || strings.Contains(n, "vpc-egress-gateway") {
				hasVegGuard = true
				break
			}
		}
		if hasVegGuard {
			r.Pass("cp-kyverno-veg", layer, "ClusterPolicy", "Kyverno VEG guard policy",
				"found VEG protection policy in Kyverno", strings.Join(names, ", "))
		} else {
			r.Warn("cp-kyverno-veg", layer, "ClusterPolicy", "Kyverno VEG guard policy",
				"no Kyverno ClusterPolicy matching veg/vpc-egress-gateway found",
				"Install vpc-egress-gateway-exclude-ambient ClusterPolicy so kube-ovn VEG pods are never captured by ambient")
		}
	}

	// 7. MetalLB / cert-manager / external-secrets (best-effort informational)
	checkOptionalComponent(ctx, c, r, "cp-metallb", layer, "metallb-system", "", "MetalLB")
	checkOptionalComponent(ctx, c, r, "cp-cert-manager", layer, "cert-manager", "", "cert-manager")
	checkOptionalComponent(ctx, c, r, "cp-eso", layer, "external-secrets", "", "External Secrets Operator")

	return ztunnelNS, ztunnelPods
}

func checkOptionalComponent(ctx context.Context, c *k8s.Client, r *report.Report, id, layer, ns, sel, title string) {
	pods, err := c.ListPods(ctx, ns, sel)
	if err != nil || len(pods) == 0 {
		r.Info(id, layer, ns, title, fmt.Sprintf("no pods found in namespace %s (may run in another namespace)", ns))
		return
	}
	ready := countReady(pods)
	if ready < len(pods) {
		r.Warn(id, layer, ns, title, fmt.Sprintf("%d/%d pods Ready", ready, len(pods)),
			fmt.Sprintf("Inspect pods in namespace %s", ns))
	} else {
		r.Pass(id, layer, ns, title, fmt.Sprintf("%d/%d pods Ready", ready, len(pods)))
	}
}

func countReady(pods []k8s.Pod) int {
	n := 0
	for _, p := range pods {
		if p.IsReady() {
			n++
		}
	}
	return n
}
