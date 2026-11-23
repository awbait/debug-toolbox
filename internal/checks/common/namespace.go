package common

import (
	"context"
	"fmt"
	"strings"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

const (
	LabelDataplaneMode  = "istio.io/dataplane-mode"
	LabelDiscovery      = "istio-discovery"
	AnnotRedirection    = "ambient.istio.io/redirection"
	LabelUseWaypoint    = "istio.io/use-waypoint"
	LabelUseWaypointNS  = "istio.io/use-waypoint-namespace"
	LabelIngressUseWP   = "istio.io/ingress-use-waypoint"
	LabelGatewayName    = "gateway.networking.k8s.io/gateway-name"
	LabelVEG            = "ovn.kubernetes.io/vpc-egress-gateway"
)

// NamespaceMeshInfo summarizes Istio Ambient enrollment of a namespace.
type NamespaceMeshInfo struct {
	Namespace      k8s.Namespace
	AmbientEnabled bool
	DiscoveryOn    bool
}

// CheckNamespaceMesh checks istio.io/dataplane-mode and istio-discovery labels on a namespace.
// If requireAmbient is true, missing ambient or discovery labels produce FAIL/WARN.
func CheckNamespaceMesh(ctx context.Context, c *k8s.Client, r *report.Report, layer, nsName string, requireAmbient bool) (NamespaceMeshInfo, error) {
	ns, err := c.GetNamespace(ctx, nsName)
	if err != nil {
		r.Fail("ns-get-"+nsName, layer, "ns/"+nsName, "Namespace exists",
			fmt.Sprintf("cannot read namespace %s: %v", nsName, err),
			fmt.Sprintf("Check namespace name %q and RBAC permissions", nsName))
		return NamespaceMeshInfo{}, err
	}

	dp := ns.Metadata.Labels[LabelDataplaneMode]
	disc := ns.Metadata.Labels[LabelDiscovery]
	info := NamespaceMeshInfo{
		Namespace:      ns,
		AmbientEnabled: dp == "ambient",
		DiscoveryOn:    disc == "enabled",
	}

	if info.AmbientEnabled && info.DiscoveryOn {
		r.Pass("ns-mesh-"+nsName, layer, "ns/"+nsName, "Namespace ambient enrollment",
			"istio.io/dataplane-mode=ambient and istio-discovery=enabled")
	} else if info.AmbientEnabled && !info.DiscoveryOn {
		r.Fail("ns-mesh-"+nsName, layer, "ns/"+nsName, "Namespace ambient enrollment",
			fmt.Sprintf("istio.io/dataplane-mode=ambient is set, but %s=enabled is MISSING (got %q)", LabelDiscovery, disc),
			fmt.Sprintf("Add label %s=enabled to namespace %s so istiod discovers its services", LabelDiscovery, nsName))
	} else if !info.AmbientEnabled && requireAmbient {
		r.Fail("ns-mesh-"+nsName, layer, "ns/"+nsName, "Namespace ambient enrollment",
			fmt.Sprintf("namespace is NOT in ambient mesh (%s=%q, %s=%q)", LabelDataplaneMode, dp, LabelDiscovery, disc),
			fmt.Sprintf("Label namespace %s with %s=ambient and %s=enabled", nsName, LabelDataplaneMode, LabelDiscovery))
	} else {
		r.Info("ns-mesh-"+nsName, layer, "ns/"+nsName, "Namespace mesh status",
			fmt.Sprintf("ambient not enabled (%s=%q, %s=%q)", LabelDataplaneMode, dp, LabelDiscovery, disc))
	}

	return info, nil
}

// CheckPodsRedirection checks that workload pods in an ambient namespace carry ambient.istio.io/redirection=enabled.
// Gateway/waypoint/VEG/explicitly opted-out pods are automatically excluded.
func CheckPodsRedirection(r *report.Report, layer, nsName string, pods []k8s.Pod, ambientExpected bool) {
	if !ambientExpected || len(pods) == 0 {
		return
	}
	var missing []string
	var redirected int
	var optedOut int

	for _, p := range pods {
		if p.Status.Phase != "Running" {
			continue
		}
		if p.Metadata.Labels[LabelDataplaneMode] == "none" ||
			p.Metadata.Labels[LabelGatewayName] != "" ||
			p.Metadata.Labels[LabelVEG] != "" {
			optedOut++
			continue
		}
		if p.Metadata.Annotations[AnnotRedirection] == "enabled" {
			redirected++
		} else {
			missing = append(missing, fmt.Sprintf("%s (node=%s, ip=%s)", p.Metadata.Name, p.Spec.NodeName, p.Status.PodIP))
		}
	}

	if len(missing) > 0 {
		r.Fail("pod-redirection-"+nsName, layer, "ns/"+nsName, "Pod ambient redirection annotation",
			fmt.Sprintf("%d running pod(s) lack %s=enabled (redirected=%d, excluded=%d)", len(missing), AnnotRedirection, redirected, optedOut),
			fmt.Sprintf("Check istio-cni-node logs on affected nodes or restart affected workloads in %s", nsName),
			strings.Join(missing, "\n"))
	} else if redirected > 0 {
		r.Pass("pod-redirection-"+nsName, layer, "ns/"+nsName, "Pod ambient redirection annotation",
			fmt.Sprintf("all %d eligible running pod(s) have %s=enabled (excluded=%d)", redirected, AnnotRedirection, optedOut))
	}
}
