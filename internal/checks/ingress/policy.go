package ingress

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/awbait/debug-toolbox/internal/checks/common"
	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

type backendTarget struct {
	Namespace   string
	ServiceName string
	Port        int
	Protocol    string // TCP or UDP
	RouteKind   string
	RouteName   string
}

func checkReferenceGrants(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	gwNS string,
	targets []backendTarget,
) {
	const layer = "Routes & Backends"

	grantsByNS := make(map[string][]k8s.ReferenceGrant)
	checked := make(map[string]bool)

	for _, t := range targets {
		if t.Namespace == gwNS {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s", t.Namespace, t.RouteKind, t.ServiceName)
		if checked[key] {
			continue
		}
		checked[key] = true

		grants, loaded := grantsByNS[t.Namespace]
		if !loaded {
			var err error
			grants, err = c.ListReferenceGrants(ctx, t.Namespace)
			if err != nil {
				r.Warn("rg-list-"+t.Namespace, layer, "ns/"+t.Namespace, "Cross-namespace ReferenceGrant",
					fmt.Sprintf("could not list ReferenceGrants in %s: %v", t.Namespace, err),
					"Verify RBAC permissions or check ReferenceGrant manually in "+t.Namespace)
				grantsByNS[t.Namespace] = nil
				continue
			}
			grantsByNS[t.Namespace] = grants
		}

		matchedName := ""
		for _, rg := range grants {
			if referenceGrantAllows(rg, gwNS, t.RouteKind, t.ServiceName) {
				matchedName = rg.Metadata.Name
				break
			}
		}

		res := fmt.Sprintf("%s/%s -> %s/%s", gwNS, t.RouteName, t.Namespace, t.ServiceName)
		if matchedName != "" {
			r.Pass("rg-"+t.Namespace+"-"+t.ServiceName, layer, res, "Cross-namespace ReferenceGrant",
				fmt.Sprintf("allowed by ReferenceGrant %s/%s", t.Namespace, matchedName))
		} else {
			r.Fail("rg-"+t.Namespace+"-"+t.ServiceName, layer, res, "Cross-namespace ReferenceGrant",
				fmt.Sprintf("NO ReferenceGrant in namespace %s allows %s from %s to access Service %s",
					t.Namespace, t.RouteKind, gwNS, t.ServiceName),
				fmt.Sprintf("Create a ReferenceGrant in namespace %s (or keep referenceGrant: true in ingress-gateway values)", t.Namespace))
		}
	}
}

func referenceGrantAllows(rg k8s.ReferenceGrant, fromNS, routeKind, svcName string) bool {
	fromOK := false
	for _, f := range rg.Spec.From {
		if (f.Group == "gateway.networking.k8s.io" || f.Group == "") &&
			strings.EqualFold(f.Kind, routeKind) &&
			f.Namespace == fromNS {
			fromOK = true
			break
		}
	}
	if !fromOK {
		return false
	}
	for _, to := range rg.Spec.To {
		if (to.Group == "" || to.Group == "core") &&
			(to.Kind == "Service" || to.Kind == "") &&
			(to.Name == "" || to.Name == svcName) {
			return true
		}
	}
	return false
}

func checkGatewayPolicies(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	gw k8s.Gateway,
	targets []backendTarget,
	backendAmbient map[string]bool,
	backendPodsByKey map[string][]k8s.Pod,
	backendSvcSelectors map[string]map[string]string,
) {
	const layer = "Policies"
	gwNS := gw.Metadata.Namespace
	gwName := gw.Metadata.Name

	// 1. Gateway namespace NetworkPolicies
	gwNPs, err := c.ListNetworkPolicies(ctx, gwNS)
	if err != nil {
		r.Warn("np-gw-list", layer, "ns/"+gwNS, "Gateway NetworkPolicies",
			fmt.Sprintf("failed to list NetworkPolicies in %s: %v", gwNS, err), "Check RBAC")
	} else {
		var egressNPs []k8s.NetworkPolicy
		for _, np := range gwNPs {
			if npMatchesGateway(np, gwName) && hasPolicyType(np, "Egress") {
				egressNPs = append(egressNPs, np)
			}
		}
		if len(egressNPs) == 0 {
			r.Info("np-gw-egress", layer, gwNS+"/"+gwName, "Gateway egress NetworkPolicy",
				"no Egress NetworkPolicy selects gateway pods (unrestricted egress)")
		} else {
			// Verify istiod 15012, CoreDNS 1053/53, and each backend NS port + 15008
			if !egressAllowsNSAndPort(egressNPs, "istio-system", 15012, "TCP") {
				r.Fail("np-gw-istiod", layer, gwNS+"/"+gwName, "Gateway NetworkPolicy -> istiod",
					"Egress NetworkPolicy on gateway pods does NOT allow istio-system:15012",
					"Allow TCP 15012 to namespace istio-system so gateway Envoy receives xDS config")
			}
			if !egressAllowsNSAndPort(egressNPs, "kube-system", 1053, "UDP") &&
				!egressAllowsNSAndPort(egressNPs, "kube-system", 53, "UDP") {
				r.Warn("np-gw-dns", layer, gwNS+"/"+gwName, "Gateway NetworkPolicy -> CoreDNS",
					"Egress NetworkPolicy on gateway pods does not explicitly allow kube-system:1053/53",
					"Ensure CoreDNS egress (TCP/UDP 1053 or 53) is permitted")
			}

			checkedDest := make(map[string]bool)
			for _, t := range targets {
				k := fmt.Sprintf("%s:%d/%s", t.Namespace, t.Port, t.Protocol)
				if checkedDest[k] {
					continue
				}
				checkedDest[k] = true

				hasAppPort := egressAllowsNSAndPort(egressNPs, t.Namespace, t.Port, t.Protocol)
				hasHBONE := egressAllowsNSAndPort(egressNPs, t.Namespace, 15008, "TCP")

				if backendAmbient[t.Namespace] && t.Protocol == "TCP" && !hasHBONE {
					r.Fail("np-gw-hbone-"+t.Namespace, layer, gwNS+"/"+gwName,
						fmt.Sprintf("Gateway NetworkPolicy -> %s (HBONE 15008)", t.Namespace),
						fmt.Sprintf("backend namespace %s is in ambient mesh, but Gateway Egress NetworkPolicy does NOT allow TCP port 15008 to %s", t.Namespace, t.Namespace),
						fmt.Sprintf("Add TCP port 15008 to Gateway Egress NetworkPolicy for namespace %s (ambient HBONE tunnel port)", t.Namespace))
				} else if !backendAmbient[t.Namespace] && !hasAppPort {
					r.Fail("np-gw-port-"+t.Namespace, layer, gwNS+"/"+gwName,
						fmt.Sprintf("Gateway NetworkPolicy -> %s:%d", t.Namespace, t.Port),
						fmt.Sprintf("Gateway Egress NetworkPolicy does NOT allow %s:%d (%s)", t.Namespace, t.Port, t.Protocol),
						fmt.Sprintf("Allow egress to namespace %s on %s/%d", t.Namespace, t.Protocol, t.Port))
				} else {
					r.Pass("np-gw-to-"+t.Namespace, layer, gwNS+"/"+gwName,
						fmt.Sprintf("Gateway Egress NetworkPolicy -> %s:%d", t.Namespace, t.Port),
						fmt.Sprintf("permitted (appPort=%v, hbone15008=%v)", hasAppPort, hasHBONE))
				}
			}
		}
	}

	// 2. Backend namespaces: NetworkPolicy (Ingress) & AuthorizationPolicy
	gwPrincipalSuffix := fmt.Sprintf("/ns/%s/sa/%s-istio", gwNS, gwName)
	seenNS := make(map[string][]backendTarget)
	for _, t := range targets {
		seenNS[t.Namespace] = append(seenNS[t.Namespace], t)
	}

	for bNS, bTargets := range seenNS {
		// Backend NetworkPolicy ingress check (scoped to NPs whose podSelector matches backend pods)
		bNPs, err := c.ListNetworkPolicies(ctx, bNS)
		if err == nil {
			var allIngressNPs []k8s.NetworkPolicy
			for _, np := range bNPs {
				if hasPolicyType(np, "Ingress") {
					allIngressNPs = append(allIngressNPs, np)
				}
			}
			if len(allIngressNPs) > 0 {
				for _, t := range bTargets {
					svcKey := fmt.Sprintf("%s/%s:%d", t.Namespace, t.ServiceName, t.Port)
					bPods := backendPodsByKey[svcKey]
					svcSel := backendSvcSelectors[svcKey]

					var matchingNPs []k8s.NetworkPolicy
					for _, np := range allIngressNPs {
						if npSelectsBackend(np, bPods, svcSel) {
							matchingNPs = append(matchingNPs, np)
						}
					}
					if len(matchingNPs) == 0 {
						r.Info("np-backend-"+bNS+"-"+t.ServiceName, layer, bNS+"/"+t.ServiceName,
							fmt.Sprintf("Backend Ingress NetworkPolicy (%s:%d)", t.ServiceName, t.Port),
							fmt.Sprintf("0 of %d Ingress NetworkPolicy(ies) in %s select pods of Service %s (unrestricted ingress)",
								len(allIngressNPs), bNS, t.ServiceName))
						continue
					}

					allowApp := ingressAllowsFromNSAndPort(matchingNPs, gwNS, gwName, t.Port, t.Protocol)
					allowHBONE := ingressAllowsFromNSAndPort(matchingNPs, gwNS, gwName, 15008, "TCP")
					if backendAmbient[bNS] && t.Protocol == "TCP" && !allowHBONE {
						r.Fail("np-backend-hbone-"+bNS, layer, bNS+"/"+t.ServiceName,
							fmt.Sprintf("Backend Ingress NetworkPolicy (%s/%s)", bNS, t.ServiceName),
							fmt.Sprintf("backend Service %s/%s is selected by %d Ingress NetworkPolicy(ies) and is in ambient mesh, but NONE allows TCP 15008 (HBONE) from gateway namespace %s",
								bNS, t.ServiceName, len(matchingNPs), gwNS),
							fmt.Sprintf("Add Ingress NetworkPolicy in %s allowing TCP 15008 (and %d) from gateway pods in %s", bNS, t.Port, gwNS))
					} else if !backendAmbient[bNS] && !allowApp {
						r.Fail("np-backend-port-"+bNS, layer, bNS+"/"+t.ServiceName,
							fmt.Sprintf("Backend Ingress NetworkPolicy (%s/%s:%d)", bNS, t.ServiceName, t.Port),
							fmt.Sprintf("backend Service %s/%s is selected by %d Ingress NetworkPolicy(ies), but NONE allows %s/%d from %s",
								bNS, t.ServiceName, len(matchingNPs), t.Protocol, t.Port, gwNS),
							fmt.Sprintf("Add Ingress NetworkPolicy in %s allowing %s/%d from gateway pods in %s", bNS, t.Protocol, t.Port, gwNS))
					} else {
						r.Pass("np-backend-"+bNS+"-"+strconv.Itoa(t.Port), layer, bNS+"/"+t.ServiceName,
							fmt.Sprintf("Backend Ingress NetworkPolicy (%s/%s:%d)", bNS, t.ServiceName, t.Port),
							fmt.Sprintf("allows gateway from %s (appPort=%v, hbone15008=%v)", gwNS, allowApp, allowHBONE))
					}
				}
			}
		}

		// Backend AuthorizationPolicy check (scoped to policies matching backend pods or Service)
		aps, err := c.ListAuthorizationPolicies(ctx, bNS)
		if err != nil {
			continue
		}
		if len(aps) == 0 {
			r.Info("ap-backend-"+bNS, layer, "ns/"+bNS, "Backend AuthorizationPolicy",
				"no AuthorizationPolicies in backend namespace (all mTLS traffic allowed)")
			continue
		}

		// Warn on L7 rules in workload AuthorizationPolicy when namespace has no waypoint
		for _, ap := range aps {
			if hasL7Rules(ap) && len(ap.Spec.TargetRefs) == 0 {
				r.Warn("ap-l7-"+bNS+"-"+ap.Metadata.Name, layer, bNS+"/"+ap.Metadata.Name,
					"L7 rules in workload AuthorizationPolicy",
					"AuthorizationPolicy uses HTTP L7 fields (paths/methods/hosts) without targetRefs (ztunnel is L4-only; L7 rules without waypoint can silently deny)",
					"Remove L7 fields or attach a waypoint proxy and bind the policy via targetRefs")
			}
		}

		for _, t := range bTargets {
			svcKey := fmt.Sprintf("%s/%s:%d", t.Namespace, t.ServiceName, t.Port)
			bPods := backendPodsByKey[svcKey]
			svcSel := backendSvcSelectors[svcKey]

			var matchingAllowAPs []k8s.AuthorizationPolicy
			for _, ap := range aps {
				if !apAppliesToBackend(ap, t.ServiceName, bPods, svcSel) {
					continue
				}
				action := strings.ToUpper(ap.Spec.Action)
				if action == "" || action == "ALLOW" {
					matchingAllowAPs = append(matchingAllowAPs, ap)
				}
			}

			portStr := strconv.Itoa(t.Port)
			if len(matchingAllowAPs) == 0 {
				r.Info("ap-backend-"+bNS+"-"+t.ServiceName+"-"+portStr, layer, bNS+"/"+t.ServiceName,
					fmt.Sprintf("Backend AuthorizationPolicy (%s:%d)", t.ServiceName, t.Port),
					fmt.Sprintf("0 of %d AuthorizationPolicy(ies) in %s apply ALLOW rules to Service %s (no implicit deny on this backend)",
						len(aps), bNS, t.ServiceName))
				continue
			}

			allowedBy := findAllowingAuthzPolicy(matchingAllowAPs, gwNS, gwPrincipalSuffix, portStr)
			if allowedBy != "" {
				r.Pass("ap-backend-"+bNS+"-"+portStr, layer, bNS+"/"+allowedBy,
					fmt.Sprintf("Backend AuthorizationPolicy (%s:%d)", bNS, t.Port),
					fmt.Sprintf("ALLOW policy %q permits gateway principal *%s on port %s", allowedBy, gwPrincipalSuffix, portStr))
			} else {
				r.Fail("ap-backend-"+bNS+"-"+portStr, layer, bNS+"/"+t.ServiceName,
					fmt.Sprintf("Backend AuthorizationPolicy (%s:%d)", bNS, t.Port),
					fmt.Sprintf("backend Service %s/%s is matched by %d ALLOW AuthorizationPolicy(ies) (Istio implicit deny active), but NONE explicitly allows gateway principal *%s on port %s",
						bNS, t.ServiceName, len(matchingAllowAPs), gwPrincipalSuffix, portStr),
					fmt.Sprintf("Add ALLOW AuthorizationPolicy in %s with principal cluster.local%s and port %q (string)", bNS, gwPrincipalSuffix, portStr))
			}
		}
	}

	// 3. OIDC / RequestAuthentication check if present
	checkOIDCResources(ctx, c, r, gw)
}

func checkOIDCResources(ctx context.Context, c *k8s.Client, r *report.Report, gw k8s.Gateway) {
	const layer = "Policies"
	ns := gw.Metadata.Namespace

	ras, err := c.ListRequestAuthentications(ctx, ns)
	if err != nil {
		return
	}
	hasOIDC := false
	for _, ra := range ras {
		for _, tr := range ra.Spec.TargetRefs {
			if tr.Kind == "Gateway" && tr.Name == gw.Metadata.Name {
				hasOIDC = true
				r.Info("oidc-ra-"+ra.Metadata.Name, layer, ns+"/"+ra.Metadata.Name, "OIDC RequestAuthentication",
					fmt.Sprintf("attached to Gateway %s (%d JWT rule(s))", gw.Metadata.Name, len(ra.Spec.JWTRules)))
			}
		}
	}
	if !hasOIDC {
		return
	}

	// Verify oauth2-proxy service & endpoints exist
	ep, err := c.GetEndpoints(ctx, "oauth2-proxy", "oauth2-proxy")
	if err != nil {
		r.Fail("oidc-proxy-ep", layer, "oauth2-proxy/oauth2-proxy", "OIDC oauth2-proxy endpoints",
			fmt.Sprintf("failed to get oauth2-proxy endpoints: %v", err),
			"Verify oauth2-proxy deployment is running in namespace oauth2-proxy")
		return
	}
	readyAddrs := countReadyAddresses(ep)
	if readyAddrs == 0 {
		r.Fail("oidc-proxy-ep", layer, "oauth2-proxy/oauth2-proxy", "OIDC oauth2-proxy endpoints",
			"oauth2-proxy service has 0 ready endpoints",
			"Check oauth2-proxy pods in namespace oauth2-proxy")
	} else {
		r.Pass("oidc-proxy-ep", layer, "oauth2-proxy/oauth2-proxy", "OIDC oauth2-proxy endpoints",
			fmt.Sprintf("%d ready endpoint(s)", readyAddrs))
	}
}

func npMatchesGateway(np k8s.NetworkPolicy, gwName string) bool {
	if len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0 {
		return true
	}
	return np.Spec.PodSelector.MatchLabels[common.LabelGatewayName] == gwName
}

func selectorIsEmpty(sel k8s.LabelSelector) bool {
	return len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

func selectorMatchesBackend(sel k8s.LabelSelector, pods []k8s.Pod, svcSelector map[string]string) bool {
	if selectorIsEmpty(sel) {
		return true
	}
	if len(pods) > 0 {
		for _, p := range pods {
			if matchesLabelSelector(sel, p.Metadata.Labels) {
				return true
			}
		}
		return false
	}
	if len(svcSelector) > 0 {
		return matchesLabelSelector(sel, svcSelector)
	}
	return false
}

func npSelectsBackend(np k8s.NetworkPolicy, pods []k8s.Pod, svcSelector map[string]string) bool {
	return selectorMatchesBackend(np.Spec.PodSelector, pods, svcSelector)
}

func apAppliesToBackend(ap k8s.AuthorizationPolicy, svcName string, pods []k8s.Pod, svcSelector map[string]string) bool {
	if len(ap.Spec.TargetRefs) > 0 {
		for _, tr := range ap.Spec.TargetRefs {
			if strings.EqualFold(tr.Kind, "Service") && tr.Name == svcName {
				return true
			}
		}
		return false
	}
	if ap.Spec.Selector == nil {
		return true
	}
	return selectorMatchesBackend(*ap.Spec.Selector, pods, svcSelector)
}

func hasPolicyType(np k8s.NetworkPolicy, pt string) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		if pt == "Ingress" {
			return len(np.Spec.Ingress) > 0
		}
		return len(np.Spec.Egress) > 0
	}
	for _, t := range np.Spec.PolicyTypes {
		if strings.EqualFold(t, pt) {
			return true
		}
	}
	return false
}

func egressAllowsNSAndPort(nps []k8s.NetworkPolicy, targetNS string, port int, proto string) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Egress {
			peerOK := len(rule.To) == 0
			for _, peer := range rule.To {
				if peerMatchesNamespace(peer, targetNS) {
					peerOK = true
					break
				}
			}
			if peerOK && portsAllow(rule.Ports, port, proto) {
				return true
			}
		}
	}
	return false
}

func ingressAllowsFromNSAndPort(nps []k8s.NetworkPolicy, fromNS, gwName string, port int, proto string) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Ingress {
			peerOK := len(rule.From) == 0
			for _, peer := range rule.From {
				if peerMatchesNamespace(peer, fromNS) {
					if peer.PodSelector == nil || len(peer.PodSelector.MatchLabels) == 0 ||
						peer.PodSelector.MatchLabels[common.LabelGatewayName] == gwName {
						peerOK = true
						break
					}
				}
			}
			if peerOK && portsAllow(rule.Ports, port, proto) {
				return true
			}
		}
	}
	return false
}

func peerMatchesNamespace(peer k8s.NetworkPolicyPeer, targetNS string) bool {
	if peer.IPBlock != nil && peer.IPBlock.CIDR == "0.0.0.0/0" {
		return true
	}
	if peer.NamespaceSelector == nil {
		return false
	}
	if len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0 {
		return true
	}
	if peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == targetNS {
		return true
	}
	for _, expr := range peer.NamespaceSelector.MatchExpressions {
		if expr.Key == "kubernetes.io/metadata.name" && expr.Operator == "In" {
			for _, v := range expr.Values {
				if v == targetNS {
					return true
				}
			}
		}
	}
	return false
}

func portsAllow(ports []k8s.NetworkPolicyPort, targetPort int, targetProto string) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		proto := p.Protocol
		if proto == "" {
			proto = "TCP"
		}
		if !strings.EqualFold(proto, targetProto) {
			continue
		}
		_, num := k8s.ParsePortRaw(p.Port)
		if num == targetPort || len(p.Port) == 0 {
			return true
		}
	}
	return false
}

func hasL7Rules(ap k8s.AuthorizationPolicy) bool {
	for _, rule := range ap.Spec.Rules {
		for _, to := range rule.To {
			if len(to.Operation.Paths) > 0 || len(to.Operation.Methods) > 0 || len(to.Operation.Hosts) > 0 {
				return true
			}
		}
	}
	return false
}

func findAllowingAuthzPolicy(aps []k8s.AuthorizationPolicy, gwNS, principalSuffix, portStr string) string {
	for _, ap := range aps {
		action := strings.ToUpper(ap.Spec.Action)
		if action != "" && action != "ALLOW" {
			continue
		}
		if len(ap.Spec.Rules) == 0 {
			continue // empty rules in ALLOW = deny-all
		}
		for _, rule := range ap.Spec.Rules {
			fromOK := len(rule.From) == 0
			for _, f := range rule.From {
				for _, p := range f.Source.Principals {
					if p == "*" || strings.HasSuffix(p, principalSuffix) {
						fromOK = true
					}
				}
				for _, ns := range f.Source.Namespaces {
					if ns == "*" || ns == gwNS {
						fromOK = true
					}
				}
				for _, ip := range f.Source.IPBlocks {
					if ip == "0.0.0.0/0" {
						fromOK = true
					}
				}
			}
			if !fromOK {
				continue
			}

			toOK := len(rule.To) == 0
			for _, to := range rule.To {
				if len(to.Operation.Ports) == 0 {
					toOK = true
					break
				}
				for _, p := range to.Operation.Ports {
					if p == portStr || p == "*" {
						toOK = true
						break
					}
				}
			}
			if toOK {
				return ap.Metadata.Name
			}
		}
	}
	return ""
}
