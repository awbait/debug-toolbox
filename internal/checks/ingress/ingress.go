package ingress

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/awbait/debug-toolbox/internal/checks/common"
	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/probe"
	"github.com/awbait/debug-toolbox/internal/report"
)

// Options configures an ingress-gateway diagnostic run.
type Options struct {
	Version      string
	Namespace    string
	GatewayName  string // optional; if empty, checks all gatewayClassName=istio Gateways in Namespace
	Since        string
	Probe        bool
	ToolboxImage string
	Verbose      bool
}

var gatewayLogErrPattern = regexp.MustCompile(`(?i)(" 50[0-9] |" 403 |" 404 |UH|UF|NR|DC|UO|upstream_reset|connection reset|TLS|handshake|RBAC|denied|error)`)

// Run performs full diagnostics for ingress-gateway installations in opts.Namespace.
func Run(ctx context.Context, c *k8s.Client, opts Options) *report.Report {
	if opts.Since == "" {
		opts.Since = "15m"
	}
	r := report.New(opts.Version, "ingress", opts.Namespace, opts.GatewayName, opts.Probe)

	// Layer 1: Control plane & release namespace
	ztunnelNS, ztunnelPods := common.CheckControlPlane(ctx, c, r, false)
	_, err := common.CheckNamespaceMesh(ctx, c, r, "Namespace", opts.Namespace, false)
	if err != nil {
		r.Finalize(c.Runner.History(), opts.Verbose)
		return r
	}

	// Discover ingress Gateways (gatewayClassName: istio)
	allGWs, err := c.ListGateways(ctx, opts.Namespace)
	if err != nil {
		r.Fail("gw-list", "Gateway", "ns/"+opts.Namespace, "List Gateways",
			fmt.Sprintf("failed to list Gateway resources: %v", err),
			"Verify Gateway API CRDs are installed and RBAC permits reading gateways.gateway.networking.k8s.io")
		r.Finalize(c.Runner.History(), opts.Verbose)
		return r
	}

	var gateways []k8s.Gateway
	for _, gw := range allGWs {
		if gw.Spec.GatewayClassName != "istio" {
			continue
		}
		if opts.GatewayName != "" && gw.Metadata.Name != opts.GatewayName {
			continue
		}
		gateways = append(gateways, gw)
	}

	if len(gateways) == 0 {
		msg := fmt.Sprintf("no Gateway with gatewayClassName=istio found in namespace %s", opts.Namespace)
		if opts.GatewayName != "" {
			msg = fmt.Sprintf("Gateway %q (gatewayClassName=istio) not found in namespace %s", opts.GatewayName, opts.Namespace)
		}
		r.Fail("gw-not-found", "Gateway", "ns/"+opts.Namespace, "Ingress Gateway discovery",
			msg, "Check namespace name or verify ingress-gateway chart release is deployed")
		r.Finalize(c.Runner.History(), opts.Verbose)
		return r
	}

	// Load routes, certs, externalsecrets, destinationrules, warning events once per namespace
	allRoutes := loadAllRoutes(ctx, c, opts.Namespace)
	certs, _ := c.ListCertificates(ctx, opts.Namespace)
	extSecrets, _ := c.ListExternalSecrets(ctx, opts.Namespace)
	destRules, _ := c.ListDestinationRules(ctx, opts.Namespace)
	warnEvents, _ := c.ListWarningEvents(ctx, opts.Namespace)

	for _, gw := range gateways {
		diagnoseSingleGateway(ctx, c, r, gw, allRoutes, certs, extSecrets, destRules, warnEvents, ztunnelNS, ztunnelPods, opts)
	}

	r.Finalize(c.Runner.History(), opts.Verbose)
	return r
}

func diagnoseSingleGateway(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	gw k8s.Gateway,
	allRoutes []k8s.Route,
	certs []k8s.Certificate,
	extSecrets []k8s.ExternalSecret,
	destRules []k8s.DestinationRule,
	warnEvents []k8s.Event,
	ztunnelNS string,
	ztunnelPods []k8s.Pod,
	opts Options,
) {
	ns := gw.Metadata.Namespace
	gwName := gw.Metadata.Name
	gwRes := ns + "/" + gwName

	// --- Layer 2: Gateway, ConfigMap, Service/MetalLB, Pods ---
	const gwLayer = "Gateway & Infrastructure"

	// Gateway conditions
	checkGatewayConditions(r, gwLayer, gw)

	// Parameters ConfigMap
	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.ParametersRef != nil {
		cmName := gw.Spec.Infrastructure.ParametersRef.Name
		if _, err := c.GetConfigMap(ctx, ns, cmName); err != nil {
			r.Fail("gw-cm-"+cmName, gwLayer, ns+"/"+cmName, "Infrastructure ConfigMap",
				fmt.Sprintf("referenced ConfigMap %s not found: %v", cmName, err),
				"Verify ingress-gateway chart created the infrastructure ConfigMap")
		} else {
			r.Pass("gw-cm-"+cmName, gwLayer, ns+"/"+cmName, "Infrastructure ConfigMap", "exists")
		}
	}

	// Gateway Pods
	gwPods, err := c.ListPods(ctx, ns, common.LabelGatewayName+"="+gwName)
	targetNodes := make(map[string]bool)
	var logTokens []string
	logTokens = append(logTokens, gwName)
	if err != nil {
		r.Fail("gw-pods-"+gwName, gwLayer, gwRes, "Gateway pods",
			fmt.Sprintf("failed to list gateway pods: %v", err), "Check RBAC")
	} else if len(gwPods) == 0 {
		r.Fail("gw-pods-"+gwName, gwLayer, gwRes, "Gateway pods",
			fmt.Sprintf("0 pods found with label %s=%s", common.LabelGatewayName, gwName),
			"Check Istio Gateway controller / istiod logs and namespace ResourceQuota or PodSecurity")
	} else {
		ready := 0
		var bad []string
		for _, p := range gwPods {
			if p.Spec.NodeName != "" {
				targetNodes[p.Spec.NodeName] = true
			}
			if p.Status.PodIP != "" {
				logTokens = append(logTokens, p.Status.PodIP)
			}
			if p.IsReady() {
				ready++
			} else {
				bad = append(bad, fmt.Sprintf("%s (phase=%s, restarts=%d, node=%s)", p.Metadata.Name, p.Status.Phase, p.TotalRestarts(), p.Spec.NodeName))
			}
		}
		if ready == 0 {
			r.Fail("gw-pods-"+gwName, gwLayer, gwRes, "Gateway pods",
				fmt.Sprintf("0/%d gateway pods Ready", len(gwPods)),
				"Inspect gateway pod describe/logs and events (common causes: missing TLS secret, ResourceQuota, nodeSelector/taints)",
				bad...)
		} else if ready < len(gwPods) {
			r.Warn("gw-pods-"+gwName, gwLayer, gwRes, "Gateway pods",
				fmt.Sprintf("%d/%d gateway pods Ready", ready, len(gwPods)),
				"Inspect non-ready gateway pods", bad...)
		} else {
			r.Pass("gw-pods-"+gwName, gwLayer, gwRes, "Gateway pods",
				fmt.Sprintf("%d/%d pods Ready", ready, len(gwPods)))
		}
	}

	// Gateway Service & MetalLB VIP
	vip := checkGatewayService(ctx, c, r, gwLayer, gw)

	// Warning events for this Gateway / Service / Pods
	var gwEventLines []string
	for _, ev := range warnEvents {
		if strings.HasPrefix(ev.InvolvedObject.Name, gwName) {
			gwEventLines = append(gwEventLines, fmt.Sprintf("%s/%s: %s (x%d) - %s",
				ev.InvolvedObject.Kind, ev.InvolvedObject.Name, ev.Reason, ev.Count, ev.Message))
		}
	}
	if len(gwEventLines) > 0 {
		if len(gwEventLines) > 8 {
			gwEventLines = gwEventLines[len(gwEventLines)-8:]
		}
		r.Warn("gw-events-"+gwName, gwLayer, gwRes, "Recent Warning events",
			fmt.Sprintf("%d Warning event(s) for %s*", len(gwEventLines), gwName),
			"Investigate Kubernetes warning events above", gwEventLines...)
	}

	// --- Layer 3: TLS Certificates ---
	checkGatewayTLS(ctx, c, r, gw, certs, extSecrets)

	// --- Layer 4: Routes & Backends ---
	const routeLayer = "Routes & Backends"
	attachedRoutes := filterRoutesForGateway(allRoutes, gwName, ns)
	if len(attachedRoutes) == 0 {
		r.Warn("routes-none-"+gwName, routeLayer, gwRes, "Attached routes",
			"no HTTPRoute/GRPCRoute/TLSRoute/TCPRoute/UDPRoute references this Gateway in namespace "+ns,
			"Verify xroutes[] and parentRefs[].gateway/sectionName in ingress-gateway values")
	}

	listenerByName := make(map[string]k8s.GatewayListener)
	for _, l := range gw.Spec.Listeners {
		listenerByName[l.Name] = l
	}

	var targets []backendTarget
	for _, rt := range attachedRoutes {
		checkRouteStatus(r, routeLayer, rt, gw, listenerByName)
		proto := "TCP"
		if strings.EqualFold(rt.Kind, "UDPRoute") {
			proto = "UDP"
		}
		for _, rule := range rt.Spec.Rules {
			for _, br := range rule.BackendRefs {
				bNS := br.Namespace
				if bNS == "" {
					bNS = rt.Metadata.Namespace
				}
				targets = append(targets, backendTarget{
					Namespace:   bNS,
					ServiceName: br.Name,
					Port:        br.Port,
					Protocol:    proto,
					RouteKind:   rt.Kind,
					RouteName:   rt.Metadata.Name,
				})
			}
		}
	}

	// Cross-namespace ReferenceGrants
	checkReferenceGrants(ctx, c, r, ns, targets)

	// Inspect each unique backend Service, Endpoints, Pods & mesh enrollment
	backendAmbient := make(map[string]bool)
	backendPodsByKey := make(map[string][]k8s.Pod)
	backendSvcIPs := make(map[string]string)
	checkedBackendNS := make(map[string]bool)
	checkedSvc := make(map[string]bool)

	for _, t := range targets {
		if !checkedBackendNS[t.Namespace] {
			checkedBackendNS[t.Namespace] = true
			nsInfo, err := common.CheckNamespaceMesh(ctx, c, r, routeLayer, t.Namespace, false)
			if err == nil {
				backendAmbient[t.Namespace] = nsInfo.AmbientEnabled
			}
			// Check DestinationRule sessionAffinity vs ingress-use-waypoint pitfall
			if nsInfo.Namespace.Metadata.Labels[common.LabelIngressUseWP] == "true" {
				warnAffinityWithWaypoint(r, routeLayer, destRules, t.Namespace, "")
			}
		}

		svcKey := fmt.Sprintf("%s/%s:%d", t.Namespace, t.ServiceName, t.Port)
		if checkedSvc[svcKey] {
			continue
		}
		checkedSvc[svcKey] = true

		svc, err := c.GetService(ctx, t.Namespace, t.ServiceName)
		if err != nil {
			r.Fail("backend-svc-"+t.Namespace+"-"+t.ServiceName, routeLayer, t.Namespace+"/"+t.ServiceName,
				"Backend Service",
				fmt.Sprintf("service %s/%s not found: %v", t.Namespace, t.ServiceName, err),
				"Verify backendRefs[].name and backendRefs[].namespace in route "+t.RouteName)
			continue
		}
		backendSvcIPs[svcKey] = svc.Spec.ClusterIP

		if svc.Metadata.Labels[common.LabelIngressUseWP] == "true" {
			warnAffinityWithWaypoint(r, routeLayer, destRules, t.Namespace, t.ServiceName)
		}

		// Check port declared on Service
		portDeclared := false
		var targetPortVal int
		for _, sp := range svc.Spec.Ports {
			if sp.Port == t.Port {
				portDeclared = true
				_, targetPortVal = k8s.ParsePortRaw(sp.TargetPort)
				break
			}
		}
		if !portDeclared {
			r.Fail("backend-svc-port-"+t.ServiceName, routeLayer, t.Namespace+"/"+t.ServiceName,
				"Backend Service port",
				fmt.Sprintf("route %s targets port %d, but Service %s/%s does not expose port %d", t.RouteName, t.Port, t.Namespace, t.ServiceName, t.Port),
				"Fix backendRefs[].port to match Service spec.ports[].port")
		} else if !backendAmbient[t.Namespace] && targetPortVal > 0 && targetPortVal != t.Port {
			r.Warn("backend-port-mismatch-"+t.ServiceName, routeLayer, t.Namespace+"/"+t.ServiceName,
				"Service port vs targetPort (non-mesh)",
				fmt.Sprintf("Service port=%d differs from targetPort=%d while namespace %s is outside mesh (ingress-gateway NetworkPolicy uses Service port %d)",
					t.Port, targetPortVal, t.Namespace, t.Port),
				"If NetworkPolicy is enabled, align Service port with containerPort or open targetPort explicitly")
		}

		// Endpoints
		ep, err := c.GetEndpoints(ctx, t.Namespace, t.ServiceName)
		if err != nil {
			r.Fail("backend-ep-"+t.ServiceName, routeLayer, t.Namespace+"/"+t.ServiceName,
				"Backend Endpoints", fmt.Sprintf("failed to get Endpoints: %v", err),
				"Check Service selector and pods in "+t.Namespace)
			continue
		}
		readyAddrs := countReadyAddresses(ep)
		if readyAddrs == 0 {
			r.Fail("backend-ep-"+t.ServiceName, routeLayer, t.Namespace+"/"+t.ServiceName,
				"Backend Endpoints",
				fmt.Sprintf("Service %s/%s has 0 Ready endpoints (gateway will return 503 UH)", t.Namespace, t.ServiceName),
				fmt.Sprintf("Check pods matching Service selector %v and readiness probes in %s", svc.Spec.Selector, t.Namespace))
			continue
		}
		r.Pass("backend-ep-"+t.ServiceName, routeLayer, t.Namespace+"/"+t.ServiceName,
			"Backend Endpoints", fmt.Sprintf("%d Ready endpoint(s) on port %d", readyAddrs, t.Port))

		// Collect backend pods for redirection & ztunnel checks
		if len(svc.Spec.Selector) > 0 {
			sel := mapToSelector(svc.Spec.Selector)
			bPods, err := c.ListPods(ctx, t.Namespace, sel)
			if err == nil {
				backendPodsByKey[svcKey] = bPods
				common.CheckPodsRedirection(r, routeLayer, t.Namespace, bPods, backendAmbient[t.Namespace])
				for _, bp := range bPods {
					if bp.Spec.NodeName != "" {
						targetNodes[bp.Spec.NodeName] = true
					}
					if bp.Status.PodIP != "" {
						logTokens = append(logTokens, bp.Status.PodIP)
					}
				}
				if len(ztunnelPods) > 0 && backendAmbient[t.Namespace] {
					zp := pickZtunnelForNodes(ztunnelPods, targetNodes)
					common.InspectZtunnelWorkloads(ctx, c, r, "Logs & ztunnel", ztunnelNS, zp, t.Namespace, bPods)
				}
			}
		}
	}

	// --- Layer 5: Policies & OIDC ---
	checkGatewayPolicies(ctx, c, r, gw, targets, backendAmbient)

	// --- Layer 6: Runtime Logs (Gateway Envoy + ztunnel on affected nodes) ---
	const logLayer = "Logs & ztunnel"
	inspectGatewayEnvoyLogs(ctx, c, r, logLayer, ns, gwName, gwPods, opts.Since)
	common.InspectZtunnelForNodes(ctx, c, r, logLayer, ztunnelNS, ztunnelPods, targetNodes, logTokens, opts.Since)

	// --- Layer 7: Active Probes (--probe) ---
	if opts.Probe {
		runIngressProbes(ctx, c, r, gw, vip, targets, backendPodsByKey, backendSvcIPs, opts)
	}
}

func checkGatewayConditions(r *report.Report, layer string, gw k8s.Gateway) {
	res := gw.Metadata.Namespace + "/" + gw.Metadata.Name
	acc, hasAcc := k8s.FindCondition(gw.Status.Conditions, "Accepted")
	prog, hasProg := k8s.FindCondition(gw.Status.Conditions, "Programmed")

	if hasAcc && acc.Status != "True" {
		r.Fail("gw-accepted-"+gw.Metadata.Name, layer, res, "Gateway Accepted",
			fmt.Sprintf("Accepted=%s (%s): %s", acc.Status, acc.Reason, acc.Message),
			"Check Gateway spec, listeners, and gatewayClassName=istio")
	} else if hasProg && prog.Status != "True" {
		r.Fail("gw-programmed-"+gw.Metadata.Name, layer, res, "Gateway Programmed",
			fmt.Sprintf("Programmed=%s (%s): %s", prog.Status, prog.Reason, prog.Message),
			"Check MetalLB VIP assignment, TLS secrets, and Gateway deployment pods")
	} else if hasAcc || hasProg {
		r.Pass("gw-status-"+gw.Metadata.Name, layer, res, "Gateway status", "Accepted=True, Programmed=True")
	} else {
		r.Warn("gw-status-"+gw.Metadata.Name, layer, res, "Gateway status",
			"Gateway has no status conditions yet", "Verify istiod Gateway API controller is running")
	}

	for _, ls := range gw.Status.Listeners {
		var issues []string
		for _, cond := range ls.Conditions {
			if (cond.Type == "Accepted" || cond.Type == "ResolvedRefs" || cond.Type == "Programmed") && cond.Status != "True" {
				issues = append(issues, fmt.Sprintf("%s=%s (%s: %s)", cond.Type, cond.Status, cond.Reason, cond.Message))
			}
		}
		if len(issues) > 0 {
			r.Fail("gw-listener-"+ls.Name, layer, res+":"+ls.Name, fmt.Sprintf("Listener %q", ls.Name),
				strings.Join(issues, "; "),
				"Check TLS certificateRef secret existence, hostname conflict, or allowedRoutes on listener "+ls.Name)
		} else if ls.AttachedRoutes == 0 {
			r.Warn("gw-listener-"+ls.Name, layer, res+":"+ls.Name, fmt.Sprintf("Listener %q", ls.Name),
				"Programmed=True, but attachedRoutes=0",
				"Check route parentRefs (kind: Gateway, exact gateway name and sectionName) and matching hostnames")
		} else {
			r.Pass("gw-listener-"+ls.Name, layer, res+":"+ls.Name, fmt.Sprintf("Listener %q", ls.Name),
				fmt.Sprintf("Programmed=True, attachedRoutes=%d", ls.AttachedRoutes))
		}
	}
}

func checkGatewayService(ctx context.Context, c *k8s.Client, r *report.Report, layer string, gw k8s.Gateway) string {
	ns := gw.Metadata.Namespace
	svcName := gw.Metadata.Name + "-istio"
	svc, err := c.GetService(ctx, ns, svcName)
	if err != nil {
		// Fallback: try same name as Gateway
		svc, err = c.GetService(ctx, ns, gw.Metadata.Name)
		if err != nil {
			r.Fail("gw-svc-"+gw.Metadata.Name, layer, ns+"/"+svcName, "Gateway LoadBalancer Service",
				fmt.Sprintf("service %s not found: %v", svcName, err),
				"Check istiod Gateway controller logs")
			return ""
		}
	}

	res := ns + "/" + svc.Metadata.Name
	requestedIP := svc.Metadata.Annotations["metallb.io/loadBalancerIPs"]
	var assignedIP string
	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		assignedIP = svc.Status.LoadBalancer.Ingress[0].IP
		if assignedIP == "" {
			assignedIP = svc.Status.LoadBalancer.Ingress[0].Hostname
		}
	}

	if svc.Spec.Type == "LoadBalancer" && assignedIP == "" {
		r.Fail("gw-vip-"+gw.Metadata.Name, layer, res, "MetalLB VIP allocation",
			fmt.Sprintf("Service type=LoadBalancer has NO external IP (requested=%q)", requestedIP),
			"Check MetalLB IPAddressPool / L2Advertisement, IP collision, and Service events")
		return ""
	}
	if requestedIP != "" && assignedIP != "" && requestedIP != assignedIP {
		r.Fail("gw-vip-match-"+gw.Metadata.Name, layer, res, "MetalLB VIP match",
			fmt.Sprintf("requested metallb.io/loadBalancerIPs=%s, but got %s", requestedIP, assignedIP),
			"Check MetalLB annotation and IPAddressPool range")
		return assignedIP
	}

	r.Pass("gw-svc-"+gw.Metadata.Name, layer, res, "Gateway Service & VIP",
		fmt.Sprintf("type=%s, VIP=%s, externalTrafficPolicy=%s, clusterIP=%s",
			svc.Spec.Type, assignedIP, svc.Spec.ExternalTrafficPolicy, svc.Spec.ClusterIP))
	return assignedIP
}

func loadAllRoutes(ctx context.Context, c *k8s.Client, ns string) []k8s.Route {
	kinds := []string{
		"httproutes.gateway.networking.k8s.io",
		"grpcroutes.gateway.networking.k8s.io",
		"tlsroutes.gateway.networking.k8s.io",
		"tcproutes.gateway.networking.k8s.io",
		"udproutes.gateway.networking.k8s.io",
	}
	var out []k8s.Route
	for _, res := range kinds {
		items, err := c.ListRoutes(ctx, res, ns)
		if err != nil {
			continue // optional experimental CRDs (TCPRoute/UDPRoute) may not be installed
		}
		out = append(out, items...)
	}
	return out
}

func filterRoutesForGateway(routes []k8s.Route, gwName, gwNS string) []k8s.Route {
	var out []k8s.Route
	for _, rt := range routes {
		for _, pr := range rt.Spec.ParentRefs {
			pNS := pr.Namespace
			if pNS == "" {
				pNS = rt.Metadata.Namespace
			}
			if pr.Name == gwName && pNS == gwNS {
				out = append(out, rt)
				break
			}
		}
	}
	return out
}

func checkRouteStatus(r *report.Report, layer string, rt k8s.Route, gw k8s.Gateway, listeners map[string]k8s.GatewayListener) {
	res := fmt.Sprintf("%s/%s/%s", rt.Kind, rt.Metadata.Namespace, rt.Metadata.Name)

	// Verify sectionName exists on Gateway
	for _, pr := range rt.Spec.ParentRefs {
		if pr.Name != gw.Metadata.Name {
			continue
		}
		if pr.SectionName != "" {
			if _, ok := listeners[pr.SectionName]; !ok {
				r.Fail("route-section-"+rt.Metadata.Name, layer, res, "Route parentRef sectionName",
					fmt.Sprintf("parentRef references listener %q which does not exist on Gateway %s", pr.SectionName, gw.Metadata.Name),
					"Fix parentRefs[].sectionName to match one of Gateway listeners[].name")
			}
		}
	}

	if len(rt.Status.Parents) == 0 {
		r.Warn("route-status-"+rt.Metadata.Name, layer, res, "Route status",
			"route has no status.parents entries yet", "Check istiod logs and parentRefs")
		return
	}

	var issues []string
	for _, p := range rt.Status.Parents {
		if p.ParentRef.Name != gw.Metadata.Name {
			continue
		}
		for _, cond := range p.Conditions {
			if (cond.Type == "Accepted" || cond.Type == "ResolvedRefs") && cond.Status != "True" {
				issues = append(issues, fmt.Sprintf("%s=%s (%s: %s)", cond.Type, cond.Status, cond.Reason, cond.Message))
			}
		}
	}

	if len(issues) > 0 {
		r.Fail("route-status-"+rt.Metadata.Name, layer, res, fmt.Sprintf("%s status", rt.Kind),
			strings.Join(issues, "; "),
			"Resolve missing ReferenceGrant, nonexistent backend Service, or hostname mismatch")
	} else {
		r.Pass("route-status-"+rt.Metadata.Name, layer, res, fmt.Sprintf("%s status", rt.Kind),
			fmt.Sprintf("Accepted=True, ResolvedRefs=True (hosts=%v)", rt.Spec.Hostnames))
	}
}

func warnAffinityWithWaypoint(r *report.Report, layer string, drs []k8s.DestinationRule, targetNS, svcName string) {
	for _, dr := range drs {
		if dr.Spec.TrafficPolicy == nil || dr.Spec.TrafficPolicy.LoadBalancer == nil ||
			dr.Spec.TrafficPolicy.LoadBalancer.ConsistentHash == nil ||
			dr.Spec.TrafficPolicy.LoadBalancer.ConsistentHash.HTTPCookie == nil {
			continue
		}
		suffix := "." + targetNS + ".svc.cluster.local"
		if svcName != "" {
			if dr.Spec.Host != svcName+suffix {
				continue
			}
		} else if !strings.HasSuffix(dr.Spec.Host, suffix) {
			continue
		}
		r.Warn("dr-affinity-waypoint-"+dr.Metadata.Name, layer, dr.Metadata.Namespace+"/"+dr.Metadata.Name,
			"sessionAffinity with ingress-use-waypoint",
			fmt.Sprintf("DestinationRule sets cookie sessionAffinity for %s, but %s/%s has %s=true (waypoint re-balances traffic and breaks cookie affinity)",
				dr.Spec.Host, targetNS, svcName, common.LabelIngressUseWP),
			"Remove istio.io/ingress-use-waypoint=true if gateway-level sticky sessions are required")
	}
}

func inspectGatewayEnvoyLogs(ctx context.Context, c *k8s.Client, r *report.Report, layer, ns, gwName string, pods []k8s.Pod, since string) {
	if len(pods) == 0 {
		return
	}
	var matches []string
	for _, p := range pods {
		logs, err := c.PodLogs(ctx, ns, p.Metadata.Name, "istio-proxy", since, 300)
		if err != nil {
			logs, err = c.PodLogs(ctx, ns, p.Metadata.Name, "", since, 300)
			if err != nil {
				continue
			}
		}
		for _, raw := range strings.Split(logs, "\n") {
			line := strings.TrimSpace(raw)
			if line != "" && gatewayLogErrPattern.MatchString(line) {
				matches = append(matches, fmt.Sprintf("[%s] %s", p.Metadata.Name, line))
			}
		}
	}
	if len(matches) == 0 {
		r.Pass("gw-envoy-logs-"+gwName, layer, ns+"/"+gwName, "Gateway Envoy logs",
			fmt.Sprintf("no 5xx/403/upstream_reset/TLS errors in last %s", since))
		return
	}
	if len(matches) > 15 {
		matches = matches[len(matches)-15:]
	}
	r.Warn("gw-envoy-logs-"+gwName, layer, ns+"/"+gwName, "Gateway Envoy error logs",
		fmt.Sprintf("found %d error/5xx/reset line(s) in last %s", len(matches), since),
		"Check response flags (UH=no healthy upstream, UF=connect failure/NetworkPolicy, NR=no route, 403=RBAC/OIDC)",
		matches...)
}

func runIngressProbes(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	gw k8s.Gateway,
	vip string,
	targets []backendTarget,
	backendPods map[string][]k8s.Pod,
	backendSvcIPs map[string]string,
	opts Options,
) {
	const layer = "Active Probes"

	// 1. Loopback check on first ready pod of each backend (ambient-check step 1)
	probedBackends := make(map[string]bool)
	for _, t := range targets {
		key := fmt.Sprintf("%s/%s:%d", t.Namespace, t.ServiceName, t.Port)
		if probedBackends[key] {
			continue
		}
		probedBackends[key] = true
		pods := backendPods[key]
		for _, p := range pods {
			if !p.IsReady() {
				continue
			}
			out, err := probe.LoopbackCheck(ctx, c, t.Namespace, p.Metadata.Name, t.Port)
			res := fmt.Sprintf("%s/%s:%d", t.Namespace, p.Metadata.Name, t.Port)
			if strings.Contains(out, "NO_TOOL") {
				r.Info("probe-loopback-"+p.Metadata.Name, layer, res, "Backend loopback check",
					"skipped: container has no curl/nc/ss (distroless)")
			} else if err != nil {
				r.Fail("probe-loopback-"+p.Metadata.Name, layer, res, "Backend loopback check (127.0.0.1)",
					fmt.Sprintf("application failed to answer on 127.0.0.1:%d: %s (%v)", t.Port, out, err),
					"Fix application listener first — loopback bypasses ambient redirection completely")
			} else {
				r.Pass("probe-loopback-"+p.Metadata.Name, layer, res, "Backend loopback check (127.0.0.1)",
					fmt.Sprintf("responded locally: %s", out))
			}
			break
		}
	}

	// 2. Temporary debug-toolbox pod outside mesh to test VIP & DNS
	sess, err := probe.Start(ctx, c, probe.Options{
		Namespace: gw.Metadata.Namespace,
		Image:     opts.ToolboxImage,
		InMesh:    false,
	})
	if err != nil {
		r.Fail("probe-pod-start", layer, gw.Metadata.Namespace, "Start debug-toolbox probe pod",
			fmt.Sprintf("could not start probe pod: %v", err),
			"Check image pull (--toolbox-image), ResourceQuota, and PodSecurity in "+gw.Metadata.Namespace)
		return
	}
	defer func() { _ = sess.Close(context.Background()) }()

	for _, l := range gw.Spec.Listeners {
		proto := strings.ToUpper(l.Protocol)
		if proto != "HTTP" && proto != "HTTPS" {
			continue
		}
		host := l.Hostname
		if host == "" || strings.HasPrefix(host, "*") {
			continue
		}

		// DNS check
		ips, err := sess.ResolveDNS(ctx, host)
		if err != nil || len(ips) == 0 {
			r.Warn("probe-dns-"+l.Name, layer, host, fmt.Sprintf("DNS lookup (%s)", host),
				fmt.Sprintf("DNS did not resolve %q from cluster (%v)", host, err),
				"Verify DNS A-record points to MetalLB VIP "+vip)
		} else if vip != "" && !containsStr(ips, vip) {
			r.Warn("probe-dns-"+l.Name, layer, host, fmt.Sprintf("DNS vs MetalLB VIP (%s)", host),
				fmt.Sprintf("DNS resolves %s -> %v, expected MetalLB VIP %s", host, ips, vip),
				"Update DNS A-record for "+host+" to "+vip)
		} else {
			r.Pass("probe-dns-"+l.Name, layer, host, fmt.Sprintf("DNS lookup (%s)", host),
				fmt.Sprintf("resolves to %v (matches VIP %s)", ips, vip))
		}

		if vip == "" {
			continue
		}

		scheme := strings.ToLower(proto)
		cr := sess.HTTPCheck(ctx, scheme, host, l.Port, vip, "")
		res := fmt.Sprintf("%s://%s:%d (VIP %s)", scheme, host, l.Port, vip)
		if cr.Err != nil || cr.StatusCode == "" || cr.StatusCode == "000" {
			r.Fail("probe-vip-"+l.Name, layer, res, fmt.Sprintf("HTTP/TLS probe via VIP (%s)", l.Name),
				fmt.Sprintf("request failed (code=%s, time=%s): %v", cr.StatusCode, cr.TimeTotal, cr.Err),
				"Check MetalLB L2/BGP announcement, externalTrafficPolicy: Local node placement, TLS cert, and gateway logs",
				cr.Verbose)
		} else if strings.HasPrefix(cr.StatusCode, "5") {
			r.Fail("probe-vip-"+l.Name, layer, res, fmt.Sprintf("HTTP/TLS probe via VIP (%s)", l.Name),
				fmt.Sprintf("gateway returned HTTP %s in %s", cr.StatusCode, cr.TimeTotal),
				"5xx from gateway points to backend/policy/ztunnel issue — check Gateway Envoy & ztunnel logs above",
				cr.Verbose)
		} else {
			r.Pass("probe-vip-"+l.Name, layer, res, fmt.Sprintf("HTTP/TLS probe via VIP (%s)", l.Name),
				fmt.Sprintf("HTTP %s in %s (remote=%s)", cr.StatusCode, cr.TimeTotal, cr.RemoteIP))
		}
	}

	// Bisection: TCP check to backend ClusterIPs
	for svcKey, cip := range backendSvcIPs {
		if cip == "" || cip == "None" {
			continue
		}
		_, portStr, ok := strings.Cut(svcKey, ":")
		if !ok {
			continue
		}
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		if port <= 0 {
			continue
		}
		out, err := sess.TCPCheck(ctx, cip, port)
		if err != nil {
			r.Info("probe-backend-tcp-"+svcKey, layer, svcKey, "Direct TCP probe from non-mesh toolbox",
				fmt.Sprintf("TCP %s:%d unreachable from non-mesh pod (%s) — expected if NetworkPolicy/STRICT mTLS isolates backend", cip, port, out))
		} else {
			r.Info("probe-backend-tcp-"+svcKey, layer, svcKey, "Direct TCP probe from non-mesh toolbox",
				fmt.Sprintf("TCP %s:%d open", cip, port))
		}
	}
}

func countReadyAddresses(ep k8s.Endpoints) int {
	n := 0
	for _, sub := range ep.Subsets {
		n += len(sub.Addresses)
	}
	return n
}

func mapToSelector(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

func pickZtunnelForNodes(pods []k8s.Pod, nodes map[string]bool) string {
	for _, p := range pods {
		if nodes[p.Spec.NodeName] && p.IsReady() {
			return p.Metadata.Name
		}
	}
	if len(pods) > 0 {
		return pods[0].Metadata.Name
	}
	return ""
}

func containsStr(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
