package ingress

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

var allocEventBracketIPs = regexp.MustCompile(`\[([^\]]+)\]`)

func checkGatewayService(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	layer string,
	gw k8s.Gateway,
	gwNS k8s.Namespace,
	warnEvents []k8s.Event,
) string {
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
	requestedIPs, ipSource := parseRequestedIPs(svc)
	requestedPool := requestedAddressPool(svc)

	var assignedIPs []string
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			assignedIPs = append(assignedIPs, ing.IP)
		} else if ing.Hostname != "" {
			assignedIPs = append(assignedIPs, ing.Hostname)
		}
	}
	assignedIP := ""
	if len(assignedIPs) > 0 {
		assignedIP = assignedIPs[0]
	}

	if svc.Spec.Type != "LoadBalancer" {
		r.Pass("gw-svc-"+gw.Metadata.Name, layer, res, "Gateway Service",
			fmt.Sprintf("type=%s, clusterIP=%s, externalTrafficPolicy=%s",
				svc.Spec.Type, svc.Spec.ClusterIP, svc.Spec.ExternalTrafficPolicy))
		return assignedIP
	}

	allocEvents := findMetalLBAllocationEvents(warnEvents, svc.Metadata.Name)
	noVIP := len(assignedIPs) == 0
	ipMismatch := len(requestedIPs) > 0 && len(assignedIPs) > 0 && !stringSetsEqual(requestedIPs, assignedIPs)

	if !noVIP && !ipMismatch {
		// VIP is assigned and matches requested IPs (if any).
		// Still check if a requested address-pool is invalid/misaligned when an AllocationFailed event is present.
		if len(allocEvents) > 0 && requestedPool != "" {
			if pools, poolErr := c.ListIPAddressPools(ctx); poolErr == nil {
				if diag := analyzeMetalLBPools(svc, gwNS, assignedIPs, "status.loadBalancer", requestedPool, pools); diag.Broken {
					ev := buildMetalLBEvidence(allocEvents, pools, nil)
					r.Fail("gw-vip-"+gw.Metadata.Name, layer, res, "MetalLB VIP allocation",
						diag.Message, diag.Suggestion, ev...)
					return assignedIP
				}
			}
		}

		r.Pass("gw-svc-"+gw.Metadata.Name, layer, res, "Gateway Service & VIP",
			fmt.Sprintf("type=%s, VIP=%s, externalTrafficPolicy=%s, clusterIP=%s",
				svc.Spec.Type, strings.Join(assignedIPs, ","), svc.Spec.ExternalTrafficPolicy, svc.Spec.ClusterIP))
		return assignedIP
	}

	// VIP is missing or does not match requested IPs — diagnose MetalLB allocation failure in detail.
	effectiveReqIPs := requestedIPs
	effectiveSource := ipSource
	if len(effectiveReqIPs) == 0 && len(allocEvents) > 0 {
		if evIPs := extractIPsFromAllocEvents(allocEvents); len(evIPs) > 0 {
			effectiveReqIPs = evIPs
			effectiveSource = "AllocationFailed event"
		}
	}

	pools, poolErr := c.ListIPAddressPools(ctx)
	ev := buildMetalLBEvidence(allocEvents, pools, poolErr)

	checkID := "gw-vip-" + gw.Metadata.Name
	title := "MetalLB VIP allocation"
	if ipMismatch {
		checkID = "gw-vip-match-" + gw.Metadata.Name
		title = "MetalLB VIP match"
	}

	// 1. Inspect IPAddressPool config directly (catches "not allowed in config" even after K8s events expire!)
	if poolErr == nil {
		diag := analyzeMetalLBPools(svc, gwNS, effectiveReqIPs, effectiveSource, requestedPool, pools)
		if diag.Broken {
			msg := diag.Message
			if ipMismatch {
				msg = fmt.Sprintf("requested %s=%s, but Service has %s — %s",
					effectiveSource, strings.Join(effectiveReqIPs, ","), strings.Join(assignedIPs, ","), diag.Message)
			}
			r.Fail(checkID, layer, res, title, msg, diag.Suggestion, ev...)
			return assignedIP
		}
	}

	// 2. Inspect MetalLB AllocationFailed warning events (works even without cluster-wide IPAddressPool RBAC)
	if len(allocEvents) > 0 {
		msg, sugg := classifyAllocationEvents(allocEvents, svc, effectiveReqIPs, assignedIPs, requestedPool, ipMismatch)
		r.Fail(checkID, layer, res, title, msg, sugg, ev...)
		return assignedIP
	}

	// 3. Fallback if no IPAddressPool issue was detected and no AllocationFailed event exists
	if ipMismatch {
		r.Fail(checkID, layer, res, title,
			fmt.Sprintf("requested %s=%s, but got %s",
				effectiveSource, strings.Join(effectiveReqIPs, ","), strings.Join(assignedIPs, ",")),
			"Check MetalLB annotation, IPAddressPool range/serviceAllocation, and metallb-controller logs",
			ev...)
		return assignedIP
	}

	r.Fail(checkID, layer, res, title,
		fmt.Sprintf("Service type=LoadBalancer has NO external IP (requested=%q, pool=%q)",
			strings.Join(effectiveReqIPs, ","), requestedPool),
		"Check MetalLB controller pods/logs, IPAddressPool / L2Advertisement, IP collision, and Service events",
		ev...)
	return ""
}

type poolDiagnosis struct {
	Broken     bool
	Code       string
	Message    string
	Suggestion string
}

func analyzeMetalLBPools(
	svc k8s.Service,
	ns k8s.Namespace,
	requestedIPs []string,
	ipSource string,
	requestedPool string,
	pools []k8s.IPAddressPool,
) poolDiagnosis {
	nsName := svc.Metadata.Namespace
	svcRes := nsName + "/" + svc.Metadata.Name

	if len(pools) == 0 {
		return poolDiagnosis{
			Broken:  true,
			Code:    "no_pools",
			Message: fmt.Sprintf("requested IP(s) %v not allowed in config: no MetalLB IPAddressPool resources exist in the cluster", requestedIPs),
			Suggestion: fmt.Sprintf("Create a MetalLB IPAddressPool (and L2Advertisement/BGPAdvertisement) covering %s",
				strings.Join(requestedIPs, ", ")),
		}
	}

	poolByName := make(map[string]k8s.IPAddressPool, len(pools))
	var poolNames []string
	for _, p := range pools {
		poolByName[p.Metadata.Name] = p
		poolNames = append(poolNames, p.Metadata.Name)
	}
	sort.Strings(poolNames)

	var namedPool *k8s.IPAddressPool
	if requestedPool != "" {
		p, ok := poolByName[requestedPool]
		if !ok {
			return poolDiagnosis{
				Broken:  true,
				Code:    "unknown_pool",
				Message: fmt.Sprintf("Service requests MetalLB address-pool %q, which does NOT exist in cluster (available pools: %v)", requestedPool, poolNames),
				Suggestion: fmt.Sprintf("Update metallb.io/address-pool to an existing IPAddressPool (%s) or create IPAddressPool %q",
					strings.Join(poolNames, ", "), requestedPool),
			}
		}
		namedPool = &p
	}

	// Explicit IP request(s)
	if len(requestedIPs) > 0 {
		for _, rawIP := range requestedIPs {
			addr, err := netip.ParseAddr(rawIP)
			if err != nil {
				return poolDiagnosis{
					Broken:     true,
					Code:       "invalid_ip",
					Message:    fmt.Sprintf("requested IP %q (%s) is not a valid IP address", rawIP, ipSource),
					Suggestion: fmt.Sprintf("Fix invalid IP address %q in %s on Service %s", rawIP, ipSource, svcRes),
				}
			}
			addr = addr.Unmap()

			// Case A: Service explicitly pinned an IPAddressPool via address-pool annotation
			if namedPool != nil {
				poolRef := poolDisplayName(*namedPool)
				if !poolContainsIP(*namedPool, addr) {
					otherHint := ""
					var otherPools []string
					for _, p := range pools {
						if p.Metadata.Name != namedPool.Metadata.Name && poolContainsIP(p, addr) {
							otherPools = append(otherPools, poolDisplayName(p))
						}
					}
					if len(otherPools) > 0 {
						otherHint = fmt.Sprintf(" (note: %s IS present in pool %s)", rawIP, strings.Join(otherPools, ", "))
					}
					return poolDiagnosis{
						Broken: true,
						Code:   "ip_not_in_requested_pool",
						Message: fmt.Sprintf("IP %q is not allowed in config: it is outside requested IPAddressPool %s (addresses=%v)%s",
							rawIP, poolRef, namedPool.Spec.Addresses, otherHint),
						Suggestion: fmt.Sprintf("Pick an IP from IPAddressPool %s (%v), add %s to it, or update metallb.io/address-pool",
							namedPool.Metadata.Name, namedPool.Spec.Addresses, rawIP),
					}
				}
				if namedPool.Spec.AvoidBuggyIPs && isBuggyIPv4(addr) {
					return poolDiagnosis{
						Broken:  true,
						Code:    "buggy_ip",
						Message: fmt.Sprintf("IP %q is not allowed in config: IPAddressPool %s has avoidBuggyIPs=true (forbids .0 and .255 addresses)", rawIP, poolRef),
						Suggestion: fmt.Sprintf("Choose a VIP not ending in .0 or .255, or set avoidBuggyIPs: false on IPAddressPool %s",
							namedPool.Metadata.Name),
					}
				}
				if ok, reason := poolAllowsService(*namedPool, ns, svc); !ok {
					return poolDiagnosis{
						Broken: true,
						Code:   "service_allocation_denied",
						Message: fmt.Sprintf("IP %q is not allowed in config: IPAddressPool %s covers %s, but spec.serviceAllocation denies %s (%s)",
							rawIP, poolRef, rawIP, svcRes, reason),
						Suggestion: fmt.Sprintf("Add namespace %q (or matching namespace/service labels) to IPAddressPool %s spec.serviceAllocation, or use an IP from a pool allowed for %s",
							nsName, namedPool.Metadata.Name, nsName),
					}
				}
				continue
			}

			// Case B: No explicit address-pool — search all pools containing this IP
			var containing []k8s.IPAddressPool
			for _, p := range pools {
				if poolContainsIP(p, addr) {
					containing = append(containing, p)
				}
			}

			if len(containing) == 0 {
				return poolDiagnosis{
					Broken:  true,
					Code:    "ip_not_in_any_pool",
					Message: fmt.Sprintf("IP %q is not allowed in config: it does not match any MetalLB IPAddressPool range in the cluster", rawIP),
					Suggestion: fmt.Sprintf("Change %s on %s to an IP from an existing MetalLB IPAddressPool, or add %s/32 (or its CIDR/range) to an IPAddressPool",
						ipSource, svcRes, rawIP),
				}
			}

			allowed := false
			var buggyPools []string
			var deniedReasons []string
			for _, p := range containing {
				if p.Spec.AvoidBuggyIPs && isBuggyIPv4(addr) {
					buggyPools = append(buggyPools, poolDisplayName(p))
					continue
				}
				if ok, reason := poolAllowsService(p, ns, svc); !ok {
					deniedReasons = append(deniedReasons, fmt.Sprintf("%s: %s", poolDisplayName(p), reason))
					continue
				}
				allowed = true
				break
			}

			if !allowed {
				if len(deniedReasons) > 0 {
					return poolDiagnosis{
						Broken: true,
						Code:   "service_allocation_denied",
						Message: fmt.Sprintf("IP %q is not allowed in config: matching IPAddressPool(s) deny %s via spec.serviceAllocation (%s)",
							rawIP, svcRes, strings.Join(deniedReasons, "; ")),
						Suggestion: fmt.Sprintf("Permit namespace %q / Service %s in the matching IPAddressPool spec.serviceAllocation, or pick a VIP from a pool allowed for %s",
							nsName, svc.Metadata.Name, nsName),
					}
				}
				if len(buggyPools) > 0 {
					return poolDiagnosis{
						Broken:  true,
						Code:    "buggy_ip",
						Message: fmt.Sprintf("IP %q is not allowed in config: matching IPAddressPool(s) %v have avoidBuggyIPs=true (forbids .0/.255)", rawIP, buggyPools),
						Suggestion: fmt.Sprintf("Choose a VIP not ending in .0 or .255, or set avoidBuggyIPs: false on %s",
							strings.Join(buggyPools, ", ")),
					}
				}
			}
		}
		return poolDiagnosis{Broken: false}
	}

	// Auto-assign (no explicit IP requested)
	if namedPool != nil {
		if ok, reason := poolAllowsService(*namedPool, ns, svc); !ok {
			return poolDiagnosis{
				Broken: true,
				Code:   "service_allocation_denied",
				Message: fmt.Sprintf("requested IPAddressPool %s denies %s via spec.serviceAllocation (%s)",
					poolDisplayName(*namedPool), svcRes, reason),
				Suggestion: fmt.Sprintf("Permit namespace %q / Service %s in IPAddressPool %s spec.serviceAllocation, or use another address-pool",
					nsName, svc.Metadata.Name, namedPool.Metadata.Name),
			}
		}
		return poolDiagnosis{Broken: false}
	}

	anyAutoAllowed := false
	for _, p := range pools {
		if p.Spec.AutoAssign != nil && !*p.Spec.AutoAssign {
			continue
		}
		if len(p.Spec.Addresses) == 0 {
			continue
		}
		if ok, _ := poolAllowsService(p, ns, svc); ok {
			anyAutoAllowed = true
			break
		}
	}
	if !anyAutoAllowed {
		return poolDiagnosis{
			Broken:  true,
			Code:    "no_autoassign_pool",
			Message: fmt.Sprintf("Service requests auto-assigned LoadBalancer IP, but no MetalLB IPAddressPool with autoAssign=true permits %s", svcRes),
			Suggestion: fmt.Sprintf("Request an explicit VIP via metallb.io/loadBalancerIPs, enable autoAssign on an IPAddressPool, or allow namespace %q in spec.serviceAllocation",
				nsName),
		}
	}
	return poolDiagnosis{Broken: false}
}

func classifyAllocationEvents(
	events []k8s.Event,
	svc k8s.Service,
	requestedIPs []string,
	assignedIPs []string,
	requestedPool string,
	ipMismatch bool,
) (string, string) {
	ns := svc.Metadata.Namespace
	svcRes := ns + "/" + svc.Metadata.Name
	reqStr := strings.Join(requestedIPs, ",")

	combined := make([]string, 0, len(events))
	for _, ev := range events {
		combined = append(combined, ev.Message)
	}
	joined := strings.Join(combined, " | ")
	low := strings.ToLower(joined)

	prefix := ""
	if ipMismatch {
		prefix = fmt.Sprintf("requested=%s vs assigned=%s; ", reqStr, strings.Join(assignedIPs, ","))
	}

	switch {
	case strings.Contains(low, "not allowed in config"):
		return fmt.Sprintf("%sMetalLB AllocationFailed: IP [%s] is not allowed in MetalLB config (outside IPAddressPool ranges or restricted by spec.serviceAllocation)",
				prefix, reqStr),
			fmt.Sprintf("Verify IP %s belongs to a MetalLB IPAddressPool spec.addresses range and that spec.serviceAllocation permits %s (inspect: kubectl get ipaddresspools.metallb.io -A -o yaml)",
				reqStr, svcRes)

	case strings.Contains(low, "already allocated"):
		return fmt.Sprintf("%sMetalLB AllocationFailed: requested IP [%s] is already allocated to another Service",
				prefix, reqStr),
			"Assign a unique unused VIP in metallb.io/loadBalancerIPs, or configure metallb.io/allow-shared-ip if sharing the IP across distinct ports is intentional"

	case strings.Contains(low, "no available ips"):
		return fmt.Sprintf("%sMetalLB AllocationFailed: IPAddressPool has no available IPs left", prefix),
			"Expand MetalLB IPAddressPool spec.addresses or release unused LoadBalancer Services"

	case strings.Contains(low, "unknown pool"):
		return fmt.Sprintf("%sMetalLB AllocationFailed: requested address-pool %q does not exist in MetalLB config",
				prefix, requestedPool),
			"Fix metallb.io/address-pool annotation to an existing IPAddressPool name or create the pool"

	default:
		return fmt.Sprintf("%sMetalLB AllocationFailed for %s: %s", prefix, svcRes, events[len(events)-1].Message),
			"Inspect MetalLB IPAddressPool / L2Advertisement config and metallb-controller logs"
	}
}

func parseRequestedIPs(svc k8s.Service) ([]string, string) {
	if raw := strings.TrimSpace(svc.Metadata.Annotations["metallb.io/loadBalancerIPs"]); raw != "" {
		return splitTrimCSV(raw), "metallb.io/loadBalancerIPs"
	}
	if raw := strings.TrimSpace(svc.Metadata.Annotations["metallb.universe.tf/loadBalancerIPs"]); raw != "" {
		return splitTrimCSV(raw), "metallb.universe.tf/loadBalancerIPs"
	}
	if raw := strings.TrimSpace(svc.Spec.LoadBalancerIP); raw != "" {
		return []string{raw}, "spec.loadBalancerIP"
	}
	return nil, ""
}

func requestedAddressPool(svc k8s.Service) string {
	if p := strings.TrimSpace(svc.Metadata.Annotations["metallb.io/address-pool"]); p != "" {
		return p
	}
	return strings.TrimSpace(svc.Metadata.Annotations["metallb.universe.tf/address-pool"])
}

func findMetalLBAllocationEvents(warnEvents []k8s.Event, svcName string) []k8s.Event {
	var out []k8s.Event
	for _, ev := range warnEvents {
		if ev.InvolvedObject.Name != svcName {
			continue
		}
		if ev.InvolvedObject.Kind != "" && !strings.EqualFold(ev.InvolvedObject.Kind, "Service") {
			continue
		}
		lowMsg := strings.ToLower(ev.Message)
		if strings.EqualFold(ev.Reason, "AllocationFailed") ||
			strings.Contains(lowMsg, "failed to allocate ip") ||
			strings.Contains(lowMsg, "not allowed in config") ||
			strings.Contains(lowMsg, "is already allocated") ||
			strings.Contains(lowMsg, "no available ips") ||
			strings.Contains(lowMsg, "unknown pool") {
			out = append(out, ev)
		}
	}
	return out
}

func extractIPsFromAllocEvents(events []k8s.Event) []string {
	seen := make(map[string]bool)
	var out []string
	for _, ev := range events {
		for _, m := range allocEventBracketIPs.FindAllStringSubmatch(ev.Message, -1) {
			if len(m) < 2 {
				continue
			}
			for _, part := range strings.FieldsFunc(m[1], func(r rune) bool {
				return r == ',' || r == ' ' || r == '"' || r == '\''
			}) {
				if addr, err := netip.ParseAddr(part); err == nil {
					s := addr.Unmap().String()
					if !seen[s] {
						seen[s] = true
						out = append(out, s)
					}
				}
			}
		}
	}
	return out
}

func buildMetalLBEvidence(events []k8s.Event, pools []k8s.IPAddressPool, poolErr error) []string {
	var ev []string
	for _, e := range events {
		ev = append(ev, fmt.Sprintf("Event %s/%s: %s (x%d) - %s",
			e.InvolvedObject.Kind, e.InvolvedObject.Name, e.Reason, e.Count, e.Message))
	}
	if poolErr != nil {
		ev = append(ev, fmt.Sprintf("IPAddressPool lookup unavailable: %v", poolErr))
		return ev
	}
	if len(pools) == 0 {
		ev = append(ev, "Configured IPAddressPools: none (0 pools in cluster)")
		return ev
	}
	for _, p := range pools {
		line := fmt.Sprintf("IPAddressPool %s: addresses=%v", poolDisplayName(p), p.Spec.Addresses)
		if p.Spec.AutoAssign != nil && !*p.Spec.AutoAssign {
			line += ", autoAssign=false"
		}
		if p.Spec.AvoidBuggyIPs {
			line += ", avoidBuggyIPs=true"
		}
		if p.Spec.ServiceAllocation != nil {
			sa := p.Spec.ServiceAllocation
			var parts []string
			if len(sa.Namespaces) > 0 {
				parts = append(parts, fmt.Sprintf("namespaces=%v", sa.Namespaces))
			}
			if len(sa.NamespaceSelectors) > 0 {
				parts = append(parts, fmt.Sprintf("namespaceSelectors=%d", len(sa.NamespaceSelectors)))
			}
			if len(sa.ServiceSelectors) > 0 {
				parts = append(parts, fmt.Sprintf("serviceSelectors=%d", len(sa.ServiceSelectors)))
			}
			if len(parts) > 0 {
				line += " (serviceAllocation: " + strings.Join(parts, ", ") + ")"
			}
		}
		ev = append(ev, line)
	}
	return ev
}

func poolDisplayName(p k8s.IPAddressPool) string {
	if p.Metadata.Namespace != "" {
		return p.Metadata.Namespace + "/" + p.Metadata.Name
	}
	return p.Metadata.Name
}

func poolContainsIP(pool k8s.IPAddressPool, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, raw := range pool.Spec.Addresses {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if pfx, err := netip.ParsePrefix(entry); err == nil {
				if pfx.Contains(addr) {
					return true
				}
			}
			continue
		}
		if strings.Contains(entry, "-") {
			left, right, ok := strings.Cut(entry, "-")
			if !ok {
				continue
			}
			start, err1 := netip.ParseAddr(strings.TrimSpace(left))
			end, err2 := netip.ParseAddr(strings.TrimSpace(right))
			if err1 != nil || err2 != nil {
				continue
			}
			start, end = start.Unmap(), end.Unmap()
			if start.BitLen() == addr.BitLen() && end.BitLen() == addr.BitLen() &&
				!addr.Less(start) && !end.Less(addr) {
				return true
			}
			continue
		}
		if single, err := netip.ParseAddr(entry); err == nil {
			if single.Unmap() == addr {
				return true
			}
		}
	}
	return false
}

func isBuggyIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[3] == 0 || b[3] == 255
}

func poolAllowsService(pool k8s.IPAddressPool, ns k8s.Namespace, svc k8s.Service) (bool, string) {
	sa := pool.Spec.ServiceAllocation
	if sa == nil {
		return true, ""
	}

	// Namespace match: empty namespaces AND empty namespaceSelectors means all namespaces allowed.
	if len(sa.Namespaces) > 0 || len(sa.NamespaceSelectors) > 0 {
		nsMatched := false
		for _, allowedNS := range sa.Namespaces {
			if allowedNS == svc.Metadata.Namespace {
				nsMatched = true
				break
			}
		}
		if !nsMatched && len(sa.NamespaceSelectors) > 0 {
			nsLabels := make(map[string]string, len(ns.Metadata.Labels)+1)
			for k, v := range ns.Metadata.Labels {
				nsLabels[k] = v
			}
			if _, ok := nsLabels["kubernetes.io/metadata.name"]; !ok && svc.Metadata.Namespace != "" {
				nsLabels["kubernetes.io/metadata.name"] = svc.Metadata.Namespace
			}
			for _, sel := range sa.NamespaceSelectors {
				if matchesLabelSelector(sel, nsLabels) {
					nsMatched = true
					break
				}
			}
		}
		if !nsMatched {
			if len(sa.Namespaces) > 0 && len(sa.NamespaceSelectors) == 0 {
				return false, fmt.Sprintf("namespace %q not in allowed namespaces %v", svc.Metadata.Namespace, sa.Namespaces)
			}
			return false, fmt.Sprintf("namespace %q does not match allowed namespaces %v or namespaceSelectors", svc.Metadata.Namespace, sa.Namespaces)
		}
	}

	// Service selector match: empty serviceSelectors means all services allowed.
	if len(sa.ServiceSelectors) > 0 {
		svcMatched := false
		for _, sel := range sa.ServiceSelectors {
			if matchesLabelSelector(sel, svc.Metadata.Labels) {
				svcMatched = true
				break
			}
		}
		if !svcMatched {
			return false, fmt.Sprintf("Service %s labels %v do not match serviceSelectors", svc.Metadata.Name, svc.Metadata.Labels)
		}
	}

	return true, ""
}

func matchesLabelSelector(sel k8s.LabelSelector, labels map[string]string) bool {
	for k, v := range sel.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, expr := range sel.MatchExpressions {
		val, exists := labels[expr.Key]
		switch expr.Operator {
		case "In":
			if !exists || !containsStr(expr.Values, val) {
				return false
			}
		case "NotIn":
			if exists && containsStr(expr.Values, val) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func splitTrimCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}
