package policies

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/awbait/debug-toolbox/internal/checks/common"
	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

// Run executes `mesh-debug policies` for a pod/workload, mapping outbound & inbound connections,
// evaluating NetworkPolicy, ztunnel, PeerAuthentication, and AuthorizationPolicy hop-by-hop,
// and optionally running live packet capture and generating console-charts/policies values.yaml.
func Run(ctx context.Context, c *k8s.Client, opts Options) *report.Report {
	if opts.Since == "" {
		opts.Since = "15m"
	}
	r := report.New(opts.Version, "policies", opts.Namespace, opts.Target, opts.Capture > 0)

	// 1. Control plane & ztunnel discovery
	ztunnelNS, ztunnelPods := common.CheckControlPlane(ctx, c, r, false)
	nsInfo, err := common.CheckNamespaceMesh(ctx, c, r, "Target & Identity", opts.Namespace, false)
	if err != nil {
		r.Finalize(c.Runner.History(), opts.Verbose)
		return r
	}

	// 2. Resolve target pod & inspect its identity
	pod, err := resolveTargetPod(ctx, c, opts.Namespace, opts.Target)
	if err != nil {
		r.Fail("pol-target", "Target & Identity", opts.Namespace+"/"+opts.Target, "Resolve target pod",
			err.Error(), "Specify a pod name or workload ref (e.g. deploy/<name>, sts/<name>, gw/<name>) in "+opts.Namespace)
		r.Finalize(c.Runner.History(), opts.Verbose)
		return r
	}

	target := inspectTargetInfo(ctx, c, pod, nsInfo.Namespace, ztunnelNS, ztunnelPods)
	r.Target = pod.Metadata.Name
	r.Mode = target.WorkloadKind
	r.Metadata["workload_kind"] = target.WorkloadKind
	r.Metadata["service_account"] = target.ServiceAccount
	r.Metadata["principal"] = target.Principal
	r.Metadata["pod_ip"] = pod.Status.PodIP
	r.Metadata["node"] = pod.Spec.NodeName
	if target.ZtunnelPod != "" {
		r.Metadata["ztunnel_pod"] = target.ZtunnelNS + "/" + target.ZtunnelPod
	}

	idDetails := []string{
		fmt.Sprintf("Pod IP: %s | Node: %s | OVN Subnet: %s", pod.Status.PodIP, pod.Spec.NodeName, firstNonEmpty(target.OVNSubnet, "<unknown>")),
		fmt.Sprintf("ServiceAccount: %s (principal: %s)", target.ServiceAccount, target.Principal),
		fmt.Sprintf("Ambient Mesh: enabled=%v, redirection=%v | Node ztunnel: %s/%s",
			target.Ambient, target.Redirected, firstNonEmpty(target.ZtunnelNS, "ztunnel"), firstNonEmpty(target.ZtunnelPod, "<none>")),
		fmt.Sprintf("Stable selector: %v (owner: %s/%s)", target.StableSelector, firstNonEmpty(target.OwnerKind, "Pod"), firstNonEmpty(target.OwnerName, pod.Metadata.Name)),
	}
	if target.HasAPIRBAC {
		idDetails = append(idDetails, "RBAC: ServiceAccount has RoleBinding/ClusterRoleBinding -> operator accessing kube-apiserver")
	}
	r.Pass("pol-identity", "Target & Identity", opts.Namespace+"/"+pod.Metadata.Name,
		fmt.Sprintf("Target workload (%s)", target.WorkloadKind),
		fmt.Sprintf("SA=%s, IP=%s, node=%s, ztunnel=%s", target.ServiceAccount, pod.Status.PodIP, pod.Spec.NodeName, firstNonEmpty(target.ZtunnelPod, "none")),
		idDetails...)

	if target.Ambient && !target.Redirected && pod.Status.Phase == "Running" {
		r.Fail("pol-redirection", "Target & Identity", opts.Namespace+"/"+pod.Metadata.Name, "Ambient redirection",
			"namespace is in ambient mesh, but pod lacks ambient.istio.io/redirection=enabled",
			"Check istio-cni-node logs on node "+pod.Spec.NodeName+" or restart the pod")
	}

	// 3. Build cluster topology index
	idx := buildClusterIndex(ctx, c, ztunnelPods)
	idx.Namespaces[nsInfo.Namespace.Metadata.Name] = nsInfo.Namespace

	// 4. Collect flows from all enabled sources (deduplicated by Flow.Key())
	flowMap := make(map[string]*Flow)
	addFlow := func(f Flow) {
		k := f.Key()
		if existing, ok := flowMap[k]; ok {
			existing.Sources = mergeUniqueStrs(existing.Sources, f.Sources)
			existing.ObservedLogs = mergeUniqueStrs(existing.ObservedLogs, f.ObservedLogs)
			existing.ObservedErrors = mergeUniqueStrs(existing.ObservedErrors, f.ObservedErrors)
			if existing.Peer.ServiceAccount == "" && f.Peer.ServiceAccount != "" {
				existing.Peer.ServiceAccount = f.Peer.ServiceAccount
				existing.Peer.Principal = f.Peer.Principal
			}
			return
		}
		copyF := f
		flowMap[k] = &copyF
	}

	// 4a. Simulated --to targets
	for _, rawTo := range opts.To {
		for _, part := range strings.Split(rawTo, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ep, err := idx.resolveSimulatedTarget(part, opts.Namespace)
			if err != nil {
				r.Warn("pol-to-parse", "Discovery", part, "Parse --to target", err.Error(), "Use kube-apiserver, ns/svc:port, or ip:port")
				continue
			}
			addFlow(Flow{
				Direction: "outbound",
				Peer:      ep,
				Sources:   []string{"simulated"},
			})
		}
	}

	// 4b. Static flows (operator RBAC, webhooks, ingress routes, waypoint ServiceEntries)
	for _, f := range discoverStaticFlows(ctx, c, target, idx) {
		addFlow(f)
	}

	// 4c. ztunnel access logs on pod's node (read-only)
	ztunnelLogsByPod := make(map[string]string)
	if target.ZtunnelNS != "" && target.ZtunnelPod != "" && pod.Status.PodIP != "" {
		if logs, err := c.PodLogs(ctx, target.ZtunnelNS, target.ZtunnelPod, "", opts.Since, 500); err == nil {
			ztunnelLogsByPod[target.ZtunnelPod] = logs
			for _, entry := range ParseZtunnelAccessLogs(logs, pod.Status.PodIP) {
				var peer Endpoint
				localPort := 0
				if entry.Direction == "outbound" {
					peer = idx.resolveIPPort(entry.DstIP, entry.DstPort, "TCP")
					if entry.DstService != "" && peer.Hostname == "" {
						peer.Hostname = entry.DstService
					}
				} else {
					peer = idx.resolveIPPort(entry.SrcIP, entry.DstPort, "TCP")
					localPort = entry.DstPort
					if entry.SrcIdentity != "" && peer.Principal == "" {
						peer.Principal = entry.SrcIdentity
						if saNS, saName := parseSPIFFEPrincipal(entry.SrcIdentity); saName != "" {
							if peer.Namespace == "" {
								peer.Namespace = saNS
							}
							peer.ServiceAccount = saName
						}
					}
				}
				f := Flow{
					Direction:    entry.Direction,
					Peer:         peer,
					LocalPort:    localPort,
					Sources:      []string{"ztunnel-logs"},
					ObservedLogs: []string{fmt.Sprintf("[%s@%s] %s", target.ZtunnelPod, pod.Spec.NodeName, entry.RawLine)},
				}
				if entry.ErrorText != "" {
					f.ObservedErrors = []string{entry.ErrorText}
				}
				addFlow(f)
			}
		}
	}

	// 4d. Active packet capture (--capture <duration>)
	if opts.Capture > 0 {
		pkts, _, capErr := RunPacketCapture(ctx, c, pod, opts.Capture, opts.CaptureMode, opts.CaptureNS, opts.ToolboxImage)
		if capErr != nil {
			r.Fail("pol-capture", "Packet Capture", opts.Namespace+"/"+pod.Metadata.Name,
				fmt.Sprintf("Live packet capture (%s)", firstNonEmpty(opts.CaptureMode, "node")),
				capErr.Error(),
				"Verify permissions to run node-capture pod in --capture-ns (default: default) with privileged+hostPID, or try --capture-mode ephemeral in a privileged namespace")
		} else {
			r.Pass("pol-capture", "Packet Capture", opts.Namespace+"/"+pod.Metadata.Name,
				fmt.Sprintf("Live packet capture (%s, %s)", firstNonEmpty(opts.CaptureMode, "node"), opts.Capture),
				fmt.Sprintf("captured %d unique connection attempt(s) (TCP SYN + UDP)", len(pkts)))
			for _, pkt := range pkts {
				peer := idx.resolveIPPort(pkt.PeerIP, pkt.Port, pkt.Protocol)
				f := Flow{
					Direction: pkt.Direction,
					Peer:      peer,
					Sources:   []string{"tcpdump"},
				}
				if pkt.Direction == "inbound" {
					f.LocalPort = pkt.Port
				}
				addFlow(f)
			}
		}
	}

	// Sort flows deterministically: outbound first, then inbound
	flows := make([]Flow, 0, len(flowMap))
	for _, f := range flowMap {
		flows = append(flows, *f)
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Direction != flows[j].Direction {
			return flows[i].Direction == "outbound"
		}
		return flows[i].Key() < flows[j].Key()
	})

	if len(flows) == 0 {
		r.Info("pol-no-flows", "Traffic Map & Policy Verdict", opts.Namespace+"/"+pod.Metadata.Name,
			"Discovered connections",
			fmt.Sprintf("no active or static flows discovered in last %s", opts.Since),
			"Use --to <kube-apiserver|ns/svc:port|ip:port> to simulate a path, or --capture 30s to capture live TCP SYN/UDP attempts")
	}

	// 5. Evaluate every flow hop-by-hop with cached per-namespace NP / AP / PA lookups
	cache := newPolicyCache(ctx, c)
	for i := range flows {
		evaluateFlow(ctx, c, target, &flows[i], idx, cache, ztunnelLogsByPod, opts.Since)
		emitFlowReportCheck(r, target, flows[i], i)
	}

	// 6. Optional console-charts/policies values.yaml generation
	if opts.EmitPolicies {
		yamlDraft := EmitPoliciesValues(target, flows, opts.PolicyName)
		r.Metadata["policies_values_yaml"] = yamlDraft
		r.Info("pol-emit-values", "Generated Policies Values", opts.Namespace+"/"+pod.Metadata.Name,
			"values.yaml draft for console-charts/policies",
			"generated values.yaml based on discovered/simulated flows (use --format yaml to print raw YAML)",
			strings.Split(strings.TrimRight(yamlDraft, "\n"), "\n")...)
	}

	r.Finalize(c.Runner.History(), opts.Verbose)
	return r
}

// --- Policy lookup cache ---

type policyCache struct {
	ctx    context.Context
	c      *k8s.Client
	nps    map[string][]k8s.NetworkPolicy
	aps    map[string][]k8s.AuthorizationPolicy
	pas    map[string][]k8s.PeerAuthentication
	meshPA []k8s.PeerAuthentication
	hasMPA bool
}

func newPolicyCache(ctx context.Context, c *k8s.Client) *policyCache {
	return &policyCache{
		ctx: ctx,
		c:   c,
		nps: make(map[string][]k8s.NetworkPolicy),
		aps: make(map[string][]k8s.AuthorizationPolicy),
		pas: make(map[string][]k8s.PeerAuthentication),
	}
}

func (pc *policyCache) getNPs(ns string) []k8s.NetworkPolicy {
	if v, ok := pc.nps[ns]; ok {
		return v
	}
	v, _ := pc.c.ListNetworkPolicies(pc.ctx, ns)
	pc.nps[ns] = v
	return v
}

func (pc *policyCache) getAPs(ns string) []k8s.AuthorizationPolicy {
	if v, ok := pc.aps[ns]; ok {
		return v
	}
	v, _ := pc.c.ListAuthorizationPolicies(pc.ctx, ns)
	pc.aps[ns] = v
	return v
}

func (pc *policyCache) getPAs(ns string) ([]k8s.PeerAuthentication, []k8s.PeerAuthentication) {
	if !pc.hasMPA {
		pc.meshPA, _ = pc.c.ListPeerAuthentications(pc.ctx, "istio-system")
		pc.hasMPA = true
	}
	v, ok := pc.pas[ns]
	if !ok {
		v, _ = pc.c.ListPeerAuthentications(pc.ctx, ns)
		pc.pas[ns] = v
	}
	return v, pc.meshPA
}

// --- Hop-by-hop evaluation ---

func evaluateFlow(
	ctx context.Context,
	c *k8s.Client,
	target TargetInfo,
	f *Flow,
	idx *ClusterIndex,
	pc *policyCache,
	ztunnelLogs map[string]string,
	since string,
) {
	srcNS := target.Namespace.Metadata.Name
	targetAsEP := Endpoint{
		Kind:           PeerPod,
		Namespace:      srcNS,
		PodName:        target.Pod.Metadata.Name,
		IP:             target.Pod.Status.PodIP,
		NodeName:       target.Pod.Spec.NodeName,
		ZtunnelPod:     target.ZtunnelPod,
		ServiceAccount: target.ServiceAccount,
		Principal:      target.Principal,
		Labels:         target.Pod.Metadata.Labels,
		StableSelector: target.StableSelector,
		Ambient:        target.Ambient,
	}

	if f.Direction == "outbound" {
		// Hop 1: Source Egress NetworkPolicy
		f.Hops = append(f.Hops, evalEgressNP(target.Pod, srcNS, f.Peer, pc.getNPs(srcNS), idx.Namespaces))

		// Hop 2: Source ztunnel @ srcNode
		f.Hops = append(f.Hops, evalZtunnelHop("Src ztunnel", target.Ambient, target.ZtunnelNS, target.ZtunnelPod, target.Pod.Spec.NodeName, f.ObservedLogs, f.ObservedErrors))

		// Hop 3-5: Destination side (only for in-cluster pods/services)
		if f.Peer.Kind == PeerService || f.Peer.Kind == PeerPod {
			dstNS := f.Peer.Namespace
			dstPods := podsForEndpoint(f.Peer, idx)

			// Hop 3: Destination Ingress NetworkPolicy
			f.Hops = append(f.Hops, evalIngressNP(dstPods, f.Peer.StableSelector, dstNS, f.Peer.ServiceName, targetAsEP, f.Peer.Port, f.Peer.Protocol, f.Peer.Ambient, pc.getNPs(dstNS), idx.Namespaces))

			// Hop 4: Destination PeerAuthentication + ztunnel @ dstNode
			dstNSPAs, meshPAs := pc.getPAs(dstNS)
			f.Hops = append(f.Hops, evalPeerAuthHop(target.Ambient, f.Peer.Ambient, dstPods, dstNS, f.Peer.Port, dstNSPAs, meshPAs))

			if f.Peer.Ambient && f.Peer.ZtunnelPod != "" && f.Peer.ZtunnelPod != target.ZtunnelPod && target.ZtunnelNS != "" {
				dstLogs, loaded := ztunnelLogs[f.Peer.ZtunnelPod]
				if !loaded {
					dstLogs, _ = c.PodLogs(ctx, target.ZtunnelNS, f.Peer.ZtunnelPod, "", since, 500)
					ztunnelLogs[f.Peer.ZtunnelPod] = dstLogs
				}
				dstErrs := findZtunnelErrorsBetween(dstLogs, target.Pod.Status.PodIP, f.Peer.effectiveIPs())
				f.Hops = append(f.Hops, evalZtunnelHop("Dst ztunnel", f.Peer.Ambient, target.ZtunnelNS, f.Peer.ZtunnelPod, f.Peer.NodeName, nil, dstErrs))
			}

			// Hop 5: Destination AuthorizationPolicy
			if f.Peer.Ambient {
				f.Hops = append(f.Hops, evalAuthzHop(targetAsEP, dstPods, f.Peer.StableSelector, dstNS, f.Peer.ServiceName, f.Peer.Port, pc.getAPs(dstNS)))
			}
		} else if f.Peer.Kind == PeerExternal && target.Ambient {
			f.Hops = append(f.Hops, HopResult{
				Hop:     "Egress path",
				Status:  report.StatusInfo,
				Summary: "external destination outside mesh (verify egress-gateway ServiceEntry/waypoint/VEG if fixed VIP is required)",
			})
		}
	} else {
		// Inbound: Peer -> Target Pod
		inPort := f.LocalPort
		if inPort == 0 {
			inPort = f.Peer.Port
		}
		if f.Peer.Kind == PeerService || f.Peer.Kind == PeerPod {
			srcPods := podsForEndpoint(f.Peer, idx)
			if len(srcPods) > 0 {
				targetForDst := targetAsEP
				targetForDst.Port = inPort
				targetForDst.Protocol = f.Peer.Protocol
				f.Hops = append(f.Hops, evalEgressNP(srcPods[0], f.Peer.Namespace, targetForDst, pc.getNPs(f.Peer.Namespace), idx.Namespaces))
			}
		}

		// Target Ingress NetworkPolicy
		f.Hops = append(f.Hops, evalIngressNP([]k8s.Pod{target.Pod}, target.StableSelector, srcNS, target.Pod.Metadata.Name, f.Peer, inPort, f.Peer.Protocol, target.Ambient, pc.getNPs(srcNS), idx.Namespaces))

		// Target PeerAuthentication + ztunnel
		dstNSPAs, meshPAs := pc.getPAs(srcNS)
		f.Hops = append(f.Hops, evalPeerAuthHop(f.Peer.Ambient, target.Ambient, []k8s.Pod{target.Pod}, srcNS, inPort, dstNSPAs, meshPAs))
		f.Hops = append(f.Hops, evalZtunnelHop("Dst ztunnel", target.Ambient, target.ZtunnelNS, target.ZtunnelPod, target.Pod.Spec.NodeName, f.ObservedLogs, f.ObservedErrors))

		// Target AuthorizationPolicy
		if target.Ambient {
			f.Hops = append(f.Hops, evalAuthzHop(f.Peer, []k8s.Pod{target.Pod}, target.StableSelector, srcNS, target.Pod.Metadata.Name, inPort, pc.getAPs(srcNS)))
		}
	}

	// Overall flow verdict = worst hop status
	f.Verdict = report.StatusPass
	for _, h := range f.Hops {
		if h.Status == report.StatusFail {
			f.Verdict = report.StatusFail
			break
		}
		if h.Status == report.StatusWarn && f.Verdict != report.StatusFail {
			f.Verdict = report.StatusWarn
		}
	}
}

func emitFlowReportCheck(r *report.Report, target TargetInfo, f Flow, idx int) {
	arrow := "->"
	dirLabel := "OUT"
	if f.Direction == "inbound" {
		arrow = "<-"
		dirLabel = "IN"
	}

	title := fmt.Sprintf("[%s] %s %s %s", dirLabel, target.Pod.Metadata.Name, arrow, f.Peer.DisplayName())
	checkID := fmt.Sprintf("pol-flow-%s-%d", f.Direction, idx)
	res := f.Peer.DisplayName()

	var lines []string
	lines = append(lines, fmt.Sprintf("Sources: %s", strings.Join(f.Sources, ", ")))
	if f.Peer.NodeName != "" || f.Peer.ServiceAccount != "" {
		lines = append(lines, fmt.Sprintf("Peer runtime: pod=%s, node=%s, ztunnel=%s, SA=%s, ambient=%v",
			firstNonEmpty(f.Peer.PodName, "-"),
			firstNonEmpty(f.Peer.NodeName, "-"),
			firstNonEmpty(f.Peer.ZtunnelPod, "-"),
			firstNonEmpty(f.Peer.ServiceAccount, "-"),
			f.Peer.Ambient))
	}
	var suggestions []string
	var failSummary []string
	for i, h := range f.Hops {
		lines = append(lines, fmt.Sprintf("%d. [%s] %s: %s", i+1, h.Status, h.Hop, h.Summary))
		for _, ev := range h.Evidence {
			lines = append(lines, "      "+ev)
		}
		if h.Status == report.StatusFail {
			failSummary = append(failSummary, fmt.Sprintf("%s (%s)", h.Hop, h.Summary))
		}
		if h.Suggestion != "" && (h.Status == report.StatusFail || h.Status == report.StatusWarn) {
			suggestions = append(suggestions, h.Suggestion)
		}
	}

	switch f.Verdict {
	case report.StatusFail:
		r.Fail(checkID, "Traffic Map & Policy Verdict", res, title,
			"BLOCKED at "+strings.Join(failSummary, "; "),
			strings.Join(mergeUniqueStrs(suggestions, nil), "; "),
			lines...)
	case report.StatusWarn:
		r.Warn(checkID, "Traffic Map & Policy Verdict", res, title,
			"ALLOWED with warnings (review hops below)",
			strings.Join(mergeUniqueStrs(suggestions, nil), "; "),
			lines...)
	default:
		r.Pass(checkID, "Traffic Map & Policy Verdict", res, title,
			"ALLOWED across all policy hops",
			lines...)
	}
}

// --- Individual hop evaluators ---

func evalEgressNP(srcPod k8s.Pod, srcNS string, dst Endpoint, nps []k8s.NetworkPolicy, nsMap map[string]k8s.Namespace) HopResult {
	var matching []k8s.NetworkPolicy
	for _, np := range nps {
		if hasPolicyType(np, "Egress") && matchesLabelSelector(np.Spec.PodSelector, srcPod.Metadata.Labels) {
			matching = append(matching, np)
		}
	}
	if len(matching) == 0 {
		return HopResult{
			Hop:     "Src Egress NetworkPolicy (" + srcNS + ")",
			Status:  report.StatusPass,
			Summary: "unrestricted (no Egress NetworkPolicy selects this pod)",
		}
	}

	proto := strings.ToUpper(dst.Protocol)
	if proto == "" {
		proto = "TCP"
	}

	// Special handling for kube-apiserver (post-DNAT IP + port 6443)
	if dst.Kind == PeerKubeAPIServer {
		ips := dst.effectiveIPs()
		if len(ips) == 0 {
			if npListAllowsAnyIPPort(matching, dst.Port, "TCP") {
				return HopResult{Hop: "Src Egress NetworkPolicy (" + srcNS + ")", Status: report.StatusPass, Summary: fmt.Sprintf("allows TCP/%d via ipBlock", dst.Port)}
			}
			return HopResult{
				Hop:        "Src Egress NetworkPolicy (" + srcNS + ")",
				Status:     report.StatusFail,
				Summary:    fmt.Sprintf("selected by %d Egress NP(s), none allows TCP/%d to kube-apiserver", len(matching), dst.Port),
				Suggestion: fmt.Sprintf("Add Egress NetworkPolicy ipBlock for control-plane node IPs on TCP/%d (post-DNAT)", dst.Port),
			}
		}
		var blockedIPs []string
		for _, ip := range ips {
			if !npListAllowsEgressToIP(matching, ip, dst.Port, "TCP") {
				blockedIPs = append(blockedIPs, ip)
			}
		}
		if len(blockedIPs) > 0 {
			hint := ""
			if npListAllowsEgressToIP(matching, blockedIPs[0], 443, "TCP") {
				hint = " (found port 443, but Kube-OVN NetworkPolicy filters post-DNAT port 6443!)"
			}
			return HopResult{
				Hop:        "Src Egress NetworkPolicy (" + srcNS + ")",
				Status:     report.StatusFail,
				Summary:    fmt.Sprintf("blocked to kube-apiserver %v:%d%s", blockedIPs, dst.Port, hint),
				Suggestion: fmt.Sprintf("Allow Egress ipBlock %v/32 on TCP/%d in %s (netpol[] in console-charts/policies)", blockedIPs, dst.Port, srcNS),
			}
		}
		return HopResult{
			Hop:     "Src Egress NetworkPolicy (" + srcNS + ")",
			Status:  report.StatusPass,
			Summary: fmt.Sprintf("allows kube-apiserver %v:%d/TCP", ips, dst.Port),
		}
	}

	// Ambient TCP peer requires HBONE 15008/TCP!
	needHBONE := dst.Ambient && proto == "TCP" && (dst.Kind == PeerService || dst.Kind == PeerPod)
	if needHBONE {
		if npListAllowsEgressToEndpoint(matching, dst, 15008, "TCP", nsMap) {
			return HopResult{
				Hop:     "Src Egress NetworkPolicy (" + srcNS + ")",
				Status:  report.StatusPass,
				Summary: fmt.Sprintf("allows HBONE TCP/15008 to %s", dst.Namespace),
			}
		}
		return HopResult{
			Hop:        "Src Egress NetworkPolicy (" + srcNS + ")",
			Status:     report.StatusFail,
			Summary:    fmt.Sprintf("destination %s is in ambient mesh, but NO Egress NP allows TCP/15008 (HBONE) to %s", dst.DisplayName(), dst.Namespace),
			Suggestion: fmt.Sprintf("Add Egress rule to %s on TCP/15008 (and %d) in %s", dst.Namespace, dst.Port, srcNS),
		}
	}

	// Non-mesh / UDP / CoreDNS / istiod / external
	if npListAllowsEgressToEndpoint(matching, dst, dst.Port, proto, nsMap) {
		return HopResult{
			Hop:     "Src Egress NetworkPolicy (" + srcNS + ")",
			Status:  report.StatusPass,
			Summary: fmt.Sprintf("allows %s/%d to %s", proto, dst.Port, dst.DisplayName()),
		}
	}
	return HopResult{
		Hop:        "Src Egress NetworkPolicy (" + srcNS + ")",
		Status:     report.StatusFail,
		Summary:    fmt.Sprintf("selected by %d Egress NP(s), none allows %s/%d to %s", len(matching), proto, dst.Port, dst.DisplayName()),
		Suggestion: fmt.Sprintf("Allow Egress %s/%d to %s in namespace %s", proto, dst.Port, dst.DisplayName(), srcNS),
	}
}

func evalIngressNP(
	dstPods []k8s.Pod,
	dstSvcSel map[string]string,
	dstNS string,
	dstName string,
	src Endpoint,
	dstPort int,
	proto string,
	dstAmbient bool,
	nps []k8s.NetworkPolicy,
	nsMap map[string]k8s.Namespace,
) HopResult {
	var matching []k8s.NetworkPolicy
	for _, np := range nps {
		if hasPolicyType(np, "Ingress") && selectorMatchesPods(np.Spec.PodSelector, dstPods, dstSvcSel) {
			matching = append(matching, np)
		}
	}
	if len(matching) == 0 {
		return HopResult{
			Hop:     "Dst Ingress NetworkPolicy (" + dstNS + ")",
			Status:  report.StatusPass,
			Summary: fmt.Sprintf("unrestricted (no Ingress NetworkPolicy selects %s/%s)", dstNS, dstName),
		}
	}

	if proto == "" {
		proto = "TCP"
	}
	checkPort := dstPort
	portDesc := fmt.Sprintf("%s/%d", proto, dstPort)
	if dstAmbient && strings.EqualFold(proto, "TCP") {
		checkPort = 15008
		portDesc = "TCP/15008 (HBONE)"
	}

	if npListAllowsIngressFromEndpoint(matching, src, checkPort, proto, nsMap) {
		return HopResult{
			Hop:     "Dst Ingress NetworkPolicy (" + dstNS + ")",
			Status:  report.StatusPass,
			Summary: fmt.Sprintf("allows %s from %s", portDesc, firstNonEmpty(src.Namespace, src.IP)),
		}
	}
	return HopResult{
		Hop:        "Dst Ingress NetworkPolicy (" + dstNS + ")",
		Status:     report.StatusFail,
		Summary:    fmt.Sprintf("%s/%s is selected by %d Ingress NP(s), none allows %s from %s", dstNS, dstName, len(matching), portDesc, firstNonEmpty(src.Namespace, src.IP)),
		Suggestion: fmt.Sprintf("Add Ingress NetworkPolicy in %s allowing %s from %s", dstNS, portDesc, firstNonEmpty(src.Namespace, src.IP)),
	}
}

func evalPeerAuthHop(srcAmbient, dstAmbient bool, dstPods []k8s.Pod, dstNS string, dstPort int, nsPAs, meshPAs []k8s.PeerAuthentication) HopResult {
	if !dstAmbient {
		return HopResult{
			Hop:     "Dst PeerAuthentication (" + dstNS + ")",
			Status:  report.StatusPass,
			Summary: "destination is outside ambient mesh (plaintext allowed)",
		}
	}
	if srcAmbient {
		return HopResult{
			Hop:     "Dst PeerAuthentication (" + dstNS + ")",
			Status:  report.StatusPass,
			Summary: "both source and destination are in ambient mesh (HBONE mTLS)",
		}
	}

	mode := effectiveMTLSMode(dstPods, dstPort, nsPAs, meshPAs)
	if strings.EqualFold(mode, "STRICT") {
		return HopResult{
			Hop:        "Dst PeerAuthentication (" + dstNS + ")",
			Status:     report.StatusFail,
			Summary:    fmt.Sprintf("non-mesh plaintext source hits STRICT mTLS on port %d (ztunnel rejects with istio_converted_static_strict)", dstPort),
			Suggestion: fmt.Sprintf("Enroll source in ambient mesh, route through Ingress Gateway, or add portLevelMtls[%d]=PERMISSIVE PeerAuthentication in %s", dstPort, dstNS),
		}
	}
	return HopResult{
		Hop:     "Dst PeerAuthentication (" + dstNS + ")",
		Status:  report.StatusPass,
		Summary: fmt.Sprintf("non-mesh source permitted (effective mTLS=%s on port %d)", mode, dstPort),
	}
}

func evalAuthzHop(src Endpoint, dstPods []k8s.Pod, dstSvcSel map[string]string, dstNS, dstSvcName string, dstPort int, aps []k8s.AuthorizationPolicy) HopResult {
	var matchingAllow []k8s.AuthorizationPolicy
	var matchingDeny []k8s.AuthorizationPolicy
	for _, ap := range aps {
		if !apAppliesToTarget(ap, dstSvcName, dstPods, dstSvcSel) {
			continue
		}
		act := strings.ToUpper(ap.Spec.Action)
		switch act {
		case "", "ALLOW":
			matchingAllow = append(matchingAllow, ap)
		case "DENY":
			matchingDeny = append(matchingDeny, ap)
		}
	}

	portStr := strconv.Itoa(dstPort)
	for _, ap := range matchingDeny {
		if authzRulesMatch(ap, src, portStr) {
			return HopResult{
				Hop:        "Dst AuthorizationPolicy (" + dstNS + ")",
				Status:     report.StatusFail,
				Summary:    fmt.Sprintf("explicitly DENIED by DENY policy %s/%s", dstNS, ap.Metadata.Name),
				Suggestion: fmt.Sprintf("Review DENY AuthorizationPolicy %s/%s", dstNS, ap.Metadata.Name),
			}
		}
	}

	if len(matchingAllow) == 0 {
		return HopResult{
			Hop:     "Dst AuthorizationPolicy (" + dstNS + ")",
			Status:  report.StatusPass,
			Summary: fmt.Sprintf("no ALLOW AuthorizationPolicy applies to %s/%s (no implicit deny)", dstNS, dstSvcName),
		}
	}

	for _, ap := range matchingAllow {
		if authzRulesMatch(ap, src, portStr) {
			return HopResult{
				Hop:     "Dst AuthorizationPolicy (" + dstNS + ")",
				Status:  report.StatusPass,
				Summary: fmt.Sprintf("allowed by %s/%s for principal %s on port %s", dstNS, ap.Metadata.Name, firstNonEmpty(src.Principal, src.IP), portStr),
			}
		}
	}
	return HopResult{
		Hop:        "Dst AuthorizationPolicy (" + dstNS + ")",
		Status:     report.StatusFail,
		Summary:    fmt.Sprintf("implicit deny active (%d ALLOW policy(ies) match %s/%s), none permits principal %q on port %s", len(matchingAllow), dstNS, dstSvcName, firstNonEmpty(src.Principal, src.IP), portStr),
		Suggestion: fmt.Sprintf("Add ALLOW AuthorizationPolicy in %s permitting principal %q on port %q", dstNS, firstNonEmpty(src.Principal, src.IP), portStr),
	}
}

func evalZtunnelHop(label string, ambient bool, ztNS, ztPod, node string, logs, errs []string) HopResult {
	where := fmt.Sprintf("%s/%s@%s", firstNonEmpty(ztNS, "ztunnel"), firstNonEmpty(ztPod, "<none>"), firstNonEmpty(node, "?"))
	if !ambient {
		return HopResult{
			Hop:     label + " (" + where + ")",
			Status:  report.StatusInfo,
			Summary: "pod is outside ambient mesh (traffic bypasses ztunnel)",
		}
	}
	if ztPod == "" {
		return HopResult{
			Hop:        label + " (node=" + node + ")",
			Status:     report.StatusWarn,
			Summary:    "no ztunnel pod found on node " + node,
			Suggestion: "Check ztunnel DaemonSet scheduling on node " + node,
		}
	}
	if len(errs) > 0 {
		return HopResult{
			Hop:        label + " (" + where + ")",
			Status:     report.StatusFail,
			Summary:    fmt.Sprintf("ztunnel logged %d error(s): %s", len(errs), errs[0]),
			Suggestion: "Inspect ztunnel logs on " + where + " to see exact drop/rejection reason",
			Evidence:   trimLines(append(errs, logs...), 4),
		}
	}
	if len(logs) > 0 {
		return HopResult{
			Hop:      label + " (" + where + ")",
			Status:   report.StatusPass,
			Summary:  fmt.Sprintf("observed %d clean access log(s) via ztunnel", len(logs)),
			Evidence: trimLines(logs, 2),
		}
	}
	return HopResult{
		Hop:     label + " (" + where + ")",
		Status:  report.StatusPass,
		Summary: "ztunnel active on node (no errors in lookback window)",
	}
}

// --- NetworkPolicy / AuthorizationPolicy / PeerAuthentication matching helpers ---

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

func selectorMatchesPods(sel k8s.LabelSelector, pods []k8s.Pod, fallback map[string]string) bool {
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
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
	if len(fallback) > 0 {
		return matchesLabelSelector(sel, fallback)
	}
	return false
}

func npListAllowsEgressToIP(nps []k8s.NetworkPolicy, ip string, port int, proto string) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Egress {
			if !npPortsAllow(rule.Ports, port, proto) {
				continue
			}
			if len(rule.To) == 0 {
				return true
			}
			for _, peer := range rule.To {
				if peer.IPBlock != nil && ipInIPBlock(ip, peer.IPBlock.CIDR, peer.IPBlock.Except) {
					return true
				}
			}
		}
	}
	return false
}

func npListAllowsAnyIPPort(nps []k8s.NetworkPolicy, port int, proto string) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Egress {
			if !npPortsAllow(rule.Ports, port, proto) {
				continue
			}
			if len(rule.To) == 0 {
				return true
			}
			for _, peer := range rule.To {
				if peer.IPBlock != nil && peer.IPBlock.CIDR != "" {
					return true
				}
			}
		}
	}
	return false
}

func npListAllowsEgressToEndpoint(nps []k8s.NetworkPolicy, dst Endpoint, port int, proto string, nsMap map[string]k8s.Namespace) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Egress {
			if !npPortsAllow(rule.Ports, port, proto) {
				continue
			}
			if len(rule.To) == 0 {
				return true
			}
			for _, peer := range rule.To {
				if npPeerMatchesEndpoint(peer, dst, np.Metadata.Namespace, nsMap) {
					return true
				}
			}
		}
	}
	return false
}

func npListAllowsIngressFromEndpoint(nps []k8s.NetworkPolicy, src Endpoint, port int, proto string, nsMap map[string]k8s.Namespace) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Ingress {
			if !npPortsAllow(rule.Ports, port, proto) {
				continue
			}
			if len(rule.From) == 0 {
				return true
			}
			for _, peer := range rule.From {
				if npPeerMatchesEndpoint(peer, src, np.Metadata.Namespace, nsMap) {
					return true
				}
			}
		}
	}
	return false
}

func npPeerMatchesEndpoint(peer k8s.NetworkPolicyPeer, ep Endpoint, npNS string, nsMap map[string]k8s.Namespace) bool {
	if peer.IPBlock != nil {
		if peer.IPBlock.CIDR == "0.0.0.0/0" && len(peer.IPBlock.Except) == 0 {
			return true
		}
		for _, ip := range ep.effectiveIPs() {
			if ipInIPBlock(ip, peer.IPBlock.CIDR, peer.IPBlock.Except) {
				return true
			}
		}
		return false
	}

	// Namespace match
	if peer.NamespaceSelector != nil {
		if ep.Namespace == "" {
			return false
		}
		nsLabels := make(map[string]string)
		if nsObj, ok := nsMap[ep.Namespace]; ok {
			for k, v := range nsObj.Metadata.Labels {
				nsLabels[k] = v
			}
		}
		if _, ok := nsLabels["kubernetes.io/metadata.name"]; !ok {
			nsLabels["kubernetes.io/metadata.name"] = ep.Namespace
		}
		if !matchesLabelSelector(*peer.NamespaceSelector, nsLabels) {
			return false
		}
	} else if peer.PodSelector != nil {
		// podSelector without namespaceSelector matches only same namespace as the NetworkPolicy
		if ep.Namespace != npNS {
			return false
		}
	}

	// PodSelector match
	if peer.PodSelector != nil {
		labels := ep.Labels
		if len(labels) == 0 {
			labels = ep.StableSelector
		}
		if !matchesLabelSelector(*peer.PodSelector, labels) {
			return false
		}
	}
	return true
}

func npPortsAllow(ports []k8s.NetworkPolicyPort, targetPort int, targetProto string) bool {
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

func ipInIPBlock(rawIP, cidr string, except []string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !pfx.Contains(addr) {
		return false
	}
	for _, ex := range except {
		if exPfx, err := netip.ParsePrefix(strings.TrimSpace(ex)); err == nil && exPfx.Contains(addr) {
			return false
		}
	}
	return true
}

func effectiveMTLSMode(dstPods []k8s.Pod, port int, nsPAs, meshPAs []k8s.PeerAuthentication) string {
	mode := "PERMISSIVE"
	portKey := strconv.Itoa(port)
	// Mesh-wide first
	for _, pa := range meshPAs {
		if pa.Spec.Selector != nil && (len(pa.Spec.Selector.MatchLabels) > 0 || len(pa.Spec.Selector.MatchExpressions) > 0) {
			continue
		}
		if pa.Spec.MTLS != nil && pa.Spec.MTLS.Mode != "" {
			mode = pa.Spec.MTLS.Mode
		}
	}
	// Namespace-wide next
	for _, pa := range nsPAs {
		if pa.Spec.Selector != nil && (len(pa.Spec.Selector.MatchLabels) > 0 || len(pa.Spec.Selector.MatchExpressions) > 0) {
			continue
		}
		if pa.Spec.MTLS != nil && pa.Spec.MTLS.Mode != "" {
			mode = pa.Spec.MTLS.Mode
		}
		if pm, ok := pa.Spec.PortLevelMTLS[portKey]; ok && pm.Mode != "" {
			mode = pm.Mode
		}
	}
	// Workload-specific last (highest precedence)
	for _, pa := range nsPAs {
		if pa.Spec.Selector == nil || (len(pa.Spec.Selector.MatchLabels) == 0 && len(pa.Spec.Selector.MatchExpressions) == 0) {
			continue
		}
		if !selectorMatchesPods(*pa.Spec.Selector, dstPods, nil) {
			continue
		}
		if pa.Spec.MTLS != nil && pa.Spec.MTLS.Mode != "" {
			mode = pa.Spec.MTLS.Mode
		}
		if pm, ok := pa.Spec.PortLevelMTLS[portKey]; ok && pm.Mode != "" {
			mode = pm.Mode
		}
	}
	return mode
}

func apAppliesToTarget(ap k8s.AuthorizationPolicy, svcName string, pods []k8s.Pod, svcSel map[string]string) bool {
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
	return selectorMatchesPods(*ap.Spec.Selector, pods, svcSel)
}

func authzRulesMatch(ap k8s.AuthorizationPolicy, src Endpoint, portStr string) bool {
	if len(ap.Spec.Rules) == 0 {
		return false
	}
	for _, rule := range ap.Spec.Rules {
		fromOK := len(rule.From) == 0
		for _, f := range rule.From {
			for _, p := range f.Source.Principals {
				if p == "*" || p == src.Principal || (src.Principal != "" && strings.HasSuffix(src.Principal, strings.TrimPrefix(p, "*"))) {
					fromOK = true
				}
			}
			for _, ns := range f.Source.Namespaces {
				if ns == "*" || (src.Namespace != "" && ns == src.Namespace) {
					fromOK = true
				}
			}
			for _, cidr := range f.Source.IPBlocks {
				if cidr == "0.0.0.0/0" {
					fromOK = true
				}
				for _, ip := range src.effectiveIPs() {
					if ipInIPBlock(ip, cidr, nil) {
						fromOK = true
					}
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
			return true
		}
	}
	return false
}

func podsForEndpoint(ep Endpoint, idx *ClusterIndex) []k8s.Pod {
	var out []k8s.Pod
	for _, ip := range ep.effectiveIPs() {
		if p, ok := idx.PodsByIP[ip]; ok {
			out = append(out, p)
		}
	}
	if len(out) == 0 && len(ep.StableSelector) > 0 && ep.Namespace != "" {
		for _, p := range idx.PodsByNS[ep.Namespace] {
			if matchesMap(ep.StableSelector, p.Metadata.Labels) {
				out = append(out, p)
			}
		}
	}
	return out
}

func findZtunnelErrorsBetween(logs, srcIP string, dstIPs []string) []string {
	if logs == "" || srcIP == "" {
		return nil
	}
	var out []string
	for _, raw := range strings.Split(logs, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.Contains(line, srcIP) {
			continue
		}
		hitDst := len(dstIPs) == 0
		for _, dip := range dstIPs {
			if dip != "" && strings.Contains(line, dip) {
				hitDst = true
				break
			}
		}
		if !hitDst {
			continue
		}
		if m := ztErrorRe.FindStringSubmatch(line); len(m) >= 2 {
			out = append(out, m[1])
		} else if strings.Contains(strings.ToLower(line), "policy rejection") || strings.Contains(strings.ToLower(line), "error") {
			out = append(out, line)
		}
	}
	return out
}

func parseSPIFFEPrincipal(p string) (ns, sa string) {
	p = strings.TrimPrefix(p, "spiffe://")
	parts := strings.Split(p, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "ns" {
			ns = parts[i+1]
		}
		if parts[i] == "sa" {
			sa = parts[i+1]
		}
	}
	return ns, sa
}

func trimLines(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	return in[len(in)-max:]
}
