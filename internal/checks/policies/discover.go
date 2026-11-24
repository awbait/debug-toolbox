package policies

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/awbait/debug-toolbox/internal/checks/common"
	"github.com/awbait/debug-toolbox/internal/k8s"
)

// resolveTargetPod resolves a pod from an explicit pod name, workload ref (deploy/sts/ds/gw), or pod prefix.
func resolveTargetPod(ctx context.Context, c *k8s.Client, ns, target string) (k8s.Pod, error) {
	if target == "" {
		return k8s.Pod{}, fmt.Errorf("target pod or workload is required (e.g. mesh-debug policies -n %s <pod|deploy/name>)", ns)
	}

	// Kind/Name shorthand: deploy/foo, sts/foo, ds/foo, gw/foo
	if kind, name, ok := strings.Cut(target, "/"); ok {
		lowKind := strings.ToLower(kind)
		switch lowKind {
		case "pod", "po":
			return c.GetPod(ctx, ns, name)
		case "gw", "gateway":
			pods, err := c.ListPods(ctx, ns, common.LabelGatewayName+"="+name)
			if err != nil {
				return k8s.Pod{}, err
			}
			return pickBestPod(pods, target)
		case "deploy", "deployment", "sts", "statefulset", "ds", "daemonset":
			resName := normalizeWorkloadResource(lowKind)
			w, err := c.GetWorkload(ctx, resName, ns, name)
			if err == nil && w.Spec.Selector != nil && len(w.Spec.Selector.MatchLabels) > 0 {
				sel := mapToSelector(w.Spec.Selector.MatchLabels)
				pods, err := c.ListPods(ctx, ns, sel)
				if err == nil && len(pods) > 0 {
					return pickBestPod(pods, target)
				}
			}
			// Fallback: prefix match in namespace
			pods, err := c.ListPods(ctx, ns, "")
			if err != nil {
				return k8s.Pod{}, err
			}
			var pref []k8s.Pod
			for _, p := range pods {
				if strings.HasPrefix(p.Metadata.Name, name+"-") || p.Metadata.Name == name {
					pref = append(pref, p)
				}
			}
			return pickBestPod(pref, target)
		}
	}

	// Try exact pod lookup first
	if p, err := c.GetPod(ctx, ns, target); err == nil {
		return p, nil
	}

	// Fallback: list pods in ns and match by prefix or gateway label
	pods, err := c.ListPods(ctx, ns, "")
	if err != nil {
		return k8s.Pod{}, fmt.Errorf("pod %s/%s not found and failed to list pods: %w", ns, target, err)
	}
	var matched []k8s.Pod
	for _, p := range pods {
		if p.Metadata.Name == target ||
			strings.HasPrefix(p.Metadata.Name, target+"-") ||
			p.Metadata.Labels[common.LabelGatewayName] == target {
			matched = append(matched, p)
		}
	}
	return pickBestPod(matched, target)
}

func pickBestPod(pods []k8s.Pod, target string) (k8s.Pod, error) {
	if len(pods) == 0 {
		return k8s.Pod{}, fmt.Errorf("no pods matched target %q", target)
	}
	for _, p := range pods {
		if p.IsReady() {
			return p, nil
		}
	}
	for _, p := range pods {
		if p.Status.Phase == "Running" {
			return p, nil
		}
	}
	return pods[0], nil
}

func normalizeWorkloadResource(k string) string {
	switch strings.ToLower(k) {
	case "deploy", "deployment":
		return "deployments"
	case "sts", "statefulset":
		return "statefulsets"
	case "ds", "daemonset":
		return "daemonsets"
	case "rs", "replicaset":
		return "replicasets"
	default:
		return k
	}
}

// inspectTargetInfo builds TargetInfo including owner, stable selector, workload kind, SA/principal, and ztunnel pod.
func inspectTargetInfo(
	ctx context.Context,
	c *k8s.Client,
	pod k8s.Pod,
	nsObj k8s.Namespace,
	ztunnelNS string,
	ztunnelPods []k8s.Pod,
) TargetInfo {
	sa := pod.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	ns := pod.Metadata.Namespace
	ambient := nsObj.Metadata.Labels[common.LabelDataplaneMode] == "ambient" &&
		pod.Metadata.Labels[common.LabelDataplaneMode] != "none" &&
		pod.Metadata.Labels[common.LabelGatewayName] == "" &&
		pod.Metadata.Labels[common.LabelVEG] == ""

	info := TargetInfo{
		Pod:            pod,
		Namespace:      nsObj,
		WorkloadKind:   WorkloadGeneric,
		ServiceAccount: sa,
		Principal:      fmt.Sprintf("cluster.local/ns/%s/sa/%s", ns, sa),
		Ambient:        ambient,
		Redirected:     pod.Metadata.Annotations[common.AnnotRedirection] == "enabled",
		ZtunnelNS:      ztunnelNS,
		OVNSubnet:      pod.Metadata.Annotations["ovn.kubernetes.io/logical_switch"],
	}

	// Find ztunnel pod on this pod's node
	for _, zp := range ztunnelPods {
		if zp.Spec.NodeName == pod.Spec.NodeName {
			info.ZtunnelPod = zp.Metadata.Name
			break
		}
	}

	// Resolve owner workload & stable selector (Pod -> ReplicaSet -> Deployment / StatefulSet / DaemonSet)
	ownerKind, ownerName, stableSel := resolveOwnerAndSelector(ctx, c, pod)
	info.OwnerKind = ownerKind
	info.OwnerName = ownerName
	if len(stableSel) > 0 {
		info.StableSelector = stableSel
	} else {
		info.StableSelector = filterStablePodLabels(pod.Metadata.Labels)
	}

	// Classify workload kind: ingress-gateway / waypoint / operator / workload
	if gwName := pod.Metadata.Labels[common.LabelGatewayName]; gwName != "" {
		info.WorkloadKind = WorkloadIngressGateway
		if gws, err := c.ListGateways(ctx, ns); err == nil {
			for _, gw := range gws {
				if gw.Metadata.Name == gwName {
					if gw.Spec.GatewayClassName == "istio-waypoint" {
						info.WorkloadKind = WorkloadWaypoint
					}
					break
				}
			}
		}
		return info
	}

	// Check if ServiceAccount has Kubernetes API RBAC -> operator
	tokenMounted := pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken
	if tokenMounted && saHasAPIRBAC(ctx, c, ns, sa) {
		info.HasAPIRBAC = true
		info.WorkloadKind = WorkloadOperator
	}
	return info
}

func resolveOwnerAndSelector(ctx context.Context, c *k8s.Client, pod k8s.Pod) (string, string, map[string]string) {
	if len(pod.Metadata.OwnerReferences) == 0 {
		return "", "", nil
	}
	ref := pod.Metadata.OwnerReferences[0]
	ns := pod.Metadata.Namespace

	switch ref.Kind {
	case "ReplicaSet":
		rs, err := c.GetWorkload(ctx, "replicasets", ns, ref.Name)
		if err == nil {
			for _, parent := range rs.Metadata.OwnerReferences {
				if parent.Kind == "Deployment" {
					if dep, err := c.GetWorkload(ctx, "deployments", ns, parent.Name); err == nil && dep.Spec.Selector != nil {
						return "Deployment", parent.Name, dep.Spec.Selector.MatchLabels
					}
					return "Deployment", parent.Name, nil
				}
			}
			if rs.Spec.Selector != nil {
				sel := make(map[string]string)
				for k, v := range rs.Spec.Selector.MatchLabels {
					if k != "pod-template-hash" {
						sel[k] = v
					}
				}
				return "ReplicaSet", ref.Name, sel
			}
		}
		return "ReplicaSet", ref.Name, nil
	case "StatefulSet":
		if sts, err := c.GetWorkload(ctx, "statefulsets", ns, ref.Name); err == nil && sts.Spec.Selector != nil {
			return "StatefulSet", ref.Name, sts.Spec.Selector.MatchLabels
		}
		return "StatefulSet", ref.Name, nil
	case "DaemonSet":
		if ds, err := c.GetWorkload(ctx, "daemonsets", ns, ref.Name); err == nil && ds.Spec.Selector != nil {
			return "DaemonSet", ref.Name, ds.Spec.Selector.MatchLabels
		}
		return "DaemonSet", ref.Name, nil
	default:
		return ref.Kind, ref.Name, nil
	}
}

func saHasAPIRBAC(ctx context.Context, c *k8s.Client, ns, sa string) bool {
	if rbs, err := c.ListRoleBindings(ctx, ns); err == nil {
		for _, rb := range rbs {
			for _, sub := range rb.Subjects {
				if sub.Kind == "ServiceAccount" && sub.Name == sa && (sub.Namespace == "" || sub.Namespace == ns) {
					return true
				}
			}
		}
	}
	if crbs, err := c.ListClusterRoleBindings(ctx); err == nil {
		for _, crb := range crbs {
			for _, sub := range crb.Subjects {
				if sub.Kind == "ServiceAccount" && sub.Name == sa && sub.Namespace == ns {
					return true
				}
			}
		}
	}
	return false
}

// buildClusterIndex populates read-only cluster lookup maps for resolving IPs, Services, and ServiceEntries.
func buildClusterIndex(ctx context.Context, c *k8s.Client, ztunnelPods []k8s.Pod) *ClusterIndex {
	idx := &ClusterIndex{
		Namespaces:      make(map[string]k8s.Namespace),
		ServicesByKey:   make(map[string]k8s.Service),
		ServicesByCIP:   make(map[string]k8s.Service),
		EndpointsByKey:  make(map[string]k8s.Endpoints),
		PodsByIP:        make(map[string]k8s.Pod),
		PodsByNS:        make(map[string][]k8s.Pod),
		ServiceByPodIP:  make(map[string]k8s.Service),
		ServiceEntryVIP: make(map[string]k8s.ServiceEntry),
		ServiceEntryHst: make(map[string]k8s.ServiceEntry),
		ZtunnelByNode:   make(map[string]k8s.Pod),
		APIServerPort:   6443,
	}

	for _, zp := range ztunnelPods {
		if zp.Spec.NodeName != "" {
			idx.ZtunnelByNode[zp.Spec.NodeName] = zp
		}
	}

	if nss, err := c.ListNamespaces(ctx); err == nil {
		for _, n := range nss {
			idx.Namespaces[n.Metadata.Name] = n
		}
	}
	if svcs, err := c.ListServices(ctx, ""); err == nil {
		for _, s := range svcs {
			key := s.Metadata.Namespace + "/" + s.Metadata.Name
			idx.ServicesByKey[key] = s
			if s.Spec.ClusterIP != "" && s.Spec.ClusterIP != "None" {
				idx.ServicesByCIP[s.Spec.ClusterIP] = s
			}
		}
	}
	if eps, err := c.ListEndpoints(ctx, ""); err == nil {
		for _, ep := range eps {
			key := ep.Metadata.Namespace + "/" + ep.Metadata.Name
			idx.EndpointsByKey[key] = ep
			svc, hasSvc := idx.ServicesByKey[key]
			for _, sub := range ep.Subsets {
				for _, addr := range sub.Addresses {
					if addr.IP == "" {
						continue
					}
					if hasSvc {
						if _, exists := idx.ServiceByPodIP[addr.IP]; !exists {
							idx.ServiceByPodIP[addr.IP] = svc
						}
					}
					if key == "default/kubernetes" {
						idx.APIServerIPs = append(idx.APIServerIPs, addr.IP)
					} else if ep.Metadata.Namespace == "kube-system" && strings.Contains(ep.Metadata.Name, "dns") {
						idx.CoreDNSIPs = append(idx.CoreDNSIPs, addr.IP)
					} else if ep.Metadata.Namespace == "istio-system" && ep.Metadata.Name == "istiod" {
						idx.IstiodIPs = append(idx.IstiodIPs, addr.IP)
					}
				}
				if key == "default/kubernetes" {
					for _, p := range sub.Ports {
						if p.Port > 0 {
							idx.APIServerPort = p.Port
							break
						}
					}
				}
			}
		}
	}
	idx.APIServerIPs = mergeUniqueStrs(idx.APIServerIPs, nil)
	idx.CoreDNSIPs = mergeUniqueStrs(idx.CoreDNSIPs, nil)
	idx.IstiodIPs = mergeUniqueStrs(idx.IstiodIPs, nil)

	if pods, err := c.ListPods(ctx, "", ""); err == nil {
		for _, p := range pods {
			if p.Status.PodIP != "" {
				idx.PodsByIP[p.Status.PodIP] = p
			}
			idx.PodsByNS[p.Metadata.Namespace] = append(idx.PodsByNS[p.Metadata.Namespace], p)
		}
	}
	if ses, err := c.ListServiceEntries(ctx, ""); err == nil {
		for _, se := range ses {
			for _, v := range se.EffectiveVIPs() {
				idx.ServiceEntryVIP[v] = se
			}
			for _, h := range se.Spec.Hosts {
				idx.ServiceEntryHst[strings.ToLower(h)] = se
			}
		}
	}
	return idx
}

// resolveIPPort maps a raw IP:port/proto into a rich Endpoint (kube-apiserver, CoreDNS, Service, Pod, ServiceEntry, or external).
func (idx *ClusterIndex) resolveIPPort(ip string, port int, proto string) Endpoint {
	if proto == "" {
		proto = "TCP"
	}
	ep := Endpoint{
		Kind:     PeerExternal,
		IP:       ip,
		Port:     port,
		Protocol: strings.ToUpper(proto),
	}

	// 1. kube-apiserver (either ClusterIP default/kubernetes:443 OR direct control-plane endpoint IP:6443)
	if svc, ok := idx.ServicesByCIP[ip]; ok && svc.Metadata.Namespace == "default" && svc.Metadata.Name == "kubernetes" {
		return idx.kubeAPIServerEndpoint()
	}
	if containsStr(idx.APIServerIPs, ip) && (port == idx.APIServerPort || port == 6443 || port == 443) {
		return idx.kubeAPIServerEndpoint()
	}

	// 2. ServiceEntry VIP (240.240.x.x / 240.241.x.x)
	if se, ok := idx.ServiceEntryVIP[ip]; ok {
		ep.Kind = PeerServiceEntry
		ep.Namespace = se.Metadata.Namespace
		if len(se.Spec.Hosts) > 0 {
			ep.Hostname = se.Spec.Hosts[0]
		}
		return ep
	}

	// 3. Kubernetes ClusterIP Service
	if svc, ok := idx.ServicesByCIP[ip]; ok {
		return idx.endpointFromService(svc, port, proto)
	}

	// 4. CoreDNS or istiod pod IP
	if containsStr(idx.CoreDNSIPs, ip) || (port == 53 || port == 1053) {
		if containsStr(idx.CoreDNSIPs, ip) {
			ep.Kind = PeerCoreDNS
			ep.Namespace = "kube-system"
			ep.ServiceName = "kube-dns"
			return ep
		}
	}
	if containsStr(idx.IstiodIPs, ip) {
		ep.Kind = PeerIstiod
		ep.Namespace = "istio-system"
		ep.ServiceName = "istiod"
		return ep
	}

	// 5. Direct Pod IP (in-cluster workload)
	if pod, ok := idx.PodsByIP[ip]; ok {
		return idx.endpointFromPod(pod, port, proto)
	}

	// 6. Endpoint IP backing a Service (e.g. headless or pod not in PodsByIP)
	if svc, ok := idx.ServiceByPodIP[ip]; ok {
		res := idx.endpointFromService(svc, port, proto)
		res.IP = ip
		return res
	}

	return ep
}

func (idx *ClusterIndex) kubeAPIServerEndpoint() Endpoint {
	port := idx.APIServerPort
	if port == 0 {
		port = 6443
	}
	ip := ""
	if len(idx.APIServerIPs) > 0 {
		ip = idx.APIServerIPs[0]
	} else if svc, ok := idx.ServicesByKey["default/kubernetes"]; ok {
		ip = svc.Spec.ClusterIP
	}
	return Endpoint{
		Kind:        PeerKubeAPIServer,
		Namespace:   "default",
		ServiceName: "kubernetes",
		IP:          ip,
		AllIPs:      append([]string(nil), idx.APIServerIPs...),
		Port:        port,
		Protocol:    "TCP",
		Ambient:     false,
	}
}

func (idx *ClusterIndex) endpointFromService(svc k8s.Service, port int, proto string) Endpoint {
	ns := svc.Metadata.Namespace
	if ns == "default" && svc.Metadata.Name == "kubernetes" {
		return idx.kubeAPIServerEndpoint()
	}
	if ns == "kube-system" && strings.Contains(svc.Metadata.Name, "dns") {
		p := port
		if p == 0 {
			p = 1053
		}
		if proto == "" {
			proto = "UDP"
		}
		return Endpoint{
			Kind:        PeerCoreDNS,
			Namespace:   "kube-system",
			ServiceName: svc.Metadata.Name,
			IP:          svc.Spec.ClusterIP,
			Port:        p,
			Protocol:    strings.ToUpper(proto),
		}
	}
	if ns == "istio-system" && svc.Metadata.Name == "istiod" {
		p := port
		if p == 0 {
			p = 15012
		}
		return Endpoint{
			Kind:        PeerIstiod,
			Namespace:   "istio-system",
			ServiceName: "istiod",
			IP:          svc.Spec.ClusterIP,
			Port:        p,
			Protocol:    "TCP",
		}
	}

	if port == 0 && len(svc.Spec.Ports) > 0 {
		port = svc.Spec.Ports[0].Port
		if proto == "" && svc.Spec.Ports[0].Protocol != "" {
			proto = svc.Spec.Ports[0].Protocol
		}
	}
	if proto == "" {
		proto = "TCP"
	}

	ep := Endpoint{
		Kind:           PeerService,
		Namespace:      ns,
		ServiceName:    svc.Metadata.Name,
		IP:             svc.Spec.ClusterIP,
		Port:           port,
		Protocol:       strings.ToUpper(proto),
		Labels:         svc.Spec.Selector,
		StableSelector: svc.Spec.Selector,
		Ambient:        idx.namespaceAmbient(ns),
	}

	// Enrich with backing pod info (node, ztunnel, SA, actual pod labels & IP)
	if k8sEP, ok := idx.EndpointsByKey[ns+"/"+svc.Metadata.Name]; ok {
		for _, sub := range k8sEP.Subsets {
			for _, addr := range sub.Addresses {
				if addr.IP != "" {
					ep.AllIPs = append(ep.AllIPs, addr.IP)
					if pod, ok := idx.PodsByIP[addr.IP]; ok && ep.PodName == "" {
						idx.enrichEndpointFromPod(&ep, pod)
					}
				}
			}
		}
	}
	if ep.PodName == "" && len(svc.Spec.Selector) > 0 {
		for _, p := range idx.PodsByNS[ns] {
			if matchesMap(svc.Spec.Selector, p.Metadata.Labels) {
				idx.enrichEndpointFromPod(&ep, p)
				break
			}
		}
	}
	return ep
}

func (idx *ClusterIndex) endpointFromPod(pod k8s.Pod, port int, proto string) Endpoint {
	if proto == "" {
		proto = "TCP"
	}
	ep := Endpoint{
		Kind:     PeerPod,
		IP:       pod.Status.PodIP,
		Port:     port,
		Protocol: strings.ToUpper(proto),
	}
	idx.enrichEndpointFromPod(&ep, pod)
	if svc, ok := idx.ServiceByPodIP[pod.Status.PodIP]; ok {
		ep.Kind = PeerService
		ep.ServiceName = svc.Metadata.Name
		if len(svc.Spec.Selector) > 0 {
			ep.StableSelector = svc.Spec.Selector
		}
	}
	return ep
}

func (idx *ClusterIndex) enrichEndpointFromPod(ep *Endpoint, pod k8s.Pod) {
	ep.Namespace = pod.Metadata.Namespace
	ep.PodName = pod.Metadata.Name
	ep.NodeName = pod.Spec.NodeName
	ep.Labels = pod.Metadata.Labels
	if len(ep.StableSelector) == 0 {
		ep.StableSelector = filterStablePodLabels(pod.Metadata.Labels)
	}
	sa := pod.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	ep.ServiceAccount = sa
	ep.Principal = fmt.Sprintf("cluster.local/ns/%s/sa/%s", pod.Metadata.Namespace, sa)
	ep.Ambient = idx.namespaceAmbient(pod.Metadata.Namespace) &&
		pod.Metadata.Labels[common.LabelDataplaneMode] != "none" &&
		pod.Metadata.Labels[common.LabelGatewayName] == "" &&
		pod.Metadata.Labels[common.LabelVEG] == ""
	if zp, ok := idx.ZtunnelByNode[pod.Spec.NodeName]; ok {
		ep.ZtunnelPod = zp.Metadata.Name
	}
}

func (idx *ClusterIndex) namespaceAmbient(ns string) bool {
	if n, ok := idx.Namespaces[ns]; ok {
		return n.Metadata.Labels[common.LabelDataplaneMode] == "ambient"
	}
	return false
}

// resolveSimulatedTarget parses `--to` specs:
//   - "kube-apiserver" | "apiserver"
//   - "coredns" | "dns"
//   - "istiod"
//   - "<ns>/<svc>:<port>[/udp]" or "<ns>/<svc>"
//   - "<ip>:<port>[/udp]"
//   - "<hostname>:<port>"
func (idx *ClusterIndex) resolveSimulatedTarget(raw string, defaultNS string) (Endpoint, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Endpoint{}, fmt.Errorf("empty --to target")
	}
	low := strings.ToLower(s)
	switch low {
	case "kube-apiserver", "apiserver", "kubernetes", "default/kubernetes":
		return idx.kubeAPIServerEndpoint(), nil
	case "coredns", "dns", "kube-dns":
		return Endpoint{Kind: PeerCoreDNS, Namespace: "kube-system", ServiceName: "kube-dns", Port: 1053, Protocol: "UDP"}, nil
	case "istiod":
		return Endpoint{Kind: PeerIstiod, Namespace: "istio-system", ServiceName: "istiod", Port: 15012, Protocol: "TCP"}, nil
	}

	proto := "TCP"
	if base, p, ok := strings.Cut(s, "/udp"); ok && p == "" {
		s = base
		proto = "UDP"
	} else if base, p, ok := strings.Cut(s, "/UDP"); ok && p == "" {
		s = base
		proto = "UDP"
	} else if base, p, ok := strings.Cut(s, "/tcp"); ok && p == "" {
		s = base
		proto = "TCP"
	} else if base, p, ok := strings.Cut(s, "/TCP"); ok && p == "" {
		s = base
		proto = "TCP"
	}

	// Extract trailing :port if present (IPv4/host/ns/svc)
	port := 0
	hostPart := s
	if lastColon := strings.LastIndex(s, ":"); lastColon > 0 && !strings.Contains(s[lastColon+1:], "]") {
		if pNum, err := strconv.Atoi(s[lastColon+1:]); err == nil && pNum > 0 {
			port = pNum
			hostPart = s[:lastColon]
		}
	}
	hostPart = strings.Trim(hostPart, "[]")

	// ns/svc form
	if ns, svcName, ok := strings.Cut(hostPart, "/"); ok {
		if svc, exists := idx.ServicesByKey[ns+"/"+svcName]; exists {
			return idx.endpointFromService(svc, port, proto), nil
		}
		if port == 0 {
			port = 80
		}
		return Endpoint{
			Kind:        PeerService,
			Namespace:   ns,
			ServiceName: svcName,
			Port:        port,
			Protocol:    proto,
			Ambient:     idx.namespaceAmbient(ns),
		}, nil
	}

	// Raw IP
	if addr, err := netip.ParseAddr(hostPart); err == nil {
		if port == 0 {
			port = 443
		}
		return idx.resolveIPPort(addr.Unmap().String(), port, proto), nil
	}

	// ServiceEntry hostname match
	if se, ok := idx.ServiceEntryHst[strings.ToLower(hostPart)]; ok {
		if port == 0 && len(se.Spec.Ports) > 0 {
			port = se.Spec.Ports[0].Number
		}
		if port == 0 {
			port = 443
		}
		vip := ""
		if vips := se.EffectiveVIPs(); len(vips) > 0 {
			vip = vips[0]
		}
		return Endpoint{
			Kind:      PeerServiceEntry,
			Namespace: se.Metadata.Namespace,
			Hostname:  hostPart,
			IP:        vip,
			Port:      port,
			Protocol:  proto,
		}, nil
	}

	// Same-namespace Service name shorthand
	if svc, exists := idx.ServicesByKey[defaultNS+"/"+hostPart]; exists {
		return idx.endpointFromService(svc, port, proto), nil
	}

	// External hostname
	if port == 0 {
		port = 443
	}
	return Endpoint{
		Kind:     PeerExternal,
		Hostname: hostPart,
		Port:     port,
		Protocol: proto,
	}, nil
}

// --- ztunnel access log parsing ---

type ztunnelAccessEntry struct {
	Direction   string // outbound | inbound
	SrcIP       string
	SrcPort     int
	DstIP       string
	DstPort     int
	DstService  string
	SrcIdentity string
	ErrorText   string
	RawLine     string
}

var (
	ztDirectionRe = regexp.MustCompile(`\bdirection=(outbound|inbound)\b`)
	ztSrcAddrRe   = regexp.MustCompile(`\bsrc\.addr=([0-9a-fA-F:.\[\]]+):(\d+)`)
	ztDstAddrRe   = regexp.MustCompile(`\bdst\.addr=([0-9a-fA-F:.\[\]]+):(\d+)`)
	ztDstSvcRe    = regexp.MustCompile(`\bdst\.service=([^\s]+)`)
	ztSrcIdentRe  = regexp.MustCompile(`\bsrc\.identity="([^"]+)"`)
	ztErrorRe     = regexp.MustCompile(`\berror="([^"]+)"`)
)

// ParseZtunnelAccessLogs parses structured ztunnel access log lines involving targetPodIP.
func ParseZtunnelAccessLogs(logs, targetPodIP string) []ztunnelAccessEntry {
	if targetPodIP == "" || logs == "" {
		return nil
	}
	var out []ztunnelAccessEntry
	for _, raw := range strings.Split(logs, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.Contains(line, targetPodIP) {
			continue
		}
		srcM := ztSrcAddrRe.FindStringSubmatch(line)
		dstM := ztDstAddrRe.FindStringSubmatch(line)
		if len(srcM) < 3 || len(dstM) < 3 {
			continue
		}
		srcIP := strings.Trim(srcM[1], "[]")
		dstIP := strings.Trim(dstM[1], "[]")
		srcPort, _ := strconv.Atoi(srcM[2])
		dstPort, _ := strconv.Atoi(dstM[2])

		dir := ""
		if dm := ztDirectionRe.FindStringSubmatch(line); len(dm) >= 2 {
			dir = dm[1]
		} else if srcIP == targetPodIP {
			dir = "outbound"
		} else if dstIP == targetPodIP {
			dir = "inbound"
		} else {
			continue
		}
		if (dir == "outbound" && srcIP != targetPodIP) || (dir == "inbound" && dstIP != targetPodIP) {
			continue
		}
		if isNoisePort(dstPort) {
			continue
		}
		entry := ztunnelAccessEntry{
			Direction: dir,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			RawLine:   line,
		}
		if m := ztDstSvcRe.FindStringSubmatch(line); len(m) >= 2 {
			entry.DstService = strings.Trim(m[1], `"`)
		}
		if m := ztSrcIdentRe.FindStringSubmatch(line); len(m) >= 2 {
			entry.SrcIdentity = strings.TrimPrefix(m[1], "spiffe://")
		}
		if m := ztErrorRe.FindStringSubmatch(line); len(m) >= 2 {
			entry.ErrorText = m[1]
		}
		out = append(out, entry)
	}
	return out
}

// discoverStaticFlows adds flows known purely from Kubernetes/Istio config:
//   - Operator RBAC -> kube-apiserver:6443
//   - WebhookConfigurations targeting a Service backed by this pod -> inbound from kube-apiserver
//   - Ingress Gateway attached Routes -> outbound backend Services
//   - Waypoint ServiceEntries -> outbound ServiceEntries + inbound from sender namespaces
func discoverStaticFlows(ctx context.Context, c *k8s.Client, target TargetInfo, idx *ClusterIndex) []Flow {
	var flows []Flow
	ns := target.Namespace.Metadata.Name

	// 1. Operator with API RBAC -> kube-apiserver:6443
	if target.HasAPIRBAC {
		flows = append(flows, Flow{
			Direction: "outbound",
			Peer:      idx.kubeAPIServerEndpoint(),
			Sources:   []string{"static-rbac"},
		})
	}

	// 2. Webhooks targeting any Service backed by this pod -> inbound from kube-apiserver
	if whs, err := c.ListWebhookConfigurations(ctx); err == nil {
		podIP := target.Pod.Status.PodIP
		for _, wh := range whs {
			for _, hook := range wh.Webhooks {
				if hook.ClientConfig.Service == nil {
					continue
				}
				svcRef := hook.ClientConfig.Service
				if svcRef.Namespace != ns {
					continue
				}
				svc, ok := idx.ServicesByKey[ns+"/"+svcRef.Name]
				if !ok {
					continue
				}
				if !podMatchesService(target.Pod, svc, podIP, idx.EndpointsByKey[ns+"/"+svcRef.Name]) {
					continue
				}
				port := 443
				if svcRef.Port != nil && *svcRef.Port > 0 {
					port = *svcRef.Port
				}
				// Resolve Service port -> targetPort if numeric
				for _, sp := range svc.Spec.Ports {
					if sp.Port == port {
						if _, tp := k8s.ParsePortRaw(sp.TargetPort); tp > 0 {
							port = tp
						}
						break
					}
				}
				apiEP := idx.kubeAPIServerEndpoint()
				apiEP.Port = port
				flows = append(flows, Flow{
					Direction: "inbound",
					Peer:      apiEP,
					LocalPort: port,
					Sources:   []string{"webhook:" + wh.Metadata.Name},
				})
			}
		}
	}

	// 3. Ingress Gateway -> attached Routes backends + istiod 15012 + CoreDNS
	if target.WorkloadKind == WorkloadIngressGateway {
		gwName := target.Pod.Metadata.Labels[common.LabelGatewayName]
		routeKinds := []string{
			"httproutes.gateway.networking.k8s.io",
			"grpcroutes.gateway.networking.k8s.io",
			"tlsroutes.gateway.networking.k8s.io",
			"tcproutes.gateway.networking.k8s.io",
			"udproutes.gateway.networking.k8s.io",
		}
		for _, kindRes := range routeKinds {
			rts, err := c.ListRoutes(ctx, kindRes, ns)
			if err != nil {
				continue
			}
			for _, rt := range rts {
				attached := false
				for _, pr := range rt.Spec.ParentRefs {
					pNS := pr.Namespace
					if pNS == "" {
						pNS = rt.Metadata.Namespace
					}
					if pr.Name == gwName && pNS == ns {
						attached = true
						break
					}
				}
				if !attached {
					continue
				}
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
						var ep Endpoint
						if svc, ok := idx.ServicesByKey[bNS+"/"+br.Name]; ok {
							ep = idx.endpointFromService(svc, br.Port, proto)
						} else {
							ep = Endpoint{
								Kind:        PeerService,
								Namespace:   bNS,
								ServiceName: br.Name,
								Port:        br.Port,
								Protocol:    proto,
								Ambient:     idx.namespaceAmbient(bNS),
							}
						}
						flows = append(flows, Flow{
							Direction: "outbound",
							Peer:      ep,
							Sources:   []string{"route:" + rt.Metadata.Name},
						})
					}
				}
			}
		}
		flows = append(flows, Flow{
			Direction: "outbound",
			Peer:      Endpoint{Kind: PeerIstiod, Namespace: "istio-system", ServiceName: "istiod", Port: 15012, Protocol: "TCP"},
			Sources:   []string{"static-gateway"},
		})
	}

	// 4. Waypoint -> bound ServiceEntries (outbound) + sender namespaces (inbound)
	if target.WorkloadKind == WorkloadWaypoint {
		wpName := target.Pod.Metadata.Labels[common.LabelGatewayName]
		if ses, err := c.ListServiceEntries(ctx, ""); err == nil {
			for _, se := range ses {
				seWP := se.Metadata.Labels[common.LabelUseWaypoint]
				seWPNS := se.Metadata.Labels[common.LabelUseWaypointNS]
				if seWPNS == "" {
					seWPNS = se.Metadata.Namespace
				}
				if seWP != wpName || seWPNS != ns {
					continue
				}
				port := 443
				if len(se.Spec.Ports) > 0 {
					port = se.Spec.Ports[0].Number
				}
				vip := ""
				if vips := se.EffectiveVIPs(); len(vips) > 0 {
					vip = vips[0]
				}
				for _, host := range se.Spec.Hosts {
					flows = append(flows, Flow{
						Direction: "outbound",
						Peer: Endpoint{
							Kind:      PeerServiceEntry,
							Namespace: se.Metadata.Namespace,
							Hostname:  host,
							IP:        vip,
							Port:      port,
							Protocol:  "TCP",
						},
						Sources: []string{"service-entry:" + se.Metadata.Namespace + "/" + se.Metadata.Name},
					})
				}
			}
		}
		flows = append(flows, Flow{
			Direction: "outbound",
			Peer:      Endpoint{Kind: PeerIstiod, Namespace: "istio-system", ServiceName: "istiod", Port: 15012, Protocol: "TCP"},
			Sources:   []string{"static-waypoint"},
		})
	}

	return flows
}

func podMatchesService(pod k8s.Pod, svc k8s.Service, podIP string, ep k8s.Endpoints) bool {
	if len(svc.Spec.Selector) > 0 && matchesMap(svc.Spec.Selector, pod.Metadata.Labels) {
		return true
	}
	if podIP != "" {
		for _, sub := range ep.Subsets {
			for _, a := range sub.Addresses {
				if a.IP == podIP {
					return true
				}
			}
		}
	}
	return false
}

func matchesMap(want, have map[string]string) bool {
	if len(want) == 0 {
		return false
	}
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
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

func containsStr(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
