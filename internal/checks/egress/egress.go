package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/awbait/debug-toolbox/internal/checks/common"
	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/probe"
	"github.com/awbait/debug-toolbox/internal/report"
)

// Options configures an egress-gateway diagnostic run.
type Options struct {
	Version      string
	Namespace    string // may be senders NS, waypoint NS, or VEG NS
	Name         string // optional VEG/Gateway/ServiceEntry filter
	Since        string
	Probe        bool
	ToolboxImage string
	ProxyURL     string // optional corporate proxy e.g. http://10.192.95.164:8090
	Verbose      bool
}

type topology struct {
	Mode       string // "mesh" | "direct"
	VEG        *k8s.VpcEgressGateway
	Waypoint   *k8s.Gateway
	Entries    []k8s.ServiceEntry
	SenderNSs  []string
	AllClusterSEs []k8s.ServiceEntry
}

// Run performs end-to-end diagnostics for egress-gateway (mesh and direct modes).
func Run(ctx context.Context, c *k8s.Client, opts Options) *report.Report {
	if opts.Since == "" {
		opts.Since = "15m"
	}
	r := report.New(opts.Version, "egress", opts.Namespace, opts.Name, opts.Probe)

	// Layer 1: Control plane
	ztunnelNS, ztunnelPods := common.CheckControlPlane(ctx, c, r, false)

	// Discover connected egress resources (senders NS <-> waypoint NS <-> VEG NS)
	allSEs, errSE := c.ListServiceEntries(ctx, "")
	allGWs, errGW := c.ListGateways(ctx, "")
	allVEGs, errVEG := c.ListVpcEgressGateways(ctx, "")
	allSubnets, _ := c.ListSubnets(ctx)

	if errSE != nil && errGW != nil && errVEG != nil {
		r.Fail("egress-discovery", "Discovery", "ns/"+opts.Namespace, "Egress resource discovery",
			fmt.Sprintf("failed to list ServiceEntry/Gateway/VpcEgressGateway: %v", errVEG),
			"Verify cluster connectivity and RBAC permissions")
		r.Finalize(c.Runner.History(), opts.Verbose)
		return r
	}

	topo := discoverTopology(opts.Namespace, opts.Name, allSEs, allGWs, allVEGs, allSubnets)
	if topo.VEG == nil && topo.Waypoint == nil && len(topo.Entries) == 0 {
		r.Fail("egress-not-found", "Discovery", "ns/"+opts.Namespace, "Egress Gateway discovery",
			fmt.Sprintf("no egress-gateway resources (VpcEgressGateway, istio-waypoint Gateway, or waypoint-bound ServiceEntry) linked to namespace %q", opts.Namespace),
			"Pass the senders namespace, waypoint namespace, or VEG namespace with -n <ns>")
		r.Finalize(c.Runner.History(), opts.Verbose)
		return r
	}

	r.Mode = topo.Mode
	r.Metadata["mode"] = topo.Mode
	if topo.VEG != nil {
		r.Metadata["veg"] = topo.VEG.Metadata.Namespace + "/" + topo.VEG.Metadata.Name
	}
	if topo.Waypoint != nil {
		r.Metadata["waypoint"] = topo.Waypoint.Metadata.Namespace + "/" + topo.Waypoint.Metadata.Name
	}
	if len(topo.SenderNSs) > 0 {
		r.Metadata["senders"] = strings.Join(topo.SenderNSs, ",")
	}
	r.Info("egress-topology", "Discovery", "ns/"+opts.Namespace, "Discovered egress topology",
		fmt.Sprintf("mode=%s, senders=%v, waypoint=%s, veg=%s, serviceEntries=%d",
			topo.Mode, topo.SenderNSs, gwLabel(topo.Waypoint), vegLabel(topo.VEG), len(topo.Entries)))

	// Map namespace -> Subnet(s) and subnetName -> Subnet
	subnetByName := make(map[string]k8s.Subnet)
	subnetsByNS := make(map[string][]k8s.Subnet)
	for _, sn := range allSubnets {
		subnetByName[sn.Metadata.Name] = sn
		for _, ns := range sn.Spec.Namespaces {
			subnetsByNS[ns] = append(subnetsByNS[ns], sn)
		}
	}

	// Track ambient status of involved namespaces
	ambientNS := make(map[string]bool)
	senderNodes := make(map[string]bool)
	logTokens := make([]string, 0, 8)

	// --- Layer 2: Senders Namespaces & Subnets ---
	const nsLayer = "Namespaces & Subnets"
	for _, sNS := range topo.SenderNSs {
		nsInfo, err := common.CheckNamespaceMesh(ctx, c, r, nsLayer, sNS, topo.Mode == "mesh")
		if err == nil {
			ambientNS[sNS] = nsInfo.AmbientEnabled
			if topo.Mode == "direct" && nsInfo.AmbientEnabled {
				r.Fail("direct-vs-ambient-"+sNS, nsLayer, "ns/"+sNS, "Direct egress vs Ambient conflict",
					fmt.Sprintf("namespace %s has istio.io/dataplane-mode=ambient AND uses direct VpcEgressGateway — OVN rule 29100 will hijack 169.254.7.127 kubelet host-probes!", sNS),
					"Direct VEG mode is incompatible with ambient mesh: switch egress-gateway to mode: mesh or disable ambient on "+sNS)
			}
		}

		// Senders pods
		sPods, err := c.ListPods(ctx, sNS, "")
		if err == nil {
			if topo.Mode == "mesh" {
				common.CheckPodsRedirection(r, nsLayer, sNS, sPods, ambientNS[sNS])
			}
			for _, p := range sPods {
				if p.Spec.NodeName != "" {
					senderNodes[p.Spec.NodeName] = true
				}
				if p.Status.PodIP != "" {
					logTokens = append(logTokens, p.Status.PodIP)
				}
			}
		}

		// Senders subnet check in direct mode
		if topo.Mode == "direct" {
			for _, sn := range subnetsByNS[sNS] {
				if sn.Spec.Private && len(sn.Spec.AllowSubnets) == 0 {
					r.Fail("subnet-private-"+sn.Metadata.Name, nsLayer, "subnet/"+sn.Metadata.Name,
						"Senders Subnet isolation (direct mode)",
						fmt.Sprintf("Subnet %s has private=true and empty allowSubnets — OVN switch ACL drops external traffic before VEG rule 29100", sn.Metadata.Name),
						"Set private: false or add target external CIDRs to allowSubnets")
				} else {
					r.Pass("subnet-senders-"+sn.Metadata.Name, nsLayer, "subnet/"+sn.Metadata.Name,
						"Senders Subnet", fmt.Sprintf("cidr=%s, private=%v", sn.Spec.CIDRBlock, sn.Spec.Private))
				}
			}
		}
	}

	// --- Layer 3: VpcEgressGateway Invariants & Pods ---
	var vegPods []k8s.Pod
	var wpPods []k8s.Pod
	if topo.VEG != nil {
		vegPods = checkVpcEgressGateway(ctx, c, r, *topo.VEG, allVEGs, subnetByName, subnetsByNS, ambientNS, topo.Mode)
	} else if misaligned, matchedSenders := findMisalignedMeshVEG(topo, allVEGs, subnetsByNS); misaligned != nil {
		reportMisalignedMeshVEG(r, *misaligned, *topo.Waypoint, matchedSenders)
		// Still inspect the misaligned VEG (subnets, externalIPs, pod IPAM events, ambient capture)
		// so all root causes surface in a single run.
		vegPods = checkVpcEgressGateway(ctx, c, r, *misaligned, allVEGs, subnetByName, subnetsByNS, ambientNS, topo.Mode)
	} else {
		r.Warn("veg-missing", "VpcEgressGateway", "ns/"+opts.Namespace, "VpcEgressGateway",
			"no VpcEgressGateway found selecting this waypoint/namespace (external traffic will exit via node SNAT, not a fixed VIP)",
			"Verify VpcEgressGateway resource exists and selectors/policies match")
	}

	// --- Layer 4: Mesh Mode (ServiceEntries, VIP Collisions, Waypoint Gateway & Envoy) ---
	if topo.Mode == "mesh" {
		checkServiceEntriesAndVIPs(ctx, c, r, topo, &logTokens)
		if topo.Waypoint != nil {
			wpPods = checkWaypointAndEnvoy(ctx, c, r, *topo.Waypoint, topo, subnetsByNS)
		} else {
			r.Fail("wp-missing", "Waypoint", "ns/"+opts.Namespace, "Waypoint Gateway",
				"mode=mesh but target waypoint Gateway was not found",
				"Check istio.io/use-waypoint and istio.io/use-waypoint-namespace labels on ServiceEntry")
		}
		checkEgressPolicies(ctx, c, r, topo)
	}

	// --- Layer 5: Kube-OVN Live Router & VEG Runtime ---
	if topo.VEG != nil {
		CheckOVNAndVEGRuntime(ctx, c, r, *topo.VEG, vegPods, wpPods, topo.Mode)
	}

	// --- Layer 6: ztunnel Logs ---
	if topo.Mode == "mesh" {
		common.InspectZtunnelForNodes(ctx, c, r, "Logs & ztunnel", ztunnelNS, ztunnelPods, senderNodes, logTokens, opts.Since)
	}

	// --- Layer 7: Active Probes (--probe) ---
	if opts.Probe {
		runEgressProbes(ctx, c, r, topo, opts)
	}

	r.Finalize(c.Runner.History(), opts.Verbose)
	return r
}

func discoverTopology(
	ns, nameFilter string,
	allSEs []k8s.ServiceEntry,
	allGWs []k8s.Gateway,
	allVEGs []k8s.VpcEgressGateway,
	allSubnets []k8s.Subnet,
) topology {
	topo := topology{
		Mode:          "mesh",
		AllClusterSEs: allSEs,
	}

	// Index waypoints (gatewayClassName: istio-waypoint)
	wpByKey := make(map[string]k8s.Gateway)
	for _, gw := range allGWs {
		if gw.Spec.GatewayClassName == "istio-waypoint" {
			wpByKey[gw.Metadata.Namespace+"/"+gw.Metadata.Name] = gw
		}
	}

	// Index subnet -> namespaces
	subnetNSs := make(map[string][]string)
	for _, sn := range allSubnets {
		subnetNSs[sn.Metadata.Name] = sn.Spec.Namespaces
	}

	// 1. Check if ns has a VpcEgressGateway
	for i := range allVEGs {
		v := allVEGs[i]
		if v.Metadata.Namespace == ns && (nameFilter == "" || v.Metadata.Name == nameFilter) {
			topo.VEG = &v
			break
		}
	}

	// 2. Check if ns has a waypoint Gateway
	for _, gw := range wpByKey {
		if gw.Metadata.Namespace == ns && (nameFilter == "" || gw.Metadata.Name == nameFilter) {
			g := gw
			topo.Waypoint = &g
			break
		}
	}

	// 3. Check if ns has ServiceEntries bound to a waypoint
	for _, se := range allSEs {
		if se.Metadata.Namespace == ns && se.Metadata.Labels[common.LabelUseWaypoint] != "" {
			if nameFilter != "" && se.Metadata.Name != nameFilter && se.Metadata.Labels[common.LabelUseWaypoint] != nameFilter {
				continue
			}
			wpName := se.Metadata.Labels[common.LabelUseWaypoint]
			wpNS := se.Metadata.Labels[common.LabelUseWaypointNS]
			if wpNS == "" {
				wpNS = se.Metadata.Namespace
			}
			if gw, ok := wpByKey[wpNS+"/"+wpName]; ok && topo.Waypoint == nil {
				g := gw
				topo.Waypoint = &g
			}
		}
	}

	// 4. If we found a VEG first, check if it selects a waypoint (mesh) or senders directly (direct)
	if topo.VEG != nil && topo.Waypoint == nil {
		if gw := findWaypointSelectedByVEG(*topo.VEG, wpByKey); gw != nil {
			topo.Waypoint = gw
		} else {
			topo.Mode = "direct"
		}
	}

	// 5. If we found a Waypoint, find the VEG that selects it
	if topo.Waypoint != nil && topo.VEG == nil {
		for i := range allVEGs {
			if vegSelectsWaypoint(allVEGs[i], *topo.Waypoint) {
				v := allVEGs[i]
				topo.VEG = &v
				break
			}
		}
	}

	// 6. If still nothing found, check if ns is targeted by a direct-mode VEG (via policies.subnets or selectors)
	if topo.VEG == nil && topo.Waypoint == nil {
		for i := range allVEGs {
			v := allVEGs[i]
			if nameFilter != "" && v.Metadata.Name != nameFilter {
				continue
			}
			if vegTargetsNamespace(v, ns, subnetNSs) {
				topo.VEG = &v
				if gw := findWaypointSelectedByVEG(v, wpByKey); gw != nil {
					topo.Waypoint = gw
					topo.Mode = "mesh"
				} else {
					topo.Mode = "direct"
				}
				break
			}
		}
	}

	// 7. Collect all ServiceEntries bound to the discovered Waypoint & all sender namespaces
	senderSet := make(map[string]bool)
	if topo.Waypoint != nil {
		topo.Mode = "mesh"
		for _, se := range allSEs {
			wpName := se.Metadata.Labels[common.LabelUseWaypoint]
			wpNS := se.Metadata.Labels[common.LabelUseWaypointNS]
			if wpNS == "" {
				wpNS = se.Metadata.Namespace
			}
			if wpName == topo.Waypoint.Metadata.Name && wpNS == topo.Waypoint.Metadata.Namespace {
				topo.Entries = append(topo.Entries, se)
				senderSet[se.Metadata.Namespace] = true
			}
		}
	} else if topo.VEG != nil {
		topo.Mode = "direct"
		for _, sel := range topo.VEG.Spec.Selectors {
			if sel.NamespaceSelector != nil {
				if n := sel.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]; n != "" {
					senderSet[n] = true
				}
			}
		}
		for _, pol := range topo.VEG.Spec.Policies {
			for _, snName := range pol.Subnets {
				for _, n := range subnetNSs[snName] {
					senderSet[n] = true
				}
			}
		}
		if len(senderSet) == 0 && ns != topo.VEG.Metadata.Namespace {
			senderSet[ns] = true
		}
	}

	// If user passed a senders NS that had SEs even when waypoint object is missing:
	if len(topo.Entries) == 0 && topo.Mode == "mesh" {
		for _, se := range allSEs {
			if se.Metadata.Namespace == ns && se.Metadata.Labels[common.LabelUseWaypoint] != "" {
				topo.Entries = append(topo.Entries, se)
				senderSet[ns] = true
			}
		}
	}

	for s := range senderSet {
		topo.SenderNSs = append(topo.SenderNSs, s)
	}
	sort.Strings(topo.SenderNSs)
	return topo
}

func checkVpcEgressGateway(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	veg k8s.VpcEgressGateway,
	allVEGs []k8s.VpcEgressGateway,
	subnetByName map[string]k8s.Subnet,
	subnetsByNS map[string][]k8s.Subnet,
	ambientNS map[string]bool,
	mode string,
) []k8s.Pod {
	const layer = "VpcEgressGateway"
	vegNS := veg.Metadata.Namespace
	vegRes := vegNS + "/" + veg.Metadata.Name

	// 1. VEG namespace MUST NEVER have ambient enabled!
	nsObj, err := c.GetNamespace(ctx, vegNS)
	if err == nil {
		if nsObj.Metadata.Labels[common.LabelDataplaneMode] == "ambient" {
			r.Fail("veg-ns-ambient", layer, "ns/"+vegNS, "VEG namespace ambient exclusion",
				fmt.Sprintf("VEG namespace %s has istio.io/dataplane-mode=ambient! Ambient interception breaks transit eth0/net1 SNAT pods (TLS hangs after ClientHello)", vegNS),
				"Move VpcEgressGateway into a dedicated non-mesh namespace (serviceMesh.never=true) and ensure Kyverno sets istio.io/dataplane-mode: none on VEG pods")
		} else {
			r.Pass("veg-ns-ambient", layer, "ns/"+vegNS, "VEG namespace ambient exclusion",
				"VEG namespace is outside ambient mesh")
		}
	}

	// 2. VEG namespace subnet must be non-private (private: false)
	for _, sn := range subnetsByNS[vegNS] {
		if sn.Spec.Private {
			r.Fail("veg-subnet-private", layer, "subnet/"+sn.Metadata.Name, "VEG Subnet private=false",
				fmt.Sprintf("VEG namespace subnet %s has private=true (OVN ACL drops external egress)", sn.Metadata.Name),
				"Set private: false on VEG namespace subnet")
		} else {
			r.Pass("veg-subnet-private", layer, "subnet/"+sn.Metadata.Name, "VEG Subnet",
				fmt.Sprintf("cidr=%s, private=false", sn.Spec.CIDRBlock))
		}
	}

	// 3. Critical filestash invariant: selectors[] must combine namespaceSelector AND podSelector in one item
	for i, sel := range veg.Spec.Selectors {
		if sel.NamespaceSelector != nil && sel.PodSelector == nil {
			r.Fail(fmt.Sprintf("veg-selector-split-%d", i), layer, vegRes, "VEG selectors AND/OR invariant",
				fmt.Sprintf("spec.selectors[%d] has namespaceSelector WITHOUT podSelector! Kube-OVN ORs list items, so this captures EVERY pod in the namespace (hijacking 169.254.7.127 kubelet probes!)", i),
				"Combine namespaceSelector and podSelector into a SINGLE element of spec.selectors[]")
		}
	}

	// 4. Critical invariant: policies.subnets must NOT exist in mesh mode or point to nonexistent/ambient subnets
	if mode == "mesh" && len(veg.Spec.Policies) > 0 {
		r.Fail("veg-policies-in-mesh", layer, vegRes, "VEG spec.policies in mesh mode",
			"VpcEgressGateway defines spec.policies in mesh mode — this captures entire pod subnets and breaks ambient 169.254.7.127 kubelet host-probes",
			"Remove spec.policies in mesh mode; use spec.selectors targeting only waypoint pods (init script enables MASQUERADE automatically)")
	}
	for _, pol := range veg.Spec.Policies {
		for _, snName := range pol.Subnets {
			sn, exists := subnetByName[snName]
			if !exists {
				r.Fail("veg-subnet-missing-"+snName, layer, vegRes, "VEG referenced Subnet",
					fmt.Sprintf("spec.policies references Subnet %q which does NOT exist in cluster (causes kube-ovn-controller reconcile loop errors)", snName),
					"Fix senders.subnet to an existing Kube-OVN Subnet name")
				continue
			}
			for _, n := range sn.Spec.Namespaces {
				if ambientNS[n] {
					r.Fail("veg-policy-ambient-"+snName, layer, vegRes, "VEG policy vs ambient namespace",
						fmt.Sprintf("spec.policies.subnets includes %q containing ambient namespace %q — kubelet 169.254.7.127 probes will time out!", snName, n),
						"Do not capture an ambient-enabled subnet via VEG policies.subnets; use mode: mesh with waypoint")
				}
			}
		}
	}

	// 5. VEG CR status, externalSubnet/externalIPs validation & replicas vs externalIPs
	if len(veg.Spec.ExternalIPs) == 0 {
		r.Fail("veg-ips", layer, vegRes, "VEG externalIPs", "spec.externalIPs is empty", "Configure externalIPs in vpcEgressGateway")
	} else if veg.Spec.Replicas != len(veg.Spec.ExternalIPs) {
		r.Warn("veg-replicas", layer, vegRes, "VEG replicas vs externalIPs",
			fmt.Sprintf("replicas=%d differs from len(externalIPs)=%d", veg.Spec.Replicas, len(veg.Spec.ExternalIPs)),
			"Align spec.replicas with the number of externalIPs")
	}
	checkVEGSubnetsAndIPs(r, layer, veg, allVEGs, subnetByName, subnetsByNS)

	if veg.Status.Ready {
		r.Pass("veg-status", layer, vegRes, "VpcEgressGateway status",
			fmt.Sprintf("Ready=true, externalIPs=%v, externalSubnet=%s", veg.Spec.ExternalIPs, veg.Spec.ExternalSubnet))
	} else {
		r.Fail("veg-status", layer, vegRes, "VpcEgressGateway status",
			fmt.Sprintf("Ready=%v (phase=%q), externalIPs=%v", veg.Status.Ready, veg.Status.Phase, veg.Spec.ExternalIPs),
			"Check kube-ovn-controller logs, externalSubnet ("+veg.Spec.ExternalSubnet+"), nodeSelector/tolerations, and VEG pods in "+vegNS)
	}

	// 6. VEG pods & ambient redirection check (CRITICAL filestash cause #2!)
	vegPods, err := c.ListPods(ctx, vegNS, common.LabelVEG+"="+veg.Metadata.Name)
	if err != nil || len(vegPods) == 0 {
		vegPods, _ = c.ListPods(ctx, vegNS, "app=vpc-egress-gateway")
	}
	if len(vegPods) == 0 {
		checkVEGPodEvents(ctx, c, r, layer, veg, subnetByName)
		r.Fail("veg-pods", layer, vegRes, "VEG pods",
			fmt.Sprintf("0 VEG pods found in namespace %s", vegNS),
			"Check VEG Deployment, ResourceQuota (LimitRange), PodSecurity (needs privileged), and nodeSelector/tolerations")
		return nil
	}

	ready := 0
	var captured []string
	for _, p := range vegPods {
		if p.IsReady() {
			ready++
		}
		if p.Metadata.Annotations[common.AnnotRedirection] == "enabled" {
			captured = append(captured, fmt.Sprintf("%s (redirection=enabled, dataplane-mode=%q)",
				p.Metadata.Name, p.Metadata.Labels[common.LabelDataplaneMode]))
		}
	}
	if len(captured) > 0 {
		r.Fail("veg-pod-captured", layer, vegRes, "VEG pod ambient capture (CRITICAL)",
			fmt.Sprintf("%d VEG pod(s) have ambient.istio.io/redirection=enabled! ztunnel intercepts transit traffic and breaks eth0/net1 replies (TLS hangs after ClientHello)", len(captured)),
			"Remove ambient label from VEG namespace, apply Kyverno ClusterPolicy vpc-egress-gateway-exclude-ambient (istio.io/dataplane-mode: none), and recreate VEG pods",
			captured...)
	} else {
		r.Pass("veg-pod-captured", layer, vegRes, "VEG pod ambient exclusion",
			fmt.Sprintf("all %d VEG pod(s) are free from ambient redirection", len(vegPods)))
	}

	if !veg.Status.Ready || ready < len(vegPods) {
		checkVEGPodEvents(ctx, c, r, layer, veg, subnetByName)
	}

	if ready == 0 {
		r.Fail("veg-pods-ready", layer, vegRes, "VEG pods Ready",
			fmt.Sprintf("0/%d VEG pods Ready", len(vegPods)),
			"Inspect VEG pod events/logs (check Kube-OVN Subnet IPAM, privileged PodSecurity, LimitRange, and Multus net1 attachment)")
	} else if ready < len(vegPods) {
		r.Warn("veg-pods-ready", layer, vegRes, "VEG pods Ready",
			fmt.Sprintf("%d/%d VEG pods Ready", ready, len(vegPods)),
			"Inspect non-ready VEG pods")
	} else {
		r.Pass("veg-pods-ready", layer, vegRes, "VEG pods Ready",
			fmt.Sprintf("%d/%d VEG pods Ready", ready, len(vegPods)))
	}

	return vegPods
}

func checkServiceEntriesAndVIPs(ctx context.Context, c *k8s.Client, r *report.Report, topo topology, logTokens *[]string) {
	const layer = "ServiceEntries & VIPs"

	if len(topo.Entries) == 0 {
		r.Fail("se-none", layer, "ServiceEntry", "ServiceEntries bound to waypoint",
			"0 ServiceEntries bound to this egress waypoint",
			"Verify ServiceEntries have labels istio.io/use-waypoint and istio.io/use-waypoint-namespace")
		return
	}

	wpNS := ""
	if topo.Waypoint != nil {
		wpNS = topo.Waypoint.Metadata.Namespace
	}

	// Track per-hostname entries bound to THIS waypoint (for Istio 1.30.4 shared waypoint VIP collision bug!)
	entriesByHost := make(map[string][]k8s.ServiceEntry)

	for _, se := range topo.Entries {
		res := se.Metadata.Namespace + "/" + se.Metadata.Name
		vips := se.EffectiveVIPs()
		for _, v := range vips {
			*logTokens = append(*logTokens, v)
		}
		for _, h := range se.Spec.Hosts {
			*logTokens = append(*logTokens, h)
			entriesByHost[h] = append(entriesByHost[h], se)
		}

		// Basic spec checks
		var specIssues []string
		if se.Spec.Location != "MESH_EXTERNAL" {
			specIssues = append(specIssues, fmt.Sprintf("location=%q (expected MESH_EXTERNAL)", se.Spec.Location))
		}
		if se.Spec.Resolution != "DNS" && se.Spec.Resolution != "STATIC" {
			specIssues = append(specIssues, fmt.Sprintf("resolution=%q (expected DNS)", se.Spec.Resolution))
		}
		if wpNS != "" && se.Metadata.Namespace != wpNS && len(se.Spec.ExportTo) > 0 {
			hasWP := false
			for _, ex := range se.Spec.ExportTo {
				if ex == "*" || ex == wpNS {
					hasWP = true
					break
				}
			}
			if !hasWP {
				specIssues = append(specIssues, fmt.Sprintf("exportTo=%v does NOT include waypoint namespace %q (waypoint will not build cluster!)", se.Spec.ExportTo, wpNS))
			}
		}

		if len(specIssues) > 0 {
			r.Fail("se-spec-"+se.Metadata.Namespace+"-"+se.Metadata.Name, layer, res,
				fmt.Sprintf("ServiceEntry spec (%v)", se.Spec.Hosts),
				strings.Join(specIssues, "; "),
				"Fix ServiceEntry spec (location: MESH_EXTERNAL, resolution: DNS, exportTo includes '.' and waypoint namespace)")
		} else {
			r.Pass("se-spec-"+se.Metadata.Namespace+"-"+se.Metadata.Name, layer, res,
				fmt.Sprintf("ServiceEntry (%v)", se.Spec.Hosts),
				fmt.Sprintf("VIPs=%v, resolution=%s, exportTo=%v", vips, se.Spec.Resolution, se.Spec.ExportTo))
		}
	}

	// CRITICAL CHECK (from real DBAAS/Observability Nov 2026 incident, chat-003):
	// Multiple ServiceEntries with the SAME hostname bound to the SAME shared waypoint with DIFFERENT VIPs!
	for host, ses := range entriesByHost {
		if len(ses) <= 1 {
			continue
		}
		vipSet := make(map[string][]string)
		for _, se := range ses {
			vips := se.EffectiveVIPs()
			vipKey := strings.Join(vips, ",")
			if vipKey == "" {
				vipKey = "<none>"
			}
			vipSet[vipKey] = append(vipSet[vipKey], se.Metadata.Namespace+"/"+se.Metadata.Name)
		}
		if len(vipSet) > 1 {
			var ev []string
			for vip, owners := range vipSet {
				ev = append(ev, fmt.Sprintf("VIP %s -> %s", vip, strings.Join(owners, ", ")))
			}
			sort.Strings(ev)
			r.Fail("se-shared-wp-vip-split-"+host, layer, host,
				fmt.Sprintf("Shared waypoint VIP split for %s (Istio 1.30.x bug)", host),
				fmt.Sprintf("%d copies of ServiceEntry for %q bind to the SAME waypoint but have %d DIFFERENT VIPs! Istio waypoint collapses services by hostname and only puts ONE VIP in main_internal filter_chain_matcher — other namespaces get 503 / 'no matching filter chain found' even though WaypointAccepted=True!",
					len(ses), host, len(vipSet)),
				"Either assign ONE identical static spec.addresses VIP (outside 240.240.0.0/16, e.g. 240.241.x.y) to all copies of this ServiceEntry, OR deploy one waypoint per sender namespace",
				ev...)
		} else {
			r.Pass("se-shared-wp-vip-sync-"+host, layer, host,
				fmt.Sprintf("Shared waypoint VIP consistency (%s)", host),
				fmt.Sprintf("all %d ServiceEntry copies share identical VIP(s)", len(ses)))
		}
	}

	// Cluster-wide VIP collision check: same VIP used by DIFFERENT hosts or DIFFERENT waypoints
	type vipOwner struct {
		Host     string
		Waypoint string
		SE       string
	}
	byVIP := make(map[string][]vipOwner)
	for _, se := range topo.AllClusterSEs {
		wp := se.Metadata.Labels[common.LabelUseWaypointNS] + "/" + se.Metadata.Labels[common.LabelUseWaypoint]
		hostKey := strings.Join(se.Spec.Hosts, ",")
		for _, vip := range se.EffectiveVIPs() {
			byVIP[vip] = append(byVIP[vip], vipOwner{
				Host:     hostKey,
				Waypoint: wp,
				SE:       se.Metadata.Namespace + "/" + se.Metadata.Name,
			})
		}
	}
	for _, se := range topo.Entries {
		for _, vip := range se.EffectiveVIPs() {
			owners := byVIP[vip]
			if len(owners) <= 1 {
				continue
			}
			first := owners[0]
			conflict := false
			var desc []string
			for _, o := range owners {
				desc = append(desc, fmt.Sprintf("%s (hosts=%s, wp=%s)", o.SE, o.Host, o.Waypoint))
				if o.Host != first.Host || o.Waypoint != first.Waypoint {
					conflict = true
				}
			}
			if conflict {
				r.Fail("se-vip-collision-"+vip, layer, vip,
					fmt.Sprintf("Cluster-wide ServiceEntry VIP collision (%s)", vip),
					fmt.Sprintf("VIP %s is shared by ServiceEntries with DIFFERENT hosts or waypoints — ztunnel keys services by VIP and will misroute traffic!", vip),
					"Assign unique static spec.addresses per (egress-gateway instance, hostname) pair",
					desc...)
			}
		}
	}
}

func checkWaypointAndEnvoy(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	wp k8s.Gateway,
	topo topology,
	subnetsByNS map[string][]k8s.Subnet,
) []k8s.Pod {
	const layer = "Waypoint & Envoy"
	wpNS := wp.Metadata.Namespace
	wpName := wp.Metadata.Name
	wpRes := wpNS + "/" + wpName

	// 1. Waypoint namespace mesh & subnet
	_, _ = common.CheckNamespaceMesh(ctx, c, r, layer, wpNS, true)
	for _, sn := range subnetsByNS[wpNS] {
		if sn.Spec.Private {
			r.Fail("wp-subnet-private", layer, "subnet/"+sn.Metadata.Name, "Waypoint Subnet private=false",
				fmt.Sprintf("Waypoint namespace subnet %s has private=true — OVN switch ACL drops external egress before VEG!", sn.Metadata.Name),
				"Set private: false on waypoint namespace subnet")
		} else {
			r.Pass("wp-subnet-private", layer, "subnet/"+sn.Metadata.Name, "Waypoint Subnet",
				fmt.Sprintf("cidr=%s, private=false", sn.Spec.CIDRBlock))
		}
	}

	// 2. Waypoint Gateway conditions
	prog, ok := k8s.FindCondition(wp.Status.Conditions, "Programmed")
	if ok && prog.Status != "True" {
		r.Fail("wp-programmed", layer, wpRes, "Waypoint Gateway status",
			fmt.Sprintf("Programmed=%s (%s): %s", prog.Status, prog.Reason, prog.Message),
			"Check istiod logs and waypoint deployment in "+wpNS)
	} else {
		r.Pass("wp-programmed", layer, wpRes, "Waypoint Gateway status", "Programmed=True")
	}

	// 3. Check allowedRoutes admits all cross-namespace senders
	var crossSenders []string
	for _, s := range topo.SenderNSs {
		if s != wpNS {
			crossSenders = append(crossSenders, s)
		}
	}
	if len(crossSenders) > 0 {
		var missingAllowed []string
		for _, s := range crossSenders {
			if !waypointAllowsSenderNS(wp, s) {
				missingAllowed = append(missingAllowed, s)
			}
		}
		if len(missingAllowed) > 0 {
			r.Fail("wp-allowed-routes", layer, wpRes, "Waypoint allowedRoutes for cross-NS senders",
				fmt.Sprintf("waypoint listener does NOT admit sender namespace(s): %v", missingAllowed),
				"Add all sender namespaces to waypointNamespace.waypoint.waypoints[].allowedNamespaces (allowedRoutes.namespaces.from=Selector)")
		} else {
			r.Pass("wp-allowed-routes", layer, wpRes, "Waypoint allowedRoutes",
				fmt.Sprintf("admits all %d cross-namespace sender(s): %v", len(crossSenders), crossSenders))
		}
	}

	// 4. Waypoint pods
	wpPods, err := c.ListPods(ctx, wpNS, common.LabelGatewayName+"="+wpName)
	if err != nil || len(wpPods) == 0 {
		r.Fail("wp-pods", layer, wpRes, "Waypoint pods",
			fmt.Sprintf("0 pods found with label %s=%s in %s", common.LabelGatewayName, wpName, wpNS),
			"Check waypoint Deployment, ResourceQuota, and PodSecurity (needs baseline) in "+wpNS)
		return nil
	}

	readyPods := make([]k8s.Pod, 0, len(wpPods))
	for _, p := range wpPods {
		if p.IsReady() {
			readyPods = append(readyPods, p)
		}
	}
	if len(readyPods) == 0 {
		r.Fail("wp-pods", layer, wpRes, "Waypoint pods",
			fmt.Sprintf("0/%d waypoint pods Ready", len(wpPods)),
			"Inspect waypoint pod logs and events in "+wpNS)
		return wpPods
	}
	r.Pass("wp-pods", layer, wpRes, "Waypoint pods", fmt.Sprintf("%d/%d pods Ready", len(readyPods), len(wpPods)))

	wpPod := readyPods[0]

	// 5. Inspect live Envoy `main_internal` listener VIPs via istioctl pc listener (catches chat-003 VIP drop live!)
	if res, err := c.Istioctl(ctx, "pc", "listener", wpPod.Metadata.Name+"."+wpNS, "--name", "main_internal", "-o", "json"); err == nil {
		matcherVIPs := extractAddressPrefixes(res.Stdout)
		if len(matcherVIPs) > 0 {
			var missingVIPs []string
			for _, se := range topo.Entries {
				for _, vip := range se.EffectiveVIPs() {
					if !matcherVIPs[vip] {
						missingVIPs = append(missingVIPs, fmt.Sprintf("%s/%s (%v) VIP=%s", se.Metadata.Namespace, se.Metadata.Name, se.Spec.Hosts, vip))
					}
				}
			}
			if len(missingVIPs) > 0 {
				r.Fail("wp-matcher-vips", layer, wpNS+"/"+wpPod.Metadata.Name,
					"Waypoint main_internal filter_chain_matcher VIPs",
					fmt.Sprintf("%d ServiceEntry VIP(s) are MISSING from live waypoint main_internal matcher (requests to them fail with 503 / no matching filter chain found)!", len(missingVIPs)),
					"Assign one shared static spec.addresses VIP across ServiceEntry copies or use per-namespace waypoints",
					missingVIPs...)
			} else {
				r.Pass("wp-matcher-vips", layer, wpNS+"/"+wpPod.Metadata.Name,
					"Waypoint main_internal filter_chain_matcher VIPs",
					"all ServiceEntry VIPs are present in live Envoy main_internal listener")
			}
		}
	}

	// 6. Inspect live Envoy clusters & stats via pilot-agent (works in distroless waypoint!)
	if clRes, err := c.PodExec(ctx, wpNS, wpPod.Metadata.Name, "", "pilot-agent", "request", "GET", "clusters"); err == nil {
		for _, se := range topo.Entries {
			for _, host := range se.Spec.Hosts {
				var hostLines []string
				var cxFail string
				var cxTotal string
				for _, line := range strings.Split(clRes.Stdout, "\n") {
					if strings.Contains(line, host) {
						if strings.Contains(line, "::cx_total::") {
							cxTotal = strings.TrimSpace(line)
							hostLines = append(hostLines, cxTotal)
						} else if strings.Contains(line, "::cx_connect_fail::") {
							cxFail = strings.TrimSpace(line)
							hostLines = append(hostLines, cxFail)
						} else if strings.Contains(line, "::added_via_api::") {
							hostLines = append(hostLines, strings.TrimSpace(line))
						}
					}
				}
				if len(hostLines) == 0 {
					r.Fail("wp-cluster-"+host, layer, wpNS+"/"+wpPod.Metadata.Name,
						fmt.Sprintf("Waypoint Envoy cluster for %s", host),
						fmt.Sprintf("cluster for %q NOT found in waypoint Envoy (pilot-agent GET clusters)", host),
						"Verify ServiceEntry exportTo includes waypoint namespace, labels use-waypoint/use-waypoint-namespace match, and waypoint allowedRoutes admits sender NS")
				} else if cxFail != "" && !strings.HasSuffix(cxFail, "::0") {
					r.Warn("wp-cluster-"+host, layer, wpNS+"/"+wpPod.Metadata.Name,
						fmt.Sprintf("Waypoint Envoy cluster for %s", host),
						"cluster exists, but cx_connect_fail > 0 (upstream connections failing between waypoint -> VEG -> external host)",
						"Check waypoint -out NetworkPolicy, VEG pod ambient exclusion, OVN 29100 rule, and external firewall",
						hostLines...)
				} else {
					r.Pass("wp-cluster-"+host, layer, wpNS+"/"+wpPod.Metadata.Name,
						fmt.Sprintf("Waypoint Envoy cluster for %s", host),
						"cluster present in Envoy", hostLines...)
				}
			}
		}
	}

	// 7. Scan waypoint pod logs for "no matching filter chain found" / 503 / reset
	if logs, err := c.PodLogs(ctx, wpNS, wpPod.Metadata.Name, "", "15m", 300); err == nil {
		var bad []string
		noChain := false
		for _, raw := range strings.Split(logs, "\n") {
			line := strings.TrimSpace(raw)
			low := strings.ToLower(line)
			if strings.Contains(low, "no matching filter chain") {
				noChain = true
				bad = append(bad, line)
			} else if strings.Contains(low, "503") || strings.Contains(low, "upstream_reset") || strings.Contains(low, "rbac") {
				bad = append(bad, line)
			}
		}
		if noChain {
			if len(bad) > 10 {
				bad = bad[len(bad)-10:]
			}
			r.Fail("wp-logs-no-chain", layer, wpNS+"/"+wpPod.Metadata.Name, "Waypoint Envoy logs",
				"detected 'no matching filter chain found' in waypoint logs (VIP mismatch between client ServiceEntry and waypoint matcher!)",
				"Check duplicate ServiceEntry VIPs above (Istio 1.30.x shared waypoint bug)", bad...)
		} else if len(bad) > 0 {
			if len(bad) > 10 {
				bad = bad[len(bad)-10:]
			}
			r.Warn("wp-logs", layer, wpNS+"/"+wpPod.Metadata.Name, "Waypoint Envoy error logs",
				fmt.Sprintf("found %d error/503/RBAC line(s) in waypoint logs", len(bad)),
				"Inspect waypoint errors above", bad...)
		}
	}

	return wpPods
}

func checkEgressPolicies(ctx context.Context, c *k8s.Client, r *report.Report, topo topology) {
	if topo.Waypoint == nil {
		return
	}
	const layer = "Policies"
	wpNS := topo.Waypoint.Metadata.Namespace
	wpName := topo.Waypoint.Metadata.Name

	// 1. Senders NS Egress NetworkPolicy -> waypoint NS:15008
	for _, sNS := range topo.SenderNSs {
		nps, err := c.ListNetworkPolicies(ctx, sNS)
		if err != nil {
			continue
		}
		var egressNPs []k8s.NetworkPolicy
		for _, np := range nps {
			if hasPolicyType(np, "Egress") {
				egressNPs = append(egressNPs, np)
			}
		}
		if len(egressNPs) == 0 {
			continue
		}
		if allowsEgressToNSPort(egressNPs, wpNS, 15008) {
			r.Pass("egw-np-senders-"+sNS, layer, "ns/"+sNS, "Senders Egress NetworkPolicy -> waypoint:15008",
				fmt.Sprintf("egress from %s to %s:15008 (HBONE) permitted", sNS, wpNS))
		} else {
			r.Fail("egw-np-senders-"+sNS, layer, "ns/"+sNS, "Senders Egress NetworkPolicy -> waypoint:15008",
				fmt.Sprintf("namespace %s has Egress NetworkPolicy, but NONE allows TCP 15008 to waypoint namespace %s!", sNS, wpNS),
				fmt.Sprintf("Enable networkPolicy.senders=true in egress-gateway or add Egress NetworkPolicy allowing %s:15008 in %s", wpNS, sNS))
		}
	}

	// 2. Waypoint NS NetworkPolicies (-in 15008, -out external ports + istiod/DNS)
	wpNPs, err := c.ListNetworkPolicies(ctx, wpNS)
	if err == nil {
		var inNPs, outNPs []k8s.NetworkPolicy
		for _, np := range wpNPs {
			if len(np.Spec.PodSelector.MatchLabels) > 0 &&
				np.Spec.PodSelector.MatchLabels[common.LabelGatewayName] != wpName {
				continue
			}
			if hasPolicyType(np, "Ingress") {
				inNPs = append(inNPs, np)
			}
			if hasPolicyType(np, "Egress") {
				outNPs = append(outNPs, np)
			}
		}
		if len(inNPs) > 0 {
			for _, sNS := range topo.SenderNSs {
				if allowsIngressFromNSPort(inNPs, sNS, 15008) {
					r.Pass("egw-np-in-"+sNS, layer, wpNS+"/"+wpName, "Waypoint Ingress NetworkPolicy",
						fmt.Sprintf("allows TCP 15008 from sender namespace %s", sNS))
				} else {
					r.Fail("egw-np-in-"+sNS, layer, wpNS+"/"+wpName, "Waypoint Ingress NetworkPolicy",
						fmt.Sprintf("waypoint has Ingress NetworkPolicy, but does NOT allow TCP 15008 from %s", sNS),
						fmt.Sprintf("Add sender namespace %s to egress-gateway senders and update -in NetworkPolicy", sNS))
				}
			}
		}
		if len(outNPs) > 0 {
			if !allowsEgressToNSPort(outNPs, "istio-system", 15012) {
				r.Fail("egw-np-out-istiod", layer, wpNS+"/"+wpName, "Waypoint Egress NetworkPolicy -> istiod",
					"waypoint Egress NetworkPolicy does NOT allow istio-system:15012",
					"Allow TCP 15012 to istio-system in waypoint -out NetworkPolicy")
			}
			// Check every ServiceEntry port is covered by some ipBlock egress rule in -out
			checkedPorts := make(map[int]bool)
			for _, se := range topo.Entries {
				for _, p := range se.Spec.Ports {
					if checkedPorts[p.Number] {
						continue
					}
					checkedPorts[p.Number] = true
					if !allowsEgressIPBlockPort(outNPs, p.Number) {
						r.Fail("egw-np-out-port-"+strconv.Itoa(p.Number), layer, wpNS+"/"+wpName,
							fmt.Sprintf("Waypoint Egress NetworkPolicy port %d", p.Number),
							fmt.Sprintf("ServiceEntry uses port %d, but waypoint -out NetworkPolicy has NO ipBlock rule allowing port %d!", p.Number, p.Number),
							fmt.Sprintf("Add external IP/CIDR and port %d to egress-gateway networkPolicy.endpoints[]", p.Number))
					}
				}
			}
		}
	}

	// 3. Waypoint AuthorizationPolicy (targetRefs -> Gateway)
	aps, err := c.ListAuthorizationPolicies(ctx, wpNS)
	if err == nil {
		var wpAPs []k8s.AuthorizationPolicy
		for _, ap := range aps {
			for _, tr := range ap.Spec.TargetRefs {
				if tr.Kind == "Gateway" && tr.Name == wpName {
					wpAPs = append(wpAPs, ap)
					break
				}
			}
		}
		if len(wpAPs) > 0 {
			for _, sNS := range topo.SenderNSs {
				if authzAllowsNS(wpAPs, sNS) {
					r.Pass("egw-ap-"+sNS, layer, wpNS+"/"+wpName, "Waypoint AuthorizationPolicy",
						fmt.Sprintf("ALLOW policy permits sender namespace %s", sNS))
				} else {
					r.Fail("egw-ap-"+sNS, layer, wpNS+"/"+wpName, "Waypoint AuthorizationPolicy",
						fmt.Sprintf("waypoint has AuthorizationPolicy attached, but sender namespace %s is NOT allowed!", sNS),
						fmt.Sprintf("Add %s to AuthorizationPolicy from.source.namespaces (or senders.additionalNamespaces)", sNS))
				}
			}
		}
	}
}

func runEgressProbes(ctx context.Context, c *k8s.Client, r *report.Report, topo topology, opts Options) {
	const layer = "Active Probes"
	if len(topo.SenderNSs) == 0 {
		r.Skip("egw-probe", layer, opts.Namespace, "Egress active probe", "no sender namespace discovered")
		return
	}
	probeNS := topo.SenderNSs[0]
	for _, s := range topo.SenderNSs {
		if s == opts.Namespace {
			probeNS = s
			break
		}
	}

	extraLabels := make(map[string]string)
	if topo.Mode == "direct" && topo.VEG != nil {
		// If VEG uses label scope, attach that label so probe pod routes through VEG!
		for _, sel := range topo.VEG.Spec.Selectors {
			if sel.PodSelector != nil {
				for k, v := range sel.PodSelector.MatchLabels {
					extraLabels[k] = v
				}
			}
		}
	}

	sess, err := probe.Start(ctx, c, probe.Options{
		Namespace:   probeNS,
		Image:       opts.ToolboxImage,
		InMesh:      topo.Mode == "mesh",
		ExtraLabels: extraLabels,
	})
	if err != nil {
		r.Fail("egw-probe-start", layer, "ns/"+probeNS, "Start debug-toolbox probe pod",
			fmt.Sprintf("failed to launch probe pod in %s: %v", probeNS, err),
			"Check --toolbox-image, ResourceQuota, and PodSecurity in "+probeNS)
		return
	}
	defer func() { _ = sess.Close(context.Background()) }()

	// In mesh mode, probe each unique ServiceEntry host:port
	probed := make(map[string]bool)
	for _, se := range topo.Entries {
		for _, host := range se.Spec.Hosts {
			port := 443
			proto := "TLS"
			if len(se.Spec.Ports) > 0 {
				port = se.Spec.Ports[0].Number
				proto = strings.ToUpper(se.Spec.Ports[0].Protocol)
			}
			key := fmt.Sprintf("%s:%d", host, port)
			if probed[key] {
				continue
			}
			probed[key] = true

			ips, err := sess.ResolveDNS(ctx, host)
			if err != nil || len(ips) == 0 {
				r.Fail("egw-probe-dns-"+host, layer, host, fmt.Sprintf("DNS lookup from %s (%s)", probeNS, host),
					fmt.Sprintf("DNS resolution failed: %v", err),
					"Check CoreDNS egress NetworkPolicy and ztunnel DNS proxy")
				continue
			}

			expectedVIPs := se.EffectiveVIPs()
			if len(expectedVIPs) > 0 && !anyIn(ips, expectedVIPs) {
				r.Warn("egw-probe-dns-"+host, layer, host, fmt.Sprintf("DNS VIP check (%s)", host),
					fmt.Sprintf("resolved to %v, expected ServiceEntry VIP %v (traffic may NOT be entering waypoint!)", ips, expectedVIPs),
					"Check that probe pod is captured by ambient (redirection=enabled) and ServiceEntry exists in "+probeNS)
			} else {
				r.Pass("egw-probe-dns-"+host, layer, host, fmt.Sprintf("DNS lookup (%s)", host),
					fmt.Sprintf("resolved to %v (matches ServiceEntry VIP)", ips))
			}

			if proto == "TLS" || proto == "HTTPS" || proto == "HTTP" {
				scheme := "https"
				if proto == "HTTP" {
					scheme = "http"
				}
				cr := sess.HTTPCheck(ctx, scheme, host, port, "", opts.ProxyURL)
				if cr.Err != nil || cr.StatusCode == "" || cr.StatusCode == "000" {
					r.Fail("egw-probe-http-"+host, layer, key, fmt.Sprintf("Egress probe to %s", key),
						fmt.Sprintf("failed (code=%s, time=%s): %v", cr.StatusCode, cr.TimeTotal, cr.Err),
						"Inspect curl trace: 'Connection reset on ClientHello' -> waypoint 503/filter chain; 'hang after ClientHello' -> VEG captured by ambient; 'timeout' -> NetworkPolicy or external firewall",
						cr.Verbose)
				} else {
					r.Pass("egw-probe-http-"+host, layer, key, fmt.Sprintf("Egress probe to %s", key),
						fmt.Sprintf("HTTP %s in %s (ip=%s)", cr.StatusCode, cr.TimeTotal, cr.RemoteIP))
				}
			} else {
				out, err := sess.TCPCheck(ctx, host, port)
				if err != nil {
					r.Fail("egw-probe-tcp-"+host, layer, key, fmt.Sprintf("TCP probe to %s", key),
						fmt.Sprintf("TCP connect failed: %s", out),
						"Check waypoint logs, OVN 29100 policy, VEG pod, and external firewall")
				} else {
					r.Pass("egw-probe-tcp-"+host, layer, key, fmt.Sprintf("TCP probe to %s", key), out)
				}
			}
		}
	}

	// In direct mode with --proxy, test corporate proxy reachability
	if topo.Mode == "direct" && opts.ProxyURL != "" {
		clean := strings.TrimPrefix(strings.TrimPrefix(opts.ProxyURL, "http://"), "https://")
		host, portStr, ok := strings.Cut(clean, ":")
		port := 8090
		if ok {
			fmt.Sscanf(portStr, "%d", &port)
		}
		out, err := sess.TCPCheck(ctx, host, port)
		if err != nil {
			r.Fail("egw-probe-proxy", layer, clean, "Direct egress -> corporate proxy",
				fmt.Sprintf("cannot reach proxy %s:%d: %s", host, port, out),
				"Run tcpdump on VEG pod net1: if SYN leaves with VIP without reply, open firewall VIP -> proxy")
		} else {
			r.Pass("egw-probe-proxy", layer, clean, "Direct egress -> corporate proxy",
				fmt.Sprintf("TCP %s:%d open", host, port))
		}
	}
}

// --- Helper functions ---

func findWaypointSelectedByVEG(veg k8s.VpcEgressGateway, wpByKey map[string]k8s.Gateway) *k8s.Gateway {
	for _, sel := range veg.Spec.Selectors {
		if sel.PodSelector == nil {
			continue
		}
		gwName := sel.PodSelector.MatchLabels[common.LabelGatewayName]
		if gwName == "" {
			continue
		}
		gwNS := ""
		if sel.NamespaceSelector != nil {
			gwNS = sel.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]
		}
		if gwNS != "" {
			if gw, ok := wpByKey[gwNS+"/"+gwName]; ok {
				g := gw
				return &g
			}
		}
		for _, gw := range wpByKey {
			if gw.Metadata.Name == gwName {
				g := gw
				return &g
			}
		}
	}
	return nil
}

func vegSelectsWaypoint(veg k8s.VpcEgressGateway, wp k8s.Gateway) bool {
	for _, sel := range veg.Spec.Selectors {
		if sel.PodSelector != nil && sel.PodSelector.MatchLabels[common.LabelGatewayName] == wp.Metadata.Name {
			if sel.NamespaceSelector == nil || sel.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == wp.Metadata.Namespace {
				return true
			}
		}
	}
	return false
}

func vegTargetsNamespace(veg k8s.VpcEgressGateway, ns string, subnetNSs map[string][]string) bool {
	for _, sel := range veg.Spec.Selectors {
		if sel.NamespaceSelector != nil && sel.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == ns {
			return true
		}
	}
	for _, pol := range veg.Spec.Policies {
		for _, sn := range pol.Subnets {
			for _, memberNS := range subnetNSs[sn] {
				if memberNS == ns {
					return true
				}
			}
		}
	}
	return false
}

func waypointAllowsSenderNS(wp k8s.Gateway, senderNS string) bool {
	if senderNS == wp.Metadata.Namespace {
		return true
	}
	for _, l := range wp.Spec.Listeners {
		if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil {
			continue
		}
		nsCfg := l.AllowedRoutes.Namespaces
		if strings.EqualFold(nsCfg.From, "All") {
			return true
		}
		if strings.EqualFold(nsCfg.From, "Selector") && nsCfg.Selector != nil {
			if nsCfg.Selector.MatchLabels["kubernetes.io/metadata.name"] == senderNS {
				return true
			}
			for _, expr := range nsCfg.Selector.MatchExpressions {
				if expr.Key == "kubernetes.io/metadata.name" && expr.Operator == "In" {
					for _, v := range expr.Values {
						if v == senderNS {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// extractAddressPrefixes walks arbitrary Envoy listener JSON and collects all "address_prefix" strings.
func extractAddressPrefixes(rawJSON string) map[string]bool {
	var data any
	if err := json.Unmarshal([]byte(rawJSON), &data); err != nil {
		return nil
	}
	out := make(map[string]bool)
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if k == "address_prefix" || k == "addressPrefix" {
					if s, ok := val.(string); ok && s != "" {
						out[s] = true
					}
				} else {
					walk(val)
				}
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(data)
	return out
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

func allowsEgressToNSPort(nps []k8s.NetworkPolicy, targetNS string, targetPort int) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Egress {
			peerOK := len(rule.To) == 0
			for _, p := range rule.To {
				if p.NamespaceSelector != nil &&
					(len(p.NamespaceSelector.MatchLabels) == 0 || p.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == targetNS) {
					peerOK = true
					break
				}
			}
			if peerOK && portsInclude(rule.Ports, targetPort) {
				return true
			}
		}
	}
	return false
}

func allowsIngressFromNSPort(nps []k8s.NetworkPolicy, fromNS string, targetPort int) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Ingress {
			peerOK := len(rule.From) == 0
			for _, p := range rule.From {
				if p.NamespaceSelector != nil &&
					(len(p.NamespaceSelector.MatchLabels) == 0 || p.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == fromNS) {
					peerOK = true
					break
				}
			}
			if peerOK && portsInclude(rule.Ports, targetPort) {
				return true
			}
		}
	}
	return false
}

func allowsEgressIPBlockPort(nps []k8s.NetworkPolicy, targetPort int) bool {
	for _, np := range nps {
		for _, rule := range np.Spec.Egress {
			hasIP := len(rule.To) == 0
			for _, p := range rule.To {
				if p.IPBlock != nil && p.IPBlock.CIDR != "" {
					hasIP = true
					break
				}
			}
			if hasIP && portsInclude(rule.Ports, targetPort) {
				return true
			}
		}
	}
	return false
}

func portsInclude(ports []k8s.NetworkPolicyPort, targetPort int) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		_, num := k8s.ParsePortRaw(p.Port)
		if num == targetPort || len(p.Port) == 0 {
			return true
		}
	}
	return false
}

func authzAllowsNS(aps []k8s.AuthorizationPolicy, senderNS string) bool {
	for _, ap := range aps {
		action := strings.ToUpper(ap.Spec.Action)
		if action != "" && action != "ALLOW" {
			continue
		}
		for _, rule := range ap.Spec.Rules {
			if len(rule.From) == 0 {
				return true
			}
			for _, f := range rule.From {
				for _, ns := range f.Source.Namespaces {
					if ns == "*" || ns == senderNS {
						return true
					}
				}
			}
		}
	}
	return false
}

func anyIn(got, want []string) bool {
	for _, g := range got {
		for _, w := range want {
			if g == w {
				return true
			}
		}
	}
	return false
}

func gwLabel(gw *k8s.Gateway) string {
	if gw == nil {
		return "<none>"
	}
	return gw.Metadata.Namespace + "/" + gw.Metadata.Name
}

func vegLabel(v *k8s.VpcEgressGateway) string {
	if v == nil {
		return "<none>"
	}
	return v.Metadata.Namespace + "/" + v.Metadata.Name
}
