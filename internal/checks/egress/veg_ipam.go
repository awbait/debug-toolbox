package egress

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/awbait/debug-toolbox/internal/checks/common"
	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

// checkVEGSubnetsAndIPs validates VpcEgressGateway externalSubnet/externalIPs and
// internalSubnet/internalIPs against Kube-OVN Subnet CIDRs, gateways, excludeIps,
// and detects cluster-wide externalIP collisions across VEGs.
func checkVEGSubnetsAndIPs(
	r *report.Report,
	layer string,
	veg k8s.VpcEgressGateway,
	allVEGs []k8s.VpcEgressGateway,
	subnetByName map[string]k8s.Subnet,
	subnetsByNS map[string][]k8s.Subnet,
) {
	vegNS := veg.Metadata.Namespace
	vegRes := vegNS + "/" + veg.Metadata.Name

	// 1. Validate externalSubnet & externalIPs
	extName := strings.TrimSpace(veg.Spec.ExternalSubnet)
	if extName == "" {
		r.Fail("veg-ext-subnet-empty", layer, vegRes, "VEG externalSubnet",
			"spec.externalSubnet is empty (Kube-OVN VEG requires an underlay externalSubnet for net1 VIP)",
			"Set spec.externalSubnet to the cluster underlay Subnet (e.g. egress-vip)")
	} else if extSN, exists := subnetByName[extName]; !exists {
		r.Fail("veg-ext-subnet-missing", layer, vegRes, "VEG externalSubnet",
			fmt.Sprintf("externalSubnet %q does NOT exist in cluster Kube-OVN Subnets (VEG pods will fail IP allocation)", extName),
			fmt.Sprintf("Create Kube-OVN underlay Subnet %q (with Multus NetworkAttachmentDefinition) or set externalSubnet to an existing underlay Subnet", extName),
			summarizeSubnets(subnetByName)...)
	} else if len(veg.Spec.ExternalIPs) > 0 {
		extIssues := false
		for _, rawIP := range veg.Spec.ExternalIPs {
			if errCode, msg, sugg := validateIPInSubnet(rawIP, extSN, "externalIP", "externalSubnet"); errCode != "" {
				extIssues = true
				r.Fail("veg-ext-ip-"+errCode, layer, vegRes,
					fmt.Sprintf("VEG externalIP %s vs Subnet %s", rawIP, extSN.Metadata.Name),
					msg, sugg, formatSubnetEvidence(extSN))
			}
		}
		if !extIssues {
			r.Pass("veg-ext-subnet", layer, "subnet/"+extSN.Metadata.Name, "VEG externalSubnet & externalIPs",
				fmt.Sprintf("externalIPs %v valid inside %s (cidr=%s)", veg.Spec.ExternalIPs, extSN.Metadata.Name, extSN.Spec.CIDRBlock))
		}
	}

	// 2. Validate internalSubnet (if set) & internalIPs (if set)
	intName := strings.TrimSpace(veg.Spec.InternalSubnet)
	if intName != "" {
		intSN, exists := subnetByName[intName]
		if !exists {
			r.Fail("veg-int-subnet-missing", layer, vegRes, "VEG internalSubnet",
				fmt.Sprintf("internalSubnet %q does NOT exist in cluster Kube-OVN Subnets", intName),
				fmt.Sprintf("Fix spec.internalSubnet to an existing Kube-OVN Subnet (or omit to use namespace %s default subnet)", vegNS),
				summarizeSubnets(subnetByName)...)
		} else if len(veg.Spec.InternalIPs) > 0 {
			for _, rawIP := range veg.Spec.InternalIPs {
				if errCode, msg, sugg := validateIPInSubnet(rawIP, intSN, "internalIP", "internalSubnet"); errCode != "" {
					r.Fail("veg-int-ip-"+errCode, layer, vegRes,
						fmt.Sprintf("VEG internalIP %s vs Subnet %s", rawIP, intSN.Metadata.Name),
						msg, sugg, formatSubnetEvidence(intSN))
				}
			}
		}
	} else if len(veg.Spec.InternalIPs) > 0 {
		// Validate internalIPs against namespace's bound subnet (or ovn-default fallback)
		var targetSN *k8s.Subnet
		if nsSubnets := subnetsByNS[vegNS]; len(nsSubnets) > 0 {
			s := nsSubnets[0]
			targetSN = &s
		} else if defSN, ok := subnetByName["ovn-default"]; ok {
			targetSN = &defSN
		}
		if targetSN != nil {
			for _, rawIP := range veg.Spec.InternalIPs {
				if errCode, msg, sugg := validateIPInSubnet(rawIP, *targetSN, "internalIP", "VEG namespace subnet"); errCode != "" {
					r.Fail("veg-int-ip-"+errCode, layer, vegRes,
						fmt.Sprintf("VEG internalIP %s vs Subnet %s", rawIP, targetSN.Metadata.Name),
						msg, sugg, formatSubnetEvidence(*targetSN))
				}
			}
		}
	}

	// 3. Cluster-wide externalIP collision across multiple VpcEgressGateways
	for _, rawIP := range veg.Spec.ExternalIPs {
		ip := strings.TrimSpace(rawIP)
		if ip == "" {
			continue
		}
		var others []string
		for _, other := range allVEGs {
			otherRes := other.Metadata.Namespace + "/" + other.Metadata.Name
			if otherRes == vegRes {
				continue
			}
			for _, oip := range other.Spec.ExternalIPs {
				if strings.TrimSpace(oip) == ip {
					others = append(others, otherRes)
					break
				}
			}
		}
		if len(others) > 0 {
			sort.Strings(others)
			r.Fail("veg-ext-ip-collision-"+ip, layer, vegRes,
				fmt.Sprintf("VEG externalIP collision (%s)", ip),
				fmt.Sprintf("externalIP %s is ALSO claimed by VpcEgressGateway %s (causes Kube-OVN AcquireAddressFailed: AddressConflict)",
					ip, strings.Join(others, ", ")),
				"Assign unique externalIPs per VpcEgressGateway")
		}
	}
}

// checkVEGPodEvents inspects Kubernetes Warning events in the VEG namespace when
// VEG is not ready or its pods are not ready, pinpointing Kube-OVN IPAM failures
// (AcquireAddressFailed: AddressOutOfRange / NoAvailableAddress / AddressConflict),
// CNI sandbox allocation errors, and scheduling failures.
func checkVEGPodEvents(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	layer string,
	veg k8s.VpcEgressGateway,
	subnetByName map[string]k8s.Subnet,
) {
	vegNS := veg.Metadata.Namespace
	vegName := veg.Metadata.Name
	vegRes := vegNS + "/" + vegName

	warnEvents, err := c.ListWarningEvents(ctx, vegNS)
	if err != nil || len(warnEvents) == 0 {
		return
	}

	var (
		ipamOutOfRange []string
		ipamNoAvail    []string
		ipamConflict   []string
		ipamOther      []string
		sandboxNoAddr  []string
		schedFailed    []string
		otherWarnings  []string
	)

	for _, ev := range warnEvents {
		if !strings.HasPrefix(ev.InvolvedObject.Name, vegName) {
			continue
		}
		line := fmt.Sprintf("%s/%s: %s (x%d) - %s",
			ev.InvolvedObject.Kind, ev.InvolvedObject.Name, ev.Reason, ev.Count, ev.Message)
		lowReason := strings.ToLower(ev.Reason)
		lowMsg := strings.ToLower(ev.Message)

		switch {
		case lowReason == "acquireaddressfailed" || strings.Contains(lowMsg, "addressoutofrange") ||
			strings.Contains(lowMsg, "noavailableaddress") || strings.Contains(lowMsg, "addressconflict"):
			switch {
			case strings.Contains(lowMsg, "addressoutofrange") || strings.Contains(lowMsg, "out of range"):
				ipamOutOfRange = append(ipamOutOfRange, line)
			case strings.Contains(lowMsg, "noavailableaddress") || strings.Contains(lowMsg, "no available"):
				ipamNoAvail = append(ipamNoAvail, line)
			case strings.Contains(lowMsg, "conflict") || strings.Contains(lowMsg, "in use") || strings.Contains(lowMsg, "already"):
				ipamConflict = append(ipamConflict, line)
			default:
				ipamOther = append(ipamOther, line)
			}
		case lowReason == "failedcreatepodsandbox" && strings.Contains(lowMsg, "no address allocated to pod"):
			sandboxNoAddr = append(sandboxNoAddr, line)
		case lowReason == "failedscheduling":
			schedFailed = append(schedFailed, line)
		default:
			otherWarnings = append(otherWarnings, line)
		}
	}

	var subnetContext []string
	if extSN, ok := subnetByName[veg.Spec.ExternalSubnet]; ok {
		subnetContext = append(subnetContext, formatSubnetEvidence(extSN))
	}
	if veg.Spec.InternalSubnet != "" {
		if intSN, ok := subnetByName[veg.Spec.InternalSubnet]; ok {
			subnetContext = append(subnetContext, formatSubnetEvidence(intSN))
		}
	}

	hasIPAMFail := false
	if len(ipamOutOfRange) > 0 {
		hasIPAMFail = true
		ev := append(append([]string{}, ipamOutOfRange...), sandboxNoAddr...)
		ev = append(ev, subnetContext...)
		r.Fail("veg-pod-ipam-range", layer, vegRes, "VEG pod Kube-OVN IPAM (AddressOutOfRange)",
			fmt.Sprintf("VEG pod failed with AcquireAddressFailed: AddressOutOfRange — static IP in externalIPs %v (or internalIPs %v) is outside Subnet %q CIDR",
				veg.Spec.ExternalIPs, veg.Spec.InternalIPs, veg.Spec.ExternalSubnet),
			fmt.Sprintf("Verify VpcEgressGateway.spec.externalIPs (%v) falls inside Subnet %q spec.cidrBlock and outside excludeIps/gateway (check: kubectl get subnet %s -o yaml)",
				veg.Spec.ExternalIPs, veg.Spec.ExternalSubnet, veg.Spec.ExternalSubnet),
			ev...)
	}
	if len(ipamNoAvail) > 0 {
		hasIPAMFail = true
		ev := append(append([]string{}, ipamNoAvail...), sandboxNoAddr...)
		ev = append(ev, subnetContext...)
		r.Fail("veg-pod-ipam-full", layer, vegRes, "VEG pod Kube-OVN IPAM (NoAvailableAddress)",
			"VEG pod failed with AcquireAddressFailed: NoAvailableAddress — target Kube-OVN Subnet has no free IPs left",
			"Expand the Kube-OVN Subnet cidrBlock or release unused pods/IPs in that Subnet",
			ev...)
	}
	if len(ipamConflict) > 0 {
		hasIPAMFail = true
		ev := append(append([]string{}, ipamConflict...), sandboxNoAddr...)
		ev = append(ev, subnetContext...)
		r.Fail("veg-pod-ipam-conflict", layer, vegRes, "VEG pod Kube-OVN IPAM (AddressConflict)",
			fmt.Sprintf("VEG pod failed with AcquireAddressFailed: AddressConflict for externalIPs %v (IP already in use or listed in Subnet excludeIps)",
				veg.Spec.ExternalIPs),
			fmt.Sprintf("Choose an unused IP not in Subnet %q excludeIps and not claimed by another pod/VEG", veg.Spec.ExternalSubnet),
			ev...)
	}
	if len(ipamOther) > 0 {
		hasIPAMFail = true
		ev := append(append([]string{}, ipamOther...), sandboxNoAddr...)
		ev = append(ev, subnetContext...)
		r.Fail("veg-pod-ipam", layer, vegRes, "VEG pod Kube-OVN IPAM",
			"VEG pod failed Kube-OVN IP address allocation (AcquireAddressFailed)",
			"Inspect kube-ovn-controller logs and Kube-OVN Subnet / VpcEgressGateway configuration",
			ev...)
	}

	if len(sandboxNoAddr) > 0 && !hasIPAMFail {
		ev := append(append([]string{}, sandboxNoAddr...), subnetContext...)
		r.Fail("veg-pod-sandbox", layer, vegRes, "VEG pod CNI sandbox (no address allocated)",
			"VEG pod FailedCreatePodSandbox: kube-ovn CNI received 'no address allocated to pod' (kube-ovn-controller failed IPAM allocation)",
			fmt.Sprintf("Check kube-ovn-controller logs, VpcEgressGateway externalSubnet (%q) / externalIPs (%v), and Pod annotations",
				veg.Spec.ExternalSubnet, veg.Spec.ExternalIPs),
			ev...)
	}

	if len(schedFailed) > 0 {
		r.Fail("veg-pod-scheduling", layer, vegRes, "VEG pod scheduling",
			"VEG pod FailedScheduling — no node matched scheduling constraints",
			"Check VpcEgressGateway spec.nodeSelector, tolerations, and node labels/taints",
			schedFailed...)
	}

	if len(otherWarnings) > 0 {
		if len(otherWarnings) > 6 {
			otherWarnings = otherWarnings[len(otherWarnings)-6:]
		}
		r.Warn("veg-events", layer, vegRes, "VEG Warning events",
			fmt.Sprintf("%d Warning event(s) for %s*", len(otherWarnings), vegName),
			"Inspect Kubernetes Warning events in "+vegNS, otherWarnings...)
	}
}

// findMisalignedMeshVEG detects a VpcEgressGateway that directly targets one of the
// mesh sender namespaces (via selectors or policies.subnets) instead of selecting
// the mesh waypoint Gateway pods.
func findMisalignedMeshVEG(
	topo topology,
	allVEGs []k8s.VpcEgressGateway,
	subnetsByNS map[string][]k8s.Subnet,
) (*k8s.VpcEgressGateway, []string) {
	if topo.Waypoint == nil || len(topo.SenderNSs) == 0 {
		return nil, nil
	}

	subnetNSs := make(map[string][]string)
	for ns, sns := range subnetsByNS {
		for _, sn := range sns {
			subnetNSs[sn.Metadata.Name] = append(subnetNSs[sn.Metadata.Name], ns)
		}
	}

	for i := range allVEGs {
		v := allVEGs[i]
		var matchedSenders []string
		for _, sNS := range topo.SenderNSs {
			if vegTargetsNamespace(v, sNS, subnetNSs) {
				matchedSenders = append(matchedSenders, sNS)
			}
		}
		if len(matchedSenders) > 0 {
			copyV := v
			return &copyV, matchedSenders
		}
	}
	return nil, nil
}

// reportMisalignedMeshVEG emits a FAIL check explaining why the VEG does not match the waypoint.
func reportMisalignedMeshVEG(r *report.Report, veg k8s.VpcEgressGateway, wp k8s.Gateway, matchedSenders []string) {
	vegRes := veg.Metadata.Namespace + "/" + veg.Metadata.Name
	wpRes := wp.Metadata.Namespace + "/" + wp.Metadata.Name
	r.Fail("veg-selector-mismatch", "VpcEgressGateway", vegRes,
		"VEG selector mismatch (targets senders instead of waypoint)",
		fmt.Sprintf("mode=mesh has waypoint %s, but VpcEgressGateway %s selects sender namespace(s) %v directly instead of waypoint pods! Waypoint egress bypasses VEG AND ambient sender pods lose 169.254.7.127 kubelet host-probes",
			wpRes, vegRes, matchedSenders),
		fmt.Sprintf("Update %s spec.selectors to ONE item combining namespaceSelector (kubernetes.io/metadata.name: %s) AND podSelector (%s: %s)",
			vegRes, wp.Metadata.Namespace, common.LabelGatewayName, wp.Metadata.Name))
}

func validateIPInSubnet(rawIP string, sn k8s.Subnet, ipRole, subnetRole string) (code, msg, suggestion string) {
	ipStr := strings.TrimSpace(rawIP)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "invalid",
			fmt.Sprintf("%s %q is not a valid IP address", ipRole, rawIP),
			fmt.Sprintf("Fix invalid %s %q in VpcEgressGateway spec", ipRole, rawIP)
	}
	addr = addr.Unmap()

	// Parse CIDRBlock (supports dual-stack CSV)
	var prefixes []netip.Prefix
	for _, part := range strings.Split(sn.Spec.CIDRBlock, ",") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(part)); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) > 0 {
		var matchedPfx *netip.Prefix
		for i := range prefixes {
			if prefixes[i].Contains(addr) {
				matchedPfx = &prefixes[i]
				break
			}
		}
		if matchedPfx == nil {
			return "range",
				fmt.Sprintf("%s %s is OUT OF RANGE for %s %q (cidr=%s) — causes Kube-OVN AcquireAddressFailed: AddressOutOfRange",
					ipRole, ipStr, subnetRole, sn.Metadata.Name, sn.Spec.CIDRBlock),
				fmt.Sprintf("Change %s to a free IP inside Subnet %q (%s, outside excludeIps/gateway), or adjust Subnet %q CIDR",
					ipRole, sn.Metadata.Name, sn.Spec.CIDRBlock, sn.Metadata.Name)
		}
		if isNetworkOrBroadcastIPv4(addr, *matchedPfx) {
			return "reserved",
				fmt.Sprintf("%s %s is the network or broadcast address of %s %q (%s)",
					ipRole, ipStr, subnetRole, sn.Metadata.Name, matchedPfx.String()),
				fmt.Sprintf("Use a valid host IP inside %s %q (%s)", subnetRole, sn.Metadata.Name, matchedPfx.String())
		}
	}

	// Gateway check (supports dual-stack CSV)
	for _, gwPart := range strings.Split(sn.Spec.Gateway, ",") {
		if gwAddr, err := netip.ParseAddr(strings.TrimSpace(gwPart)); err == nil {
			if gwAddr.Unmap() == addr {
				return "reserved",
					fmt.Sprintf("%s %s collides with %s %q gateway (%s)",
						ipRole, ipStr, subnetRole, sn.Metadata.Name, sn.Spec.Gateway),
					fmt.Sprintf("Choose an IP different from gateway %s in Subnet %q", sn.Spec.Gateway, sn.Metadata.Name)
			}
		}
	}

	// ExcludeIPs check (single IP or Kube-OVN start..end range)
	for _, ex := range sn.Spec.ExcludeIPs {
		if excludeEntryContains(ex, addr) {
			return "excluded",
				fmt.Sprintf("%s %s falls inside excludeIps (%q) of %s %q — Kube-OVN IPAM refuses to allocate it",
					ipRole, ipStr, ex, subnetRole, sn.Metadata.Name),
				fmt.Sprintf("Choose an IP outside excludeIps %v of Subnet %q, or remove %s from excludeIps",
					sn.Spec.ExcludeIPs, sn.Metadata.Name, ipStr)
		}
	}

	return "", "", ""
}

func isNetworkOrBroadcastIPv4(addr netip.Addr, pfx netip.Prefix) bool {
	if !addr.Is4() || !pfx.Addr().Is4() || pfx.Bits() >= 31 {
		return false
	}
	masked := pfx.Masked().Addr()
	if addr == masked {
		return true
	}
	b := masked.As4()
	hostMask := uint32(1)<<(32-pfx.Bits()) - 1
	bcastNum := binary.BigEndian.Uint32(b[:]) | hostMask
	var bcastBytes [4]byte
	binary.BigEndian.PutUint32(bcastBytes[:], bcastNum)
	return addr == netip.AddrFrom4(bcastBytes)
}

func excludeEntryContains(raw string, addr netip.Addr) bool {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return false
	}
	addr = addr.Unmap()

	// Kube-OVN range format: "10.193.98.0..10.193.98.10"
	if left, right, ok := strings.Cut(entry, ".."); ok {
		start, err1 := netip.ParseAddr(strings.TrimSpace(left))
		end, err2 := netip.ParseAddr(strings.TrimSpace(right))
		if err1 == nil && err2 == nil {
			start, end = start.Unmap(), end.Unmap()
			return start.BitLen() == addr.BitLen() && end.BitLen() == addr.BitLen() &&
				!addr.Less(start) && !end.Less(addr)
		}
		return false
	}
	// Dash range fallback
	if left, right, ok := strings.Cut(entry, "-"); ok {
		start, err1 := netip.ParseAddr(strings.TrimSpace(left))
		end, err2 := netip.ParseAddr(strings.TrimSpace(right))
		if err1 == nil && err2 == nil {
			start, end = start.Unmap(), end.Unmap()
			return start.BitLen() == addr.BitLen() && end.BitLen() == addr.BitLen() &&
				!addr.Less(start) && !end.Less(addr)
		}
		return false
	}
	// CIDR fallback
	if strings.Contains(entry, "/") {
		if pfx, err := netip.ParsePrefix(entry); err == nil {
			return pfx.Contains(addr)
		}
		return false
	}
	// Single IP
	if single, err := netip.ParseAddr(entry); err == nil {
		return single.Unmap() == addr
	}
	return false
}

func formatSubnetEvidence(sn k8s.Subnet) string {
	line := fmt.Sprintf("Subnet %s: cidr=%s", sn.Metadata.Name, sn.Spec.CIDRBlock)
	if sn.Spec.Gateway != "" {
		line += ", gateway=" + sn.Spec.Gateway
	}
	if sn.Spec.Provider != "" {
		line += ", provider=" + sn.Spec.Provider
	}
	if len(sn.Spec.ExcludeIPs) > 0 {
		line += fmt.Sprintf(", excludeIps=%v", sn.Spec.ExcludeIPs)
	}
	return line
}

func summarizeSubnets(subnetByName map[string]k8s.Subnet) []string {
	if len(subnetByName) == 0 {
		return []string{"Cluster Kube-OVN Subnets: none"}
	}
	names := make([]string, 0, len(subnetByName))
	for name := range subnetByName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, formatSubnetEvidence(subnetByName[n]))
	}
	return out
}
