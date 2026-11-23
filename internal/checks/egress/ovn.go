package egress

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

var (
	ovn29100Regex  = regexp.MustCompile(`29100\s+(.+?)\s+reroute\s+(\S+)`)
	vegGroupRegex  = regexp.MustCompile(`\$(VEG\.[A-Za-z0-9._-]+)`)
)

// CheckOVNAndVEGRuntime inspects live OVN router 29100 policy rules, port_group/address_set,
// and VEG pod ip-rule table (read-only).
func CheckOVNAndVEGRuntime(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	veg k8s.VpcEgressGateway,
	vegPods []k8s.Pod,
	expectedWaypointPods []k8s.Pod,
	mode string,
) {
	const layer = "Kube-OVN & VEG Runtime"
	vegRes := veg.Metadata.Namespace + "/" + veg.Metadata.Name

	// 1. Check VEG pod `ip rule` for istio-cni fwmark 0x111 (ambient capture signature)
	for _, vp := range vegPods {
		if !vp.IsReady() {
			continue
		}
		res, err := c.PodExec(ctx, vp.Metadata.Namespace, vp.Metadata.Name, "gateway", "ip", "rule")
		if err != nil {
			// Fallback without container name
			res, err = c.PodExec(ctx, vp.Metadata.Namespace, vp.Metadata.Name, "", "ip", "rule")
		}
		if err != nil {
			r.Info("veg-iprule-"+vp.Metadata.Name, layer, vp.Metadata.Namespace+"/"+vp.Metadata.Name,
				"VEG pod ip rule check", fmt.Sprintf("skipped (exec error: %v)", err))
			continue
		}
		if strings.Contains(res.Stdout, "0x111") && strings.Contains(res.Stdout, "lookup 100") {
			r.Fail("veg-iprule-"+vp.Metadata.Name, layer, vp.Metadata.Namespace+"/"+vp.Metadata.Name,
				"VEG pod ambient interception (ip rule)",
				"VEG pod netns contains istio-cni rule `fwmark 0x111/0xfff lookup 100` — ztunnel is intercepting transit traffic!",
				"Ensure VEG namespace has NO istio.io/dataplane-mode=ambient, add Kyverno mutate istio.io/dataplane-mode=none for VEG pods, and recreate the VEG pod",
				strings.TrimSpace(res.Stdout))
		} else {
			r.Pass("veg-iprule-"+vp.Metadata.Name, layer, vp.Metadata.Namespace+"/"+vp.Metadata.Name,
				"VEG pod ip rule check", "clean (no istio-cni fwmark 0x111 redirection rules)")
		}
		break
	}

	// 2. Query OVN NB leader for priority 29100 rules
	leader, err := c.DetectOVNLeader(ctx)
	if err != nil {
		r.Warn("ovn-leader", layer, "kube-system/ovn-central", "Kube-OVN NB leader",
			fmt.Sprintf("could not locate ovn-nb-leader pod: %v", err),
			"Check ovn-central pods in kube-system to inspect OVN router policy 29100")
		return
	}

	vpc := veg.Spec.VPC
	if vpc == "" {
		vpc = "ovn-cluster"
	}
	res, err := c.PodExec(ctx, "kube-system", leader, "", "ovn-nbctl", "lr-policy-list", vpc)
	if err != nil {
		r.Warn("ovn-lr-policy", layer, "kube-system/"+leader, "OVN lr-policy-list "+vpc,
			fmt.Sprintf("failed to run ovn-nbctl lr-policy-list: %v", err),
			"Verify pods/exec RBAC in kube-system")
		return
	}

	vegIPs := make(map[string]bool)
	for _, vp := range vegPods {
		if vp.Status.PodIP != "" {
			vegIPs[vp.Status.PodIP] = true
		}
	}

	var matchedRules []string
	var portGroups []string
	var addrSets []string

	for _, raw := range strings.Split(res.Stdout, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "29100") {
			continue
		}
		m := ovn29100Regex.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		matchExpr := m[1]
		nextHop := m[2]
		if len(vegIPs) > 0 && !vegIPs[nextHop] {
			continue
		}
		matchedRules = append(matchedRules, line)
		if gm := vegGroupRegex.FindStringSubmatch(matchExpr); len(gm) >= 2 {
			tok := gm[1]
			if strings.HasSuffix(tok, "_ip4") {
				portGroups = append(portGroups, strings.TrimSuffix(tok, "_ip4"))
			} else if strings.HasSuffix(tok, ".ipv4") {
				addrSets = append(addrSets, tok)
			}
		}
	}

	if len(matchedRules) == 0 {
		r.Fail("ovn-policy-29100", layer, vegRes, "OVN router policy 29100",
			fmt.Sprintf("NO priority 29100 reroute rule found in %s pointing to VEG pod IP(s) %v", vpc, keysOf(vegIPs)),
			"Check kube-ovn-controller logs and VpcEgressGateway selectors/policies; verify referenced subnets exist")
		return
	}

	r.Pass("ovn-policy-29100", layer, vegRes, "OVN router policy 29100",
		fmt.Sprintf("found %d priority-29100 rule(s) pointing to VEG pod(s)", len(matchedRules)),
		matchedRules...)

	// 3. Inspect port_group(s) for selector-based VEG (verify exact pod membership)
	for _, pg := range uniqueStrs(portGroups) {
		pgRes, err := c.PodExec(ctx, "kube-system", leader, "",
			"ovn-nbctl", "--columns=name,ports", "list", "port_group", pg)
		if err != nil {
			continue
		}
		// Count UUIDs in ports=[...]
		portUUIDs := extractUUIDs(pgRes.Stdout)
		if mode == "mesh" && len(expectedWaypointPods) > 0 {
			if len(portUUIDs) == 0 {
				r.Fail("ovn-pg-"+pg, layer, "port_group/"+pg, "OVN port_group membership",
					fmt.Sprintf("port_group %s has 0 ports, expected %d waypoint pod(s) — waypoint traffic will NOT route via VEG VIP!",
						pg, len(expectedWaypointPods)),
					"Check VpcEgressGateway selectors (namespaceSelector + podSelector) and kube-ovn-controller sync")
			} else if len(portUUIDs) > len(expectedWaypointPods) {
				r.Fail("ovn-pg-"+pg, layer, "port_group/"+pg, "OVN port_group over-capture",
					fmt.Sprintf("port_group %s contains %d ports, but only %d waypoint pod(s) exist! Application pods may be captured (breaks 169.254.7.127 kubelet probes!)",
						pg, len(portUUIDs), len(expectedWaypointPods)),
					"Ensure VpcEgressGateway selectors combine namespaceSelector AND podSelector in ONE list item and run VEG/waypoint in dedicated namespaces")
			} else if len(portUUIDs) < len(expectedWaypointPods) {
				r.Warn("ovn-pg-"+pg, layer, "port_group/"+pg, "OVN port_group sync lag",
					fmt.Sprintf("port_group %s has %d port(s), expected %d Ready waypoint pod(s) (possible kube-ovn startup race)",
						pg, len(portUUIDs), len(expectedWaypointPods)),
					"Re-check in a few seconds or inspect kube-ovn-controller logs")
			} else {
				r.Pass("ovn-pg-"+pg, layer, "port_group/"+pg, "OVN port_group membership",
					fmt.Sprintf("port_group %s matches exactly %d waypoint pod(s)", pg, len(portUUIDs)))
			}
		} else {
			r.Info("ovn-pg-"+pg, layer, "port_group/"+pg, "OVN port_group membership",
				fmt.Sprintf("port_group %s contains %d logical switch port(s)", pg, len(portUUIDs)))
		}
	}

	// 4. Inspect address_set(s) for policy-based VEG
	for _, as := range uniqueStrs(addrSets) {
		asRes, err := c.PodExec(ctx, "kube-system", leader, "",
			"ovn-nbctl", "--columns=name,addresses", "find", "address_set", "name="+as)
		if err != nil {
			continue
		}
		if mode == "mesh" && strings.Contains(asRes.Stdout, `"`) {
			r.Fail("ovn-as-"+as, layer, "address_set/"+as, "OVN address_set in mesh mode",
				fmt.Sprintf("address_set %s is populated in mesh mode — policies.subnets should NOT be used with ambient mesh!", as),
				"Remove spec.policies from VpcEgressGateway in mesh mode; init script already applies MASQUERADE for selectors",
				strings.TrimSpace(asRes.Stdout))
		} else {
			r.Info("ovn-as-"+as, layer, "address_set/"+as, "OVN address_set", strings.TrimSpace(asRes.Stdout))
		}
	}
}

var uuidRegex = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func extractUUIDs(s string) []string {
	return uuidRegex.FindAllString(s, -1)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func uniqueStrs(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
