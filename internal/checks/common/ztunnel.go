package common

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

var ztunnelErrPattern = regexp.MustCompile(`(?i)(error|deny|denied|rbac|reject|reset|timeout|refused|503|no matching|failed)`)

// InspectZtunnelForNodes checks ztunnel logs on specific nodes, filtered by keywords/IPs/namespaces.
func InspectZtunnelForNodes(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	layer string,
	ztunnelNS string,
	ztunnelPods []k8s.Pod,
	targetNodes map[string]bool,
	filterTokens []string,
	since string,
) {
	if ztunnelNS == "" || len(ztunnelPods) == 0 {
		r.Skip("ztunnel-logs", layer, "ztunnel", "ztunnel error logs", "ztunnel pods not available")
		return
	}

	var matchedPods []k8s.Pod
	for _, zp := range ztunnelPods {
		if len(targetNodes) == 0 || targetNodes[zp.Spec.NodeName] {
			matchedPods = append(matchedPods, zp)
		}
	}
	if len(matchedPods) == 0 {
		r.Warn("ztunnel-logs", layer, ztunnelNS+"/ztunnel", "ztunnel pods on target nodes",
			"no ztunnel pods found on the nodes running target workloads",
			"Check ztunnel DaemonSet scheduling and tolerations")
		return
	}

	var evidence []string
	var policyRejections int
	var strictMtlsDenies int
	var hbone503 int

	for _, zp := range matchedPods {
		logs, err := c.PodLogs(ctx, ztunnelNS, zp.Metadata.Name, "", since, 500)
		if err != nil {
			evidence = append(evidence, fmt.Sprintf("[%s@%s] failed to read logs: %v", zp.Metadata.Name, zp.Spec.NodeName, err))
			continue
		}
		lines := FilterRelevantLogLines(logs, filterTokens, 12)
		for _, line := range lines {
			low := strings.ToLower(line)
			if strings.Contains(low, "policy rejection") || strings.Contains(low, "rbac") {
				policyRejections++
			}
			if strings.Contains(low, "istio_converted_static_strict") {
				strictMtlsDenies++
			}
			if strings.Contains(low, "503") || strings.Contains(low, "http status 503") {
				hbone503++
			}
			evidence = append(evidence, fmt.Sprintf("[%s@%s] %s", zp.Metadata.Name, zp.Spec.NodeName, line))
		}
	}

	if len(evidence) == 0 {
		r.Pass("ztunnel-logs", layer, ztunnelNS+"/ztunnel", "ztunnel logs on target nodes",
			fmt.Sprintf("no error/deny lines matching target IPs/NS in last %s across %d ztunnel pod(s)", since, len(matchedPods)))
		return
	}

	if len(evidence) > 20 {
		evidence = evidence[len(evidence)-20:]
	}

	var hints []string
	if strictMtlsDenies > 0 {
		hints = append(hints, "Non-mesh plaintext client hit STRICT mTLS (istio_converted_static_strict): route traffic via Ingress Gateway or add PERMISSIVE PeerAuthentication on that port")
	}
	if policyRejections > 0 {
		hints = append(hints, "AuthorizationPolicy rejected traffic (policy rejection/RBAC): verify ALLOW policy principals and string ports in destination namespace")
	}
	if hbone503 > 0 {
		hints = append(hints, "HBONE 503 from waypoint/peer: check waypoint filter_chain_matcher VIPs (duplicate ServiceEntry across namespaces?) and upstream connectivity")
	}
	if len(hints) == 0 {
		hints = append(hints, "Review the ztunnel error lines above to pinpoint the failing hop (timeout -> NetworkPolicy/OVN; immediate reset -> AuthorizationPolicy/waypoint)")
	}

	r.Fail("ztunnel-logs", layer, ztunnelNS+"/ztunnel", "ztunnel errors/denies detected",
		fmt.Sprintf("found %d relevant error/deny log line(s) across %d ztunnel pod(s) in last %s", len(evidence), len(matchedPods), since),
		strings.Join(hints, "; "),
		evidence...)
}

// InspectZtunnelWorkloads checks whether pods appear in `istioctl ztunnel-config workloads` with HBONE protocol.
func InspectZtunnelWorkloads(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	layer string,
	ztunnelNS string,
	ztunnelPod string,
	targetNS string,
	expectedPods []k8s.Pod,
) {
	if ztunnelNS == "" || ztunnelPod == "" || len(expectedPods) == 0 {
		return
	}
	res, err := c.Istioctl(ctx, "-n", ztunnelNS, "ztunnel-config", "workloads", ztunnelPod)
	if err != nil {
		r.Warn("ztunnel-workloads-"+targetNS, layer, ztunnelNS+"/"+ztunnelPod, "ztunnel-config workloads",
			fmt.Sprintf("could not query istioctl ztunnel-config workloads: %v", err),
			"Ensure istioctl is installed and RBAC permits pods/exec & pods/portforward in "+ztunnelNS)
		return
	}

	lines := strings.Split(res.Stdout, "\n")
	podLine := make(map[string]string)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Standard columns: NAMESPACE POD NAME IP NODE WAYPOINT PROTOCOL
		ns := fields[0]
		name := fields[1]
		if ns == targetNS {
			podLine[name] = line
		}
	}

	var missing []string
	var nonHBONE []string
	var okCount int
	for _, p := range expectedPods {
		if p.Status.Phase != "Running" || p.Metadata.Labels[LabelDataplaneMode] == "none" ||
			p.Metadata.Labels[LabelGatewayName] != "" || p.Metadata.Labels[LabelVEG] != "" {
			continue
		}
		line, found := podLine[p.Metadata.Name]
		if !found {
			missing = append(missing, p.Metadata.Name)
			continue
		}
		if strings.Contains(line, "HBONE") {
			okCount++
		} else {
			nonHBONE = append(nonHBONE, line)
		}
	}

	if len(missing) > 0 || len(nonHBONE) > 0 {
		var ev []string
		if len(missing) > 0 {
			ev = append(ev, "Missing in ztunnel: "+strings.Join(missing, ", "))
		}
		ev = append(ev, nonHBONE...)
		r.Fail("ztunnel-workloads-"+targetNS, layer, "ns/"+targetNS, "Workloads registered in ztunnel as HBONE",
			fmt.Sprintf("%d HBONE, %d missing, %d non-HBONE", okCount, len(missing), len(nonHBONE)),
			"Verify namespace has both istio.io/dataplane-mode=ambient and istio-discovery=enabled, and check istio-cni-node logs",
			ev...)
	} else if okCount > 0 {
		r.Pass("ztunnel-workloads-"+targetNS, layer, "ns/"+targetNS, "Workloads registered in ztunnel as HBONE",
			fmt.Sprintf("all %d workload pod(s) seen by ztunnel with protocol HBONE", okCount))
	}
}

// RunZtunnelReport implements the standalone `mesh-debug ztunnel` subcommand.
func RunZtunnelReport(ctx context.Context, c *k8s.Client, version, ns, podName, since string, verbose bool) *report.Report {
	r := report.New(version, "ztunnel", ns, podName, false)
	ztunnelNS, ztunnelPods := CheckControlPlane(ctx, c, r, false)
	if ns == "" {
		r.Finalize(c.Runner.History(), verbose)
		return r
	}

	nsInfo, err := CheckNamespaceMesh(ctx, c, r, "Namespace", ns, false)
	if err != nil {
		r.Finalize(c.Runner.History(), verbose)
		return r
	}

	pods, err := c.ListPods(ctx, ns, "")
	if err != nil {
		r.Fail("ztunnel-list-pods", "Namespace", "ns/"+ns, "List pods",
			fmt.Sprintf("failed to list pods: %v", err), "Check RBAC permissions")
		r.Finalize(c.Runner.History(), verbose)
		return r
	}

	var selected []k8s.Pod
	targetNodes := make(map[string]bool)
	tokens := []string{ns}
	for _, p := range pods {
		if podName != "" && p.Metadata.Name != podName {
			continue
		}
		selected = append(selected, p)
		if p.Spec.NodeName != "" {
			targetNodes[p.Spec.NodeName] = true
		}
		if p.Status.PodIP != "" {
			tokens = append(tokens, p.Status.PodIP)
		}
	}

	if podName != "" && len(selected) == 0 {
		r.Fail("ztunnel-pod-missing", "Namespace", ns+"/"+podName, "Target pod",
			fmt.Sprintf("pod %s not found in namespace %s", podName, ns), "Check pod name")
		r.Finalize(c.Runner.History(), verbose)
		return r
	}

	CheckPodsRedirection(r, "Namespace", ns, selected, nsInfo.AmbientEnabled)

	if len(ztunnelPods) > 0 {
		// Pick a ztunnel pod on one of the target nodes (or first ready ztunnel).
		zp := ztunnelPods[0].Metadata.Name
		for _, cand := range ztunnelPods {
			if targetNodes[cand.Spec.NodeName] && cand.IsReady() {
				zp = cand.Metadata.Name
				break
			}
		}
		InspectZtunnelWorkloads(ctx, c, r, "ztunnel", ztunnelNS, zp, ns, selected)
	}
	InspectZtunnelForNodes(ctx, c, r, "ztunnel", ztunnelNS, ztunnelPods, targetNodes, tokens, since)

	r.Finalize(c.Runner.History(), verbose)
	return r
}

// FilterRelevantLogLines keeps error/deny lines matching any of filterTokens (if provided).
func FilterRelevantLogLines(logs string, filterTokens []string, maxLines int) []string {
	var cleanTokens []string
	seenTok := make(map[string]bool)
	for _, t := range filterTokens {
		t = strings.TrimSpace(t)
		if t != "" && !seenTok[t] {
			seenTok[t] = true
			cleanTokens = append(cleanTokens, t)
		}
	}
	sort.Strings(cleanTokens)

	var matched []string
	for _, raw := range strings.Split(logs, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !ztunnelErrPattern.MatchString(line) {
			continue
		}
		if len(cleanTokens) > 0 {
			hit := false
			for _, tok := range cleanTokens {
				if strings.Contains(line, tok) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		matched = append(matched, line)
	}
	if maxLines > 0 && len(matched) > maxLines {
		matched = matched[len(matched)-maxLines:]
	}
	return matched
}
