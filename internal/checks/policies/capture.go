package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/probe"
)

// CapturedPacket summarizes one observed connection attempt from tcpdump.
type CapturedPacket struct {
	Direction string // "outbound" | "inbound"
	PeerIP    string
	Port      int    // destination port (remote port for outbound, local port for inbound)
	Protocol  string // "TCP" | "UDP"
}

// RunPacketCapture executes a short-lived tcpdump capture in the target pod's network namespace.
//   - mode "node" (default): runs a temporary privileged debug-toolbox pod on the target pod's node
//     in captureNS (works in PodSecurity baseline/restricted namespaces and distroless pods,
//     and never mutates the target pod).
//   - mode "ephemeral": uses `kubectl debug <pod> --profile=netadmin` (only works in privileged NS).
func RunPacketCapture(
	ctx context.Context,
	c *k8s.Client,
	target k8s.Pod,
	duration time.Duration,
	mode string,
	captureNS string,
	toolboxImage string,
) ([]CapturedPacket, string, error) {
	if duration <= 0 {
		return nil, "", nil
	}
	if toolboxImage == "" {
		toolboxImage = probe.DefaultToolboxImage
	}
	if mode == "" {
		mode = "node"
	}
	if captureNS == "" {
		captureNS = "default"
	}

	sec := int(duration.Seconds())
	if sec < 3 {
		sec = 3
	}
	if sec > 180 {
		sec = 180
	}

	// Capture only TCP SYN (non-ACK) connection attempts and UDP packets (DNS, etc.)
	// so we see both succeeded and blocked connection attempts with minimal noise.
	bpfFilter := `((tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack == 0)) or udp`

	var rawOut string
	var err error
	switch strings.ToLower(mode) {
	case "node":
		rawOut, err = captureViaNode(ctx, c, target, sec, captureNS, toolboxImage, bpfFilter)
	case "ephemeral":
		rawOut, err = captureViaEphemeral(ctx, c, target, sec, toolboxImage, bpfFilter)
	default:
		return nil, "", fmt.Errorf("unsupported capture-mode %q (expected node or ephemeral)", mode)
	}
	if err != nil {
		return nil, rawOut, err
	}
	pkts := ParseTcpdumpOutput(rawOut, target.Status.PodIP)
	return pkts, rawOut, nil
}

func captureViaNode(
	ctx context.Context,
	c *k8s.Client,
	target k8s.Pod,
	sec int,
	captureNS string,
	image string,
	bpfFilter string,
) (string, error) {
	if target.Spec.NodeName == "" {
		return "", fmt.Errorf("target pod %s/%s has no assigned nodeName", target.Metadata.Namespace, target.Metadata.Name)
	}
	cid := extractContainerID(target)
	if cid == "" {
		return "", fmt.Errorf("target pod %s/%s has no running containerID for nsenter", target.Metadata.Namespace, target.Metadata.Name)
	}

	capPodName := fmt.Sprintf("mesh-debug-cap-%d", time.Now().Unix()%100000)
	manifest := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      capPodName,
			"namespace": captureNS,
			"labels": map[string]string{
				"app":                     "mesh-debug-capture",
				"istio.io/dataplane-mode": "none",
			},
		},
		"spec": map[string]any{
			"nodeName":      target.Spec.NodeName,
			"hostPID":       true,
			"restartPolicy": "Never",
			"tolerations": []map[string]any{
				{"operator": "Exists"},
			},
			"containers": []map[string]any{
				{
					"name":    "capture",
					"image":   image,
					"command": []string{"sleep", strconv.Itoa(sec + 60)},
					"securityContext": map[string]any{
						"privileged": true,
					},
					"resources": map[string]any{
						"requests": map[string]string{"cpu": "50m", "memory": "64Mi"},
						"limits":   map[string]string{"cpu": "250m", "memory": "256Mi"},
					},
					"volumeMounts": []map[string]any{
						{"name": "host-root", "mountPath": "/host", "readOnly": true},
					},
				},
			},
			"volumes": []map[string]any{
				{"name": "host-root", "hostPath": map[string]string{"path": "/"}},
			},
		},
	}

	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	if _, err := c.KubectlStdin(ctx, string(rawManifest), "apply", "-f", "-"); err != nil {
		return "", fmt.Errorf("create node-capture pod in %s on node %s: %w", captureNS, target.Spec.NodeName, err)
	}
	defer func() {
		_, _ = c.Kubectl(context.Background(), "delete", "pod", capPodName, "-n", captureNS, "--ignore-not-found=true", "--wait=false")
	}()

	if _, err := c.Kubectl(ctx, "wait", "--for=condition=Ready", "pod/"+capPodName, "-n", captureNS, "--timeout=45s"); err != nil {
		return "", fmt.Errorf("node-capture pod %s/%s not Ready: %w", captureNS, capPodName, err)
	}

	script := fmt.Sprintf(
		`PID=$(chroot /host crictl inspect --output go-template --template '{{.info.pid}}' %q 2>/dev/null || chroot /host crictl inspect %q 2>/dev/null | jq -r '.info.pid // empty'); `+
			`if [ -z "$PID" ]; then echo "__ERR_NO_PID__"; exit 1; fi; `+
			`timeout %d nsenter -t "$PID" -n tcpdump -i any -nn -l -q %q 2>&1 || true`,
		cid, cid, sec, bpfFilter,
	)

	res, err := c.PodExec(ctx, captureNS, capPodName, "capture", "sh", "-c", script)
	if err != nil && !strings.Contains(res.Stdout, "IP ") && !strings.Contains(res.Stdout, "IP6 ") {
		if strings.Contains(res.Stdout, "__ERR_NO_PID__") {
			return res.Stdout, fmt.Errorf("could not resolve container PID for %s via crictl on node %s", cid, target.Spec.NodeName)
		}
		return res.Stdout, fmt.Errorf("node-capture tcpdump failed: %w", err)
	}
	return res.Stdout, nil
}

func captureViaEphemeral(
	ctx context.Context,
	c *k8s.Client,
	target k8s.Pod,
	sec int,
	image string,
	bpfFilter string,
) (string, error) {
	script := fmt.Sprintf(`timeout %d tcpdump -i any -nn -l -q %q 2>&1 || true`, sec, bpfFilter)
	res, err := c.Kubectl(ctx, "debug", target.Metadata.Name, "-n", target.Metadata.Namespace,
		"--image="+image, "--profile=netadmin", "--attach=true", "--quiet",
		"--", "sh", "-c", script)
	if err != nil && !strings.Contains(res.Stdout, "IP ") && !strings.Contains(res.Stdout, "IP6 ") {
		return res.Stdout, fmt.Errorf("ephemeral tcpdump failed (note: PodSecurity baseline/restricted forbids NET_RAW; use --capture-mode node): %w", err)
	}
	return res.Stdout, nil
}

func extractContainerID(p k8s.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.ContainerID != "" {
			id := cs.ContainerID
			if _, after, ok := strings.Cut(id, "://"); ok {
				return after
			}
			return id
		}
	}
	return ""
}

// Matches standard `tcpdump -nn -q` lines for IPv4 and IPv6, e.g.:
//
//	08:01:02.123456 eth0 Out IP 172.19.10.5.45122 > 10.96.0.1.443: tcp 0
//	08:01:02.123456 IP 172.19.10.5.53411 > 10.96.0.10.53: UDP, length 42
var tcpdumpLineRe = regexp.MustCompile(`\b(IP6?)\s+([0-9a-fA-F:.]+)\.(\d+)\s+>\s+([0-9a-fA-F:.]+)\.(\d+):\s+(\S+)`)

// ParseTcpdumpOutput extracts deduplicated outbound/inbound connection attempts from tcpdump output.
func ParseTcpdumpOutput(raw, podIP string) []CapturedPacket {
	seen := make(map[string]bool)
	var out []CapturedPacket

	podAddr, _ := netip.ParseAddr(strings.TrimSpace(podIP))
	podAddr = podAddr.Unmap()

	for _, line := range strings.Split(raw, "\n") {
		m := tcpdumpLineRe.FindStringSubmatch(line)
		if len(m) < 7 {
			continue
		}
		srcIPStr, srcPortStr := m[2], m[3]
		dstIPStr, dstPortStr := m[4], m[5]
		protoTok := strings.ToUpper(strings.TrimRight(m[6], ","))

		proto := "TCP"
		if strings.HasPrefix(protoTok, "UDP") || strings.Contains(strings.ToUpper(line), "UDP") {
			proto = "UDP"
		} else if !strings.HasPrefix(protoTok, "TCP") && !strings.Contains(strings.ToUpper(line), "FLAGS [S]") {
			continue
		}

		srcAddr, err1 := netip.ParseAddr(srcIPStr)
		dstAddr, err2 := netip.ParseAddr(dstIPStr)
		srcPort, err3 := strconv.Atoi(srcPortStr)
		dstPort, err4 := strconv.Atoi(dstPortStr)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			continue
		}
		srcAddr, dstAddr = srcAddr.Unmap(), dstAddr.Unmap()

		if isNoiseIP(srcAddr) || isNoiseIP(dstAddr) {
			continue
		}

		var dir, peerIP string
		var port int
		if podAddr.IsValid() && srcAddr == podAddr {
			// Skip UDP reply packets originating from a local low service port to a high ephemeral port
			if proto == "UDP" && srcPort <= 1053 && dstPort >= 32768 {
				continue
			}
			dir = "outbound"
			peerIP = dstAddr.String()
			port = dstPort
		} else if podAddr.IsValid() && dstAddr == podAddr {
			// Skip UDP replies returning from remote DNS/service port to our ephemeral port
			if proto == "UDP" && srcPort <= 1053 && dstPort >= 32768 {
				continue
			}
			dir = "inbound"
			peerIP = srcAddr.String()
			port = dstPort
		} else {
			continue
		}

		if isNoisePort(port) {
			continue
		}

		key := fmt.Sprintf("%s|%s|%d|%s", dir, peerIP, port, proto)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, CapturedPacket{
			Direction: dir,
			PeerIP:    peerIP,
			Port:      port,
			Protocol:  proto,
		})
	}
	return out
}

func isNoiseIP(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	// Istio Ambient kubelet host-probe link-local IP
	if addr.String() == "169.254.7.127" {
		return true
	}
	return false
}

func isNoisePort(port int) bool {
	switch port {
	case 0, 15001, 15006, 15008, 15020, 15021, 15090:
		return true
	}
	return false
}
