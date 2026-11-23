package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/awbait/debug-toolbox/internal/k8s"
)

const DefaultToolboxImage = "harbor.idp.ecpk.test/core/debug-toolbox:latest"

// Options configures temporary debug-toolbox pod creation.
type Options struct {
	Namespace   string
	Image       string
	InMesh      bool              // false -> istio.io/dataplane-mode: none
	ExtraLabels map[string]string // e.g. ecpk/egress=<veg> for direct/label mode
	Timeout     time.Duration
}

// Session represents a temporary debug-toolbox pod that cleans itself up on Close.
type Session struct {
	Client    *k8s.Client
	Namespace string
	PodName   string
}

// Start creates a ResourceQuota-safe temporary debug-toolbox pod and waits until Running/Ready.
func Start(ctx context.Context, c *k8s.Client, opts Options) (*Session, error) {
	if opts.Image == "" {
		opts.Image = DefaultToolboxImage
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 45 * time.Second
	}

	podName := fmt.Sprintf("mesh-debug-probe-%d", time.Now().Unix()%100000)
	labels := map[string]string{
		"app": "mesh-debug-probe",
	}
	if !opts.InMesh {
		labels["istio.io/dataplane-mode"] = "none"
	}
	for k, v := range opts.ExtraLabels {
		labels[k] = v
	}

	manifest := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      podName,
			"namespace": opts.Namespace,
			"labels":    labels,
		},
		"spec": map[string]any{
			"restartPolicy": "Never",
			"securityContext": map[string]any{
				"seccompProfile": map[string]any{"type": "RuntimeDefault"},
			},
			"containers": []map[string]any{
				{
					"name":    "toolbox",
					"image":   opts.Image,
					"command": []string{"sleep", "600"},
					"resources": map[string]any{
						"requests": map[string]string{"cpu": "50m", "memory": "64Mi"},
						"limits":   map[string]string{"cpu": "250m", "memory": "256Mi"},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	if _, err := c.KubectlStdin(ctx, string(raw), "apply", "-f", "-"); err != nil {
		return nil, fmt.Errorf("create probe pod %s/%s: %w", opts.Namespace, podName, err)
	}

	s := &Session{
		Client:    c,
		Namespace: opts.Namespace,
		PodName:   podName,
	}

	waitTimeout := fmt.Sprintf("%ds", int(opts.Timeout.Seconds()))
	if _, err := c.Kubectl(ctx, "wait", "--for=condition=Ready", "pod/"+podName, "-n", opts.Namespace, "--timeout="+waitTimeout); err != nil {
		_ = s.Close(context.Background())
		return nil, fmt.Errorf("probe pod %s/%s did not become Ready within %s: %w", opts.Namespace, podName, waitTimeout, err)
	}
	return s, nil
}

// Close removes the temporary probe pod.
func (s *Session) Close(ctx context.Context) error {
	if s == nil || s.PodName == "" {
		return nil
	}
	_, err := s.Client.Kubectl(ctx, "delete", "pod", s.PodName, "-n", s.Namespace, "--ignore-not-found=true", "--wait=false")
	return err
}

// ResolveDNS resolves host from inside the probe pod.
func (s *Session) ResolveDNS(ctx context.Context, host string) ([]string, error) {
	res, err := s.Client.PodExec(ctx, s.Namespace, s.PodName, "toolbox", "dig", "+short", "+time=3", "+tries=1", host)
	if err != nil {
		// Fallback to getent if dig fails.
		res2, err2 := s.Client.PodExec(ctx, s.Namespace, s.PodName, "toolbox", "getent", "hosts", host)
		if err2 != nil {
			return nil, fmt.Errorf("dns lookup for %s failed: %v", host, err)
		}
		var ips []string
		for _, line := range strings.Split(res2.Stdout, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				ips = append(ips, fields[0])
			}
		}
		return ips, nil
	}
	var out []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, ";") {
			out = append(out, line)
		}
	}
	return out, nil
}

// TCPCheck tests TCP reachability via nc -zv.
func (s *Session) TCPCheck(ctx context.Context, host string, port int) (string, error) {
	res, err := s.Client.PodExec(ctx, s.Namespace, s.PodName, "toolbox",
		"nc", "-zv", "-w", "5", host, fmt.Sprintf("%d", port))
	combined := strings.TrimSpace(res.Stdout + "\n" + res.Stderr)
	return combined, err
}

// CurlResult captures concise HTTP/TLS probe results.
type CurlResult struct {
	StatusCode string
	RemoteIP   string
	TimeTotal  string
	Verbose    string
	Err        error
}

// HTTPCheck runs curl against scheme://host:port/ optionally pinning --resolve and/or -x proxy.
func (s *Session) HTTPCheck(ctx context.Context, scheme, host string, port int, resolveIP, proxyURL string) CurlResult {
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	args := []string{
		"curl", "-sS", "-v", "-k", "--max-time", "8",
		"-o", "/dev/null",
		"-w", "\n__MESH_DEBUG__ code=%{http_code} ip=%{remote_ip} time=%{time_total}s\n",
	}
	if resolveIP != "" {
		args = append(args, "--resolve", fmt.Sprintf("%s:%d:%s", host, port, resolveIP))
	}
	if proxyURL != "" {
		args = append(args, "-x", proxyURL)
	}
	args = append(args, url)

	res, err := s.Client.PodExec(ctx, s.Namespace, s.PodName, "toolbox", args...)
	cr := CurlResult{
		Verbose: compactCurlVerbose(res.Stderr),
		Err:     err,
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if strings.HasPrefix(line, "__MESH_DEBUG__") {
			for _, field := range strings.Fields(line) {
				if k, v, ok := strings.Cut(field, "="); ok {
					switch k {
					case "code":
						cr.StatusCode = v
					case "ip":
						cr.RemoteIP = v
					case "time":
						cr.TimeTotal = v
					}
				}
			}
		}
	}
	return cr
}

// LoopbackCheck verifies whether an application container actually listens on 127.0.0.1:port (ambient-check step 1).
func LoopbackCheck(ctx context.Context, c *k8s.Client, ns, pod string, port int) (string, error) {
	script := fmt.Sprintf(
		`if command -v curl >/dev/null 2>&1; then curl -sS -o /dev/null -w "http_code=%%{http_code}" -m 3 http://127.0.0.1:%d/; `+
			`elif command -v nc >/dev/null 2>&1; then nc -zv -w 3 127.0.0.1 %d; `+
			`elif command -v ss >/dev/null 2>&1; then ss -ltn | grep ":%d "; `+
			`else echo "NO_TOOL"; fi`,
		port, port, port,
	)
	res, err := c.PodExec(ctx, ns, pod, "", "sh", "-c", script)
	out := strings.TrimSpace(res.Stdout + " " + res.Stderr)
	return out, err
}

func compactCurlVerbose(stderr string) string {
	var kept []string
	for _, raw := range strings.Split(stderr, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "< HTTP/") || strings.HasPrefix(line, "curl:") {
			// Skip overly chatty TLS dump lines while keeping key handshake/cert/error lines.
			if strings.Contains(line, "CAfile:") || strings.Contains(line, "CApath:") {
				continue
			}
			kept = append(kept, line)
		}
	}
	if len(kept) > 15 {
		kept = kept[:15]
	}
	return strings.Join(kept, "\n")
}
