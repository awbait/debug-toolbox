package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/awbait/debug-toolbox/internal/checks/common"
	"github.com/awbait/debug-toolbox/internal/checks/egress"
	"github.com/awbait/debug-toolbox/internal/checks/ingress"
	"github.com/awbait/debug-toolbox/internal/checks/policies"
	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/probe"
	"github.com/awbait/debug-toolbox/internal/report"
)

var version = "dev"

type commonFlags struct {
	Namespace    string
	Kubeconfig   string
	Context      string
	ZtunnelNS    string
	Format       string
	Since        string
	Probe        bool
	ToolboxImage string
	ProxyURL     string
	Verbose      bool
	NoColor      bool
	Timeout      time.Duration
}

func main() {
	if len(os.Args) < 2 {
		printRootUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "-h", "--help", "help":
		printRootUsage()
		return
	case "version", "--version":
		fmt.Printf("mesh-debug %s\n", version)
		return
	case "status", "ingress", "egress", "ztunnel", "policies":
		os.Exit(runSubcommand(subcmd, os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", subcmd)
		printRootUsage()
		os.Exit(1)
	}
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runSubcommand(subcmd string, args []string) int {
	fs := flag.NewFlagSet("mesh-debug "+subcmd, flag.ContinueOnError)
	var cf commonFlags
	var podName string
	var toTargets stringSliceFlag
	var captureDur time.Duration
	var captureMode string
	var captureNS string
	var emitPolicies bool
	var policyName string

	defaultImage := os.Getenv("TOOLBOX_IMAGE")
	if defaultImage == "" {
		defaultImage = probe.DefaultToolboxImage
	}

	fs.StringVar(&cf.Namespace, "n", "", "Target Kubernetes namespace")
	fs.StringVar(&cf.Namespace, "namespace", "", "Target Kubernetes namespace")
	fs.StringVar(&cf.Kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	fs.StringVar(&cf.Context, "context", "", "Kubernetes context name")
	fs.StringVar(&cf.ZtunnelNS, "ztunnel-ns", "", "Override ztunnel namespace (auto-detected if empty)")
	fs.StringVar(&cf.Format, "format", "text", "Output format: text | markdown | json")
	fs.StringVar(&cf.Since, "since", "15m", "Log lookback window (e.g. 5m, 15m, 1h)")
	fs.BoolVar(&cf.Probe, "probe", false, "Enable active probes (loopback exec + temporary debug-toolbox pod)")
	fs.StringVar(&cf.ToolboxImage, "toolbox-image", defaultImage, "Image for temporary debug-toolbox probe pod")
	fs.StringVar(&cf.ProxyURL, "proxy", "", "Optional corporate HTTP proxy URL for egress --probe (e.g. http://10.192.95.164:8090)")
	fs.BoolVar(&cf.Verbose, "verbose", false, "Include executed kubectl/istioctl commands in output")
	fs.BoolVar(&cf.NoColor, "no-color", false, "Disable ANSI colors in text output")
	fs.DurationVar(&cf.Timeout, "timeout", 2*time.Minute, "Overall diagnostic timeout")
	if subcmd == "ztunnel" {
		fs.StringVar(&podName, "pod", "", "Filter ztunnel diagnostics to a specific pod")
	}
	if subcmd == "policies" {
		fs.Var(&toTargets, "to", "Simulate target path (repeatable: kube-apiserver, coredns, istiod, ns/svc:port, ip:port)")
		fs.DurationVar(&captureDur, "capture", 0, "Live packet capture duration (e.g. 30s) via tcpdump to discover connection attempts")
		fs.StringVar(&captureMode, "capture-mode", "node", "Capture mode: node (default, works with PodSecurity baseline/restricted) | ephemeral")
		fs.StringVar(&captureNS, "capture-ns", "default", "Namespace for temporary privileged node-capture pod")
		fs.BoolVar(&emitPolicies, "emit-policies", false, "Generate console-charts/policies values.yaml draft")
		fs.StringVar(&policyName, "policy-name", "", "Optional 2..6 char policy name for --emit-policies")
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	target := ""
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	if (subcmd == "ingress" || subcmd == "egress" || subcmd == "ztunnel" || subcmd == "policies") && cf.Namespace == "" {
		fmt.Fprintf(os.Stderr, "error: -n / --namespace is required for %q\n", subcmd)
		return 1
	}
	if subcmd == "policies" && target == "" {
		fmt.Fprintf(os.Stderr, "error: target pod or workload (e.g. <pod> or deploy/<name>) is required for \"policies\"\n")
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeoutCancel := context.WithTimeout(ctx, cf.Timeout)
	defer timeoutCancel()

	runner := k8s.NewExecRunner()
	client := k8s.NewClient(runner, cf.Kubeconfig, cf.Context, cf.ZtunnelNS)

	var rep *report.Report
	switch subcmd {
	case "status":
		rep = report.New(version, "status", "", "", false)
		common.CheckControlPlane(ctx, client, rep, true)
		rep.Finalize(runner.History(), cf.Verbose)
	case "ingress":
		rep = ingress.Run(ctx, client, ingress.Options{
			Version:      version,
			Namespace:    cf.Namespace,
			GatewayName:  target,
			Since:        cf.Since,
			Probe:        cf.Probe,
			ToolboxImage: cf.ToolboxImage,
			Verbose:      cf.Verbose,
		})
	case "egress":
		rep = egress.Run(ctx, client, egress.Options{
			Version:      version,
			Namespace:    cf.Namespace,
			Name:         target,
			Since:        cf.Since,
			Probe:        cf.Probe,
			ToolboxImage: cf.ToolboxImage,
			ProxyURL:     cf.ProxyURL,
			Verbose:      cf.Verbose,
		})
	case "ztunnel":
		rep = common.RunZtunnelReport(ctx, client, version, cf.Namespace, podName, cf.Since, cf.Verbose)
	case "policies":
		rep = policies.Run(ctx, client, policies.Options{
			Version:      version,
			Namespace:    cf.Namespace,
			Target:       target,
			Since:        cf.Since,
			To:           toTargets,
			Capture:      captureDur,
			CaptureMode:  captureMode,
			CaptureNS:    captureNS,
			ToolboxImage: cf.ToolboxImage,
			EmitPolicies: emitPolicies,
			PolicyName:   policyName,
			Verbose:      cf.Verbose,
		})
	}

	if subcmd == "policies" && strings.EqualFold(cf.Format, "yaml") {
		if y := rep.Metadata["policies_values_yaml"]; y != "" {
			fmt.Print(y)
			return rep.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "error: --format yaml requires --emit-policies\n")
		return 1
	}

	useColor := !cf.NoColor && isTerminal(os.Stdout)
	if err := report.Write(os.Stdout, rep, report.FormatOptions{
		Format:  cf.Format,
		Color:   useColor,
		Verbose: cf.Verbose,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error rendering report: %v\n", err)
		return 1
	}
	return rep.ExitCode()
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

func printRootUsage() {
	fmt.Print(`mesh-debug - Istio Ambient + Kube-OVN diagnostics for ingress-gateway & egress-gateway

Usage:
  mesh-debug <command> [flags] [target]

Commands:
  status                         Check cluster-wide mesh control plane, kube-ovn, kyverno, MetalLB
  ingress -n <ns> [gateway]      Diagnose ingress-gateway (Gateway, TLS, Routes, ReferenceGrant, Policies, ztunnel)
  egress  -n <ns> [name]         Diagnose egress-gateway (mesh & direct; accepts senders, waypoint, or VEG namespace)
  ztunnel -n <ns> [--pod <pod>]  Inspect ambient redirection, ztunnel-config workloads, and filtered ztunnel logs
  policies -n <ns> <pod|deploy/x> Map pod/operator/gateway traffic hops (NP, ztunnel, PA, AP), optional --capture & --emit-policies
  version                        Print version

Common Flags:
  -n, --namespace <ns>           Target namespace
  --format text|markdown|json    Output format (default: text; use json for LLM automation)
  --probe                        Run active probes (loopback check + temporary debug-toolbox pod with auto-cleanup)
  --toolbox-image <image>        Override debug-toolbox image (default: $TOOLBOX_IMAGE)
  --proxy <url>                  Corporate HTTP proxy URL for egress --probe
  --since <duration>             Log lookback window (default: 15m)
  --ztunnel-ns <ns>              Override ztunnel namespace (auto-detected by default)
  --kubeconfig <path>            Explicit kubeconfig path
  --context <name>               Explicit kubectl context
  --verbose                      Include executed kubectl/istioctl commands in output
  --no-color                     Disable ANSI colors

Exit codes:
  0  HEALTHY or DEGRADED (no FAIL checks)
  1  CLI usage or runtime error
  2  BROKEN (one or more FAIL checks detected)
`)
}
