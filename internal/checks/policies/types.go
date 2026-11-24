package policies

import (
	"fmt"
	"strings"
	"time"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

// Options configures a `mesh-debug policies` diagnostic run.
type Options struct {
	Version      string
	Namespace    string
	Target       string        // pod name, deploy/<name>, sts/<name>, ds/<name>, or pod prefix
	Since        string        // log lookback window (default 15m)
	To           []string      // optional simulated targets (e.g. kube-apiserver, ns/svc:port, ip:port)
	Capture      time.Duration // if > 0, run live packet capture for this duration
	CaptureMode  string        // "node" (default, works with PSS baseline/restricted) | "ephemeral"
	CaptureNS    string        // namespace for temporary node-capture pod (default "default")
	ToolboxImage string
	EmitPolicies bool   // generate values.yaml draft for console-charts/policies
	PolicyName   string // optional 2..6 char name for generated policy entry
	Verbose      bool
}

const (
	WorkloadGeneric        = "workload"
	WorkloadOperator       = "operator"
	WorkloadIngressGateway = "ingress-gateway"
	WorkloadWaypoint       = "waypoint"
)

const (
	PeerPod           = "pod"
	PeerService       = "service"
	PeerKubeAPIServer = "kube-apiserver"
	PeerCoreDNS       = "coredns"
	PeerIstiod        = "istiod"
	PeerServiceEntry  = "service-entry"
	PeerExternal      = "external"
	PeerUnknown       = "unknown"
)

// Endpoint describes a resolved source or destination workload/service/external IP.
type Endpoint struct {
	Kind           string            // Peer* constant
	Namespace      string
	ServiceName    string
	PodName        string
	IP             string
	AllIPs         []string          // e.g. all control-plane endpoint IPs for kube-apiserver
	Port           int
	Protocol       string            // TCP | UDP
	NodeName       string
	ZtunnelPod     string
	ServiceAccount string
	Principal      string            // cluster.local/ns/<ns>/sa/<sa>
	Labels         map[string]string
	StableSelector map[string]string // from Deployment/StatefulSet/Service
	Ambient        bool
	Hostname       string
}

// DisplayName returns a concise human-readable label for an endpoint.
func (e Endpoint) DisplayName() string {
	proto := e.Protocol
	if proto == "" {
		proto = "TCP"
	}
	switch e.Kind {
	case PeerKubeAPIServer:
		return fmt.Sprintf("kube-apiserver (%s:%d/%s)", strings.Join(e.effectiveIPs(), ","), e.Port, proto)
	case PeerCoreDNS:
		return fmt.Sprintf("CoreDNS kube-system/kube-dns (:%d/%s)", e.Port, proto)
	case PeerIstiod:
		return fmt.Sprintf("istiod istio-system/istiod (:%d/%s)", e.Port, proto)
	case PeerServiceEntry:
		h := e.Hostname
		if h == "" {
			h = e.IP
		}
		return fmt.Sprintf("ServiceEntry %s (%s:%d/%s)", h, e.IP, e.Port, proto)
	case PeerService, PeerPod:
		name := e.ServiceName
		if name == "" {
			name = e.PodName
		}
		if name == "" {
			name = e.IP
		}
		if e.Namespace != "" {
			return fmt.Sprintf("%s/%s:%d/%s", e.Namespace, name, e.Port, proto)
		}
		return fmt.Sprintf("%s:%d/%s", name, e.Port, proto)
	default:
		if e.Hostname != "" {
			return fmt.Sprintf("%s (%s:%d/%s)", e.Hostname, e.IP, e.Port, proto)
		}
		return fmt.Sprintf("%s:%d/%s", e.IP, e.Port, proto)
	}
}

func (e Endpoint) effectiveIPs() []string {
	if len(e.AllIPs) > 0 {
		return e.AllIPs
	}
	if e.IP != "" {
		return []string{e.IP}
	}
	return nil
}

// HopResult represents a single step along the network path.
type HopResult struct {
	Hop        string
	Status     report.Status
	Summary    string
	Suggestion string
	Evidence   []string
}

// Flow represents one discovered or simulated connection involving the target pod.
type Flow struct {
	Direction      string   // "outbound" | "inbound"
	Peer           Endpoint // remote endpoint (for inbound, Peer.Port is the destination port on target pod)
	LocalPort      int      // for inbound, target pod's listening port
	Sources        []string // ztunnel-logs, tcpdump, static-rbac, webhook, route, service-entry, simulated
	ObservedLogs   []string
	ObservedErrors []string
	Hops           []HopResult
	Verdict        report.Status
}

// FlowKey uniquely identifies a deduplicated flow.
func (f Flow) Key() string {
	proto := strings.ToUpper(f.Peer.Protocol)
	if proto == "" {
		proto = "TCP"
	}
	port := f.Peer.Port
	if f.Direction == "inbound" && f.LocalPort > 0 {
		port = f.LocalPort
	}
	switch f.Peer.Kind {
	case PeerKubeAPIServer:
		return fmt.Sprintf("%s|kube-apiserver|%d|%s", f.Direction, port, proto)
	case PeerCoreDNS:
		return fmt.Sprintf("%s|coredns|%d|%s", f.Direction, port, proto)
	case PeerIstiod:
		return fmt.Sprintf("%s|istiod|%d|%s", f.Direction, port, proto)
	case PeerServiceEntry:
		return fmt.Sprintf("%s|se|%s|%d|%s", f.Direction, f.Peer.Hostname, port, proto)
	case PeerService, PeerPod:
		target := f.Peer.ServiceName
		if target == "" {
			target = f.Peer.PodName
		}
		if target == "" {
			target = f.Peer.IP
		}
		return fmt.Sprintf("%s|svc|%s/%s|%d|%s", f.Direction, f.Peer.Namespace, target, port, proto)
	default:
		return fmt.Sprintf("%s|ip|%s|%d|%s", f.Direction, f.Peer.IP, port, proto)
	}
}

// TargetInfo summarizes the inspected pod and its runtime context.
type TargetInfo struct {
	Pod            k8s.Pod
	Namespace      k8s.Namespace
	WorkloadKind   string // Workload* constant
	OwnerKind      string // Deployment, StatefulSet, DaemonSet, ...
	OwnerName      string
	StableSelector map[string]string
	ServiceAccount string
	Principal      string
	Ambient        bool
	Redirected     bool
	ZtunnelNS      string
	ZtunnelPod     string // ztunnel pod on Pod.Spec.NodeName
	OVNSubnet      string
	HasAPIRBAC     bool
}

// ClusterIndex holds read-only cluster topology maps for fast IP/Service/NS resolution.
type ClusterIndex struct {
	Namespaces      map[string]k8s.Namespace
	ServicesByKey   map[string]k8s.Service   // ns/name -> Service
	ServicesByCIP   map[string]k8s.Service   // clusterIP -> Service
	EndpointsByKey  map[string]k8s.Endpoints // ns/name -> Endpoints
	PodsByIP        map[string]k8s.Pod
	PodsByNS        map[string][]k8s.Pod
	ServiceByPodIP  map[string]k8s.Service // endpoint IP -> owning Service
	ServiceEntryVIP map[string]k8s.ServiceEntry
	ServiceEntryHst map[string]k8s.ServiceEntry
	ZtunnelByNode   map[string]k8s.Pod
	APIServerIPs    []string
	APIServerPort   int
	CoreDNSIPs      []string
	IstiodIPs       []string
}
