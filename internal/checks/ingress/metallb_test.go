package ingress

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

func findCheck(rep *report.Report, id string) (report.Check, bool) {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return report.Check{}, false
}

func TestMetalLBIPNotAllowedOutsidePools(t *testing.T) {
	f := baseHealthyIngressRunner(t, time.Now().Add(90*24*time.Hour), []string{"app.idp.ecpk.test"})

	// Exact scenario: Service requests 10.193.98.110 which is outside all IPAddressPools,
	// and MetalLB emits AllocationFailed: ["10.193.98.110"] is not allowed in config.
	f.On("kubectl get service ed-dev-igw-nbox-main-istio -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw","annotations":{"metallb.io/loadBalancerIPs":"10.193.98.110"}},"spec":{"type":"LoadBalancer","clusterIP":"10.96.1.10","externalTrafficPolicy":"Local"},"status":{"loadBalancer":{}}}`)
	f.On("kubectl get events -n app-igw --field-selector type=Warning -o json",
		`{"items":[{"type":"Warning","reason":"AllocationFailed","count":3,"message":"Failed to allocate IP for \"app-igw/ed-dev-igw-nbox-main-istio\": [\"10.193.98.110\"] is not allowed in config","involvedObject":{"kind":"Service","name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw"}}]}`)
	f.On("kubectl get ipaddresspools.metallb.io -A -o json",
		`{"items":[{"metadata":{"name":"igw-pool","namespace":"metallb-system"},"spec":{"addresses":["10.193.98.10-10.193.98.50","10.193.99.0/28"]}}]}`)

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "app-igw"})

	if rep.Summary.Verdict != "BROKEN" {
		t.Fatalf("expected BROKEN, got %s", rep.Summary.Verdict)
	}
	chk, ok := findCheck(rep, "gw-vip-ed-dev-igw-nbox-main")
	if !ok || chk.Status != report.StatusFail {
		t.Fatalf("expected FAIL check gw-vip-ed-dev-igw-nbox-main, got: %+v", chk)
	}
	if !strings.Contains(chk.Message, "10.193.98.110") || !strings.Contains(chk.Message, "not allowed in config") {
		t.Errorf("unexpected check message: %s", chk.Message)
	}
	joinedEv := strings.Join(chk.Evidence, "\n")
	if !strings.Contains(joinedEv, "AllocationFailed") || !strings.Contains(joinedEv, "metallb-system/igw-pool") {
		t.Errorf("expected event and pool list in evidence, got:\n%s", joinedEv)
	}
}

func TestMetalLBIPNotAllowedByServiceAllocation(t *testing.T) {
	f := baseHealthyIngressRunner(t, time.Now().Add(90*24*time.Hour), []string{"app.idp.ecpk.test"})

	// IP 10.193.98.110 IS in the pool's CIDR, but pool.spec.serviceAllocation restricts namespaces to ["other-ns"].
	f.On("kubectl get service ed-dev-igw-nbox-main-istio -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw","annotations":{"metallb.universe.tf/loadBalancerIPs":"10.193.98.110"}},"spec":{"type":"LoadBalancer","clusterIP":"10.96.1.10"},"status":{"loadBalancer":{}}}`)
	f.On("kubectl get events -n app-igw --field-selector type=Warning -o json",
		`{"items":[{"type":"Warning","reason":"AllocationFailed","count":1,"message":"Failed to allocate IP for \"app-igw/ed-dev-igw-nbox-main-istio\": [\"10.193.98.110\"] is not allowed in config","involvedObject":{"kind":"Service","name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw"}}]}`)
	f.On("kubectl get ipaddresspools.metallb.io -A -o json",
		`{"items":[{"metadata":{"name":"finops-pool","namespace":"metallb-system"},"spec":{"addresses":["10.193.98.0/24"],"serviceAllocation":{"namespaces":["other-ns"]}}}]}`)

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "app-igw"})

	chk, ok := findCheck(rep, "gw-vip-ed-dev-igw-nbox-main")
	if !ok || chk.Status != report.StatusFail {
		t.Fatalf("expected FAIL check gw-vip-ed-dev-igw-nbox-main, got: %+v", chk)
	}
	if !strings.Contains(chk.Message, "serviceAllocation") || !strings.Contains(chk.Message, "app-igw") {
		t.Errorf("expected serviceAllocation denial mentioning app-igw, got: %s", chk.Message)
	}
}

func TestMetalLBIPNotAllowedEventOnlyWhenPoolsForbidden(t *testing.T) {
	f := baseHealthyIngressRunner(t, time.Now().Add(90*24*time.Hour), []string{"app.idp.ecpk.test"})

	// Simulate RBAC Forbidden on cluster-wide ipaddresspools.metallb.io, with AllocationFailed event present.
	f.On("kubectl get service ed-dev-igw-nbox-main-istio -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw","annotations":{"metallb.io/loadBalancerIPs":"10.193.98.110"}},"spec":{"type":"LoadBalancer","clusterIP":"10.96.1.10"},"status":{"loadBalancer":{}}}`)
	f.On("kubectl get events -n app-igw --field-selector type=Warning -o json",
		`{"items":[{"type":"Warning","reason":"AllocationFailed","count":5,"message":"Failed to allocate IP for \"app-igw/ed-dev-igw-nbox-main-istio\": [\"10.193.98.110\"] is not allowed in config","involvedObject":{"kind":"Service","name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw"}}]}`)
	f.OnErr("kubectl get ipaddresspools.metallb.io -A -o json",
		`Error from server (Forbidden): ipaddresspools.metallb.io is forbidden`,
		fmt.Errorf("forbidden"))

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "app-igw"})

	chk, ok := findCheck(rep, "gw-vip-ed-dev-igw-nbox-main")
	if !ok || chk.Status != report.StatusFail {
		t.Fatalf("expected FAIL check gw-vip-ed-dev-igw-nbox-main, got: %+v", chk)
	}
	if !strings.Contains(chk.Message, "not allowed in MetalLB config") || !strings.Contains(chk.Message, "10.193.98.110") {
		t.Errorf("expected fallback event diagnosis for 'not allowed in config', got: %s", chk.Message)
	}
}

func TestMetalLBIPNotAllowedEvenWhenEventsExpired(t *testing.T) {
	f := baseHealthyIngressRunner(t, time.Now().Add(90*24*time.Hour), []string{"app.idp.ecpk.test"})

	// No warning events (expired after 1h), requested via spec.loadBalancerIP, outside pool ranges.
	f.On("kubectl get service ed-dev-igw-nbox-main-istio -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw"},"spec":{"type":"LoadBalancer","clusterIP":"10.96.1.10","loadBalancerIP":"10.193.98.110"},"status":{"loadBalancer":{}}}`)
	f.On("kubectl get events -n app-igw --field-selector type=Warning -o json", `{"items":[]}`)
	f.On("kubectl get ipaddresspools.metallb.io -A -o json",
		`{"items":[{"metadata":{"name":"default-pool","namespace":"metallb-system"},"spec":{"addresses":["10.193.10.1-10.193.10.99"]}}]}`)

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "app-igw"})

	chk, ok := findCheck(rep, "gw-vip-ed-dev-igw-nbox-main")
	if !ok || chk.Status != report.StatusFail {
		t.Fatalf("expected FAIL check gw-vip-ed-dev-igw-nbox-main, got: %+v", chk)
	}
	if !strings.Contains(chk.Message, "10.193.98.110") || !strings.Contains(chk.Message, "not allowed in config") {
		t.Errorf("expected config mismatch diagnosis even without events, got: %s", chk.Message)
	}
}

func TestMetalLBRequestedPoolMismatchAndCollision(t *testing.T) {
	// 1. Requested address-pool doesn't contain IP, while another pool does
	f := baseHealthyIngressRunner(t, time.Now().Add(90*24*time.Hour), []string{"app.idp.ecpk.test"})
	f.On("kubectl get service ed-dev-igw-nbox-main-istio -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw","annotations":{"metallb.io/loadBalancerIPs":"10.193.98.110","metallb.io/address-pool":"pool-a"}},"spec":{"type":"LoadBalancer","clusterIP":"10.96.1.10"},"status":{"loadBalancer":{"ingress":[{"ip":"10.193.10.50"}]}}}`)
	f.On("kubectl get ipaddresspools.metallb.io -A -o json",
		`{"items":[{"metadata":{"name":"pool-a","namespace":"metallb-system"},"spec":{"addresses":["10.193.10.0/24"]}},{"metadata":{"name":"pool-b","namespace":"metallb-system"},"spec":{"addresses":["10.193.98.100-10.193.98.120"]}}]}`)

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "app-igw"})

	chk, ok := findCheck(rep, "gw-vip-match-ed-dev-igw-nbox-main")
	if !ok || chk.Status != report.StatusFail {
		t.Fatalf("expected FAIL check gw-vip-match-ed-dev-igw-nbox-main, got: %+v", chk)
	}
	if !strings.Contains(chk.Message, "pool-a") || !strings.Contains(chk.Message, "pool-b") {
		t.Errorf("expected message mentioning pool-a and hint for pool-b, got: %s", chk.Message)
	}

	// 2. IP already allocated collision (valid in pool, event says already allocated)
	f2 := baseHealthyIngressRunner(t, time.Now().Add(90*24*time.Hour), []string{"app.idp.ecpk.test"})
	f2.On("kubectl get service ed-dev-igw-nbox-main-istio -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw","annotations":{"metallb.io/loadBalancerIPs":"10.193.98.110"}},"spec":{"type":"LoadBalancer","clusterIP":"10.96.1.10"},"status":{"loadBalancer":{}}}`)
	f2.On("kubectl get events -n app-igw --field-selector type=Warning -o json",
		`{"items":[{"type":"Warning","reason":"AllocationFailed","count":2,"message":"Failed to allocate IP for \"app-igw/ed-dev-igw-nbox-main-istio\": \"10.193.98.110\" is already allocated to \"other-ns/other-svc\"","involvedObject":{"kind":"Service","name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw"}}]}`)
	f2.On("kubectl get ipaddresspools.metallb.io -A -o json",
		`{"items":[{"metadata":{"name":"pool-b","namespace":"metallb-system"},"spec":{"addresses":["10.193.98.100-10.193.98.120"]}}]}`)

	client2 := k8s.NewClient(f2, "", "", "")
	rep2 := Run(context.Background(), client2, Options{Version: "test", Namespace: "app-igw"})

	chk2, ok := findCheck(rep2, "gw-vip-ed-dev-igw-nbox-main")
	if !ok || chk2.Status != report.StatusFail {
		t.Fatalf("expected FAIL check gw-vip-ed-dev-igw-nbox-main, got: %+v", chk2)
	}
	if !strings.Contains(chk2.Message, "already allocated") {
		t.Errorf("expected collision message, got: %s", chk2.Message)
	}
}

func TestPoolContainsIPAndAvoidBuggyIPs(t *testing.T) {
	pool := k8s.IPAddressPool{}
	pool.Metadata.Name = "test-pool"
	pool.Metadata.Namespace = "metallb-system"
	pool.Spec.Addresses = []string{
		"10.193.98.0/24",
		"10.193.99.10-10.193.99.20",
		"10.193.100.5",
		"2001:db8::10-2001:db8::20",
	}
	pool.Spec.AvoidBuggyIPs = true

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.193.98.110", true},
		{"10.193.98.0", true},
		{"10.193.99.10", true},
		{"10.193.99.20", true},
		{"10.193.99.21", false},
		{"10.193.100.5", true},
		{"10.193.100.6", false},
		{"2001:db8::15", true},
		{"2001:db8::25", false},
	}
	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.ip)
		if got := poolContainsIP(pool, addr); got != tc.want {
			t.Errorf("poolContainsIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}

	svc := k8s.Service{}
	svc.Metadata.Name = "ed-tco-igw-obs-finops-istio"
	svc.Metadata.Namespace = "ecpk-finops"
	ns := k8s.Namespace{}
	ns.Metadata.Name = "ecpk-finops"

	diag := analyzeMetalLBPools(svc, ns, []string{"10.193.98.0"}, "metallb.io/loadBalancerIPs", "", []k8s.IPAddressPool{pool})
	if !diag.Broken || diag.Code != "buggy_ip" {
		t.Errorf("expected buggy_ip diagnosis for .0 with avoidBuggyIPs=true, got: %+v", diag)
	}
}
