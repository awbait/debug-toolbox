package egress

import (
	"context"
	"strings"
	"testing"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

func findCheckByID(rep *report.Report, id string) (report.Check, bool) {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return report.Check{}, false
}

func TestVEGAddressOutOfRangeAndMisalignedSelector(t *testing.T) {
	f := baseHealthyMeshEgressRunner()

	// Exact reproduction of the obs-dev-ns-veg-vip / ed-dev-veg-obs-ceph incident:
	// 1) VEG externalIP 10.193.98.205 is outside egress-vip CIDR (10.193.97.0/24)
	// 2) VEG selectors target sender NS nbox-app directly (without podSelector) instead of waypoint
	// 3) VEG pod is Pending with AcquireAddressFailed (AddressOutOfRange) + FailedCreatePodSandbox (no address allocated)
	f.On("kubectl get vpcegressgateways.kubeovn.io -A -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip","namespace":"nbox-dev-ns-veg-vip"},"spec":{"vpc":"ovn-cluster","replicas":1,"internalSubnet":"ovn-default","externalSubnet":"egress-vip","externalIPs":["10.193.98.205"],"selectors":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"nbox-app"}}}]},"status":{"ready":false,"phase":"Pending"}}]}`)
	f.On("kubectl get subnets.kubeovn.io -o json",
		`{"items":[{"metadata":{"name":"ovn-default"},"spec":{"cidrBlock":"172.30.0.0/16","gateway":"172.30.0.1"}},{"metadata":{"name":"nbox-dev-subnet-egw-eg"},"spec":{"cidrBlock":"172.19.20.0/28","private":false,"namespaces":["nbox-dev-ns-egw-eg"]}},{"metadata":{"name":"nbox-dev-subnet-veg-vip"},"spec":{"cidrBlock":"172.19.21.0/29","private":false,"namespaces":["nbox-dev-ns-veg-vip"]}},{"metadata":{"name":"egress-vip"},"spec":{"cidrBlock":"10.193.97.0/24","gateway":"10.193.97.1","provider":"egress-vip.kube-system"}}]}`)
	f.On("kubectl get pods -n nbox-dev-ns-veg-vip -l ovn.kubernetes.io/vpc-egress-gateway=ed-dev-veg-nbox-vip -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip-6575fc8888-9hsph","namespace":"nbox-dev-ns-veg-vip","labels":{"ovn.kubernetes.io/vpc-egress-gateway":"ed-dev-veg-nbox-vip"}},"spec":{"nodeName":"10.193.98.42"},"status":{"phase":"Pending","containerStatuses":[{"name":"gateway","ready":false}]}}]}`)
	f.On("kubectl get events -n nbox-dev-ns-veg-vip --field-selector type=Warning -o json",
		`{"items":[`+
			`{"type":"Warning","reason":"AcquireAddressFailed","count":14,"message":"AddressOutOfRange","involvedObject":{"kind":"Pod","name":"ed-dev-veg-nbox-vip-6575fc8888-9hsph","namespace":"nbox-dev-ns-veg-vip"}},`+
			`{"type":"Warning","reason":"FailedCreatePodSandbox","count":2,"message":"Failed to create pod sandbox: plugin type=\"kube-ovn\" failed (add): RPC failed; request ip return 500 no address allocated to pod nbox-dev-ns-veg-vip/ed-dev-veg-nbox-vip-6575fc8888-9hsph provider ovn","involvedObject":{"kind":"Pod","name":"ed-dev-veg-nbox-vip-6575fc8888-9hsph","namespace":"nbox-dev-ns-veg-vip"}}`+
			`]}`)

	// Start from sender namespace nbox-app: must detect misaligned VEG AND its IPAM AddressOutOfRange!
	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "nbox-app"})

	if rep.Summary.Verdict != "BROKEN" {
		t.Fatalf("expected BROKEN, got %s", rep.Summary.Verdict)
	}
	wantFails := []string{
		"veg-selector-mismatch",
		"veg-selector-split-0",
		"veg-ext-ip-range",
		"veg-pod-ipam-range",
		"veg-pods-ready",
	}
	for _, id := range wantFails {
		chk, ok := findCheckByID(rep, id)
		if !ok || chk.Status != report.StatusFail {
			t.Errorf("expected FAIL check %q, got ok=%v check=%+v", id, ok, chk)
		}
	}

	rangeChk, _ := findCheckByID(rep, "veg-ext-ip-range")
	if !strings.Contains(rangeChk.Message, "10.193.98.205") || !strings.Contains(rangeChk.Message, "AddressOutOfRange") {
		t.Errorf("unexpected veg-ext-ip-range message: %s", rangeChk.Message)
	}
	ipamChk, _ := findCheckByID(rep, "veg-pod-ipam-range")
	joinedEv := strings.Join(ipamChk.Evidence, "\n")
	if !strings.Contains(joinedEv, "AcquireAddressFailed") || !strings.Contains(joinedEv, "FailedCreatePodSandbox") {
		t.Errorf("expected both AcquireAddressFailed and FailedCreatePodSandbox in evidence, got:\n%s", joinedEv)
	}
}

func TestVEGSubnetMissingExcludedGatewayAndCollision(t *testing.T) {
	// 1. Missing externalSubnet
	f1 := baseHealthyMeshEgressRunner()
	f1.On("kubectl get subnets.kubeovn.io -o json",
		`{"items":[{"metadata":{"name":"nbox-dev-subnet-egw-eg"},"spec":{"cidrBlock":"172.19.20.0/28","private":false,"namespaces":["nbox-dev-ns-egw-eg"]}},{"metadata":{"name":"nbox-dev-subnet-veg-vip"},"spec":{"cidrBlock":"172.19.21.0/29","private":false,"namespaces":["nbox-dev-ns-veg-vip"]}}]}`)
	rep1 := Run(context.Background(), k8s.NewClient(f1, "", "", ""), Options{Version: "test", Namespace: "nbox-app"})
	if chk, ok := findCheckByID(rep1, "veg-ext-subnet-missing"); !ok || chk.Status != report.StatusFail {
		t.Fatalf("expected FAIL veg-ext-subnet-missing, got %+v", chk)
	}

	// 2. externalIP inside excludeIps range (10.193.97.0..10.193.97.10) + cluster-wide VEG IP collision
	f2 := baseHealthyMeshEgressRunner()
	f2.On("kubectl get subnets.kubeovn.io -o json",
		`{"items":[{"metadata":{"name":"nbox-dev-subnet-egw-eg"},"spec":{"cidrBlock":"172.19.20.0/28","private":false,"namespaces":["nbox-dev-ns-egw-eg"]}},{"metadata":{"name":"nbox-dev-subnet-veg-vip"},"spec":{"cidrBlock":"172.19.21.0/29","private":false,"namespaces":["nbox-dev-ns-veg-vip"]}},{"metadata":{"name":"egress-vip"},"spec":{"cidrBlock":"10.193.97.0/24","gateway":"10.193.97.1","excludeIps":["10.193.97.0..10.193.97.10"]}}]}`)
	f2.On("kubectl get vpcegressgateways.kubeovn.io -A -o json",
		`{"items":[`+
			`{"metadata":{"name":"ed-dev-veg-nbox-vip","namespace":"nbox-dev-ns-veg-vip"},"spec":{"vpc":"ovn-cluster","replicas":1,"externalSubnet":"egress-vip","externalIPs":["10.193.97.5"],"selectors":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"nbox-dev-ns-egw-eg"}},"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-wp-nbox-eg"}}}]},"status":{"ready":true}},`+
			`{"metadata":{"name":"ed-dev-veg-other","namespace":"other-veg"},"spec":{"vpc":"ovn-cluster","replicas":1,"externalSubnet":"egress-vip","externalIPs":["10.193.97.5"]},"status":{"ready":true}}`+
			`]}`)
	rep2 := Run(context.Background(), k8s.NewClient(f2, "", "", ""), Options{Version: "test", Namespace: "nbox-app"})
	if chk, ok := findCheckByID(rep2, "veg-ext-ip-excluded"); !ok || chk.Status != report.StatusFail {
		t.Errorf("expected FAIL veg-ext-ip-excluded, got %+v", chk)
	}
	if chk, ok := findCheckByID(rep2, "veg-ext-ip-collision-10.193.97.5"); !ok || chk.Status != report.StatusFail {
		t.Errorf("expected FAIL veg-ext-ip-collision-10.193.97.5, got %+v", chk)
	}

	// 3. Gateway IP and broadcast IP validation
	sn := k8s.Subnet{}
	sn.Metadata.Name = "egress-vip"
	sn.Spec.CIDRBlock = "10.193.97.0/24"
	sn.Spec.Gateway = "10.193.97.1"
	sn.Spec.ExcludeIPs = []string{"10.193.97.10..10.193.97.20", "10.193.97.50"}

	if code, _, _ := validateIPInSubnet("10.193.97.1", sn, "externalIP", "externalSubnet"); code != "reserved" {
		t.Errorf("expected reserved for gateway IP, got %q", code)
	}
	if code, _, _ := validateIPInSubnet("10.193.97.0", sn, "externalIP", "externalSubnet"); code != "reserved" {
		t.Errorf("expected reserved for network IP, got %q", code)
	}
	if code, _, _ := validateIPInSubnet("10.193.97.255", sn, "externalIP", "externalSubnet"); code != "reserved" {
		t.Errorf("expected reserved for broadcast IP, got %q", code)
	}
	if code, _, _ := validateIPInSubnet("10.193.97.15", sn, "externalIP", "externalSubnet"); code != "excluded" {
		t.Errorf("expected excluded for IP in .. range, got %q", code)
	}
	if code, _, _ := validateIPInSubnet("10.193.97.50", sn, "externalIP", "externalSubnet"); code != "excluded" {
		t.Errorf("expected excluded for single excluded IP, got %q", code)
	}
	if code, _, _ := validateIPInSubnet("10.193.98.205", sn, "externalIP", "externalSubnet"); code != "range" {
		t.Errorf("expected range for out-of-CIDR IP, got %q", code)
	}
	if code, _, _ := validateIPInSubnet("10.193.97.42", sn, "externalIP", "externalSubnet"); code != "" {
		t.Errorf("expected valid IP 10.193.97.42, got %q", code)
	}
}

func TestVEGPodFailedSchedulingEvent(t *testing.T) {
	f := baseHealthyMeshEgressRunner()
	f.On("kubectl get vpcegressgateways.kubeovn.io -A -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip","namespace":"nbox-dev-ns-veg-vip"},"spec":{"vpc":"ovn-cluster","replicas":1,"externalSubnet":"egress-vip","externalIPs":["10.193.97.5"],"selectors":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"nbox-dev-ns-egw-eg"}},"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-wp-nbox-eg"}}}]},"status":{"ready":false}}]}`)
	f.On("kubectl get pods -n nbox-dev-ns-veg-vip -l ovn.kubernetes.io/vpc-egress-gateway=ed-dev-veg-nbox-vip -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip-0","namespace":"nbox-dev-ns-veg-vip"},"status":{"phase":"Pending"}}]}`)
	f.On("kubectl get events -n nbox-dev-ns-veg-vip --field-selector type=Warning -o json",
		`{"items":[{"type":"Warning","reason":"FailedScheduling","count":3,"message":"0/6 nodes are available: 6 node(s) didn't match Pod's node affinity/selector.","involvedObject":{"kind":"Pod","name":"ed-dev-veg-nbox-vip-0","namespace":"nbox-dev-ns-veg-vip"}}]}`)

	rep := Run(context.Background(), k8s.NewClient(f, "", "", ""), Options{Version: "test", Namespace: "nbox-app"})
	if chk, ok := findCheckByID(rep, "veg-pod-scheduling"); !ok || chk.Status != report.StatusFail {
		t.Fatalf("expected FAIL veg-pod-scheduling, got %+v", chk)
	}
}
