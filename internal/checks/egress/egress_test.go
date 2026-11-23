package egress

import (
	"bytes"
	"context"
	"testing"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

func baseHealthyMeshEgressRunner() *k8s.FakeRunner {
	f := k8s.NewFakeRunner()

	// Control plane
	f.On("kubectl get pods -n istio-system -l app=istiod -o json",
		`{"items":[{"metadata":{"name":"istiod-1","namespace":"istio-system"},"status":{"phase":"Running","containerStatuses":[{"name":"discovery","ready":true}]}}]}`)
	f.On("kubectl get pods -A -l app=ztunnel -o json",
		`{"items":[{"metadata":{"name":"ztunnel-n1","namespace":"ztunnel"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"istio-proxy","ready":true}]}}]}`)
	f.On("kubectl get pods -n ztunnel -l app=ztunnel -o json",
		`{"items":[{"metadata":{"name":"ztunnel-n1","namespace":"ztunnel"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"istio-proxy","ready":true}]}}]}`)
	f.On("kubectl get pods -A -l k8s-app=istio-cni-node -o json",
		`{"items":[{"metadata":{"name":"istio-cni-1","namespace":"istio-cni"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"install-cni","ready":true}]}}]}`)

	// Discovery objects
	f.On("kubectl get serviceentries.networking.istio.io -A -o json",
		`{"items":[{"metadata":{"name":"ed-dev-egw-nbox-s3","namespace":"nbox-app","labels":{"istio.io/use-waypoint":"ed-dev-wp-nbox-eg","istio.io/use-waypoint-namespace":"nbox-dev-ns-egw-eg"}},"spec":{"hosts":["str.idp.ecpk.test"],"addresses":["240.241.0.1"],"exportTo":[".","nbox-dev-ns-egw-eg"],"location":"MESH_EXTERNAL","resolution":"DNS","ports":[{"number":443,"name":"tls","protocol":"TLS"}]}}]}`)
	f.On("kubectl get gateways.gateway.networking.k8s.io -A -o json",
		`{"items":[{"metadata":{"name":"ed-dev-wp-nbox-eg","namespace":"nbox-dev-ns-egw-eg"},"spec":{"gatewayClassName":"istio-waypoint","listeners":[{"name":"mesh","port":15008,"protocol":"HBONE","allowedRoutes":{"namespaces":{"from":"Selector","selector":{"matchExpressions":[{"key":"kubernetes.io/metadata.name","operator":"In","values":["nbox-app"]}]}}}}]},"status":{"conditions":[{"type":"Accepted","status":"True"},{"type":"Programmed","status":"True"}]}}]}`)
	f.On("kubectl get vpcegressgateways.kubeovn.io -A -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip","namespace":"nbox-dev-ns-veg-vip"},"spec":{"vpc":"ovn-cluster","replicas":1,"externalSubnet":"egress-vip","externalIPs":["10.193.97.5"],"selectors":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"nbox-dev-ns-egw-eg"}},"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-wp-nbox-eg"}}}]},"status":{"ready":true}}]}`)
	f.On("kubectl get subnets.kubeovn.io -o json",
		`{"items":[{"metadata":{"name":"nbox-dev-subnet-egw-eg"},"spec":{"cidrBlock":"172.19.20.0/28","private":false,"namespaces":["nbox-dev-ns-egw-eg"]}},{"metadata":{"name":"nbox-dev-subnet-veg-vip"},"spec":{"cidrBlock":"172.19.21.0/29","private":false,"namespaces":["nbox-dev-ns-veg-vip"]}}]}`)

	// Namespaces
	f.On("kubectl get namespace nbox-app -o json",
		`{"metadata":{"name":"nbox-app","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}}`)
	f.On("kubectl get namespace nbox-dev-ns-egw-eg -o json",
		`{"metadata":{"name":"nbox-dev-ns-egw-eg","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}}`)
	f.On("kubectl get namespace nbox-dev-ns-veg-vip -o json",
		`{"metadata":{"name":"nbox-dev-ns-veg-vip","labels":{"namespace-role":"egress"}}}`)

	// Pods
	f.On("kubectl get pods -n nbox-app -o json",
		`{"items":[{"metadata":{"name":"app-0","namespace":"nbox-app","annotations":{"ambient.istio.io/redirection":"enabled"}},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","podIP":"172.19.10.5","containerStatuses":[{"name":"app","ready":true}]}}]}`)
	f.On("kubectl get pods -n nbox-dev-ns-veg-vip -l ovn.kubernetes.io/vpc-egress-gateway=ed-dev-veg-nbox-vip -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip-0","namespace":"nbox-dev-ns-veg-vip","labels":{"istio.io/dataplane-mode":"none","ovn.kubernetes.io/vpc-egress-gateway":"ed-dev-veg-nbox-vip"}},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","podIP":"172.19.21.2","containerStatuses":[{"name":"gateway","ready":true}]}}]}`)
	f.On("kubectl get pods -n nbox-dev-ns-egw-eg -l gateway.networking.k8s.io/gateway-name=ed-dev-wp-nbox-eg -o json",
		`{"items":[{"metadata":{"name":"ed-dev-wp-nbox-eg-abc","namespace":"nbox-dev-ns-egw-eg","labels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-wp-nbox-eg"}},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","podIP":"172.19.20.3","containerStatuses":[{"name":"istio-proxy","ready":true}]}}]}`)

	// Waypoint Envoy live checks
	f.On("istioctl pc listener ed-dev-wp-nbox-eg-abc.nbox-dev-ns-egw-eg --name main_internal -o json",
		`[{"filterChains":[{"filterChainMatch":{"prefixRanges":[{"addressPrefix":"240.241.0.1"}]}}]}]`)
	f.On("kubectl exec -n nbox-dev-ns-egw-eg ed-dev-wp-nbox-eg-abc -- pilot-agent request GET clusters",
		"inbound-vip|443|tcp|str.idp.ecpk.test::cx_total::12\ninbound-vip|443|tcp|str.idp.ecpk.test::cx_connect_fail::0\n")
	f.On("kubectl logs -n nbox-dev-ns-egw-eg ed-dev-wp-nbox-eg-abc --since=15m --tail=300", "")

	// Policies
	f.On("kubectl get networkpolicies -n nbox-app -o json",
		`{"items":[{"metadata":{"name":"ed-dev-np-eg-nbox-senders","namespace":"nbox-app"},"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"nbox-dev-ns-egw-eg"}}}],"ports":[{"port":15008,"protocol":"TCP"}]}]}}]}`)
	f.On("kubectl get networkpolicies -n nbox-dev-ns-egw-eg -o json",
		`{"items":[{"metadata":{"name":"ed-dev-np-eg-nbox-in","namespace":"nbox-dev-ns-egw-eg"},"spec":{"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-wp-nbox-eg"}},"policyTypes":["Ingress"],"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"nbox-app"}}}],"ports":[{"port":15008,"protocol":"TCP"}]}]}},{"metadata":{"name":"ed-dev-np-eg-nbox-out","namespace":"nbox-dev-ns-egw-eg"},"spec":{"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-wp-nbox-eg"}},"policyTypes":["Egress"],"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"istio-system"}}}],"ports":[{"port":15012,"protocol":"TCP"}]},{"to":[{"ipBlock":{"cidr":"10.193.96.209/32"}}],"ports":[{"port":443,"protocol":"TCP"}]}]}}]}`)
	f.On("kubectl get authorizationpolicies.security.istio.io -n nbox-dev-ns-egw-eg -o json",
		`{"items":[{"metadata":{"name":"ed-dev-ap-nbox-eg","namespace":"nbox-dev-ns-egw-eg"},"spec":{"targetRefs":[{"kind":"Gateway","name":"ed-dev-wp-nbox-eg"}],"action":"ALLOW","rules":[{"from":[{"source":{"namespaces":["nbox-app"]}}]}]}}]}`)

	// VEG runtime & OVN
	f.On("kubectl exec -n nbox-dev-ns-veg-vip ed-dev-veg-nbox-vip-0 -c gateway -- ip rule",
		"0:\tfrom all lookup local\n32765:\tfrom all fwmark 0x4000/0x4000 lookup 1000\n")
	f.On("kubectl get pods -n kube-system -l ovn-nb-leader=true -o json",
		`{"items":[{"metadata":{"name":"ovn-central-0","namespace":"kube-system"},"status":{"phase":"Running","containerStatuses":[{"name":"ovn-central","ready":true}]}}]}`)
	f.On("kubectl exec -n kube-system ovn-central-0 -- ovn-nbctl lr-policy-list ovn-cluster",
		"Routing Policies\n     31000  ip4.dst == 172.19.0.0/16 allow\n     29100  ip4.src == $VEG.abc123_ip4 reroute 172.19.21.2\n")
	f.On("kubectl exec -n kube-system ovn-central-0 -- ovn-nbctl --columns=name,ports list port_group VEG.abc123",
		"name  : \"VEG.abc123\"\nports : [11111111-1111-1111-1111-111111111111]\n")

	// ztunnel logs
	f.On("kubectl logs -n ztunnel ztunnel-n1 --since=15m --tail=500", "")
	return f
}

func TestEgressMeshHealthy(t *testing.T) {
	f := baseHealthyMeshEgressRunner()
	client := k8s.NewClient(f, "", "", "")

	// Can start from senders NS, waypoint NS, OR VEG NS and discover the exact same healthy topology
	for _, startNS := range []string{"nbox-app", "nbox-dev-ns-egw-eg", "nbox-dev-ns-veg-vip"} {
		rep := Run(context.Background(), client, Options{Version: "test", Namespace: startNS})
		if rep.Summary.Verdict != "HEALTHY" {
			var buf bytes.Buffer
			_ = report.Write(&buf, rep, report.FormatOptions{Format: "text"})
			t.Fatalf("startNS=%s: expected HEALTHY, got %s:\n%s", startNS, rep.Summary.Verdict, buf.String())
		}
	}
}

func TestEgressFilestashIncidents(t *testing.T) {
	f := baseHealthyMeshEgressRunner()

	// Reproduce BOTH filestash root causes at once:
	// 1) VEG selectors split into 2 OR items + policies.subnets set in mesh mode
	f.On("kubectl get vpcegressgateways.kubeovn.io -A -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip","namespace":"nbox-dev-ns-veg-vip"},"spec":{"vpc":"ovn-cluster","replicas":1,"externalSubnet":"egress-vip","externalIPs":["10.193.97.5"],"selectors":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"nbox-dev-ns-egw-eg"}}},{"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-wp-nbox-eg"}}}],"policies":[{"snat":true,"subnets":["nbox-dev-subnet-egw-eg"]}]},"status":{"ready":true}}]}`)
	// 2) VEG pod captured by ambient (redirection=enabled + ip rule 0x111 lookup 100)
	f.On("kubectl get pods -n nbox-dev-ns-veg-vip -l ovn.kubernetes.io/vpc-egress-gateway=ed-dev-veg-nbox-vip -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nbox-vip-0","namespace":"nbox-dev-ns-veg-vip","annotations":{"ambient.istio.io/redirection":"enabled"},"labels":{"ovn.kubernetes.io/vpc-egress-gateway":"ed-dev-veg-nbox-vip"}},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","podIP":"172.19.21.2","containerStatuses":[{"name":"gateway","ready":true}]}}]}`)
	f.On("kubectl exec -n nbox-dev-ns-veg-vip ed-dev-veg-nbox-vip-0 -c gateway -- ip rule",
		"0:\tfrom all lookup local\n100:\tfrom all fwmark 0x111/0xfff lookup 100\n")
	// 3) OVN port_group over-captured 3 pods instead of 1 waypoint pod
	f.On("kubectl exec -n kube-system ovn-central-0 -- ovn-nbctl --columns=name,ports list port_group VEG.abc123",
		"name  : \"VEG.abc123\"\nports : [11111111-1111-1111-1111-111111111111, 22222222-2222-2222-2222-222222222222, 33333333-3333-3333-3333-333333333333]\n")

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "nbox-app"})

	if rep.Summary.Verdict != "BROKEN" {
		t.Fatalf("expected BROKEN, got %s", rep.Summary.Verdict)
	}
	wantFails := []string{
		"veg-selector-split-0",
		"veg-policies-in-mesh",
		"veg-pod-captured",
		"veg-iprule-ed-dev-veg-nbox-vip-0",
		"ovn-pg-VEG.abc123",
	}
	got := make(map[string]bool)
	for _, c := range rep.Checks {
		if c.Status == report.StatusFail {
			got[c.ID] = true
		}
	}
	for _, id := range wantFails {
		if !got[id] {
			t.Errorf("expected FAIL check %q not triggered; got=%v", id, got)
		}
	}
}

func TestEgressSharedWaypointVIPCollision_Chat003(t *testing.T) {
	f := baseHealthyMeshEgressRunner()

	// Reproduce DBAAS / Observability Nov 2026 bug (chat-003):
	// Two sender namespaces have copies of ServiceEntry for str.idp.ecpk.test bound to the SAME waypoint,
	// each with its own auto-allocated VIP (240.240.0.1 vs 240.240.0.7).
	// Waypoint main_internal matcher only keeps 240.240.0.1 and logs "no matching filter chain found".
	f.On("kubectl get serviceentries.networking.istio.io -A -o json",
		`{"items":[`+
			`{"metadata":{"name":"ed-dev-egw-nbox-s3","namespace":"nbox-app","labels":{"istio.io/use-waypoint":"ed-dev-wp-nbox-eg","istio.io/use-waypoint-namespace":"nbox-dev-ns-egw-eg"}},"spec":{"hosts":["str.idp.ecpk.test"],"exportTo":[".","nbox-dev-ns-egw-eg"],"location":"MESH_EXTERNAL","resolution":"DNS","ports":[{"number":443,"name":"tls","protocol":"TLS"}]},"status":{"addresses":[{"value":"240.240.0.1"}]}},`+
			`{"metadata":{"name":"ed-dev-egw-nbox-s3","namespace":"nbox-app-2","labels":{"istio.io/use-waypoint":"ed-dev-wp-nbox-eg","istio.io/use-waypoint-namespace":"nbox-dev-ns-egw-eg"}},"spec":{"hosts":["str.idp.ecpk.test"],"exportTo":[".","nbox-dev-ns-egw-eg"],"location":"MESH_EXTERNAL","resolution":"DNS","ports":[{"number":443,"name":"tls","protocol":"TLS"}]},"status":{"addresses":[{"value":"240.240.0.7"}]}}`+
			`]}`)
	f.On("kubectl get namespace nbox-app-2 -o json",
		`{"metadata":{"name":"nbox-app-2","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}}`)
	f.On("kubectl get pods -n nbox-app-2 -o json", `{"items":[]}`)
	f.On("kubectl get networkpolicies -n nbox-app-2 -o json", `{"items":[]}`)
	f.On("istioctl pc listener ed-dev-wp-nbox-eg-abc.nbox-dev-ns-egw-eg --name main_internal -o json",
		`[{"filterChains":[{"filterChainMatch":{"prefixRanges":[{"addressPrefix":"240.240.0.1"}]}}]}]`)
	f.On("kubectl logs -n nbox-dev-ns-egw-eg ed-dev-wp-nbox-eg-abc --since=15m --tail=300",
		"closing connection from 172.21.26.217:53162: no matching filter chain found\n")

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "nbox-app-2"})

	if rep.Summary.Verdict != "BROKEN" {
		t.Fatalf("expected BROKEN, got %s", rep.Summary.Verdict)
	}
	wantFails := []string{
		"se-shared-wp-vip-split-str.idp.ecpk.test",
		"wp-matcher-vips",
		"wp-logs-no-chain",
	}
	got := make(map[string]bool)
	for _, c := range rep.Checks {
		if c.Status == report.StatusFail {
			got[c.ID] = true
		}
	}
	for _, id := range wantFails {
		if !got[id] {
			t.Errorf("expected FAIL check %q not triggered; got=%v", id, got)
		}
	}
}

func TestEgressDirectModeConflicts(t *testing.T) {
	f := k8s.NewFakeRunner()
	f.On("kubectl get pods -n istio-system -l app=istiod -o json",
		`{"items":[{"metadata":{"name":"istiod-1","namespace":"istio-system"},"status":{"phase":"Running","containerStatuses":[{"name":"discovery","ready":true}]}}]}`)
	f.On("kubectl get pods -A -l app=ztunnel -o json",
		`{"items":[{"metadata":{"name":"ztunnel-n1","namespace":"ztunnel"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"istio-proxy","ready":true}]}}]}`)
	f.On("kubectl get pods -n ztunnel -l app=ztunnel -o json",
		`{"items":[{"metadata":{"name":"ztunnel-n1","namespace":"ztunnel"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"istio-proxy","ready":true}]}}]}`)
	f.On("kubectl get pods -A -l k8s-app=istio-cni-node -o json",
		`{"items":[{"metadata":{"name":"istio-cni-1","namespace":"istio-cni"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"install-cni","ready":true}]}}]}`)

	f.On("kubectl get serviceentries.networking.istio.io -A -o json", `{"items":[]}`)
	f.On("kubectl get gateways.gateway.networking.k8s.io -A -o json", `{"items":[]}`)
	f.On("kubectl get vpcegressgateways.kubeovn.io -A -o json",
		`{"items":[{"metadata":{"name":"ed-dev-veg-nex-vip","namespace":"nex-veg"},"spec":{"vpc":"ovn-cluster","replicas":1,"externalSubnet":"egress-vip","externalIPs":["10.193.97.2"],"policies":[{"snat":true,"subnets":["nex-subnet","missing-subnet"]}]},"status":{"ready":true}}]}`)
	f.On("kubectl get subnets.kubeovn.io -o json",
		`{"items":[{"metadata":{"name":"nex-subnet"},"spec":{"cidrBlock":"172.19.30.0/24","private":true,"namespaces":["tech-nexus"]}},{"metadata":{"name":"nex-veg-subnet"},"spec":{"cidrBlock":"172.19.31.0/29","private":true,"namespaces":["nex-veg"]}}]}`)

	// tech-nexus wrongly has ambient enabled while using direct VEG + private subnet
	f.On("kubectl get namespace tech-nexus -o json",
		`{"metadata":{"name":"tech-nexus","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}}`)
	f.On("kubectl get namespace nex-veg -o json", `{"metadata":{"name":"nex-veg"}}`)
	f.On("kubectl get pods -n tech-nexus -o json", `{"items":[]}`)
	f.On("kubectl get pods -n nex-veg -l ovn.kubernetes.io/vpc-egress-gateway=ed-dev-veg-nex-vip -o json",
		`{"items":[{"metadata":{"name":"veg-0","namespace":"nex-veg"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","podIP":"172.19.31.2","containerStatuses":[{"name":"gateway","ready":true}]}}]}`)
	f.On("kubectl exec -n nex-veg veg-0 -c gateway -- ip rule", "0: from all lookup local\n")
	f.On("kubectl get pods -n kube-system -l ovn-nb-leader=true -o json",
		`{"items":[{"metadata":{"name":"ovn-central-0","namespace":"kube-system"},"status":{"phase":"Running","containerStatuses":[{"name":"ovn-central","ready":true}]}}]}`)
	f.On("kubectl exec -n kube-system ovn-central-0 -- ovn-nbctl lr-policy-list ovn-cluster",
		"29100 ip4.src == $VEG.xyz.ipv4 reroute 172.19.31.2\n")
	f.On("kubectl exec -n kube-system ovn-central-0 -- ovn-nbctl --columns=name,addresses find address_set name=VEG.xyz.ipv4",
		`addresses: ["172.19.30.0/24"]`)

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "tech-nexus"})

	if rep.Mode != "direct" {
		t.Fatalf("expected direct mode, got %q", rep.Mode)
	}
	wantFails := []string{
		"direct-vs-ambient-tech-nexus",
		"subnet-private-nex-subnet",
		"veg-subnet-private",
		"veg-subnet-missing-missing-subnet",
		"veg-policy-ambient-nex-subnet",
	}
	got := make(map[string]bool)
	for _, c := range rep.Checks {
		if c.Status == report.StatusFail {
			got[c.ID] = true
		}
	}
	for _, id := range wantFails {
		if !got[id] {
			t.Errorf("expected FAIL check %q not triggered; got=%v", id, got)
		}
	}
}
