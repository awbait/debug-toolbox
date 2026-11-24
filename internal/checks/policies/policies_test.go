package policies

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/awbait/debug-toolbox/internal/k8s"
)

func basePoliciesFakeRunner() *k8s.FakeRunner {
	f := k8s.NewFakeRunner()

	// Control plane
	f.On("kubectl get pods -n istio-system -l app=istiod -o json",
		`{"items":[{"metadata":{"name":"istiod-1","namespace":"istio-system"},"status":{"phase":"Running","containerStatuses":[{"name":"discovery","ready":true}]}}]}`)
	f.On("kubectl get pods -A -l app=ztunnel -o json",
		`{"items":[`+
			`{"metadata":{"name":"ztunnel-w1","namespace":"ztunnel"},"spec":{"nodeName":"worker-1"},"status":{"phase":"Running","containerStatuses":[{"name":"istio-proxy","ready":true}]}},`+
			`{"metadata":{"name":"ztunnel-w2","namespace":"ztunnel"},"spec":{"nodeName":"worker-2"},"status":{"phase":"Running","containerStatuses":[{"name":"istio-proxy","ready":true}]}}`+
			`]}`)
	f.On("kubectl get pods -A -l k8s-app=istio-cni-node -o json",
		`{"items":[{"metadata":{"name":"istio-cni-1","namespace":"istio-cni"},"spec":{"nodeName":"worker-1"},"status":{"phase":"Running","containerStatuses":[{"name":"install-cni","ready":true}]}}]}`)

	// Namespaces
	f.On("kubectl get namespace app-core -o json",
		`{"metadata":{"name":"app-core","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled","ecpk/instance":"ed","ecpk/cluster":"dev","ecpk/project":"nbox"}}}`)
	f.On("kubectl get namespaces -o json",
		`{"items":[`+
			`{"metadata":{"name":"app-core","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled","ecpk/instance":"ed","ecpk/cluster":"dev","ecpk/project":"nbox"}}},`+
			`{"metadata":{"name":"app-pg","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}},`+
			`{"metadata":{"name":"app-igw","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}},`+
			`{"metadata":{"name":"kube-system"}},`+
			`{"metadata":{"name":"istio-system"}},`+
			`{"metadata":{"name":"default"}}`+
			`]}`)

	// Cluster Services, Endpoints, Pods, ServiceEntries
	f.On("kubectl get services -A -o json",
		`{"items":[`+
			`{"metadata":{"name":"kubernetes","namespace":"default"},"spec":{"clusterIP":"10.96.0.1","ports":[{"port":443,"targetPort":6443,"protocol":"TCP"}]}},`+
			`{"metadata":{"name":"kube-dns","namespace":"kube-system"},"spec":{"clusterIP":"10.96.0.10","ports":[{"port":53,"targetPort":1053,"protocol":"UDP"}]}},`+
			`{"metadata":{"name":"postgresql","namespace":"app-pg"},"spec":{"clusterIP":"10.96.20.5","selector":{"app.kubernetes.io/name":"postgresql"},"ports":[{"port":5432,"targetPort":5432,"protocol":"TCP"}]}},`+
			`{"metadata":{"name":"netbox","namespace":"app-core"},"spec":{"clusterIP":"10.96.10.5","selector":{"app.kubernetes.io/name":"netbox"},"ports":[{"port":8080,"targetPort":8080,"protocol":"TCP"}]}}`+
			`]}`)
	f.On("kubectl get endpoints -A -o json",
		`{"items":[`+
			`{"metadata":{"name":"kubernetes","namespace":"default"},"subsets":[{"addresses":[{"ip":"10.193.98.10"},{"ip":"10.193.98.11"}],"ports":[{"port":6443,"protocol":"TCP"}]}]},`+
			`{"metadata":{"name":"kube-dns","namespace":"kube-system"},"subsets":[{"addresses":[{"ip":"172.19.0.10"}],"ports":[{"port":1053,"protocol":"UDP"}]}]},`+
			`{"metadata":{"name":"postgresql","namespace":"app-pg"},"subsets":[{"addresses":[{"ip":"172.19.20.8","nodeName":"worker-2"}],"ports":[{"port":5432,"protocol":"TCP"}]}]},`+
			`{"metadata":{"name":"netbox","namespace":"app-core"},"subsets":[{"addresses":[{"ip":"172.19.10.5","nodeName":"worker-1"}],"ports":[{"port":8080,"protocol":"TCP"}]}]}`+
			`]}`)
	f.On("kubectl get pods -A -o json",
		`{"items":[`+
			`{"metadata":{"name":"netbox-6f7d-abc","namespace":"app-core","labels":{"app.kubernetes.io/name":"netbox","pod-template-hash":"6f7d"},"annotations":{"ambient.istio.io/redirection":"enabled","ovn.kubernetes.io/logical_switch":"nbox-dev-subnet-core"},"ownerReferences":[{"kind":"ReplicaSet","name":"netbox-6f7d"}]},"spec":{"nodeName":"worker-1","serviceAccountName":"netbox"},"status":{"phase":"Running","podIP":"172.19.10.5","containerStatuses":[{"name":"netbox","ready":true,"containerID":"containerd://deadbeef"}]}},`+
			`{"metadata":{"name":"postgresql-0","namespace":"app-pg","labels":{"app.kubernetes.io/name":"postgresql","statefulset.kubernetes.io/pod-name":"postgresql-0"},"annotations":{"ambient.istio.io/redirection":"enabled"}},"spec":{"nodeName":"worker-2","serviceAccountName":"postgresql"},"status":{"phase":"Running","podIP":"172.19.20.8","containerStatuses":[{"name":"pg","ready":true}]}},`+
			`{"metadata":{"name":"ed-dev-igw-nbox-istio-xyz","namespace":"app-igw","labels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-igw-nbox","app.kubernetes.io/name":"ingress-istio"}},"spec":{"nodeName":"worker-1","serviceAccountName":"ed-dev-igw-nbox-istio"},"status":{"phase":"Running","podIP":"172.19.5.4","containerStatuses":[{"name":"istio-proxy","ready":true}]}}`+
			`]}`)
	f.On("kubectl get serviceentries.networking.istio.io -A -o json", `{"items":[]}`)

	// Target pod & owner Deployment
	f.On("kubectl get pod netbox-6f7d-abc -n app-core -o json",
		`{"metadata":{"name":"netbox-6f7d-abc","namespace":"app-core","labels":{"app.kubernetes.io/name":"netbox","pod-template-hash":"6f7d"},"annotations":{"ambient.istio.io/redirection":"enabled","ovn.kubernetes.io/logical_switch":"nbox-dev-subnet-core"},"ownerReferences":[{"kind":"ReplicaSet","name":"netbox-6f7d"}]},"spec":{"nodeName":"worker-1","serviceAccountName":"netbox"},"status":{"phase":"Running","podIP":"172.19.10.5","containerStatuses":[{"name":"netbox","ready":true,"containerID":"containerd://deadbeef"}]}}`)
	f.On("kubectl get replicasets netbox-6f7d -n app-core -o json",
		`{"kind":"ReplicaSet","metadata":{"name":"netbox-6f7d","namespace":"app-core","ownerReferences":[{"kind":"Deployment","name":"netbox"}]},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"netbox","pod-template-hash":"6f7d"}}}}`)
	f.On("kubectl get deployments netbox -n app-core -o json",
		`{"kind":"Deployment","metadata":{"name":"netbox","namespace":"app-core"},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"netbox"}}}}`)

	// RBAC / Webhooks (default empty)
	f.On("kubectl get rolebindings -n app-core -o json", `{"items":[]}`)
	f.On("kubectl get clusterrolebindings -o json", `{"items":[]}`)
	f.On("kubectl get validatingwebhookconfigurations -o json", `{"items":[]}`)
	f.On("kubectl get mutatingwebhookconfigurations -o json", `{"items":[]}`)

	// PeerAuthentications
	f.On("kubectl get peerauthentications.security.istio.io -n istio-system -o json",
		`{"items":[{"metadata":{"name":"default","namespace":"istio-system"},"spec":{"mtls":{"mode":"STRICT"}}}]}`)
	f.On("kubectl get peerauthentications.security.istio.io -n app-core -o json", `{"items":[]}`)
	f.On("kubectl get peerauthentications.security.istio.io -n app-pg -o json", `{"items":[]}`)

	return f
}

func TestPoliciesWorkloadMapZtunnelAndEmitValues(t *testing.T) {
	f := basePoliciesFakeRunner()

	// ztunnel logs on worker-1 show:
	//  - outbound to postgresql (172.19.20.8:5432) failing with policy rejection
	//  - inbound from ingress gateway (172.19.5.4 -> 172.19.10.5:8080) succeeding
	f.On("kubectl logs -n ztunnel ztunnel-w1 --since=15m --tail=500",
		`2026-11-24T08:00:01Z info access direction=outbound src.addr=172.19.10.5:41234 dst.addr=172.19.20.8:5432 dst.service=postgresql.app-pg.svc.cluster.local error="connection closed due to policy rejection"`+"\n"+
			`2026-11-24T08:00:02Z info access direction=inbound src.addr=172.19.5.4:52110 dst.addr=172.19.10.5:8080 src.identity="spiffe://cluster.local/ns/app-igw/sa/ed-dev-igw-nbox-istio"`+"\n")
	f.On("kubectl logs -n ztunnel ztunnel-w2 --since=15m --tail=500",
		`2026-11-24T08:00:01Z error access direction=inbound src.addr=172.19.10.5:41234 dst.addr=172.19.20.8:5432 error="connection closed due to policy rejection"`+"\n")

	// NetworkPolicies allow 15008, but app-pg AuthorizationPolicy denies netbox SA!
	f.On("kubectl get networkpolicies -n app-core -o json",
		`{"items":[{"metadata":{"name":"ed-dev-np-nbox-core","namespace":"app-core"},"spec":{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"netbox"}},"policyTypes":["Ingress","Egress"],"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"app-igw"}}}],"ports":[{"port":8080,"protocol":"TCP"},{"port":15008,"protocol":"TCP"}]}],"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"app-pg"}}}],"ports":[{"port":5432,"protocol":"TCP"},{"port":15008,"protocol":"TCP"}]}]}}]}`)
	f.On("kubectl get networkpolicies -n app-pg -o json",
		`{"items":[{"metadata":{"name":"ed-dev-np-pg","namespace":"app-pg"},"spec":{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"postgresql"}},"policyTypes":["Ingress"],"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"app-core"}}}],"ports":[{"port":5432,"protocol":"TCP"},{"port":15008,"protocol":"TCP"}]}]}}]}`)
	f.On("kubectl get networkpolicies -n app-igw -o json", `{"items":[]}`)

	f.On("kubectl get authorizationpolicies.security.istio.io -n app-core -o json",
		`{"items":[{"metadata":{"name":"allow-igw","namespace":"app-core"},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"netbox"}},"action":"ALLOW","rules":[{"from":[{"source":{"principals":["cluster.local/ns/app-igw/sa/ed-dev-igw-nbox-istio"]}}],"to":[{"operation":{"ports":["8080"]}}]}]}}]}`)
	f.On("kubectl get authorizationpolicies.security.istio.io -n app-pg -o json",
		`{"items":[{"metadata":{"name":"pg-strict","namespace":"app-pg"},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"postgresql"}},"action":"ALLOW","rules":[{"from":[{"source":{"principals":["cluster.local/ns/other/sa/other"]}}],"to":[{"operation":{"ports":["5432"]}}]}]}}]}`)

	rep := Run(context.Background(), k8s.NewClient(f, "", "", ""), Options{
		Version:      "test",
		Namespace:    "app-core",
		Target:       "netbox-6f7d-abc",
		To:           []string{"kube-apiserver", "coredns", "10.193.100.2:443"},
		EmitPolicies: true,
	})

	if rep.Summary.Verdict != "BROKEN" {
		t.Fatalf("expected BROKEN due to pg AuthorizationPolicy + kube-apiserver Egress NP, got %s", rep.Summary.Verdict)
	}
	if rep.Metadata["ztunnel_pod"] != "ztunnel/ztunnel-w1" {
		t.Errorf("expected ztunnel_pod=ztunnel/ztunnel-w1, got %q", rep.Metadata["ztunnel_pod"])
	}
	if rep.Metadata["principal"] != "cluster.local/ns/app-core/sa/netbox" {
		t.Errorf("unexpected principal: %q", rep.Metadata["principal"])
	}

	// Verify emitted values.yaml for console-charts/policies
	yamlOut := rep.Metadata["policies_values_yaml"]
	if yamlOut == "" {
		t.Fatalf("expected generated policies_values_yaml in metadata")
	}
	for _, mustContain := range []string{
		"instance: ed",
		"cluster: dev",
		"project: nbox",
		"serviceAccount: netbox",
		`app.kubernetes.io/name: "netbox"`,
		"namespace: app-igw",
		"serviceAccount: ed-dev-igw-nbox-istio",
		"namespace: app-pg",
		"port: 5432",
		"cidr: 10.193.98.10/32",
		"port: 6443",
		"kubernetes.io/metadata.name: kube-system",
		"authzpol: []",
		"10.193.100.2",
	} {
		if !strings.Contains(yamlOut, mustContain) {
			t.Errorf("emitted YAML missing %q:\n%s", mustContain, yamlOut)
		}
	}
	// Must NOT leak pod-template-hash into stable selector!
	if strings.Contains(yamlOut, "pod-template-hash") {
		t.Errorf("emitted YAML must not include ephemeral pod-template-hash:\n%s", yamlOut)
	}
}

func TestPoliciesOperatorAPIServerPostDNATAndWebhook(t *testing.T) {
	f := basePoliciesFakeRunner()

	// Make netbox-6f7d-abc an operator (ClusterRoleBinding + ValidatingWebhookConfiguration)
	f.On("kubectl get clusterrolebindings -o json",
		`{"items":[{"metadata":{"name":"netbox-operator"},"subjects":[{"kind":"ServiceAccount","name":"netbox","namespace":"app-core"}]}]}`)
	f.On("kubectl get validatingwebhookconfigurations -o json",
		`{"items":[{"metadata":{"name":"netbox-webhook"},"webhooks":[{"name":"validate.netbox.io","clientConfig":{"service":{"namespace":"app-core","name":"netbox","port":8080}}}]}]}`)
	f.On("kubectl logs -n ztunnel ztunnel-w1 --since=15m --tail=500", "")

	// Egress NP mistakenly opens port 443 instead of post-DNAT 6443 for kube-apiserver!
	f.On("kubectl get networkpolicies -n app-core -o json",
		`{"items":[{"metadata":{"name":"op-np","namespace":"app-core"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],"egress":[{"to":[{"ipBlock":{"cidr":"10.193.98.10/32"}},{"ipBlock":{"cidr":"10.193.98.11/32"}}],"ports":[{"port":443,"protocol":"TCP"}]}]}}]}`)
	f.On("kubectl get authorizationpolicies.security.istio.io -n app-core -o json", `{"items":[]}`)

	rep := Run(context.Background(), k8s.NewClient(f, "", "", ""), Options{
		Version:   "test",
		Namespace: "app-core",
		Target:    "netbox-6f7d-abc",
	})

	if rep.Mode != WorkloadOperator {
		t.Fatalf("expected workload kind %q, got %q", WorkloadOperator, rep.Mode)
	}

	foundAPIPostDNATHint := false
	foundWebhookStrictMTLS := false
	for _, chk := range rep.Checks {
		joined := chk.Message + "\n" + strings.Join(chk.Evidence, "\n") + "\n" + strings.Join(chk.Details, "\n")
		if strings.Contains(joined, "post-DNAT port 6443") {
			foundAPIPostDNATHint = true
		}
		if strings.Contains(joined, "STRICT mTLS") && strings.Contains(chk.Title, "kube-apiserver") {
			foundWebhookStrictMTLS = true
		}
	}
	if !foundAPIPostDNATHint {
		t.Errorf("expected post-DNAT port 6443 hint for operator kube-apiserver flow")
	}
	if !foundWebhookStrictMTLS {
		t.Errorf("expected STRICT mTLS failure for inbound kube-apiserver webhook to ambient operator")
	}
}

func TestParseTcpdumpOutput(t *testing.T) {
	raw := strings.Join([]string{
		"08:01:02.111111 eth0 Out IP 172.19.10.5.45122 > 10.96.0.1.443: tcp 0",
		"08:01:02.111222 eth0 Out IP 172.19.10.5.53411 > 10.96.0.10.53: UDP, length 42",
		"08:01:02.111333 eth0 In  IP 10.96.0.10.53 > 172.19.10.5.53411: UDP, length 98",
		"08:01:02.111444 eth0 Out IP 172.19.10.5.48900 > 172.19.20.8.5432: tcp 0",
		"08:01:02.111555 eth0 Out IP 172.19.10.5.49000 > 169.254.7.127.8080: tcp 0",
		"08:01:02.111666 lo   In  IP 127.0.0.1.51000 > 127.0.0.1.8080: tcp 0",
		"08:01:02.111777 eth0 In  IP 172.19.5.4.55001 > 172.19.10.5.8080: tcp 0",
		"08:01:02.111888 eth0 Out IP 172.19.10.5.55002 > 172.19.20.8.15008: tcp 0",
	}, "\n")

	pkts := ParseTcpdumpOutput(raw, "172.19.10.5")
	if len(pkts) != 4 {
		t.Fatalf("expected 4 filtered packets (443, 53/UDP, 5432, inbound 8080), got %d: %+v", len(pkts), pkts)
	}
	want := map[string]bool{
		"outbound|10.96.0.1|443|TCP":    false,
		"outbound|10.96.0.10|53|UDP":    false,
		"outbound|172.19.20.8|5432|TCP": false,
		"inbound|172.19.5.4|8080|TCP":   false,
	}
	for _, p := range pkts {
		k := p.Direction + "|" + p.PeerIP + "|" + strconv.Itoa(p.Port) + "|" + p.Protocol
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected packet parsed: %s", k)
		}
		want[k] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing expected packet: %s", k)
		}
	}
}
