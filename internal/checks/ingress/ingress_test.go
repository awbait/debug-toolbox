package ingress

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

func makeTestCertB64(t *testing.T, dnsNames []string, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return base64.StdEncoding.EncodeToString(crtPEM), base64.StdEncoding.EncodeToString(keyPEM)
}

func baseHealthyIngressRunner(t *testing.T, certNotAfter time.Time, certDNS []string) *k8s.FakeRunner {
	t.Helper()
	f := k8s.NewFakeRunner()
	crtB64, keyB64 := makeTestCertB64(t, certDNS, certNotAfter)

	f.On("kubectl get pods -n istio-system -l app=istiod -o json",
		`{"items":[{"metadata":{"name":"istiod-1","namespace":"istio-system"},"status":{"phase":"Running","containerStatuses":[{"name":"discovery","ready":true}]}}]}`)
	f.On("kubectl get pods -A -l app=ztunnel -o json",
		`{"items":[{"metadata":{"name":"ztunnel-n1","namespace":"ztunnel"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"istio-proxy","ready":true}]}}]}`)
	f.On("kubectl get pods -A -l k8s-app=istio-cni-node -o json",
		`{"items":[{"metadata":{"name":"istio-cni-1","namespace":"istio-cni"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","containerStatuses":[{"name":"install-cni","ready":true}]}}]}`)
	f.On("kubectl get namespace app-igw -o json",
		`{"metadata":{"name":"app-igw","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}}`)
	f.On("kubectl get namespace app-backend -o json",
		`{"metadata":{"name":"app-backend","labels":{"istio.io/dataplane-mode":"ambient","istio-discovery":"enabled"}}}`)
	f.On("kubectl get gateways.gateway.networking.k8s.io -n app-igw -o json",
		`{"items":[{"metadata":{"name":"ed-dev-igw-nbox-main","namespace":"app-igw"},"spec":{"gatewayClassName":"istio","infrastructure":{"parametersRef":{"kind":"ConfigMap","name":"ed-dev-cm-nbox-main"}},"listeners":[{"name":"https","hostname":"app.idp.ecpk.test","port":443,"protocol":"HTTPS","tls":{"mode":"Terminate","certificateRefs":[{"kind":"Secret","name":"ed-dev-secret-main-nbox-https"}]}}]},"status":{"conditions":[{"type":"Accepted","status":"True"},{"type":"Programmed","status":"True"}],"listeners":[{"name":"https","attachedRoutes":1,"conditions":[{"type":"Accepted","status":"True"},{"type":"ResolvedRefs","status":"True"},{"type":"Programmed","status":"True"}]}]}}]}`)
	f.On("kubectl get configmap ed-dev-cm-nbox-main -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-cm-nbox-main","namespace":"app-igw"}}`)
	f.On("kubectl get pods -n app-igw -l gateway.networking.k8s.io/gateway-name=ed-dev-igw-nbox-main -o json",
		`{"items":[{"metadata":{"name":"ed-dev-igw-nbox-main-istio-abc","namespace":"app-igw"},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","podIP":"10.0.1.10","containerStatuses":[{"name":"istio-proxy","ready":true}]}}]}`)
	f.On("kubectl get service ed-dev-igw-nbox-main-istio -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-igw-nbox-main-istio","namespace":"app-igw","annotations":{"metallb.io/loadBalancerIPs":"10.193.10.50"}},"spec":{"type":"LoadBalancer","clusterIP":"10.96.1.10","externalTrafficPolicy":"Local"},"status":{"loadBalancer":{"ingress":[{"ip":"10.193.10.50"}]}}}`)
	f.On("kubectl get secret ed-dev-secret-main-nbox-https -n app-igw -o json",
		`{"metadata":{"name":"ed-dev-secret-main-nbox-https","namespace":"app-igw"},"type":"kubernetes.io/tls","data":{"tls.crt":"`+crtB64+`","tls.key":"`+keyB64+`"}}`)
	f.On("kubectl get certificates.cert-manager.io -n app-igw -o json",
		`{"items":[{"metadata":{"name":"ed-dev-cert-main-nbox-https","namespace":"app-igw"},"spec":{"secretName":"ed-dev-secret-main-nbox-https","dnsNames":["app.idp.ecpk.test"],"issuerRef":{"name":"platform-ca","kind":"ClusterIssuer"}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)
	f.On("kubectl get externalsecrets.external-secrets.io -n app-igw -o json", `{"items":[]}`)
	f.On("kubectl get destinationrules.networking.istio.io -n app-igw -o json", `{"items":[]}`)
	f.On("kubectl get requestauthentications.security.istio.io -n app-igw -o json", `{"items":[]}`)
	f.On("kubectl get events -n app-igw --field-selector type=Warning -o json", `{"items":[]}`)
	f.On("kubectl get httproutes.gateway.networking.k8s.io -n app-igw -o json",
		`{"items":[{"kind":"HTTPRoute","metadata":{"name":"ed-dev-hr-main-nbox-app","namespace":"app-igw"},"spec":{"parentRefs":[{"kind":"Gateway","name":"ed-dev-igw-nbox-main","sectionName":"https"}],"hostnames":["app.idp.ecpk.test"],"rules":[{"backendRefs":[{"name":"web","namespace":"app-backend","port":8080}]}]},"status":{"parents":[{"parentRef":{"name":"ed-dev-igw-nbox-main","sectionName":"https"},"conditions":[{"type":"Accepted","status":"True"},{"type":"ResolvedRefs","status":"True"}]}]}}]}`)
	f.On("kubectl get grpcroutes.gateway.networking.k8s.io -n app-igw -o json", `{"items":[]}`)
	f.On("kubectl get tlsroutes.gateway.networking.k8s.io -n app-igw -o json", `{"items":[]}`)
	f.On("kubectl get tcproutes.gateway.networking.k8s.io -n app-igw -o json", `{"items":[]}`)
	f.On("kubectl get udproutes.gateway.networking.k8s.io -n app-igw -o json", `{"items":[]}`)
	f.On("kubectl get referencegrants.gateway.networking.k8s.io -n app-backend -o json",
		`{"items":[{"metadata":{"name":"ed-dev-rg-main-nbox-routes","namespace":"app-backend"},"spec":{"from":[{"group":"gateway.networking.k8s.io","kind":"HTTPRoute","namespace":"app-igw"}],"to":[{"group":"","kind":"Service","name":"web"}]}}]}`)
	f.On("kubectl get service web -n app-backend -o json",
		`{"metadata":{"name":"web","namespace":"app-backend"},"spec":{"clusterIP":"10.96.2.20","selector":{"app":"web"},"ports":[{"port":8080,"targetPort":8080,"protocol":"TCP"}]}}`)
	f.On("kubectl get endpoints web -n app-backend -o json",
		`{"metadata":{"name":"web","namespace":"app-backend"},"subsets":[{"addresses":[{"ip":"10.0.2.20","nodeName":"node-1"}],"ports":[{"port":8080}]}]}`)
	f.On("kubectl get pods -n app-backend -l app=web -o json",
		`{"items":[{"metadata":{"name":"web-0","namespace":"app-backend","annotations":{"ambient.istio.io/redirection":"enabled"}},"spec":{"nodeName":"node-1"},"status":{"phase":"Running","podIP":"10.0.2.20","containerStatuses":[{"name":"web","ready":true}]}}]}`)
	f.On("kubectl get networkpolicies -n app-igw -o json",
		`{"items":[{"metadata":{"name":"ed-dev-np-nbox-main","namespace":"app-igw"},"spec":{"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-igw-nbox-main"}},"policyTypes":["Ingress","Egress"],"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"istio-system"}}}],"ports":[{"port":15012,"protocol":"TCP"}]},{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}],"ports":[{"port":1053,"protocol":"UDP"}]},{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"app-backend"}}}],"ports":[{"port":8080,"protocol":"TCP"},{"port":15008,"protocol":"TCP"}]}]}}]}`)
	f.On("kubectl get networkpolicies -n app-backend -o json",
		`{"items":[{"metadata":{"name":"ed-dev-np-main-nbox-routes","namespace":"app-backend"},"spec":{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"app-igw"}},"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-igw-nbox-main"}}}],"ports":[{"port":8080,"protocol":"TCP"},{"port":15008,"protocol":"TCP"}]}]}}]}`)
	f.On("kubectl get authorizationpolicies.security.istio.io -n app-backend -o json",
		`{"items":[{"metadata":{"name":"ed-dev-ap-main-nbox-routes","namespace":"app-backend"},"spec":{"action":"ALLOW","rules":[{"from":[{"source":{"principals":["cluster.local/ns/app-igw/sa/ed-dev-igw-nbox-main-istio"]}}],"to":[{"operation":{"ports":["8080"]}}]}]}}]}`)
	f.On("istioctl -n ztunnel ztunnel-config workloads ztunnel-n1",
		"NAMESPACE   POD NAME IP        NODE   WAYPOINT PROTOCOL\napp-backend web-0    10.0.2.20 node-1 None     HBONE\n")
	f.On("kubectl logs -n app-igw ed-dev-igw-nbox-main-istio-abc -c istio-proxy --since=15m --tail=300", "2026-11-23 GET / 200 OK\n")
	f.On("kubectl logs -n ztunnel ztunnel-n1 --since=15m --tail=500", "2026-11-23 info access connection complete src=10.0.1.10 dst=10.0.2.20\n")
	return f
}

func TestIngressHealthy(t *testing.T) {
	f := baseHealthyIngressRunner(t, time.Now().Add(90*24*time.Hour), []string{"app.idp.ecpk.test"})
	client := k8s.NewClient(f, "", "", "")

	rep := Run(context.Background(), client, Options{
		Version:   "test",
		Namespace: "app-igw",
		Verbose:   true,
	})
	if rep.Summary.Verdict != "HEALTHY" {
		var buf bytes.Buffer
		_ = report.Write(&buf, rep, report.FormatOptions{Format: "text"})
		t.Fatalf("expected HEALTHY, got %s:\n%s", rep.Summary.Verdict, buf.String())
	}

	// Verify JSON serialization is valid
	var jbuf bytes.Buffer
	if err := report.Write(&jbuf, rep, report.FormatOptions{Format: "json"}); err != nil {
		t.Fatalf("json format failed: %v", err)
	}
	var decoded report.Report
	if err := json.Unmarshal(jbuf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
}

func TestIngressBrokenScenarios(t *testing.T) {
	f := baseHealthyIngressRunner(t, time.Now().Add(-24*time.Hour), []string{"wrong.idp.ecpk.test"})
	// Break 1: Missing ReferenceGrant
	f.On("kubectl get referencegrants.gateway.networking.k8s.io -n app-backend -o json", `{"items":[]}`)
	// Break 2: NetworkPolicy missing port 15008 HBONE
	f.On("kubectl get networkpolicies -n app-igw -o json",
		`{"items":[{"metadata":{"name":"ed-dev-np-nbox-main","namespace":"app-igw"},"spec":{"podSelector":{"matchLabels":{"gateway.networking.k8s.io/gateway-name":"ed-dev-igw-nbox-main"}},"policyTypes":["Egress"],"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"istio-system"}}}],"ports":[{"port":15012,"protocol":"TCP"}]},{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}],"ports":[{"port":1053,"protocol":"UDP"}]},{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"app-backend"}}}],"ports":[{"port":8080,"protocol":"TCP"}]}]}}]}`)
	// Break 3: AuthorizationPolicy deny-all without ALLOW for gateway principal
	f.On("kubectl get authorizationpolicies.security.istio.io -n app-backend -o json",
		`{"items":[{"metadata":{"name":"deny-all","namespace":"app-backend"},"spec":{}}]}`)
	// Break 4: ztunnel logs show policy rejection
	f.On("kubectl logs -n ztunnel ztunnel-n1 --since=15m --tail=500",
		`2026-11-23 error access src.addr=10.0.1.10 dst.addr=10.0.2.20:8080 error="connection closed due to policy rejection"`)

	client := k8s.NewClient(f, "", "", "")
	rep := Run(context.Background(), client, Options{Version: "test", Namespace: "app-igw"})

	if rep.Summary.Verdict != "BROKEN" {
		t.Fatalf("expected BROKEN, got %s", rep.Summary.Verdict)
	}

	wantFailIDs := []string{
		"tls-expiry-https",
		"rg-app-backend-web",
		"np-gw-hbone-app-backend",
		"ap-backend-app-backend-8080",
		"ztunnel-logs",
	}
	gotFail := make(map[string]bool)
	for _, chk := range rep.Checks {
		if chk.Status == report.StatusFail {
			gotFail[chk.ID] = true
		}
	}
	for _, id := range wantFailIDs {
		if !gotFail[id] {
			t.Errorf("expected FAIL check %q not found; got fails: %v", id, gotFail)
		}
	}

	var md bytes.Buffer
	if err := report.Write(&md, rep, report.FormatOptions{Format: "markdown"}); err != nil {
		t.Fatalf("markdown format error: %v", err)
	}
	if !strings.Contains(md.String(), "Recommended Actions") {
		t.Errorf("expected Recommended Actions in markdown output")
	}
}
