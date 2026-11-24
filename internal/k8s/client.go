package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Client provides typed access to Kubernetes, Istio, and Kube-OVN via Runner.
type Client struct {
	Runner        Runner
	Kubeconfig    string
	Context       string
	ZtunnelNS     string // optional override; auto-detected if empty
	ztunnelNSOnce string
}

func NewClient(runner Runner, kubeconfig, k8sContext, ztunnelNS string) *Client {
	return &Client{
		Runner:     runner,
		Kubeconfig: kubeconfig,
		Context:    k8sContext,
		ZtunnelNS:  ztunnelNS,
	}
}

func (c *Client) baseKubectlArgs() []string {
	var args []string
	if c.Kubeconfig != "" {
		args = append(args, "--kubeconfig", c.Kubeconfig)
	}
	if c.Context != "" {
		args = append(args, "--context", c.Context)
	}
	return args
}

func (c *Client) Kubectl(ctx context.Context, args ...string) (CmdResult, error) {
	full := append(c.baseKubectlArgs(), args...)
	return c.Runner.Run(ctx, "kubectl", full...)
}

func (c *Client) KubectlStdin(ctx context.Context, stdin string, args ...string) (CmdResult, error) {
	full := append(c.baseKubectlArgs(), args...)
	return c.Runner.RunWithStdin(ctx, stdin, "kubectl", full...)
}

func (c *Client) Istioctl(ctx context.Context, args ...string) (CmdResult, error) {
	var full []string
	if c.Kubeconfig != "" {
		full = append(full, "--kubeconfig", c.Kubeconfig)
	}
	if c.Context != "" {
		full = append(full, "--context", c.Context)
	}
	full = append(full, args...)
	return c.Runner.Run(ctx, "istioctl", full...)
}

// GetJSON executes `kubectl get ... -o json` and decodes into out.
func (c *Client) GetJSON(ctx context.Context, out any, args ...string) error {
	full := append([]string{"get"}, args...)
	full = append(full, "-o", "json")
	res, err := c.Kubectl(ctx, full...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(res.Stdout), out); err != nil {
		return fmt.Errorf("parse json for kubectl %s: %w", strings.Join(full, " "), err)
	}
	return nil
}

func (c *Client) GetNamespace(ctx context.Context, name string) (Namespace, error) {
	var ns Namespace
	err := c.GetJSON(ctx, &ns, "namespace", name)
	return ns, err
}

func (c *Client) ListNamespaces(ctx context.Context) ([]Namespace, error) {
	var list List[Namespace]
	err := c.GetJSON(ctx, &list, "namespaces")
	return list.Items, err
}

func (c *Client) GetPod(ctx context.Context, namespace, name string) (Pod, error) {
	var p Pod
	err := c.GetJSON(ctx, &p, "pod", name, "-n", namespace)
	return p, err
}

func (c *Client) ListPods(ctx context.Context, namespace, selector string) ([]Pod, error) {
	args := []string{"pods"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	if selector != "" {
		args = append(args, "-l", selector)
	}
	var list List[Pod]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) ListServices(ctx context.Context, namespace string) ([]Service, error) {
	args := []string{"services"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[Service]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) GetService(ctx context.Context, namespace, name string) (Service, error) {
	var svc Service
	err := c.GetJSON(ctx, &svc, "service", name, "-n", namespace)
	return svc, err
}

func (c *Client) GetEndpoints(ctx context.Context, namespace, name string) (Endpoints, error) {
	var ep Endpoints
	err := c.GetJSON(ctx, &ep, "endpoints", name, "-n", namespace)
	return ep, err
}

func (c *Client) ListEndpoints(ctx context.Context, namespace string) ([]Endpoints, error) {
	args := []string{"endpoints"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[Endpoints]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) GetWorkload(ctx context.Context, resource, namespace, name string) (Workload, error) {
	var w Workload
	err := c.GetJSON(ctx, &w, resource, name, "-n", namespace)
	return w, err
}

func (c *Client) ListRoleBindings(ctx context.Context, namespace string) ([]RBACBinding, error) {
	var list List[RBACBinding]
	err := c.GetJSON(ctx, &list, "rolebindings", "-n", namespace)
	return list.Items, err
}

func (c *Client) ListClusterRoleBindings(ctx context.Context) ([]RBACBinding, error) {
	var list List[RBACBinding]
	err := c.GetJSON(ctx, &list, "clusterrolebindings")
	return list.Items, err
}

func (c *Client) ListWebhookConfigurations(ctx context.Context) ([]WebhookConfiguration, error) {
	var out []WebhookConfiguration
	var vList List[WebhookConfiguration]
	if err := c.GetJSON(ctx, &vList, "validatingwebhookconfigurations"); err == nil {
		out = append(out, vList.Items...)
	}
	var mList List[WebhookConfiguration]
	if err := c.GetJSON(ctx, &mList, "mutatingwebhookconfigurations"); err == nil {
		out = append(out, mList.Items...)
	}
	return out, nil
}

func (c *Client) GetSecret(ctx context.Context, namespace, name string) (Secret, error) {
	var s Secret
	err := c.GetJSON(ctx, &s, "secret", name, "-n", namespace)
	return s, err
}

func (c *Client) GetConfigMap(ctx context.Context, namespace, name string) (ConfigMap, error) {
	var cm ConfigMap
	err := c.GetJSON(ctx, &cm, "configmap", name, "-n", namespace)
	return cm, err
}

func (c *Client) ListGateways(ctx context.Context, namespace string) ([]Gateway, error) {
	args := []string{"gateways.gateway.networking.k8s.io"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[Gateway]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) ListRoutes(ctx context.Context, kindResource, namespace string) ([]Route, error) {
	args := []string{kindResource}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[Route]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) ListReferenceGrants(ctx context.Context, namespace string) ([]ReferenceGrant, error) {
	var list List[ReferenceGrant]
	err := c.GetJSON(ctx, &list, "referencegrants.gateway.networking.k8s.io", "-n", namespace)
	return list.Items, err
}

func (c *Client) ListNetworkPolicies(ctx context.Context, namespace string) ([]NetworkPolicy, error) {
	var list List[NetworkPolicy]
	err := c.GetJSON(ctx, &list, "networkpolicies", "-n", namespace)
	return list.Items, err
}

func (c *Client) ListAuthorizationPolicies(ctx context.Context, namespace string) ([]AuthorizationPolicy, error) {
	args := []string{"authorizationpolicies.security.istio.io"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[AuthorizationPolicy]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) ListPeerAuthentications(ctx context.Context, namespace string) ([]PeerAuthentication, error) {
	args := []string{"peerauthentications.security.istio.io"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[PeerAuthentication]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) ListDestinationRules(ctx context.Context, namespace string) ([]DestinationRule, error) {
	var list List[DestinationRule]
	err := c.GetJSON(ctx, &list, "destinationrules.networking.istio.io", "-n", namespace)
	return list.Items, err
}

func (c *Client) ListRequestAuthentications(ctx context.Context, namespace string) ([]RequestAuthentication, error) {
	var list List[RequestAuthentication]
	err := c.GetJSON(ctx, &list, "requestauthentications.security.istio.io", "-n", namespace)
	return list.Items, err
}

func (c *Client) ListServiceEntries(ctx context.Context, namespace string) ([]ServiceEntry, error) {
	args := []string{"serviceentries.networking.istio.io"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[ServiceEntry]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) ListCertificates(ctx context.Context, namespace string) ([]Certificate, error) {
	var list List[Certificate]
	err := c.GetJSON(ctx, &list, "certificates.cert-manager.io", "-n", namespace)
	return list.Items, err
}

func (c *Client) ListExternalSecrets(ctx context.Context, namespace string) ([]ExternalSecret, error) {
	var list List[ExternalSecret]
	err := c.GetJSON(ctx, &list, "externalsecrets.external-secrets.io", "-n", namespace)
	return list.Items, err
}

func (c *Client) ListVpcEgressGateways(ctx context.Context, namespace string) ([]VpcEgressGateway, error) {
	args := []string{"vpcegressgateways.kubeovn.io"}
	if namespace == "" {
		args = append(args, "-A")
	} else {
		args = append(args, "-n", namespace)
	}
	var list List[VpcEgressGateway]
	err := c.GetJSON(ctx, &list, args...)
	return list.Items, err
}

func (c *Client) ListSubnets(ctx context.Context) ([]Subnet, error) {
	var list List[Subnet]
	err := c.GetJSON(ctx, &list, "subnets.kubeovn.io")
	return list.Items, err
}

func (c *Client) ListIPAddressPools(ctx context.Context) ([]IPAddressPool, error) {
	var list List[IPAddressPool]
	err := c.GetJSON(ctx, &list, "ipaddresspools.metallb.io", "-A")
	return list.Items, err
}

func (c *Client) ListWarningEvents(ctx context.Context, namespace string) ([]Event, error) {
	var list List[Event]
	err := c.GetJSON(ctx, &list, "events", "-n", namespace, "--field-selector", "type=Warning")
	return list.Items, err
}

func (c *Client) PodLogs(ctx context.Context, namespace, pod, container, since string, tail int) (string, error) {
	args := []string{"logs", "-n", namespace, pod}
	if container != "" {
		args = append(args, "-c", container)
	}
	if since != "" {
		args = append(args, "--since="+since)
	}
	if tail > 0 {
		args = append(args, fmt.Sprintf("--tail=%d", tail))
	}
	res, err := c.Kubectl(ctx, args...)
	return res.Stdout, err
}

func (c *Client) PodExec(ctx context.Context, namespace, pod, container string, cmd ...string) (CmdResult, error) {
	args := []string{"exec", "-n", namespace, pod}
	if container != "" {
		args = append(args, "-c", container)
	}
	args = append(args, "--")
	args = append(args, cmd...)
	return c.Kubectl(ctx, args...)
}

// DetectZtunnelNamespace discovers whether ztunnel runs in "ztunnel" or "istio-system" (or any other NS).
func (c *Client) DetectZtunnelNamespace(ctx context.Context) (string, []Pod, error) {
	if c.ZtunnelNS != "" {
		pods, err := c.ListPods(ctx, c.ZtunnelNS, "app=ztunnel")
		return c.ZtunnelNS, pods, err
	}
	if c.ztunnelNSOnce != "" {
		pods, err := c.ListPods(ctx, c.ztunnelNSOnce, "app=ztunnel")
		return c.ztunnelNSOnce, pods, err
	}
	pods, err := c.ListPods(ctx, "", "app=ztunnel")
	if err != nil {
		return "", nil, err
	}
	if len(pods) == 0 {
		return "", nil, fmt.Errorf("no pods with label app=ztunnel found in cluster")
	}
	c.ztunnelNSOnce = pods[0].Metadata.Namespace
	return c.ztunnelNSOnce, pods, nil
}

// DetectOVNLeader finds the kube-system ovn-central pod with ovn-nb-leader=true.
func (c *Client) DetectOVNLeader(ctx context.Context) (string, error) {
	pods, err := c.ListPods(ctx, "kube-system", "ovn-nb-leader=true")
	if err != nil {
		return "", err
	}
	for _, p := range pods {
		if p.IsReady() {
			return p.Metadata.Name, nil
		}
	}
	if len(pods) > 0 {
		return pods[0].Metadata.Name, nil
	}
	return "", fmt.Errorf("no ovn-nb-leader=true pod found in kube-system")
}

// IsNotFound checks whether a kubectl error indicates a missing resource or CRD.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "notfound") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "the server doesn't have a resource type")
}

// IsForbidden checks whether a kubectl error indicates RBAC denial.
func IsForbidden(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "forbidden")
}
