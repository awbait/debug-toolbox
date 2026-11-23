package k8s

import (
	"encoding/json"
	"strings"
)

type ObjectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type List[T any] struct {
	Items []T `json:"items"`
}

// --- Core Kubernetes ---

type Namespace struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		NodeName           string `json:"nodeName"`
		ServiceAccountName string `json:"serviceAccountName"`
		Containers         []struct {
			Name  string `json:"name"`
			Ports []struct {
				Name          string `json:"name"`
				ContainerPort int    `json:"containerPort"`
				Protocol      string `json:"protocol"`
			} `json:"ports"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		PodIP             string `json:"podIP"`
		HostIP            string `json:"hostIP"`
		ContainerStatuses []struct {
			Name         string `json:"name"`
			Ready        bool   `json:"ready"`
			RestartCount int    `json:"restartCount"`
			State        struct {
				Waiting *struct {
					Reason  string `json:"reason"`
					Message string `json:"message"`
				} `json:"waiting,omitempty"`
				Terminated *struct {
					Reason   string `json:"reason"`
					ExitCode int    `json:"exitCode"`
				} `json:"terminated,omitempty"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func (p Pod) IsReady() bool {
	if p.Status.Phase != "Running" || len(p.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, cs := range p.Status.ContainerStatuses {
		if !cs.Ready {
			return false
		}
	}
	return true
}

func (p Pod) TotalRestarts() int {
	total := 0
	for _, cs := range p.Status.ContainerStatuses {
		total += cs.RestartCount
	}
	return total
}

type Service struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Type                  string            `json:"type"`
		ClusterIP             string            `json:"clusterIP"`
		ExternalTrafficPolicy string            `json:"externalTrafficPolicy"`
		Selector              map[string]string `json:"selector"`
		Ports                 []struct {
			Name       string          `json:"name"`
			Port       int             `json:"port"`
			TargetPort json.RawMessage `json:"targetPort"`
			Protocol   string          `json:"protocol"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type Endpoints struct {
	Metadata ObjectMeta `json:"metadata"`
	Subsets  []struct {
		Addresses []struct {
			IP        string `json:"ip"`
			NodeName  string `json:"nodeName"`
			TargetRef *struct {
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"targetRef"`
		} `json:"addresses"`
		NotReadyAddresses []struct {
			IP string `json:"ip"`
		} `json:"notReadyAddresses"`
		Ports []struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
	} `json:"subsets"`
}

type Secret struct {
	Metadata ObjectMeta        `json:"metadata"`
	Type     string            `json:"type"`
	Data     map[string]string `json:"data"`
}

type ConfigMap struct {
	Metadata ObjectMeta        `json:"metadata"`
	Data     map[string]string `json:"data"`
}

type Event struct {
	Type           string `json:"type"`
	Reason         string `json:"reason"`
	Message        string `json:"message"`
	Count          int    `json:"count"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"involvedObject"`
}

type LabelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels,omitempty"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values,omitempty"`
	} `json:"matchExpressions,omitempty"`
}

type NetworkPolicyPort struct {
	Protocol string          `json:"protocol,omitempty"`
	Port     json.RawMessage `json:"port,omitempty"`
}

type NetworkPolicyPeer struct {
	PodSelector       *LabelSelector `json:"podSelector,omitempty"`
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`
	IPBlock           *struct {
		CIDR   string   `json:"cidr"`
		Except []string `json:"except,omitempty"`
	} `json:"ipBlock,omitempty"`
}

type NetworkPolicy struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		PodSelector LabelSelector `json:"podSelector"`
		PolicyTypes []string      `json:"policyTypes"`
		Ingress     []struct {
			From  []NetworkPolicyPeer `json:"from,omitempty"`
			Ports []NetworkPolicyPort `json:"ports,omitempty"`
		} `json:"ingress,omitempty"`
		Egress []struct {
			To    []NetworkPolicyPeer `json:"to,omitempty"`
			Ports []NetworkPolicyPort `json:"ports,omitempty"`
		} `json:"egress,omitempty"`
	} `json:"spec"`
}

// --- Gateway API ---

type Gateway struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		GatewayClassName string `json:"gatewayClassName"`
		Infrastructure   *struct {
			Labels        map[string]string `json:"labels,omitempty"`
			ParametersRef *struct {
				Group string `json:"group"`
				Kind  string `json:"kind"`
				Name  string `json:"name"`
			} `json:"parametersRef,omitempty"`
		} `json:"infrastructure,omitempty"`
		Listeners []GatewayListener `json:"listeners"`
	} `json:"spec"`
	Status struct {
		Addresses []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"addresses"`
		Conditions []Condition `json:"conditions"`
		Listeners  []struct {
			Name           string      `json:"name"`
			AttachedRoutes int         `json:"attachedRoutes"`
			Conditions     []Condition `json:"conditions"`
		} `json:"listeners"`
	} `json:"status"`
}

type GatewayListener struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      *struct {
		Mode            string `json:"mode"`
		CertificateRefs []struct {
			Group     string `json:"group,omitempty"`
			Kind      string `json:"kind,omitempty"`
			Name      string `json:"name"`
			Namespace string `json:"namespace,omitempty"`
		} `json:"certificateRefs,omitempty"`
	} `json:"tls,omitempty"`
	AllowedRoutes *struct {
		Namespaces *struct {
			From     string         `json:"from"`
			Selector *LabelSelector `json:"selector,omitempty"`
		} `json:"namespaces,omitempty"`
	} `json:"allowedRoutes,omitempty"`
}

// Route represents HTTPRoute / GRPCRoute / TLSRoute / TCPRoute / UDPRoute uniformly.
type Route struct {
	Kind     string     `json:"kind"`
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		ParentRefs []struct {
			Group       string `json:"group,omitempty"`
			Kind        string `json:"kind,omitempty"`
			Name        string `json:"name"`
			Namespace   string `json:"namespace,omitempty"`
			SectionName string `json:"sectionName,omitempty"`
		} `json:"parentRefs"`
		Hostnames []string `json:"hostnames,omitempty"`
		Rules     []struct {
			Filters []struct {
				Type string `json:"type"`
			} `json:"filters,omitempty"`
			BackendRefs []struct {
				Group     string `json:"group,omitempty"`
				Kind      string `json:"kind,omitempty"`
				Name      string `json:"name"`
				Namespace string `json:"namespace,omitempty"`
				Port      int    `json:"port"`
				Weight    *int   `json:"weight,omitempty"`
			} `json:"backendRefs,omitempty"`
		} `json:"rules"`
	} `json:"spec"`
	Status struct {
		Parents []struct {
			ParentRef struct {
				Name        string `json:"name"`
				Namespace   string `json:"namespace,omitempty"`
				SectionName string `json:"sectionName,omitempty"`
			} `json:"parentRef"`
			Conditions []Condition `json:"conditions"`
		} `json:"parents"`
	} `json:"status"`
}

type ReferenceGrant struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		From []struct {
			Group     string `json:"group"`
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
		} `json:"from"`
		To []struct {
			Group string `json:"group"`
			Kind  string `json:"kind"`
			Name  string `json:"name,omitempty"`
		} `json:"to"`
	} `json:"spec"`
}

// --- Istio ---

type AuthorizationPolicy struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Action   string         `json:"action,omitempty"`
		Selector *LabelSelector `json:"selector,omitempty"`
		TargetRefs []struct {
			Group string `json:"group"`
			Kind  string `json:"kind"`
			Name  string `json:"name"`
		} `json:"targetRefs,omitempty"`
		Provider *struct {
			Name string `json:"name"`
		} `json:"provider,omitempty"`
		Rules []struct {
			From []struct {
				Source struct {
					Principals    []string `json:"principals,omitempty"`
					Namespaces    []string `json:"namespaces,omitempty"`
					IPBlocks      []string `json:"ipBlocks,omitempty"`
					NotPrincipals []string `json:"notPrincipals,omitempty"`
				} `json:"source"`
			} `json:"from,omitempty"`
			To []struct {
				Operation struct {
					Ports   []string `json:"ports,omitempty"`
					Hosts   []string `json:"hosts,omitempty"`
					Paths   []string `json:"paths,omitempty"`
					Methods []string `json:"methods,omitempty"`
				} `json:"operation"`
			} `json:"to,omitempty"`
			When []struct {
				Key    string   `json:"key"`
				Values []string `json:"values"`
			} `json:"when,omitempty"`
		} `json:"rules,omitempty"`
	} `json:"spec"`
}

type PeerAuthentication struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Selector *LabelSelector `json:"selector,omitempty"`
		MTLS     *struct {
			Mode string `json:"mode"`
		} `json:"mtls,omitempty"`
		PortLevelMTLS map[string]struct {
			Mode string `json:"mode"`
		} `json:"portLevelMtls,omitempty"`
	} `json:"spec"`
}

type DestinationRule struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Host          string   `json:"host"`
		ExportTo      []string `json:"exportTo,omitempty"`
		TrafficPolicy *struct {
			LoadBalancer *struct {
				ConsistentHash *struct {
					HTTPCookie *struct {
						Name string `json:"name"`
						TTL  string `json:"ttl,omitempty"`
					} `json:"httpCookie,omitempty"`
				} `json:"consistentHash,omitempty"`
			} `json:"loadBalancer,omitempty"`
			ConnectionPool *struct {
				HTTP *struct {
					H2UpgradePolicy string `json:"h2UpgradePolicy,omitempty"`
				} `json:"http,omitempty"`
			} `json:"connectionPool,omitempty"`
		} `json:"trafficPolicy,omitempty"`
	} `json:"spec"`
}

type RequestAuthentication struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		TargetRefs []struct {
			Group string `json:"group"`
			Kind  string `json:"kind"`
			Name  string `json:"name"`
		} `json:"targetRefs,omitempty"`
		JWTRules []struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwksUri"`
		} `json:"jwtRules,omitempty"`
	} `json:"spec"`
}

type ServiceEntry struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Hosts      []string `json:"hosts"`
		Addresses  []string `json:"addresses,omitempty"`
		ExportTo   []string `json:"exportTo,omitempty"`
		Location   string   `json:"location,omitempty"`
		Resolution string   `json:"resolution,omitempty"`
		Ports      []struct {
			Number   int    `json:"number"`
			Name     string `json:"name"`
			Protocol string `json:"protocol"`
		} `json:"ports,omitempty"`
	} `json:"spec"`
	Status struct {
		Addresses []struct {
			Host  string `json:"host,omitempty"`
			Value string `json:"value"`
		} `json:"addresses,omitempty"`
		Conditions []Condition `json:"conditions,omitempty"`
	} `json:"status"`
}

// EffectiveVIPs returns explicit spec.addresses if set, otherwise auto-allocated status.addresses.
func (se ServiceEntry) EffectiveVIPs() []string {
	if len(se.Spec.Addresses) > 0 {
		out := make([]string, len(se.Spec.Addresses))
		copy(out, se.Spec.Addresses)
		return out
	}
	var out []string
	for _, a := range se.Status.Addresses {
		if a.Value != "" {
			out = append(out, a.Value)
		}
	}
	return out
}

// --- cert-manager & External Secrets ---

type Certificate struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		SecretName string   `json:"secretName"`
		DNSNames   []string `json:"dnsNames"`
		IssuerRef  struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"issuerRef"`
	} `json:"spec"`
	Status struct {
		Conditions []Condition `json:"conditions"`
		NotAfter   string      `json:"notAfter,omitempty"`
	} `json:"status"`
}

type ExternalSecret struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		SecretStoreRef struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"secretStoreRef"`
		Target struct {
			Name string `json:"name"`
		} `json:"target"`
	} `json:"spec"`
	Status struct {
		Conditions []Condition `json:"conditions"`
	} `json:"status"`
}

// --- Kube-OVN ---

type VpcEgressGateway struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		VPC            string   `json:"vpc"`
		Replicas       int      `json:"replicas"`
		ExternalSubnet string   `json:"externalSubnet"`
		ExternalIPs    []string `json:"externalIPs"`
		Selectors      []struct {
			NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`
			PodSelector       *LabelSelector `json:"podSelector,omitempty"`
		} `json:"selectors,omitempty"`
		Policies []struct {
			SNAT     bool     `json:"snat"`
			Subnets  []string `json:"subnets,omitempty"`
			IPBlocks []string `json:"ipBlocks,omitempty"`
		} `json:"policies,omitempty"`
	} `json:"spec"`
	Status struct {
		Ready      bool        `json:"ready"`
		Phase      string      `json:"phase,omitempty"`
		Conditions []Condition `json:"conditions,omitempty"`
	} `json:"status"`
}

type Subnet struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		CIDRBlock    string   `json:"cidrBlock"`
		Gateway      string   `json:"gateway"`
		GatewayType  string   `json:"gatewayType"`
		Private      bool     `json:"private"`
		NatOutgoing  bool     `json:"natOutgoing"`
		AllowSubnets []string `json:"allowSubnets,omitempty"`
		Namespaces   []string `json:"namespaces,omitempty"`
		Provider     string   `json:"provider,omitempty"`
	} `json:"spec"`
	Status struct {
		Conditions []Condition `json:"conditions,omitempty"`
	} `json:"status"`
}

// --- Helpers ---

func FindCondition(conds []Condition, typ string) (Condition, bool) {
	for _, c := range conds {
		if c.Type == typ {
			return c, true
		}
	}
	return Condition{}, false
}

func ParsePortRaw(raw json.RawMessage) (string, int) {
	if len(raw) == 0 {
		return "", 0
	}
	var num int
	if err := json.Unmarshal(raw, &num); err == nil {
		return "", num
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, 0
	}
	return strings.Trim(string(raw), `"`), 0
}
