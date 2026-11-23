package ingress

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/awbait/debug-toolbox/internal/k8s"
	"github.com/awbait/debug-toolbox/internal/report"
)

func checkGatewayTLS(
	ctx context.Context,
	c *k8s.Client,
	r *report.Report,
	gw k8s.Gateway,
	certs []k8s.Certificate,
	extSecrets []k8s.ExternalSecret,
) {
	const layer = "TLS & Certificates"
	ns := gw.Metadata.Namespace

	certBySecret := make(map[string]k8s.Certificate)
	for _, ct := range certs {
		certBySecret[ct.Spec.SecretName] = ct
	}
	esBySecret := make(map[string]k8s.ExternalSecret)
	for _, es := range extSecrets {
		if es.Spec.Target.Name != "" {
			esBySecret[es.Spec.Target.Name] = es
		}
	}

	checkedAny := false
	for _, l := range gw.Spec.Listeners {
		proto := strings.ToUpper(l.Protocol)
		if proto != "HTTPS" && proto != "TLS" {
			continue
		}
		if l.TLS == nil || !strings.EqualFold(l.TLS.Mode, "Terminate") {
			continue
		}
		checkedAny = true

		if len(l.TLS.CertificateRefs) == 0 {
			r.Fail("tls-ref-"+l.Name, layer, fmt.Sprintf("%s/%s:%s", ns, gw.Metadata.Name, l.Name),
				"TLS certificateRef",
				fmt.Sprintf("listener %q (%s:%d) has tls.mode=Terminate but no certificateRefs", l.Name, proto, l.Port),
				"Add certificateRefs or configure tls section in ingress-gateway values")
			continue
		}

		for _, ref := range l.TLS.CertificateRefs {
			secNS := ref.Namespace
			if secNS == "" {
				secNS = ns
			}
			secRes := fmt.Sprintf("secret/%s/%s", secNS, ref.Name)

			// Check owning Certificate (cert-manager) if present
			if secNS == ns {
				if ct, ok := certBySecret[ref.Name]; ok {
					checkCertManagerStatus(r, layer, ns, ct)
				}
				if es, ok := esBySecret[ref.Name]; ok {
					checkExternalSecretStatus(r, layer, ns, es)
				}
			}

			sec, err := c.GetSecret(ctx, secNS, ref.Name)
			if err != nil {
				r.Fail("tls-secret-"+l.Name+"-"+ref.Name, layer, secRes,
					fmt.Sprintf("TLS Secret for listener %q", l.Name),
					fmt.Sprintf("secret %s/%s not accessible: %v", secNS, ref.Name, err),
					"Check Certificate (cert-manager) or ExternalSecret (ESO) status and SecretStore/Vault connectivity")
				continue
			}

			crtB64 := sec.Data["tls.crt"]
			keyB64 := sec.Data["tls.key"]
			if crtB64 == "" || keyB64 == "" {
				r.Fail("tls-secret-data-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS Secret keys for listener %q", l.Name),
					"secret is missing tls.crt or tls.key data",
					"Verify Secret template type kubernetes.io/tls and Vault property names (crtProperty/keyProperty)")
				continue
			}

			crtPEM, err := base64.StdEncoding.DecodeString(crtB64)
			if err != nil {
				r.Fail("tls-secret-b64-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS certificate decode for listener %q", l.Name),
					fmt.Sprintf("failed to base64-decode tls.crt: %v", err),
					"Inspect tls.crt content in secret "+secRes)
				continue
			}

			block, _ := pem.Decode(crtPEM)
			if block == nil {
				r.Fail("tls-secret-pem-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS certificate PEM for listener %q", l.Name),
					"tls.crt does not contain a valid PEM block",
					"Check certificate encoding in Vault or cert-manager issuer")
				continue
			}

			x509Cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				r.Fail("tls-secret-x509-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS X.509 parse for listener %q", l.Name),
					fmt.Sprintf("invalid X.509 certificate: %v", err),
					"Re-issue or fix tls.crt in "+secRes)
				continue
			}

			now := time.Now().UTC()
			if now.After(x509Cert.NotAfter) {
				r.Fail("tls-expiry-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS certificate expiry (%s)", l.Name),
					fmt.Sprintf("certificate EXPIRED on %s", x509Cert.NotAfter.Format(time.RFC3339)),
					"Renew certificate via cert-manager or update Vault secret")
				continue
			}
			if now.Before(x509Cert.NotBefore) {
				r.Fail("tls-notbefore-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS certificate validity (%s)", l.Name),
					fmt.Sprintf("certificate is not valid until %s", x509Cert.NotBefore.Format(time.RFC3339)),
					"Check cluster clock or re-issue certificate")
				continue
			}

			// Verify hostname coverage when listener specifies a concrete hostname
			if l.Hostname != "" {
				if !certCoversHostname(x509Cert, l.Hostname) {
					r.Fail("tls-san-"+l.Name, layer, secRes,
						fmt.Sprintf("TLS certificate hostname match (%s)", l.Name),
						fmt.Sprintf("certificate DNSNames %v (CN=%q) do NOT cover listener hostname %q",
							x509Cert.DNSNames, x509Cert.Subject.CommonName, l.Hostname),
						fmt.Sprintf("Provide a certificate covering %q in tls.certificates (remember: *.a.b covers one subdomain level only)", l.Hostname))
					continue
				}
			}

			daysLeft := int(time.Until(x509Cert.NotAfter).Hours() / 24)
			if daysLeft < 14 {
				r.Warn("tls-expiry-soon-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS certificate expiring soon (%s)", l.Name),
					fmt.Sprintf("certificate expires in %d day(s) (%s)", daysLeft, x509Cert.NotAfter.Format("2006-01-02")),
					"Check cert-manager renewal or ESO refreshInterval")
			} else {
				r.Pass("tls-cert-"+l.Name, layer, secRes,
					fmt.Sprintf("TLS certificate valid (%s)", l.Name),
					fmt.Sprintf("covers %q, expires %s (%d days left)", l.Hostname, x509Cert.NotAfter.Format("2006-01-02"), daysLeft))
			}
		}
	}

	if !checkedAny {
		r.Info("tls-none", layer, ns+"/"+gw.Metadata.Name, "TLS termination", "no Terminate HTTPS/TLS listeners configured on this Gateway")
	}
}

func checkCertManagerStatus(r *report.Report, layer, ns string, ct k8s.Certificate) {
	res := fmt.Sprintf("certificate/%s/%s", ns, ct.Metadata.Name)
	cond, ok := k8s.FindCondition(ct.Status.Conditions, "Ready")
	if !ok {
		r.Warn("cm-cert-"+ct.Metadata.Name, layer, res, "cert-manager Certificate",
			"Certificate has no Ready condition yet",
			"Check cert-manager logs and ClusterIssuer "+ct.Spec.IssuerRef.Name)
		return
	}
	if cond.Status != "True" {
		r.Fail("cm-cert-"+ct.Metadata.Name, layer, res, "cert-manager Certificate",
			fmt.Sprintf("Ready=%s (%s): %s", cond.Status, cond.Reason, cond.Message),
			fmt.Sprintf("Inspect CertificateRequest and ClusterIssuer %q for domain %v", ct.Spec.IssuerRef.Name, ct.Spec.DNSNames))
	} else {
		r.Pass("cm-cert-"+ct.Metadata.Name, layer, res, "cert-manager Certificate",
			fmt.Sprintf("Ready=True (issuer=%s)", ct.Spec.IssuerRef.Name))
	}
}

func checkExternalSecretStatus(r *report.Report, layer, ns string, es k8s.ExternalSecret) {
	res := fmt.Sprintf("externalsecret/%s/%s", ns, es.Metadata.Name)
	cond, ok := k8s.FindCondition(es.Status.Conditions, "Ready")
	if !ok {
		r.Warn("eso-"+es.Metadata.Name, layer, res, "ExternalSecret sync",
			"ExternalSecret has no Ready condition yet",
			fmt.Sprintf("Verify SecretStore %q in namespace %s", es.Spec.SecretStoreRef.Name, ns))
		return
	}
	if cond.Status != "True" {
		r.Fail("eso-"+es.Metadata.Name, layer, res, "ExternalSecret sync",
			fmt.Sprintf("Ready=%s (%s): %s", cond.Status, cond.Reason, cond.Message),
			fmt.Sprintf("Check Vault path and SecretStore %q in namespace %s", es.Spec.SecretStoreRef.Name, ns))
	} else {
		r.Pass("eso-"+es.Metadata.Name, layer, res, "ExternalSecret sync",
			fmt.Sprintf("Ready=True (store=%s)", es.Spec.SecretStoreRef.Name))
	}
}

func certCoversHostname(cert *x509.Certificate, hostname string) bool {
	if strings.HasPrefix(hostname, "*.") {
		// Wildcard listener: check exact wildcard match in SANs or CN.
		for _, san := range cert.DNSNames {
			if strings.EqualFold(san, hostname) {
				return true
			}
		}
		return strings.EqualFold(cert.Subject.CommonName, hostname)
	}
	return cert.VerifyHostname(hostname) == nil
}
