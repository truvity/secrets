// Package stack is the Pulumi program that applies an estate's desired state
// (pkg/estate) through pkg/apply. It is apart from pkg/estate so that the
// derivation stays free of Pulumi: an estate's configuration loaders can build
// and review the state without linking the provider SDKs.
package stack

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/estate"
)

// The stack's outputs, under the names consumers read.
const (
	// OutputNamespaces lists the environment namespaces: its presence marks
	// the configuration deployed.
	OutputNamespaces = "namespaces"
	// OutputSSHUserCAs and OutputSSHHostCAs are each environment's SSH user
	// and host CA public keys, by environment.
	OutputSSHUserCAs = "sshUserCaPublicKeys"
	OutputSSHHostCAs = "sshHostCaPublicKeys"
)

type (
	// Options is what [Deploy] needs beside the desired state.
	Options struct {
		// Address, Login, BeforeApply and OIDCClientSecrets are pkg/apply's
		// (apply.Options).
		Address           string
		Login             apply.Login
		BeforeApply       func(context.Context) error
		OIDCClientSecrets map[string]pulumi.StringInput
		// Chains loads the committed, ceremony-signed certificates the
		// server imports.
		Chains estate.Chains
		// DomainCSROutputs names the output carrying each trust domain's
		// intermediate request, by trust domain: what the root ceremony
		// signs.
		DomainCSROutputs map[string]string
		// EnvironmentCSROutput names the output carrying every identity
		// environment CA's request, by environment, whichever phase it is in.
		EnvironmentCSROutput string
		// Logger records each signed chain installed; nil is slog.Default.
		Logger *slog.Logger
		// Select is apply.Options.Select: this stack applies only part of
		// the estate (docs/decisions/0005). The outputs of what it does
		// not register -- a CA's request, an SSH CA's key -- are left out,
		// and an identity environment CA is bootstrapped only by the stack
		// that selects its mount. nil applies, and exports, everything.
		Select func(apply.Resource) bool
	}
)

// Deploy applies the desired state through pkg/apply -- every namespace below
// root, root's jobs and web UI door, the PKI -- under the names existing state
// holds (estate.Desired.LegacyResourceNames), and exports what consumers
// read: the namespaces, each environment's SSH CA keys, and the certificate
// requests the root ceremony signs.
//
// An identity environment CA that is not signed yet is bootstrapped beside
// the apply: its mount and the request of the key the server generates,
// under the name the apply adopts once it is signed. A pending domain
// intermediate (estate.PKI.PendingDomains) is bootstrapped the same way, in
// root, and its request is exported under the domain's request output.
func Deploy(c *pulumi.Context, desired *estate.Desired, opts Options) error {
	state, err := desired.Model()
	if err != nil {
		return err
	}

	in := desired.Inputs()
	rename := apply.RenameFrom(desired.LegacyResourceNames())
	identity := in.PKI.Contract.URITrustDomain(in.PKI.Identity)

	// Which unsigned identity CAs this stack bootstraps, decided -- and a
	// split of one refused -- before anything is registered.
	bootstraps := map[string]bool{}

	if identity != nil {
		for _, environment := range identity.Environments {
			if in.PKI.Signed[environment] {
				continue
			}

			owned, err := selectsBootstrap(opts.Select, rename, environment, identity.IssuingMountPath(), identity.EnvironmentCAIssuerName(environment))
			if err != nil {
				return err
			}

			bootstraps[environment] = owned
		}
	}

	// Two trust domains' requests under one output would hide one of them
	// from the ceremony.
	outputs := map[string]string{}

	for domain, output := range opts.DomainCSROutputs {
		if other, taken := outputs[output]; taken {
			first, second := min(domain, other), max(domain, other)

			return fmt.Errorf("stack: trust domains %s and %s share the request output %q", first, second, output)
		}

		outputs[output] = domain
	}

	// Which pending domain intermediates this stack bootstraps, decided the
	// same way, before anything is registered.
	pendingDomains := map[string]bool{}

	for i := range desired.PKI.Pending {
		pending := &desired.PKI.Pending[i]

		if _, ok := opts.DomainCSROutputs[pending.TrustDomain]; !ok {
			return fmt.Errorf("stack: trust domain %s has no request output", pending.TrustDomain)
		}

		owned, err := selectsBootstrap(opts.Select, rename, "", pending.Mount, pending.KeyName)
		if err != nil {
			return err
		}

		pendingDomains[pending.TrustDomain] = owned
	}

	result, err := apply.Deploy(c, state, apply.Options{
		Address:           opts.Address,
		Login:             opts.Login,
		BeforeApply:       opts.BeforeApply,
		OIDCClientSecrets: opts.OIDCClientSecrets,
		SignedChain:       desired.SignedChain(c.Context(), opts.Logger, opts.Chains),
		Rename:            rename,
		Select:            opts.Select,
	})
	if err != nil {
		return err
	}

	c.Export(OutputNamespaces, pulumi.ToStringArray(result.Namespaces))
	c.Export(OutputSSHUserCAs, environmentKeys(result.SSHCAPublicKeys, in.Names.SSH.Mount))
	c.Export(OutputSSHHostCAs, environmentKeys(result.SSHHostCAPublicKeys, in.Names.SSH.HostMount))

	for i := range desired.PKI.Domains {
		domain := &desired.PKI.Domains[i]

		output, ok := opts.DomainCSROutputs[domain.TrustDomain]
		if !ok {
			return fmt.Errorf("stack: trust domain %s has no request output", domain.TrustDomain)
		}

		// Registered by another stack: its request is that stack's output.
		csr, registered := result.CertificateRequests[domain.IssuerName]
		if !registered && opts.Select != nil {
			continue
		}

		c.Export(output, csr)
	}

	for i := range desired.PKI.Pending {
		pending := &desired.PKI.Pending[i]
		if !pendingDomains[pending.TrustDomain] {
			continue
		}

		csr, err := apply.BootstrapEnvironmentCA(c, result.Provider, apply.BootstrapEnvironmentCAOptions{
			Mount:            pending.Mount,
			DefaultLeaseTTL:  pending.LeaseTTL,
			MaxLeaseTTL:      pending.LeaseTTL,
			MountDescription: pending.MountDescription,
			KeyName:          pending.KeyName,
			CommonName:       pending.CommonName,
			Organization:     pending.Organization,
			KeyCurve:         pending.KeyCurve,
			Rename:           rename,
		})
		if err != nil {
			return err
		}

		c.Export(opts.DomainCSROutputs[pending.TrustDomain], csr)
	}

	if identity == nil || len(identity.Environments) == 0 {
		return nil
	}

	generation, err := estate.ActiveGeneration(in.PKI.Contract)
	if err != nil {
		return err
	}

	csrs := pulumi.StringMap{}

	for _, environment := range identity.Environments {
		if in.PKI.Signed[environment] {
			csr, registered := result.CertificateRequests[identity.EnvironmentCAIssuerName(environment)]
			if registered || opts.Select == nil {
				csrs[environment] = csr
			}

			continue
		}

		if !bootstraps[environment] {
			continue
		}

		zone, err := desired.PrivateZone(environment)
		if err != nil {
			return err
		}

		csr, err := apply.BootstrapEnvironmentCA(c, result.Provider, apply.BootstrapEnvironmentCAOptions{
			Namespace:        environment,
			Mount:            identity.IssuingMountPath(),
			DefaultLeaseTTL:  identity.Role.Lifetimes.Default,
			MaxLeaseTTL:      identity.Role.Lifetimes.Maximum,
			MountDescription: strings.ReplaceAll(in.Text.IdentityBootstrap, "{env}", environment),
			KeyName:          identity.EnvironmentCAIssuerName(environment),
			CommonName:       zone + " " + identity.EnvironmentCA.CommonNameSuffix,
			Organization:     generation.Certificate.Subject.Organization,
			KeyCurve:         identity.EnvironmentCA.KeyCurve,
			Rename:           rename,
		})
		if err != nil {
			return err
		}

		csrs[environment] = csr
	}

	if len(csrs) > 0 || opts.Select == nil {
		c.Export(opts.EnvironmentCSROutput, csrs)
	}

	return nil
}

// selectsBootstrap reports whether this stack bootstraps an unsigned CA --
// an identity environment CA in its environment's namespace, or a pending
// domain intermediate in root (namespace "") -- always without a selector;
// otherwise when it selects the CA's mount, and then its request too (the
// two are one unit). The names are the ones apply.Deploy gives the same
// objects once the CA is signed.
func selectsBootstrap(selects func(apply.Resource) bool, rename func(string) string, namespace, mount, keyName string) (bool, error) {
	if selects == nil {
		return true, nil
	}

	mountName := mount
	if namespace != "" {
		mountName = namespace + "-" + mount
	}

	mountResource := apply.Resource{Type: apply.TypeMount, Name: rename(mountName)}
	csrResource := apply.Resource{Type: apply.TypePKIIntermediateCertRequest, Name: rename(keyName + "-csr")}

	owned := selects(mountResource)
	if selects(csrResource) != owned {
		return false, fmt.Errorf("stack: select: %s %s and %s are selected apart; a mount is applied with its CA, its issuers and its configuration",
			csrResource.Type, csrResource.Name, mountResource.Name)
	}

	return owned, nil
}

// environmentKeys is the environments' public keys of one SSH mount, by
// environment.
func environmentKeys(keys map[apply.MountRef]pulumi.StringOutput, mount string) pulumi.StringMap {
	out := pulumi.StringMap{}

	for ref, key := range keys {
		if ref.Namespace != "" && ref.Path == mount {
			out[ref.Namespace] = key
		}
	}

	return out
}

// OIDCClientSecret reads an OIDC client's secret from the Secret another
// system delivers, before the apply touches the server: a client not
// delivered yet stops a preview too. The client id is read back as a check
// that the Secret is the client the mounts name. The value never reaches a
// log or an error; mark it secret.
func OIDCClientSecret(ctx context.Context, kubectl apply.Kubectl, delivered apply.DeliveredSecret, client string) (string, error) {
	id, err := delivered.Key(ctx, kubectl, "client-id")
	if err != nil {
		return "", err
	}

	if id != client {
		return "", fmt.Errorf("secret %s/%s names client %q, want %q", delivered.Namespace, delivered.Name, id, client)
	}

	return delivered.Key(ctx, kubectl, "client-secret")
}
