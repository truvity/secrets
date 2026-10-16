package estate

import (
	"fmt"
	"slices"

	"github.com/truvity/secrets/pkg/model"
)

// The view ([Desired]) becomes the public model here: what pkg/apply
// converges the server onto. Everything the apply would otherwise name
// differently from what state already holds is data here: the Pulumi names
// a resource has always had ([Desired.LegacyResourceNames]).

// Model is the desired state as the public model, ready for pkg/apply: the
// library's derivation (builder.Spec.Build) joined to the PKI.
func (d *Desired) Model() (*model.Desired, error) {
	if d.built == nil || d.derivation == nil || d.in == nil {
		return nil, fmt.Errorf("estate: the desired state was never built")
	}

	out := *d.built.Model
	out.Namespaces = slices.Clone(out.Namespaces)

	// The contract's authorities are the server's PKI: the domain
	// intermediates in root, each environment's issuing CAs in its
	// namespace. The library derives them, Apply places them.
	if err := d.derivation.Apply(&out); err != nil {
		return nil, err
	}

	if err := out.Validate(); err != nil {
		return nil, err
	}

	return &out, nil
}

// IdentityBootstrapCSRName is the Pulumi name of the certificate signing
// request of one environment's root-signed identity CA: named after the
// mount and the environment, because no issuer existed yet to name it
// after when the bootstrap created it.
func (d *Desired) IdentityBootstrapCSRName(environment string) string {
	identity := d.in.PKI.Contract.URITrustDomain(d.in.PKI.Identity)

	return identity.IssuingMountPath() + "-" + environment + d.in.PKI.BootstrapSuffix + "-csr"
}

// LegacyResourceNames maps the Pulumi name pkg/apply gives a resource that
// already exists under a different name to the name it has always had, so
// adopting it is an empty preview (apply.RenameFrom). pkg/apply names an
// issuer's resources after the issuer; these resources were named
// otherwise when they were created:
//
//   - an identity environment CA's bootstrap certificate signing request,
//     named after the MOUNT, before any issuer existed to name it after;
//   - the identity roles of an environment PKI.LegacyRoleIssuers names: a
//     role that moved onto the root-signed CA as the same object keeps the
//     name of the issuer that first carried it;
//   - the restore role of the private domain's issuing CAs, named after
//     its namespace and mount (<namespace>-<mount>-role-<role>): the
//     issuing mount it sits on predates the issuer it signs with.
//
// Without an entry the preview would create the resource under the new
// name and DELETE it under the old one, removing the object both name.
func (d *Desired) LegacyResourceNames() map[string]string {
	pkiIn := &d.in.PKI
	renames := map[string]string{}

	for environment, issuer := range d.identityIssuers {
		renames[issuer+"-csr"] = d.IdentityBootstrapCSRName(environment)

		if old, ok := pkiIn.LegacyRoleIssuers[environment]; ok {
			for _, role := range d.identityRoles {
				renames[issuer+"-role-"+role] = old + "-role-" + role
			}
		}
	}

	for i := range d.Namespaces {
		namespace := &d.Namespaces[i]

		for j := range namespace.IssuingCAs {
			issuing := &namespace.IssuingCAs[j]
			if issuing.TrustDomain != pkiIn.Private {
				continue
			}

			for k := range issuing.Roles {
				if issuing.Roles[k].Name == pkiIn.RestoreRole {
					renames[issuing.IssuerName+"-role-"+pkiIn.RestoreRole] = namespace.Name + "-" + issuing.Mount + "-role-" + pkiIn.RestoreRole
				}
			}
		}
	}

	return renames
}
