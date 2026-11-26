package estate

import (
	"fmt"
	"slices"
	"strings"

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

	vendors, err := d.vendorNamespaces()
	if err != nil {
		return nil, err
	}

	out.Vendors = vendors

	// The contract's authorities are the server's PKI: the domain
	// intermediates in root, each environment's issuing CAs in its
	// namespace -- or a party's domains in the party's namespaces. The
	// library derives them, Apply places them.
	if err := d.derivation.Apply(&out); err != nil {
		return nil, err
	}

	if err := d.vendorDoors(&out); err != nil {
		return nil, err
	}

	if err := out.Validate(); err != nil {
		return nil, err
	}

	return &out, nil
}

// vendorNamespaces are the parties' namespaces as the model holds them,
// before the PKI is placed in them: each `<vendor>/<env>` holds the
// environment's cluster mount, carrying the cert-manager logins of the
// party's issuing CAs there and their policies. The mount trusts the
// cluster's own issuer, as the environment's does.
func (d *Desired) vendorNamespaces() ([]model.Namespace, error) {
	out := make([]model.Namespace, 0, len(d.Vendors))

	for i := range d.Vendors {
		view := &d.Vendors[i]
		namespace := model.Namespace{Name: view.Name}

		if _, env, nested := strings.Cut(view.Name, "/"); nested {
			at := slices.IndexFunc(d.in.Clusters, func(c Cluster) bool { return c.Name == env })
			if at < 0 {
				return nil, fmt.Errorf("estate: party namespace %s has no cluster %s", view.Name, env)
			}

			trust := clusterTrust(d.in, d.in.Names.ClusterMountPrefix+env, d.in.Clusters[at].Issuer)
			trust.Workloads = slices.Clone(d.vendorLogins[view.Name])

			mount, policies, err := trust.Model()
			if err != nil {
				return nil, fmt.Errorf("estate: party namespace %s: %w", view.Name, err)
			}

			namespace.Auth = []model.JWTMount{mount}
			namespace.Policies = policies
		}

		out = append(out, namespace)
	}

	return out, nil
}

// vendorDoors gives each party namespace its own login (PKI.VendorDoors):
// in `<vendor>/<env>` a door admitting that environment's groups to that
// environment's PKI mounts, and in `<vendor>` a door admitting the
// intermediate's environment's groups to the intermediate mount. A door's
// policy names the PKI mounts of its own namespace and nothing else --
// nothing of `sys/`, nothing of another environment.
func (d *Desired) vendorDoors(out *model.Desired) error {
	doors := d.in.PKI.VendorDoors
	if doors == nil {
		return nil
	}

	if err := doors.validate(); err != nil {
		return err
	}

	if !slices.ContainsFunc(d.in.Clusters, func(c Cluster) bool { return c.Name == doors.IntermediateEnvironment }) {
		return fmt.Errorf("estate: PKI.VendorDoors.IntermediateEnvironment %q is no cluster of the estate", doors.IntermediateEnvironment)
	}

	for i := range out.Vendors {
		namespace := &out.Vendors[i]

		vendor, environment, nested := strings.Cut(namespace.Name, "/")
		if !nested {
			environment = doors.IntermediateEnvironment
		}

		for j := range namespace.Auth {
			if namespace.Auth[j].Path == doors.Mount {
				return fmt.Errorf("estate: PKI.VendorDoors.Mount %s is also %s's cluster mount", doors.Mount, namespace.Name)
			}
		}

		var rules []model.Rule
		for j := range namespace.PKI {
			rules = append(rules, doorRules(namespace.PKI[j].Path, !nested)...)
		}

		groups := make([]string, 0, len(doors.Groups))
		for _, group := range doors.Groups {
			groups = append(groups, doors.expand(group, environment, vendor))
		}

		namespace.Auth = append(namespace.Auth, model.JWTMount{
			Path:         doors.Mount,
			Description:  "the roster's tokens for " + vendor + "'s own stack, " + environment + "'s groups",
			DiscoveryURL: d.in.Roster.Issuer,
			Roles: []model.Role{{
				Name:            doors.Role,
				BoundAudiences:  []string{doors.expand(doors.Audience, environment, vendor)},
				UserClaim:       doors.UserClaim,
				GroupsClaim:     doors.GroupsClaim,
				BoundClaims:     map[string][]string{doors.GroupsClaim: groups},
				Policies:        []string{doors.Role},
				NoDefaultPolicy: true,
				TTL:             doors.TTL,
			}},
		})
		namespace.Policies = append(namespace.Policies, model.Policy{Name: doors.Role, Rules: rules})
	}

	return nil
}

// doorRules are what a party's own stack does in one PKI mount, and no
// more: generate a key that never leaves the mount and its request, import
// the signed certificate, name the issuer and the key, configure the
// mount, and manage the roles; on the intermediate's mount also sign the
// party's issuing CAs. Never issue or sign a leaf (cert-manager has its own
// login for that), never generate or import an exportable key.
func doorRules(mount string, intermediate bool) []model.Rule {
	write := []string{model.CapCreate, model.CapUpdate}
	read := []string{model.CapRead, model.CapList}
	manage := []string{model.CapCreate, model.CapRead, model.CapUpdate, model.CapDelete, model.CapList}

	rules := []model.Rule{
		{Path: mount + "/intermediate/generate/internal", Capabilities: write},
		{Path: mount + "/intermediate/set-signed", Capabilities: write},
		{Path: mount + "/issuer/*", Capabilities: []string{model.CapRead, model.CapUpdate}},
		{Path: mount + "/issuers", Capabilities: read},
		{Path: mount + "/key/*", Capabilities: []string{model.CapRead, model.CapUpdate}},
		{Path: mount + "/keys", Capabilities: read},
		{Path: mount + "/config/*", Capabilities: []string{model.CapRead, model.CapUpdate}},
		{Path: mount + "/roles/*", Capabilities: manage},
		{Path: mount + "/roles", Capabilities: read},
		{Path: mount + "/cert/*", Capabilities: read},
	}

	if intermediate {
		rules = append(rules, model.Rule{Path: mount + "/root/sign-intermediate", Capabilities: write})
	}

	return rules
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
