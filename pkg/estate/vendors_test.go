package estate_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
	"github.com/truvity/secrets/pkg/model"
)

func withVendorNamespace(t *testing.T, doors bool, clusters ...string) estate.Inputs {
	t.Helper()

	in := example.Inputs(t, "testdata/contract.yaml")
	if len(clusters) == 0 {
		clusters = []string{"alpha"}
	}

	example.WithVendorDomain(t, &in, clusters...)
	example.WithVendorNamespace(t, &in, doors)

	return in
}

func modelNamespace(t *testing.T, desired *model.Desired, name string) *model.Namespace {
	t.Helper()

	for _, namespace := range desired.Applied() {
		if namespace.Name == name {
			return namespace
		}
	}

	t.Fatalf("the model has no namespace %q", name)

	return nil
}

// A party's domain lives in its namespace: its intermediate in
// `vendor-a`, its alpha issuing CA, cert-manager login and policy in
// `vendor-a/alpha`, and nothing of it in root or in alpha.
func TestAVendorDomainLivesInItsNamespace(t *testing.T) {
	desired, err := estate.Build(withVendorNamespace(t, false))
	require.NoError(t, err)

	names := []string{}
	for _, namespace := range desired.Vendors {
		names = append(names, namespace.Name)
	}

	assert.Equal(t, []string{"vendor-a", "vendor-a/alpha"}, names)

	for _, ca := range issuingCAsOf(desired, "alpha") {
		assert.NotEqual(t, vendor, ca.TrustDomain, "alpha keeps a vendor issuing CA")
	}

	m, err := desired.Model()
	require.NoError(t, err)

	for _, mount := range m.Root.PKI {
		assert.NotContains(t, mount.Path, "vendor-a", "root holds %s", mount.Path)
	}

	party := modelNamespace(t, m, "vendor-a")
	require.Len(t, party.PKI, 1)
	assert.True(t, party.PKI[0].Issuers[0].External, "the domain intermediate is signed by the root, outside the server")

	child := modelNamespace(t, m, "vendor-a/alpha")
	require.Len(t, child.PKI, 1)
	assert.Equal(t, &model.IssuerRef{Namespace: "vendor-a", Mount: party.PKI[0].Path, Issuer: party.PKI[0].Issuers[0].Name},
		child.PKI[0].Issuers[0].SignedBy)

	require.Len(t, child.Auth, 1, "the cluster's mount, in the party's namespace")
	require.Len(t, child.Auth[0].Roles, 1)
	assert.Equal(t, "vendor-a-ca", child.Auth[0].Roles[0].Name)
	require.Len(t, child.Policies, 1)
	assert.Equal(t, child.PKI[0].Path+"/sign/"+child.PKI[0].Roles[0].Name, child.Policies[0].Rules[0].Path)

	for _, namespace := range m.Namespaces {
		for _, mount := range namespace.PKI {
			assert.NotContains(t, mount.Path, "vendor-a", "%s holds %s", namespace.Name, mount.Path)
		}
	}
}

// Each party namespace has its own door (PKI.VendorDoors): in
// `<vendor>/<env>` admitting that environment's groups to that
// environment's PKI mounts, in `<vendor>` the intermediate's environment's
// groups to the intermediate mount; no default policy, nothing of sys/.
func TestAVendorNamespacesDoors(t *testing.T) {
	desired, err := estate.Build(withVendorNamespace(t, true))
	require.NoError(t, err)

	m, err := desired.Model()
	require.NoError(t, err)

	for name, env := range map[string]string{"vendor-a": "beta", "vendor-a/alpha": "alpha"} {
		namespace := modelNamespace(t, m, name)

		at := slices.IndexFunc(namespace.Auth, func(a model.JWTMount) bool { return a.Path == "jwt-pki" })
		require.GreaterOrEqual(t, at, 0, "%s has no door", name)

		door := namespace.Auth[at]
		assert.Equal(t, desired.Inputs().Roster.Issuer, door.DiscoveryURL, name)
		require.Len(t, door.Roles, 1)

		role := door.Roles[0]
		assert.Equal(t, "pki-admin", role.Name)
		assert.Equal(t, []string{env + ":openbao:vendor-a"}, role.BoundAudiences, name)
		assert.Equal(t, "sub", role.UserClaim)
		assert.Equal(t, "groups", role.GroupsClaim)
		assert.Equal(t, map[string][]string{"groups": {env + ":vendor-a:pki:internal:deployer", env + ":vendor-a:pki:internal:sre"}}, role.BoundClaims, name)
		assert.Equal(t, []string{"pki-admin"}, role.Policies)
		assert.True(t, role.NoDefaultPolicy)
		assert.Equal(t, "15m", role.TTL)

		policy := namespace.Policies[slices.IndexFunc(namespace.Policies, func(p model.Policy) bool { return p.Name == "pki-admin" })]
		require.Len(t, namespace.PKI, 1)
		mount := namespace.PKI[0].Path

		for _, rule := range policy.Rules {
			assert.True(t, strings.HasPrefix(rule.Path, mount+"/"), "%s's door names %s, outside its own PKI mount", name, rule.Path)

			for _, forbidden := range []string{"/issue/", "/sign/", "exported", "/root/generate", "/keys/generate", "/keys/import"} {
				assert.NotContains(t, rule.Path, forbidden, "%s's door names %s", name, rule.Path)
			}
		}

		paths := map[string]bool{}
		for _, rule := range policy.Rules {
			paths[rule.Path] = true
		}

		assert.True(t, paths[mount+"/intermediate/generate/internal"], "%s: the request", name)
		assert.True(t, paths[mount+"/intermediate/set-signed"], "%s: the import", name)
		assert.Equal(t, name == "vendor-a", paths[mount+"/root/sign-intermediate"], "%s: signing the issuing CAs is the intermediate's alone", name)
	}

	without, err := estate.Build(withVendorNamespace(t, false))
	require.NoError(t, err)

	plain, err := without.Model()
	require.NoError(t, err)
	assert.Empty(t, modelNamespace(t, plain, "vendor-a").Auth, "no doors declared, no door")
}

// One environment's door cannot reach another environment's namespace, the
// party's intermediate, root or sys/: every path it names is one of its
// own namespace's PKI mounts.
func TestAnEnvironmentsDoorCannotReachAnother(t *testing.T) {
	desired, err := estate.Build(withVendorNamespace(t, true, "alpha", "beta"))
	require.NoError(t, err)

	m, err := desired.Model()
	require.NoError(t, err)

	alpha := modelNamespace(t, m, "vendor-a/alpha")
	beta := modelNamespace(t, m, "vendor-a/beta")
	party := modelNamespace(t, m, "vendor-a")

	for _, policy := range alpha.Policies {
		if policy.Name != "pki-admin" {
			continue
		}

		for _, rule := range policy.Rules {
			assert.True(t, slices.ContainsFunc(alpha.PKI, func(m model.PKIMount) bool { return strings.HasPrefix(rule.Path, m.Path+"/") }),
				"alpha's door names %s", rule.Path)

			for _, other := range []string{"beta/", "vendor-a/", "sys/", "../", "/"} {
				assert.False(t, strings.HasPrefix(rule.Path, other), "alpha's door names %s", rule.Path)
			}
		}
	}

	// The intermediate's door names the intermediate mount and no child.
	for _, policy := range party.Policies {
		for _, rule := range policy.Rules {
			assert.False(t, strings.HasPrefix(rule.Path, "alpha/") || strings.HasPrefix(rule.Path, "beta/"),
				"the intermediate's door names %s", rule.Path)
		}
	}

	// Each environment's door binds its own environment's audience.
	for _, namespace := range []*model.Namespace{alpha, beta} {
		_, env, _ := strings.Cut(namespace.Name, "/")
		for _, door := range namespace.Auth {
			if door.Path == "jwt-pki" {
				assert.Equal(t, []string{env + ":openbao:vendor-a"}, door.Roles[0].BoundAudiences)
			}
		}
	}
}

func TestCredentialRolesAreRefusedInAPartyNamespace(t *testing.T) {
	in := withVendorNamespace(t, false)
	vendorDomain := in.PKI.Contract.DNSTrustDomain(vendor)
	vendorDomain.CredentialRoles = slices.Clone(in.PKI.Contract.DNSTrustDomain(in.PKI.Private).CredentialRoles)
	require.NotEmpty(t, vendorDomain.CredentialRoles, "the example's private domain declares a credential role")
	require.NoError(t, in.PKI.Contract.Validate())

	wantBuildError(t, in, "declares credential roles; a party's namespace signs no person's request")
}

// The estate's model splits as the server owner's and the party's runs
// would: every resource of the party's namespaces exactly once, the party's
// only inside its PKI mounts.
func TestAVendorEstateModelSplits(t *testing.T) {
	desired, err := estate.Build(withVendorNamespace(t, true))
	require.NoError(t, err)

	m, err := desired.Model()
	require.NoError(t, err)

	party, owner := apply.SelectVendor("vendor-a"), apply.SelectVendorMounts("vendor-a")

	for _, r := range []apply.Resource{
		{Type: apply.TypeNamespace, Namespace: "vendor-a"},
		{Type: apply.TypeMount, Namespace: "vendor-a/alpha"},
		{Type: apply.TypeJWTAuthBackendRole, Namespace: "vendor-a/alpha"},
		{Type: apply.TypePKIIntermediateCertRequest, Namespace: "vendor-a"},
		{Type: apply.TypePKIRole, Namespace: "vendor-a/alpha"},
	} {
		assert.NotEqual(t, party(r), owner(r), "%v is selected by both or neither", r)
	}

	for _, r := range []apply.Resource{
		{Type: apply.TypePKIRole, Namespace: "alpha"},
		{Type: apply.TypePKIRole, Namespace: ""},
		{Type: apply.TypePKIRole, Namespace: "vendor-b/alpha"},
		{Type: apply.TypePKIRole, Namespace: "vendor-ab"},
	} {
		assert.False(t, party(r) || owner(r), "%v is outside the party's namespace", r)
	}

	assert.True(t, slices.ContainsFunc(m.Vendors, func(n model.Namespace) bool { return n.Name == "vendor-a/alpha" }))
}

func TestAVendorIssuerNamesItsNamespace(t *testing.T) {
	in := withVendorNamespace(t, false)

	view, err := in.PKI.Issuer(vendor, in.PKI.Contract.DNSTrustDomain(vendor).Roles[0].Name)
	require.NoError(t, err)
	assert.Equal(t, "vendor-a", view.Namespace)
	assert.Equal(t, "vendor-a/alpha", view.ServerNamespace("alpha"))

	private, err := in.PKI.Issuer(in.PKI.Private, in.PKI.Contract.DNSTrustDomain(in.PKI.Private).Roles[0].Name)
	require.NoError(t, err)
	assert.Empty(t, private.Namespace)
	assert.Equal(t, "alpha", private.ServerNamespace("alpha"))
}

func TestTheEstatesOwnDomainsStayInRoot(t *testing.T) {
	in := withVendorDomain(t)
	in.PKI.Contract.DNSTrustDomain(in.PKI.Private).Namespace = "vendor-a"

	wantBuildError(t, in, "is the estate's own (PKI.Private, Origin or Identity) and stays in root")
}

func TestAVendorNamespaceNamedLikeAnEnvironmentIsRefused(t *testing.T) {
	in := withVendorDomain(t)
	in.PKI.Contract.DNSTrustDomain(vendor).Namespace = "alpha"

	_, err := estate.Build(in)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), `namespace "alpha" is also an environment's name`), err.Error())
}

func TestTheIntermediatesDoorNeedsAKnownEnvironment(t *testing.T) {
	in := withVendorNamespace(t, true)
	in.PKI.VendorDoors.IntermediateEnvironment = "nope"

	desired, err := estate.Build(in)
	require.NoError(t, err)

	_, err = desired.Model()
	require.ErrorContains(t, err, `PKI.VendorDoors.IntermediateEnvironment "nope" is no cluster of the estate`)
}
