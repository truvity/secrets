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

func withVendorNamespace(t *testing.T, admins ...string) estate.Inputs {
	t.Helper()

	in := withVendorDomain(t)
	example.WithVendorNamespace(t, &in, admins...)

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
	desired, err := estate.Build(withVendorNamespace(t))
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

// The party namespace's admin login is the roster's door, each admin group
// granted the party's PKI mounts and nothing above them.
func TestAVendorNamespacesAdminLogin(t *testing.T) {
	desired, err := estate.Build(withVendorNamespace(t, "vendor-a-admins"))
	require.NoError(t, err)

	m, err := desired.Model()
	require.NoError(t, err)

	party := modelNamespace(t, m, "vendor-a")
	require.Len(t, party.Groups, 1)
	assert.Equal(t, "vendor-a-admins", party.Groups[0].Name)
	require.Len(t, party.Policies, 1)

	paths := []string{}
	for _, rule := range party.Policies[0].Rules {
		paths = append(paths, rule.Path)
		assert.NotContains(t, rule.Path, "sys/")
	}

	child := modelNamespace(t, m, "vendor-a/alpha")
	assert.ElementsMatch(t, []string{party.PKI[0].Path + "/*", "alpha/" + child.PKI[0].Path + "/*"}, paths)

	without, err := estate.Build(withVendorNamespace(t))
	require.NoError(t, err)

	plain, err := without.Model()
	require.NoError(t, err)
	assert.Empty(t, modelNamespace(t, plain, "vendor-a").Auth, "no admin groups, no login")
}

// The estate's model splits as the server owner's and the party's runs
// would: every resource of the party's namespaces exactly once, the party's
// only inside its PKI mounts.
func TestAVendorEstateModelSplits(t *testing.T) {
	desired, err := estate.Build(withVendorNamespace(t, "vendor-a-admins"))
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
	in := withVendorNamespace(t)

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
