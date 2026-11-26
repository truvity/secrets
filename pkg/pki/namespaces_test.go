package pki

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/model"
)

// A domain with a namespace of its own derives into it: its intermediate in
// `<namespace>`, each issuing CA in `<namespace>/<environment>`, signed by
// the intermediate there. Every other domain derives as before.
func TestADomainDerivesIntoItsNamespace(t *testing.T) {
	plain, err := withVendorDomain(t).Derive(vendorEnvironments())
	require.NoError(t, err)

	contract := withVendorDomain(t)
	contract.DNSTrustDomain("vendor-a").Namespace = "vendor-a"
	require.NoError(t, contract.Validate())

	derivation, err := contract.Derive(vendorEnvironments())
	require.NoError(t, err)

	for i := range derivation.Domains {
		domain := &derivation.Domains[i]
		if domain.Domain != "vendor-a" {
			assert.Equal(t, plain.Domains[i], *domain)

			continue
		}

		assert.Equal(t, "vendor-a", domain.NamespacePath())
	}

	for key, authority := range issuingByKey(derivation) {
		if key.domain != "vendor-a" {
			assert.Equal(t, issuingByKey(plain)[key], authority)

			continue
		}

		assert.Equal(t, "vendor-a/"+key.environment, authority.NamespacePath())
		assert.Equal(t, "vendor-a", authority.SignedBy.Namespace)
	}

	assert.Empty(t, mountsNamed(derivation.RootMounts(), "pki-vendor-a"), "root holds no vendor mount")
	assert.Len(t, derivation.DomainMounts("vendor-a"), 1)

	dev, err := derivation.EnvironmentMounts("dev")
	require.NoError(t, err)
	assert.Empty(t, mountsNamed(dev, "pki-vendor-a"), "dev holds no vendor mount")

	vendorDev, err := derivation.EnvironmentMounts("vendor-a/dev")
	require.NoError(t, err)
	assert.Len(t, vendorDev, 1)
}

func TestApplyNeedsTheVendorNamespaces(t *testing.T) {
	contract := withVendorDomain(t)
	contract.DNSTrustDomain("vendor-a").Namespace = "vendor-a"
	require.NoError(t, contract.Validate())

	derivation, err := contract.Derive(vendorEnvironments())
	require.NoError(t, err)

	desired := &model.Desired{Namespaces: []model.Namespace{{Name: "dev"}, {Name: "prod"}}}
	require.ErrorContains(t, derivation.Apply(desired), `namespace "vendor-a" holds domain intermediates but the desired state has no such party namespace`)

	desired.Vendors = []model.Namespace{{Name: "vendor-a"}, {Name: "vendor-a/dev"}, {Name: "vendor-a/prod"}}
	require.NoError(t, derivation.Apply(desired))
	assert.Len(t, desired.Vendors[0].PKI, 1)
	assert.Len(t, desired.Vendors[1].PKI, 1)
}

func TestADomainNamespaceIsRefusedWhen(t *testing.T) {
	bad := withVendorDomain(t)
	bad.DNSTrustDomain("vendor-a").Namespace = "vendor-a/dev"
	wantValidateError(t, bad, `trustDomains.dns[vendor-a].namespace "vendor-a/dev" is not one lower-case label`)

	clash := withVendorDomain(t)
	clash.DNSTrustDomain("vendor-a").Namespace = "dev"
	require.NoError(t, clash.Validate())
	wantDeriveError(t, clash, vendorEnvironments(), DeriveOptions{}, `trust domain vendor-a's namespace "dev" is also an environment's name`)
}

func TestAPendingDomainKeepsItsNamespace(t *testing.T) {
	contract := withVendorDomain(t)
	contract.DNSTrustDomain("vendor-a").Namespace = "vendor-a"
	require.NoError(t, contract.Validate())

	derivation, err := contract.DeriveWith(vendorEnvironments(), DeriveOptions{PendingDomains: []string{"vendor-a"}})
	require.NoError(t, err)
	require.Len(t, derivation.Pending, 1)
	assert.Equal(t, "vendor-a", derivation.Pending[0].Namespace)
}

func mountsNamed(mounts []model.PKIMount, path string) []model.PKIMount {
	var out []model.PKIMount

	for i := range mounts {
		if mounts[i].Path == path {
			out = append(out, mounts[i])
		}
	}

	return out
}
