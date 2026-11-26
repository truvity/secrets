package estate_test

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
	"github.com/truvity/secrets/pkg/model"
)

// recordingChains answers every chain and records which root generation
// each was asked under.
type recordingChains struct{ asked map[string]string }

func (r *recordingChains) DomainIntermediate(trustDomain, generation string) (estate.Chain, error) {
	r.asked["domain "+trustDomain] = generation

	return estate.Chain{PEM: "chain"}, nil
}

func (r *recordingChains) EnvironmentCA(environment, _, generation string) (estate.Chain, error) {
	r.asked["environment "+environment] = generation

	return estate.Chain{PEM: "chain"}, nil
}

func withVendorRoot(t *testing.T) estate.Inputs {
	t.Helper()

	in := withVendorDomain(t)
	example.WithVendorRoot(t, &in)

	return in
}

// With one root the view's Roots is empty, so a single-root estate's
// desired state is what it always was.
func TestOneRootHasNoFurtherRoots(t *testing.T) {
	desired, err := estate.Build(withVendorDomain(t))
	require.NoError(t, err)
	assert.Empty(t, desired.PKI.Roots)
}

func TestAVendorRootIsInTheView(t *testing.T) {
	single, err := estate.Build(withVendorDomain(t))
	require.NoError(t, err)

	desired, err := estate.Build(withVendorRoot(t))
	require.NoError(t, err)

	assert.Equal(t, single.PKI.Root, desired.PKI.Root, "Root stays the private domain's root")
	require.Len(t, desired.PKI.Roots, 1)
	assert.Equal(t, example.VendorRoot, desired.PKI.Roots[0].GenerationID)
	assert.Equal(t, "Vendor A", desired.PKI.Roots[0].Organization)

	at := slices.IndexFunc(desired.PKI.Domains, func(d estate.DomainAuthority) bool { return d.TrustDomain == vendor })
	require.GreaterOrEqual(t, at, 0)
	assert.Contains(t, desired.PKI.Domains[at].ArtifactPath, example.VendorRoot+"-intermediate-"+vendor)

	for _, ca := range issuingCAsOf(desired, "alpha") {
		if ca.TrustDomain == vendor {
			assert.Equal(t, "Vendor A", ca.Organization)
		}
	}
}

// Every chain is loaded under its own domain's root, never another's.
func TestChainsLoadUnderEachDomainsOwnRoot(t *testing.T) {
	in := withVendorRoot(t)

	desired, err := estate.Build(in)
	require.NoError(t, err)

	chains := &recordingChains{asked: map[string]string{}}
	signed := desired.SignedChain(context.Background(), nil, chains)

	for _, domain := range desired.PKI.Domains {
		_, err := signed(model.IssuerRef{Mount: domain.Mount, Issuer: domain.IssuerName})
		require.NoError(t, err)
	}

	estateRoot := in.PKI.Contract.Generations[0].ID

	for _, domain := range desired.PKI.Domains {
		want := estateRoot
		if domain.TrustDomain == vendor {
			want = example.VendorRoot
		}

		assert.Equal(t, want, chains.asked["domain "+domain.TrustDomain], "domain %s", domain.TrustDomain)
	}
}

func TestActiveGenerationWithSeveralActiveRootsIsRefused(t *testing.T) {
	in := withVendorRoot(t)

	_, err := estate.ActiveGeneration(in.PKI.Contract)
	require.ErrorContains(t, err, "the PKI contract has 2 active root generations")

	one := withVendorDomain(t)
	generation, err := estate.ActiveGeneration(one.PKI.Contract)
	require.NoError(t, err)
	assert.Equal(t, one.PKI.Contract.Generations[0].ID, generation.ID)
}

// A pending vendor domain is checked against its own root's artifact.
func TestAPendingDomainIsCheckedUnderItsOwnRoot(t *testing.T) {
	in := withVendorRoot(t)
	in.PKI.PendingDomains = []string{vendor}

	desired, err := estate.Build(in)
	require.NoError(t, err)
	require.Len(t, desired.PKI.Pending, 1)
	assert.Equal(t, "Vendor A", desired.PKI.Pending[0].Organization)
}
