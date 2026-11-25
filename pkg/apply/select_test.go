package apply_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/apply"
)

// leaves are the kinds a consumer's stack may hold apart from the mounts
// and namespaces they live in: what one tenant's grants are made of.
var leaves = map[string]bool{
	apply.TypePolicy:             true,
	apply.TypeGroup:              true,
	apply.TypeGroupAlias:         true,
	apply.TypeJWTAuthBackendRole: true,
	apply.TypeAWSAuthBackendRole: true,
	apply.TypePKIRole:            true,
	apply.TypeSSHRole:            true,
}

const providerKey = "pulumi:providers:vault openbao"

func key(r registered) string { return r.Type + " " + r.Name }

func keys(m *mocks) map[string]registered {
	out := map[string]registered{}
	for _, r := range m.sorted() {
		out[key(r)] = r
	}

	return out
}

func selected(pick func(apply.Resource) bool) apply.Options {
	opts := options()
	opts.Select = pick

	return opts
}

// The model applied as two stacks, the platform's (everything but the
// leaves) and a tenant's (the leaves), registers every resource of the
// whole exactly once, the provider in both, with the same inputs except
// what the tenant reads from the server.
func TestASplitModelRegistersEachResourceOnce(t *testing.T) {
	whole, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	platform, _, err := deploy(t, example(t), selected(func(r apply.Resource) bool { return !leaves[r.Type] }), false)
	require.NoError(t, err)

	tenant, _, err := deploy(t, example(t), selected(func(r apply.Resource) bool { return leaves[r.Type] }), false)
	require.NoError(t, err)

	all, mine, theirs := keys(whole), keys(platform), keys(tenant)

	for k := range all {
		_, inPlatform := mine[k]
		_, inTenant := theirs[k]

		if k == providerKey {
			assert.True(t, inPlatform && inTenant, "the provider is in every stack")

			continue
		}

		assert.True(t, inPlatform != inTenant, "%s is in exactly one stack (platform %v, tenant %v)", k, inPlatform, inTenant)
	}

	for k := range mine {
		assert.Contains(t, all, k, "the platform registers nothing the whole does not")
	}

	for k, r := range theirs {
		assert.Contains(t, all, k, "the tenant registers nothing the whole does not")

		for _, dep := range r.DependsOn {
			found := false

			for other := range theirs {
				if strings.HasSuffix(other, " "+dep) {
					found = true
				}
			}

			assert.True(t, found, "%s waits for %s, which another stack owns", k, dep)
		}

		want := fmt.Sprint(all[k].Inputs)
		if strings.Contains(want, "#accessor") {
			assert.Contains(t, fmt.Sprint(r.Inputs), "lookup:", "%s reads the accessor from the server", k)

			continue
		}

		if k != providerKey {
			assert.Equal(t, all[k].Inputs, r.Inputs, "%s has the inputs it has in the whole", k)
		}
	}

	assert.Empty(t, whole.calls, "the whole reads nothing from the server")
	assert.Empty(t, platform.calls, "the owner of the auth mounts reads nothing from the server")
	assert.NotEmpty(t, tenant.calls, "a stack without the auth mounts reads their accessors")
}

// An accessor is read only where something registered needs it, and once
// per mount.
func TestAnAccessorIsReadOncePerMountAndOnlyWhenNeeded(t *testing.T) {
	m, _, err := deploy(t, example(t), selected(func(r apply.Resource) bool {
		return r.Type == apply.TypePolicy
	}), false)
	require.NoError(t, err)
	assert.Empty(t, m.calls, "policies need no accessor")

	m, _, err = deploy(t, example(t), selected(func(r apply.Resource) bool { return leaves[r.Type] }), false)
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, call := range m.calls {
		assert.False(t, seen[call], "%s is read twice", call)
		seen[call] = true
	}
}

// A selection that cuts a unit is refused before the run registers it.
func TestASelectionThatSplitsAUnitIsRefused(t *testing.T) {
	for name, apart := range map[string]string{
		"a group without its alias":       apply.TypeGroupAlias,
		"a PKI mount without its issuers": apply.TypePKIIssuer,
		"a PKI mount without its config":  apply.TypePKIAutoTidy,
		"a root without its mount":        apply.TypePKIRootCert,
		"an SSH mount without its CA":     apply.TypeSSHCA,
		"an AWS mount without its client": apply.TypeAWSAuthBackendClient,
		"a KV mount without its canary":   apply.TypeKVSecret,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := deploy(t, example(t), selected(func(r apply.Resource) bool { return r.Type != apart }), false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apply: select")
			assert.Contains(t, err.Error(), apart)
		})
	}
}

// Selecting everything is the whole, byte for byte.
func TestSelectingEverythingIsTheWhole(t *testing.T) {
	whole, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	every, _, err := deploy(t, example(t), selected(func(apply.Resource) bool { return true }), false)
	require.NoError(t, err)

	assert.Equal(t, whole.sorted(), every.sorted())
	assert.Empty(t, every.calls)
}

// A unit split in the last namespace is refused before anything at all is
// registered -- not after the namespaces before it, which under `up` would
// be a partial apply.
func TestASplitUnitLateInTheModelRegistersNothing(t *testing.T) {
	m, _, err := deploy(t, example(t), selected(func(r apply.Resource) bool {
		return r != apply.Resource{Type: apply.TypeKVSecret, Name: "prod-restore-canary"}
	}), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prod-restore-canary")
	assert.Empty(t, m.sorted(), "nothing is registered, the provider included")
}

// An auth mount another stack owns and the server does not have yet is an
// error that names it and says which stack goes first.
func TestAMissingAuthMountNamesItsOwner(t *testing.T) {
	_, _, err := deployWith(t, &mocks{missingAuth: "oidc"}, example(t),
		selected(func(r apply.Resource) bool { return leaves[r.Type] }), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth mount oidc, which another stack owns")
	assert.Contains(t, err.Error(), "apply the stack that owns oidc first")
}
