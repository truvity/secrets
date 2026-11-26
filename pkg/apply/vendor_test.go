package apply_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/model"
)

const vendor = "vendor-a"

// withVendor is the model golden with a party's namespaces
// (testdata/vendors.yaml): vendor-a, and its dev child.
func withVendor(t *testing.T) *model.Desired {
	t.Helper()

	desired := example(t)

	raw, err := os.ReadFile("testdata/vendors.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &desired.Vendors))
	require.NoError(t, desired.Validate())

	return desired
}

// ofVendor is every registered resource of the party's namespaces: in this
// fixture, every one whose name carries the party's name.
func ofVendor(m *mocks) map[string]registered {
	out := map[string]registered{}

	for k, r := range keys(m) {
		if strings.Contains(r.Name, vendor) {
			out[k] = r
		}
	}

	return out
}

func vendorOptions(pick func(apply.Resource) bool, loginNamespace string) apply.Options {
	opts := selected(pick)
	opts.Login.Namespace = loginNamespace

	return opts
}

// The party's own stack and the server owner's half of the party's
// namespace together register every resource of it exactly once; the
// party's run registers nothing outside it, and no namespace, mount or
// auth mount at all.
func TestAVendorNamespaceIsSplitBetweenTheOwnerAndTheParty(t *testing.T) {
	whole, _, err := deploy(t, withVendor(t), options(), false)
	require.NoError(t, err)

	all := ofVendor(whole)
	require.NotEmpty(t, all)

	party, _, err := deploy(t, withVendor(t), vendorOptions(apply.SelectVendor(vendor), vendor), false)
	require.NoError(t, err)

	owner, _, err := deploy(t, withVendor(t), selected(apply.SelectVendorMounts(vendor)), false)
	require.NoError(t, err)

	got := map[string]int{}

	for k, r := range keys(party) {
		if r.Type == "pulumi:providers:vault" {
			continue
		}

		require.Contains(t, all, k, "the party's run registers %s, outside its namespace", k)
		assert.NotContains(t, []string{apply.TypeNamespace, apply.TypeMount, apply.TypeJWTAuthBackend, apply.TypeJWTAuthBackendRole, apply.TypePolicy}, r.Type,
			"the party's run registers %s", k)

		got[k]++
	}

	for k, r := range keys(owner) {
		if r.Type == "pulumi:providers:vault" {
			continue
		}

		require.Contains(t, all, k, "the owner's vendor run registers %s, outside the party's namespace", k)

		got[k]++
	}

	for k := range all {
		assert.Equal(t, 1, got[k], "%s is registered by %d of the two runs", k, got[k])
	}

	// The owner makes the namespaces and the empty mounts; the party
	// writes the intermediate's request and import and the issuing CA.
	assert.Contains(t, keys(owner), apply.TypeNamespace+" ns-vendor-a-dev")
	assert.Contains(t, keys(owner), apply.TypeMount+" vendor-a-pki-vendor-a-private")
	assert.Contains(t, keys(party), apply.TypePKIIntermediateCertRequest+" vendor-a-int-csr")
	assert.Contains(t, keys(party), apply.TypePKIRootSignIntermediate+" vendor-a-dev-signed")
}

// A party's run logged in at its namespace sends every namespace argument
// relative to it, and its provider logs in and works there.
func TestAVendorRunWorksInItsOwnNamespace(t *testing.T) {
	party, _, err := deploy(t, withVendor(t), vendorOptions(apply.SelectVendor(vendor), vendor), false)
	require.NoError(t, err)

	for _, r := range party.sorted() {
		switch {
		case r.Type == "pulumi:providers:vault":
			assert.Equal(t, vendor, r.Inputs["namespace"])
			jwt, _ := r.Inputs["authLoginJwt"].(map[string]any)
			assert.Equal(t, vendor, jwt["namespace"])
			assert.NotContains(t, jwt, "useRootNamespace")
		case strings.HasPrefix(r.Name, "vendor-a-dev-") && r.Type != apply.TypePKIRootSignIntermediate:
			assert.Equal(t, "dev", r.Inputs["namespace"], r.Name)
		case strings.HasPrefix(r.Name, "vendor-a-int-"), r.Type == apply.TypePKIRootSignIntermediate:
			assert.NotContains(t, r.Inputs, "namespace", r.Name)
		}
	}
}

// The server owner's run registers the party's namespaces protected, the
// child inside its parent and after it: a plan that drops one is refused
// as for any protected resource, and none is ever deleted by a plan.
func TestVendorNamespacesAreProtected(t *testing.T) {
	owner, _, err := deploy(t, withVendor(t), selected(apply.SelectVendorMounts(vendor)), false)
	require.NoError(t, err)

	parent, ok := owner.named("ns-vendor-a")
	require.True(t, ok)
	assert.True(t, parent.Protect)
	assert.Equal(t, vendor, parent.Inputs["path"])

	child, ok := owner.named("ns-vendor-a-dev")
	require.True(t, ok)
	assert.True(t, child.Protect)
	assert.Equal(t, vendor, child.Inputs["namespace"])
	assert.Equal(t, "dev", child.Inputs["path"])
	assert.Contains(t, child.DependsOn, "ns-vendor-a")

	// An environment's namespace keeps the protection it had.
	whole, _, err := deploy(t, withVendor(t), options(), false)
	require.NoError(t, err)

	env, ok := whole.named("ns-dev")
	require.True(t, ok)
	assert.False(t, env.Protect)
}

// In a party's namespace the mount's contents stay one unit of their own.
func TestASelectionThatSplitsAVendorMountsContentsIsRefused(t *testing.T) {
	_, _, err := deploy(t, withVendor(t), selected(func(r apply.Resource) bool {
		return apply.SelectVendor(vendor)(r) && r.Name != "vendor-a-int-import"
	}), false)
	require.ErrorContains(t, err, "in a party's namespace a mount's CA, issuers and configuration are applied together")
}

// A selection that ignores the namespace selects what it did: the model
// without parties registers exactly the golden, and a party's namespaces
// add only their own resources.
func TestAVendorAddsOnlyItsOwnResources(t *testing.T) {
	without, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	with, _, err := deploy(t, withVendor(t), options(), false)
	require.NoError(t, err)

	for k, r := range keys(with) {
		if strings.Contains(r.Name, vendor) {
			continue
		}

		assert.Contains(t, keys(without), k)
	}

	assert.Len(t, keys(with), len(keys(without))+len(ofVendor(with)))
}

func TestVendorNamespacesAreValidated(t *testing.T) {
	cases := map[string]struct {
		mutate func(*model.Desired)
		want   string
	}{
		"a child before its parent": {func(d *model.Desired) {
			d.Vendors[0], d.Vendors[1] = d.Vendors[1], d.Vendors[0]
		}, "vendor namespace vendor-a/dev is listed before its parent vendor-a"},
		"a party named like an environment": {func(d *model.Desired) {
			d.Vendors = d.Vendors[:1]
			d.Vendors[0].Name = "dev"
		}, "vendor namespace dev is also an environment's name"},
		"a deeper path": {func(d *model.Desired) {
			d.Vendors[1].Name = "vendor-a/dev/x"
		}, "is not a plain name"},
		"a project": {func(d *model.Desired) {
			d.Vendors[1].Projects = []model.ProjectNamespace{{Name: "x"}}
		}, "vendor namespace vendor-a/dev holds a project"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			desired := withVendor(t)
			c.mutate(desired)
			require.ErrorContains(t, desired.Validate(), c.want)
		})
	}
}

// A door's bound claims reach the role as OpenBAO's comma-separated list,
// matched as plain strings, and its token carries no default policy.
func TestARolesBoundClaimsAndNoDefaultPolicy(t *testing.T) {
	owner, _, err := deploy(t, withVendor(t), selected(apply.SelectVendorMounts(vendor)), false)
	require.NoError(t, err)

	role, ok := owner.named("vendor-a-role-jwt-admin-admin")
	require.True(t, ok)
	assert.Equal(t, map[string]any{"groups": "vendor-a-deployers,vendor-a-sres"}, role.Inputs["boundClaims"])
	assert.Equal(t, "string", role.Inputs["boundClaimsType"])
	assert.Equal(t, true, role.Inputs["tokenNoDefaultPolicy"])

	// A role with neither sends neither.
	whole, _, err := deploy(t, example(t), options(), false)
	require.NoError(t, err)

	for _, r := range whole.sorted() {
		if r.Type == apply.TypeJWTAuthBackendRole {
			assert.NotContains(t, r.Inputs, "boundClaims", r.Name)
			assert.NotContains(t, r.Inputs, "tokenNoDefaultPolicy", r.Name)
		}
	}
}

func TestABoundClaimValueWithACommaIsRefused(t *testing.T) {
	desired := withVendor(t)
	desired.Vendors[0].Auth[0].Roles[0].BoundClaims = map[string][]string{"groups": {"a,b"}}
	require.ErrorContains(t, desired.Validate(), `binds claim groups to "a,b": a value is non-empty and has no comma`)
}

// `acme/devel` and a namespace called `acme-devel` would share resource
// names.
func TestAVendorChildNamedLikeAnotherNamespaceIsRefused(t *testing.T) {
	desired := withVendor(t)
	desired.Vendors = append(desired.Vendors, model.Namespace{Name: "vendor-a-dev"})
	require.ErrorContains(t, desired.Validate(), "vendor namespace vendor-a-dev and namespace vendor-a/dev are both named vendor-a-dev in the apply")

	env := withVendor(t)
	env.Namespaces = append(env.Namespaces, model.Namespace{Name: "vendor-a-dev"})
	require.ErrorContains(t, env.Validate(), "are both named vendor-a-dev in the apply")
}

// A login below root makes no namespace, mount or auth mount, and applies
// nothing without a selection: the server owner's run logs in at root.
func TestALoginBelowRootIsRefusedWhatOnlyRootCanMake(t *testing.T) {
	_, _, err := deploy(t, withVendor(t), vendorOptions(nil, vendor), false)
	require.ErrorContains(t, err, "a login in namespace vendor-a needs a selection")

	m, _, err := deploy(t, withVendor(t), vendorOptions(apply.SelectVendorMounts(vendor), vendor), false)
	require.ErrorContains(t, err, "which only a login above it can make; the server owner's run logs in at root")
	assert.Empty(t, m.sorted(), "nothing is registered, the provider included")

	_, _, err = deploy(t, withVendor(t), vendorOptions(apply.SelectVendor(vendor), vendor), false)
	require.NoError(t, err)
}

// The selection checks name a party's child the way its resources are
// named: a group in `vendor-a/dev` split from its alias is refused.
func TestSelectionChecksUseTheChildsResourceNames(t *testing.T) {
	desired := withVendor(t)
	desired.Vendors[1].Groups = []model.Group{{Name: "team", Policies: []string{"pki-vendor-a"}, Doors: []string{"jwt-dev"}}}
	require.NoError(t, desired.Validate())

	m, _, err := deploy(t, desired, selected(func(r apply.Resource) bool {
		return r.Type != apply.TypeGroupAlias || !strings.HasPrefix(r.Name, "vendor-a-dev-")
	}), false)
	require.ErrorContains(t, err, "vendor-a-dev-alias-team")
	// Refused by the check before anything is registered, not halfway.
	assert.Empty(t, m.sorted(), "nothing is registered, the provider included")
}
