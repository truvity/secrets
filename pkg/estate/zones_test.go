package estate_test

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
	"github.com/truvity/secrets/pkg/pki"
)

const vendor = example.VendorDomain

// withVendorDomain is the example estate with a further DNS trust domain
// reaching alpha only.
func withVendorDomain(t *testing.T) estate.Inputs {
	t.Helper()

	in := example.Inputs(t, "testdata/contract.yaml")
	example.WithVendorDomain(t, &in, "alpha")

	return in
}

func clusterAt(t *testing.T, in estate.Inputs, name string) int {
	t.Helper()

	at := slices.IndexFunc(in.Clusters, func(c estate.Cluster) bool { return c.Name == name })
	if at < 0 {
		t.Fatalf("no cluster %s", name)
	}

	return at
}

func issuingCAsOf(desired estate.Desired, namespace string) []estate.IssuingCA {
	for i := range desired.Namespaces {
		if desired.Namespaces[i].Name == namespace {
			return desired.Namespaces[i].IssuingCAs
		}
	}

	return nil
}

func wantBuildError(t *testing.T, in estate.Inputs, substring string) {
	t.Helper()

	_, err := estate.Build(in)
	if err == nil || !strings.Contains(err.Error(), substring) {
		t.Errorf("Build() = %v, want an error containing %q", err, substring)
	}
}

// A further DNS trust domain takes its zone from Cluster.Zones, reaches the
// clusters it lists and no other, and leaves every issuing CA of the
// domains authored before as it was.
func TestFurtherDNSDomainTakesItsOwnZone(t *testing.T) {
	was, err := estate.Build(example.Inputs(t, "testdata/contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	desired, err := estate.Build(withVendorDomain(t))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	for i := range desired.Namespaces {
		name := desired.Namespaces[i].Name

		var mine, others []estate.IssuingCA

		for _, ca := range desired.Namespaces[i].IssuingCAs {
			if ca.TrustDomain == vendor {
				mine = append(mine, ca)
			} else {
				others = append(others, ca)
			}
		}

		if !reflect.DeepEqual(others, issuingCAsOf(was, name)) {
			t.Errorf("%s: the issuing CAs of the domains authored before changed", name)
		}

		switch {
		case name == "alpha" && len(mine) != 1:
			t.Errorf("alpha vendor-a issuing CAs = %d, want 1", len(mine))
		case name == "alpha":
			if mine[0].Mount != "pki-vendor-a" || !slices.Equal(mine[0].PermittedDomains, []string{"alpha.vendor-a.example"}) {
				t.Errorf("alpha vendor-a = mount %q constrained to %v", mine[0].Mount, mine[0].PermittedDomains)
			}
		case len(mine) != 0:
			t.Errorf("%s is not in vendor-a's environments and has its issuing CA", name)
		}
	}

	if !slices.ContainsFunc(desired.PKI.Domains, func(d estate.DomainAuthority) bool { return d.TrustDomain == vendor }) {
		t.Error("no vendor-a intermediate in the root namespace")
	}
}

// A zone is required where the domain reaches, and refused where nothing
// reads it.
func TestFurtherDNSDomainZoneRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, in *estate.Inputs)
		want   string
	}{
		"a reached cluster with no zone": {func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "alpha")].Zones = nil
		}, "cluster alpha has no vendor-a zone"},
		"a zone where the domain does not reach": {func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "beta")].Zones = map[string]string{vendor: "beta.vendor-a.example"}
		}, `cluster beta has a zone for "vendor-a"`},
		"a zone for the private domain": {func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "alpha")].Zones["private"] = "alpha.example.private"
		}, `cluster alpha has a zone for "private"`},
		"a zone for no domain": {func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "alpha")].Zones["vendor-b"] = "alpha.vendor-b.example"
		}, `cluster alpha has a zone for "vendor-b"`},
		"a zone outside the domain": {func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "alpha")].Zones[vendor] = "alpha.example.private"
		}, "is not vendor-a.example or under it"},
	} {
		t.Run(name, func(t *testing.T) {
			in := withVendorDomain(t)
			tc.mutate(t, &in)
			wantBuildError(t, in, tc.want)
		})
	}
}

// What the derivation would read wrongly is refused before it derives.
func TestTrustDomainInputRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, in *estate.Inputs)
		want   string
	}{
		"private and origin as one": {func(_ *testing.T, in *estate.Inputs) {
			in.PKI.Origin = in.PKI.Private
		}, `PKI.Private and PKI.Origin are both "private"`},
		"a private domain that skips a cluster": {func(_ *testing.T, in *estate.Inputs) {
			in.PKI.Contract.DNSTrustDomain(in.PKI.Private).Environments = []string{"alpha", "ops"}
		}, "does not reach cluster beta"},
		"a dns domain listing no cluster": {func(_ *testing.T, in *estate.Inputs) {
			in.PKI.Contract.DNSTrustDomain(vendor).Environments = []string{"alpha", "nowhere"}
		}, `dns trust domain vendor-a lists environment "nowhere"`},
		"a pending private domain": {func(_ *testing.T, in *estate.Inputs) {
			in.PKI.PendingDomains = []string{in.PKI.Private}
		}, "trust domain private cannot be pending"},
		"a pending origin domain": {func(_ *testing.T, in *estate.Inputs) {
			in.PKI.PendingDomains = []string{in.PKI.Origin}
		}, "trust domain origin cannot be pending"},
		"a pending domain that is none": {func(_ *testing.T, in *estate.Inputs) {
			in.PKI.PendingDomains = []string{"vendor-b"}
		}, `pending domain "vendor-b" is no dns trust domain`},
	} {
		t.Run(name, func(t *testing.T) {
			in := withVendorDomain(t)
			tc.mutate(t, &in)
			wantBuildError(t, in, tc.want)
		})
	}
}

// A URI domain's list may name an environment this estate does not build,
// as at v0.51.0: a partial estate (one cluster of several) still builds.
func TestURIDomainMayListEnvironmentsTheEstateDoesNotBuild(t *testing.T) {
	in := example.Inputs(t, "testdata/contract.yaml")
	identity := in.PKI.Contract.URITrustDomain(in.PKI.Identity)
	identity.Environments = append(identity.Environments, "elsewhere")

	if _, err := estate.Build(in); err != nil {
		t.Fatalf("build: %v", err)
	}
}

// A domain whose intermediate is committed is not pending: listing it would
// drop its issuing CAs, roles and logins.
func TestPendingDomainWithItsArtifactIsRefused(t *testing.T) {
	raw, err := os.ReadFile("testdata/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}

	fsys := fstest.MapFS{"contract.yaml": {Data: raw}}

	contract, err := pki.LoadFS(fsys, "contract.yaml", "")
	if err != nil {
		t.Fatal(err)
	}

	in := example.Inputs(t, "testdata/contract.yaml")
	in.PKI.Contract = contract
	example.WithVendorDomain(t, &in, "alpha")
	in.PKI.PendingDomains = []string{vendor}

	if _, err := estate.Build(in); err != nil {
		t.Fatalf("build with no artifact: %v", err)
	}

	generation, err := estate.ActiveGeneration(contract)
	if err != nil {
		t.Fatal(err)
	}

	spec, err := contract.DNSIntermediateSpec(vendor, generation.ID)
	if err != nil {
		t.Fatal(err)
	}

	fsys[spec.ArtifactPath] = &fstest.MapFile{Data: []byte("signed")}

	wantBuildError(t, in, "trust domain vendor-a is pending, but its intermediate is committed")
}

// Where the origin domain does not reach, no origin zone is needed.
func TestOriginZoneOnlyWhereOriginReaches(t *testing.T) {
	in := example.Inputs(t, "testdata/contract.yaml")
	in.PKI.Contract.DNSTrustDomain(in.PKI.Origin).Environments = []string{"alpha", "ops"}
	in.Clusters[clusterAt(t, in, "beta")].OriginZone = ""
	in.Clusters[clusterAt(t, in, "beta")].OriginNames = nil

	desired, err := estate.Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	for _, ca := range issuingCAsOf(desired, "beta") {
		if ca.TrustDomain == in.PKI.Origin {
			t.Error("beta has an origin issuing CA, though origin does not reach it")
		}
	}

	in.Clusters[clusterAt(t, in, "alpha")].OriginZone = ""
	wantBuildError(t, in, "cluster alpha has no origin zone")
}

// A pending domain renders its root mount, key and request alone: nothing in
// any environment, no import, and so the same model as the estate without
// the domain. No zone is needed, and one given is kept, not refused.
func TestPendingDomainRendersOnlyItsRequest(t *testing.T) {
	without, err := estate.Build(example.Inputs(t, "testdata/contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	wantModel, err := without.Model()
	if err != nil {
		t.Fatal(err)
	}

	for name, zone := range map[string]string{"with its zone": "alpha.vendor-a.example", "with no zone": ""} {
		t.Run(name, func(t *testing.T) {
			in := withVendorDomain(t)
			in.PKI.PendingDomains = []string{vendor}

			if zone == "" {
				in.Clusters[clusterAt(t, in, "alpha")].Zones = nil
			}

			desired, err := estate.Build(in)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			want := []estate.PendingDomain{{
				TrustDomain: vendor, Mount: "pki-" + vendor,
				MountDescription: "vendor-a.example Intermediate CA; signs environment issuing CAs only",
				LeaseTTL:         "87600h",
				KeyName:          "example-vendor-a-2026-09",
				CommonName:       "vendor-a.example Intermediate CA",
				Organization:     "Example Org",
				KeyCurve:         "P-384",
			}}
			if !reflect.DeepEqual(desired.PKI.Pending, want) {
				t.Errorf("pending = %+v, want %+v", desired.PKI.Pending, want)
			}

			if slices.ContainsFunc(desired.PKI.Domains, func(d estate.DomainAuthority) bool { return d.TrustDomain == vendor }) {
				t.Error("a pending domain has an intermediate to import")
			}

			for i := range desired.Namespaces {
				for _, ca := range desired.Namespaces[i].IssuingCAs {
					if ca.TrustDomain == vendor {
						t.Errorf("%s has a vendor-a issuing CA while the domain is pending", desired.Namespaces[i].Name)
					}
				}
			}

			model, err := desired.Model()
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(model, wantModel) {
				t.Error("a pending domain changed the model: everything of it but the bootstrap must wait for its signature")
			}
		})
	}
}

// The yaml keys of the new inputs, read and written back.
func TestTrustDomainInputKeysRoundTrip(t *testing.T) {
	var cluster estate.Cluster
	if err := yaml.Unmarshal([]byte("name: alpha\nzones: {vendor-a: alpha.vendor-a.example}\n"), &cluster); err != nil {
		t.Fatal(err)
	}

	if cluster.Zones[vendor] != "alpha.vendor-a.example" {
		t.Errorf("zones read as %v", cluster.Zones)
	}

	var in estate.PKI
	if err := yaml.Unmarshal([]byte("pendingDomains: [vendor-a]\n"), &in); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(in.PendingDomains, []string{vendor}) {
		t.Errorf("pendingDomains read as %v", in.PendingDomains)
	}

	for value, key := range map[any]string{&cluster: "zones:", &in: "pendingDomains:"} {
		out, err := yaml.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(out), key) {
			t.Errorf("%T written without %s:\n%s", value, key, out)
		}
	}
}
