package estate_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
	"github.com/truvity/secrets/pkg/pki"
)

// withVendorDomain adds a further DNS trust domain, vendor-a.example, shaped
// like the private one, reaching alpha only, and alpha's zone for it.
func withVendorDomain(t *testing.T) estate.Inputs {
	t.Helper()

	in := example.Inputs(t, "testdata/contract.yaml")
	contract := in.PKI.Contract

	private := contract.DNSTrustDomain(in.PKI.Private)
	if private == nil {
		t.Fatal("the example contract has no private domain")
	}

	role := private.Roles[0]
	role.Name = "vendor-a"

	contract.TrustDomains.DNS = append(contract.TrustDomains.DNS, pki.DNSTrustDomain{
		Name:           "vendor-a",
		Suffix:         "vendor-a.example",
		RootGeneration: private.RootGeneration,
		Environments:   []string{"alpha"},
		DomainIntermediate: pki.DomainIntermediate{
			Name: "example-vendor-a-2026-09",
			Subject: pki.Subject{
				CommonName:   "vendor-a.example Intermediate CA",
				Organization: private.DomainIntermediate.Subject.Organization,
			},
			KeyCurve:            private.DomainIntermediate.KeyCurve,
			MaxPathLen:          private.DomainIntermediate.MaxPathLen,
			PermittedDNSDomains: []string{"vendor-a.example"},
		},
		Lifetimes: private.Lifetimes,
		Placement: pki.Placement{IssuingMount: "pki-vendor-a"},
		IssuingCA: private.IssuingCA,
		Roles:     []pki.LeafRole{role},
	})

	if err := contract.Validate(); err != nil {
		t.Fatalf("the contract with a further domain does not validate: %v", err)
	}

	in.PKI.ClusterIssuers["vendor-a"] = "vendor-a-ca"
	in.Clusters[clusterAt(t, in, "alpha")].Zones = map[string]string{"vendor-a": "alpha.vendor-a.example"}

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

		var vendor []estate.IssuingCA

		var others []estate.IssuingCA

		for _, ca := range desired.Namespaces[i].IssuingCAs {
			if ca.TrustDomain == "vendor-a" {
				vendor = append(vendor, ca)
			} else {
				others = append(others, ca)
			}
		}

		if !reflect.DeepEqual(others, issuingCAsOf(was, name)) {
			t.Errorf("%s: the issuing CAs of the domains authored before changed", name)
		}

		switch {
		case name == "alpha" && len(vendor) != 1:
			t.Errorf("alpha vendor-a issuing CAs = %d, want 1", len(vendor))
		case name == "alpha":
			if vendor[0].Mount != "pki-vendor-a" || !slices.Equal(vendor[0].PermittedDomains, []string{"alpha.vendor-a.example"}) {
				t.Errorf("alpha vendor-a = mount %q constrained to %v", vendor[0].Mount, vendor[0].PermittedDomains)
			}
		case len(vendor) != 0:
			t.Errorf("%s is not in vendor-a's environments and has its issuing CA", name)
		}
	}

	if !slices.ContainsFunc(desired.PKI.Domains, func(d estate.DomainAuthority) bool { return d.TrustDomain == "vendor-a" }) {
		t.Error("no vendor-a intermediate in the root namespace")
	}
}

// A zone is required where the domain reaches, and refused where nothing
// reads it.
func TestFurtherDNSDomainZoneRefusals(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, in *estate.Inputs){
		"a reached cluster with no zone": func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "alpha")].Zones = nil
		},
		"a zone where the domain does not reach": func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "beta")].Zones = map[string]string{"vendor-a": "beta.vendor-a.example"}
		},
		"a zone for the private domain": func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "alpha")].Zones["private"] = "alpha.example.private"
		},
		"a zone for no domain": func(t *testing.T, in *estate.Inputs) {
			in.Clusters[clusterAt(t, *in, "alpha")].Zones["vendor-b"] = "alpha.vendor-b.example"
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := withVendorDomain(t)
			mutate(t, &in)

			if _, err := estate.Build(in); err == nil {
				t.Error("built; want a refusal")
			}
		})
	}
}
