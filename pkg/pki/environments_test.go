package pki

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// withVendorDomain is the estate contract with a further DNS trust domain,
// vendor-a.example, shaped like the private one and listing environments.
// Its environments list is the only lever under test.
func withVendorDomain(t *testing.T, environments ...string) *Contract {
	t.Helper()

	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	private := contract.DNSTrustDomain("private")
	if private == nil {
		t.Fatal("the estate contract has no private domain")
	}

	role := private.Roles[0]
	role.Name = "vendor-a"

	contract.TrustDomains.DNS = append(contract.TrustDomains.DNS, DNSTrustDomain{
		Name:           "vendor-a",
		Suffix:         "vendor-a.example",
		RootGeneration: private.RootGeneration,
		Environments:   environments,
		DomainIntermediate: DomainIntermediate{
			Name: "example-vendor-a-2026-09",
			Subject: Subject{
				CommonName:   "vendor-a.example Intermediate CA",
				Organization: private.DomainIntermediate.Subject.Organization,
			},
			KeyCurve:            private.DomainIntermediate.KeyCurve,
			MaxPathLen:          private.DomainIntermediate.MaxPathLen,
			PermittedDNSDomains: []string{"vendor-a.example"},
		},
		Lifetimes: private.Lifetimes,
		Placement: Placement{IssuingMount: "pki-vendor-a"},
		IssuingCA: private.IssuingCA,
		Roles:     []LeafRole{role},
	})

	if err := contract.Validate(); err != nil {
		t.Fatalf("the contract with a further domain does not validate: %v", err)
	}

	return contract
}

type issuingKey struct{ environment, domain string }

func issuingByKey(derivation *Derivation) map[issuingKey]Authority {
	out := map[issuingKey]Authority{}
	for i := range derivation.Issuing {
		out[issuingKey{derivation.Issuing[i].Environment, derivation.Issuing[i].Domain}] = derivation.Issuing[i]
	}

	return out
}

// A DNS domain that lists environments reaches those and no other: the
// others need no zone for it and derive nothing of it. Its intermediate is
// one, in the root namespace, whoever it reaches.
func TestDNSDomainReachesOnlyItsEnvironments(t *testing.T) {
	contract := withVendorDomain(t, "dev")

	environments := estateEnvironments()
	environments[0].Zones["vendor-a"] = "dev.vendor-a.example"
	// prod has no vendor-a zone, and needs none.

	derivation, err := contract.Derive(environments)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	issuing := issuingByKey(derivation)

	dev, ok := issuing[issuingKey{"dev", "vendor-a"}]
	if !ok {
		t.Fatal("dev has no vendor-a issuing CA")
	}

	if dev.Mount != "pki-vendor-a" || dev.Issuer != "example-vendor-a-2026-09-dev" {
		t.Errorf("dev vendor-a = mount %q issuer %q", dev.Mount, dev.Issuer)
	}

	if !slices.Equal(dev.PermittedDNSDomains, []string{"dev.vendor-a.example"}) {
		t.Errorf("dev vendor-a is constrained to %v, want only its own zone", dev.PermittedDNSDomains)
	}

	if _, ok := issuing[issuingKey{"prod", "vendor-a"}]; ok {
		t.Error("prod is not in vendor-a's environments and must derive nothing of it")
	}

	var intermediates int

	for i := range derivation.Domains {
		if derivation.Domains[i].Domain == "vendor-a" {
			intermediates++
		}
	}

	if intermediates != 1 {
		t.Errorf("vendor-a intermediates = %d, want 1", intermediates)
	}

	mounts, err := derivation.EnvironmentMounts("prod")
	if err != nil {
		t.Fatal(err)
	}

	for _, mount := range mounts {
		if mount.Path == "pki-vendor-a" {
			t.Error("prod has the vendor-a mount")
		}
	}
}

// Adding a domain changes nothing the others derive: every authority of
// the domains authored before is the same, field for field.
func TestAFurtherDNSDomainLeavesTheOthersAsTheyWere(t *testing.T) {
	before, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	was, err := before.Derive(estateEnvironments())
	if err != nil {
		t.Fatal(err)
	}

	environments := estateEnvironments()
	environments[0].Zones["vendor-a"] = "dev.vendor-a.example"

	is, err := withVendorDomain(t, "dev").Derive(environments)
	if err != nil {
		t.Fatal(err)
	}

	var issuing []Authority

	for i := range is.Issuing {
		if is.Issuing[i].Domain != "vendor-a" {
			issuing = append(issuing, is.Issuing[i])
		}
	}

	if !reflect.DeepEqual(issuing, was.Issuing) {
		t.Error("the issuing CAs of the domains authored before changed")
	}

	if !reflect.DeepEqual(is.Domains[:len(was.Domains)], was.Domains) {
		t.Error("the intermediates authored before changed")
	}
}

// Left out, the list means every environment, as before it existed: an
// environment without the domain's zone is then refused, not skipped.
func TestDNSDomainWithNoEnvironmentsReachesEvery(t *testing.T) {
	contract := withVendorDomain(t)

	environments := estateEnvironments()
	environments[0].Zones["vendor-a"] = "dev.vendor-a.example"

	if _, err := contract.Derive(environments); err == nil || !strings.Contains(err.Error(), "prod has no value") {
		t.Errorf("derive = %v, want prod refused for its missing vendor-a zone", err)
	}

	environments[1].Zones["vendor-a"] = "prod.vendor-a.example"

	derivation, err := contract.Derive(environments)
	if err != nil {
		t.Fatal(err)
	}

	issuing := issuingByKey(derivation)
	for _, environment := range []string{"dev", "prod"} {
		if _, ok := issuing[issuingKey{environment, "vendor-a"}]; !ok {
			t.Errorf("%s has no vendor-a issuing CA", environment)
		}
	}
}

func TestDNSDomainEnvironmentsRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		environments []string
		want         string
	}{
		"a name that is not bare": {[]string{"dev.example"}, "is not a bare environment name"},
		"a name twice":            {[]string{"dev", "dev"}, `duplicates "dev"`},
	} {
		t.Run(name, func(t *testing.T) {
			contract := mutate(func(c *Contract) { c.TrustDomains.DNS[0].Environments = tc.environments })

			err := contract.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
