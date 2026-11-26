package pki

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
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
		"an empty list":           {[]string{}, "environments is empty"},
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

// vendorEnvironments gives each estate environment a vendor-a zone.
func vendorEnvironments() []Environment {
	environments := estateEnvironments()
	environments[0].Zones["vendor-a"] = "dev.vendor-a.example"
	environments[1].Zones["vendor-a"] = "prod.vendor-a.example"

	return environments
}

func wantDeriveError(t *testing.T, contract *Contract, environments []Environment, options DeriveOptions, substring string) {
	t.Helper()

	_, err := contract.DeriveWith(environments, options)
	if err == nil || !strings.Contains(err.Error(), substring) {
		t.Errorf("DeriveWith() = %v, want an error containing %q", err, substring)
	}
}

// A zone belongs to its own domain: a DNS name, the suffix or under it,
// inside the intermediate's constraint; and in a constrained domain the
// environments' zones stay apart.
func TestDNSDomainZoneRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		contract func(*Contract)
		zones    func([]Environment)
		want     string
	}{
		"a zone that is no dns name": {zones: func(e []Environment) { e[0].Zones["vendor-a"] = "dev_vendor-a.example" },
			want: `zone "dev_vendor-a.example" of trust domain vendor-a is not a lower-case DNS name`},
		"a zone in upper case": {zones: func(e []Environment) { e[0].Zones["vendor-a"] = "Dev.vendor-a.example" },
			want: "is not a lower-case DNS name"},
		"a zone outside the suffix": {zones: func(e []Environment) { e[0].Zones["vendor-a"] = "dev.example.private" },
			want: `zone "dev.example.private" of trust domain vendor-a is not vendor-a.example or under it`},
		"a zone that only ends like the suffix": {zones: func(e []Environment) { e[0].Zones["vendor-a"] = "devvendor-a.example" },
			want: "is not vendor-a.example or under it"},
		"a zone outside the constraint": {
			contract: func(c *Contract) {
				c.DNSTrustDomain("vendor-a").DomainIntermediate.PermittedDNSDomains = []string{"prod.vendor-a.example"}
			},
			want: `zone "dev.vendor-a.example" of trust domain vendor-a is outside its name constraint`,
		},
		"a zone that is the whole suffix": {zones: func(e []Environment) { e[1].Zones["vendor-a"] = "vendor-a.example" },
			want: "is the domain's whole suffix"},
		"two environments with one zone": {zones: func(e []Environment) { e[1].Zones["vendor-a"] = "dev.vendor-a.example" },
			want: `environments dev and prod share zone "dev.vendor-a.example"`},
		"one zone under another": {zones: func(e []Environment) { e[1].Zones["vendor-a"] = "eu.dev.vendor-a.example" },
			want: "of trust domain vendor-a nest"},
	} {
		t.Run(name, func(t *testing.T) {
			contract := withVendorDomain(t)
			if tc.contract != nil {
				tc.contract(contract)
			}

			environments := vendorEnvironments()
			if tc.zones != nil {
				tc.zones(environments)
			}

			wantDeriveError(t, contract, environments, DeriveOptions{}, tc.want)
		})
	}
}

// An unconstrained domain may give an environment its whole suffix, as the
// origin domain does for prod: nothing is fenced in to keep apart.
func TestUnconstrainedDomainMayUseItsSuffix(t *testing.T) {
	contract, err := Load("testdata/contract-estate.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := contract.Derive(estateEnvironments()); err != nil {
		t.Fatalf("derive: %v", err)
	}
}

// Two DNS domains keep their names apart: no suffix or constraint entry of
// one equal to or under one of the other.
func TestDNSDomainsStayApart(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*DNSTrustDomain)
		want   string
	}{
		"a suffix under another's": {func(d *DNSTrustDomain) {
			d.Suffix = "vendor.example.private"
			d.DomainIntermediate.PermittedDNSDomains = []string{"vendor.example.private"}
		}, `trust domains private and vendor-a overlap: "example.private" and "vendor.example.private"`},
		"a suffix equal to another's": {func(d *DNSTrustDomain) {
			d.Suffix = "example.net"
			d.DomainIntermediate.PermittedDNSDomains = []string{"example.net"}
		}, `trust domains origin and vendor-a overlap: "example.net" and "example.net"`},
		"a constraint entry another holds": {func(d *DNSTrustDomain) {
			d.DomainIntermediate.PermittedDNSDomains = []string{"vendor-a.example", "cluster.local"}
		}, `trust domains private and vendor-a overlap: "cluster.local" and "cluster.local"`},
	} {
		t.Run(name, func(t *testing.T) {
			contract := withVendorDomain(t)
			tc.mutate(contract.DNSTrustDomain("vendor-a"))

			err := contract.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestReachesOfNoDomainIsFalse(t *testing.T) {
	var domain *DNSTrustDomain
	if domain.Reaches("dev") {
		t.Error("a nil domain reaches dev")
	}

	contract := withVendorDomain(t, "dev")
	if contract.DNSTrustDomain("nowhere").Reaches("dev") {
		t.Error("a domain the contract does not declare reaches dev")
	}
}

// The yaml key of the list, read, refused empty, and written back.
func TestDNSDomainEnvironmentsKeyRoundTrip(t *testing.T) {
	var domain DNSTrustDomain
	if err := yaml.Unmarshal([]byte("name: vendor-a\nenvironments: [dev]\n"), &domain); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(domain.Environments, []string{"dev"}) {
		t.Errorf("environments read as %v", domain.Environments)
	}

	out, err := yaml.Marshal(&domain)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), "environments:") {
		t.Errorf("written without environments:\n%s", out)
	}

	var empty DNSTrustDomain
	if err := yaml.Unmarshal([]byte("environments: []\n"), &empty); err != nil {
		t.Fatal(err)
	}

	contract := mutate(func(c *Contract) { c.TrustDomains.DNS[0].Environments = empty.Environments })
	if err := contract.Validate(); err == nil || !strings.Contains(err.Error(), "environments is empty") {
		t.Errorf("`environments: []` validates as %v, want refused", err)
	}
}

// A pending domain derives its intermediate's key and request alone:
// nothing in any environment, which then needs no zone for it, and every
// other authority as it was.
func TestPendingDomainDerivesOnlyItsKey(t *testing.T) {
	contract := withVendorDomain(t)

	was, err := contract.DeriveWith(vendorEnvironments(), DeriveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	is, err := contract.DeriveWith(estateEnvironments(), DeriveOptions{PendingDomains: []string{"vendor-a"}})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	want := []PendingIntermediate{{
		Domain: "vendor-a", Mount: "pki-vendor-a",
		MountDescription: "vendor-a.example Intermediate CA; signs environment issuing CAs only",
		LeaseTTL:         "87600h",
		KeyName:          "example-vendor-a-2026-09",
		CommonName:       "vendor-a.example Intermediate CA",
		Organization:     "Example Org",
		KeyCurve:         "P-384",
	}}
	if !reflect.DeepEqual(is.Pending, want) {
		t.Errorf("pending = %+v, want %+v", is.Pending, want)
	}

	signed := was.Domains[slices.IndexFunc(was.Domains, func(a Authority) bool { return a.Domain == "vendor-a" })]
	if signed.Mount != want[0].Mount || signed.Issuer != want[0].KeyName || signed.TTL != want[0].LeaseTTL ||
		signed.mountDescription != want[0].MountDescription {
		t.Errorf("the signed domain derives mount %q issuer %q ttl %q: the pending one must match", signed.Mount, signed.Issuer, signed.TTL)
	}

	var domains, issuing []Authority

	for _, a := range was.Domains {
		if a.Domain != "vendor-a" {
			domains = append(domains, a)
		}
	}

	for _, a := range was.Issuing {
		if a.Domain != "vendor-a" {
			issuing = append(issuing, a)
		}
	}

	if !reflect.DeepEqual(is.Domains, domains) || !reflect.DeepEqual(is.Issuing, issuing) {
		t.Error("a pending domain changed the other authorities, or derived one of its own")
	}
}

func TestPendingDomainRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate  func(*Contract)
		pending []string
		want    string
	}{
		"no such domain": {pending: []string{"vendor-b"}, want: `pending domain "vendor-b" is no dns trust domain`},
		"a uri domain":   {pending: []string{"identity"}, want: `pending domain "identity" is no dns trust domain`},
		"a domain twice": {pending: []string{"vendor-a", "vendor-a"}, want: `pending domain "vendor-a" is named twice`},
		"a shared mount": {
			mutate:  func(c *Contract) { c.DNSTrustDomain("vendor-a").Placement.DomainMount = "pki-example-private" },
			pending: []string{"vendor-a"},
			want:    "pending domain vendor-a shares its domain mount pki-example-private with private",
		},
	} {
		t.Run(name, func(t *testing.T) {
			contract := withVendorDomain(t)
			if tc.mutate != nil {
				tc.mutate(contract)
			}

			wantDeriveError(t, contract, vendorEnvironments(), DeriveOptions{PendingDomains: tc.pending}, tc.want)
		})
	}
}
