package pki

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/custody"
)

const (
	vendorRoot    = "vendor-a-root-2026-11"
	vendorAccount = "444455556666"
	vendorKey     = "arn:aws:kms:eu-central-1:444455556666:key/mrk-vendor"
	vendorReplica = "arn:aws:kms:eu-north-1:444455556666:key/mrk-vendor"
	vendorRole    = "arn:aws:iam::444455556666:role/root-ceremony"
	vendorAdmin   = "arn:aws:iam::444455556666:role/root-admin"
)

// vendorGeneration is a second active root, in an account of its own, with
// an organization of its own so a derivation shows which root signed what.
func vendorGeneration(from RootGeneration) RootGeneration {
	generation := from
	generation.ID = vendorRoot
	generation.Certificate.Subject = Subject{CommonName: "Vendor A Private Root 2026-11", Organization: "Vendor A"}
	generation.Custody.AccountID = vendorAccount
	generation.Custody.Profile = "vendor-a-root@admin"
	generation.Custody.TrustedPrincipalARNPattern = "arn:aws:iam::444455556666:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_role-admin_*"
	generation.State = GenerationActive

	return generation
}

// withVendorRoot is withVendorDomain with the vendor-a domain moved under a
// root of its own: two active roots, one per party.
func withVendorRoot(t *testing.T, environments ...string) *Contract {
	t.Helper()

	contract := withVendorDomain(t, environments...)
	contract.Generations = append(contract.Generations, vendorGeneration(contract.Generations[0]))
	contract.DNSTrustDomain("vendor-a").RootGeneration = vendorRoot
	contract.DNSTrustDomain("vendor-a").DomainIntermediate.Subject.Organization = "Vendor A"
	contract.Migration.TrustedGenerations = append(contract.Migration.TrustedGenerations, vendorRoot)

	require.NoError(t, contract.Validate())

	return contract
}

func TestSeveralActiveRootsValidate(t *testing.T) {
	contract := withVendorRoot(t)
	estateRoot := contract.Generations[0].ID

	ids := []string{}
	for _, generation := range contract.ActiveGenerations() {
		ids = append(ids, generation.ID)
	}

	assert.Equal(t, []string{estateRoot, vendorRoot}, ids)
	assert.Equal(t, []string{contract.Generations[0].Custody.AccountID, vendorAccount}, contract.CustodyAccounts())

	inVendor := contract.GenerationsInAccount(vendorAccount)
	require.Len(t, inVendor, 1)
	assert.Equal(t, vendorRoot, inVendor[0].ID)

	root, err := contract.TrustDomainRoot("vendor-a")
	require.NoError(t, err)
	assert.Equal(t, vendorRoot, root.ID)

	root, err = contract.TrustDomainRoot("private")
	require.NoError(t, err)
	assert.Equal(t, estateRoot, root.ID)

	_, err = contract.TrustDomainRoot("nope")
	require.ErrorContains(t, err, `no trust domain named "nope"`)

	assert.True(t, contract.DeclaresUnder(vendorRoot))
	assert.True(t, contract.DeclaresUnder(estateRoot))
	assert.False(t, contract.DeclaresUnder("nope"))
}

// Each domain derives under its OWN root: its intermediate's artifact is
// that root's, and its issuing CAs carry that root's organization. The
// estate root's domains derive exactly as with one root.
func TestEachDomainDerivesUnderItsOwnRoot(t *testing.T) {
	single, err := withVendorDomain(t).Derive(vendorEnvironments())
	require.NoError(t, err)

	contract := withVendorRoot(t)

	derivation, err := contract.Derive(vendorEnvironments())
	require.NoError(t, err)

	for i := range derivation.Domains {
		domain := &derivation.Domains[i]
		if domain.Domain == "vendor-a" {
			assert.Equal(t, contract.ArtifactPath(IntermediateArtifactName(vendorRoot, "vendor-a", "")), domain.ArtifactPath)
			assert.Equal(t, "Vendor A", domain.Organization)

			continue
		}

		assert.Equal(t, single.Domains[i], *domain, "domain %s moved with the vendor root", domain.Domain)
	}

	for key, authority := range issuingByKey(derivation) {
		if key.domain == "vendor-a" {
			assert.Equal(t, "Vendor A", authority.Organization, "issuing CA %v", key)

			continue
		}

		assert.Equal(t, issuingByKey(single)[key], authority, "issuing CA %v moved with the vendor root", key)
	}
}

func TestADomainBelowARootThatIsNotActiveIsRefused(t *testing.T) {
	contract := withVendorRoot(t)
	contract.RootGeneration(vendorRoot).State = GenerationPreparing
	require.NoError(t, contract.Validate(), "a preparing root beside an active one is a valid contract")

	wantDeriveError(t, contract, vendorEnvironments(), DeriveOptions{},
		`trust domain vendor-a is declared below root generation "vendor-a-root-2026-11", which is preparing, not active`)
}

func TestAnEmptyRootGenerationIsTheOneActiveRoot(t *testing.T) {
	contract := validContract()
	contract.TrustDomains.DNS[0].RootGeneration = ""
	contract.TrustDomains.URI[0].RootGeneration = ""

	require.NoError(t, contract.Validate())
	assert.Equal(t, "example-root-2026-01", contract.TrustDomains.DNS[0].RootGeneration)
	assert.Equal(t, "example-root-2026-01", contract.TrustDomains.URI[0].RootGeneration)
}

func TestAnEmptyRootGenerationWithSeveralActiveRootsIsRefused(t *testing.T) {
	for _, kind := range []string{"dns", "uri"} {
		t.Run(kind, func(t *testing.T) {
			contract := validContract()
			contract.Generations = append(contract.Generations, vendorGeneration(contract.Generations[0]))

			if kind == "dns" {
				contract.TrustDomains.DNS[1].RootGeneration = ""
			} else {
				contract.TrustDomains.URI[0].RootGeneration = ""
			}

			wantValidateError(t, contract,
				"rootGeneration is required: 2 root generations are active (example-root-2026-01, vendor-a-root-2026-11), so none is the default")
		})
	}
}

// twoAccountContract is validContract with a second active root in an
// account of its own; the edge domain is declared under it.
func twoAccountContract(t *testing.T) *Contract {
	t.Helper()

	contract := validContract()
	contract.Generations = append(contract.Generations, vendorGeneration(contract.Generations[0]))
	contract.TrustDomains.DNS[1].RootGeneration = vendorRoot
	contract.Migration.TrustedGenerations = append(contract.Migration.TrustedGenerations, vendorRoot)
	require.NoError(t, contract.Validate())

	return contract
}

func vendorOutputs() *CustodyOutputs {
	return &CustodyOutputs{
		AdminRoleARN:    vendorAdmin,
		CeremonyRoleARN: vendorRole,
		Generations: map[string]CustodyGeneration{vendorRoot: {
			Alias:           custody.DefaultAliasPrefix + vendorRoot,
			PrimaryKeyARN:   vendorKey,
			PrimaryRegion:   "eu-central-1",
			ReplicaKeyARN:   vendorReplica,
			ReplicaRegion:   "eu-north-1",
			CeremonyRoleARN: vendorRole,
		}},
	}
}

// One custody outputs file per account: each verifies its own account's
// generations, and the other account's generations are none of its
// business.
func TestCustodyOutputsArePerAccount(t *testing.T) {
	contract := twoAccountContract(t)

	require.NoError(t, contract.VerifyCustodyOutputs(validOutputs()))
	require.NoError(t, contract.VerifyCustodyOutputs(vendorOutputs()))

	verdict, err := contract.VerifyCustody(validOutputs(), "example-root-2026-01", matching())
	require.NoError(t, err)
	assert.Equal(t, testKey, verdict.KeyARN)
	assert.NotContains(t, strings.Join(verdict.Proven, "\n"), vendorRoot, "the estate account's check proves nothing of the vendor's")

	verdict, err = contract.VerifyCustody(vendorOutputs(), vendorRoot, CustodyRequest{KeyARN: vendorKey})
	require.NoError(t, err)
	assert.Equal(t, vendorRole, verdict.RoleARN)
	assert.Equal(t, "vendor-a-root@admin", verdict.Profile)
	assert.Contains(t, strings.Join(verdict.Proven, "\n"), `generation "vendor-a-root-2026-11": account 444455556666`)
}

func TestCustodyOutputsOfAnotherAccountAreRefused(t *testing.T) {
	contract := twoAccountContract(t)

	// The ceremony for the vendor root, handed the estate account's file.
	_, err := contract.VerifyCustody(validOutputs(), vendorRoot, CustodyRequest{KeyARN: vendorKey})
	require.ErrorContains(t, err, `generation "vendor-a-root-2026-11": the published key is in account 111122223333, `+
		`the contract's custody account is 444455556666: pass that account's custody outputs`)

	// The estate account's file publishing the vendor's generation.
	mixed := validOutputs()
	mixed.Generations[vendorRoot] = CustodyGeneration{
		Alias:           custody.DefaultAliasPrefix + vendorRoot,
		PrimaryKeyARN:   strings.Replace(testKey, "mrk-example", "mrk-vendor", 1),
		PrimaryRegion:   "eu-central-1",
		ReplicaKeyARN:   strings.Replace(testReplica, "mrk-example", "mrk-vendor", 1),
		ReplicaRegion:   "eu-north-1",
		CeremonyRoleARN: testRole,
	}
	require.ErrorContains(t, contract.VerifyCustodyOutputs(mixed),
		`generation "vendor-a-root-2026-11": the published key is in account 111122223333, the contract's custody account is 444455556666`)

	// The vendor account's file missing the vendor's generation is refused
	// as before: a published file covers its account's generations whole.
	empty := vendorOutputs()
	other := empty.Generations[vendorRoot]
	other.Alias = custody.DefaultAliasPrefix + "vendor-a-root-2027-01"
	empty.Generations = map[string]CustodyGeneration{"vendor-a-root-2027-01": other}
	require.ErrorContains(t, contract.VerifyCustodyOutputs(empty), "which the contract does not author")
}

func TestAnAccountsOutputsMustPublishEveryGenerationOfIt(t *testing.T) {
	contract := twoAccountContract(t)

	second := vendorGeneration(contract.Generations[0])
	second.ID = "vendor-a-root-2027-01"
	second.State = GenerationPreparing
	contract.Generations = append(contract.Generations, second)
	require.NoError(t, contract.Validate())

	require.ErrorContains(t, contract.VerifyCustodyOutputs(vendorOutputs()),
		`the custody outputs do not publish authored generation "vendor-a-root-2027-01"`)
	require.NoError(t, contract.VerifyCustodyOutputs(validOutputs()), "the estate account holds no generation of the vendor's")
}

// Each root signs break-glass leaves for its own domains only.
func TestEmergencyServerSpecIsPerRoot(t *testing.T) {
	contract := twoAccountContract(t)
	notBefore := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	spec, err := contract.EmergencyServerSpec(vendorRoot, "emergency.edge.example.org", notBefore)
	require.NoError(t, err)
	assert.Equal(t, vendorRoot, spec.GenerationID)
	assert.Equal(t, contract.RootArtifactPath(vendorRoot), spec.RootArtifactPath)

	_, err = contract.EmergencyServerSpec("example-root-2026-01", "emergency.edge.example.org", notBefore)
	require.ErrorContains(t, err,
		`"emergency.edge.example.org" is not under a dns trust domain that requires trust and is declared below root generation "example-root-2026-01"`)

	contract.RootGeneration(vendorRoot).State = GenerationPreparing
	_, err = contract.EmergencyServerSpec(vendorRoot, "emergency.edge.example.org", notBefore)
	require.ErrorContains(t, err, "only an active generation signs a break-glass leaf")
}

func TestAKeyIsOneGenerationsOnly(t *testing.T) {
	cases := map[string]func(*CustodyOutputs){
		// The same multi-region key, its replica in another region.
		"repeated primary key": func(o *CustodyOutputs) {
			second := o.Generations["example-root-2026-01"]
			second.Alias = custody.DefaultAliasPrefix + "example-root-2027-01"
			second.ReplicaRegion = "eu-west-1"
			second.ReplicaKeyARN = strings.Replace(testReplica, "eu-north-1", "eu-west-1", 1)
			o.Generations["example-root-2027-01"] = second
		},
		// The same multi-region key, its primary in another region.
		"repeated replica key": func(o *CustodyOutputs) {
			second := o.Generations["example-root-2026-01"]
			second.Alias = custody.DefaultAliasPrefix + "example-root-2027-01"
			second.PrimaryRegion = "eu-west-3"
			second.PrimaryKeyARN = strings.Replace(testKey, "eu-central-1", "eu-west-3", 1)
			o.Generations["example-root-2027-01"] = second
		},
	}

	want := map[string]string{
		"repeated primary key": `generation "example-root-2027-01": primaryKeyArn ` + testKey + ` is also generation "example-root-2026-01"'s`,
		"repeated replica key": `generation "example-root-2027-01": replicaKeyArn ` + testReplica + ` is also generation "example-root-2026-01"'s`,
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			outputs := validOutputs()
			mutate(outputs)
			require.ErrorContains(t, outputs.Validate(), want[name])
		})
	}
}

func TestAnActiveRootWithDomainsMustBeTrusted(t *testing.T) {
	// The internal domain does not require trust itself: the root does.
	contract := validContract()
	contract.Generations = append(contract.Generations, vendorGeneration(contract.Generations[0]))
	contract.TrustDomains.DNS[0].RootGeneration = vendorRoot

	wantValidateError(t, contract,
		`root generation "vendor-a-root-2026-11" is active and has trust domains below it, but migration.trustedGenerations omits it`)

	// An active root nothing is declared under yet needs no trust.
	idle := validContract()
	idle.Generations = append(idle.Generations, vendorGeneration(idle.Generations[0]))
	require.NoError(t, idle.Validate())
}
