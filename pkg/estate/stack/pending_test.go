package stack

import (
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
)

const (
	vendorMount = "vault:index/mount:Mount pki-vendor-a"
	vendorCSR   = "vault:pkiSecret/secretBackendIntermediateCertRequest:SecretBackendIntermediateCertRequest example-vendor-a-2026-09-csr"
)

// inputsRecorder records every resource the program registers, with its
// inputs.
type inputsRecorder struct {
	mu     sync.Mutex
	names  []string
	inputs map[string]resource.PropertyMap
}

func (r *inputsRecorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := args.TypeToken + " " + args.Name
	r.names = append(r.names, name)

	if r.inputs == nil {
		r.inputs = map[string]resource.PropertyMap{}
	}

	r.inputs[name] = args.Inputs.Copy()

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (r *inputsRecorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

// vendorEstate is the example estate with the further domain vendor-a on
// alpha, pending or signed.
func vendorEstate(t *testing.T, pending bool) estate.Desired {
	t.Helper()

	in := example.Inputs(t, "../testdata/contract.yaml")
	example.WithVendorDomain(t, &in, "alpha")

	if pending {
		in.PKI.PendingDomains = []string{example.VendorDomain}
	}

	desired, err := estate.Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	return desired
}

func vendorOptions(chains estate.Chains) Options {
	opts := deployOptions(chains)
	opts.DomainCSROutputs["vendor-a"] = "vendorCsr"

	return opts
}

func deployRecorded(t *testing.T, desired estate.Desired, opts Options) *inputsRecorder {
	t.Helper()

	mocks := &inputsRecorder{}

	if err := pulumi.RunErr(func(c *pulumi.Context) error {
		return Deploy(c, &desired, opts)
	}, pulumi.WithMocks("example", "openbao-config", mocks)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return mocks
}

func missingFrom(names, from []string) []string {
	var out []string

	for _, name := range names {
		if !slices.Contains(from, name) {
			out = append(out, name)
		}
	}

	slices.Sort(out)

	return out
}

// A pending domain adds its root mount and its key's request, and nothing
// else: no import, no issuer, nothing in an environment, and no signed
// chain asked for.
func TestPendingDomainBootstrapsOnlyItsMountAndRequest(t *testing.T) {
	baseline, err := estate.Build(example.Inputs(t, "../testdata/contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	without := deployRecorded(t, baseline, deployOptions(&fakeChains{}))

	chains := &fakeChains{}
	pending := deployRecorded(t, vendorEstate(t, true), vendorOptions(chains))

	if added := missingFrom(pending.names, without.names); !slices.Equal(added, []string{vendorMount, vendorCSR}) {
		t.Errorf("a pending domain adds %v, want only its mount and request", added)
	}

	if gone := missingFrom(without.names, pending.names); len(gone) != 0 {
		t.Errorf("a pending domain removes %v", gone)
	}

	for _, asked := range chains.asked {
		if strings.Contains(asked, "vendor-a") {
			t.Errorf("a signed chain was asked for while the domain is pending: %s", asked)
		}
	}
}

// Signing the domain keeps the mount and the request in place -- the same
// names and the same inputs, so no replace -- and adds the rest of it.
func TestSigningAPendingDomainKeepsItsResources(t *testing.T) {
	pending := deployRecorded(t, vendorEstate(t, true), vendorOptions(&fakeChains{}))
	signed := deployRecorded(t, vendorEstate(t, false), vendorOptions(&fakeChains{}))

	if gone := missingFrom(pending.names, signed.names); len(gone) != 0 {
		t.Errorf("signing drops %v", gone)
	}

	for _, name := range []string{vendorMount, vendorCSR} {
		if !reflect.DeepEqual(pending.inputs[name], signed.inputs[name]) {
			t.Errorf("%s changes on signing:\npending %v\nsigned  %v", name, pending.inputs[name], signed.inputs[name])
		}
	}

	added := missingFrom(signed.names, pending.names)
	for _, want := range []string{
		"vault:pkiSecret/secretBackendIntermediateSetSigned:SecretBackendIntermediateSetSigned example-vendor-a-2026-09-import",
		"vault:pkiSecret/secretBackendIssuer:SecretBackendIssuer example-vendor-a-2026-09-issuer",
		"vault:index/mount:Mount alpha-pki-vendor-a",
	} {
		if !slices.Contains(added, want) {
			t.Errorf("signing does not add %s", want)
		}
	}
}

// A pending domain's request is an output: one must be named for it.
func TestPendingDomainNeedsARequestOutput(t *testing.T) {
	desired := vendorEstate(t, true)
	opts := deployOptions(&fakeChains{})

	err := pulumi.RunErr(func(c *pulumi.Context) error {
		return Deploy(c, &desired, opts)
	}, pulumi.WithMocks("example", "openbao-config", &recorder{}))
	if err == nil || !strings.Contains(err.Error(), "trust domain vendor-a has no request output") {
		t.Errorf("Deploy() = %v, want the missing output refused", err)
	}
}

// Select places a pending domain's resources and a signed domain's
// resources in one stack each, the same way on every run: split by kind or
// by domain, the stacks together register each resource of the whole once.
func TestSelectPlacesPendingAndSignedDomainsOnce(t *testing.T) {
	grants := map[string]bool{
		apply.TypePolicy: true, apply.TypeGroup: true, apply.TypeGroupAlias: true,
		apply.TypeJWTAuthBackendRole: true, apply.TypeAWSAuthBackendRole: true,
		apply.TypePKIRole: true, apply.TypeSSHRole: true,
	}

	splits := map[string]func(apply.Resource) bool{
		"by kind":   func(r apply.Resource) bool { return grants[r.Type] },
		"by domain": func(r apply.Resource) bool { return strings.Contains(r.Name, "vendor-a") },
	}

	const provider = "pulumi:providers:vault openbao"

	for _, pending := range []bool{true, false} {
		desired := vendorEstate(t, pending)

		for split, selects := range splits {
			t.Run(map[bool]string{true: "pending ", false: "signed "}[pending]+split, func(t *testing.T) {
				run := func(selects func(apply.Resource) bool) []string {
					opts := vendorOptions(&fakeChains{})
					opts.Select = selects

					return deployRecorded(t, desired, opts).names
				}

				whole := run(nil)
				in := run(selects)
				out := run(func(r apply.Resource) bool { return !selects(r) })

				if again := run(selects); !slices.Equal(sorted(again), sorted(in)) {
					t.Error("the same selection placed the resources differently on a second run")
				}

				count := map[string]int{}
				for _, name := range append(slices.Clone(in), out...) {
					count[name]++
				}

				for _, name := range whole {
					if want := map[bool]int{true: 2, false: 1}[name == provider]; count[name] != want {
						t.Errorf("%s is registered %d times across the two stacks, want %d", name, count[name], want)
					}
				}

				if len(count) != len(whole) {
					t.Errorf("the two stacks register %d names, the whole %d", len(count), len(whole))
				}

				for _, name := range []string{vendorMount, vendorCSR} {
					if slices.Contains(in, name) == slices.Contains(out, name) {
						t.Errorf("%s is not in exactly one of the two stacks", name)
					}
				}

				if slices.Contains(in, vendorMount) != slices.Contains(in, vendorCSR) {
					t.Error("the mount and the request of the domain intermediate are in different stacks")
				}
			})
		}
	}
}

// A selection that splits a pending domain's mount from its request is
// refused before anything is registered.
func TestDeployRefusesASplitPendingDomain(t *testing.T) {
	desired := vendorEstate(t, true)
	mocks := &recorder{}
	opts := vendorOptions(&fakeChains{})
	opts.Select = func(r apply.Resource) bool { return r.Name != "example-vendor-a-2026-09-csr" }

	err := pulumi.RunErr(func(c *pulumi.Context) error {
		return Deploy(c, &desired, opts)
	}, pulumi.WithMocks("example", "openbao-config", mocks))
	if err == nil || !strings.Contains(err.Error(), "are selected apart") {
		t.Fatalf("want a select refusal, got %v", err)
	}

	if len(mocks.names) != 0 {
		t.Errorf("%d resources registered before the refusal: %v", len(mocks.names), mocks.names)
	}
}

func sorted(names []string) []string {
	out := slices.Clone(names)
	slices.Sort(out)

	return out
}

// The bootstrap asks the selection about the names apply.Deploy gives the
// same objects: the mount alone in root, "<namespace>-<mount>" below it, and
// "<key>-csr" for the request.
func TestSelectsBootstrapAsksForDeploysNames(t *testing.T) {
	for namespace, wantMount := range map[string]string{"": "pki-vendor-a", "alpha": "alpha-pki-vendor-a"} {
		var asked []apply.Resource

		owned, err := selectsBootstrap(func(r apply.Resource) bool {
			asked = append(asked, r)

			return true
		}, func(name string) string { return name }, namespace, "pki-vendor-a", "example-vendor-a-2026-09")
		if err != nil || !owned {
			t.Fatalf("selectsBootstrap(%q) = %v, %v", namespace, owned, err)
		}

		want := []apply.Resource{
			{Type: apply.TypeMount, Name: wantMount},
			{Type: apply.TypePKIIntermediateCertRequest, Name: "example-vendor-a-2026-09-csr"},
		}
		if !slices.Equal(asked, want) {
			t.Errorf("namespace %q: asked %v, want %v", namespace, asked, want)
		}
	}
}

// Two trust domains' requests under one output are refused.
func TestDeployRefusesASharedRequestOutput(t *testing.T) {
	desired := vendorEstate(t, true)
	opts := vendorOptions(&fakeChains{})
	opts.DomainCSROutputs["vendor-a"] = "privateCsr"

	err := pulumi.RunErr(func(c *pulumi.Context) error {
		return Deploy(c, &desired, opts)
	}, pulumi.WithMocks("example", "openbao-config", &recorder{}))
	if err == nil || !strings.Contains(err.Error(), `trust domains private and vendor-a share the request output "privateCsr"`) {
		t.Errorf("Deploy() = %v, want the shared output refused", err)
	}
}
