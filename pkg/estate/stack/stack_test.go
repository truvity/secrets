package stack

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/apply"
	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/estate/internal/example"
	"github.com/truvity/secrets/pkg/model"
)

type (
	// recorder records every resource and output the program registers.
	recorder struct {
		mu    sync.Mutex
		names []string
	}

	// fakeChains answers every request with a placeholder chain, and
	// records what was asked.
	fakeChains struct {
		mu    sync.Mutex
		asked []string
	}
)

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.names = append(r.names, args.TypeToken+" "+args.Name)
	r.mu.Unlock()

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (r *recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func (f *fakeChains) DomainIntermediate(trustDomain, generation string) (estate.Chain, error) {
	return f.chain("domain " + trustDomain + " " + generation)
}

func (f *fakeChains) EnvironmentCA(environment, zone, generation string) (estate.Chain, error) {
	return f.chain("environment " + environment + " " + zone + " " + generation)
}

func (f *fakeChains) chain(what string) (estate.Chain, error) {
	f.mu.Lock()
	f.asked = append(f.asked, what)
	f.mu.Unlock()

	return estate.Chain{PEM: "-----BEGIN CERTIFICATE-----\n" + what + "\n-----END CERTIFICATE-----\n", ArtifactPath: "pki-roots/" + what}, nil
}

func deployOptions(chains estate.Chains) Options {
	return Options{
		Address: "https://bao.example.org",
		Login: apply.Login{
			Mount: model.RosterMount, Role: model.RosterRole,
			Token: func(context.Context) (string, error) { return "login-token", nil },
		},
		OIDCClientSecrets:    map[string]pulumi.StringInput{model.RosterUIClient: pulumi.String("ui-secret")},
		Chains:               chains,
		DomainCSROutputs:     map[string]string{"private": "privateCsr", "origin": "originCsr"},
		EnvironmentCSROutput: "environmentCsrs",
	}
}

// The stack applies the example estate under the names state holds: the
// restore role under its issuing mount's name, an unsigned identity
// CA bootstrapped under the name the apply adopts once it is signed, and the
// signed artifacts the ceremony committed for every external issuer.
func TestDeployAppliesUnderTheAdoptedNames(t *testing.T) {
	in := example.Inputs(t, "../testdata/contract.yaml")

	desired, err := estate.Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	mocks, chains := &recorder{}, &fakeChains{}

	err = pulumi.RunErr(func(c *pulumi.Context) error {
		return Deploy(c, &desired, deployOptions(chains))
	}, pulumi.WithMocks("example", "openbao-config", mocks))
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	for _, want := range []string{
		"vault:pkiSecret/secretBackendIntermediateCertRequest:SecretBackendIntermediateCertRequest pki-identity-beta-root-signed-csr",
		"vault:pkiSecret/secretBackendRole:SecretBackendRole alpha-pki-role-restore-check",
	} {
		if !slices.Contains(mocks.names, want) {
			t.Errorf("no %s among %d resources", want, len(mocks.names))
		}
	}

	for _, name := range mocks.names {
		if strings.HasSuffix(name, " example-private-2026-09-alpha-role-restore-check") {
			t.Errorf("%s registered under the apply's own name, not the one state holds", name)
		}
	}

	slices.Sort(chains.asked)

	if want := []string{
		"domain origin example-root-2026-09",
		"domain private example-root-2026-09",
		"environment alpha alpha.example.private example-root-2026-09",
	}; !slices.Equal(chains.asked, want) {
		t.Errorf("chains asked for %v, want %v", chains.asked, want)
	}
}

// Without a loader, or with a request output missing, the stack refuses.
func TestDeployRefuses(t *testing.T) {
	in := example.Inputs(t, "../testdata/contract.yaml")

	desired, err := estate.Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	for name, mutate := range map[string]func(*Options){
		"no chain loader":   func(o *Options) { o.Chains = nil },
		"no request output": func(o *Options) { delete(o.DomainCSROutputs, "origin") },
	} {
		t.Run(name, func(t *testing.T) {
			opts := deployOptions(&fakeChains{})
			mutate(&opts)

			err := pulumi.RunErr(func(c *pulumi.Context) error {
				return Deploy(c, &desired, opts)
			}, pulumi.WithMocks("example", "openbao-config", &recorder{}))
			if err == nil {
				t.Error("deployed; want a refusal")
			}
		})
	}
}

// secretKubectl answers `get secret` with the keys it holds, base64 the way
// the API returns them.
func secretKubectl(data map[string]string, fail error) apply.Kubectl {
	return func(_ context.Context, args ...string) ([]byte, error) {
		if fail != nil {
			return nil, fail
		}

		if len(args) < 2 || args[0] != "get" || args[1] != "secret" {
			return nil, fmt.Errorf("unexpected kubectl %s", strings.Join(args, " "))
		}

		for key, value := range data {
			if strings.HasSuffix(args[len(args)-1], "{.data."+key+"}") {
				return []byte(base64.StdEncoding.EncodeToString([]byte(value))), nil
			}
		}

		return nil, nil
	}
}

var delivered = apply.DeliveredSecret{Namespace: "openbao", Name: "ui-client", Hint: "deliver it first"}

func TestOIDCClientSecretReadsTheDeliveredSecret(t *testing.T) {
	got, err := OIDCClientSecret(context.Background(), secretKubectl(map[string]string{
		"client-id": "openbao-ui", "client-secret": "s3cr3t",
	}, nil), delivered, "openbao-ui")
	if err != nil || got != "s3cr3t" {
		t.Fatalf("OIDCClientSecret = %q, %v", got, err)
	}
}

// A missing Secret, an empty key, or another client's credential all stop
// the apply, and no error carries the secret.
func TestOIDCClientSecretRefusesWhatWouldFailAtSignIn(t *testing.T) {
	for name, kubectl := range map[string]apply.Kubectl{
		"not delivered": secretKubectl(nil, errors.New(`secrets "ui-client" not found`)),
		"empty secret":  secretKubectl(map[string]string{"client-id": "openbao-ui"}, nil),
		"other client":  secretKubectl(map[string]string{"client-id": "argocd", "client-secret": "s3cr3t"}, nil),
	} {
		_, err := OIDCClientSecret(context.Background(), kubectl, delivered, "openbao-ui")
		if err == nil {
			t.Errorf("%s: accepted", name)

			continue
		}

		if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: error leaks the secret: %v", name, err)
		}
	}
}

// The estate applied as two stacks -- the grants (policies, groups and
// aliases, roles) and everything else -- registers each resource of the
// whole exactly once, the provider in both, and bootstraps an unsigned
// identity CA only in the stack that holds its mount.
func TestDeploySplitIntoTwoStacks(t *testing.T) {
	in := example.Inputs(t, "../testdata/contract.yaml")

	desired, err := estate.Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	grants := map[string]bool{
		apply.TypePolicy: true, apply.TypeGroup: true, apply.TypeGroupAlias: true,
		apply.TypeJWTAuthBackendRole: true, apply.TypeAWSAuthBackendRole: true,
		apply.TypePKIRole: true, apply.TypeSSHRole: true,
	}

	run := func(selects func(apply.Resource) bool) []string {
		t.Helper()

		mocks := &recorder{}
		opts := deployOptions(&fakeChains{})
		opts.Select = selects

		if err := pulumi.RunErr(func(c *pulumi.Context) error {
			return Deploy(c, &desired, opts)
		}, pulumi.WithMocks("example", "openbao-config", mocks)); err != nil {
			t.Fatalf("deploy: %v", err)
		}

		return mocks.names
	}

	whole := run(nil)
	grantNames := run(func(r apply.Resource) bool { return grants[r.Type] })
	rest := run(func(r apply.Resource) bool { return !grants[r.Type] })

	const provider = "pulumi:providers:vault openbao"

	count := map[string]int{}
	for _, name := range append(append([]string{}, grantNames...), rest...) {
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

	const bootstrap = "vault:pkiSecret/secretBackendIntermediateCertRequest:SecretBackendIntermediateCertRequest pki-identity-beta-root-signed-csr"
	if slices.Contains(grantNames, bootstrap) || !slices.Contains(rest, bootstrap) {
		t.Errorf("the bootstrap request belongs to the stack holding its mount")
	}
}

// A selection that splits an unsigned identity CA's mount from its request
// is refused before anything is registered.
func TestDeployRefusesASplitBootstrapBeforeRegistering(t *testing.T) {
	in := example.Inputs(t, "../testdata/contract.yaml")

	desired, err := estate.Build(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	mocks := &recorder{}
	opts := deployOptions(&fakeChains{})
	opts.Select = func(r apply.Resource) bool { return r.Type != apply.TypePKIIntermediateCertRequest }

	err = pulumi.RunErr(func(c *pulumi.Context) error {
		return Deploy(c, &desired, opts)
	}, pulumi.WithMocks("example", "openbao-config", mocks))
	if err == nil || !strings.Contains(err.Error(), "select") {
		t.Fatalf("want a select refusal, got %v", err)
	}

	if len(mocks.names) != 0 {
		t.Errorf("%d resources registered before the refusal: %v", len(mocks.names), mocks.names)
	}
}
