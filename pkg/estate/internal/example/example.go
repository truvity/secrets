// Package example is a small estate with made-up names, for the tests of
// pkg/estate and its stack.
package example

import (
	"slices"
	"strings"
	"testing"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/estate"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

// Inputs is a small estate with made-up names: three clusters, ops
// the management one, every kind of input once.
func Inputs(t testing.TB, contractPath string) estate.Inputs {
	t.Helper()

	contract, err := pki.Load(contractPath)
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}

	sa := model.ServiceAccountSubject

	return estate.Inputs{
		Management: "ops",
		Names: estate.Names{
			KVMount: "kv", Canary: "canary", OperatorKV: "operators", Operators: "all:openbao:operator",
			ClusterMountPrefix: "jwt-", WriterMount: "jwt-ops", RootMount: "jwt-ops",
			StoreSubject: sa("external-secrets", "external-secrets"),
			TokenTTL:     "15m", NamespaceTokenTTL: "1h", CredentialMaxTTL: "1h",
			Metadata: map[string]string{"source": "example"},
			Jobs: estate.Jobs{
				RestoreCheck:   estate.Job{Role: "restore-check", Subject: sa("openbao", "restore-check"), Policy: "restore-check"},
				Snapshot:       estate.Job{Role: "snapshot", Subject: sa("openbao", "snapshot"), Policy: "snapshot"},
				RootGeneration: estate.Job{Role: "root-generation", Subject: sa("openbao", "root-generation"), Policy: "root-generation"},
				PluginCatalog:  estate.Job{Role: "plugin-catalog", Subject: sa("openbao", "plugin-catalog"), Policy: "plugin-catalog"},
				PluginType:     "auth", PluginName: "aws",
			},
			SSH: estate.SSHNames{
				Shape: builder.SSHShape{
					UserKeyType: "ed25519", HostKeyType: "ed25519", KeyIDFormat: "{{token_display_name}}", Extension: "permit-pty",
					UserTTL: "1h", UserMaxTTL: "1h", HostTTL: "24h", HostMaxTTL: "24h",
				},
				Mount: "ssh", CAKeyType: "ed25519", HostMount: "ssh-host", HostKeyType: "ed25519",
				UserRole: "user", UserPrincipal: "ops", CIRole: "ci", CIPrincipal: "builder", CIForceCommand: "builder-serve",
			},
			Workers: estate.Workers{
				LoginRole: "worker-host", Subject: sa("builders", "worker"), TTL: "15m", Policy: "worker-sign",
				HostRole: "worker", Domains: []string{"builders.example.internal"},
			},
			HostAuth: estate.HostAuthNames{Mount: "aws", PluginVersion: "v0.1.0", TTL: "15m"},
		},
		Text: estate.Text{
			OperatorKV: "operators only", EnvironmentKV: "the {env} secrets", ProjectKV: "the {project} secrets",
			SSHUser: "the {env} SSH user CA", SSHHostWorkers: "the {env} workers' host CA", SSHHostFleets: "the {env} fleets' host CA",
			HostAuth: "the {env} fleets' instance roles", IdentityBootstrap: "{env} identity CA",
		},
		Groups: estate.Groups{
			Name: func(env, thing, role string) string { return env + ":" + thing + ":" + role },
			Holds: func(group string) bool {
				return !strings.HasSuffix(group, ":viewer") || strings.HasPrefix(group, "alpha:")
			},
			OpenBAO: "openbao", Writer: "writer", SSH: "ssh", SSHUser: "user", Database: "db", DatabaseClient: "client",
			Deployer: "deployer", Approver: "approver", Viewer: "viewer", DBA: "dba",
		},
		Roster: model.Roster{
			Issuer: "https://id.example.org", TTL: "1h", ClaimMappings: map[string]string{"email": "email"},
			UI: &model.RosterUI{RedirectURIs: []string{"https://bao.example.org/ui/vault/auth/oidc/oidc/callback"}},
		},
		Clusters: []estate.Cluster{
			{
				Name: "beta", Issuer: "https://oidc.example.org/beta", Stores: []string{"app"},
				PrivateZone: "beta.example.private", OriginZone: "beta.example.net", OriginNames: []string{"shop.example.net"},
			},
			{
				Name: "alpha", Issuer: "https://oidc.example.org/alpha", Stores: []string{"app", "app"}, Workers: true,
				Runners:     []estate.Runner{{Role: "runner-b", Subject: sa("runners", "b")}, {Role: "runner-a", Subject: sa("runners", "a")}},
				PrivateZone: "alpha.example.private", OriginZone: "alpha.example.net", OriginNames: []string{"*.alpha.example.net"},
			},
			{
				Name: "ops", Issuer: "https://oidc.example.org/ops", Stores: []string{"app", "platform"},
				PrivateZone: "ops.example.private", OriginZone: "ops.example.net", OriginNames: []string{"console.example.net"},
			},
		},
		Projects:          map[string][]string{"shop": {"alpha", "beta"}},
		ProjectSecrets:    map[string][]string{"shop": {"alpha"}, "team": {"alpha"}},
		ProjectViewers:    map[string][]string{"team": {"alpha"}},
		ProjectNamespaces: []string{"alpha"},
		Writers:           []estate.Writer{{Name: "writer", Subject: sa("platform", "writer"), Prefixes: map[string][]string{"ops": {"backup"}, "alpha": {"apps"}}}},
		Exporters:         []estate.Writer{{Name: "exporter", Subject: sa("platform", "exporter"), Prefixes: map[string][]string{"ops": {"apps", "exports"}}}},
		Service: estate.Service{
			Role: "svc", Subject: sa("svc", "svc"), Root: "svc", Writes: map[string][]string{"ops": {"svc/private", "svc/export"}},
			ConfigRole: "svc-config", ConfigPrefix: "svc/config", ConfigIn: []string{"ops"},
			ClientsRole: "svc-clients", ClientsKind: "clients", Clients: []string{"console"},
			Exports: []estate.Export{{Role: "svc-export-app", Prefix: "svc/export/app", Environments: []string{"ops"}}},
		},
		CrossReads: []estate.CrossRead{{Role: "metrics-reader", Key: "metrics/write-token", Environments: []string{"beta"}}},
		CISecrets:  []builder.SecretGrant{{Policy: "ci-npm", Path: "ci/npm", Groups: []string{"acme:widget:publish"}}},
		Stores: estate.Stores{
			HasLayout:    func(kind string) bool { return kind != "unknown" },
			Access:       map[string]builder.Access{"platform": {builder.Key("platform/one-*")}},
			PolicyPrefix: "eso-",
		},
		PKI: estate.PKI{
			Contract: contract, Private: "private", Origin: "origin", Identity: "identity", OriginRole: "origin",
			Signed:         map[string]bool{"alpha": true},
			ClusterIssuers: map[string]string{"private": "private-ca", "origin": "origin-ca", "identity": "identity-ca"},
			PolicyPrefix:   "pki-", AudiencePrefix: "openbao-", Subject: sa("cert-manager", "cert-manager"),
			DBClientRole: "db-client", RestoreRole: "restore-check", BootstrapSuffix: "-root-signed",
			LegacyRoleIssuers: map[string]string{"alpha": "example-identity-old-alpha"},
		},
		HostFleets: []estate.HostFleet{{
			Environment: "beta", Name: "edge", Domain: "edge.example.net", InstanceRoleARN: "arn:aws:iam::111122223333:role/beta-edge",
			AuthRole: "edge-host", SigningRole: "edge", Policy: "edge-sign", ServerID: "bao.beta.example.org",
		}},
	}
}

// VendorDomain is the further DNS trust domain [WithVendorDomain] adds.
const VendorDomain = "vendor-a"

// WithVendorDomain adds to in a further DNS trust domain, vendor-a.example,
// shaped like the private one and reaching the given clusters (every
// cluster when none is given), with its own mount, intermediate and
// cluster issuer, and each listed cluster's zone for it.
func WithVendorDomain(t testing.TB, in *estate.Inputs, clusters ...string) {
	t.Helper()

	contract := in.PKI.Contract

	private := contract.DNSTrustDomain(in.PKI.Private)
	if private == nil {
		t.Fatal("the example contract has no private domain")
	}

	role := private.Roles[0]
	role.Name = VendorDomain

	contract.TrustDomains.DNS = append(contract.TrustDomains.DNS, pki.DNSTrustDomain{
		Name:           VendorDomain,
		Suffix:         "vendor-a.example",
		RootGeneration: private.RootGeneration,
		Environments:   clusters,
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

	in.PKI.ClusterIssuers[VendorDomain] = "vendor-a-ca"

	for i := range in.Clusters {
		cluster := &in.Clusters[i]
		if len(clusters) != 0 && !slices.Contains(clusters, cluster.Name) {
			continue
		}

		cluster.Zones = map[string]string{VendorDomain: cluster.Name + ".vendor-a.example"}
	}
}

// VendorRoot is the root generation [WithVendorRoot] adds.
const VendorRoot = "vendor-a-root-2026-11"

// WithVendorRoot moves the vendor domain ([WithVendorDomain], which it must
// follow) under a root of its own, in an account of its own: two active
// roots, one per party.
func WithVendorRoot(t testing.TB, in *estate.Inputs) {
	t.Helper()

	contract := in.PKI.Contract

	generation := contract.Generations[0]
	generation.ID = VendorRoot
	generation.Certificate.Subject = pki.Subject{CommonName: "Vendor A Private Root 2026-11", Organization: "Vendor A"}
	generation.Custody.AccountID = "444455556666"
	generation.Custody.Profile = "vendor-a-root@admin"
	generation.Custody.TrustedPrincipalARNPattern = "arn:aws:iam::444455556666:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_role-admin_*"
	generation.State = pki.GenerationActive

	contract.Generations = append(contract.Generations, generation)
	contract.Migration.TrustedGenerations = append(contract.Migration.TrustedGenerations, VendorRoot)

	vendor := contract.DNSTrustDomain(VendorDomain)
	if vendor == nil {
		t.Fatal("WithVendorRoot needs WithVendorDomain first")
	}

	vendor.RootGeneration = VendorRoot
	vendor.DomainIntermediate.Subject.Organization = "Vendor A"

	if err := contract.Validate(); err != nil {
		t.Fatalf("the contract with a vendor root does not validate: %v", err)
	}
}

// VendorNamespace is the party namespace [WithVendorNamespace] gives the
// vendor domain.
const VendorNamespace = "vendor-a"

// WithVendorNamespace puts the vendor domain ([WithVendorDomain], which it
// must follow) in a party namespace of its own, with the parties' doors
// when doors is true.
func WithVendorNamespace(t testing.TB, in *estate.Inputs, doors bool) {
	t.Helper()

	vendor := in.PKI.Contract.DNSTrustDomain(VendorDomain)
	if vendor == nil {
		t.Fatal("WithVendorNamespace needs WithVendorDomain first")
	}

	vendor.Namespace = VendorNamespace

	if err := in.PKI.Contract.Validate(); err != nil {
		t.Fatalf("the contract with a vendor namespace does not validate: %v", err)
	}

	if doors {
		in.PKI.VendorDoors = &estate.VendorDoors{
			Mount:    "jwt-pki",
			Role:     "pki-admin",
			Audience: "{env}:openbao:{vendor}",
			Groups: []string{
				"{env}:{vendor}:pki:internal:deployer", "{env}:{vendor}:pki:internal:sre", "{env}:{vendor}:pki:internal:ci",
			},
			UserClaim:   "sub",
			GroupsClaim: "groups",
			TTL:         "15m",
			// The fixture's clusters are ops, alpha and beta; the
			// intermediate's door admits beta's groups.
			IntermediateEnvironment: "beta",
		}
	}
}
