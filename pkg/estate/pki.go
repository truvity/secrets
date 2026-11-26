package estate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/secrets/pkg/builder"
	"github.com/truvity/secrets/pkg/model"
	"github.com/truvity/secrets/pkg/pki"
)

// credentialCommonName is the only common name a credential PKI role signs:
// the caller's own subject, as its roster login recorded it.
const credentialCommonName = "roster-subject"

type (
	// PrivatePKI is the authority chain the server serves. Root and Domains
	// are the contract's (pkg/pki). Root is NOT a mount: its key lives
	// outside the server and signs exactly once, in the ceremony; the server
	// only holds the certificates it signed.
	PrivatePKI struct {
		// Root is the root generation the private domain is declared under:
		// with one active generation, the contract's root.
		Root RootAuthority `yaml:"root"`
		// Roots are the other active root generations some trust domain is
		// declared under, in authored order: empty with one root, one per
		// further party with a root of its own. Like Root, it is a VIEW for
		// a reader and a consumer: nothing is applied from it (a root's key
		// lives outside the server).
		Roots   []RootAuthority   `yaml:"roots,omitempty"`
		Domains []DomainAuthority `yaml:"domains"`
		// Pending are the domain intermediates the root has not signed yet
		// (PKI.PendingDomains): their mount, key and request alone.
		Pending []PendingDomain `yaml:"pending,omitempty"`
	}

	// PendingDomain is one DNS domain intermediate the root has not signed
	// yet: phase A of its ceremony, bootstrapped beside the apply under the
	// names the apply adopts once it is signed (pkg/estate/stack).
	PendingDomain struct {
		TrustDomain string `yaml:"trustDomain"`
		// Namespace is the domain's own namespace, empty for root.
		Namespace        string `yaml:"namespace,omitempty"`
		Mount            string `yaml:"mount"`
		MountDescription string `yaml:"mountDescription"`
		LeaseTTL         string `yaml:"leaseTtl"`
		KeyName          string `yaml:"keyName"`
		CommonName       string `yaml:"commonName"`
		Organization     string `yaml:"organization"`
		KeyCurve         string `yaml:"keyCurve"`
	}

	// RootAuthority is one active root generation of the contract.
	RootAuthority struct {
		GenerationID  string `yaml:"generationId"`
		CommonName    string `yaml:"commonName"`
		Organization  string `yaml:"organization"`
		Custody       string `yaml:"custody"`
		KeyCurve      string `yaml:"keyCurve"`
		TTL           string `yaml:"ttl"`
		MaxPathLength int    `yaml:"maxPathLength"`
		ArtifactPath  string `yaml:"artifactPath"`
	}

	// DomainAuthority is one trust domain's intermediate: the first CA under
	// the root, in a root-namespace mount, carrying the name constraint when
	// its domain has one.
	DomainAuthority struct {
		TrustDomain      string   `yaml:"trustDomain"`
		Mount            string   `yaml:"mount"`
		IssuerName       string   `yaml:"issuerName"`
		CommonName       string   `yaml:"commonName"`
		Organization     string   `yaml:"organization"`
		KeyCurve         string   `yaml:"keyCurve"`
		TTL              string   `yaml:"ttl"`
		MaxPathLength    int      `yaml:"maxPathLength"`
		PermittedDomains []string `yaml:"permittedDomains"`
		// PermittedURIDomains is a URI trust domain's shape of the same idea.
		PermittedURIDomains []string `yaml:"permittedUriDomains,omitempty"`
		// ArtifactPath is where the ceremony writes this intermediate's
		// signed certificate, and where the import reads it back.
		ArtifactPath string `yaml:"artifactPath"`
	}

	// IssuingCA is one environment's issuing CA in one trust domain, offering
	// the leaf roles the contract declares. Its key never leaves the
	// environment's namespace.
	IssuingCA struct {
		TrustDomain         string   `yaml:"trustDomain"`
		Mount               string   `yaml:"mount"`
		IssuerName          string   `yaml:"issuerName"`
		CommonName          string   `yaml:"commonName"`
		Organization        string   `yaml:"organization"`
		KeyCurve            string   `yaml:"keyCurve"`
		TTL                 string   `yaml:"ttl"`
		MaxPathLength       int      `yaml:"maxPathLength"`
		PermittedDomains    []string `yaml:"permittedDomains"`
		PermittedURIDomains []string `yaml:"permittedUriDomains,omitempty"`
		// External marks an issuing CA the root signs directly, outside the
		// server, never one signed by another issuer declared here.
		External bool `yaml:"external,omitempty"`
		// Policy grants sign on every role below it, and AuthRole is the
		// cert-manager login that carries that policy.
		Policy   string          `yaml:"policy"`
		AuthRole string          `yaml:"authRole"`
		Roles    []model.PKIRole `yaml:"roles"`
		// CredentialRoles sign people's CSRs. They sit on this issuer and are
		// granted to credential groups only, never to Policy.
		CredentialRoles []CredentialRole `yaml:"credentialRoles,omitempty"`
	}

	// CredentialRole is a PKI role that signs a person's CSR, on one of the
	// environment's issuing CAs: never cert-manager's.
	CredentialRole struct {
		Name string `yaml:"name"`
		// CommonName is what the certificate may be issued to: the caller's
		// own subject on SubjectMount, and nobody else's.
		CommonName    string   `yaml:"commonName"`
		SubjectMount  string   `yaml:"subjectMount"`
		CNValidations []string `yaml:"cnValidations"`
		// OU is the subject OU the role pins (empty = none).
		OU       string `yaml:"ou,omitempty"`
		Server   bool   `yaml:"server"`
		Client   bool   `yaml:"client"`
		KeyCurve string `yaml:"keyCurve"`
		TTL      string `yaml:"ttl"`
		MaxTTL   string `yaml:"maxTtl"`
	}
)

// configurePrivatePKI declares the whole authority chain: the root and the
// domain intermediates from the contract, and one issuing CA per trust
// domain in every environment namespace.
//
// Everything the contract declares is pkg/pki's derivation; what is this
// file's is the view of it, and the policies and cert-manager logins that
// carry each issuing CA's roles.
//
// It returns each environment's cert-manager logins, by environment name,
// which ride the environment's cluster mount after everything else on it.
func configurePrivatePKI(desired *Desired, inputs *Inputs, clusters []Cluster) (map[string][]builder.Workload, error) {
	in := &inputs.PKI
	contract := in.Contract
	if contract == nil {
		return nil, fmt.Errorf("estate: the private PKI contract is required")
	}

	generation, err := privateRoot(in)
	if err != nil {
		return nil, err
	}

	if len(desired.Namespaces) == 0 {
		return nil, fmt.Errorf("estate: private PKI has no environment namespaces")
	}

	byName := make(map[string]Cluster, len(clusters))
	for i := range clusters {
		byName[clusters[i].Name] = clusters[i]
	}

	if err := checkPKIDomains(in, desired, byName); err != nil {
		return nil, err
	}

	environments := make([]pki.Environment, 0, len(desired.Namespaces))

	for i := range desired.Namespaces {
		cluster, ok := byName[desired.Namespaces[i].Name]
		if !ok {
			return nil, fmt.Errorf("estate: namespace %s has no cluster inputs", desired.Namespaces[i].Name)
		}

		environment, err := pkiEnvironment(in, &cluster)
		if err != nil {
			return nil, err
		}

		environments = append(environments, environment)
	}

	derivation, err := contract.DeriveWith(environments, pki.DeriveOptions{PendingDomains: in.PendingDomains})
	if err != nil {
		return nil, fmt.Errorf("estate: %w", err)
	}

	desired.derivation = derivation
	desired.identityIssuers = map[string]string{}

	if identity := contract.URITrustDomain(in.Identity); identity != nil {
		for _, environment := range identity.Environments {
			desired.identityIssuers[environment] = identity.EnvironmentCAIssuerName(environment)
		}

		desired.identityRoles = []string{identity.Role.Name}
	}

	desired.PKI = PrivatePKI{Root: rootAuthority(contract, generation)}

	for _, other := range declaredRoots(contract) {
		if other.ID != generation.ID {
			desired.PKI.Roots = append(desired.PKI.Roots, rootAuthority(contract, other))
		}
	}

	for i := range derivation.Domains {
		domain := &derivation.Domains[i]

		desired.PKI.Domains = append(desired.PKI.Domains, DomainAuthority{
			TrustDomain:         domain.Domain,
			Mount:               domain.Mount,
			IssuerName:          domain.Issuer,
			CommonName:          domain.CommonName,
			Organization:        domain.Organization,
			KeyCurve:            domain.KeyCurve,
			TTL:                 domain.TTL,
			MaxPathLength:       domain.MaxPathLength,
			PermittedDomains:    slices.Clone(domain.PermittedDNSDomains),
			PermittedURIDomains: slices.Clone(domain.PermittedURIDomains),
			ArtifactPath:        domain.ArtifactPath,
		})
	}

	for i := range derivation.Pending {
		pending := &derivation.Pending[i]

		desired.PKI.Pending = append(desired.PKI.Pending, PendingDomain{
			TrustDomain:      pending.Domain,
			Namespace:        pending.Namespace,
			Mount:            pending.Mount,
			MountDescription: pending.MountDescription,
			LeaseTTL:         pending.LeaseTTL,
			KeyName:          pending.KeyName,
			CommonName:       pending.CommonName,
			Organization:     pending.Organization,
			KeyCurve:         pending.KeyCurve,
		})
	}

	logins := make(map[string][]builder.Workload, len(desired.Namespaces))

	if err := configureVendors(desired, inputs, derivation); err != nil {
		return nil, err
	}

	for i := range desired.Namespaces {
		namespace := &desired.Namespaces[i]

		for j := range derivation.Issuing {
			authority := &derivation.Issuing[j]
			if authority.Environment != namespace.Name || authority.Namespace != "" {
				continue
			}

			login, err := configureIssuingCA(inputs, namespace, authority)
			if err != nil {
				return nil, err
			}

			logins[namespace.Name] = append(logins[namespace.Name], login)
		}
	}

	return logins, nil
}

// checkPKIDomains refuses trust-domain inputs the derivation would read
// wrongly: the private and origin domains as one, a private domain that does
// not reach every cluster, a pending private or origin domain, a pending
// domain whose artifact is committed, and a DNS domain that lists an
// environment the estate has no cluster or namespace for. A URI domain's
// list is the URI domain's own business, as it always was: it may name an
// environment this estate does not build.
func checkPKIDomains(in *PKI, desired *Desired, clusters map[string]Cluster) error {
	if in.Private == in.Origin {
		return fmt.Errorf("estate: PKI.Private and PKI.Origin are both %q: they are two different trust domains", in.Private)
	}

	contract := in.Contract

	// The estate's own private, origin and identity domains stay in root:
	// the restore check, the identity CAs and the origin names rest on
	// them there. A party's further domains take namespaces of their own.
	for _, name := range []string{in.Private, in.Origin, in.Identity} {
		if namespace := vendorOf(contract, name); namespace != "" {
			return fmt.Errorf("estate: trust domain %s is the estate's own (PKI.Private, Origin or Identity) and stays in root, not in namespace %s",
				name, namespace)
		}
	}

	if err := checkPendingDomains(in); err != nil {
		return err
	}

	known := make(map[string]bool, len(clusters)+len(desired.Namespaces))
	for name := range clusters {
		known[name] = true
	}

	for i := range desired.Namespaces {
		known[desired.Namespaces[i].Name] = true
	}

	if private := contract.DNSTrustDomain(in.Private); private != nil {
		names := make([]string, 0, len(clusters))
		for name := range clusters {
			names = append(names, name)
		}

		slices.Sort(names)

		for _, name := range names {
			if !private.Reaches(name) {
				return fmt.Errorf("estate: the private domain %s does not reach cluster %s: it reaches every cluster", in.Private, name)
			}
		}
	}

	for i := range contract.TrustDomains.DNS {
		domain := &contract.TrustDomains.DNS[i]

		for _, environment := range domain.Environments {
			if !known[environment] {
				return fmt.Errorf("estate: dns trust domain %s lists environment %q, which is no cluster or namespace of the estate", domain.Name, environment)
			}
		}
	}

	return nil
}

// checkPendingDomains refuses a pending private or origin domain, and a
// pending domain whose intermediate's artifact is committed: listing a
// signed domain as pending would drop its issuing CAs, roles and logins.
func checkPendingDomains(in *PKI) error {
	if len(in.PendingDomains) == 0 {
		return nil
	}

	for _, name := range in.PendingDomains {
		if name == in.Private || name == in.Origin {
			return fmt.Errorf("estate: trust domain %s cannot be pending: the private and origin domains are signed before anything else", name)
		}

		// An unknown name is the derivation's to refuse.
		domain := in.Contract.DNSTrustDomain(name)
		if domain == nil {
			continue
		}

		spec, err := in.Contract.DNSIntermediateSpec(name, domain.RootGeneration)
		if err != nil {
			return fmt.Errorf("estate: pending domain %s: %w", name, err)
		}

		signed, err := in.Contract.IntermediateSigned(spec)
		if err != nil {
			return fmt.Errorf("estate: pending domain %s: %w", name, err)
		}

		if signed {
			return fmt.Errorf("estate: trust domain %s is pending, but its intermediate is committed at %s: drop it from PKI.PendingDomains", name, spec.ArtifactPath)
		}
	}

	return nil
}

// pkiEnvironment is one environment's inputs to the library's derivation:
// the zone each trust domain substitutes for {zone}, the names the origin
// role may sign, and whether the environment's own identity CA is signed.
func pkiEnvironment(in *PKI, cluster *Cluster) (pki.Environment, error) {
	privateZone, err := zoneOf(in, cluster, in.Private)
	if err != nil {
		return pki.Environment{}, err
	}

	environment := pki.Environment{
		Name: cluster.Name,
		Zones: map[string]string{
			in.Private: privateZone,
			// A workload's identity is a host in its environment's private
			// zone.
			in.Identity: privateZone,
		},
		Catalog: map[string][]string{
			pki.CatalogKey(in.Origin, in.OriginRole): slices.Clone(cluster.OriginNames),
		},
	}

	// The origin zone is needed only where the origin domain reaches.
	if origin := in.Contract.DNSTrustDomain(in.Origin); origin == nil || origin.Reaches(cluster.Name) {
		originZone, err := zoneOf(in, cluster, in.Origin)
		if err != nil {
			return pki.Environment{}, err
		}

		environment.Zones[in.Origin] = originZone
	}

	if err := furtherZones(in, cluster, environment.Zones); err != nil {
		return pki.Environment{}, err
	}

	// Until an environment's own identity CA is signed it renders NOTHING of
	// the identity domain: the bootstrap creates its mount and key alone.
	if !in.Signed[cluster.Name] {
		environment.PendingCAs = []string{in.Identity}
	}

	return environment, nil
}

// furtherZones adds to zones the zone of every DNS trust domain other than
// the private and origin ones that reaches the cluster, from
// Cluster.Zones. It refuses a domain that reaches the cluster with no zone,
// and an entry of Cluster.Zones that feeds no such domain: a zone nothing
// reads is a mistake in the inputs, not a default. A pending domain needs no
// zone yet, and its entry is kept for when it is signed.
func furtherZones(in *PKI, cluster *Cluster, zones map[string]string) error {
	fed := map[string]bool{}

	for i := range in.Contract.TrustDomains.DNS {
		domain := &in.Contract.TrustDomains.DNS[i]
		if domain.Name == in.Private || domain.Name == in.Origin || !domain.Reaches(cluster.Name) {
			continue
		}

		if slices.Contains(in.PendingDomains, domain.Name) {
			fed[domain.Name] = true

			continue
		}

		zone, err := zoneOf(in, cluster, domain.Name)
		if err != nil {
			return err
		}

		zones[domain.Name] = zone
		fed[domain.Name] = true
	}

	names := make([]string, 0, len(cluster.Zones))
	for name := range cluster.Zones {
		names = append(names, name)
	}

	slices.Sort(names)

	for _, name := range names {
		if !fed[name] {
			return fmt.Errorf("estate: cluster %s has a zone for %q, which is not a further dns trust domain that reaches it", cluster.Name, name)
		}
	}

	return nil
}

// configureIssuingCA records one derived issuing CA in its namespace's view,
// and returns the cert-manager login whose policy grants sign on every role
// below it.
func configureIssuingCA(inputs *Inputs, namespace *Namespace, authority *pki.Authority) (builder.Workload, error) {
	in := &inputs.PKI
	clusterIssuer, ok := in.ClusterIssuers[authority.Domain]
	if !ok {
		return builder.Workload{}, fmt.Errorf("estate: trust domain %q has no cluster issuer", authority.Domain)
	}

	policy := in.PolicyPrefix + clusterIssuer

	roles := make([]model.PKIRole, 0, len(authority.Roles))
	signs := make([]builder.Clause, 0, len(authority.Roles))

	for i := range authority.Roles {
		role := authority.Roles[i]
		// The model's issuer is filled when the view becomes the model.
		role.Issuer = ""

		roles = append(roles, role)
		signs = append(signs, builder.Sign(authority.Mount, role.Name))
	}

	credentials := make([]CredentialRole, 0, len(authority.CredentialRoles))

	for i := range authority.CredentialRoles {
		role := &authority.CredentialRoles[i]
		credentials = append(credentials, CredentialRole{
			Name:          role.Name,
			CommonName:    credentialCommonName,
			SubjectMount:  role.SubjectMount,
			CNValidations: slices.Clone(role.CNValidations),
			OU:            role.OU,
			Server:        role.Server,
			Client:        role.Client,
			KeyCurve:      role.KeyCurve,
			TTL:           role.TTL,
			MaxTTL:        role.MaxTTL,
		})
	}

	namespace.IssuingCAs = append(namespace.IssuingCAs, IssuingCA{
		TrustDomain:         authority.Domain,
		Mount:               authority.Mount,
		IssuerName:          authority.Issuer,
		CommonName:          authority.CommonName,
		Organization:        authority.Organization,
		KeyCurve:            authority.KeyCurve,
		TTL:                 authority.TTL,
		MaxPathLength:       authority.MaxPathLength,
		PermittedDomains:    slices.Clone(authority.PermittedDNSDomains),
		PermittedURIDomains: slices.Clone(authority.PermittedURIDomains),
		External:            authority.External,
		Policy:              policy,
		AuthRole:            clusterIssuer,
		Roles:               roles,
		CredentialRoles:     credentials,
	})

	return certManagerLogin(inputs, clusterIssuer, policy, in.AudiencePrefix+clusterIssuer, signs...), nil
}

// configureVendors declares the parties' namespaces of the domains that have
// one: `<vendor>` for each, then `<vendor>/<env>` for each environment one
// of its domains reaches, holding that environment's issuing CAs and the
// cert-manager logins that sign through them.
func configureVendors(desired *Desired, inputs *Inputs, derivation *pki.Derivation) error {
	desired.vendorLogins = map[string][]builder.Workload{}

	at := func(path string) *Namespace {
		for i := range desired.Vendors {
			if desired.Vendors[i].Name == path {
				return &desired.Vendors[i]
			}
		}

		desired.Vendors = append(desired.Vendors, Namespace{Name: path})

		return &desired.Vendors[len(desired.Vendors)-1]
	}

	for _, name := range inputs.PKI.Contract.TrustDomainNames() {
		if namespace := vendorOf(inputs.PKI.Contract, name); namespace != "" {
			at(namespace)
		}
	}

	for i := range derivation.Issuing {
		authority := &derivation.Issuing[i]
		if authority.Namespace == "" {
			continue
		}

		path := authority.NamespacePath()

		login, err := configureIssuingCA(inputs, at(path), authority)
		if err != nil {
			return err
		}

		desired.vendorLogins[path] = append(desired.vendorLogins[path], login)
	}

	// Each party's own namespace, then its children, in the order they
	// were met: a child is made inside its parent, after it.
	ordered := make([]Namespace, 0, len(desired.Vendors))

	for i := range desired.Vendors {
		parent := desired.Vendors[i].Name
		if strings.Contains(parent, "/") {
			continue
		}

		ordered = append(ordered, desired.Vendors[i])

		for j := range desired.Vendors {
			if strings.HasPrefix(desired.Vendors[j].Name, parent+"/") {
				ordered = append(ordered, desired.Vendors[j])
			}
		}
	}

	desired.Vendors = ordered

	return nil
}

func vendorOf(contract *pki.Contract, domain string) string {
	if d := contract.DNSTrustDomain(domain); d != nil {
		return d.Namespace
	}

	if d := contract.URITrustDomain(domain); d != nil {
		return d.Namespace
	}

	return ""
}

// certManagerLogin is one role on the environment's cluster mount:
// cert-manager's ServiceAccount, one audience, one policy granting sign on
// the paths given.
func certManagerLogin(in *Inputs, role, policy, audience string, signs ...builder.Clause) builder.Workload {
	return builder.Workload{Role: role, Subject: in.PKI.Subject, Audience: audience, TTL: in.Names.TokenTTL, Policy: policy, Access: signs}
}

// ActiveGeneration is the contract's one active root generation. A contract
// with several active generations (one root per party) has no such one: ask
// for a trust domain's own with [pki.Contract.TrustDomainRoot].
func ActiveGeneration(contract *pki.Contract) (*pki.RootGeneration, error) {
	active := contract.ActiveGenerations()

	switch len(active) {
	case 0:
		return nil, fmt.Errorf("estate: the PKI contract declares no active root generation")
	case 1:
		return active[0], nil
	}

	ids := make([]string, 0, len(active))
	for _, generation := range active {
		ids = append(ids, generation.ID)
	}

	return nil, fmt.Errorf("estate: the PKI contract has %d active root generations (%s): ask for a trust domain's own root",
		len(active), strings.Join(ids, ", "))
}

// privateRoot is the root generation the view's Root shows: the private
// domain's, or, with no private domain named, the one active generation.
func privateRoot(in *PKI) (*pki.RootGeneration, error) {
	if in.Private != "" && in.Contract.DNSTrustDomain(in.Private) != nil {
		generation, err := in.Contract.TrustDomainRoot(in.Private)
		if err != nil {
			return nil, fmt.Errorf("estate: %w", err)
		}

		return generation, nil
	}

	return ActiveGeneration(in.Contract)
}

// declaredRoots are the root generations some trust domain is declared
// under, in authored order.
func declaredRoots(contract *pki.Contract) []*pki.RootGeneration {
	var roots []*pki.RootGeneration

	for i := range contract.Generations {
		generation := &contract.Generations[i]
		if contract.DeclaresUnder(generation.ID) {
			roots = append(roots, generation)
		}
	}

	return roots
}

func rootAuthority(contract *pki.Contract, generation *pki.RootGeneration) RootAuthority {
	return RootAuthority{
		GenerationID:  generation.ID,
		CommonName:    generation.Certificate.Subject.CommonName,
		Organization:  generation.Certificate.Subject.Organization,
		Custody:       generation.Custody.Provider,
		KeyCurve:      contract.Global.KeyCurve,
		TTL:           generation.Lifetime,
		MaxPathLength: generation.Certificate.MaxPathLen,
		ArtifactPath:  contract.RootArtifactPath(generation.ID),
	}
}

// zoneOf is the zone a trust domain substitutes for {zone} on one cluster:
// the private zone for the private domain, the origin zone for the origin
// domain, and the cluster's own entry in Zones for any other.
func zoneOf(in *PKI, cluster *Cluster, trustDomain string) (string, error) {
	var zone string

	switch trustDomain {
	case in.Private:
		zone = cluster.PrivateZone
	case in.Origin:
		zone = cluster.OriginZone
	default:
		zone = cluster.Zones[trustDomain]
	}

	if strings.TrimSpace(zone) == "" {
		return "", fmt.Errorf("estate: cluster %s has no %s zone", cluster.Name, trustDomain)
	}

	return zone, nil
}
