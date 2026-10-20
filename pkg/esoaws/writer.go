package esoaws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// KindWriters is the type token of the writers component.
const KindWriters = "truvity:secrets/esoaws:Writers"

// The SSM and KMS actions External Secrets' Parameter Store provider calls
// when it pushes a SecureString (checked against v2.13.0, providers/v1/aws/
// parameterstore): GetParameter with decryption to compare the stored value,
// ListTagsForResource to check that it manages the parameter, PutParameter to
// write, AddTagsToResource to tag a parameter it created, and KMS Encrypt,
// Decrypt and GenerateDataKey for the SecureString. It never deletes a
// parameter unless a PushSecret asks (deletionPolicy Delete), which this
// package does not grant.
var (
	writerSSMActions = []string{"ssm:AddTagsToResource", "ssm:GetParameter", "ssm:ListTagsForResource", "ssm:PutParameter"}
	writerKMSActions = []string{"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"}
)

type (
	// WritersArgs configures NewWriters, which runs in the account that holds
	// the parameters and the cluster: a writer role is one narrow exception to
	// the reader-only rule, and its trusted principal (the cluster identity)
	// is in the same account.
	WritersArgs struct {
		// Name is the component's logical name.
		Name string
		// Provider is the AWS provider of the account. Required.
		Provider pulumi.ProviderResource
		// AccountID, Region and Partition (empty: DefaultPartition) are the
		// account and region every parameter ARN a grant's policy names is
		// built in.
		AccountID string
		Region    string
		Partition string
		// Clusters are the clusters whose External Secrets write here; each
		// must be in PodIdentityMode. A writer on a WebIdentity cluster is
		// refused: the stores of such a cluster each carry their own
		// ServiceAccount and the chart renders no writer store for it.
		Clusters []Cluster
		// Grants are the writer roles, one per grant. At least one.
		Grants []WriteGrant
		// PermissionsBoundary is the boundary policy's ARN put on every
		// writer role; empty sets none.
		PermissionsBoundary string
		// Tags are put on every writer role.
		Tags map[string]string
	}

	// WriteGrant is one writer role: which cluster may assume it, and the one
	// prefix it writes.
	WriteGrant struct {
		// Name is the IAM role's name, its logical name and its key in
		// Writers.RoleARNs. The inline policy is "<Name>-policy".
		Name string
		// Cluster is the Name of the Cluster whose External Secrets assume
		// the role.
		Cluster string
		// Prefix is the parameter path the role writes, ending in "/"
		// ("/app/client/": every parameter under that path, at any depth).
		// Exactly one, with at least one segment: never "/", never a
		// wildcard. The chart's writer store pins the same prefix.
		Prefix string
		// KMSKeyARN is the customer-managed key the parameters are
		// SecureStrings of, as a known string. Exactly one of KMSKeyARN and
		// KMSKey is required: a writer of the account's default
		// aws/ssm key would let every principal of the account that may call
		// SSM read what it writes. The role gets Encrypt, Decrypt and
		// GenerateDataKey on it, through SSM only and for these parameters
		// only; the key's own policy must admit the role too
		// (Writers.KeyPolicyStatement).
		KMSKeyARN string
		// KMSKey is the same key as an output of the program that makes it
		// (a kms.Key's Arn), resolved at apply and checked then like
		// KMSKeyARN. The role's policy waits for it.
		KMSKey pulumi.StringInput
	}

	// Writers is the writer side: one writer role per grant.
	Writers struct {
		pulumi.ResourceState

		// RoleARNs is each grant's role ARN by grant name: the `role` of the
		// cluster's writer store.
		RoleARNs map[string]pulumi.StringOutput
	}
)

func (a WritersArgs) withDefaults() WritersArgs {
	if a.Partition == "" {
		a.Partition = DefaultPartition
	}

	return a
}

// readers is the part of the arguments the reader-side validation reads: the
// account, region and partition, and the clusters.
func (a WritersArgs) readers() ReadersArgs {
	return ReadersArgs{
		AccountID: a.AccountID, Region: a.Region, Partition: a.Partition,
		Clusters: a.Clusters, PermissionsBoundary: a.PermissionsBoundary,
	}.withDefaults()
}

func (a WritersArgs) validate() error {
	var errs []error

	if a.Name == "" {
		errs = append(errs, errors.New("args.Name is empty"))
	}

	if a.Provider == nil {
		errs = append(errs, errors.New("args.Provider is nil"))
	}

	if len(a.Grants) == 0 {
		errs = append(errs, errors.New("args.Grants is empty: a component that grants nothing should not be declared"))
	}

	r := a.readers()
	if err := r.validateSource(); err != nil {
		return errors.Join(append(errs, err)...)
	}

	var (
		names  = map[string]bool{}
		prefix = map[string]string{}
		used   = map[string]bool{}
	)

	for i, c := range r.Clusters {
		if err := r.validateCluster(c); err != nil {
			errs = append(errs, fmt.Errorf("args.Clusters[%d] (%s): %w", i, c.Name, err))

			continue
		}

		if c.Mode != PodIdentityMode {
			errs = append(errs, fmt.Errorf("args.Clusters[%d] (%s): a writer role trusts a PodIdentity cluster's controller identity; %s has none", i, c.Name, c.Mode))
		}
	}

	for i, g := range a.Grants {
		if names[g.Name] {
			errs = append(errs, fmt.Errorf("args.Grants[%d]: duplicate name %q", i, g.Name))
		}

		names[g.Name] = true
		used[g.Cluster] = true

		if other, ok := prefix[g.Prefix]; ok && g.Prefix != "" {
			errs = append(errs, fmt.Errorf("args.Grants[%d] (%s): prefix %q is grant %s's already; one role per prefix", i, g.Name, g.Prefix, other))
		}

		prefix[g.Prefix] = g.Name

		if err := a.validateGrant(g); err != nil {
			errs = append(errs, fmt.Errorf("args.Grants[%d] (%s): %w", i, g.Name, err))
		}
	}

	for i, c := range a.Clusters {
		if c.Name != "" && !used[c.Name] {
			errs = append(errs, fmt.Errorf("args.Clusters[%d]: no grant names cluster %q; drop it", i, c.Name))
		}
	}

	return errors.Join(errs...)
}

// validateGrant checks one grant: its name, its cluster, its prefix and its
// key.
func (a WritersArgs) validateGrant(g WriteGrant) error {
	var errs []error

	if !roleNameRe.MatchString(g.Name) {
		errs = append(errs, fmt.Errorf("grant.Name %q is not an IAM role name (1 to 64 of A-Z a-z 0-9 +=,.@_-)", g.Name))
	}

	if _, ok := a.readers().cluster(g.Cluster); !ok {
		errs = append(errs, fmt.Errorf("grant.Cluster %q is not in args.Clusters", g.Cluster))
	}

	if _, err := a.writePrefix(g.Prefix); err != nil {
		errs = append(errs, err)
	}

	switch {
	case g.KMSKeyARN != "" && g.KMSKey != nil:
		errs = append(errs, errors.New("grant.KMSKeyARN and grant.KMSKey are both set: name the key once"))
	case g.KMSKeyARN == "" && g.KMSKey == nil:
		errs = append(errs, errors.New("grant.KMSKeyARN (or KMSKey) is required: what a writer writes on the default aws/ssm key "+
			"is readable by every principal of the account that may call SSM"))
	case g.KMSKeyARN != "":
		if err := a.readers().checkKey(g.KMSKeyARN); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writePrefix validates a grant's prefix and returns its path without the
// leading slash and the trailing "/".
func (a WritersArgs) writePrefix(p string) (string, error) {
	switch {
	case !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/"):
		return "", fmt.Errorf("grant.Prefix %q: start and end with \"/\" (a hierarchical path, e.g. /app/client/)", p)
	case strings.ContainsAny(p, "*?"):
		return "", fmt.Errorf("grant.Prefix %q: no wildcards", p)
	case strings.Trim(p, "/") == "":
		return "", fmt.Errorf("grant.Prefix %q is every parameter in the account; name a path", p)
	case strings.Contains(p, "//") || !parameterRe.MatchString(p[1:]):
		return "", fmt.Errorf("grant.Prefix %q is not a parameter path (letters, digits, '.', '-', '_' and '/', no empty segment)", p)
	}

	return strings.TrimSuffix(p[1:], "/"), nil
}

func (a WritersArgs) parameterARN(resource string) string {
	return fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/%s", a.Partition, a.Region, a.AccountID, resource)
}

// WriterTrustPolicy is a grant's trust document: exactly the cluster
// identity's role, for sts:AssumeRole and for the transitive session tags
// EKS Pod Identity sets, and no other tag keys. It is the reader's trust
// (ReaderTrustPolicy) for a PodIdentity cluster.
func WriterTrustPolicy(args WritersArgs, grant WriteGrant) (string, error) {
	args = args.withDefaults()

	r := args.readers()
	if err := r.validateSource(); err != nil {
		return "", err
	}

	c, ok := r.cluster(grant.Cluster)
	if !ok {
		return "", fmt.Errorf("grant.Cluster %q is not in args.Clusters", grant.Cluster)
	}

	if err := r.validateCluster(c); err != nil {
		return "", fmt.Errorf("cluster %s: %w", c.Name, err)
	}

	if c.Mode != PodIdentityMode {
		return "", fmt.Errorf("cluster %s is %s: a writer role trusts a PodIdentity controller identity", c.Name, c.Mode)
	}

	return jsonDoc(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{{
		"Sid":       "ExternalSecretsOperator",
		"Effect":    "Allow",
		"Principal": map[string]any{"AWS": c.PodIdentity.RoleARN},
		"Action":    []string{"sts:AssumeRole", "sts:TagSession"},
		"Condition": map[string]any{"ForAllValues:StringEquals": tagKeysCondition()},
	}}})
}

// WriterPolicy is a grant's permission document, built in the account and
// region of the arguments: the SSM actions a push calls, on the parameters
// under the grant's prefix and nowhere else (no delete, no read of any other
// path, no DescribeParameters), and Encrypt, Decrypt and GenerateDataKey on
// the grant's key through SSM in this region, for the same parameters. It
// validates the source and the grant first. A document over
// MaxInlinePolicySize is an error.
func WriterPolicy(args WritersArgs, grant WriteGrant) (string, error) {
	args = args.withDefaults()

	if err := args.readers().validateSource(); err != nil {
		return "", err
	}

	if err := args.validateGrant(grant); err != nil {
		return "", err
	}

	if grant.KMSKey != nil {
		return "", errors.New("grant.KMSKey is an output that is known at apply: NewWriters builds the policy then; " +
			"WriterPolicy takes the key as a string (KMSKeyARN)")
	}

	return args.writerPolicy(grant, grant.KMSKeyARN)
}

// writerKeyOutput builds the policy of a grant whose key is an output of the
// program: at apply, where the key's ARN is known. The ARN is the key's own, so
// it is checked only for being an ARN without a wildcard (a mocked program's ARNs
// are not real ones; a real key's is whatever KMS made).
func (a WritersArgs) writerKeyOutput(grant WriteGrant) pulumi.StringInput {
	return grant.KMSKey.ToStringOutput().ApplyT(func(keyARN string) (string, error) {
		if !strings.HasPrefix(keyARN, "arn:") || strings.ContainsAny(keyARN, "*?") {
			return "", fmt.Errorf("grant %s: the key's ARN %q is not an ARN", grant.Name, keyARN)
		}

		return a.writerPolicy(grant, keyARN)
	}).(pulumi.StringOutput)
}

// writerPolicy is the document, for a grant already validated and its key.
func (a WritersArgs) writerPolicy(grant WriteGrant, keyARN string) (string, error) {
	path, _ := a.writePrefix(grant.Prefix)
	params := a.parameterARN(path + "/*")

	doc, err := jsonDoc(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{
		{
			"Sid":      "WriteParameters",
			"Effect":   "Allow",
			"Action":   writerSSMActions,
			"Resource": []string{params},
		},
		{
			"Sid":      "EncryptParameters",
			"Effect":   "Allow",
			"Action":   writerKMSActions,
			"Resource": keyARN,
			"Condition": map[string]any{
				"StringEquals": map[string]any{"kms:ViaService": viaSSM(a.Region, a.Partition)},
				"StringLike":   map[string]any{"kms:EncryptionContext:PARAMETER_ARN": []string{params}},
			},
		},
	}})
	if err != nil {
		return "", err
	}

	return doc, checkSize(fmt.Sprintf("writer %s's policy", grant.Name), doc)
}

// WriterKeyPolicyStatement is the statement a customer-managed key's policy
// needs for a grant's role, in the shape the account's other key policies use
// (a statement for the account root narrowed by aws:PrincipalArn, so the role
// need not exist when the key is made): the same actions as the role's
// policy, through SSM only and for the grant's parameters only. The key's
// policy must not also let the account's other principals use the key through
// SSM, or the key is no better than aws/ssm. It validates the source and the
// grant first.
func WriterKeyPolicyStatement(args WritersArgs, grant WriteGrant) (map[string]any, error) {
	args = args.withDefaults()

	if err := args.readers().validateSource(); err != nil {
		return nil, err
	}

	if err := args.validateGrant(grant); err != nil {
		return nil, err
	}

	path, _ := args.writePrefix(grant.Prefix)

	return map[string]any{
		"Sid":       "ExternalSecretsWriter" + sidOf(grant.Name),
		"Effect":    "Allow",
		"Principal": map[string]any{"AWS": fmt.Sprintf("arn:%s:iam::%s:root", args.Partition, args.AccountID)},
		"Action":    writerKMSActions,
		"Resource":  "*",
		"Condition": map[string]any{
			"ArnEquals":    map[string]any{"aws:PrincipalArn": fmt.Sprintf("arn:%s:iam::%s:role/%s", args.Partition, args.AccountID, grant.Name)},
			"StringEquals": map[string]any{"kms:ViaService": viaSSM(args.Region, args.Partition)},
			"StringLike":   map[string]any{"kms:EncryptionContext:PARAMETER_ARN": []string{args.parameterARN(path + "/*")}},
		},
	}, nil
}

// sidOf turns a role name into the alphanumerics a policy Sid takes.
func sidOf(name string) string {
	var b strings.Builder

	up := true

	for _, r := range name {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			if up && r >= 'a' && r <= 'z' {
				r -= 'a' - 'A'
			}

			b.WriteRune(r)

			up = false
		default:
			up = true
		}
	}

	return b.String()
}

func viaSSM(region, partition string) string {
	suffix := "amazonaws.com"
	if strings.HasPrefix(partition, "aws-cn") {
		suffix = "amazonaws.com.cn"
	}

	return "ssm." + region + "." + suffix
}

// NewWriters registers the component and one writer role per grant. It
// registers nothing and returns an error when args are invalid.
func NewWriters(ctx *pulumi.Context, args WritersArgs, opts ...pulumi.ResourceOption) (*Writers, error) {
	args = args.withDefaults()

	if err := args.validate(); err != nil {
		return nil, fmt.Errorf("esoaws: writers %q: %w", args.Name, err)
	}

	type planned struct {
		grant  WriteGrant
		trust  string
		policy pulumi.StringInput
	}

	plan := make([]planned, 0, len(args.Grants))

	for _, g := range args.Grants {
		trust, err := WriterTrustPolicy(args, g)
		if err != nil {
			return nil, fmt.Errorf("esoaws: writers %q: grant %s: %w", args.Name, g.Name, err)
		}

		var policy pulumi.StringInput

		if g.KMSKey == nil {
			doc, err := WriterPolicy(args, g)
			if err != nil {
				return nil, fmt.Errorf("esoaws: writers %q: grant %s: %w", args.Name, g.Name, err)
			}

			policy = pulumi.String(doc)
		} else {
			// The key is made by the same program: its ARN is known at apply,
			// where the policy is built.
			policy = args.writerKeyOutput(g)
		}

		plan = append(plan, planned{grant: g, trust: trust, policy: policy})
	}

	comp := &Writers{RoleARNs: map[string]pulumi.StringOutput{}}
	if err := ctx.RegisterComponentResource(KindWriters, args.Name, comp, opts...); err != nil {
		return nil, err
	}

	child := []pulumi.ResourceOption{pulumi.Parent(comp), pulumi.Provider(args.Provider)}

	for _, p := range plan {
		roleArgs := &iam.RoleArgs{
			Name:             pulumi.String(p.grant.Name),
			AssumeRolePolicy: pulumi.String(p.trust),
		}
		if args.PermissionsBoundary != "" {
			roleArgs.PermissionsBoundary = pulumi.String(args.PermissionsBoundary)
		}

		if len(args.Tags) > 0 {
			roleArgs.Tags = pulumi.ToStringMap(args.Tags)
		}

		role, err := iam.NewRole(ctx, p.grant.Name, roleArgs, child...)
		if err != nil {
			return nil, fmt.Errorf("esoaws: create role %s: %w", p.grant.Name, err)
		}

		if _, err := iam.NewRolePolicy(ctx, p.grant.Name+"-policy", &iam.RolePolicyArgs{
			Name:   pulumi.String(p.grant.Name),
			Role:   role.Name,
			Policy: p.policy,
		}, child...); err != nil {
			return nil, fmt.Errorf("esoaws: create inline policy of %s: %w", p.grant.Name, err)
		}

		comp.RoleARNs[p.grant.Name] = role.Arn
	}

	roles := pulumi.StringMap{}
	for name, arn := range comp.RoleARNs {
		roles[name] = arn
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{"roleArns": roles}); err != nil {
		return nil, err
	}

	return comp, nil
}
