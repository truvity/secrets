package esoaws

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// recoveryKMSActions are the recovery role's actions, the writer's three in the
// order estates have rendered them since before this builder (a key policy's
// text is a Pulumi input, so its order is part of the contract).
var recoveryKMSActions = []string{"kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"}

// maxKeyPolicyBytes is KMS's limit on a key policy document.
const maxKeyPolicyBytes = 32768

// KeyAdministrationActions is key administration without any use of the key:
// the key policy's own, the alias, rotation, tags, deletion. Not the
// cryptographic actions, and not CreateGrant (a grant is a way to hand out
// Decrypt).
var KeyAdministrationActions = []string{
	"kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias",
	"kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus",
	"kms:ListAliases", "kms:ListGrants", "kms:ListKeyPolicies", "kms:ListResourceTags",
	"kms:PutKeyPolicy", "kms:UpdateKeyDescription",
	"kms:EnableKey", "kms:DisableKey", "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:RotateKeyOnDemand",
	"kms:TagResource", "kms:UntagResource",
	"kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
}

type (
	// SecureStringKeyArgs configures NewSecureStringKey: one customer-managed
	// KMS key for SSM SecureStrings that External Secrets writes (PushSecret),
	// with the writer role of NewWriters and a key policy that names every
	// principal that may use the key. It is the key NewWriters asks for
	// (WriteGrant.KMSKey) and the policy WriterKeyPolicyStatement is a part of.
	SecureStringKeyArgs struct {
		// Name is the logical name of the key and of its alias.
		Name string
		// Description is the key's description.
		Description string
		// Alias is the key's alias, "alias/<name>".
		Alias string
		// PolicyID is the key policy document's Id.
		PolicyID string
		// Writers carries the account, region, partition, cluster identity,
		// permissions boundary and tags of the writer role, and Name (the
		// writers component's logical name) and Provider, which is also the
		// key's and the alias's. Its Grants must be empty: Writer is the
		// grant, and the key is made before the grant can name it.
		Writers WritersArgs
		// Writer is the one writer role. Its KMSKey and KMSKeyARN are set by
		// NewSecureStringKey (to the key it makes).
		Writer WriteGrant
		// Readers are the principals that decrypt through SSM, by role ARN
		// pattern, and ReaderStatements are ready-made statements for the
		// same (a builder library's own half of its grant). Both are
		// optional, and Readers come first in the policy.
		Readers          []KeyReader
		ReaderStatements []map[string]any
		// Recovery is the emergency role's pattern, and RecoveryParameters
		// the parameters it may use the key for. Both or neither.
		Recovery           string
		RecoveryParameters []string
	}

	// KeyReader is one statement of the key policy that lets the roles
	// matching RoleARNPattern decrypt through SSM, for the named parameters
	// only. Like every statement of the policy it is the account root
	// narrowed by aws:PrincipalArn, so the roles need not exist when the key
	// is made, and each role still needs its own IAM allow.
	KeyReader struct {
		// Sid is the statement's id, unique in the policy.
		Sid string
		// RoleARNPattern is an ArnLike pattern of the role ARNs.
		RoleARNPattern string
		// Parameters are the parameters' names, each with its leading "/";
		// an entry may end in "*".
		Parameters []string
	}

	// SecureStringKey is what NewSecureStringKey made.
	SecureStringKey struct {
		Key     *kms.Key
		Alias   *kms.Alias
		Writers *Writers
		// WriterRoleARN is the writer role's ARN.
		WriterRoleARN pulumi.StringOutput
	}
)

func (a SecureStringKeyArgs) validate() error {
	var errs []error

	for field, v := range map[string]string{"Name": a.Name, "Alias": a.Alias, "PolicyID": a.PolicyID, "Description": a.Description} {
		if v == "" {
			errs = append(errs, fmt.Errorf("args.%s is empty", field))
		}
	}

	if !strings.HasPrefix(a.Alias, "alias/") {
		errs = append(errs, fmt.Errorf("args.Alias %q does not start with alias/", a.Alias))
	}

	if len(a.Writers.Grants) > 0 {
		errs = append(errs, errors.New("args.Writers.Grants is set: args.Writer is the grant"))
	}

	if a.Writer.KMSKey != nil || a.Writer.KMSKeyARN != "" {
		errs = append(errs, errors.New("args.Writer names a key: it is the key this makes"))
	}

	if (a.Recovery == "") != (len(a.RecoveryParameters) == 0) {
		errs = append(errs, errors.New("args.Recovery and args.RecoveryParameters are set together or not at all"))
	}

	for i, r := range a.Readers {
		if r.Sid == "" || r.RoleARNPattern == "" || len(r.Parameters) == 0 {
			errs = append(errs, fmt.Errorf("args.Readers[%d]: Sid, RoleARNPattern and Parameters are required", i))
		}
	}

	return errors.Join(errs...)
}

// withWriter is the arguments of the writer role and the grant, as the key's
// policy and NewWriters read them. The policy statement never reads the key,
// so the grant carries an empty output until the key exists.
func (a SecureStringKeyArgs) withWriter() (WritersArgs, WriteGrant) {
	grant := a.Writer
	grant.KMSKeyARN = ""
	grant.KMSKey = pulumi.String("")

	return a.Writers.withDefaults(), grant
}

// SecureStringKeyPolicy is the key's policy document, in this order: key
// administration for the account root (no cryptographic action), the writer
// role, the Readers, the ReaderStatements, and the recovery role. A statement
// id that appears twice is refused, and so is a document over KMS's limit.
func SecureStringKeyPolicy(args SecureStringKeyArgs) (string, error) {
	if err := args.validate(); err != nil {
		return "", fmt.Errorf("esoaws: key %q: %w", args.Name, err)
	}

	wargs, grant := args.withWriter()

	writer, err := WriterKeyPolicyStatement(wargs, grant)
	if err != nil {
		return "", fmt.Errorf("esoaws: key %q: %w", args.Name, err)
	}

	var (
		root = map[string]any{"AWS": fmt.Sprintf("arn:%s:iam::%s:root", wargs.Partition, wargs.AccountID)}
		via  = map[string]any{"kms:ViaService": viaSSM(wargs.Region, wargs.Partition)}
		arns = func(names []string) []string {
			out := make([]string, 0, len(names))
			for _, n := range names {
				out = append(out, wargs.parameterARN(strings.TrimPrefix(n, "/")))
			}

			return out
		}
	)

	// A statement of the account root, narrowed to roles by pattern, and to
	// SSM and the parameters.
	narrowed := func(sid, rolePattern string, actions, params []string) map[string]any {
		return map[string]any{
			"Sid":       sid,
			"Effect":    "Allow",
			"Principal": root,
			"Action":    actions,
			"Resource":  "*",
			"Condition": map[string]any{
				"ArnLike":      map[string]any{"aws:PrincipalArn": rolePattern},
				"StringEquals": via,
				"StringLike":   map[string]any{"kms:EncryptionContext:PARAMETER_ARN": arns(params)},
			},
		}
	}

	statements := []map[string]any{
		{
			"Sid":       "KeyAdministration",
			"Effect":    "Allow",
			"Principal": root,
			"Action":    KeyAdministrationActions,
			"Resource":  "*",
		},
		writer,
	}

	for _, r := range args.Readers {
		statements = append(statements, narrowed(r.Sid, r.RoleARNPattern, []string{"kms:Decrypt"}, r.Parameters))
	}

	statements = append(statements, args.ReaderStatements...)

	if args.Recovery != "" {
		statements = append(statements,
			narrowed("BreakglassRecovers", args.Recovery, recoveryKMSActions, args.RecoveryParameters))
	}

	return keyPolicyDocument(args.PolicyID, statements)
}

func keyPolicyDocument(id string, statements []map[string]any) (string, error) {
	seen := map[string]bool{}

	for i, s := range statements {
		sid, _ := s["Sid"].(string)
		if sid == "" {
			return "", fmt.Errorf("key policy statement %d has no Sid", i)
		}

		if seen[sid] {
			return "", fmt.Errorf("key policy: Sid %q appears twice", sid)
		}

		seen[sid] = true
	}

	raw, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Id": id, "Statement": statements})
	if err != nil {
		return "", fmt.Errorf("render key policy: %w", err)
	}

	if len(raw) > maxKeyPolicyBytes {
		return "", fmt.Errorf("key policy is %d bytes, KMS takes %d at most", len(raw), maxKeyPolicyBytes)
	}

	return string(raw), nil
}

// NewSecureStringKey makes the key, its alias and the writer role, in that
// order, in the writers' account. Nothing is registered when the arguments are
// invalid. The resources and their logical names:
//
//	aws:kms/key:Key      <Name>
//	aws:kms/alias:Alias  <Name>
//	NewWriters           <Writers.Name>
func NewSecureStringKey(ctx *pulumi.Context, args SecureStringKeyArgs, opts ...pulumi.ResourceOption) (*SecureStringKey, error) {
	policy, err := SecureStringKeyPolicy(args)
	if err != nil {
		return nil, err
	}

	if args.Writers.Provider == nil {
		return nil, fmt.Errorf("esoaws: key %q: args.Writers.Provider is nil", args.Name)
	}

	// The writers are checked in full before the key is registered.
	checked, grant := args.withWriter()
	checked.Grants = []WriteGrant{grant}

	if err := checked.validate(); err != nil {
		return nil, fmt.Errorf("esoaws: key %q: %w", args.Name, err)
	}

	keyOpts := append([]pulumi.ResourceOption{pulumi.Provider(args.Writers.Provider)}, opts...)

	// The key is protected: a deleted key takes every SecureString under it.
	keyResOpts := append(append([]pulumi.ResourceOption{}, keyOpts...), pulumi.Protect(true))

	k, err := kms.NewKey(ctx, args.Name, &kms.KeyArgs{
		Description:          pulumi.String(args.Description),
		DeletionWindowInDays: pulumi.Int(30),
		EnableKeyRotation:    pulumi.Bool(true),
		Policy:               pulumi.String(policy),
	}, keyResOpts...)
	if err != nil {
		return nil, fmt.Errorf("esoaws: key %q: %w", args.Name, err)
	}

	alias, err := kms.NewAlias(ctx, args.Name, &kms.AliasArgs{
		Name:        pulumi.String(args.Alias),
		TargetKeyId: k.KeyId,
	}, keyOpts...)
	if err != nil {
		return nil, fmt.Errorf("esoaws: key %q alias: %w", args.Name, err)
	}

	wargs := args.Writers
	grant = args.Writer
	grant.KMSKey = k.Arn
	wargs.Grants = []WriteGrant{grant}

	writers, err := NewWriters(ctx, wargs, opts...)
	if err != nil {
		return nil, fmt.Errorf("esoaws: key %q writer: %w", args.Name, err)
	}

	return &SecureStringKey{Key: k, Alias: alias, Writers: writers, WriterRoleARN: writers.RoleARNs[grant.Name]}, nil
}
