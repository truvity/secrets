package custody

import (
	"encoding/json"
	"fmt"
	"slices"
)

const (
	policyVersionKey      = "Version"
	policyStatementKey    = "Statement"
	policySidKey          = "Sid"
	policyEffectKey       = "Effect"
	policyPrincipalKey    = "Principal"
	policyActionKey       = "Action"
	policyResourceKey     = "Resource"
	policyConditionKey    = "Condition"
	policyStringEqualsKey = "StringEquals"
	policyArnLikeKey      = "ArnLike"
	policyArnNotLikeKey   = "ArnNotLike"
	policyStringNotEquals = "StringNotEquals"
	policyNumericLessThan = "NumericLessThan"
	policyPrincipalARNKey = "aws:PrincipalArn"
	policyAWSKey          = "AWS"
	policyAllow           = "Allow"
	policyDeny            = "Deny"
	policyAnyPrincipal    = "*"
	policyVersion         = "2012-10-17"
	kmsDescribeKey        = "kms:DescribeKey"
	kmsSigningAlgorithm   = "kms:SigningAlgorithm"
	kmsMessageType        = "kms:MessageType"
	ecdsaSHA384           = "ECDSA_SHA_384"
	messageTypeDigest     = "DIGEST"
	kmsReplicaRegion      = "kms:ReplicaRegion"
	kmsReplicateKey       = "kms:ReplicateKey"
	kmsScheduleDeletion   = "kms:ScheduleKeyDeletion"
	kmsPendingWindowDays  = "kms:ScheduleKeyDeletionPendingWindowInDays"
)

var (
	// adminActions is administration without signing, deletion
	// scheduling, grant creation or key-policy writes.
	adminActions = []string{
		"kms:CancelKeyDeletion",
		"kms:CreateAlias",
		"kms:DeleteAlias",
		kmsDescribeKey,
		"kms:DisableKey",
		"kms:EnableKey",
		"kms:GetKeyPolicy",
		// The four the AWS provider reads back after every create and
		// update -- DescribeKey, GetKeyPolicy, GetKeyRotationStatus and
		// ListResourceTags. A key policy that omits one fails the apply
		// AFTER the key exists, which is the worst moment to find out.
		// GetKeyRotationStatus is asked even of a SIGN_VERIFY key, which
		// cannot rotate.
		"kms:GetKeyRotationStatus",
		"kms:ListKeyPolicies",
		"kms:ListResourceTags",
		"kms:ReplicateKey",
		"kms:TagResource",
		"kms:UntagResource",
		"kms:UpdateAlias",
		"kms:UpdateKeyDescription",
		"kms:UpdatePrimaryRegion",
	}
	ceremonyReadActions = []string{kmsDescribeKey, "kms:GetPublicKey"}

	// breakGlassOnlyActions are what the DenyDestructiveExceptBreakGlass
	// statement refuses to every principal but the break-glass one: the
	// calls that destroy a root, disable it, rewrite who may sign with it,
	// hand out its use by grant, or swap its material.
	breakGlassOnlyActions = []string{
		"kms:CreateGrant",
		"kms:DisableKey",
		"kms:ImportKeyMaterial",
		"kms:PutKeyPolicy",
		"kms:ScheduleKeyDeletion",
	}

	// strictRootBreakGlassOnlyActions are added to breakGlassOnlyActions
	// under Args.StrictRoot: making a replica the primary, and the two grant
	// calls (no grant can exist without CreateGrant; denied for clarity).
	// kms:ReplicateKey is handled apart (keyPolicy): break-glass only for a
	// root without a replica region, and for one with a replica region
	// refused everywhere but there, so the apply can make the planned replica.
	strictRootBreakGlassOnlyActions = []string{
		"kms:RetireGrant",
		"kms:RevokeGrant",
		"kms:UpdatePrimaryRegion",
	}
)

// StrictRootBreakGlassOnlyActions returns the actions a key policy denies to
// every principal but the break-glass pattern under Args.StrictRoot, sorted:
// BreakGlassOnlyActions, UpdatePrimaryRegion, RetireGrant and RevokeGrant.
// For a root without a replica region the Deny lists kms:ReplicateKey too.
func StrictRootBreakGlassOnlyActions() []string {
	actions := append(slices.Clone(breakGlassOnlyActions), strictRootBreakGlassOnlyActions...)
	slices.Sort(actions)
	return actions
}

// BreakGlassOnlyActions returns the actions a key policy denies to every
// principal but the break-glass pattern when Args.BreakGlassPrincipalARNPattern
// is set.
func BreakGlassOnlyActions() []string {
	return slices.Clone(breakGlassOnlyActions)
}

// policyOptions are the opt-in parts of the key policy and the ceremony
// role's trust. The zero value renders the documents exactly as before
// either option existed.
type policyOptions struct {
	breakGlassPrincipalARNPattern string
	ceremonyTrustConditions       []TrustCondition
	strictRoot                    bool
	// replicaRegion is the generation's replica region, read under
	// strictRoot only; empty for a root without a replica.
	replicaRegion string
}

// breakGlassOnly is the action list of the break-glass Deny.
func (o policyOptions) breakGlassOnly() []string {
	if !o.strictRoot {
		return breakGlassOnlyActions
	}
	actions := StrictRootBreakGlassOnlyActions()
	if o.replicaRegion == "" {
		actions = append(actions, kmsReplicateKey)
		slices.Sort(actions)
	}
	return actions
}

func (a Args) policyOptions() policyOptions {
	return policyOptions{
		breakGlassPrincipalARNPattern: a.BreakGlassPrincipalARNPattern,
		ceremonyTrustConditions:       a.CeremonyTrustConditions,
		strictRoot:                    a.StrictRoot,
	}
}

// arn composes an ARN from its parts. Composed, never written out: this
// package takes every account, region and name as an input.
func arn(partition, service, region, account, resource string) string {
	return "arn:" + partition + ":" + service + ":" + region + ":" + account + ":" + resource
}

// roleTrustPolicy lets exactly the trusted human principals of the account
// assume a custody role. extra are further conditions every assumption must
// also meet (Args.CeremonyTrustConditions, for the ceremony role); validate
// has refused any that would collide with the principal condition.
func roleTrustPolicy(partition, accountID, trustedPrincipalARNPattern string, extra ...TrustCondition) (string, error) {
	condition := map[string]map[string]any{
		policyArnLikeKey: {policyPrincipalARNKey: trustedPrincipalARNPattern},
	}
	for _, item := range extra {
		if condition[item.Operator] == nil {
			condition[item.Operator] = map[string]any{}
		}
		condition[item.Operator][item.Key] = slices.Clone(item.Values)
	}
	return marshalPolicy(map[string]any{
		policyVersionKey: policyVersion,
		policyStatementKey: []map[string]any{{
			policySidKey:       "ApprovedSSOAdminAssumeRole",
			policyEffectKey:    policyAllow,
			policyPrincipalKey: map[string]any{policyAWSKey: arn(partition, "iam", "", accountID, "root")},
			policyActionKey:    "sts:AssumeRole",
			policyConditionKey: condition,
		}},
	})
}

// keyPolicy is the key's own authority, and it is the WHOLE authority: a
// KMS key policy that does not name a principal means no IAM policy can
// grant that principal anything, however privileged it is.
//
// That is why the trusted administrator appears here as well as the admin
// role it may assume. The custody is applied from that session, and the
// AWS provider reads a key's tags and policy straight back after creating
// it -- so a policy naming only the admin role leaves the provider unable
// to finish creating the key it has just made, with the key created and
// the apply failed. It is not a widening: the admin role's trust policy
// admits exactly this pattern, so the same human already holds these
// actions one `sts:AssumeRole` away. Signing, deletion scheduling, grant
// creation and key-policy writes stay out of both.
//
// The account-root statement is the break-glass: it can read and rewrite
// the policy and nothing else, so a policy that locked everyone out can be
// repaired without the key being unrecoverable.
//
// With a break-glass pattern (options), a last statement denies
// breakGlassOnlyActions to every principal whose ARN does not match it: the
// account root, the trusted administrators and both roles included. The
// account-root recovery statement then works for the break-glass principal
// alone, and the administration statements drop the actions the Deny would
// refuse anyway, so the document reads as what is possible.
func keyPolicy(partition, accountID, trustedPrincipalARNPattern, adminRoleARN, ceremonyRoleARN string, options policyOptions) (string, error) {
	accountRoot := arn(partition, "iam", "", accountID, "root")
	administration := adminActions
	denied := options.breakGlassOnly()
	if options.breakGlassPrincipalARNPattern != "" {
		administration = slices.DeleteFunc(slices.Clone(adminActions), func(action string) bool {
			return slices.Contains(denied, action)
		})
	}
	signCondition := map[string]any{kmsSigningAlgorithm: ecdsaSHA384}
	if options.strictRoot {
		signCondition[kmsMessageType] = messageTypeDigest
	}
	statements := []map[string]any{
		{
			policySidKey:       "BreakGlassPolicyRecovery",
			policyEffectKey:    policyAllow,
			policyPrincipalKey: map[string]any{policyAWSKey: accountRoot},
			policyActionKey:    []string{kmsDescribeKey, "kms:GetKeyPolicy", "kms:PutKeyPolicy"},
			policyResourceKey:  "*",
		},
		{
			policySidKey:       "KeyAdministrationWithoutSigningOrDeletion",
			policyEffectKey:    policyAllow,
			policyPrincipalKey: map[string]any{policyAWSKey: adminRoleARN},
			policyActionKey:    administration,
			policyResourceKey:  "*",
		},
		{
			policySidKey:       "KeyAdministrationByApprovedSSOAdmin",
			policyEffectKey:    policyAllow,
			policyPrincipalKey: map[string]any{policyAWSKey: accountRoot},
			policyActionKey:    administration,
			policyResourceKey:  "*",
			policyConditionKey: map[string]any{
				policyArnLikeKey: map[string]any{policyPrincipalARNKey: trustedPrincipalARNPattern},
			},
		},
		{
			policySidKey:       "ExplicitRootCeremonyRead",
			policyEffectKey:    policyAllow,
			policyPrincipalKey: map[string]any{policyAWSKey: ceremonyRoleARN},
			policyActionKey:    ceremonyReadActions,
			policyResourceKey:  "*",
		},
		{
			policySidKey:       "ExplicitRootCeremonySign",
			policyEffectKey:    policyAllow,
			policyPrincipalKey: map[string]any{policyAWSKey: ceremonyRoleARN},
			policyActionKey:    "kms:Sign",
			policyResourceKey:  "*",
			policyConditionKey: map[string]any{
				policyStringEqualsKey: signCondition,
			},
		},
	}
	if options.strictRoot {
		// The window is a key input too, but a direct API call could pass a
		// shorter one: refuse it to every principal, the break-glass one
		// included. Changing it means rewriting this policy, which is
		// break-glass.
		statements = append(statements, map[string]any{
			policySidKey:       "DenyDeletionWindowUnder30Days",
			policyEffectKey:    policyDeny,
			policyPrincipalKey: map[string]any{policyAWSKey: policyAnyPrincipal},
			policyActionKey:    kmsScheduleDeletion,
			policyResourceKey:  "*",
			policyConditionKey: map[string]any{
				policyNumericLessThan: map[string]any{kmsPendingWindowDays: DefaultDeletionWindowDays},
			},
		})
		if options.replicaRegion != "" {
			// The administrators may replicate the root to its one planned
			// region (the apply creates the replica that way) and nowhere
			// else; the break-glass principal is exempt, as from the Deny
			// below. A second replica in that region fails anyway: it exists.
			statements = append(statements, map[string]any{
				policySidKey:       "DenyReplicationElsewhereExceptBreakGlass",
				policyEffectKey:    policyDeny,
				policyPrincipalKey: map[string]any{policyAWSKey: policyAnyPrincipal},
				policyActionKey:    kmsReplicateKey,
				policyResourceKey:  "*",
				policyConditionKey: map[string]any{
					policyStringNotEquals: map[string]any{kmsReplicaRegion: options.replicaRegion},
					policyArnNotLikeKey:   map[string]any{policyPrincipalARNKey: options.breakGlassPrincipalARNPattern},
				},
			})
		}
	}
	if options.breakGlassPrincipalARNPattern != "" {
		statements = append(statements, map[string]any{
			policySidKey:       "DenyDestructiveExceptBreakGlass",
			policyEffectKey:    policyDeny,
			policyPrincipalKey: map[string]any{policyAWSKey: policyAnyPrincipal},
			policyActionKey:    denied,
			policyResourceKey:  "*",
			// ArnNotLike holds when the key is absent, so a caller with no
			// principal ARN at all (a service acting on its own) is denied
			// too.
			policyConditionKey: map[string]any{
				policyArnNotLikeKey: map[string]any{policyPrincipalARNKey: options.breakGlassPrincipalARNPattern},
			},
		})
	}
	return marshalPolicy(map[string]any{
		policyVersionKey:   policyVersion,
		policyStatementKey: statements,
	})
}

func marshalPolicy(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}
	return string(raw), nil
}
