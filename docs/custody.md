# Custody of the root key

`pkg/custody` is a Pulumi Go module that creates what a KMS-rooted PKI
needs before its first ceremony, and nothing that signs:

| Per | Resources |
|---|---|
| account | two IAM roles: **admin** (administer the keys; cannot sign, schedule deletion, create grants or write the key policy) and **ceremony** (read the public key and sign, `ECDSA_SHA_384` only) |
| root generation | a multi-region `ECC_NIST_P384` `SIGN_VERIFY` key, its replica in a second region, an alias in each; the keys `Protect` and `RetainOnDelete`, the aliases `Protect`, a 30-day deletion window |
| generation × region | the Sign alarm: an SNS topic with e-mail subscriptions, an EventBridge rule matching CloudTrail's `kms:Sign` on that key, a CloudWatch alarm on the rule |

```go
import "github.com/truvity/secrets/pkg/custody"

keys, err := custody.Deploy(ctx, custody.Args{
    AccountID:                     "111122223333",
    Profile:                       "example-custody",
    TrustedPrincipalARNPattern:    "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_admin_*",
    AdminRoleName:                 "private-pki-root-admin",
    CeremonyRoleName:              "private-pki-root-ceremony",
    PermissionsBoundaryPolicyName: "example-boundary",
    Generations: []custody.Generation{
        {ID: "example-root-2026-01", Region: "eu-example-1", ReplicaRegion: "eu-example-2"},
    },
    Notify: []string{"security@example.com"},
})
// keys.Generations[i].Key.Arn is what `openbaoctl pki create-root --key-arn` takes;
// keys.CeremonyRole.Arn is its --role-arn.
```

Every input is in [reference.md](reference.md#pkgcustody).

## The key policy is the whole authority

A KMS key policy that does not name a principal means no IAM policy can
grant that principal anything. So the policy says everything:

| Statement | Principal | Actions |
|---|---|---|
| `BreakGlassPolicyRecovery` | the account root | `DescribeKey`, `GetKeyPolicy`, `PutKeyPolicy`: a policy that locked everyone out can be repaired, and nothing else |
| `KeyAdministrationWithoutSigningOrDeletion` | the admin role | administration: aliases, enable/disable, tags, description, replication, primary region, cancel deletion, and the four reads the provider needs |
| `KeyAdministrationByApprovedSSOAdmin` | the account root, `ArnLike` the trusted pattern | the same administration, for the session that applies this |
| `ExplicitRootCeremonyRead` | the ceremony role | `DescribeKey`, `GetPublicKey` |
| `ExplicitRootCeremonySign` | the ceremony role | `Sign`, only with `kms:SigningAlgorithm = ECDSA_SHA_384` |

The trusted administrator appears beside the admin role because the
custody is applied from that session and the AWS provider reads a key's
tags and policy back right after creating it: a policy naming only the
admin role leaves the provider unable to finish creating the key it has
just made. It is not a widening -- both roles' trust policies admit
exactly that pattern, so the same person already holds these actions one
`sts:AssumeRole` away. Signing, deletion scheduling, grant creation and
key-policy writes stay out of both.

The administration list includes `GetKeyRotationStatus` and
`ListResourceTags`: the provider asks for both after every create and
update, even of a `SIGN_VERIFY` key that cannot rotate, and a policy that
omits one fails the apply **after** the key exists.

## Break-glass only: the Deny and the ceremony trust

Two options harden the custody further. Both are off by default; without
them every document renders exactly as before.

**`BreakGlassPrincipalARNPattern`** names the custody account's break-glass
role (an `ArnLike` pattern). Every key policy then ends in one more
statement:

| Statement | Principal | Effect |
|---|---|---|
| `DenyDestructiveExceptBreakGlass` | every principal, `ArnNotLike` the break-glass pattern | **Deny** `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`, `CreateGrant`, `ImportKeyMaterial` (`custody.BreakGlassOnlyActions()`) |

The Deny covers the account root, the trusted administrators and both
roles, and a caller with no principal ARN at all. The administration
statements drop `DisableKey`, the one of those actions they used to allow,
so the policy reads as what is possible. `BreakGlassPolicyRecovery` stays
and now serves the break-glass role alone: it is the one way to change a
key policy, and through it the one way to the other denied actions (rewrite
the policy, then act). The pattern must be a role in the custody account
and must differ from `TrustedPrincipalARNPattern`; a wrong exemption cannot
be repaired by anyone the Deny refuses, so check it before the first apply.

Two consequences for the apply:

- The keys are created with `BypassPolicyLockoutSafetyCheck`. KMS refuses
  a policy that would stop the caller from writing the next one, and the
  session that applies the custody is, by design, such a caller.
- A later change of a key policy is not an apply. The provider would call
  `PutKeyPolicy` as the applying session and be denied; the break-glass
  role writes the policy (once per region: a replica keeps its own copy)
  and the stack is refreshed afterwards.

**`CeremonyTrustConditions`** adds conditions to the ceremony role's trust
policy, beside the trusted principal pattern; the admin role's trust is
unchanged. Each is an operator, a key and its values
(`{"StringLike": {"aws:userid": ["*:custodian@example.com"]}}`), every one
must hold, and an operator and key pair may appear once. Pass only what the
trusted sessions carry. A session from IAM Identity Center has no
`aws:MultiFactorAuthPresent`, whatever the identity provider enforced: a
`Bool` condition on it can never be met and would lock every ceremony out,
and `BoolIfExists` would always pass. Multi-factor authentication for such
sessions is the identity provider's; what the trust can narrow is which
session may assume the role, for example one person's `aws:userid`.

## The Sign alarm

After the ceremony a root key signs two or three times in its life, so
the alarm does not rate-limit, it says "this happened at all". KMS has no
CloudWatch metric for `Sign`, so detection is CloudTrail through
EventBridge; the rule matches the key by every name a caller can use (key
ARN, key id, alias, alias ARN, in `resources` or in `requestParameters`),
and the alarm on the rule's `TriggeredRules` metric is the standing,
visible ALARM state behind the immediate notification. One matched call
in one minute breaches it; missing data, the normal state, does not.

It is duplicated per region because a multi-region key can be signed with
in either, and CloudTrail, EventBridge and CloudWatch are regional.

Two prerequisites are outside the module. Check both before the first
ceremony, or its signature is the one nobody hears:

1. **A multi-region trail logging management events** in the custody
   account. EventBridge emits `AWS API Call via CloudTrail` only where a
   trail records the call.
2. **Every subscription confirmed.** An e-mail subscription is
   `PendingConfirmation` until someone follows the AWS mail, in both
   regions; `aws sns list-subscriptions-by-topic` shows which are.

## Adopting existing custody

`Deploy` registers every resource directly on the caller's context (under
whatever `pulumi.Parent` the caller passes), not inside a component
resource of its own, and every Pulumi name is derived from the inputs:
`provider/aws/<RolesProviderName>`, `provider/aws/<generation>-primary`
and `-replica`, the role names, `<generation>`, `<generation>-alias`,
`<generation>-replica`, `<generation>-replica-alias`, and
`<generation>-sign-alert-<region>-{topic,topic-policy,subscription-<address>,rule,target,alarm}`.
Custody that already runs under those names is adopted with an empty
preview; see [adoption.md](adoption.md#adopting-an-existing-ceremony-and-custody).
A wrapper type would have put itself into every child's URN, and a
changed URN on a protected, retained root key is a replacement nobody
wants to review.
