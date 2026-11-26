# 0008 — A party's trust domains live in a namespace of its own

**Status:** Accepted
**Date:** 2026-11-26

## Context

ADR 0007 lets each party hang its chains from a root of its own. The
server still held every party's CAs in the same places: the domain
intermediates in root, each environment's issuing CAs in that
environment's namespace. A party's own stack could only apply them with a
token that reaches root and every environment, which is every other
party's CAs too.

The server's namespaces can make that boundary: a token scoped to one
namespace reaches that namespace and the ones below it, nothing beside or
above. OpenBAO has no Sentinel, so a policy cannot let a token create PKI
mounts without letting it create any mount: whoever applies a party's
namespaces must not need `sys/` at all.

## Decision

**Placement.** A trust domain (DNS or URI) may name a `namespace`. Empty
is the root namespace and the environment's own, as before. Named, the
domain's intermediate lives in `<namespace>` itself, and each environment
it reaches gets `<namespace>/<env>`, holding that environment's issuing
CA, its roles, the cluster's auth mount with cert-manager's login, and that
login's policy. A namespace is one lower-case label and may not be an
environment's name. The model holds these as `Desired.Vendors`: each party
namespace, then its children, a child after its parent.

**Two stacks per party namespace, one boundary.** The server owner's stack
makes everything a party's token may not: the namespaces, the empty PKI
mounts, the auth mounts with their roles, the policies and the groups
(`apply.SelectVendorMounts`). The party's own stack writes everything
inside those PKI mounts: the intermediate's key and request, the import,
the issuers, the configuration, the roles and each issuing CA's contents
(`apply.SelectVendor`). Together the two select every resource of the
party's namespaces exactly once, and the party's selection never selects a
resource in root or in another party's namespace. `apply.Resource` carries
the namespace a resource configures, so a selection can say so.

**A login below root.** `apply.Login.Namespace` logs the provider in, and
keeps it working, in one namespace: every namespace argument is then
relative to it, and nothing outside it is registered. A party's stack logs
in at `<namespace>`, through the roster's door there, which the server
owner's stack declares for the groups the estate names
(`estate.PKI.VendorAdmins`), each granted the party's PKI mounts and
nothing of `sys/`.

**Never deleted by a plan.** A party's namespaces are registered protected:
deleting a namespace takes everything in it, and is slow enough to stick.
Dropping one from the model is refused like dropping any protected
resource.

**The unit rules.** A PKI mount and its contents stay one unit everywhere
but in a party's namespace, where the contents are a unit of their own. The
same holds for a pending domain's phase A (ADR 0006): in root the mount and
its request are one unit, and in a party's namespace the server owner's
stack makes the mount and the party's own stack the key and its request.

**The issuer view.** `estate.IssuerView.Namespace` names the domain's party
namespace, and `ServerNamespace(env)` is what cert-manager's vault issuer
names as `namespace:`; its login role is on the cluster's mount there.

## Consequences

- With no domain naming a namespace, nothing changes: every derive, estate,
  apply and render golden is unchanged, and a selection that ignores
  `Resource.Namespace` selects what it did.
- A party's stack applies with a token that cannot reach root, an
  environment, or another party.
- The server owner's stack must be applied before the party's: the party's
  resources refer to the mounts by their declared paths.
- In `pkg/estate`, the estate's own private, origin and identity domains
  stay in root (the restore check, the identity CAs and the origin names
  rest on them there); a party's further domains take namespaces. Moving a
  domain into a namespace is a new intermediate in it, not a move: this
  decision migrates nothing.

## Alternatives considered

- **One provider per namespace in one stack.** It would still need a token
  for every namespace in one run, which is the boundary this decision
  exists to make.
- **Flat per-environment mounts in `<namespace>`** (`pki-<env>`) instead of
  child namespaces. Fewer namespaces, but every environment's login and
  policy would share one namespace, and today's mount names and per-
  environment policies would not carry over.
- **Letting the party make its own mounts.** Without Sentinel the policy
  that allows a PKI mount allows any mount, and an auth mount is a door.
