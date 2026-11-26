# 0007 — Several active roots, one per party

**Status:** Accepted
**Date:** 2026-11-26

## Context

A contract could author several root generations, and each trust domain
already named its own (`rootGeneration`). But exactly one generation could
be active, and `Contract.Derive` refused any domain not declared under it.
A generation was a point in time: the next root, overlapping the last one
during a rotation.

An estate that serves several parties may want each party's chains to hang
from a root of its own, held in that party's own account, so that one
party's root key signs nothing of another's and its custody can be
administered, audited and, one day, handed over on its own. That needs
several roots active at once, each signing only the domains declared under
it.

Custody already lived per generation in the contract
(`rootGenerations[].custody.accountId`), but the custody outputs a ceremony
checks against (`pki.CustodyOutputs`, from one `pkg/custody` deployment)
describe one account, and `Contract.VerifyCustody` required them to publish
every generation the contract authors.

## Decision

**Several active generations.** `Validate` requires at least one active
generation, not exactly one. Each trust domain (DNS or URI) derives under
the generation it names, which must be authored and active; its domain
intermediate's artifact, its root-signed environment CAs' artifacts and its
issuing CAs' organization are that root's. An empty `rootGeneration` is the
contract's one active generation (`Validate` fills it in); with several
active, it is required, so which root signs a domain is never the order of a
list.

**Custody per account.** A custody outputs file speaks for one account: its
roles' account. `VerifyCustody` refuses a file for another account than the
signed generation's custody (naming both), and requires the file to publish
every generation the contract authors in that account and nothing else. A
contract with one custody account checks exactly what it did. A consumer
deploys one `pkg/custody` per account (`Contract.CustodyAccounts`,
`Contract.GenerationsInAccount`) and syncs each one's outputs; a ceremony
passes the file of its generation's account. The `openbaoctl` flag stays one
`--custody-outputs FILE`.

**Break-glass per root.** `EmergencyServerSpec(generation, name, …)` signs
only under an active, trusted generation, for a name under a require-trusted
DNS domain declared under that same generation.

**The estate view.** `PrivatePKI.Root` is the private domain's root (with
one root, the root); `PrivatePKI.Roots` lists the other active roots some
domain is declared under, and is left out when there are none. Chains are
loaded under each domain's own root. `estate.ActiveGeneration` still returns
the one active generation and refuses when there are several; a consumer
asks `Contract.TrustDomainRoot(domain)` instead.

## Consequences

- A contract with one active root derives, verifies and renders byte for byte
  what it did: every derive, estate and render golden is unchanged.
- Each further root needs its own ceremony, its own custody (keys, roles,
  sign alerts) in its own account, its own entry in
  `migration.trustedGenerations` for whatever must verify its leaves, and
  its own custody outputs file.
- A domain moves to another root by naming it and re-signing its
  intermediate under it: the artifact name carries the generation, so the
  new chain is a new artifact beside the old one. This decision does not
  move any domain.
- Lifetimes and path lengths are unchanged: each root keeps its own, and
  each domain is checked against the root it names, as before.
- What it does not cover: where a party's domains live inside the server
  (namespaces), and the key policy a party's root should hold to. Both are
  their own changes.

## Alternatives considered

- **One root, a name-constrained intermediate per party.** That is what
  ADR 0006 gives, and it stays the default. It keeps every party's chain
  under one key and one account, which is what this decision exists to
  avoid for an estate that wants it.
- **Several custody outputs files on one flag, or one file holding several
  accounts.** Either would let a ceremony be handed every file at once. One
  file per account is already the shape one `pkg/custody` deployment
  exports; picking the file is the operator's one choice, and a wrong one
  is refused by name, so neither the format nor the flag needs to change.
- **A default root per domain kind.** Rejected: with several active roots,
  a domain that names none is a mistake to refuse, not a gap to fill.
