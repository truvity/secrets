# 0006 — Any number of DNS trust domains, each reaching its own environments

**Status:** Accepted
**Date:** 2026-11-26

## Context

A contract could already declare any number of DNS trust domains, but
`pki.Contract.Derive` gave every environment every one of them. `pkg/estate`
knew two zones per cluster, `PrivateZone` and `OriginZone`, and passed a
zone to the derivation for the private, origin and identity domains only.
A third DNS domain was therefore refused: the derivation found no value for
`{zone}` in any environment.

That fits an estate with one private suffix. It does not fit an estate that
serves several parties, each with its own private suffix in only some
environments, where one party's chain must not be able to sign another's
names.

A further domain also needs its intermediate signed by the root before its
mounts can be applied. `apply.Deploy` imports the committed chain of every
domain intermediate, so declaring a domain whose artifact is not committed
yet failed every preview and apply. Only the identity domain's
per-environment CAs had a phase-A path (`PKI.Signed`,
`pki.Environment.PendingCAs`, `apply.BootstrapEnvironmentCA`).

## Decision

**Reach.** A DNS trust domain may list its environments (`environments`),
with the same meaning as a URI domain's list. An environment it does not
list gets no issuing CA, roles or mount of it, and needs no zone for it.
Left out, the list means every environment, so a contract written before it
derives what it did. Stated, it names at least one environment. The domain
intermediate is one either way, in the root namespace.

**Zones.** `pkg/estate` gives every DNS domain other than `PKI.Private` and
`PKI.Origin` its zone from the cluster's `Zones`, keyed by the domain's
name. A further domain that reaches a cluster without an entry is refused,
and so is an entry that no such domain reads: a zone nothing reads is a
mistake in the inputs, not a default. The private domain reaches every
cluster, because the identity domain and the restore check rest on its
zone. The origin zone is needed only where the origin domain reaches.

**Separation.** A suffix is a lower-case DNS name, and a constraint entry
beside the suffix lies outside it: every environment's issuing CA carries
those entries, so one under the suffix would reach into other environments'
zones. The derivation refuses:
- a zone that is not a lower-case DNS name, is not its domain's suffix or
  under it, or falls outside the intermediate's name constraint;
- in a name-constrained domain, a zone equal to the whole suffix, a zone
  that nests with a constraint entry beside the suffix, two environments
  with one zone, and one zone under another's;
- two DNS domains whose suffixes or name-constraint entries are equal or
  nested;
- a role that would sign another DNS domain's names: a `static` pattern
  (refused when the contract is validated) or a `catalog` name with a
  leading `*.` dropped (refused when it derives), equal to, under or above
  another domain's suffix or constraint entry.

A role's names need not sit under its own suffix, because an unconstrained
domain (an origin domain, say) publishes names in several zones. Its chain
carries no constraint at all, so these checks on its roles are its only
fence.

**Pending.** A DNS domain whose artifact is not committed yet is pending
(`pki.DeriveOptions.PendingDomains`, `estate.PKI.PendingDomains`). It
derives only a `PendingIntermediate`: its domain mount's path, description
and lease, and its key's name and subject. `pkg/estate/stack` bootstraps
that beside the apply with `apply.BootstrapEnvironmentCA` in root, the way
an identity environment CA is bootstrapped. The mount and the request are
registered under the names, and with the inputs, that `Deploy` gives the
same objects once the domain is signed, so the switch adopts them in place.
The request is exported under the domain's request output for the ceremony
to sign.

## Consequences

- An existing contract and an existing set of estate inputs derive byte for
  byte what they did; the derive and estate goldens do not change.
- A party's domain gets its own intermediate, constrained to its own suffix,
  so its environments' issuing CAs can sign nothing under another party's
  suffix. Each such intermediate is a further root signature in the
  ceremony.
- The separation checks refuse inputs that were accepted before. An input
  they refuse put one party's or one environment's names under another's
  chain, so the refusal is the point; the adoption step is to fix it.
- `Cluster.Zones` must not name the private or origin domain. Those keep
  their own fields, so there is one place each zone is written.
- A pending domain needs a domain mount of its own: a shared mount's default
  issuer, URLs and CRL belong to whichever domain is authored first, and
  signing a pending one would move them. The private and origin domains are
  never pending. A domain whose artifact is committed is refused as pending:
  listing it would drop its issuing CAs, roles and logins, and a stack that
  holds the grants would delete them.
- The pending mount and request are selectable with `Options.Select` like
  any other resource, as one unit (ADR 0005). Moving a domain from pending
  to signed is one change: drop it from the pending list in the change that
  commits its artifact.
- A DNS domain that lists an environment the estate has no cluster or
  namespace for is refused, so a typo cannot silently reach nothing. A URI
  domain's list is left as it was: it may name environments a partial
  estate does not build.

## Alternatives considered

**One intermediate for several suffixes.** Rejected: a domain has one
suffix and one zone per environment, so this needs a domain with several
zones, and one key would then cover every party.

**Widen the private domain's intermediate with further suffixes and give
them `static` roles.** Rejected: a literal pattern is the same in every
environment, so one environment's issuing CA could sign another's names,
and the chain every workload already trusts would change.

**A pending flag on the model's issuer, handled inside `Deploy`.**
Rejected: the mount's default issuer, its URLs, CRL and tidy all hang on an
imported issuer, so `Deploy` would need a second shape of PKI mount. The
identity path already keeps phase A outside `Deploy`, under the names
`Deploy` adopts, and a domain intermediate fits it unchanged.
