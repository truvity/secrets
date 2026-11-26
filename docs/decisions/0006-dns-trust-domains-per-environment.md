# 0006 — Any number of DNS trust domains, each reaching its own environments

**Status:** Accepted
**Date:** 2026-11-26

## Context

A contract could already declare any number of DNS trust domains, but
`pki.Contract.Derive` gave every environment every one of them, and
`pkg/estate` knew two zones per cluster: `PrivateZone`, for every DNS domain
but the origin one, and `OriginZone`. That fits an estate with one private
suffix. It does not fit an estate that serves several parties, each with
its own private suffix in only some environments, where one party's chain
must not be able to sign another's names. A further domain then either
substituted the private zone for `{zone}`, a name outside its own
intermediate's constraint, or needed a zone in every environment, including
ones that have none.

## Decision

A DNS trust domain may list its environments (`environments`), with the
same meaning as a URI domain's list: an environment it does not list gets
no issuing CA, roles or mount of it, and needs no zone for it. Left out,
the list means every environment, so a contract written before it derives
what it did. The domain intermediate is one either way, in the root
namespace.

`pkg/estate` gives every DNS domain other than `PKI.Private` and
`PKI.Origin` its zone from the cluster's `Zones`, keyed by the domain's
name. A further domain that reaches a cluster without an entry is refused,
and so is an entry that no such domain reads: a zone nothing reads is a
mistake in the inputs, not a default.

## Consequences

- An existing contract and an existing set of estate inputs derive byte for
  byte what they did; the derive and estate goldens do not change.
- A party's domain gets its own intermediate, constrained to its own suffix,
  so its environments' issuing CAs can sign nothing under another party's
  suffix. Each such intermediate is a further root signature in the
  ceremony.
- `Cluster.Zones` must not name the private or origin domain. Those keep
  their own fields, so there is one place each zone is written.
- Which environments a domain reaches is the contract's choice. That each
  listed environment exists is the consumer's to prove: a name with no
  environment behind it derives nothing, as for a URI domain.

## Alternatives considered

**One intermediate for several suffixes.** Rejected: a domain has one
suffix and one zone per environment, so this needs a domain with several
zones, and one key would then cover every party.

**Widen the private domain's intermediate with further suffixes and give
them `static` roles.** Rejected: a literal pattern is the same in every
environment, so one environment's issuing CA could sign another's names,
and the chain every workload already trusts would change.
