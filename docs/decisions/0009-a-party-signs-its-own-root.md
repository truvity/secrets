# 0009 — A party signs its own root, from its own repository

**Status:** Accepted
**Date:** 2026-11-27

## Context

ADR 0007 lets each party hang its chains from a root of its own, with its
custody in its own account. The ceremony that signs a root, though, lived
in each consumer's own code: a repository that authored one root built the
spec from its contract, read one custody outputs file it knew the name of,
and called `ceremony.CreateRoot`. A second repository that wanted to sign
its own root had to copy that glue, and `create-root` itself signed on the
first invocation, with no review of the exact template.

## Decision

**One root command.** `openbaoctl pki sign-root` signs a root from any
repository that holds a contract, in the same two steps as
`sign-intermediate`:

- `--print-template` prints the template the contract and the key
  determine, and the SHA-256 of its TBSCertificate. With `--public-key`
  (the key's exported SubjectPublicKeyInfo) it needs no credential.
- `--confirm-template <sha256>` signs only that template: a different hash
  is refused before anything, a KMS key that is not the reviewed one is
  refused before the reservation, then `<artifact>.attempt` is reserved
  and the one signature made.

The library holds it as `ceremony.PrepareRoot`, `ceremony.SignRoot` and
`RootPlan`, so a repository that wraps the ceremony in its own command
calls the same code.

**The repository is the boundary.** The artifact is written under the
contract's own artifact directory, relative to the contract file; the
custody outputs are the generation's own account's file, checked as in
ADR 0007. A party's root, its intermediates (`sign-intermediate
--contract`) and their artifacts all live in the repository that holds
that party's contract.

**Trust without authorship.** A contract may list
`migration.trustedExternal`: a root authored in another repository,
committed here as a PEM file and pinned by its SHA-256. It joins the
trust bundle after the authored roots. It signs nothing here, and nothing
here is declared under it.

## Consequences

- A party's root ceremony needs no code of its own: a contract, that
  account's custody outputs, and the command.
- Every root signature is reviewed first, as every intermediate already
  was.
- `create-root` keeps its behaviour for hierarchy files and existing
  callers; new ceremonies use `sign-root`.
- A verifier that trusts another party's root holds that root's bytes and
  digest, reviewed in its own repository; a swapped file fails the render.
