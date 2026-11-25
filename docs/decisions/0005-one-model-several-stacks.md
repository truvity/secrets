# 0005 — One model may be applied as several stacks

**Status:** Accepted
**Date:** 2026-11-25

## Context

`pkg/apply` registers a whole [model.Desired] in one Pulumi program, so an
installation holds its OpenBAO configuration in one stack. An estate that
serves several tenants then has one stack that every tenant's change goes
through: a pending change of one tenant shows in the preview of another,
and a deploy for one carries the other's along. Splitting the model into
several models does not help: a tenant's grants (its policies, groups and
aliases, its PKI and SSH roles) live inside the platform's namespaces and
mounts and refer to them, by path and by an auth mount's accessor.

## Decision

`Options.Select` chooses which resources of the one model a run registers.
The caller passes a predicate over `apply.Resource{Type, Name}` (the Pulumi
type token and the logical name after `Rename`); the provider is always
registered. Every stack runs the same model with its own predicate, and the
predicates partition the model.

A selected resource that refers to an unselected one takes that reference
from what the model already declares or from the server, never from
another stack's outputs:

- a namespace or a mount by its declared path, with no dependency on it;
- an auth mount's accessor with the `getAuthBackend` data source, read once
  per mount and only when a registered resource needs it.

Some resources only make sense together, and a selection that splits them
is refused: a mount and its CA, its issuers and their configuration; an AWS
auth mount and its client; a KV mount and its canary; an identity group and
its alias. `Deploy` checks the whole model for such a split in a pass of its
own before it registers anything, the provider included, so a refused
selection never leaves a partial apply behind.

## Consequences

- With `Select` unset, `Deploy` registers exactly what it did; the resources
  golden does not change.
- The names are the same in every split, so a state is split with
  `pulumi state move`, and joined back the same way.
- The stack that owns the namespaces, mounts and auth mounts is applied
  before the stacks that refer to them; on a fresh server the others fail
  their lookup until it is, with an error that names the auth mount and
  says to apply the stack that owns it first.
- A tenant's stack reads from the server on preview, so it needs the same
  login as the platform's.
- What is selected is the caller's choice. This library refuses only the
  splits that cannot work; that each resource lands in exactly one stack is
  the caller's to prove (a test over its own predicates).

## Alternatives considered

**One model per stack.** Rejected: a tenant's grants refer to the
platform's mounts and auth mounts, which a second model would have to
declare too, and then two stacks would own the same object.

**Stack references between the stacks.** Rejected: every reference the
grants need is either declared in the model already (a path) or readable
from the server (an accessor). A stack reference would add an output
contract between stacks and an ordering through Pulumi, with nothing it
knows that the model does not.
