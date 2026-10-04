# ADR-0002 — Declarative, rule-based policy engine

* **Status:** Accepted
* **Spec:** `pront.md` §19, §37, §50

## Context

The classifier answers *"what is this content?"*. Enforcement needs a separate
answer to *"what do we do about it?"* §50 requires that models can be swapped
**without** changing the firewall, API or policy — so verdict→action mapping must
live outside the inference code.

A previous implementation used a compiled-lambda/predicate style rule, which made
policy opaque and un-serialisable in practice. A second concern is **tenant
isolation** (§37): different customers legitimately need different outcomes.

## Decision

Implement policy as **ordered, declarative rules** in the top-level `policy`
package (`policy/models.py`, `policy/engine.py`):

```json
{ "field": "verdict", "operator": "==", "value": "NSFW", "action": "block" }
```

* First matching rule wins; otherwise `default_action` applies.
* Operators: `> >= < <= == != in "not in" contains matches` — **no `eval`**, so a
  policy file can never execute code.
* `PolicyRegistry` resolves a tenant policy over the global one, and a tenant
  override keeps the *global* default action so a tenant cannot widen access by
  omission.
* Every decision records which rule fired (audit, §18/§47).
* `app/core/policy.py` is a thin bridge that flattens a `ClassificationResult`
  into a rule context — it never imports the orchestrator (no import cycle) and
  means file-based and config-based policies run through identical code.

## Alternatives

| Option | Why not |
|--------|---------|
| Hard-coded `if verdict == NSFW` | Breaks §50: every model swap touches enforcement |
| JSON Logic / CEL / Rego | Powerful, but adds a heavy dependency and a new language to audit |
| Database-backed policies | Correct at scale, but unnecessary latency on the hot path; revisit if §33 needs it |

## Consequences

* **Positive:** policies are diffable, reviewable by security auditors, and
  hot-swappable; tenant scoping is first-class.
* **Negative:** no arithmetic in rules (no "score > 0.9 **and** text > 0.5" in one
  rule) — expressiveness is traded for auditability. Extend with more rules if
  a real policy needs it.
* **Security impact:** malformed rules are skipped and logged rather than
  aborting evaluation, so one bad line cannot fail open or halt enforcement.

## License impact

None; first-party code.