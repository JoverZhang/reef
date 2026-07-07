# Coding Rules

## Simplicity First

Minimum code that solves the problem. Nothing speculative.

No features beyond what was asked.
No abstractions for single-use code.
No "flexibility" or "configurability" that wasn't requested.
No error handling for impossible scenarios.
If you write 200 lines and it could be 50, rewrite it.
Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## Single Source of Truth

Every semantic fact must have one owner.

Do not define the same provider rule, generated profile contract, derived value, port formula, token formula, or deployment path in multiple places.
Put facts in their natural owner: core owns the derived cluster model, provider manifests own provider runtime facts, and YAML templates own readable static profile configuration.
DRY is not the goal by itself. Avoid duplicated meaning, not harmless repeated syntax.

## Project Rules

- `justfile` is the user interface. Do not add another CLI layer.
- Python is the generator and glue layer only.
- Ansible is the deployment engine only.
- Next.js serves generated subscriptions only; it does not deploy nodes.
- Do not add configuration unless `docs/DESIGN.md` requires it.
- Do not add provider plugin mechanics beyond the provider manifest and directory convention.
- Do not hardcode subscription bodies in Next.js route files.
- Generated files go under `build/` or `web/generated/`.
- Secrets never go into git.
- `.env` is local state and must not be committed.
- `REEF_SECRET` is the root seed. Do not reuse it directly as a password, URL token, or SSH key.
- CI logs must not print subscription URL tokens, generated subscription bodies, private keys, or derived passwords.
- The first implementation should optimize for the two-node-pair test matrix, not hypothetical large deployments.

## Documentation Rules

- `docs/DESIGN.md` describes product behavior and contracts.
- `docs/ARCHITECTURE.md` describes repository structure and artifact boundaries.
- Concrete provider details belong in `providers/<provider-id>/`, not in `docs/DESIGN.md`.
- If behavior changes, update docs in the same change.
