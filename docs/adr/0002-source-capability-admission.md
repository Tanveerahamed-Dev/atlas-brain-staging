# ADR-0002: Default-closed source capability admission

Status: proposed

The standard library includes dynamic import and code-execution helpers.
Membership in it alone does not admit an engine source capability.

Admit only the named standard-library APIs in `tools/fence.py:STDLIB_API`.
The initial 22 entries cover current engine imports and existing positive controls.
Every new API requires an owner-approved update; engine-internal imports remain
subject to the same source gate. No pack-loader exception exists.

Reject unregistered modules, exports, module-handle reflection, wildcard imports
and private attribute access except the existing constructor protocols.
Keep all existing dependency, denied-import and dynamic-code refusal plants.
Plant `pkgutil.resolve_name` through the required tracked-file command and
exercise the unregistered standard-library module class on both operating systems.

This is a source admission policy, not hostile Python containment. The separate
output witness, full runner, runtime audit and OS isolation remain distinct gates.
The tradeoff is deliberate: adding a legitimate API can block another stream
until its owner-approved admission update lands.
