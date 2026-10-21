"""An uncertain binding cannot erase a possible carrier or prove a scalar result."""
import ast

from tools.call_bindings import CallableBindings


def expression(text):
    return ast.parse(text, mode="eval").body


def test_conditional_rebinding_joins_carrier_and_unknown_origins():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.assign("carrier", expression("iter"), "factory.")
    bindings.assign("carrier", expression("lambda values: values"), "factory.")
    assert bindings.origins(expression("carrier"), "factory.") == {"builtins.iter", None}
    assert bindings.has_carrier(expression("carrier"), "factory.")
    assert not bindings.primitive_call(expression("carrier(values)"), "factory.")


def test_all_alternatives_must_prove_primitive_and_parameters_shadow_builtins():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.assign("predicate", expression("isinstance"), "factory.")
    bindings.assign("predicate", expression("issubclass"), "factory.")
    assert bindings.primitive_call(expression("predicate(value, kind)"), "factory.")
    bindings.assign("predicate", expression("unknown"), "factory.")
    assert not bindings.primitive_call(expression("predicate(value, kind)"), "factory.")
    bindings.argument("len", "factory.")
    assert not bindings.primitive_call(expression("len(value)"), "factory.")


def test_nested_scope_keeps_outer_origins_and_conditional_choices():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.assign("carrier", expression("iter if flag else len"), "outer.")
    assert bindings.origins(expression("carrier"), "outer.inner.") == {"builtins.iter", "builtins.len"}
    assert not bindings.primitive_call(expression("carrier(value)"), "outer.inner.")


def test_rebound_attribute_cannot_keep_a_primitive_api_proof():
    bindings = CallableBindings("atlas_brain.example", {"json": "json"}, {"json": "json"}, set())
    assert bindings.primitive_call(expression("json.dumps(value)"), "")
    bindings.assign("json.dumps", expression("unknown"), "")
    assert not bindings.primitive_call(expression("json.dumps(value)"), "")
