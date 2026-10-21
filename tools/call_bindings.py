"""Conservative callable-origin joins and narrow primitive-result proofs; no permissions."""
import ast
import builtins

BUILTINS = frozenset(vars(builtins))
SCALARS = frozenset({"bool", "int", "float", "complex", "str", "bytes", "bytearray", "isinstance", "issubclass", "callable", "len", "all", "any", "hash", "id", "repr", "ascii", "format", "bin", "oct", "hex", "ord", "chr"})
SCALAR_APIS = frozenset({"json.dumps", "math.isfinite", "stat.S_ISDIR", "stat.S_ISREG"})
CARRIERS = frozenset({"iter", "next", "aiter", "anext", "list", "tuple", "set", "frozenset", "dict", "reversed", "enumerate", "zip", "sorted"})


class CallableBindings:
    def __init__(self, module, aliases, exports, declarations):
        self.module, self.aliases, self.exports, self.declarations = module, aliases, exports, declarations
        self.possible, self.values, self.definitions = {}, {}, {}
        self.external = set()

    @staticmethod
    def scope_keys(name, scope):
        parts = scope.rstrip(".").split(".") if scope else []
        return [".".join((*parts[:length], name)) for length in range(len(parts), -1, -1)]

    def external_name(self, name, scope):
        return any(key in self.external for key in self.scope_keys(name.split(".")[0], scope))

    def origins(self, value, scope):
        if isinstance(value, ast.Name):
            if self.external_name(value.id, scope):
                # Explicit outer bindings can be mutated outside this lexical walk.
                # Over-approximate named alternatives; never certify a scalar from them.
                roots = {None}
                for key, alternatives in self.possible.items():
                    if key.rsplit(".", 1)[-1] == value.id:
                        roots.update(alternatives)
                return frozenset(roots)
            for key in self.scope_keys(value.id, scope):
                if key in self.possible:
                    return frozenset(self.possible[key])
                if key in self.exports:
                    target = self.exports[key]
                    return frozenset({target if isinstance(target, str) else None})
                if key in self.declarations:
                    return frozenset({None})
            if value.id in self.aliases:
                return frozenset({self.aliases[value.id]})
            return frozenset({"builtins." + value.id if value.id in BUILTINS else None})
        if isinstance(value, ast.Attribute):
            def dotted(node):
                if isinstance(node, ast.Name):
                    return node.id
                base = dotted(node.value) if isinstance(node, ast.Attribute) else ""
                return base + "." + node.attr if base else ""
            for key in self.scope_keys(dotted(value), scope):
                if key in self.possible:
                    return frozenset(self.possible[key])
            return frozenset(root + "." + value.attr if root is not None else None
                             for root in self.origins(value.value, scope))
        if isinstance(value, ast.IfExp):
            return self.origins(value.body, scope) | self.origins(value.orelse, scope)
        if isinstance(value, ast.BoolOp):
            return frozenset().union(*(self.origins(part, scope) for part in value.values))
        return frozenset({None})

    def assign(self, name, value, scope):
        key = scope + name
        possible = self.origins(value, scope)
        self.possible.setdefault(key, set()).update(possible)
        self.values.setdefault(key, []).append((value, scope))

    def argument(self, name, scope):
        self.possible.setdefault(scope + name, set()).add(None)
        self.values.setdefault(scope + name, []).append((None, scope))

    def declare(self, node, scope):
        key, origin = scope + node.name, self.module + "." + scope + node.name
        self.possible.setdefault(key, set()).add(origin)
        definitions = self.definitions.setdefault(origin, [])
        if not any(previous is node for previous, _ in definitions):
            definitions.append((node, scope + node.name + "."))

    def predeclare(self, tree):
        def walk(node, scope=""):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                self.external.update(scope + name for name in node.names)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                self.declare(node, scope)
                self.declarations.add(scope + node.name)
                scope += node.name + "."
            for child in ast.iter_child_nodes(node):
                walk(child, scope)
        walk(tree)

    def has_carrier(self, value, scope):
        return any(root in {"builtins." + name for name in CARRIERS} for root in self.origins(value, scope))

    def primitive_call(self, value, scope):
        if not isinstance(value, ast.Call):
            return False
        origins = self.origins(value.func, scope)
        root = value.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and self.external_name(root.id, scope):
            return False
        scalar = SCALAR_APIS | {"builtins." + name for name in SCALARS}
        return bool(origins) and all(root in scalar for root in origins)
