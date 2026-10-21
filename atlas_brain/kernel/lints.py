"""Nested repetition shape support for the regex lint; no engine execution."""
import ast
import re


def nested_unbounded(pattern: str) -> bool:
    """Track groups, escaped characters and character classes before repeats."""
    stack: list[bool] = [False]
    last_group = False
    escaped = in_class = False
    for index, char in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            last_group = False
            continue
        if char == '[':
            in_class = True
        if in_class:
            if char == ']':
                in_class = False
            continue
        if char == '(':
            stack.append(False)
        elif char == ')':
            last_group = stack.pop() if len(stack) > 1 else False
            stack[-1] |= last_group
            continue
        elif char in '*+' or (char == '{' and re.search(r'^\{\d+,\}', pattern[index:], re.ASCII)):
            if last_group:
                return True
            stack[-1] = True
        last_group = False
    return False


def resolved_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve an AST name using the scanner's supplied import environment."""
    if isinstance(node, ast.Name):
        if node.id not in aliases:
            return node.id
        return aliases[node.id]
    if isinstance(node, ast.Attribute):
        return resolved_name(node.value, aliases) + '.' + node.attr
    if isinstance(node, ast.Subscript):
        return resolved_name(node.value, aliases)
    return ''


def resolved_tail(node: ast.AST, aliases: dict[str, str]) -> str:
    return resolved_name(node, aliases).split('.')[-1]


def contains_name(node: ast.AST, names: tuple[str, ...], aliases: dict[str, str]) -> bool:
    return any(resolved_tail(part, aliases) in names for part in ast.walk(node))
