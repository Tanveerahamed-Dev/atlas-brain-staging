"""Conservative admission guard for every parse-kit regex (no runtime parsers)."""
import re


# These expressions inspect pattern syntax, never capture data.
_QUANTIFIER = re.compile(r"\{(?:\d+(?:,\d*)?|,\d*)\}", re.ASCII)
_NAME = re.compile(r"\(\?P<[A-Za-z_][A-Za-z_0-9]*>", re.ASCII)


def compile_pattern(pattern: str) -> re.Pattern[bytes]:
    """Refuse nested repeats, repeated alternation and non-local constructs.

    Deliberately conservative: even a bounded repeat around a repeated group
    is refused. Patterns use ASCII syntax and match bytes, preserving offsets.
    Inline flags, lookarounds, conditional groups and backreferences are outside
    this rule-table grammar. Escapes and character classes remain opaque atoms.
    """
    try:
        compiled = re.compile(pattern.encode("ascii"), re.ASCII)
    except (UnicodeEncodeError, re.error) as exc:
        raise ValueError("invalid ASCII rule pattern") from exc
    # Each frame records whether any descendant repeats or alternates.
    frames: list[tuple[bool, bool]] = [(False, False)]
    atom = (False, False)
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if pattern[index + 1].isdigit():
                raise ValueError("backreferences are forbidden")
            index += 2
            atom = (False, False)
            continue
        if char == "[":
            index += 1
            if pattern[index] == "^":
                index += 1
            if pattern[index] == "]":
                index += 1
            while pattern[index] != "]":
                index += 2 if pattern[index] == "\\" else 1
            index += 1
            atom = (False, False)
            continue
        if char == "(":
            if pattern.startswith("(?:", index):
                index += 3
            elif pattern.startswith("(?", index):
                name = _NAME.match(pattern, index)
                if name is None:
                    raise ValueError("unsupported group construct")
                index = name.end()
            else:
                index += 1
            frames.append((False, False))
            atom = (False, False)
            continue
        if char == ")":
            atom = frames.pop()
            parent = frames[-1]
            frames[-1] = (parent[0] or atom[0], parent[1] or atom[1])
        elif char == "|":
            frames[-1] = (frames[-1][0], True)
            atom = (False, False)
        else:
            quantifier = _QUANTIFIER.match(pattern, index)
            if char in "*+?" or quantifier is not None:
                if atom[0] or atom[1]:
                    raise ValueError("nested repeat or repeated alternation")
                frames[-1] = (True, frames[-1][1])
                index = quantifier.end() if quantifier is not None else index + 1
                if index < len(pattern) and pattern[index] in "?+":
                    index += 1  # lazy / possessive modifier, not another atom
                atom = (True, False)
                continue
            atom = (False, False)
        index += 1
    return compiled

