"""Name normalisation and the catalogue types the SQL dialects fill (M12).

A dialect describes itself with data: function and object catalogues (names and `*` patterns
mapped to a risk class) and word rules (leading words, `exp.Command` heads). The shared classifier
in `modgudr.sql.classify` applies them; a dialect never walks a syntax tree itself.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from sqlglot import exp

from modgudr.spi import Risk

#: Oracle's alternative spellings of the dynamic performance views, all meaning `V$…`.
_VIEW_SPELLINGS = (("GV_$", "V$"), ("GV$", "V$"), ("V_$", "V$"))


def _fold(parts: Sequence[str]) -> list[str]:
    """Case and quotes folded (`"V$SQL"`, `v$sql` and `V$SQL` are one name), `SYS.` dropped."""
    names = [part.upper() for part in parts]
    if len(names) > 1 and names[0] == "SYS":
        names = names[1:]
    return names


def function_name(parts: Sequence[str]) -> str:
    """The catalogue key of a function: `sys.utl_http.request` is `UTL_HTTP.REQUEST`."""
    return ".".join(_fold(parts))


def object_name(parts: Sequence[str]) -> str:
    """The catalogue key of a table or view: `sys.gv_$session` is `V$SESSION`."""
    names = _fold(parts)
    last = names[-1]
    for spelling, canonical in _VIEW_SPELLINGS:
        if last.startswith(spelling):
            names[-1] = canonical + last[len(spelling) :]
            break
    return ".".join(names)


def dotted_parts(node: exp.Expr) -> list[str] | None:
    """The names of a qualifier chain (`exp.Dot` of identifiers and columns), outermost first.

    None when a part is not a plain name, so the caller cannot compose a qualified name.
    """
    if isinstance(node, exp.Dot):
        left = dotted_parts(node.this)
        right = dotted_parts(node.expression)
        return None if left is None or right is None else left + right
    if isinstance(node, exp.Column):
        parts: list[str] = []
        for part in node.parts:
            if not isinstance(part, exp.Identifier):
                return None
            parts.append(part.name)
        return parts
    if isinstance(node, exp.Identifier | exp.Var):
        return [node.name]
    return None


def call_parts(call: exp.Func) -> list[str] | None:
    """The qualified name of a function call as written: `sys.utl_http.request(x)` gives
    `["sys", "utl_http", "request"]`.

    Qualified calls are `exp.Dot` chains with the call last (§5.3 of the sqlglot report). The leaf
    of an unknown function is its written name; a function sqlglot knows has its canonical name.
    None when the qualifier is not a chain of plain names.
    """
    leaf = call.name if isinstance(call, exp.Anonymous) else call.sql_name()
    parent = call.parent
    if isinstance(parent, exp.Dot) and parent.expression is call:
        qualifier = dotted_parts(parent.this)
        return None if qualifier is None else [*qualifier, leaf]
    return [leaf]


class Catalogue:
    """Names (normalised, see `function_name` and `object_name`) and `*` patterns to a class.

    An exact name wins. Otherwise the most specific matching pattern decides: the one with the
    most characters besides `*` (`SYSTEM$GET_*` before `SYSTEM$*`). Between equally specific
    patterns the higher class wins. A name no entry matches is not in the catalogue (None).
    """

    def __init__(self, entries: Mapping[str, Risk]) -> None:
        self._entries = {name.upper(): risk for name, risk in entries.items()}
        self._exact = {name: risk for name, risk in self._entries.items() if "*" not in name}
        self._patterns = [
            (re.compile(".*".join(re.escape(piece) for piece in name.split("*"))), name, risk)
            for name, risk in self._entries.items()
            if "*" in name
        ]

    @property
    def entries(self) -> Mapping[str, Risk]:
        return dict(self._entries)

    def lookup(self, name: str) -> Risk | None:
        key = name.upper()
        exact = self._exact.get(key)
        if exact is not None:
            return exact
        best: tuple[int, int, Risk] | None = None
        for pattern, text, risk in self._patterns:
            if pattern.fullmatch(key):
                candidate = (len(text) - text.count("*"), risk.rank, risk)
                if best is None or candidate[:2] > best[:2]:
                    best = candidate
        return None if best is None else best[2]


def _alternatives(word: str) -> frozenset[str]:
    return frozenset(w.upper() for w in word.split("|"))


@dataclass(frozen=True)
class WordRule:
    """A statement class keyed by its first words: `SHOW SECRETS` is `sql:show`, secret.

    Each element of `words` is a set of alternatives that the word at that position must be in.
    The statement may continue after the matched words.
    """

    words: tuple[frozenset[str], ...]
    #: The action name without the `sql:` prefix (`plsql`, `show`, `describe`).
    action: str
    risk: Risk

    @classmethod
    def of(cls, spec: str, action: str, risk: Risk) -> WordRule:
        """`WordRule.of("DESCRIBE|DESC SECRET", "describe", Risk.SECRET)`."""
        return cls(tuple(_alternatives(word) for word in spec.split()), action, risk)

    def matches(self, words: Sequence[str]) -> bool:
        if len(words) < len(self.words):
            return False
        return all(word in allowed for word, allowed in zip(words, self.words, strict=False))


@dataclass(frozen=True)
class DialectRules:
    """What the shared classifier needs from a dialect."""

    #: The sqlglot dialect name (`snowflake`, `oracle`), passed as `read=` to every parse.
    sqlglot_dialect: str
    functions: Catalogue
    objects: Catalogue
    #: Rules on the statement's first words, checked before parsing, after the shared
    #: `BEGIN`/`DECLARE` rule. For statements sqlglot cannot parse (`DESCRIBE SECRET s`).
    leading: tuple[WordRule, ...] = ()
    #: Rules for `exp.Command` on its head and the first words of its tail, checked before the
    #: shared ones (`ALTER SESSION`, `SET`, `CALL`, `EXECUTE`, `GRANT`, `REVOKE`, `EXPLAIN`).
    commands: tuple[WordRule, ...] = ()
    #: Words that are a whole statement's first word only in a PL/SQL or scripting block.
    block_words: frozenset[str] = field(default_factory=lambda: frozenset({"BEGIN", "DECLARE"}))
