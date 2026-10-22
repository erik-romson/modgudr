"""Oracle's catalogues and statement rules (§7.2, §8.1, M12).

Oracle reads run inside a read-only transaction, but a PL/SQL package function can still leave
the database or change it: the supplied packages are `admin`, except a small read allowlist (the
one an existing Oracle diagnostics guard uses: `dbms_xplan`, `dbms_metadata`, `dbms_lob`).
Revealing a credential or a link's login is `secret`.
"""

from __future__ import annotations

from collections.abc import Mapping

from sqlglot import exp

from modgudr.spi import Risk
from modgudr.sql.catalogue import Catalogue, DialectRules, WordRule

SQLGLOT_DIALECT = "oracle"

_ADMIN_PACKAGES = ("DBMS_*", "UTL_*", "OWA_*", "HTP", "HTP.*", "HTF", "HTF.*", "APEX_*", "CTX_*")


def _functions() -> dict[str, Risk]:
    """Package prefixes are `admin`; the allowlist below them is `read`.

    The `*.` forms catch a schema-qualified spelling (`app.dbms_x.f`); `SYS.` is dropped by the
    normalisation. `HTTPURITYPE` is a constructor and its methods (`HTTPURITYPE(…).GETCLOB()`).
    """
    entries: dict[str, Risk] = {}
    for pattern in (*_ADMIN_PACKAGES, "HTTPURITYPE", "HTTPURITYPE.*"):
        entries[pattern] = Risk.ADMIN
        entries[f"*.{pattern}"] = Risk.ADMIN
    allowed = (
        "DBMS_XPLAN.*",
        "DBMS_LOB.SUBSTR",
        "DBMS_LOB.INSTR",
        "DBMS_LOB.GETLENGTH",
        "DBMS_LOB.COMPARE",
        "DBMS_METADATA.GET_DDL",
        "DBMS_METADATA.GET_GRANTED_DDL",
    )
    for name in allowed:
        entries[name] = Risk.READ
        entries[f"*.{name}"] = Risk.READ
    return entries


#: Functions by normalised name (`SYS.` dropped, upper case). Every other function is not in the
#: catalogue, so `read` (assumption A9).
FUNCTIONS: Mapping[str, Risk] = _functions()

#: Objects by normalised name: `SYS.` dropped, `V_$`, `GV$` and `GV_$` spelt `V$`. The views that
#: hold password hashes and link logins are `secret`; the dictionary and performance views are
#: `read`. The exact names win over the patterns.
OBJECTS: Mapping[str, Risk] = {
    "DBA_USERS": Risk.SECRET,
    "USER$": Risk.SECRET,
    "LINK$": Risk.SECRET,
    "USER_HISTORY$": Risk.SECRET,
    "DBA_DB_LINKS": Risk.SECRET,
    "V$*": Risk.READ,
    "DBA_*": Risk.READ,
    "ALL_*": Risk.READ,
}

_DDL_FUNCTIONS = frozenset({"DBMS_METADATA.GET_DDL", "DBMS_METADATA.GET_GRANTED_DDL"})
#: First arguments of `GET_DDL` that name a credential-bearing object.
_SECRET_DDL_TYPES = frozenset({"USER", "DB_LINK"})


def _refine_call(name: str, call: exp.Func) -> Risk | None:
    """A call over a database link is `admin`.

    `DBMS_METADATA.GET_DDL('USER', …)` and `('DB_LINK', …)` show password hashes and link logins;
    a first argument that is not a string literal could be either, so it is `secret` too.
    """
    if "@" in name:
        return Risk.ADMIN  # a function over a database link: `pkg.fn@link(x)` leaves the database
    if not any(name == ddl or name.endswith(f".{ddl}") for ddl in _DDL_FUNCTIONS):
        return None
    first = call.expressions[0] if call.expressions else None
    if (
        isinstance(first, exp.Literal)
        and first.is_string
        and first.name.strip().upper() not in _SECRET_DDL_TYPES
    ):
        return None
    return Risk.SECRET


RULES = DialectRules(
    sqlglot_dialect=SQLGLOT_DIALECT,
    functions=Catalogue(FUNCTIONS),
    objects=Catalogue(OBJECTS),
    # `ALTER SESSION`, `SET`, `CALL`, `EXECUTE`, `GRANT` and `REVOKE` are the shared `exp.Command`
    # rules. Oracle's only EXPLAIN is `EXPLAIN PLAN` (it writes PLAN_TABLE: only the `plan` op
    # runs it); `EXPLAIN ANALYZE …` and the like are unknown.
    commands=(WordRule.of("EXPLAIN PLAN", "explain", Risk.READ),),
    dropped_shared_commands=frozenset({"explain"}),
    block_words=frozenset({"BEGIN", "DECLARE", "START"}),
    refine_call=_refine_call,
)
