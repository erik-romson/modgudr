"""Snowflake's catalogues and statement rules (§7.2, §8.1, M12).

Snowflake has no read-only transaction, so read safety rests on this classification and on the
role's rights (edge case SF-07). Leaving the account is `admin`: `SYSTEM$*` functions, stage
COPY (shared code), `PUT`, `GET`, `REMOVE`. Revealing a credential is `secret`.
"""

from __future__ import annotations

from collections.abc import Mapping

from modgudr.spi import Risk
from modgudr.sql.catalogue import Catalogue, DialectRules, WordRule

SQLGLOT_DIALECT = "snowflake"

#: Functions by normalised name. `SYSTEM$*` reaches outside the query (cancel, abort, pipes,
#: tasks) and is `admin`, except the read allowlist; `SYSTEM$GET_*` returns tokens, keys and
#: configuration and is `secret`. The `*.` forms catch a qualified spelling of the same names.
#: Every other function is not in the catalogue, so `read` (assumption A9).
FUNCTIONS: Mapping[str, Risk] = {
    "SYSTEM$*": Risk.ADMIN,
    "*.SYSTEM$*": Risk.ADMIN,
    "SYSTEM$GET_*": Risk.SECRET,
    "*.SYSTEM$GET_*": Risk.SECRET,
    "SYSTEM$TYPEOF": Risk.READ,
}

#: Objects by normalised name. Snowflake's secret objects are reached through statements
#: (`SHOW SECRETS`, `DESCRIBE SECRET`, below), not through tables or views.
OBJECTS: Mapping[str, Risk] = {}

#: Statements classified on their first words before parsing. sqlglot cannot parse
#: `DESCRIBE SECRET s` at all and reads `DESCRIBE INTEGRATION i` as an ordinary DESCRIBE.
LEADING: tuple[WordRule, ...] = (
    WordRule.of("DESCRIBE|DESC SECRET", "describe", Risk.SECRET),
    WordRule.of("DESCRIBE|DESC INTEGRATION", "describe", Risk.SECRET),
    WordRule.of(
        "DESCRIBE|DESC STORAGE|SECURITY|API|NOTIFICATION|CATALOG INTEGRATION",
        "describe",
        Risk.SECRET,
    ),
    WordRule.of("DESCRIBE|DESC EXTERNAL ACCESS INTEGRATION", "describe", Risk.SECRET),
)

#: `exp.Command` forms of Snowflake, checked before the shared ones. Any other Command is
#: `sql:unknown` (`SHOW GRANTS`, `SHOW ROLES`, …).
COMMANDS: tuple[WordRule, ...] = (
    WordRule.of("SHOW SECRETS", "show", Risk.SECRET),
    WordRule.of("SHOW INTEGRATIONS", "show", Risk.SECRET),
    # Stage files: `GET @stage file://…` downloads, `REMOVE`/`RM` deletes staged files.
    WordRule.of("GET", "get", Risk.ADMIN),
    WordRule.of("REMOVE|RM", "remove", Risk.ADMIN),
)

RULES = DialectRules(
    sqlglot_dialect=SQLGLOT_DIALECT,
    functions=Catalogue(FUNCTIONS),
    objects=Catalogue(OBJECTS),
    leading=LEADING,
    commands=COMMANDS,
    block_words=frozenset({"BEGIN", "DECLARE"}),
)
