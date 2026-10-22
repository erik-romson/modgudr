"""The `store.bws` block of the company file (M19): `project` and an optional `serverUrl`.

`mode` and `tokenFile` stay refused: the policy loader refuses them at load (M10), and this model
forbids every key it does not name.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator


class BwsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    #: The project uuid whose secrets this store serves.
    project: str
    #: The Bitwarden server, for example the EU vault; the default cloud when unset.
    serverUrl: str | None = None

    @field_validator("project")
    @classmethod
    def _project(cls, value: str) -> str:
        try:
            return str(uuid.UUID(value))
        except ValueError:
            raise ValueError("must be the project's uuid") from None

    @field_validator("serverUrl")
    @classmethod
    def _server(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or any(c.isspace() or ord(c) < 32 or c in '"\\' for c in value)
        ):
            raise ValueError("must be an https:// URL without userinfo")
        return value


def parse_settings(raw: Mapping[str, object]) -> BwsSettings:
    """Validate the block. Raises `ValueError` naming the keys at fault, never their values."""
    try:
        return BwsSettings.model_validate(dict(raw))
    except ValidationError as exc:
        problems = [
            f"store.bws.{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False)
        ]
        raise ValueError("; ".join(problems)) from None
