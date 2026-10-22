"""Credential providers as one `provider:` target sees them (§8.4, M6, M8, M18).

A `provider:` target has no stored secret and no pins. Its connector asks `TargetCredentials` for
the cluster endpoint and a token, and only while a call executes (M6 step 9, after the decision
record): nothing Azure provides is needed before the record.

- A failure names its stage: `provider.endpoint` or `provider.token` (M9).
- A minted token is registered with the scrubber before the connector sees it (M8); lock clears
  the scrubber's set and the provider's caches (M7).
- A result that arrives after the session locked is discarded (`SessionLocked`).
"""

from __future__ import annotations

from collections.abc import Mapping

from ..spi import (
    CredentialProvider,
    Endpoint,
    EndpointRequest,
    MintedToken,
    ProviderTarget,
    TokenRequest,
    UpstreamFailure,
)
from .scrub import Scrubber
from .secrets import CallScope, SessionLocked, current_scope
from .session import Session

STAGE_ENDPOINT = "provider.endpoint"
STAGE_TOKEN = "provider.token"


class TargetCredentials:
    """The `Credentials` of one `provider:` target."""

    def __init__(
        self,
        provider: CredentialProvider,
        target: ProviderTarget,
        *,
        scrubber: Scrubber,
        session: Session,
    ) -> None:
        self.provider = provider
        self.target = target
        self._scrubber = scrubber
        self._session = session

    def _scope(self) -> CallScope:
        scope = current_scope()
        if scope is None:
            raise RuntimeError("a credential provider is used only while a call executes")
        self._still_unlocked(scope)
        return scope

    def _still_unlocked(self, scope: CallScope) -> None:
        if not self._session.is_current(scope.epoch):
            raise SessionLocked

    async def endpoint(self, cluster: Mapping[str, str]) -> Endpoint:
        scope = self._scope()
        request = EndpointRequest(self.target, tuple(sorted(cluster.items())))
        try:
            found = await self.provider.endpoint(request)
        except UpstreamFailure as exc:
            raise UpstreamFailure(str(exc), stage=STAGE_ENDPOINT) from None
        self._still_unlocked(scope)
        return found

    async def token(self, resource: str) -> MintedToken:
        scope = self._scope()
        try:
            minted = await self.provider.mint(TokenRequest(self.target, resource))
        except UpstreamFailure as exc:
            raise UpstreamFailure(str(exc), stage=STAGE_TOKEN) from None
        self._still_unlocked(scope)
        if not minted.value:
            raise UpstreamFailure(
                f"the {self.provider.name} provider returned an empty token", stage=STAGE_TOKEN
            )
        self._scrubber.add(minted.value)
        return minted
