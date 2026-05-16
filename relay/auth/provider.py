from __future__ import annotations

from relay.extensions import db, oauth
from relay.models.organization import Organization, OIDCProvider, OrgDomain
from authlib.jose.errors import JoseError

_registered: set[str] = set()

def get_provider_for_domain(domain: str) -> OIDCProvider | None:
    return db.session.scalar(db.select(OIDCProvider).join(OIDCProvider.organization).join(Organization.domains).where(OrgDomain.domain == domain, OrgDomain.verified==True))

def get_oauth_client(config: OIDCProvider):
    name = f"org_{config.organization_id}"

    if name not in _registered:
        oauth.register(
            name,
            client_id=config.client_id,
            client_secret=config.client_secret,
            server_metadata_url=f"{config.issuer}/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
        )
        _registered.add(name)
    return oauth.create_client(name)

def clear_provider_cache(organization_id: str) -> None:
    name = f"org_{organization_id}"
    oauth._registered.discard(name)
    oauth._clients.pop(name, None)

    
