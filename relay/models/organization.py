from __future__ import annotations
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
import sqlalchemy.orm as so
from sqlalchemy.orm import validates

from relay.extensions import db
from relay.security.encryption import EncryptedString
from ulid import ULID

if TYPE_CHECKING:
    from relay.models.user import User

class Organization(db.Model):
    __tablename__ = "organizations"

    id: so.Mapped[str] = so.mapped_column(sa.String(255), primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.String(255))
    slug: so.Mapped[str] = so.mapped_column(sa.String(100), unique=True, index=True)
    created_at: so.Mapped[datetime] = so.mapped_column(default=datetime.utcnow)

    domains: so.Mapped[list[OrgDomain]] = so.relationship(back_populates="organization")
    oidc_provider: so.Mapped[OIDCProvider | None] = so.relationship(back_populates="organization", uselist=False)
    saml_provider: so.Mapped[SAMLProvider | None] = so.relationship(back_populates="organization", uselist=False)

    users: so.Mapped[list[User]] = so.relationship(back_populates="organization")

    @property
    def sso_required(self) -> bool:
        oidc_required = self.oidc_provider is not None and self.oidc_provider.enforce_sso
        saml_required = self.saml_provider is not None and self.saml_provider.enforce_sso
        return oidc_required or saml_required
    
    @validates("slug")
    def _normalize_slug(self, key: str, value: str) -> str:
        return value.lower().strip() if value else value
    
class OrgDomain(db.Model):
    __tablename__ = "org_domains"

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    organization_id: so.Mapped[str] = so.mapped_column(sa.String(255), sa.ForeignKey("organizations.id"), index=True)
    domain: so.Mapped[str] = so.mapped_column(sa.String(255), unique=True, index=True)
    verified: so.Mapped[bool] = so.mapped_column(default=False)
    verification_token: so.Mapped[str | None] = so.mapped_column(sa.String(64))
    organization: so.Mapped[Organization] = so.relationship(back_populates="domains")

class OIDCProvider(db.Model):
    __tablename__ = "oidc_providers"

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    organization_id: so.Mapped[str] = so.mapped_column(sa.ForeignKey("organizations.id"), unique=True, index=True)
    issuer: so.Mapped[str] = so.mapped_column(sa.String(512))
    client_id: so.Mapped[str] = so.mapped_column(sa.String(255))
    client_secret: so.Mapped[str] = so.mapped_column(EncryptedString(1024))
    enforce_sso: so.Mapped[bool] = so.mapped_column(default=False)
    organization: so.Mapped[Organization] = so.relationship(back_populates="oidc_provider")

class SAMLProvider(db.Model):
    __tablename__ = "saml_providers"

    id: so.Mapped[str] = so.mapped_column(sa.String(26), primary_key=True, default=lambda: str(ULID()))
    organization_id: so.Mapped[str] = so.mapped_column(sa.ForeignKey("organizations.id"), unique=True,index=True)
    idp_entity_id: so.Mapped[str] = so.mapped_column(sa.String(512))
    idp_sso_url: so.Mapped[str] = so.mapped_column(sa.String(512))
    idp_x509_cert: so.Mapped[str] = so.mapped_column(sa.Text)
    name_id_format: so.Mapped[str] = so.mapped_column(sa.String(255), default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    email_attribute: so.Mapped[str | None] = so.mapped_column(sa.String(255))
    name_attribute: so.Mapped[str | None] = so.mapped_column(sa.String(255))
    enforce_sso: so.Mapped[bool] = so.mapped_column(default=False)
    sp_private_key: so.Mapped[str | None] = so.mapped_column(EncryptedString(4096))
    sp_certificate: so.Mapped[str | None] = so.mapped_column(sa.Text)

    organization: so.Mapped[Organization] = so.relationship(back_populates="saml_provider")