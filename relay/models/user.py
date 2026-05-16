from __future__ import annotations
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
import sqlalchemy.orm as so
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from relay.extensions import db

if TYPE_CHECKING:
    from relay.models.organization import Organization

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id: so.Mapped[str] = so.mapped_column(sa.String(26), primary_key=True)
    organization_id: so.Mapped[str | None] = so.mapped_column(sa.String(255), sa.ForeignKey("organizations.id"), index=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(255), unique=True, index=True)
    display_name: so.Mapped[str | None] = so.mapped_column(sa.String(255))
    external_id: so.Mapped[str | None] = so.mapped_column(sa.String(255), index=True)
    password_hash: so.Mapped[str | None] = so.mapped_column(sa.String(255))
    active: so.Mapped[bool] = so.mapped_column(sa.Boolean, default=True)
    created_at: so.Mapped[datetime] = so.mapped_column(default=datetime.utcnow)
    last_login_at: so.Mapped[datetime | None] = so.mapped_column()

    organization: so.Mapped[Organization] = so.relationship(back_populates="users")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if self.password_hash is None:
            return False
        return check_password_hash(self.password_hash, password)
    
    __table_args__ = (
        sa.UniqueConstraint("organization_id", "email", name="uq_user_org_email"),
    )