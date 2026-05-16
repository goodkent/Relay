from __future__ import annotations
from datetime import datetime

from ulid import ULID
from relay.extensions import db
from relay.models.organization import Organization
from relay.models.user import User

def provision_user(claims: dict, organization: Organization) -> User:
    external_id: str = claims["sub"]
    email: str = claims.get("email","").lower()

    user = db.session.scalar(db.select(User).where(User.organization_id == organization.id, User.external_id == external_id))

    if user is None and email:
        user = db.session.scalar(db.select(User).where(User.organization_id == organization.id, User.email == email))
        if user is not None:
            user.external_id = external_id
    
    if user is None:
        user = User(id=str(ULID()),
                    organization_id=organization.id,
                    email=email,
                    display_name=claims.get("name"),
                    external_id=external_id)
        db.session.add(user)
    
    user.last_login_at = datetime.utcnow()
    db.session.commit
    return user
