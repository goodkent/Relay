from flask import Blueprint
from relay.extensions import db, login_manager

bp = Blueprint("auth", __name__)

@login_manager.user_loader
def load_user(user_id: str):
    from relay.models.user import User
    return db.session.get(User, user_id)

from relay.auth import routes
