from flask import Blueprint

bp = Blueprint("main", __name__)

from relay.main import routes
