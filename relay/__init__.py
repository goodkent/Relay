from __future__ import annotations
import os
import click

from dotenv import load_dotenv
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from relay.config import Config, DevelopmentConfig, ProductionConfig
from relay.extensions import db, migrate, csrf, db, login_manager

def create_app(config_class: type[Config] = DevelopmentConfig) -> Flask:
    load_dotenv()

    app = Flask(__name__)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    if config_class is None:
        env = os.environ.get("FLASK_ENV", "development")
        config_class = ProductionConfig if env == "production" else DevelopmentConfig
    
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app,db)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    from relay.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    from relay.main import bp as main_bp
    app.register_blueprint(main_bp)

    @app.cli.command("create-user")
    @click.argument("email")
    @click.password_option()
    def create_user(email: str, password: str) -> None:
        """Create a new local user for testing."""
        from relay.models.user import User
        from ulid import ULID
        user = User(id=str(ULID()), email=email.lower())
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Created user: {email}")
    return app

