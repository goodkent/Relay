from __future__ import annotations
import os
from dotenv import load_dotenv
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from relay.config import Config, DevelopmentConfig, ProductionConfig
from relay.extensions import db, migrate

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

    from relay.main import bp as main_bp
    app.register_blueprint(main_bp)

    return app