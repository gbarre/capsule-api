import os
import connexion
import logging
import werkzeug
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_oidc import OpenIDConnect
from config import ProdConfig
from exceptions import render_exception
from nats import NATS


basedir = os.path.abspath(os.path.dirname(__file__))

# Create the SQLAlchemy db instance
db = SQLAlchemy()

# Initialize Migration
migrate = Migrate()

# Initialize Marshmallow
ma = Marshmallow()

# Initialize OpenIDConnect
oidc = OpenIDConnect()

# Initialize NATS
nats = NATS()


def create_app(config=ProdConfig):
    # Create the connexion application instance
    connex_app = connexion.App(
        __name__, specification_dir=os.path.join(basedir, 'spec'))

    # Read the swagger.yml file to configure the endpoints
    connex_app.add_api('openapi.json', strict_validation=True, validate_responses=True)
    for error_code in werkzeug.exceptions.default_exceptions:
        connex_app.add_error_handler(error_code, render_exception)

    # Get the underlying Flask app instance
    app = connex_app.app
    app.config.from_object(config)

    # Initializing app extensions
    db.init_app(app)
    migrate.init_app(app, db)
    ma.init_app(app)
    oidc.init_app(app)
    return connex_app
