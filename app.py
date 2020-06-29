import os
import connexion
import werkzeug
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

# Create the SQLAlchemy db instance.
# Warning: this object can be imported in another modules below, so
# it must be created before.
db = SQLAlchemy()

from flask_migrate import Migrate
from flask_marshmallow import Marshmallow

# Initialize Marshmallow.
# Warning: this object can be imported in another modules below, so
# it must be created before.
ma = Marshmallow()

from flask_oidc import OpenIDConnect
from exceptions import render_exception
from nats import NATS


basedir = os.path.abspath(os.path.dirname(__file__))


# Wrapper of the class XOpenIDConnect to load the legacy config file
# client_secrets.json directly from the YAML configuration file.
class XOpenIDConnect(OpenIDConnect):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load_secrets(self, app):
        return app.config['OIDC_CLIENT_SECRETS']


# Initialize Migration
migrate = Migrate()

# Initialize OpenIDConnect
oidc = XOpenIDConnect()

# Initialize NATS
nats = NATS()

# Initialize CORS
cors = CORS()

from nats.listener import create_nats_listener


def create_app(config):
    # Create the connexion application instance
    connex_app = connexion.App(
        __name__, specification_dir=os.path.join(basedir, 'spec'))

    # Read the swagger.yml file to configure the endpoints
    connex_app.add_api(
        'openapi.json',
        strict_validation=True,
        validate_responses=True
    )
    for error_code in werkzeug.exceptions.default_exceptions:
        connex_app.add_error_handler(error_code, render_exception)
    connex_app.add_error_handler(
        connexion.exceptions.ProblemException,
        render_exception
    )

    # Get the underlying Flask app instance
    app = connex_app.app
    app.config.from_object(config)

    # Initializing app extensions
    db.init_app(app)
    migrate.init_app(app, db)
    ma.init_app(app)
    oidc.init_app(app)
    cors.init_app(app)
    nats_listener = create_nats_listener(app, config)
    nats_listener.start()
    return connex_app
