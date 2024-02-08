import os
import connexion
import prance
from typing import Any, Dict
from pathlib import Path
import werkzeug
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import logging

from config import YamlConfig

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


def get_bundled_specs(main_file: Path) -> Dict[str, Any]:
    parser = prance.ResolvingParser(
        str(main_file.absolute()),
        lazy=True,
        strict=True,
    )
    parser.parse()
    return parser.specification


def create_app(config: YamlConfig):
    # Manage swagger ui config
    swagger_ui_config = config.SWAGGER_UI_CONFIG
    api_version = config.API_VERSION

    options = {}
    options['swagger_ui_config'] = {}
    options['swagger_ui_config']['urls'] = []

    for o in swagger_ui_config['urls']:
        options['swagger_ui_config']['urls'].append({
            "url": f'{o["url"]}{api_version}/openapi.json',
            "name": f'{o["name"]}'
        })

    # Create the connexion application instance
    connex_app = connexion.App(
        __name__,
        options=options,
    )

    # Read the swagger file to configure the endpoints
    connex_app.add_api(
        get_bundled_specs(
            Path("spec/index.yml"),
        ),
        resolver=connexion.RestyResolver("rest_api"),
        strict_validation=True,
        validate_responses=True,
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

    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers

    @app.route('/')
    def root():
        return f'The specification for {config.APP_NAME} is available '\
               f'<a href="./{api_version}/ui/">here</a>.'

    # Initializing app extensions
    db.init_app(app)
    migrate.init_app(app, db)
    ma.init_app(app)
    oidc.init_app(app)
    cors.init_app(app)
    nats_listener = create_nats_listener(app, config)
    nats_listener.start()
    return connex_app
