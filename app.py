import os
import connexion
import logging
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_oidc import OpenIDConnect
from config import LocalConfig

# TODO: variabiliser la création d'application avec un objet config

basedir = os.path.abspath(os.path.dirname(__file__))

# Create the connexion application instance
connex_app = connexion.App(
    __name__, specification_dir=os.path.join(basedir, 'spec'))

# Get the underlying Flask app instance
app = connex_app.app
app.config.from_object(LocalConfig)

# Create the SqlAlchemy db instance
db = SQLAlchemy(app)

# Initialize Migration
migrate = Migrate(app, db)

# Initialize Marshmallow
ma = Marshmallow(app)

# Initialize OpenIDConnect
oidc = OpenIDConnect(app)