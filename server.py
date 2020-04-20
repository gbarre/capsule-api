"""
Main module of the server file
"""

# 3rd party moudles
from flask import render_template

# Local modules
import config
import db

db.init_db()
# Get the application instance
connex_app = config.connex_app

# Read the swagger.yml file to configure the endpoints
# TODO: Voir comment on peut utiliser une spec découpée
connex_app.add_api('openapi.json', strict_validation=True)

if __name__ == "__main__":
    connex_app.run(debug=True)
