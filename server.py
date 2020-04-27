"""
Main module of the server file
"""

# Local modules
from app import connex_app, app

# Read the swagger.yml file to configure the endpoints
# TODO: Voir comment on peut utiliser une spec découpée
# TODO: Activer la validation des réponses avec `validate_responses=true`
connex_app.add_api('openapi.json', strict_validation=True)

if __name__ == "__main__":
    connex_app.run(debug=True)
