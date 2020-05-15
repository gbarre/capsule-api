"""
Main module of the server file
"""

from app import create_app
from config import LocalConfig
from flask_cors import CORS

connex_app = create_app(LocalConfig)
app = connex_app.app
CORS(app)

if __name__ == "__main__":
    connex_app.run()
