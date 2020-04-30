"""
Main module of the server file
"""

from app import create_app
from config import LocalConfig

connex_app = create_app(LocalConfig)
app = connex_app.app

if __name__ == "__main__":
    connex_app.run()
