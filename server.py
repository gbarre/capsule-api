"""
Main module of the server file
"""

from app import create_app
from nats import thread
from config import LocalConfig
# TODO: Move CORS in app.py
from flask_cors import CORS

connex_app = create_app(LocalConfig)
app = connex_app.app
CORS(app)

if __name__ == "__main__":
    nats_listener = thread.NATSListener()
    nats_listener.start()
    connex_app.run()
