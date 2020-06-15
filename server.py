"""
Main module of the server file
"""

import sys
from app import create_app
from nats.listener import create_nats_listener
from config import YamlConfig
# TODO: Move CORS in app.py
from flask_cors import CORS

# TODO: Implement a kind of --config option.
if len(sys.argv) == 1:
    config_file = './config.yml'
else:
    config_file = sys.argv[1]

# TODO: manage error config like "no such file", "bad config syntax" etc.
yamlconfig = YamlConfig(config_file)

connex_app = create_app(yamlconfig)
app = connex_app.app
nats_listener = create_nats_listener(app, yamlconfig)
CORS(app)

if __name__ == "__main__":
    nats_listener.start()
    # NOTE: reloader should be deactivated for mitigating duplicated
    #       NATS client connections
    connex_app.run(use_reloader=False)
