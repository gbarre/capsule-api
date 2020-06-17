"""
Main module of the server file
"""

import argparse
from app import create_app
from nats.listener import create_nats_listener
from config import YamlConfig
# TODO: Move CORS in app.py
from flask_cors import CORS


parser = argparse.ArgumentParser()
parser.add_argument(
    '--config', '-c',
    dest='config_file',
    type=str,
    required=False,
    help="The YAML configuration file of the API server.",
)

# Parse only known arguments because others arguments are added during
# a DB migration.
args, unknown = parser.parse_known_args()
config_file = args.config_file

# The default YAML config file is the option is not provided.
if config_file is None:
    config_file = './config.yml'

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
