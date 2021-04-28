"""
Main module of the server file
"""

import json
from json.decoder import JSONDecodeError
import os
import argparse
from app import create_app
from config import YamlConfig
from pathlib import Path
from flask import request, g


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
    config_file = os.environ.get('CAPSULE_API_CONFIG')

if config_file is None:
    if Path('config.yml').is_file():
        config_file = 'config.yml'
    else:
        config_file = '/etc/capsule-api/config.yml'

yamlconfig = YamlConfig(config_file)

connex_app = create_app(yamlconfig)
app = connex_app.app

from app import oidc


@app.after_request
def log_request_info(response):
    if request.method == "OPTIONS":  # ignore noise from front
        return response

    # Get username from token
    if hasattr(g, 'capsule_app_token'):  # Get user name from application token
        name = g.capsule_app_token
    else:  # look with keycloak by validating token
        try:
            token = request.headers['Authorization'].split(None, 1)[1].strip()
            if oidc._validate_token(token):
                name = g.oidc_token_info['username']
            else:
                name = "unknown"
        except (KeyError, AttributeError):
            name = "unknown"

    data = request.get_data()
    if len(data) > 0 and name != "unknown":
        try:
            payload = json.loads(data.decode('utf-8'))
        except JSONDecodeError:
            msg = f'{name} send {request.method} request with BAD data: {data}'
            app.logger.warn(msg)
            return response
        keys = ['crt', 'key']
        for key in keys:
            if key in payload:
                payload[key] = "****** secure data ******"
        p_string = json.dumps(payload)
        msg = f'{name} send {request.method} request with payload: {p_string}'
        app.logger.info(msg)

    return response


if __name__ == "__main__":
    # NOTE: reloader should be deactivated for mitigating duplicated
    #       NATS client connections
    app.logger.info(f'Configured with {Path(config_file).resolve()}')
    connex_app.run(use_reloader=False)
