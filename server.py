"""
Main module of the server file
"""

# import os
# import argparse
from app import create_app
# from config import YamlConfig
# from pathlib import Path
from utils import get_config


# parser = argparse.ArgumentParser()
# parser.add_argument(
#     '--config', '-c',
#     dest='config_file',
#     type=str,
#     required=False,
#     help="The YAML configuration file of the API server.",
# )

# # Parse only known arguments because others arguments are added during
# # a DB migration.
# args, unknown = parser.parse_known_args()
# config_file = args.config_file

# # The default YAML config file is the option is not provided.
# if config_file is None:
#     config_file = os.environ.get('CAPSULE_API_CONFIG')

# if config_file is None:
#     if Path('config.yml').is_file():
#         config_file = 'config.yml'
#     else:
#         config_file = '/etc/capsule-api/config.yml'

yamlconfig = get_config()

connex_app = create_app(yamlconfig)
app = connex_app.app

if __name__ == "__main__":
    # NOTE: reloader should be deactivated for mitigating duplicated
    #       NATS client connections
    # app.logger.info(f'Configured with {Path(config_file).resolve()}')
    connex_app.run(use_reloader=False)
