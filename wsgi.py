from app import create_app
from config import YamlConfig


# Parse only known arguments because others arguments are added during
# a DB migration.
# args, unknown = parser.parse_known_args()
# config_file = args.config_file
config_file = None

# The default YAML config file is the option is not provided.
if config_file is None:
    config_file = './config.yml'

yamlconfig = YamlConfig(config_file)

connex_app = create_app(yamlconfig)
app = connex_app.app

if __name__ == "__main__":
    # NOTE: reloader should be deactivated for mitigating duplicated
    #       NATS client connections
    connex_app.run(use_reloader=False)
