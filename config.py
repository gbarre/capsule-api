import yaml
from exceptions import ConfigError


class YamlConfig:

    def __init__(self, config_file):
        try:
            with open(config_file) as f:
                config = yaml.full_load(f)
        except FileNotFoundError:  # pragma: no cover
            raise ConfigError(f"File {config_file} not found.")

        try:
            api = config['api']
            self.APP_NAME = api['app_name']
            self.HOST = api['host']
            self.PRIVATE_KEY = api['rsa_private_key']
            self.DEBUG = api['debug']
            self.SECRET_KEY = api['secret_key']
            self.ENV = api['env']
            self.CLUSTER_PARTS = api['cluster_parts']
            self.VOLUMES_GLOBAL_SIZE = api['volumes_size']['global']
            self.VOLUMES_DEFAULT_SIZE = api['volumes_size']['default']
            self.ADMINS = api['admins']
            self.SUPERADMINS = api['superadmins']

            self.NATS_URI = api['nats']['uri']
            self.NATS_CA_CERT = api['nats']['ca_cert']
            nats_log_level = api['nats']['log_level']
            if nats_log_level in ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL']:
                self.NATS_LOG_LEVEL = nats_log_level
            else:
                raise ConfigError("Config file must have "  # pragma: no cover
                                  "api>nats>log_level with a value setted in "
                                  "['DEBUG', 'INFO', 'WARN', "
                                  "'ERROR', 'FATAL'].")

            sqlalc = api['sqlalchemy']
            self.SQLALCHEMY_ECHO = sqlalc['echo']
            self.SQLALCHEMY_TRACK_MODIFICATIONS = sqlalc['track_modifications']

            # OIDC
            _oidc = api['oidc']
            self.OIDC_CLIENT_SECRETS = _oidc['client_secrets']
            self.OIDC_ID_TOKEN_COOKIE_SECURE = _oidc['id_token_cookie_secure']
            self.OIDC_REQUIRE_VERIFIED_EMAIL = _oidc['require_verified_email']
            self.OIDC_USER_INFO_ENABLED = _oidc['user_info_enabled']
            self.OIDC_OPENID_REALM = _oidc['openid_realm']
            self.OIDC_SCOPES = _oidc['scopes']
            self.OIDC_INTROSPECTION_AUTH_METHOD = \
                _oidc['introspection_auth_method']

            # Database
            self.SQLALCHEMY_DATABASE_URI = api['database_uri']

            self.SQLALCHEMY_ENGINE_OPTIONS = {
                # To avoid "SQL lost connection".
                'pool_pre_ping': True,
            }

            # Drivers
            self.DRIVERS = config['drivers']
        except KeyError as e:  # pragma: no cover
            raise ConfigError(f"The key `{e}` is not present in the YAML "
                              "configuration file.")

    def get_pubkey_from_driver(self, drivername):
        try:  # pragma: no cover
            driver = self.DRIVERS[drivername]
        except KeyError as d:  # pragma: no cover
            raise ConfigError(f"The driver `{d}` is not present in the YAML "
                              "configuration file.")
        try:  # pragma: no cover
            return driver['rsa_public_key']
        except KeyError as e:  # pragma: no cover
            raise ConfigError(f"The key `{e}` is not present in the YAML "
                              f"configuration file for the driver {driver}.")
