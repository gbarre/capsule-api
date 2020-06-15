import yaml


class YamlConfig:

    def __init__(self, config_file):
        try:
            with open(config_file) as f:
                config = yaml.full_load(f)
        except FileNotFoundError:
            config = None

        # TOOD: KeyError to manage.
        self.APP_NAME = config['api']['app_name']
        self.HOST = config['api']['host']
        self.PRIVATE_KEY = config['api']['rsa_private_key']
        self.NATS_URI = config['api']['nats']['uri']
        self.DEBUG = config['api']['debug']
        self.SECRET_KEY = config['api']['secret_key']
        self.ENV = config['api']['env']
        self.SQLALCHEMY_ECHO = config['api']['sqlalchemy']['echo']
        self.SQLALCHEMY_TRACK_MODIFICATIONS = config['api']['sqlalchemy']['track_modifications']

        # OIDC
        # TODO: get client secrets config in the same YAML file with overriding
        #  of the method load_secrets from the class OpenIDConnect.
        self.OIDC_CLIENT_SECRETS = config['api']['oidc']['client_secrets']
        self.OIDC_ID_TOKEN_COOKIE_SECURE = config['api']['oidc']['id_token_cookie_secure']
        self.OIDC_REQUIRE_VERIFIED_EMAIL = config['api']['oidc']['require_verified_email']
        self.OIDC_USER_INFO_ENABLED = config['api']['oidc']['user_info_enabled']
        self.OIDC_OPENID_REALM = config['api']['oidc']['openid_realm']
        self.OIDC_SCOPES = config['api']['oidc']['scopes']
        self.OIDC_INTROSPECTION_AUTH_METHOD = config['api']['oidc']['introspection_auth_method']

        # Database
        self.SQLALCHEMY_DATABASE_URI = config['api']['database_uri']

        # Drivers
        self.DRIVERS = config['drivers']

    def get_pubkey_from_driver(self, drivername):
        # TODO: Catch KeyError.
        return self.DRIVERS[drivername]['rsa_public_key']
