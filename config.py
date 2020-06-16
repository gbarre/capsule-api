import yaml


class YamlConfig:

    def __init__(self, config_file):
        try:
            with open(config_file) as f:
                config = yaml.full_load(f)
        except FileNotFoundError:
            config = None

        # TOOD: KeyError to manage.
        api = config['api']
        self.APP_NAME = api['app_name']
        self.HOST = api['host']
        self.PRIVATE_KEY = api['rsa_private_key']
        self.NATS_URI = api['nats']['uri']
        self.DEBUG = api['debug']
        self.SECRET_KEY = api['secret_key']
        self.ENV = api['env']

        sqlalc = api['sqlalchemy']
        self.SQLALCHEMY_ECHO = sqlalc['echo']
        self.SQLALCHEMY_TRACK_MODIFICATIONS = sqlalc['track_modifications']

        # OIDC
        # TODO: get client secrets config in the same YAML file with overriding
        #  of the method load_secrets from the class OpenIDConnect.
        _oidc = api['oidc']
        self.OIDC_CLIENT_SECRETS = _oidc['client_secrets']
        self.OIDC_ID_TOKEN_COOKIE_SECURE = _oidc['id_token_cookie_secure']
        self.OIDC_REQUIRE_VERIFIED_EMAIL = _oidc['require_verified_email']
        self.OIDC_USER_INFO_ENABLED = _oidc['user_info_enabled']
        self.OIDC_OPENID_REALM = _oidc['openid_realm']
        self.OIDC_SCOPES = _oidc['scopes']
        self.OIDC_INTROSPECTION_AUTH_METHOD = _oidc['introspection_auth_method']

        # Database
        self.SQLALCHEMY_DATABASE_URI = api['database_uri']

        # Drivers
        self.DRIVERS = config['drivers']

    def get_pubkey_from_driver(self, drivername):
        # TODO: Catch KeyError.
        return self.DRIVERS[drivername]['rsa_public_key']
