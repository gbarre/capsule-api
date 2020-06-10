import os
from dotenv import load_dotenv

load_dotenv()

# TODO: Decide the way that we want to configure
#       the application (INI, ENV, YAML, etc.)


class Config(object):
    """Global cofnguration object."""
    APP_NAME = 'capsule-api'
    DEBUG = False
    SQLALCHEMY_ECHO = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'SomethingNotEntirelySecret'

    # OIDC
    OIDC_CLIENT_SECRETS = 'client_secrets.json'
    OIDC_ID_TOKEN_COOKIE_SECURE = False
    OIDC_REQUIRE_VERIFIED_EMAIL = False
    OIDC_USER_INFO_ENABLED = True
    OIDC_OPENID_REALM = 'flask-demo'
    OIDC_SCOPES = ['openid', 'email', 'profile']
    OIDC_INTROSPECTION_AUTH_METHOD = 'client_secret_post'


class ProdConfig(Config):
    # FIXME: Fix production configuration
    ENV = 'production'


class TestConfig(Config):
    # FIXME: Fix test configuration
    ENV = 'test'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_capsule.db'
    OIDC_CLIENT_SECRETS = 'client_secrets.json.sample'
    NATS_URI = 'nats://localhost:4222'


class LocalConfig(Config):
    ENV = 'development'
    DEBUG = True
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = '{driver}://{user}:{passw}@{host}:{port}/{db}'\
        .format(
            driver='mysql+pymysql',
            user='root',
            passw=os.environ.get('MYSQL_ROOT_PASSWORD'),
            host='localhost',
            port=30306,
            db=os.environ.get('MYSQL_DATABASE'),
        )
    # NATS_URI = 'nats://localhost:4222'
    NATS_URI = 'nats://demo.nats.io:4222'
