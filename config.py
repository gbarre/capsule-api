import os
from dotenv import load_dotenv

load_dotenv()

# TODO: Decide the way that we want to configure the application (INI, ENV, YAML, etc.)

class Config(object):
    """Global cofnguration object."""
    DEBUG = False
    SQLALCHEMY_ECHO = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProdConfig(Config):
    ENV = 'production'

class TestConfig(Config):
    ENV = 'test'

class LocalConfig(Config):
    ENV = 'development'
    DEBUG = True
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{user}:{passw}@{host}:{port}/{db}'.format(
        user='root',
        passw=os.environ.get('MYSQL_ROOT_PASSWORD'),
        host='localhost',
        port=30306,
        db=os.environ.get('MYSQL_DATABASE'),
    )