import pytest
import webtest
# from unittest.mock import MagicMock, patch
from app import create_app
from app import db as _db
from config import YamlConfig
from tests.foodata import DBFooData
import random
import os


@pytest.fixture(scope='function')
def app():
    yamlconfig = YamlConfig('./config-test-nats.yml')
    rand = random.randint(1, 999999)
    yamlconfig.SQLALCHEMY_DATABASE_URI = yamlconfig.SQLALCHEMY_DATABASE_URI\
        .replace(".db", f"-{rand}.db")
    # with patch("app.create_nats_listener", return_value=MagicMock()):
    connex_app = create_app(yamlconfig)
    return connex_app.app


@pytest.fixture(scope='function')
def testapp(app):
    return webtest.TestApp(app)


@pytest.fixture(scope='function', autouse=True)
def db(app):
    with app.app_context():
        _db.create_all()

        dbfoodata = DBFooData(_db)
        yield dbfoodata

        _db.session.close()
        _db.drop_all()
        db_uri = app.config["SQLALCHEMY_DATABASE_URI"]
        os.remove(db_uri.replace('sqlite:///', ''))
