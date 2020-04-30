import pytest
import webtest
from app import create_app
from app import db as _db
from config import TestConfig


@pytest.fixture(scope='function')
def app():
    connex_app = create_app(TestConfig)
    return connex_app.app


@pytest.fixture(scope='function')
def testapp(app):
    return webtest.TestApp(app)

@pytest.fixture(scope='function', autouse=True)
def db(app):
    # HACK: app parameter is here to trigger db object configuration
    with app.app_context():
        _db.create_all()
    
        yield _db

        _db.session.close()
        _db.drop_all()


@pytest.fixture(scope='function')
def setup_initial_data(app):
    # HACK: app parameter is here to trigger db object configuration
    pass