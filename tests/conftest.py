import pytest
import webtest
from app import create_app
from app import db as _db
from config import TestConfig
from models import WebApp
from models import AddOn
from models import Runtime
from models import AvailableOption
from models import RoleEnum
from models import OptionValueTypeEnum
from models import AvailableOptionValidationRule
from models import ValidationRuleEnum
from models import RuntimeTypeEnum
from models import FQDN
from models import Option


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
    
        setup_initial_data(_db)
        yield _db

        _db.session.close()
        _db.drop_all()


def setup_initial_data(db):
    available_opt = AvailableOption(
        access_level=RoleEnum.user,
        tag='Apache',
        name='vhost.conf',
        value_type=OptionValueTypeEnum.file,
        description='Apache2 vhost configuration file.',
    )

    validation_rule = AvailableOptionValidationRule(
        type=ValidationRuleEnum.gte,
        arg='1',
    )
    validation_rule2 = AvailableOptionValidationRule(
        type=ValidationRuleEnum.lte,
        arg='42',
    )
    available_opt2 = AvailableOption(
        access_level=RoleEnum.user,
        tag='PHP',
        name='worker',
        value_type=OptionValueTypeEnum.integer,
        description='PHP worker count.',
        default_value='6',
        validation_rules = [
            validation_rule,
            validation_rule2,
        ]
    )

    runtime = Runtime(
        description='Stack web classique Apache 2.4 + PHP 7.2.x',
        family='Apache PHP',
        name='apache-2.4 php-7.2.x',
        type=RuntimeTypeEnum.webapp,
        available_opts=[
            available_opt,
            available_opt2,
        ]
    )

    fqdn = FQDN(name="main.fqdn.ac-versailles.fr", alias=False)
    fqdn2 = FQDN(name="secondary.fqdn.ac-versailles.fr", alias=True)

    option = Option(field_name='worker', tag='PHP', value='42')
    webapp = WebApp(
        env="""
        HTTPS_PROXY=https://proxy:3128/
        HTTP_PROXY=http://proxy:3128/
        """,
        fqdns=[
            fqdn,
            fqdn2,
        ],
        opts=[
            option,
        ],
        quota_cpu_max='2.5',
        quota_memory_max='4',
        quota_volume_size='20',
        runtime=runtime,
        tls_redirect_https=True,
    )

    db.session.add_all([
        validation_rule,
        validation_rule2,
        available_opt,
        available_opt2,
        runtime,
        option,
        fqdn,
        fqdn2,
        webapp,
    ])
    db.session.commit()
