from flask.globals import current_app
from models import RoleEnum
from utils import oidc_require_role


# GET /cluster
@oidc_require_role(min_role=RoleEnum.user)
def get():
    return current_app.config['ACME_DOMAINS']
