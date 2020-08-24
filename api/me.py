from models import RoleEnum
from models import user_schema
from utils import oidc_require_role


# GET /me
@oidc_require_role(min_role=RoleEnum.user)
def search(user):
    return user_schema.dump(user).data
