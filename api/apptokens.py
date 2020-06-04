from models import RoleEnum
from utils import oidc_require_role

# GET /apptokens
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, filters, user):
    pass


# POST /apptokens
@oidc_require_role(min_role=RoleEnum.user)
def post(user):
    pass


# DELETE /apptokens/{tId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(apptoken_id, user):
    pass
