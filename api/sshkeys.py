from models import RoleEnum, SSHKey
from app import db, oidc
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden


# /GET /sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit):
    # TODO: test filters with relationships
    # TODO: check role : user see his keys, admin/superadmin see all
    try:
        results = SSHKey.query.limit(limit).offset(offset).all()
    except:
        raise BadRequest

    if not results:
        raise NotFound(description="No sshkeys have been found.")

    res = []
    for result in results:
        res.append(result.public_key)

    return res


# /POST /sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def post():
    pass

# /DELETE /sshkeys/{skId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(sshkey_id):
    pass
