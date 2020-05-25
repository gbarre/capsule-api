from flask import request
from models import RoleEnum, SSHKey, sshkey_schema, sshkeys_schema
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

    return sshkeys_schema.dump(results).data


# /POST /sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def post(user):
    sshkey_data = request.get_json()
    data = sshkey_schema.load(sshkey_data).data

    public_key = data["public_key"]

    sshkey = SSHKey(public_key=public_key, user_id=user.id)
    db.session.add(sshkey)
    db.session.commit()

    result = SSHKey.query.get(sshkey.id)
    return sshkey_schema.dump(result).data, 201, {
        'Location': f'{request.base_url}/{sshkey.id}',
    }

# /DELETE /sshkeys/{skId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(sshkey_id, user):
    # TODO: capsule owners should be able to delete sshkey
    try:
        sshkey = SSHKey.query.get(sshkey_id)
    except:
        raise BadRequest

    if sshkey is None:
        raise NotFound(description=f"The requested sshkey '{sshkey_id}' has not been found.")

    if (user.id is not sshkey.user_id) and (user.role < RoleEnum.admin):
        raise Forbidden

    db.session.delete(sshkey)
    db.session.commit()
    return None, 204
