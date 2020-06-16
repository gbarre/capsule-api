from flask import request
from models import RoleEnum, SSHKey, sshkey_schema, sshkeys_schema
from app import db
from utils import oidc_require_role, valid_sshkey
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy.exc import StatementError


# /GET /sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, user):
    query = []
    if user.role < RoleEnum.admin:
        query.append(SSHKey.owner == user)
    results = SSHKey.query.filter(*query).limit(limit).offset(offset).all()

    if not results:
        raise NotFound(description="No sshkeys have been found.")

    return sshkeys_schema.dump(results).data


# /POST /sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def post(user):
    sshkey_data = request.get_json()
    data = sshkey_schema.load(sshkey_data).data

    public_key = data["public_key"]

    if not valid_sshkey(public_key):
        raise BadRequest(description=f"'{public_key}' is not "
                         "a valid ssh public key")

    sshkey = SSHKey(public_key=public_key, user_id=user.id)
    db.session.add(sshkey)
    db.session.commit()

    result = SSHKey.query.get(sshkey.id)
    return sshkey_schema.dump(result).data, 201, {
        'Location': f'{request.base_url}/sshkeys/{sshkey.id}',
    }


# /DELETE /sshkeys/{skId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(sshkey_id, user):
    try:
        sshkey = SSHKey.query.get(sshkey_id)
    except StatementError as e:
        raise BadRequest(description=str(e))

    if sshkey is None:
        raise NotFound(description=f"The requested sshkey '{sshkey_id}' "
                       "has not been found.")

    if (user.id is not sshkey.user_id) and (user.role < RoleEnum.admin):
        raise Forbidden

    db.session.delete(sshkey)
    db.session.commit()
    return None, 204
