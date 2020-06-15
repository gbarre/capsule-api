from flask import request
from models import RoleEnum, Capsule, SSHKey, capsule_output_schema
from app import db
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
from sqlalchemy.exc import StatementError


def _get_capsule(capsule_id, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError as e:
        raise BadRequest(description=str(e))

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden

    return capsule


# /POST /capsules/{cId}/sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user):
    sshkey_data = request.get_json()
    capsule = _get_capsule(capsule_id, user)

    for public_key in sshkey_data:
        for key in capsule.authorized_keys:
            if public_key == key.public_key:
                raise Conflict(description="'public_key' already exist "
                               "for this capsule")

        sshkey = SSHKey(public_key=public_key)
        capsule.authorized_keys.append(sshkey)

    db.session.commit()

    result = Capsule.query.filter_by(id=capsule_id).first()
    return capsule_output_schema.dump(result).data, 201, {
        'Location': f'{request.base_url}/capsules/{capsule.id}',
    }


# /DELETE /capsules/{cId}/sshkeys/{skId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, sshkey_id, user):
    capsule = _get_capsule(capsule_id, user)
    try:
        sshkey = SSHKey.query.get(sshkey_id)
    except StatementError as e:
        raise BadRequest(description=str(e))

    if sshkey is None:
        raise NotFound(description=f"The requested sshkey '{sshkey_id}' "
                       "has not been found.")

    if sshkey not in capsule.authorized_keys:
        raise BadRequest
    elif (sshkey.user_id is not None) or (len(sshkey.capsules) > 1):
        # sshkey is linked to a user or in other(s) capsule(s)
        capsule.authorized_keys.remove(sshkey)
    else:  # sshkey is juste present for this capsule
        db.session.delete(sshkey)

    db.session.commit()
    return None, 204
