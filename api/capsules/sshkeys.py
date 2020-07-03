from flask import request
from models import RoleEnum, Capsule, SSHKey, capsule_output_schema
from app import db, nats
from utils import oidc_require_role, valid_sshkey
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
from sqlalchemy.exc import StatementError


def _get_capsule(capsule_id, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

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
        if not valid_sshkey(public_key):
            raise BadRequest(description=f"'{public_key}' is not "
                             "a valid ssh public key")

        for key in capsule.authorized_keys:
            if public_key == key.public_key:
                raise Conflict(description="'public_key' already exist "
                               "for this capsule")

        sshkey = SSHKey(public_key=public_key)
        capsule.authorized_keys.append(sshkey)

    db.session.commit()

    nats.publish_webapp_present(capsule)

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
    except StatementError:
        raise BadRequest(description=f"'{sshkey_id}' is not a valid id.")

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

    nats.publish_webapp_present(capsule)

    return None, 204
