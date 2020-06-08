from flask import request
from models import RoleEnum, Capsule, SSHKey, sshkey_schema, sshkeys_schema, capsule_output_schema
from app import db, oidc
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict


def _get_capsule(capsule_id, user):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden("You don't have the permission to access the requested resource.")

    return capsule

# /POST /capsules/{cId}/sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user):
    sshkey_data = request.get_json()
    capsule = _get_capsule(capsule_id, user)

    for public_key in sshkey_data:
        for key in capsule.authorized_keys:
            if public_key == key.public_key:
                raise Conflict(description="'public_key' already exist for this capsule")

        sshkey = SSHKey(public_key=public_key, user_id=user.id)
        capsule.authorized_keys.append(sshkey)

    db.session.commit()

    result = capsule.query.get(capsule.id)
    return capsule_output_schema.dump(result).data, 201, {
        'Location': f'{request.base_url}/capsules/{capsule.id}',
    }

# /DELETE /capsules/{cId}/sshkeys/{skId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, sshkey_id, user):
    capsule = _get_capsule(capsule_id, user)
    try:
        sshkey = SSHKey.query.get(sshkey_id)
    except:
        raise BadRequest

    if sshkey is None:
        raise NotFound(description=f"The requested sshkey '{sshkey_id}' has not been found.")

    if sshkey not in capsule.authorized_keys:
        raise BadRequest

    db.session.delete(sshkey)
    db.session.commit()
    return None, 204
