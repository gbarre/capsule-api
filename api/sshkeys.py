import datetime
from flask import request
from models import Capsule, User
from models import RoleEnum, SSHKey, sshkey_schema, sshkeys_schema
from app import db, nats
from utils import oidc_require_role, valid_sshkey
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy.exc import StatementError


def nats_publish_webapp_present(user):
    query = []
    query.append(Capsule.owners.any(User.name == user.name))
    capsules = Capsule.query.filter(*query).all()
    now = datetime.datetime.now()
    for capsule in capsules:
        if now > (capsule.no_update + datetime.timedelta(hours=24)):
            nats.publish_webapp_present(capsule)


# /GET /sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, user):
    query = []
    if user.role < RoleEnum.admin:
        query.append(SSHKey.owner == user)
    results = SSHKey.query.filter(*query).limit(limit).offset(offset).all()

    if not results:
        raise NotFound(description="No sshkeys have been found.")

    return sshkeys_schema.dump(results)


# /POST /sshkeys
@oidc_require_role(min_role=RoleEnum.user)
def post(user):
    sshkey_data = request.get_json()
    # data = sshkey_schema.load(sshkey_data)

    if 'public_key' not in sshkey_data:
        raise BadRequest("The key 'public_key' is required.")

    public_key = sshkey_data["public_key"]

    if not valid_sshkey(public_key):
        raise BadRequest(description=f"'{public_key}' is not "
                         "a valid ssh public key")

    sshkey = SSHKey(public_key=public_key, user_id=user.id)
    db.session.add(sshkey)
    db.session.commit()

    nats_publish_webapp_present(user)

    result = SSHKey.query.get(sshkey.id)
    return sshkey_schema.dump(result), 201, {
        'Location': f'{request.base_url}/sshkeys/{sshkey.id}',
    }


# /DELETE /sshkeys/{skId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(sshkey_id, user):
    try:
        sshkey = SSHKey.query.get(sshkey_id)
    except StatementError:
        raise BadRequest(description=f"'{sshkey_id}' is not a valid id.")

    if sshkey is None:
        raise NotFound(description=f"The requested sshkey '{sshkey_id}' "
                       "has not been found.")

    if (user.id != sshkey.user_id) and (user.role < RoleEnum.admin):
        raise Forbidden

    db.session.delete(sshkey)
    db.session.commit()

    nats_publish_webapp_present(user)

    return None, 204
