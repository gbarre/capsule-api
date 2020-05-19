from flask import request
from models import RoleEnum
from models import SSHKey, User
from models import Capsule, capsule_schema, capsules_schema
from app import db, oidc
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy import inspect
from utils import check_owners_on_keycloak, oidc_require_role, REGEX_CAPSULE_NAME
from exceptions import KeycloakUserNotFound


# GET /capsules
@oidc.accept_token(require_token=True, render_errors=False)
def search(offset, limit, filters):
    # TODO: test filters with relationships
    # TODO: check role : user see his capsules, admin/superadmin see all
    try:
        results = Capsule.query.filter_by(**filters).limit(limit).offset(offset).all()
    except:
        raise BadRequest

    if not results:
        raise NotFound(description="No capsules have been found.")

    return capsules_schema.dump(results).data


# POST /capsules
#@oidc.accept_token(require_token=True, render_errors=False)
@oidc_require_role(min_role=RoleEnum.admin)
def post():
    capsule_data = request.get_json()
    data = capsule_schema.load(capsule_data).data

    try:  # Check if owners exist on Keycloak
        check_owners_on_keycloak(data['owners'])
    except KeycloakUserNotFound as e:
        raise BadRequest(description=f'{e.missing_username} is an invalid user.')

    # Get existent users, create the others
    for i, owner in enumerate(data['owners']):
        user = User.query.filter_by(name=owner).one_or_none()
        if user is None:  # User does not exist in DB
            data['owners'][i] = User(name=owner, role=RoleEnum.user)
        else:
            data['owners'][i] = user

    # Get existent ssh keys, create the others
    if 'authorized_keys' in data:
        for i, public_key in enumerate(data['authorized_keys']):
            sshkey = SSHKey.query.filter_by(public_key=public_key).one_or_none()
            if sshkey is None:
                data['authorized_keys'][i] = SSHKey(public_key=public_key)
            else:
                data['authorized_keys'][i] = sshkey

    capsule_name = data['name']

    if not REGEX_CAPSULE_NAME.match(capsule_name):
        raise BadRequest(description=f'The capsule name "{capsule_name}" contains illegal charaters.')

    caps = Capsule.query.filter_by(name=capsule_name).limit(1).one_or_none()
    if caps is not None:
        raise BadRequest(description=f'{capsule_name} already exists.')

    capsule = Capsule(**data)
    db.session.add(capsule)
    db.session.commit()

    result = Capsule.query.get(capsule.id)
    return capsule_schema.dump(result).data, 201, {
        'Location': f'{request.base_url}/{capsule.id}',
    }


# GET /capsules/{cID}
# TODO: Adapt the spec exception schema
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, user_infos):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    owners = capsule_schema.dump(capsule).data['owners']
    (user_role, user_name) = user_infos
    if (user_role is RoleEnum.user) and (user_name not in owners):
        raise Forbidden

    return capsule_schema.dump(capsule).data


# @oidc.accept_token(require_token=True, render_errors=False)
# def put(capsule_id, capsule):
#     capsule_data = request.get_json()
#     data = capsule_schema.load(capsule_data).data

#     try:
#         capsule = Capsule.query.get(capsule_id)
#     except:
#         raise BadRequest
#     if capsule is None:
#         raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

#     capsule.update(**data)
#     for owner in capsule.owners:
#         # Check keycloak user and force the associated role
#         #
#         # if inspect(owner).transient:  # if owner does not yet exist in database
#         #   try:
#         #       owner.role = check_owner_nsuniqueid_on_keycloak(owner.id)
#         #   except:
#         #     raise BadRequest
#         if inspect(owner).transient:  # TODO: à remplacer ^
#             owner.role = 'user'

#     db.session.add(capsule)
#     db.session.commit()

#     result = Capsule.query.get(capsule.id)
#     return capsule_schema.dump(result).data


@oidc_require_role(min_role=RoleEnum.superadmin)
def delete(capsule_id):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    db.session.delete(capsule)
    db.session.commit()
    return None, 204