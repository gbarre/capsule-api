from flask import request
from models import RoleEnum
from models import Capsule, User, user_schema, capsule_output_schema
from app import db, oidc
from utils import oidc_require_role, check_owners_on_keycloak
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
from exceptions import KeycloakUserNotFound


# /GET /capsules/{cId}/owners
@oidc_require_role(min_role=RoleEnum.user)
def search(capsule_id, offset, limit, filters, user):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    owners = []
    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True
        user_json = user_schema.dump(owner).data
        owners.append(user_json)

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden("You don't have the permission to access the requested resource.")

    return owners


# /PATCH /capsules/{cId}/owners
@oidc_require_role(min_role=RoleEnum.user)
def patch(capsule_id, user):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    owner_data = request.get_json()

    if "newOwner" not in owner_data:
        raise BadRequest("The key newOwner is required.")
    new_owner = owner_data["newOwner"]

    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True
        if new_owner == owner.name:
            raise Conflict

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden("You don't have the permission to access the requested resource.")

    try:  # Check if owners exist on Keycloak
        check_owners_on_keycloak([new_owner])
    except KeycloakUserNotFound as e:
        raise NotFound(description=f'{e.missing_username} is an invalid user.')

    # Get existent users, create the others
    user = User.query.filter_by(name=new_owner).one_or_none()
    if user is None:  # User does not exist in DB
        new_user = User(name=new_owner, role=RoleEnum.user)
    else:
        new_user = user

    capsule.owners.append(new_user)
    db.session.commit()

    result = Capsule.query.get(capsule.id)
    return capsule_output_schema.dump(result).data, 200, {
        'Location': f'{request.base_url}/{capsule.id}',
    }


# /DELETE /capsules/{cId}/owners/{uId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, user_id, user):
    if user_id == user.name:
        raise Conflict

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

    try:  # Check if owners exist on Keycloak
        check_owners_on_keycloak([user_id])
    except KeycloakUserNotFound as e:
        raise NotFound(description=f'{e.missing_username} is an invalid user.')

    user = User.query.filter_by(name=user_id).one_or_none()
    if user is None:
        raise NotFound(description=f'{e.missing_username} is an invalid user.')

    capsule.owners.remove(user)
    db.session.commit()
    return None, 204