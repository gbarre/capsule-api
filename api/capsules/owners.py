from flask import request
from models import RoleEnum
from models import Capsule, User, user_schema, capsule_output_schema
from app import db, nats
from utils import oidc_require_role, check_owners_on_keycloak
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
from exceptions import KeycloakUserNotFound
from sqlalchemy.exc import StatementError


def _get_capsule(capsule_id, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    return capsule


# /GET /capsules/{cId}/owners
@oidc_require_role(min_role=RoleEnum.user)
def search(capsule_id, offset, limit, filters, user):
    capsule = _get_capsule(capsule_id, user)

    owners = []
    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True
        user_json = user_schema.dump(owner).data
        owners.append(user_json)

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden

    return owners


# /PATCH /capsules/{cId}/owners
@oidc_require_role(min_role=RoleEnum.user)
def patch(capsule_id, user):
    capsule = _get_capsule(capsule_id, user)
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
        raise Forbidden

    try:  # Check if owners exist on Keycloak
        check_owners_on_keycloak([new_owner])
    except KeycloakUserNotFound as e:
        raise NotFound(description=f'{e.missing_username} was not '
                                   'found in Keycloak.')

    # Get existent users, create the others
    user = User.query.filter_by(name=new_owner).one_or_none()
    if user is None:  # User does not exist in DB
        new_user = User(name=new_owner, role=RoleEnum.user)
    else:
        new_user = user

    capsule.owners.append(new_user)
    db.session.commit()

    nats.publish_webapp_present(capsule)

    result = Capsule.query.filter_by(id=capsule_id).first()
    return capsule_output_schema.dump(result).data, 200, {
        'Location': f'{request.base_url}/{capsule.id}',
    }


# /DELETE /capsules/{cId}/owners/{uId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, user_id, user):
    if user_id == user.name:
        raise Conflict

    capsule = _get_capsule(capsule_id, user)
    user_is_owner = False
    user_id_in_owners = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True
        if user_id == owner.name:
            user_id_in_owners = True

    if not user_id_in_owners:
        raise NotFound(description=f'{user_id} is not in owners.')

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden()

    user = User.query.filter_by(name=user_id).one_or_none()
    if user is None:  # pragma: no cover
        raise NotFound(description=f'{user} is an invalid user.')

    capsule.owners.remove(user)
    db.session.commit()

    nats.publish_webapp_present(capsule)

    return None, 204
