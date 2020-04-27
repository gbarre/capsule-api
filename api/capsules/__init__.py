from flask import request
from models import User, Capsule, capsule_schema, capsules_schema
from app import db, oidc
from werkzeug.exceptions import NotFound, BadRequest
from sqlalchemy import inspect
from utils import check_owners_on_keycloak
from exceptions import KeycloakUserNotFound

# GET /capsules
@oidc.accept_token(require_token=True)
def search(offset, limit, filters):
    # TODO: test filters with relationships
    try:
        results = Capsule.query.filter_by(**filters).limit(limit).offset(offset).all()
    except:
        raise BadRequest

    if not results:
        raise NotFound(description="No capsules have been found.")

    return capsules_schema.dump(results).data


# POST /capsules
@oidc.accept_token(require_token=True)
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
            data['owners'][i] = User(name=owner, role='user')
        else:
            data['owners'][i] = user
    
    capsule = Capsule(**data)
    db.session.add(capsule)
    db.session.commit()

    result = Capsule.query.get(capsule.id)
    return capsule_schema.dump(result).data, 201


# GET /capsules/{cID}
# TODO: Adapt the spec exception schema
@oidc.accept_token(require_token=True)
def get(capsule_id):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    return capsule_schema.dump(capsule).data


# @oidc.accept_token(require_token=True)
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


@oidc.accept_token(require_token=True)
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