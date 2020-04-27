from flask import request
from models import Capsule, capsule_schema, capsules_schema
from app import db
from werkzeug.exceptions import NotFound, BadRequest
from sqlalchemy import inspect

# GET /capsules
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
def post():
    capsule_data = request.get_json()
    data = capsule_schema.load(capsule_data).data

    capsule = Capsule(**data)
    for owner in capsule.owners:
        # Check keycloak user and force the associated role
        #
        # if inspect(owner).transient:  # if owner does not yet exist in database 
        #   try:
        #       owner.role = check_owner_nsuniqueid_on_keycloak(owner.id)
        #   except:
        #     raise BadRequest
        if inspect(owner).transient:  # TODO: à remplacer ^ 
            owner.role = 'user'

    db.session.add(capsule)
    db.session.commit()

    result = Capsule.query.get(capsule.id)
    return capsule_schema.dump(result).data, 201


# GET /capsules/{cID}
# TODO: Adapt the spec exception schema
def get(capsule_id):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.") 

    return capsule_schema.dump(capsule).data


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