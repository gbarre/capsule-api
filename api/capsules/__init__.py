from flask import request
from models import Capsule, capsule_schema, capsules_schema
from config import db
from werkzeug.exceptions import NotFound, BadRequest

def search(offset, limit, filters):
    pass

# POST /capsules
def post():
    capsule_data = request.get_json()
    data = capsule_schema.load(capsule_data).data

    print(data)
    # FIXME: owners?
    capsule = Capsule(**data)
    db.session.add(capsule)
    db.session.commit()

    print(capsule)
    result = Capsule.query.get(capsule.id)
    return capsule_schema.dump(result).data

# GET /capsules/{cID}
# TODO: Adapt the spec exception schema
def get(capsule_id):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).one_or_none()
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.") 
    
    return capsule_schema.dump(capsule).data

def put(capsule_id, capsule):
    pass

def delete(capsule_id):
    pass