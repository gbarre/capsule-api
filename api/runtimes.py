from flask import request
from app import db, oidc
from werkzeug.exceptions import NotFound, BadRequest
from models import Runtime, runtime_schema, runtimes_schema
import json
# from enum import Enum
from models import RoleEnum
from utils import oidc_require_role

# class SerializeEnum(json.JSONEncoder):
#     def default(self, obj):
#         if isinstance(obj, Enum):
#             return obj.name
#         return json.JSONEncoder.default(self, obj)


# GET /runtimes
@oidc.accept_token(require_token=True, render_errors=False)
def search(offset, limit, filters):
    # TODO: test filters with relationships
    #try:
    results = Runtime.query.filter_by(**filters).limit(limit).offset(offset).all()
    #except:
    #    raise BadRequest

    if not results:
        raise NotFound(description="No runtimes have been found.")

    return runtimes_schema.dump(results).data


# POST /runtimes
@oidc_require_role(min_role=RoleEnum.superadmin)
def post():
    runtime_data = request.get_json()
    data = runtime_schema.load(runtime_data).data

    runtime = Runtime(**data)
    db.session.add(runtime)
    db.session.commit()

    result = runtime.query.get(runtime.id)
    return runtime_schema.dump(result).data, 201, {
        'Location': f'{request.base_url}/{runtime.id}',
    }


# GET /runtimes/{rID}
@oidc.accept_token(require_token=True, render_errors=False)
def get(runtime_id):
    pass


# PUT /runtimes/{rId}
@oidc_require_role(min_role=RoleEnum.superadmin)
def put(runtime_id, runtime):
    pass


# DELETE /runtimes/{rId}
@oidc_require_role(min_role=RoleEnum.superadmin)
def delete(runtime_id):
    pass
