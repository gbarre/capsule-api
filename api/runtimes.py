from app import db, oidc
from werkzeug.exceptions import NotFound, BadRequest
from models import Runtime, runtime_schema, runtimes_schema
import json
from enum import Enum


class SerializeEnum(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.name
        return json.JSONEncoder.default(self, obj)


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

# GET /runtimes/{rID}
@oidc.accept_token(require_token=True, render_errors=False)
def get(runtime_id):
    pass

# POST /runtimes
@oidc.accept_token(require_token=True, render_errors=False)
def post(runtime):
    pass

# PUT /runtimes/{rId}
@oidc.accept_token(require_token=True, render_errors=False)
def put(runtime_id, runtime):
    pass

# DELETE /runtimes/{rId}
@oidc.accept_token(require_token=True, render_errors=False)
def delete(runtime_id):
    pass
