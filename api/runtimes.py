from flask import request
from app import db
from werkzeug.exceptions import NotFound, BadRequest
from models import Runtime, runtime_schema, runtimes_schema
from models import RoleEnum
from models import AvailableOption
from utils import oidc_require_role, build_query_filters


# GET /runtimes
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, filters):
    try:
        query = build_query_filters(Runtime, filters)
        results = Runtime.query.filter(*query)\
            .limit(limit).offset(offset).all()
    except:
        raise BadRequest

    if not results:
        raise NotFound(description="No runtimes have been found.")

    return runtimes_schema.dump(results).data


# POST /runtimes
@oidc_require_role(min_role=RoleEnum.superadmin)
def post(runtime=None):
    # runtime could come from PUT
    if runtime is None:
        runtime_data = request.get_json()
        data = runtime_schema.load(runtime_data).data

        if "available_opts" in data:
            available_opts = AvailableOption.create(data["available_opts"])
            data.pop("available_opts")
            runtime = Runtime(**data, available_opts=available_opts)
        else:
            runtime = Runtime(**data)

    db.session.add(runtime)
    db.session.commit()

    result = runtime.query.get(runtime.id)
    return runtime_schema.dump(result).data, 201, {
        'Location': f'{request.base_url}/{runtime.id}',
    }


# GET /runtimes/{rID}
@oidc_require_role(min_role=RoleEnum.user)
def get(runtime_id):
    try:
        runtime = Runtime.query.get(runtime_id)
    except:
        raise BadRequest

    if runtime is None:
        raise NotFound(description=f"The requested runtime '{runtime_id}' "
                       "has not been found.")

    return runtime_schema.dump(runtime).data


# PUT /runtimes/{rId}
@oidc_require_role(min_role=RoleEnum.superadmin)
def put(runtime_id):
    runtime_data = request.get_json()
    data = runtime_schema.load(runtime_data).data

    try:
        runtime = Runtime.query.get(runtime_id)
    except:
        raise BadRequest

    if runtime is None:
        return post(runtime=runtime)

    runtime.desc = data["desc"]
    runtime.fam = data["fam"]
    runtime.name = data["name"]
    runtime.runtime_type = data["runtime_type"]

    delattr(runtime, "available_opts")
    if "available_opts" in data:
        available_opts = AvailableOption.create(data["available_opts"])
        runtime.available_opts = available_opts

    db.session.commit()

    result = Runtime.query.get(runtime.id)
    return runtime_schema.dump(result).data


# DELETE /runtimes/{rId}
@oidc_require_role(min_role=RoleEnum.superadmin)
def delete(runtime_id):
    try:
        runtime = Runtime.query.get(runtime_id)
    except:
        raise BadRequest

    if runtime is None:
        raise NotFound(description=f"The requested runtime '{runtime_id}' "
                       "has not been found.")

    db.session.delete(runtime)
    db.session.commit()
    return None, 204
