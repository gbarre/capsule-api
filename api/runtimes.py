from flask import request
from app import db
from werkzeug.exceptions import NotFound, BadRequest
from models import Runtime, runtime_schema, runtimes_schema
from models import RoleEnum
from models import AvailableOption
from utils import oidc_require_role, build_query_filters
from sqlalchemy.exc import StatementError


# GET /runtimes
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, filters):
    try:
        query = build_query_filters(Runtime, filters)
        results = Runtime.query.filter(*query)\
            .limit(limit).offset(offset).all()
    except AttributeError:
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

        if "available_opts" in data and len(data['available_opts']) > 0:
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
    except StatementError:
        raise BadRequest(description=f"'{runtime_id}' is not a valid id.")

    if runtime is None:
        raise NotFound(description=f"The requested runtime '{runtime_id}' "
                       "has not been found.")

    result_json = runtime_schema.dump(runtime).data
    return result_json, 200, {
        'Location': f'{request.base_url}/runtimes/{runtime.id}'
    }


# PUT /runtimes/{rId}
@oidc_require_role(min_role=RoleEnum.superadmin)
def put(runtime_id):
    runtime_data = request.get_json()
    try:
        runtime = Runtime.query.get(runtime_id)
    except StatementError:
        raise BadRequest(description=f"'{runtime_id}' is not a valid id.")

    if runtime is None:
        return post(runtime=runtime)

    data = runtime_schema.load(runtime_data).data

    runtime.description = data["description"]
    runtime.fam = data["fam"]
    runtime.name = data["name"]
    runtime.runtime_type = data["runtime_type"]

    runtime.uri_template = None
    if 'uri_template' in data:
        runtime.uri_template = data['uri_template']

    runtime.available_opts = []
    if "available_opts" in data and len(data['available_opts']) > 0:
        available_opts = AvailableOption.create(data["available_opts"])
        runtime.available_opts = available_opts

    db.session.commit()
    return get(str(runtime.id))


# DELETE /runtimes/{rId}
@oidc_require_role(min_role=RoleEnum.superadmin)
def delete(runtime_id):
    try:
        runtime = Runtime.query.get(runtime_id)
    except StatementError:
        raise BadRequest(description=f"'{runtime_id}' is not a valid id.")

    if runtime is None:
        raise NotFound(description=f"The requested runtime '{runtime_id}' "
                       "has not been found.")

    db.session.delete(runtime)
    db.session.commit()
    return None, 204
