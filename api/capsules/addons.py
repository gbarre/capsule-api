from flask import request
import ast
import json
from models import RoleEnum
from models import Capsule
from models import AddOn, addon_schema, addons_schema
from models import Option
from models import Runtime, RuntimeTypeEnum
from app import db, nats
from utils import oidc_require_role, build_query_filters
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy.exc import StatementError


def _get_capsule(capsule_id, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError as e:
        raise BadRequest(description=str(e))

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden

    return capsule


# POST /capsules/{cID}/addons
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user, addon_data=None):
    capsule = _get_capsule(capsule_id, user)

    if addon_data is None:
        addon_data = request.get_json()

    runtime_id = addon_data["runtime_id"]
    runtime = Runtime.query.get(runtime_id)

    if runtime is None:
        raise BadRequest(description=f"The runtime_id '{runtime_id}' "
                         "does not exist.")

    if runtime.runtime_type is not RuntimeTypeEnum.addon:
        raise BadRequest(description=f"The runtime_id '{runtime.id}' "
                         "has not type 'addon'.")

    if "env" in addon_data:
        addon_data["env"] = json.dumps(addon_data["env"])

    if "opts" in addon_data:
        opts = Option.create(addon_data["opts"], runtime_id)
        addon_data.pop("opts")

        addon = AddOn(**addon_data, opts=opts)
    else:
        addon = AddOn(**addon_data)

    # TODO: ensure name is "human readable"
    # TODO: build uri

    capsule.addons.append(addon)

    db.session.add(addon)
    db.session.commit()

    nats.publish_addon_present(addon, capsule.name)

    result_json = addon_schema.dump(addon).data
    result_json["env"] = json.loads(result_json["env"])
    return result_json, 201, {
        'Location':
            f'{request.base_url}/capsules/{capsule_id}/addons/{addon.id}',
    }


# GET /capsules/{cID}/addons
@oidc_require_role(min_role=RoleEnum.user)
def search(capsule_id, user, offset, limit, filters):
    _get_capsule(capsule_id, user)

    try:
        query = build_query_filters(AddOn, filters)
        query.append(AddOn.capsule_id == capsule_id)
        results = AddOn.query.filter(*query).limit(limit).offset(offset).all()
    except AttributeError as e:
        raise BadRequest(description=str(e))

    if not results:
        raise NotFound(description="No addons have been found.")

    results = addons_schema.dump(results).data
    for result in results:
        if result['env'] is not None:
            result["env"] = ast.literal_eval(result["env"])
        else:
            result['env'] = dict()

    return results


# GET /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)

    try:
        result = AddOn.query.get(addon_id)
    except StatementError as e:
        raise BadRequest(description=str(e))

    if not result:
        raise NotFound(description=f"The requested addon '{addon_id}' "
                       "has not been found.")

    if str(result.capsule.id) != capsule_id:
        raise Forbidden

    result = addon_schema.dump(result).data
    if result['env'] is not None:
        result["env"] = ast.literal_eval(result["env"])
    else:
        result['env'] = dict()

    return result, 200, {
        'Location':
        f'{request.base_url}/capsules/{capsule.id}/addons/{addon_id}',
    }


# PUT /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def put(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)
    addon_data = request.get_json()

    try:
        addon = AddOn.query.get(addon_id)
    except StatementError as e:
        raise BadRequest(description=str(e))

    if not addon:
        raise NotFound(description=f"The requested addon '{addon_id}' "
                       "has not been found.")

    if str(addon.capsule.id) != capsule_id:
        raise Forbidden

    addon.description = addon_data["description"]
    addon.name = addon_data["name"]
    addon.runtime_id = addon_data["runtime_id"]

    if "env" in addon_data:
        addon.env = str(addon_data["env"])

    if "opts" in addon_data:
        opts = Option.create(addon_data["opts"])
        addon.opts = opts

    db.session.commit()

    nats.publish_addon_present(addon, capsule.name)

    return get(capsule_id, addon_id)


# DELETE /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)

    addon = AddOn.query.get(addon_id)
    if not addon:
        raise NotFound(description="This addon is not present in this capsule")

    if str(addon.capsule.id) != capsule_id:
        raise Forbidden

    runtime_id = addon.runtime_id

    db.session.delete(addon)
    db.session.commit()

    nats.publish_addon_absent(addon_id, runtime_id)

    return None, 204
