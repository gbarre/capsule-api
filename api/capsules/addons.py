from flask import request
import ast
import json
from models import RoleEnum
from models import Capsule, User
from models import AddOn, addon_schema, addons_schema
from models import Option
from models import Runtime, RuntimeTypeEnum
from app import db
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict


def _get_capsule(capsule_id, user):
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

    return capsule


# POST /capsules/{cID}/addons
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user, addon_data=None):
    capsule = _get_capsule(capsule_id, user)

    if addon_data is None:
        addon_data = request.get_json()

    runtime = Runtime.query.get(addon_data["runtime_id"])
    if runtime.runtime_type is not RuntimeTypeEnum.addon:
        raise BadRequest(description=f"The runtime_id '{runtime.id}' has not type 'addon'.")

    if "env" in addon_data:
        addon_data["env"] = json.dumps(addon_data["env"])

    if "opts" in addon_data:
        opts = Option.create(addon_data["opts"])
        addon_data.pop("opts")

        addon = AddOn(**addon_data, opts=opts)
    else:
        addon = AddOn(**addon_data)

    capsule.addons.append(addon)

    db.session.add(addon)
    db.session.commit()

    result = AddOn.query.get(addon.id)
    result_json = addon_schema.dump(addon).data
    result_json["env"] = json.loads(result_json["env"])
    return result_json, 201, {
        'Location': f'{request.base_url}/capsules/{capsule_id}/addons/{addon.id}',
    }


# GET /capsules/{cID}/addons
@oidc_require_role(min_role=RoleEnum.user)
def search(capsule_id, user, offset, limit, filters):
    capsule = _get_capsule(capsule_id, user)


# GET /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)


# PUT /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def put(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)


# DELETE /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)

    try:
        addon = AddOn.query.get(addon_id)
    except:
        raise NotFound(description="This addon is not present in this capsule.")

    db.session.delete(addon)
    db.session.commit()
    return None, 204