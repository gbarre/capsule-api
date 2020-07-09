from flask import request
from models import RoleEnum
from models import Capsule
from models import AddOn, addon_schema, addons_schema
from models import Option
from models import Runtime, RuntimeTypeEnum
from app import db, nats
from utils import build_query_filters, is_valid_name, oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy.exc import StatementError


def _get_capsule(capsule_id, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

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

    data = addon_schema.load(addon_data).data

    addon_name = data['name']
    if not is_valid_name(addon_name):
        msg = f'The addon name "{addon_name}" is invalid: only lowercase '\
            'alphanumeric characters or "-" are allowed, the first and the '\
            'last characters must be alphanumeric, the name must have at '\
            'least 2 characters and less than 64 characters.'
        raise BadRequest(description=msg)

    # Ensure the addon name is unique for this capsule
    capsule_addons = AddOn.query.filter_by(capsule_id=capsule.id).all()
    for addon in capsule_addons:
        if addon.name == addon_name:
            raise BadRequest(description="This capsule already have an "
                             f"addon named '{addon_name}'.")

    runtime_id = data["runtime_id"]
    runtime = Runtime.query.get(runtime_id)

    if runtime is None:
        raise BadRequest(description=f"The runtime_id '{runtime_id}' "
                         "does not exist.")

    if runtime.runtime_type is not RuntimeTypeEnum.addon:
        raise BadRequest(description=f"The runtime_id '{runtime.id}' "
                         "has not type 'addon'.")

    if "opts" in data:
        opts = Option.create(data["opts"], runtime_id, user.role)
        data.pop("opts")

        addon = AddOn(**data, opts=opts)
    else:
        addon = AddOn(**data)

    addon.uri = runtime.generate_uri(capsule)

    capsule.addons.append(addon)

    db.session.add(addon)
    db.session.commit()

    nats.publish_addon_present(addon, capsule.name)

    result_json = addon_schema.dump(addon).data
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
    except AttributeError:
        raise BadRequest

    if not results:
        raise NotFound(description="No addons have been found.")

    results = addons_schema.dump(results).data

    return results


# GET /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)

    try:
        result = AddOn.query.get(addon_id)
    except StatementError:
        raise BadRequest(description=f"'{addon_id}' is not a valid id.")

    if not result:
        raise NotFound(description=f"The requested addon '{addon_id}' "
                       "has not been found.")

    if str(result.capsule.id) != capsule_id:
        raise Forbidden

    result = addon_schema.dump(result).data

    return result, 200, {
        'Location':
        f'{request.base_url}/capsules/{capsule.id}/addons/{addon_id}',
    }


# PUT /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def put(capsule_id, addon_id, user):
    capsule = _get_capsule(capsule_id, user)
    addon_data = request.get_json()
    data = addon_schema.load(addon_data).data

    try:
        addon = AddOn.query.get(addon_id)
    except StatementError:
        raise BadRequest(description=f"'{addon_id}' is not a valid id.")

    if not addon:
        raise NotFound(description=f"The requested addon '{addon_id}' "
                       "has not been found.")

    if str(addon.capsule.id) != capsule_id:
        raise Forbidden(description="bad capsule id")

    addon.description = data["description"]

    addon_name = data['name']
    if not is_valid_name(addon_name):
        msg = f'The addon name "{addon_name}" is invalid: only lowercase '\
            'alphanumeric characters or "-" are allowed, the first and the '\
            'last characters must be alphanumeric, the name must have at '\
            'least 2 characters and less than 64 characters.'
        raise BadRequest(description=msg)
    addon.name = data["name"]

    if data["runtime_id"] != str(addon.runtime_id):
        raise BadRequest(description="The runtime_id cannot be changed.")
    addon.runtime_id = data["runtime_id"]

    addon.env = data["env"]

    if "opts" in data:
        opts = Option.create(data["opts"], data['runtime_id'], user.role)
        addon.opts = opts
    else:
        addon.opts = []

    db.session.commit()

    nats.publish_addon_present(addon, capsule.name)

    return get(capsule_id, addon_id)


# DELETE /capsules/{cID}/addons/{aID}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, addon_id, user):
    _get_capsule(capsule_id, user)

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
