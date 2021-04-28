import datetime
from exceptions import PaymentRequired
from flask import request
from flask.globals import current_app
from models import RoleEnum
from models import Capsule
from models import WebApp, webapp_schema
from models import Option
from models import Runtime, RuntimeTypeEnum
from app import db, nats
from utils import getWebappsVolumeUsage, oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
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


# /POST /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user, webapp_data=None):
    capsule = _get_capsule(capsule_id, user)

    if len(capsule.fqdns) == 0:
        raise Conflict(description="A webapp need at least one FQDN.")

    webapp = capsule.webapp

    # Only one webapp per capsule
    if webapp is not None:
        raise Conflict(description="This capsule already has a webapp.")

    # Datas could come from PUT
    if webapp is None:
        webapp_data = request.get_json()
    data = webapp_schema.load(webapp_data)

    runtime_id = data["runtime_id"]
    try:
        runtime = Runtime.query.get(runtime_id)
    except StatementError:
        raise BadRequest(description=f"'{runtime_id}' is not a valid id.")

    if runtime is None:
        raise BadRequest(description=f"The runtime_id '{runtime_id}' "
                         "does not exist.")

    if runtime.runtime_type is not RuntimeTypeEnum.webapp:
        raise BadRequest(description=f"The runtime_id '{runtime.id}' "
                         "has not type 'webapp'.")

    newArgs = dict()

    if "opts" in data:
        opts = Option.create(data["opts"], runtime_id, user.role)
        data.pop("opts")
        newArgs["opts"] = opts

    if "volume_size" not in data:
        data['volume_size'] = current_app.config['VOLUMES_DEFAULT_SIZE']
    else:
        if (user.role is RoleEnum.user) and (not user.parts_manager):
            raise Forbidden(description='You cannot set webapp volume size.')

    remaining_size = getWebappsVolumeUsage()
    target_size = data['volume_size'] + remaining_size
    if target_size > current_app.config['VOLUMES_GLOBAL_SIZE']:
        msg = 'Please set a lower volume size for this webapp or prepare '\
              'some Bitcoins... :-)'
        raise PaymentRequired(description=msg)

    webapp = WebApp(**data, **newArgs)
    capsule.webapp = webapp

    db.session.add(webapp)
    db.session.commit()

    result = WebApp.query.get(capsule.webapp_id)

    now = datetime.datetime.now()
    if now > (capsule.no_update + datetime.timedelta(hours=24)):
        nats.publish_webapp_present(capsule)

    # Api response
    result_json = webapp_schema.dump(result)

    return result_json, 201, {
        'Location': f'{request.base_url}/{capsule.id}/webapp',
    }


# /GET /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, user):
    capsule = _get_capsule(capsule_id, user)

    if capsule.webapp_id is None:
        raise NotFound

    result = WebApp.query.get(capsule.webapp_id)
    result_json = webapp_schema.dump(result)

    return result_json, 200, {
        'Location': f'{request.base_url}/{capsule.id}/webapp',
    }


# /PUT /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def put(capsule_id, user):
    capsule = _get_capsule(capsule_id, user)
    webapp = capsule.webapp
    webapp_data = request.get_json()

    # PUT become POST if there is no webapp
    if webapp is None:
        return post(capsule_id=capsule_id, webapp_data=webapp_data)

    data = webapp_schema.load(webapp_data)

    webapp.env = None
    if "env" in webapp_data:
        webapp.env = webapp_data["env"]

    # Ensure new runtime_id has same familly
    new_runtime_id = str(data["runtime_id"])
    try:
        new_runtime = Runtime.query.get(new_runtime_id)
    except StatementError:
        raise BadRequest(description=f"'{new_runtime_id}' is not a valid id.")
    if new_runtime is None:
        raise BadRequest(description=f"The runtime_id '{new_runtime_id}' "
                         "does not exist.")
    new_fam = str(new_runtime.fam)
    old_fam = str(webapp.runtime.fam)
    if new_fam != old_fam:
        raise BadRequest(f"Changing runtime familly from '{old_fam}' "
                         f"to '{new_fam}' is not possible")
    webapp.runtime_id = data["runtime_id"]

    webapp.opts = []
    if "opts" in data:
        opts = Option.create(data["opts"], data["runtime_id"], user.role)
        webapp.opts = opts

    if "volume_size" in data:
        if (user.role is RoleEnum.user) and (not user.parts_manager):
            raise Forbidden(description='You cannot set webapp volume size.')

        remaining_size = getWebappsVolumeUsage(str(webapp.id))
        target_size = data['volume_size'] + remaining_size
        if target_size > current_app.config['VOLUMES_GLOBAL_SIZE']:
            msg = 'Please set a lower volume size for this webapp or prepare '\
                'some Bitcoins... :-)'
            raise PaymentRequired(description=msg)
        webapp.volume_size = data['volume_size']

    capsule.webapp = webapp
    db.session.commit()

    now = datetime.datetime.now()
    if now > (capsule.no_update + datetime.timedelta(hours=24)):
        nats.publish_webapp_present(capsule)

    return get(capsule_id)


# /DELETE /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, user):
    capsule = _get_capsule(capsule_id, user)

    webapp = capsule.webapp

    if webapp is None:
        raise NotFound(description="This capsule does not have webapp.")

    webapp_id = str(webapp.id)

    db.session.delete(webapp)
    db.session.commit()

    now = datetime.datetime.now()
    if now > (capsule.no_update + datetime.timedelta(hours=24)):
        nats.publish_webapp_absent(webapp_id)

    return None, 204
