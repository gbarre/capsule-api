# TODO: check cron syntax for POST & PUT
from flask import request
from ast import literal_eval
from models import RoleEnum
from models import Capsule
from models import WebApp, webapp_schema
from models import FQDN, Option
from models import Runtime, RuntimeTypeEnum
from app import db
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
from sqlalchemy.exc import StatementError
import base64
import binascii


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


# /POST /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user, webapp_data=None):
    capsule = _get_capsule(capsule_id, user)
    webapp = capsule.webapp

    # Only one webapp per capsule
    if webapp is not None:
        raise Conflict(description="This capsule already has a webapp.")

    # Datas could come from PUT
    if webapp_data is None:
        webapp_data = request.get_json()

    runtime_id = webapp_data["runtime_id"]
    runtime = Runtime.query.get(runtime_id)

    if runtime is None:
        raise BadRequest(description=f"The runtime_id '{runtime_id}' "
                         "does not exist.")

    if runtime.runtime_type is not RuntimeTypeEnum.webapp:
        raise BadRequest(description=f"The runtime_id '{runtime.id}' "
                         "has not type 'webapp'.")

    if "env" in webapp_data:
        webapp_data["env"] = str(webapp_data["env"])

    newArgs = dict()
    if "fqdns" in webapp_data:
        fqdns = FQDN.create(webapp_data["fqdns"])
        webapp_data.pop("fqdns")
        newArgs["fqdns"] = fqdns

    if "opts" in webapp_data:
        opts = Option.create(webapp_data["opts"], runtime_id)
        webapp_data.pop("opts")
        newArgs["opts"] = opts

    if ("tls_key" in webapp_data and "tls_crt" not in webapp_data) or \
            ("tls_crt" in webapp_data and "tls_key" not in webapp_data):
        raise BadRequest(description="Both tls_crt and tls_key are "
                                     "required together")

    if "tls_crt" in webapp_data and "tls_key" in webapp_data:
        try:
            base64.b64decode(webapp_data['tls_crt'])
            base64.b64decode(webapp_data['tls_key'])
        except binascii.Error:
            webapp_data['tls_crt'] = base64.b64encode(webapp_data['tls_crt'])
            webapp_data['tls_key'] = base64.b64encode(webapp_data['tls_key'])
        # TODO: ensure crt & key are paired (via hte modulus).

    webapp = WebApp(**webapp_data, **newArgs)
    capsule.webapp = webapp

    db.session.add(webapp)
    db.session.commit()

    result = WebApp.query.get(capsule.webapp_id)
    result_json = webapp_schema.dump(result).data
    if result_json['env'] is not None:
        result_json["env"] = literal_eval(result_json["env"])
    else:
        result_json["env"] = {}

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
    result_json = webapp_schema.dump(result).data
    if result_json['env'] is not None:
        result_json["env"] = literal_eval(result_json["env"])
    else:
        result_json["env"] = {}

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

    if "env" in webapp_data:
        webapp.env = str(webapp_data["env"])

    if "fqdns" in webapp_data:
        fqdns = FQDN.create(webapp_data["fqdns"])
        webapp.fqdns = fqdns

    # TODO: ensure new runtime_id has same familly
    webapp.runtime_id = webapp_data["runtime_id"]

    if "opts" in webapp_data:
        opts = Option.create(webapp_data["opts"], webapp_data["runtime_id"])
        webapp.opts = opts

    if "tls_crt" in webapp_data and "tls_key" in webapp_data:
        try:
            base64.b64decode(webapp_data['tls_crt'])
            base64.b64decode(webapp_data['tls_key'])
        except binascii.Error:
            webapp_data['tls_crt'] = base64.b64encode(webapp_data['tls_crt'])
            webapp_data['tls_key'] = base64.b64encode(webapp_data['tls_key'])
        # TODO: ensure crt & key are paired (via hte modulus).
        webapp.tls_crt = webapp_data["tls_crt"]
        webapp.tls_key = webapp_data["tls_key"]
    else:
        webapp.tls_crt = None
        webapp.tls_key = None

    if "tls_redirect_https" in webapp_data:
        webapp.tls_redirect_https = webapp_data["tls_redirect_https"]
    else:
        webapp.tls_redirect_https = False

    for attribute in ['cron_cmd', 'cron_schedule']:
        if attribute in webapp_data:
            setattr(webapp, attribute, webapp_data[attribute])
        else:
            setattr(webapp, attribute, None)

    capsule.webapp = webapp
    db.session.commit()

    return get(capsule_id)


# /DELETE /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, user):
    capsule = _get_capsule(capsule_id, user)

    webapp = capsule.webapp

    if webapp is None:
        raise NotFound(description="This capsule does not have webapp.")

    db.session.delete(webapp)
    db.session.commit()
    return None, 204
