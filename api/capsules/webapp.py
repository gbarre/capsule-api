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


def _get_capsule(capsule_id, user):
    try:
        capsule = Capsule.query.get(capsule_id)
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
        opts = Option.create(webapp_data["opts"])
        webapp_data.pop("opts")
        newArgs["opts"] = opts

    webapp = WebApp(**webapp_data, **newArgs)
    capsule.webapp = webapp

    db.session.add(webapp)
    db.session.commit()

    result = WebApp.query.get(capsule.webapp_id)
    result_json = webapp_schema.dump(result).data
    if 'env' in result_json:
        result_json["env"] = literal_eval(result_json["env"])

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
    if 'env' in result_json:
        result_json["env"] = literal_eval(result_json["env"])

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

    if "opts" in webapp_data:
        opts = Option.create(webapp_data["opts"])
        webapp.opts = opts

    webapp.runtime_id = webapp_data["runtime_id"]

    if "tls_crt" in webapp_data:
        webapp.tls_crt = webapp_data["tls_crt"]
    else:
        webapp.tls_crt = None

    if "tls_key" in webapp_data:
        webapp.tls_key = webapp_data["tls_key"]
    else:
        webapp.tls_key = None

    if "tls_redirect_https" in webapp_data:
        webapp.tls_redirect_https = webapp_data["tls_redirect_https"]
    else:
        webapp.tls_redirect_https = False

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
