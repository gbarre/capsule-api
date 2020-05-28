from flask import request
import ast
from models import RoleEnum
from models import Capsule, User
from models import WebApp, webapp_schema
from models import FQDN, Option
from app import db, oidc
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
from pprint import pprint


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

# /POST /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user, webapp=None):
    capsule = _get_capsule(capsule_id, user)
    webapp = capsule.webapp

    # Only one webapp per capsule
    if webapp is not None:
        raise Conflict(description="This capsule already has a webapp.")

    webapp_data = request.get_json()

    if "env" in webapp_data:
        webapp_data["env"] = str(webapp_data["env"])

    newArgs = dict()
    if "fqdns" in webapp_data:
        fqdns = []
        for fqdn in webapp_data["fqdns"]:
            fqdns.append(FQDN(**fqdn))
        webapp_data.pop("fqdns")
        newArgs["fqdns"] = fqdns

    if "opts" in webapp_data:
        opts = []
        for opt in webapp_data["opts"]:
            opts.append(Option(**opt))
        webapp_data.pop("opts")
        newArgs["opts"] = opts

    webapp = WebApp(**webapp_data, **newArgs)
    capsule.webapp = webapp

    db.session.add(webapp)
    db.session.commit()

    result = WebApp.query.get(capsule.webapp_id)
    result_json = webapp_schema.dump(result).data
    result_json["env"] = ast.literal_eval(result_json["env"])

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
    result_json["env"] = ast.literal_eval(result_json["env"])

    return result_json, 200, {
        'Location': f'{request.base_url}/{capsule.id}/webapp',
    }

# /PUT /capsules/{cId}/webapp
@oidc_require_role(min_role=RoleEnum.user)
def put(capsule_id, user):
    capsule = _get_capsule(capsule_id, user)

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