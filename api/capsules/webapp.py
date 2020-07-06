from flask import request
from models import RoleEnum
from models import Capsule
from models import WebApp, webapp_schema
from models import FQDN, Option
from models import Runtime, RuntimeTypeEnum
from app import db, nats
from utils import oidc_require_role, is_keycert_associated
from werkzeug.exceptions import NotFound, BadRequest, Forbidden, Conflict
from sqlalchemy.exc import StatementError
import base64
import binascii
from exceptions import NotValidPEMFile


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
    webapp = capsule.webapp

    # Only one webapp per capsule
    if webapp is not None:
        raise Conflict(description="This capsule already has a webapp.")

    # Datas could come from PUT
    if webapp is None:
        webapp_data = request.get_json()
        data = webapp_schema.load(webapp_data).data

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
    if "fqdns" in data:
        fqdns = FQDN.create(data["fqdns"])
        data.pop("fqdns")
        newArgs["fqdns"] = fqdns

    if "opts" in data:
        opts = Option.create(data["opts"], runtime_id, user.role)
        data.pop("opts")
        newArgs["opts"] = opts

    if ("tls_key" in data and "tls_crt" not in data) or \
            ("tls_crt" in data and "tls_key" not in data):
        raise BadRequest(description="Both tls_crt and tls_key are "
                                     "required together")

    if "tls_crt" in data and "tls_key" in data:
        try:
            str_cert = base64.b64decode(data['tls_crt'])
            str_key = base64.b64decode(data['tls_key'])
        except binascii.Error:
            raise BadRequest(description="'tls_crt' and 'tls_key' must be "
                                         "base64 encoded.")
        try:
            # Ensure that certificate and key are paired.
            if not is_keycert_associated(str_key, str_cert):
                raise BadRequest(description="The certificate and the key "
                                             "are not associated")
        # TODO: look for cert length (> 4096) or better than RSA
        except NotValidPEMFile:
            raise BadRequest

    webapp = WebApp(**data, **newArgs)
    capsule.webapp = webapp

    db.session.add(webapp)
    db.session.commit()

    result = WebApp.query.get(capsule.webapp_id)

    nats.publish_webapp_present(capsule)

    # Api response
    result_json = webapp_schema.dump(result).data

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

    data = webapp_schema.load(webapp_data).data

    webapp.env = None
    if "env" in webapp_data:
        webapp.env = webapp_data["env"]

    if "fqdns" in data:
        fqdns = FQDN.create(data["fqdns"])
        webapp.fqdns = fqdns

    # Ensure new runtime_id has same familly
    new_runtime_id = str(data["runtime_id"])
    try:
        new_runtime = Runtime.query.get(new_runtime_id)
    except StatementError:
        raise BadRequest(description=f"'{new_runtime_id}' is not a valid id.")
    if new_runtime is None:
        raise BadRequest(description=f"The runtime_id '{new_runtime_id}' "
                         "does not exist.")
    new_fam = new_runtime.fam
    old_fam = webapp.runtime.fam
    if new_fam is not old_fam:
        raise BadRequest(f"Changing runtime familly from '{old_fam}' "
                         f"to '{new_fam}' is not possible")
    webapp.runtime_id = data["runtime_id"]

    webapp.opts = []
    if "opts" in data:
        opts = Option.create(data["opts"], data["runtime_id"], user.role)
        webapp.opts = opts

    if ("tls_key" in data and "tls_crt" not in data) or \
            ("tls_crt" in data and "tls_key" not in data):
        raise BadRequest(description="Both tls_crt and tls_key are "
                                     "required together")

    if "tls_crt" in data and "tls_key" in data:
        try:
            str_cert = base64.b64decode(data['tls_crt'])
            str_key = base64.b64decode(data['tls_key'])
        except binascii.Error:
            raise BadRequest(description="'tls_crt' and 'tls_key' must be "
                                         "base64 encoded.")
        try:
            # Ensure that certificate and key are paired.
            if not is_keycert_associated(str_key, str_cert):
                raise BadRequest(description="The certificate and the key "
                                             "are not associated")
        except NotValidPEMFile:
            raise BadRequest
        webapp.tls_crt = data["tls_crt"]
        webapp.tls_key = data["tls_key"]
    else:
        webapp.tls_crt = None
        webapp.tls_key = None

    webapp.tls_redirect_https = False
    if "tls_redirect_https" in data:
        webapp.tls_redirect_https = data["tls_redirect_https"]

    # TODO: implement cron in an other file
    # for attribute in ['cron_cmd', 'cron_schedule']:
    #     if attribute in data:
    #         setattr(webapp, attribute, data[attribute])
    #     else:
    #         setattr(webapp, attribute, None)

    capsule.webapp = webapp
    db.session.commit()

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

    nats.publish_webapp_absent(webapp_id)

    return None, 204
