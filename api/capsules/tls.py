import datetime
from flask import request
from models import Capsule, capsule_output_schema
from models import RoleEnum
from app import db, nats
from utils import oidc_require_role, is_keycert_associated, \
    get_certificate_issuer, get_certificate_cn, get_certificate_san, \
    get_certificate_notBefore, get_certificate_notAfter, \
    get_certificate_hasExpired
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy.exc import StatementError
import base64
import binascii
from exceptions import NotValidPEMFile


# PATCH /capsules/{cID}/tls
@oidc_require_role(min_role=RoleEnum.user)  # user only with delegation
def patch(capsule_id, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    if user.role < RoleEnum.admin and not capsule.delegate_tls:
        raise Forbidden

    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden

    data = request.get_json()

    if ("key" in data and "crt" not in data) or \
            ("crt" in data and "key" not in data):
        raise BadRequest(description="Both crt and key are "
                                     "required together")

    if "crt" in data and "key" in data:
        try:
            str_cert = base64.b64decode(data['crt'])
            str_key = base64.b64decode(data['key'])
        except binascii.Error:
            raise BadRequest(description="'crt' and 'key' must be "
                                         "base64 encoded.")
        try:
            # Ensure that certificate and key are paired.
            if not is_keycert_associated(str_key, str_cert):
                raise BadRequest(description="The certificate and the key "
                                             "are not associated")
        except NotValidPEMFile:  # Possible ??
            raise BadRequest
        capsule.tls_crt = data["crt"]
        capsule.tls_key = data["key"]

    if "enable_https" in data:
        capsule.enable_https = data["enable_https"]
        if not data['enable_https']:
            capsule.tls_crt = None
            capsule.tls_key = None
        if "force_redirect_https" in data:
            capsule.force_redirect_https = data["force_redirect_https"]

    db.session.commit()

    webapp = capsule.webapp
    now = datetime.datetime.now()
    if now > (capsule.no_update + datetime.timedelta(hours=24)) and\
       webapp is not None:
        nats.publish_webapp_present(capsule)

    result = capsule_output_schema.dump(capsule)
    return result, 200, {
        'Location': f'{request.base_url}/capsules/{capsule.id}',
    }


# GET /capsules/{cID}/tls
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, user):
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

    crt = capsule.tls_crt
    if crt is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "does not have certificate.")

    result = {
        "CN": get_certificate_cn(crt),
        "SAN": get_certificate_san(crt),
        "notBefore": get_certificate_notBefore(crt),
        "notAfter": get_certificate_notAfter(crt),
        "hasExpired": get_certificate_hasExpired(crt),
        "issuer": str(get_certificate_issuer(crt)),
    }
    return result
