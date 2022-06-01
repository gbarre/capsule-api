import datetime
from flask import request
from models import FQDN, RoleEnum
from models import Capsule
from models import fqdn_schema
from app import db, nats
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy.exc import IntegrityError, StatementError


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


def _capsuleHasPrimaryFQDN(fqdns):
    for fqdn in fqdns:
        if not fqdn.alias:
            return True
    return False


# POST /capsules/{cID}/fqdns
@oidc_require_role(min_role=RoleEnum.user)  # user only with delegation
def post(capsule_id, user):
    capsule = _get_capsule(capsule_id, user)
    if user.role < RoleEnum.admin and not capsule.delegate_tls:
        raise Forbidden

    fqdn_data = request.get_json()
    data = fqdn_schema.load(fqdn_data)

    existing_fqdn = FQDN.query.filter_by(name=data['name']).one_or_none()
    if existing_fqdn is not None:
        raise BadRequest(description=f'{data["name"]} already exists.')

    if not data['alias'] and _capsuleHasPrimaryFQDN(capsule.fqdns):
        raise BadRequest(description='Only one primary FQDN by capsule')

    fqdn = FQDN(**data)
    capsule.fqdns.append(fqdn)

    db.session.add(fqdn)
    db.session.commit()

    webapp = capsule.webapp
    now = datetime.datetime.now()
    if now > (capsule.no_update + datetime.timedelta(hours=24)) and\
       webapp is not None:
        nats.publish_webapp_present(capsule)

    result = fqdn_schema.dump(fqdn)
    return result, 201, {
        'Location':
            f'{request.base_url}/capsules/{capsule.id}/fqdns/{fqdn.id}',
    }


# PUT /capsules/{cID}/fqdns/{fID}
@oidc_require_role(min_role=RoleEnum.user)  # user only with delegation
def put(capsule_id, fqdn_id, user):
    capsule = _get_capsule(capsule_id, user)
    if user.role < RoleEnum.admin and not capsule.delegate_fqdns:
        raise Forbidden

    fqdn_data = request.get_json()
    data = fqdn_schema.load(fqdn_data)

    try:
        fqdn = FQDN.query.get(fqdn_id)
    except StatementError:
        raise BadRequest(description=f"'{fqdn_id}' is not a valid id.")

    if not fqdn:
        raise NotFound(description=f"The requested FQDN '{fqdn_id}' "
                       "has not been found.")

    if not data['alias'] and \
       _capsuleHasPrimaryFQDN(capsule.fqdns) and fqdn.alias:
        raise BadRequest(description='Only one primary FQDN by capsule')

    fqdn.alias = data["alias"]
    fqdn.name = data["name"]

    try:
        db.session.commit()
    except IntegrityError:
        raise BadRequest(description=f"'{data['name']}' already exists.")

    webapp = capsule.webapp
    now = datetime.datetime.now()
    if now > (capsule.no_update + datetime.timedelta(hours=24)) and\
       webapp is not None:
        nats.publish_webapp_present(capsule)

    result = fqdn_schema.dump(fqdn)
    return result, 200, {
        'Location':
            f'{request.base_url}/capsules/{capsule.id}/fqdns/{fqdn.id}',
    }


# DELETE /capsules/{cID}/fqdns/{fID}
@oidc_require_role(min_role=RoleEnum.user)  # user only with delegation
def delete(capsule_id, fqdn_id, user):
    capsule = _get_capsule(capsule_id, user)
    if user.role < RoleEnum.admin and not capsule.delegate_tls:
        raise Forbidden

    if len(capsule.fqdns) == 1:
        raise Forbidden(description="A webapp need at least one FQDN.")

    try:
        fqdn = FQDN.query.get(fqdn_id)
    except StatementError:
        raise BadRequest(description=f"'{fqdn_id}' is not a valid id.")

    if not fqdn:
        raise NotFound(description=f"The requested FQDN '{fqdn_id}' "
                       "has not been found.")

    db.session.delete(fqdn)
    db.session.commit()

    webapp = capsule.webapp
    now = datetime.datetime.now()
    if now > (capsule.no_update + datetime.timedelta(hours=24)) and\
       webapp is not None:
        nats.publish_webapp_present(capsule)

    return None, 204
