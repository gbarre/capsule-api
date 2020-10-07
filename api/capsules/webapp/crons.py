from flask import request
from models import RoleEnum
from models import Capsule
from models import Cron, cron_schema, crons_schema
from app import db, nats
from utils import build_query_filters, oidc_require_role
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

    if capsule.webapp is None:
        raise NotFound(description="This capsule does not have webapp.")

    user_is_owner = False
    for owner in capsule.owners:
        if user.name == owner.name:
            user_is_owner = True

    if (not user_is_owner) and (user.role == RoleEnum.user):
        raise Forbidden

    return capsule


# GET /capsules/{cID}/webapp/crons
@oidc_require_role(min_role=RoleEnum.user)
def search(capsule_id, user, offset, limit, filters):
    capsule = _get_capsule(capsule_id, user)

    try:
        query = build_query_filters(Cron, filters)
        query.append(Cron.webapp_id == capsule.webapp_id)
        results = Cron.query.filter(*query).limit(limit).offset(offset).all()
    except AttributeError:
        raise BadRequest

    if not results:
        raise NotFound(description="No crons have been found.")

    results = crons_schema.dump(results).data

    return results


# POST /capsules/{cID}/webapp/crons
@oidc_require_role(min_role=RoleEnum.user)
def post(capsule_id, user, cron_data=None):
    capsule = _get_capsule(capsule_id, user)
    webapp = capsule.webapp

    if len(webapp.crons) > 0:
        raise Forbidden(description="Only one cron by webapp is allowed")

    if cron_data is None:
        cron_data = request.get_json()

    data = cron_schema.load(cron_data).data
    cron = Cron(**data)
    webapp.crons.append(cron)

    db.session.add(cron)
    db.session.commit()

    nats.publish_webapp_present(capsule)

    result_json = cron_schema.dump(cron).data
    return result_json, 201, {
        'Location':
            f'{request.base_url}/capsules/{capsule_id}/webapp/{cron.id}',
    }


# GET /capsules/{cID}/webapp/crons/{crId}
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, cron_id, user):
    capsule = _get_capsule(capsule_id, user)

    try:
        cron = Cron.query.get(cron_id)
    except StatementError:
        raise BadRequest(description=f"'{cron_id}' is not a valid id.")

    if not cron:
        raise NotFound(description=f"The requested cron '{cron_id}' "
                       "has not been found.")

    if str(cron.webapp_id) != str(capsule.webapp_id):
        raise Forbidden

    result = cron_schema.dump(cron).data

    return result, 200, {
        'Location':
        f'{request.base_url}/capsules/{capsule.id}/webapp/crons/{cron_id}',
    }


# PUT /capsules/{cID}/webapp/crons{crId}
@oidc_require_role(min_role=RoleEnum.user)
def put(capsule_id, cron_id, user):
    capsule = _get_capsule(capsule_id, user)
    webapp = capsule.webapp

    cron_data = request.get_json()
    data = cron_schema.load(cron_data).data

    try:
        cron = Cron.query.get(cron_id)
    except StatementError:
        raise BadRequest(description=f"'{cron_id}' is not a valid id.")

    if not cron:
        raise NotFound(description=f"The requested cron '{cron_id}' "
                       "has not been found.")

    if str(cron.webapp_id) != str(webapp.id):
        raise Forbidden

    cron.command = data['command']
    data.pop('command')
    cron.minute = "0"
    if 'minute' in data:
        cron.minute = data['minute']

    keys = ['hour', 'month', 'month_day', 'week_day']
    for key in keys:
        if key in data:
            setattr(cron, key, data[key])
        else:
            setattr(cron, key, "*")

    db.session.commit()
    nats.publish_webapp_present(capsule)
    return get(capsule_id, cron_id)


# DELETE /capsules/{cID}/webapp/crons{crId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(capsule_id, cron_id, user):
    capsule = _get_capsule(capsule_id, user)
    webapp = capsule.webapp

    try:
        cron = Cron.query.get(cron_id)
    except StatementError:
        raise BadRequest(description=f"'{cron_id}' is not a valid id.")

    if not cron:
        raise NotFound(description="This cron is not present in this webapp")

    if str(cron.webapp_id) != str(webapp.id):
        raise Forbidden

    db.session.delete(cron)
    db.session.commit()

    # TODO: we may need another message to delete the cron here
    nats.publish_webapp_present(capsule)

    return None, 204
