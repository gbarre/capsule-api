from flask import request
from models import RoleEnum
from models import SSHKey, User
from models import Capsule, capsule_output_schema, capsules_output_schema
from models import capsule_input_schema
from models import capsules_verbose_schema, capsule_verbose_schema
from app import db, nats
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from utils import check_owners_on_keycloak, oidc_require_role
from utils import is_valid_name, build_query_filters
from exceptions import KeycloakUserNotFound
from sqlalchemy.exc import StatementError


# GET /capsules
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, filters, verbose, user):
    # TODO: pagination hyperlinks (next, previous, etc.)
    try:
        # https://stackoverflow.com/questions/6474989/sqlalchemy-filter-by-membership-in-at-least-one-many-to-many-related-table
        query = build_query_filters(Capsule, filters)
        if user.role < RoleEnum.admin:
            query.append(Capsule.owners.any(User.name == user.name))
        results = Capsule.query.filter(*query)\
            .limit(limit).offset(offset).all()
    except AttributeError:
        raise BadRequest

    if not results:
        raise NotFound(description="No capsules have been found.")

    if verbose is True:
        return capsules_verbose_schema.dump(results).data
    else:
        return capsules_output_schema.dump(results).data


# POST /capsules
@oidc_require_role(min_role=RoleEnum.admin)
def post():
    capsule_data = request.get_json()
    data = capsule_input_schema.load(capsule_data).data

    try:  # Check if owners exist on Keycloak
        check_owners_on_keycloak(data['owners'])
    except KeycloakUserNotFound as e:
        raise BadRequest(
            description=f'{e.missing_username} is an invalid user.'
        )

    # Get existent users, create the others
    for i, owner in enumerate(data['owners']):
        user = User.query.filter_by(name=owner).one_or_none()
        if user is None:  # User does not exist in DB
            data['owners'][i] = User(name=owner, role=RoleEnum.user)
        else:
            data['owners'][i] = user

    # Get existent ssh keys, create the others
    if 'authorized_keys' in data:
        for i, public_key in enumerate(data['authorized_keys']):
            sshkey = SSHKey.query\
                .filter_by(public_key=public_key).one_or_none()
            if sshkey is None:
                data['authorized_keys'][i] = SSHKey(public_key=public_key)
            else:
                data['authorized_keys'][i] = sshkey

    capsule_name = data['name']

    # https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
    if not is_valid_name(capsule_name):
        msg = f'The capsule name "{capsule_name}" is invalid: only lowercase '\
            'alphanumeric characters or "-" are allowed, the first and the '\
            'last characters must be alphanumeric, the name must have at '\
            'least 2 characters and less than 64 characters.'
        raise BadRequest(description=msg)

    caps = Capsule.query.filter_by(name=capsule_name).limit(1).one_or_none()
    if caps is not None:
        raise BadRequest(description=f'{capsule_name} already exists.')

    capsule = Capsule(**data)
    db.session.add(capsule)
    db.session.commit()

    caps = Capsule.query.filter_by(id=capsule.id).first()
    result = capsule_output_schema.dump(caps).data

    return result, 201, {
        'Location': f'{request.base_url}/capsules/{capsule.id}',
    }


# GET /capsules/{cID}
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, verbose, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    owners = capsule_output_schema.dump(capsule).data['owners']
    if (user.role is RoleEnum.user) and (user.name not in owners):
        raise Forbidden

    if verbose is True:
        return capsule_verbose_schema.dump(capsule).data
    else:
        return capsule_output_schema.dump(capsule).data

# PATCH /capsules/{cID}
@oidc_require_role(min_role=RoleEnum.user)
def patch(capsule_id, user):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    owners = capsule_output_schema.dump(capsule).data['owners']
    if (user.role is RoleEnum.user) and (user.name not in owners):
        raise Forbidden

    data = request.get_json()
    try:
        no_update = data['no_update']
    except KeyError:
        raise BadRequest(description="'no_update' is a required property.")

    capsule.no_update = no_update
    db.session.commit()

    caps = Capsule.query.filter_by(id=capsule_id).first()
    result = capsule_output_schema.dump(caps).data

    return result, 200, {
        'Location': f'{request.base_url}/capsules/{capsule.id}',
    }


# DELETE /capsules/{cID}
@oidc_require_role(min_role=RoleEnum.superadmin)
def delete(capsule_id):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    # Get infos for nats after db.session.commit
    webapp_id = None
    if capsule.webapp_id is not None:
        webapp_id = str(capsule.webapp_id)

    addons_infos = []
    for addon in capsule.addons:
        addons_infos.append({
            'id': addon.id,
            'runtime_id': addon.runtime_id,
        })

    db.session.delete(capsule)
    db.session.commit()

    if not capsule.no_update:
        if webapp_id is not None:
            nats.publish_webapp_absent(webapp_id)

        for addon in addons_infos:
            nats.publish_addon_absent(addon['id'], addon['runtime_id'])

    return None, 204
