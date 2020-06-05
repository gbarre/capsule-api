import json
from flask import request
from models import RoleEnum
from models import SSHKey, User
from models import Capsule, capsule_output_schema, capsules_output_schema
from models import capsule_input_schema
from models import capsules_users_table, capsules_verbose_schema
from app import db, oidc, nats
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from sqlalchemy import inspect
from utils import check_owners_on_keycloak, get_user_from_keycloak, oidc_require_role, is_valid_capsule_name, build_query_filters
from exceptions import KeycloakUserNotFound


# GET /capsules
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, filters, verbose, user):
    # TODO: verbose mode
    # TODO: pagination hyperlinks (next, previous, etc.)
    # TODO: filters semms to failed : http://localhost:5000/v1/capsules?filters[name]=first-test-caps
    # NOTE: https://stackoverflow.com/questions/6474989/sqlalchemy-filter-by-membership-in-at-least-one-many-to-many-related-table

    try:
        query = build_query_filters(Capsule, filters)
        if user.role < RoleEnum.admin:
            query.append(Capsule.owners.any(User.name == user.name))
        results = Capsule.query.filter(*query).limit(limit).offset(offset).all()
    except:
        raise BadRequest

    if not results:
        raise NotFound(description="No capsules have been found.")

    if verbose is True:
        return capsules_verbose_schema.dump(results).data
    else:
        return capsules_output_schema.dump(results).data


# POST /capsules
#@oidc.accept_token(require_token=True, render_errors=False)
@oidc_require_role(min_role=RoleEnum.admin)
def post():
    capsule_data = request.get_json()
    data = capsule_input_schema.load(capsule_data).data

    try:  # Check if owners exist on Keycloak
        check_owners_on_keycloak(data['owners'])
    except KeycloakUserNotFound as e:
        raise BadRequest(description=f'{e.missing_username} is an invalid user.')

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
            sshkey = SSHKey.query.filter_by(public_key=public_key).one_or_none()
            if sshkey is None:
                data['authorized_keys'][i] = SSHKey(public_key=public_key)
            else:
                data['authorized_keys'][i] = sshkey

    capsule_name = data['name']

    # https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
    if not is_valid_capsule_name(capsule_name):
        msg = f'The capsule name "{capsule_name}" is invalid: only lowercase alphanumeric characters '\
               'or "-" are allowed, the first and the last characters must be alphanumeric, '\
               'the name must have at least 2 characters and less than 64 characters.'
        raise BadRequest(description=msg)

    caps = Capsule.query.filter_by(name=capsule_name).limit(1).one_or_none()
    if caps is not None:
        raise BadRequest(description=f'{capsule_name} already exists.')

    capsule = Capsule(**data)
    db.session.add(capsule)
    db.session.commit()

    result = capsule_output_schema.dump(Capsule.query.get(capsule.id)).data

    nats.publish_capsule(result)

    return result, 201, {
        'Location': f'{request.base_url}/{capsule.id}',
    }


# GET /capsules/{cID}
@oidc_require_role(min_role=RoleEnum.user)
def get(capsule_id, user):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    owners = capsule_output_schema.dump(capsule).data['owners']
    if (user.role is RoleEnum.user) and (user.name not in owners):
        raise Forbidden

    return capsule_output_schema.dump(capsule).data


@oidc_require_role(min_role=RoleEnum.superadmin)
def delete(capsule_id):
    try:
        capsule = Capsule.query.get(capsule_id)
    except:
        raise BadRequest

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' has not been found.")

    db.session.delete(capsule)
    db.session.commit()
    return None, 204