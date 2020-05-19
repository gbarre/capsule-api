import json
import requests
import re
from models import RoleEnum
from models import User, Capsule, capsule_schema
from flask import current_app, g
from exceptions import KeycloakUserNotFound, KeycloakIdNotFound
from werkzeug.exceptions import BadRequest, Forbidden, NotFound
from functools import wraps
from app import oidc
from inspect import signature


OIDC_CONFIG = None

REGEX_CAPSULE_NAME = re.compile('^[a-z][-a-z0-9]+$')


def check_owners_on_keycloak(usernames):
    global OIDC_CONFIG

    if OIDC_CONFIG is None:
        with open(current_app.config['OIDC_CLIENT_SECRETS']) as json_file:
            OIDC_CONFIG = json.load(json_file)

    issuer = OIDC_CONFIG['web']['issuer']
    token_uri = OIDC_CONFIG['web']['token_uri']
    admin_uri = OIDC_CONFIG['web']['admin_uri']
    client_id = OIDC_CONFIG['web']['client_id']
    client_secret = OIDC_CONFIG['web']['client_secret']

    token_res = requests.post(token_uri, data={
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
    }).json()
    access_token = token_res['access_token']

    for username in usernames:
        res = requests.get(f'{admin_uri}/users?username={username}',
                           headers={
                               'Accept': 'application/json',
                               'Authorization': f'Bearer {access_token}',
                           }).json()
        if not res:
            raise KeycloakUserNotFound(username)


def oidc_require_role(min_role):

    def decorator(view_func):

        @wraps(view_func)
        @oidc.accept_token(require_token=True, render_errors=False)
        def wrapper(*args, **kwargs):
            user = check_user_role(min_role)

            sig = signature(view_func)
            if "user" in sig.parameters:
                kwargs["user"] = user

            return view_func(*args, **kwargs)

        return wrapper

    return decorator

def check_user_role(min_role=RoleEnum.admin):
    # Get user uid in keycloak from token
    kc_user_id = g.oidc_token_info['sub']
    try:
        kc_user = get_user_from_keycloak(kc_user_id)
        name = kc_user['username']
    except KeycloakIdNotFound as e:
        raise BadRequest(description=f'{e.missing_id} is an invalid id.')
    # Look for user role
    user = User.query.filter_by(name=name).one_or_none()

    if (user is None) or (user.role < min_role) :
        raise Forbidden

    return user

def get_user_from_keycloak(id):
    global OIDC_CONFIG

    if OIDC_CONFIG is None:
        with open(current_app.config['OIDC_CLIENT_SECRETS']) as json_file:
            OIDC_CONFIG = json.load(json_file)

    issuer = OIDC_CONFIG['web']['issuer']
    token_uri = OIDC_CONFIG['web']['token_uri']
    admin_uri = OIDC_CONFIG['web']['admin_uri']
    client_id = OIDC_CONFIG['web']['client_id']
    client_secret = OIDC_CONFIG['web']['client_secret']

    token_res = requests.post(token_uri, data={
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
    }).json()
    access_token = token_res['access_token']

    res = requests.get(f'{admin_uri}/users/{id}',
                        headers={
                            'Accept': 'application/json',
                            'Authorization': f'Bearer {access_token}',
                        }).json()
    if not res:
        raise KeycloakIdNotFound(id)

    return res
