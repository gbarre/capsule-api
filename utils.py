import json
import requests
import re
from models import RoleEnum, Runtime
from models import User, Capsule, AppToken
from flask import current_app, g, request
from exceptions import KeycloakUserNotFound, KeycloakIdNotFound
from werkzeug.exceptions import BadRequest, Forbidden, NotFound, Unauthorized
from functools import wraps
from app import oidc
from inspect import signature
from marshmallow import fields
from sqlalchemy.util import symbol
from hashlib import sha512


OIDC_CONFIG = None


def is_valid_capsule_name(name):

    if len(name) > 64:
        return False

    # WARNING: a capsule name will be the name of a namespace in k8s.
    # https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
    pattern = re.compile('^[a-z0-9][-a-z0-9]*[a-z0-9]$')

    if pattern.match(name):
        return True
    else:
        return False


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
        if username == "":
            raise KeycloakUserNotFound("empty username")
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
        @require_auth
        def wrapper(*args, **kwargs):

            user = check_user_role(min_role)

            sig = signature(view_func)
            if "user" in sig.parameters:
                kwargs["user"] = user

            return view_func(*args, **kwargs)

        return wrapper

    return decorator


def require_auth(view_func):
    def wrapper(*args, **kwargs):
        if 'X-Capsule-Application' in request.headers and request.headers['X-Capsule-Application'].startswith('Bearer '):
            token = request.headers['X-Capsule-Application'].split(None, 1)[1].strip()
            (validity, username) = check_apptoken(token)
            if validity:
                g.capsule_app_token = username
                return view_func(*args, **kwargs)
            else:
                response_body = {'error': 'invalid_token', 'error_description': 'Token required but invalid'}
                return response_body, 401, {'WWW-X-Capsule-Application': 'Bearer'}
        else:  # Fallback on Keycloak auth
            return oidc.accept_token(require_token=True, render_errors=False)(view_func)(*args, **kwargs)

    return wrapper


def check_apptoken(token):
    hashed_token = sha512(token.encode('ascii')).hexdigest()
    apptoken = AppToken.query.filter_by(token=hashed_token).first()
    if apptoken is None:
        raise Unauthorized(description="Token is not valid.")
    else:
        username = apptoken.user.name
        return (True, username)


def check_user_role(min_role=RoleEnum.admin):
    if hasattr(g, 'capsule_app_token'):  # Get user name from application token
        name = g.capsule_app_token  # TODO: Change the way to get user name from token
    else:  # Keycloak auth
        kc_user_id = g.oidc_token_info['sub']
        try:
            name = get_user_from_keycloak(kc_user_id)
        except KeycloakIdNotFound as e:
            raise BadRequest(description=f'{e.missing_id} is an invalid id.')

    # Look for user role
    user = User.query.filter_by(name=name).one_or_none()

    if (user is None) or (user.role < min_role) :
        raise Forbidden

    return user

def get_user_from_keycloak(id, by_name=False):
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

    if "username" not in res:
        raise KeycloakIdNotFound(id)

    return res["username"]

def build_query_filters(model_class, filters):
    query = []
    # For instance, with http://localhost:5000/v1/capsules?filters[name]=first-test-caps&filters[owners]=user1,user2:
    #
    #   model_class = Capsule
    #   filters = [
    #       "name": "first-test-caps",
    #       "owners": "user1,user2"
    #   ]

    for filter, value in filters.items():
        # filter = "name"
        # value = "first-test-caps"
        field = getattr(model_class, filter)
        # filed = Capsule.name
        if field is None:
            continue

        # If the property to filter on is a collection
        if hasattr(field.property, 'direction') \
            and field.property.direction in (symbol('ONETOMANY'), symbol('MANYTOMANY')):
            value_class = field.property.entity.mapper.entity
            # value_class = User

            if hasattr(value_class, '__default_filter__'):
                property_to_filter = value_class.__default_filter__
            else:
                property_to_filter = 'id'

            value_class_property = getattr(value_class, property_to_filter)
            # value_class_property = User.name
            if ',' in value:
                values = value.split(',')
                for v in values:
                    query.append(field.any(value_class_property == v))
            elif '|' in value:
                values = value.split('|')
                query.append(field.any(value_class_property.in_(values)))
            else:
                # For instance with "owners" filter: query.append(Capsule.owners.any(User.id == user.id))
                query.append(field.any(value_class_property == value))
        else:
            # query.append(Capsule.name == "first-test-caps"))
            query.append(field == value)
    return query
