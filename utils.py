import requests
import re
from models import RoleEnum
from models import User, AppToken
from flask import current_app, g, request
from exceptions import KeycloakIdNotFound, KeycloakUserNotFound
from exceptions import NotValidPEMFile
from werkzeug.exceptions import BadRequest, Forbidden
from werkzeug.exceptions import ServiceUnavailable
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from functools import wraps
from app import oidc, db
from inspect import signature
from sqlalchemy.util import symbol
from hashlib import sha512
import base64
import struct
import binascii
from sqlalchemy.exc import OperationalError


OIDC_CONFIG = None


def is_valid_name(name):

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
    oidc_client_secrets = current_app.config['OIDC_CLIENT_SECRETS']['web']
    token_uri = oidc_client_secrets['token_uri']
    admin_uri = oidc_client_secrets['admin_uri']
    client_id = oidc_client_secrets['client_id']
    client_secret = oidc_client_secrets['client_secret']

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
        try:
            token = request.headers['Authorization'].split(None, 1)[1].strip()
            (validity, username) = check_apptoken(token)
        except KeyError:
            validity = False
        if validity:
            g.capsule_app_token = username
            return view_func(*args, **kwargs)
        else:  # Fallback on Keycloak auth
            return oidc.accept_token(
                require_token=True,
                render_errors=False
            )(view_func)(*args, **kwargs)

    return wrapper


def check_apptoken(token):
    hashed_token = sha512(token.encode('ascii')).hexdigest()
    try:
        apptoken = AppToken.query.filter_by(token=hashed_token).first()
    except OperationalError:
        raise ServiceUnavailable("The database is unreachable.")
    if apptoken is not None:
        username = apptoken.user.name
        return (True, username)
    else:
        return (False, None)


def check_user_role(min_role=RoleEnum.admin):
    if hasattr(g, 'capsule_app_token'):  # Get user name from application token
        name = g.capsule_app_token
    else:  # Keycloak auth
        kc_user_id = g.oidc_token_info['sub']
        try:
            name = get_user_from_keycloak(kc_user_id)
        except KeycloakIdNotFound as e:
            raise BadRequest(description=f'{e.missing_id} is an invalid id.')

    # Look for user role
    user = User.query.filter_by(name=name).one_or_none()

    if user is None:
        if name in current_app.config['ADMINS']:
            user = User(name=name, role=RoleEnum.admin)
        elif name in current_app.config['SUPERADMINS']:
            user = User(name=name, role=RoleEnum.superadmin)
        else:
            raise Forbidden
        db.session.add(user)
        db.session.commit()

    if user.role < min_role:
        raise Forbidden

    return user


def get_user_from_keycloak(id, by_name=False):
    oidc_client_secrets = current_app.config['OIDC_CLIENT_SECRETS']['web']
    token_uri = oidc_client_secrets['token_uri']
    admin_uri = oidc_client_secrets['admin_uri']
    client_id = oidc_client_secrets['client_id']
    client_secret = oidc_client_secrets['client_secret']

    token_res = requests.post(token_uri, data={
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
    }).json()
    access_token = token_res['access_token']

    res = requests.get(f'{admin_uri}/users/{id}', headers={
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}',
    }).json()

    if "username" not in res:
        raise KeycloakIdNotFound(id)

    return res["username"]


def build_query_filters(model_class, filters):
    query = []
    # For instance, with
    # http://localhost:5000/v1/capsules?filters[name]=first-test-caps&filters[owners]=user1,user2:
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
                and field.property.direction in \
                (symbol('ONETOMANY'), symbol('MANYTOMANY')):
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
                # For instance with "owners" filter:
                # query.append(Capsule.owners.any(User.id == user.id))
                query.append(field.any(value_class_property == value))
        else:
            # query.append(Capsule.name == "first-test-caps"))
            query.append(field == value)
    return query


def valid_sshkey(public_key):
    # Inspired from  https://gist.github.com/piyushbansal/5243418
    key = bytes(public_key, 'utf-8')
    array = key.split()
    # Each rsa-ssh key has 3 different strings in it, first one being
    # typeofkey second one being keystring third one being username .
    if len(array) != 3:
        return False
    typeofkey = array[0]
    string = array[1]
    # username = array[2]
    # must have only valid rsa-ssh key characters ie binascii characters
    try:
        data = base64.b64decode(string)
    except binascii.Error:
        return False
    a = 4
    # unpack the contents of data, from data[:4],
    # it must be equal to 7, property of ssh key.
    try:
        str_len = struct.unpack('>I', data[:a])[0]
    except struct.error:
        return False
    # data[4:11] must have string which matches with the typeofkey,
    # another ssh key property.
    if data[a:a + str_len] == typeofkey and int(str_len) == int(7):
        return True
    else:
        return False


def is_keycert_associated(str_key, str_cert):

    try:
        issuer_public_key = load_pem_private_key(
            str_key,
            password=None,
            backend=default_backend(),
        ).public_key()
    except ValueError:
        raise NotValidPEMFile('The private key is not a valid PEM file')

    try:
        cert_to_check = x509.load_pem_x509_certificate(
            str_cert,
            default_backend(),
        )
    except ValueError:
        raise NotValidPEMFile('The certificate is not a valid PEM file')

    try:
        issuer_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            # Depends on the algorithm used to create the certificate
            padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
