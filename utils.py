import requests
import re
from models import RoleEnum
from models import User, AppToken
from flask import current_app, g, request
from exceptions import KeycloakUserNotFound, KeycloakIdNotFound
from exceptions import NotRSACertificate, NotValidPEMFile
from werkzeug.exceptions import BadRequest, Forbidden
from werkzeug.exceptions import ServiceUnavailable, Unauthorized
from functools import wraps
from app import oidc
from inspect import signature
from sqlalchemy.util import symbol
from hashlib import sha512
import base64
import struct
import binascii
import OpenSSL.crypto
from Crypto.Util import asn1
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
        if 'X-Capsule-Application' in request.headers and \
                request.headers['X-Capsule-Application'].startswith('Bearer '):
            token = request.headers['X-Capsule-Application']\
                .split(None, 1)[1].strip()
            (validity, username) = check_apptoken(token)
            if validity:
                g.capsule_app_token = username
                return view_func(*args, **kwargs)
            else:
                response_body = {
                    'error': 'invalid_token',
                    'error_description': 'Token required but invalid',
                }
                return response_body, 401,\
                    {'WWW-X-Capsule-Application': 'Bearer'}
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
    if apptoken is None:
        raise Unauthorized(description="Token is not valid.")
    else:
        username = apptoken.user.name
        return (True, username)


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

    if (user is None) or (user.role < min_role):
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

    c = OpenSSL.crypto

    try:
        cert = c.load_certificate(c.FILETYPE_PEM, str_cert)
    except Exception:
        raise NotValidPEMFile('The certificate is not a valid PEM file')
    try:
        priv = c.load_privatekey(c.FILETYPE_PEM, str_key)
    except Exception:
        raise NotValidPEMFile('The private key is not a valid PEM file')

    pub = cert.get_pubkey()

    # Only works for RSA (I think)
    if pub.type() != c.TYPE_RSA or priv.type() != c.TYPE_RSA:
        raise NotRSACertificate('Can only handle RSA keys and certificates')

    # This seems to work with public as well
    pub_asn1 = c.dump_privatekey(c.FILETYPE_ASN1, pub)
    priv_asn1 = c.dump_privatekey(c.FILETYPE_ASN1, priv)

    # Decode DER
    pub_der = asn1.DerSequence()
    pub_der.decode(pub_asn1)
    priv_der = asn1.DerSequence()
    priv_der.decode(priv_asn1)

    # Get the modulus
    pub_modulus = pub_der[1]
    priv_modulus = priv_der[1]

    if pub_modulus == priv_modulus:
        return True
    else:
        return False
