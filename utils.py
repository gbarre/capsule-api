import requests
import re

from sshpubkeys.exceptions import InvalidKeyError
from models import Capsule, RoleEnum, SizeEnum, WebApp
from models import User, AppToken
from flask import current_app, g, request
from exceptions import KeycloakIdNotFound, KeycloakUserNotFound
from werkzeug.exceptions import BadRequest, Forbidden
from werkzeug.exceptions import ServiceUnavailable
import OpenSSL
from functools import wraps
from app import oidc, db
from inspect import signature
from sqlalchemy.util import symbol
from hashlib import sha512
from sshpubkeys import SSHKey
from sqlalchemy.exc import OperationalError
import datetime
import base64


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


def check_owners_on_keycloak(usernames):  # pragma: no cover
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
    except OperationalError:  # pragma: no cover
        raise ServiceUnavailable("The database is unreachable.")
    if apptoken is not None:
        username = apptoken.user.name
        return (True, username)
    else:
        return (False, None)


def check_user_role(min_role=RoleEnum.admin):
    if hasattr(g, 'capsule_app_token'):  # Get user name from application token
        name = g.capsule_app_token
    else:  # Keycloak auth  # pragma: no cover
        kc_user_id = g.oidc_token_info['sub']
        try:
            name = get_user_from_keycloak(kc_user_id)
        except KeycloakIdNotFound as e:
            raise BadRequest(description=f'{e.missing_id} is an invalid id.')

    # Look for user role
    user = User.query.filter_by(name=name).one_or_none()

    if user is None:  # pragma: no cover
        if name in current_app.config['ADMINS']:
            user = User(
                name=name,
                role=RoleEnum.admin,
                parts_manager=True
            )
        elif name in current_app.config['SUPERADMINS']:
            user = User(
                name=name,
                role=RoleEnum.superadmin,
                parts_manager=True
            )
        else:
            user = User(name=name, role=RoleEnum.user)
        db.session.add(user)
        db.session.commit()

    if user.role < min_role:
        raise Forbidden

    return user


def get_user_from_keycloak(id, by_name=False):  # pragma: no cover
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


def build_query_filters(model_class, filters):  # pragma: no cover
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
    ssh = SSHKey(public_key, strict=True)
    try:
        ssh.parse()
    except InvalidKeyError:
        return False
    except NotImplementedError:
        return False
    return True


def is_keycert_associated(str_key, str_cert):

    """
    :type cert: str
    :type private_key: str
    :rtype: bool
    """
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM,
            # str_key.decode('ascii'),
            str_key,
        )
    except OpenSSL.crypto.Error:
        raise BadRequest('The private key is not a valid PEM file')

    try:
        cert_obj = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            # str_cert.decode('ascii'),
            str_cert,
        )
    except OpenSSL.crypto.Error:
        raise BadRequest('The certificate is not a valid PEM file')

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error:
        return False


def getClusterPartsUsage(capsule_name):
    capsules = Capsule.query.filter(Capsule.name != capsule_name)
    parts = 0
    for capsule in capsules:
        capsule_parts = SizeEnum.getparts(capsule.size)
        parts = parts + capsule_parts

    return parts


def getWebappsVolumeUsage(webapp_id=None):
    webapps = WebApp.query.filter(WebApp.id != webapp_id)
    used = 0
    for webapp in webapps:
        used = used + webapp.volume_size

    return used


def get_certificate_cn(x509cert):
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(x509cert)
    )
    subject = cert.get_subject()
    if "CN=" in str(subject):
        return subject.CN
    else:
        res = str(subject)\
            .replace("<X509Name object '/", '')\
            .replace("'>", '').replace('/', ', ')
    return res


def get_certificate_san(x509cert):
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(x509cert)
    )
    san = ''
    ext_count = cert.get_extension_count()
    for i in range(0, ext_count):
        ext = cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    if len(san) > 0:
        dns_array = san.split("DNS:")
        san = []
        for dns in dns_array:
            if len(dns) > 0:
                san.append(dns.replace(', ', ''))
    else:
        san = ['']
    return san


def get_certificate_notBefore(x509cert):
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(x509cert)
    )
    notBeforeString = cert.get_notBefore().decode("utf-8").replace('Z', '')
    return datetime.datetime.strptime(notBeforeString, '%Y%m%d%H%M%S')


def get_certificate_notAfter(x509cert):
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(x509cert)
    )
    notBeforeString = cert.get_notAfter().decode("utf-8").replace('Z', '')
    return datetime.datetime.strptime(notBeforeString, '%Y%m%d%H%M%S')


def get_certificate_hasExpired(x509cert):
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(x509cert)
    )
    return cert.has_expired()


def get_certificate_issuer(x509cert):
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(x509cert)
    )
    issuer = str(cert.get_issuer())\
        .replace("<X509Name object '/", '')\
        .replace("'>", '').replace('/', ', ')
    return issuer
