import json
import requests
from flask import current_app
from exceptions import KeycloakUserNotFound


OIDC_CONFIG = None


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