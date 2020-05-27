# from app import oidc
# from exceptions import KeycloakUserNotFound
from tests.utils import *
# from unittest.mock import patch
import tests.foodata as foodata
# from werkzeug.exceptions import Forbidden
# from models import RoleEnum, User
# import pytest
from pprint import pprint

class TestCapsuleWebapp:

    _webapp_input = {
            "env": {
                "HTTP_PROXY": "http://example.com:3128/",
                "HTTPS_PROXY": "https://example.com:3128/",
            },
            "fqdns": [
                {
                    "name": "main.example.com",
                    "alias": False
                },
                {
                    "name": "secondary.example.com",
                    "alias": True
                },
            ],
            "opts" : [
                {
                    "field_name": "worker",
                    "tag": "PHP",
                    "value": "42"
                },
            ],
            "quota_cpu_max": "2.5",
            "quota_memory_max": "4",
            "quota_volume_size": "20",
            "tls_redirect_https": True,
            #"runtime_id": "..."
        }

    _webapp_output = foodata.webapp

    ################################################
    #### Testing POST /capsules/{cId}/webapp
    ################################################
    # Response 400:
    def test_post_bad_capsule_id(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.post_json('/v1/capsules/' + bad_id + "/webapp", self._webapp_input, status=400)

    def test_post_missing_runtime_id(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            res = testapp.post_json('/v1/capsules/' + capsule_id + "/webapp", self._webapp_input, status=400)

    def test_post_missing_fqdns(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            # Build webapp with correct runtime_id
            runtime_id = get_runtime_id(testapp)
            new_webapp = self._webapp_input
            new_webapp["runtime_id"] = runtime_id
            new_webapp.pop("fqdns")

            res = testapp.post_json('/v1/capsules/' + capsule_id + "/webapp", new_webapp, status=400)

    # Response 401:

    # Response 403:

    # Response 409:

    # Response 201:

    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/webapp
    ################################################
    # Response 401:

    # Response 403:

    # Response 404:

    # Response 200:

    ################################################

    ################################################
    #### Testing PUT /capsules/{cId}/webapp
    ################################################
    # Response 200:

    # Response 201:

    # Response 401:

    # Response 400:

    # Response 403:

    ################################################

    ################################################
    #### Testing DELETE /capsules/{cId}/webapp
    ################################################
    # Response 204:

    # Response 401:

    # Response 403:

    # Response 404:

    ################################################

