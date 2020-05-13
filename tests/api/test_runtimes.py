from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import dict_contains
from unittest.mock import patch
import tests.foodata as foodata


class TestRuntimes:

    _runtime_input = {
        "name": "Runtime Test",
        "runtimeType": "webapp"
    }

    _runtime_output = foodata.runtime1

    #################################
    #### Testing GET /runtimes
    #################################
    # Response 200:
    def test_get(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True):
            res = testapp.get('/v1/runtimes', status=200).json

            assert dict_contains(res[0], self._runtime_output)

    # Response 401:
    def test_get_with_no_token(self, testapp):
        testapp.get('/v1/runtimes', status=401)
    #################################

    #################################
    #### Testing POST /runtimes
    #################################
    # Response 201:
    # def test_create(self, testapp, db):
    #     with patch.object(oidc, 'validate_token', return_value=True):
    #         res = testapp.post_json('/v1/runtimes', self._runtime_input, status=201).json
    #         assert dict_contains(res, self._runtime_input)

    # Response 400:
    # TODO: bad json input (missing name or runtimeType)

    # Response 401:
    # def test_create_with_no_token(self, testapp):
    #     testapp.post_json('/v1/runtimes', self._runtime_input, status=401)

    # Response 403:
    # def test_create_with_non_admin(self, testapp, db, monkeypatch):

    #################################

    # TODO: GET ; PUT & DELETE runtimes/rId
    #################################
    #### Testing GET /runtimes/rId
    #################################
    # Response 200:


    # Response 401:


    # Response 200:


    #################################

    #################################
    #### Testing PUT /runtimes/rId
    #################################
    # Response 200:


    # Response 201:


    # Response 400:


    # Response 401:


    # Response 403:


    #################################

    #################################
    #### Testing DELETE /runtimes/rId
    #################################
    # Response 204:


    # Response 400:


    # Response 401:


    # Response 403:


    #################################