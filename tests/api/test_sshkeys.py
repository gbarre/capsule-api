from app import oidc
from tests.utils import dict_contains
from unittest.mock import patch
import tests.foodata as foodata
from werkzeug.exceptions import Forbidden
from models import RoleEnum, User
import pytest


class TestSshKeys:

    _sshkeys_output = [foodata.sshkey1, foodata.sshkey2]

    _foobar = User(name="toto1", role=RoleEnum.user)

    #################################
    #### Testing GET /sshkeys
    #################################
    # Response 404: TODO after filter by user

    # Response 403: WHY ???

    # Response 401:
    def test_get_with_no_token(self, testapp):
        testapp.get("/v1/sshkeys", status=401)

    # Response 200:
    def test_get(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            res = testapp.get("/v1/sshkeys", status=200).json
            for key in self._sshkeys_output:
                assert key in res

    #################################

    #################################
    #### Testing POST /sshkeys
    #################################
    # Response 403:

    # Response 401:

    # Response 201:

    #################################

    #################################
    #### Testing DELETE /sshkeys
    #################################
    # Response 204:

    # Response 400:

    # Response 401:

    # Response 403:
