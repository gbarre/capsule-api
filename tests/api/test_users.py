from app import oidc
from tests.utils import *
from unittest.mock import patch
import tests.foodata as foodata
from models import RoleEnum, User
from werkzeug.exceptions import Forbidden


class TestUsers:
    _user_output = foodata.user1

    #################################
    #### Testing GET /users
    #################################
    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            res = testapp.get(api_version + "/users", status=403)

    # Response 401:
    def test_get_with_no_token(self, testapp, users):
        testapp.get(api_version + "/users", status=401)

    # Response 200:
    def test_get(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=users["fake_admin"]):

            res = testapp.get(api_version + "/users", status=200).json

            assert dict_contains(res[0], self._user_output)

    #################################

    #################################
    #### Testing GET /users/uId
    #################################
    # Response 404:
    def test_get_bad_user(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=users["fake_admin"]):

            res = testapp.get(api_version + "/users/XYZ", status=404).json
            assert "The requested user 'XYZ' has not been found." in res["detail"]

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            user_id = foodata.user1["name"]
            res = testapp.get(api_version + "/users/" + user_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 401:
    def test_get_with_no_token(self, testapp, users):
        user_id = foodata.user1["name"]
        testapp.get(api_version + "/users/" + user_id, status=401)

    # Response 200:
    def test_get_user(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=users["fake_admin"]):

            user_id = foodata.user1["name"]
            # Get this user by id
            user = testapp.get(api_version + "/users/" + user_id, status=200).json
            assert dict_contains(user, self._user_output)
    #################################