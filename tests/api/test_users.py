from app import oidc
from tests.utils import *
from unittest.mock import patch
from models import user_schema, users_schema
from werkzeug.exceptions import Forbidden


class TestUsers:

    #################################
    #### Testing GET /users
    #################################
    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            res = testapp.get(api_version + "/users", status=403)

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        testapp.get(api_version + "/users", status=401)

    # Response 200:
    def test_get(self, testapp, db):
        users_output = users_schema.dump(db.users).data

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.get(api_version + "/users", status=200).json
            assert dict_contains(res, users_output)

    #################################

    #################################
    #### Testing GET /users/uId
    #################################
    # Response 404:
    def test_get_bad_user(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.get(api_version + "/users/XYZ", status=404).json
            assert "The requested user 'XYZ' has not been found." in res["error_description"]

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            user_id = db.user1.name
            res = testapp.get(api_version + "/users/" + user_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["error_description"]

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        user_id = db.user1.name
        testapp.get(api_version + "/users/" + user_id, status=401)

    # Response 200:
    def test_get_user(self, testapp, db):
        user_output = user_schema.dump(db.user1).data
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user):

            user_id = db.user1.name
            # Get this user by id
            user = testapp.get(api_version + "/users/" + user_id, status=200).json
            assert dict_contains(user, user_output)
    #################################