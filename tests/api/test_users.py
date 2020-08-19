from tests.utils import api_version, dict_contains, bad_id
from app import oidc
from unittest.mock import patch
from models import user_schema, users_schema
from werkzeug.exceptions import Forbidden
from exceptions import KeycloakUserNotFound


class TestUsers:

    #################################
    # Testing GET /users
    #################################
    # Response 200:
    def test_get(self, testapp, db):
        users_output = users_schema.dump(db.users).data

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.get(
                api_version + "/users",
                status=200
            ).json
            assert dict_contains(res, users_output)

    # Response 400:
    def test_get_bad_request(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.get(
                api_version + "/users?filters[foo]=bar",
                status=400
            )

    # Response 401:
    def test_get_all_with_no_token(self, testapp, db):
        testapp.get(
            api_version + "/users",
            status=401
        )

    # Response 403:
    def test_get_all_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            testapp.get(
                api_version + "/users",
                status=403
            )
    #################################

    #################################
    # Testing GET /users/uId
    #################################
    # Response 200:
    def test_get_user(self, testapp, db):
        user_output = user_schema.dump(db.user1).data
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            user_id = db.user1.name
            # Get this user by id
            user = testapp.get(
                api_version + "/users/" + user_id,
                status=200
            ).json
            assert dict_contains(user, user_output)

    def test_get_keycloak_user(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.users.check_owners_on_keycloak"):

            res = testapp.get(
                api_version + "/users/new_user",
                status=200
            ).json
            assert 'new_user' in res['name']

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        user_id = db.user1.name
        testapp.get(
            api_version + "/users/" + user_id,
            status=401
        )

    # Response 403:
    def test_get_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            user_id = db.user1.name
            testapp.get(
                api_version + "/users/" + user_id,
                status=403
            )

    # Response 404:
    def test_get_bad_user(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch(
                 "api.users.check_owners_on_keycloak",
                 side_effect=KeycloakUserNotFound(bad_id)):

            res = testapp.get(
                api_version + "/users/" + bad_id,
                status=404
            ).json
            msg = f"{bad_id} was not found in Keycloak."
            assert msg in res["error_description"]
    #################################
