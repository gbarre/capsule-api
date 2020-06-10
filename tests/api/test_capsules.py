from tests.utils import api_version, dict_contains, unexisting_id, bad_id
from app import oidc, nats
from exceptions import KeycloakUserNotFound
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
from models import capsule_output_schema
import json
import pytest


class TestCapsules:
    _capsule_input = {
        "name": "test-capsule",
        "owners": [
            "foobar",
            "barfoo",
            "toto1",
        ],
    }

    _capsule_input_illegal = {
        "name": "1 Capsule with_illegal charactères",
        "owners": [
            "foobar"
        ]
    }

    @staticmethod
    def build_output(db):
        return json.loads(capsule_output_schema.dumps(db.capsule1).data)

    #################################
    # Testing GET /capsules
    #################################
    # Response 404:
    def test_get_no_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                api_version + "/capsules",
                status=404
            )

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        testapp.get(
            api_version + "/capsules",
            status=401
        )

    # Response 200:
    def test_get(self, testapp, db):
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules",
                status=200
            ).json
            assert dict_contains(res[0], capsule_output)
    #################################

    #################################
    # Testing POST /capsules
    #################################
    # Response 400:
    def test_create_raises_on_invalid_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch(
                 "api.capsules.check_owners_on_keycloak",
                 side_effect=KeycloakUserNotFound("barfoo")):

            res = testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=400
            ).json
            assert "barfoo" in res["error_description"]

    def test_create_illegal_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(
                api_version + "/capsules",
                self._capsule_input_illegal,
                status=400
            ).json
            assert "illegal" in res["error_description"]

    def test_create_duplicated_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"), \
             patch.object(nats, "publish_capsule"):

            # Create first caps
            testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=201
            ).json

            # Atempt to recreate
            res = testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=400
            ).json
            assert "already exists" in res["error_description"]

    def test_create_bad_json_missing_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("name")
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=400
            ).json
            assert "'name' is a required property" in res["error_description"]

    def test_create_bad_json_missing_owners(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("owners")
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=400
            ).json
            msg = "'owners' is a required property"
            assert msg in res["error_description"]

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        testapp.post_json(
            api_version + "/capsules",
            self._capsule_input,
            status=401
        )

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch(
                 "utils.check_user_role",
                 side_effect=Forbidden("User has not sufficient right")):

            testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=403
            )

    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"), \
             patch.object(nats, "publish_capsule") as publish_method:

            res = testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=201
            ).json
            publish_method.assert_called_once_with(res)
            assert dict_contains(res, self._capsule_input)
    #################################

    #################################
    # Testing GET /capsules/cId
    #################################
    # Response 404:
    def test_get_bad_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + unexisting_id,
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' "\
                  "has not been found."
            assert msg in res["error_description"]

    # Response 403:
    def test_get_capsule_raise_bad_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            testapp.get(
                api_version + "/capsules/" + unexisting_id,
                status=403
            )

    # Response 200:
    def test_get_capsule(self, testapp, db):
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Get this capsule by id
            capsule = testapp.get(
                api_version + "/capsules/" + capsule_id,
                status=200
            ).json
            assert dict_contains(capsule, capsule_output)
    #################################

    #################################
    # Testing DELETE /capsules/cId
    #################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Delete this capsule
            testapp.delete(
                api_version + "/capsules/" + capsule_id,
                status=204
            )

            # No more capsule
            res = testapp.get(
                api_version + "/capsules/" + capsule_id,
                status=404
            ).json
            msg = f"The requested capsule '{capsule_id}' has not been found."
            assert msg in res["error_description"]

    # Response 400:
    def test_delete_bad_capsule(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            testapp.delete(
                api_version + '/capsules/' + bad_id,
                status=400
            )

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        # Delete this capsule
        testapp.delete(
            api_version + "/capsules/" + capsule_id,
            status=401
        )

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this capsule
            testapp.delete(
                api_version + "/capsules/" + capsule_id,
                status=403
            )
    #################################
