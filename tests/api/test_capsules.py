from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import *
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
from models import RoleEnum, capsule_schema
import pytest


class TestCapsules:
    _capsule_input = {
        "name": "test-capsule",
        "owners": [
            "foobar",
            "barfoo",
            "toto1",
        ],
        "authorized_keys": [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfIjBj6woA9p+xZh8cqeiZLzN"\
            "RARCP0Ym9gITKNgRxjRNJj+nfkBSK27A5TjL7cFFyUf1BOhY+Rwsj8wC0jt0NsbAfF"\
            "oX+qdbqra/FC4GYwyfLfIMnZrBSjFJ0uDe5zNgDuGsvNpPAx4LA+hqdUN0iXYpMYsz"\
            "+W9KtofeG8xbCGWHUaQPxxhralgJjkhAWxoCq7Gj92Kbb5/bvOBHpEeMdD6iDJ2zfW"\
            "/xyRI8btllTDGzKmYVZlSHwbNje3jX4yiR2V20SlewSn07K7xykmTPsUPgpx+uysYR"\
            "VwWUb2sWJVARfjZUzeSLrDATpxQIWYU9iY0l4cPOztnTMZN3LIBkD john@doe",
        ]
    }

    _capsule_input_illegal = {
        "name" : "1 Capsule with_illegal charactères",
        "owners": [
            "foobar"
        ]
    }

    @staticmethod
    def build_output(db):
        return capsule_schema.dumps(db.capsule1).data

    #################################
    #### Testing GET /capsules
    #################################
    # Response 404:
    def test_get_no_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            testapp.get(api_version + "/capsules", status=404)

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        testapp.get(api_version + "/capsules", status=401)

    # Response 200:
    def test_get(self, testapp, db):
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(api_version + "/capsules", status=200).json
            from pprint import pprint
            pprint(res[0])
            pprint(capsule_output)
            assert dict_contains(res[0], capsule_output)
    #################################

    #################################
    #### Testing POST /capsules
    #################################
    # Response 400:
    def test_create_raises_on_invalid_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user), \
            patch("api.capsules.check_owners_on_keycloak", side_effect=KeycloakUserNotFound("barfoo")):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input, status=400).json
            assert "barfoo" in res["detail"]

    def test_create_illegal_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input_illegal, status=400).json
            assert "illegal" in res["detail"]

    def test_create_duplicated_name(self, testapp, db):
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(api_version + "/capsules", capsule_output, status=400).json
            assert "already exists" in res["detail"]

    def test_create_bad_json_missing_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user), \
            patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("name")
            res = testapp.post_json(api_version + "/capsules", temp_input, status=400).json
            assert "'name' is a required property" in res["detail"]

    def test_create_bad_json_missing_owners(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user), \
            patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("owners")
            res = testapp.post_json(api_version + "/capsules", temp_input, status=400).json
            assert "'owners' is a required property" in res["detail"]

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        testapp.post_json(api_version + "/capsules", self._capsule_input, status=401)

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden("User has not sufficient right")):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input, status=403).json

    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input, status=201).json
            assert dict_contains(res, self._capsule_input)
    #################################

    #################################
    #### Testing GET /capsules/cId
    #################################
    # Response 404:
    def test_get_bad_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(api_version + "/capsules/ffffffff-ffff-ffff-ffff-ffffffffffff", status=404).json
            assert "The requested capsule 'ffffffff-ffff-ffff-ffff-ffffffffffff' has not been found." in res["detail"]

    # Response 403:
    def test_get_capsule_raise_bad_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            res = testapp.get(api_version + "/capsules/ffffffff-ffff-ffff-ffff-ffffffffffff", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 200:
    def test_get_capsule(self, testapp, db):
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Get this capsule by id
            capsule = testapp.get(api_version + "/capsules/" + capsule_id, status=200).json
            assert dict_contains(capsule, capsule_output)
    #################################

    #################################
    #### Testing DELETE /capsules/cId
    #################################
    # Response 204:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.superadmin_user):

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Delete this capsule
            testapp.delete(api_version + "/capsules/" + capsule_id, status=204)

            # No more capsule
            res = testapp.get(api_version + "/capsules/" + capsule_id, status=404).json
            assert "The requested capsule '" + capsule_id + "' has not been found." in res["detail"]

    # Response 400:
    def test_delete_bad_capsule(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.superadmin_user):

            res = testapp.delete(api_version + '/capsules/XYZ', status=400).json
            assert "The browser (or proxy) sent a request that this server could not understand." in res["detail"]

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        # Delete this capsule
        testapp.delete(api_version + "/capsules/" + capsule_id, status=401)

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
         capsule_id = str(db.capsule1.id)
         with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this capsule
            res = testapp.delete(api_version + "/capsules/" + capsule_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]
    #################################