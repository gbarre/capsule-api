from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import *
from unittest.mock import patch
import tests.foodata as foodata
from werkzeug.exceptions import Forbidden
from models import RoleEnum, User
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

    _capsule_output = foodata.capsule1

    #################################
    #### Testing GET /capsules
    #################################
    # Response 401:
    def test_get_with_no_token(self, testapp):
        testapp.get(api_version + "/capsules", status=401)

    # Response 403: TODO

    # Response 200:
    def test_get(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.get(api_version + "/capsules", status=200).json
            assert dict_contains(res[0], self._capsule_output)
    #################################

    #################################
    #### Testing POST /capsules
    #################################
    # Response 400:
    def test_create_raises_on_invalid_owner(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_admin), \
            patch("api.capsules.check_owners_on_keycloak", side_effect=KeycloakUserNotFound("barfoo")):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input, status=400).json
            assert "barfoo" in res["detail"]

    def test_create_illegal_name(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_admin), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input_illegal, status=400).json
            assert "illegal" in res["detail"]

    def test_create_duplicated_name(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_admin), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(api_version + "/capsules", self._capsule_output, status=400).json
            assert "already exists" in res["detail"]

    def test_create_bad_json_missing_name(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_admin), \
            patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("name")
            res = testapp.post_json(api_version + "/capsules", temp_input, status=400).json
            assert "'name' is a required property" in res["detail"]

    def test_create_bad_json_missing_owners(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_admin), \
            patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("owners")
            res = testapp.post_json(api_version + "/capsules", temp_input, status=400).json
            assert "'owners' is a required property" in res["detail"]

    # Response 401:
    def test_create_with_no_token(self, testapp):
        testapp.post_json(api_version + "/capsules", self._capsule_input, status=401)

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden("User has not sufficient right")):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input, status=403).json

    # Response 201:
    def test_create(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_admin), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(api_version + "/capsules", self._capsule_input, status=201).json
            assert dict_contains(res, self._capsule_input)
    #################################

    #################################
    #### Testing GET /capsules/cId
    #################################
    # Response 404:
    def test_get_bad_capsule(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.get(api_version + "/capsules/ffffffff-ffff-ffff-ffff-ffffffffffff", status=404).json
            assert "The requested capsule 'ffffffff-ffff-ffff-ffff-ffffffffffff' has not been found." in res["detail"]

    # Response 403:
    def test_get_capsule_raise_bad_owner(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            res = testapp.get(api_version + "/capsules/ffffffff-ffff-ffff-ffff-ffffffffffff", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 200:
    def test_get_capsule(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Get the capsule id
            res = testapp.get(api_version + "/capsules", status=200).json
            capsule_id = res[0]["id"]
            # Get this capsule by id
            capsule = testapp.get(api_version + "/capsules/" + capsule_id, status=200).json
            assert dict_contains(capsule, self._capsule_output)
    #################################

    #################################
    #### Testing DELETE /capsules/cId
    #################################
    # Response 204:
    # TODO: how to remove the header "Content-Type" in the a DELETE request only?
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_capsule(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_superadmin):

            # Get the capsule id
            res = testapp.get(api_version + "/capsules", status=200).json
            capsule_id = res[0]["id"]
            # Delete this capsule
            testapp.delete(api_version + "/capsules/" + capsule_id, status=204)

            # No more capsule
            res = testapp.get(api_version + "/capsules/" + capsule_id, status=404).json
            assert "The requested capsule '" + capsule_id + "' has not been found." in res["detail"]

    # Response 400:
    def test_delete_bad_capsule(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=fake_superadmin):

            res = testapp.delete(api_version + '/capsules/XYZ', status=400).json
            assert "The browser (or proxy) sent a request that this server could not understand." in res["detail"]

    # Response 401:
    def test_delete_unauthenticated(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Get the capsule id
            res = testapp.get(api_version + "/capsules", status=200).json
            capsule_id = res[0]["id"]

        # Delete this capsule
        testapp.delete(api_version + "/capsules/" + capsule_id, status=401)

    # Response 403:
    def test_delete_insufficient_rights(self, testapp):
         with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Get the capsule id
            res = testapp.get(api_version + "/capsules", status=200).json
            capsule_id = res[0]["id"]

         with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this capsule
            res = testapp.delete(api_version + "/capsules/" + capsule_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]
    #################################