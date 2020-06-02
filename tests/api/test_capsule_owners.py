from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import *
from unittest.mock import patch
import tests.foodata as foodata
from werkzeug.exceptions import Forbidden
from models import RoleEnum, User
import pytest


class TestCapsuleOwners:

    _owners_input = {
        "newOwner": "tutu3",
    }
    _bad_owner_input = {
        "owner": "titi4",
    }

    _owners_output = [ {"name": u} for u in foodata.capsule1["owners"] ]

    ################################################
    #### Testing GET /capsules/{cId}/owners
    ################################################
    # Response 400:
    def test_get_bad_request(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.get(api_version + "/capsules/" + bad_id + "/owners", status=400)

    # Response 401:
    def test_get_with_no_token(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        testapp.get(api_version + "/capsules/" + capsule_id + "/owners", status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=users["fake_user"]):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/owners", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_get_bad_id(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.get(api_version + "/capsules/" + unexisting_id + "/owners", status=404).json
            assert "The requested capsule '" + unexisting_id + "' has not been found." in res["detail"]

    # Response 200:
    def test_get(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/owners", status=200).json
            assert dict_contains(res, self._owners_output)
    ################################################

    ################################################
    #### Testing PATCH /capsules/{cId}/owners
    ################################################
    # Response 400:
    def test_patch_bad_request_wrong_capsule_id(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            testapp.patch_json(api_version + "/capsules/" + bad_id + "/owners", self._owners_input, status=400)

    def test_patch_bad_request_wrong_input(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.patch_json(api_version + "/capsules/" + capsule_id + "/owners", self._bad_owner_input, status=400).json
            print(res)
            assert "The key newOwner is required." in res["detail"]

    # Response 401:
    def test_patch_unauthorized(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        testapp.patch_json(api_version + "/capsules/" + capsule_id + "/owners", self._owners_input, status=401)

    # Response 403:
    def test_patch_forbidden(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=users["fake_user"]):

            res = testapp.patch_json(api_version + "/capsules/" + capsule_id + "/owners", self._owners_input, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_patch_not_found_capsule_id(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.patch_json(api_version + "/capsules/" + unexisting_id + "/owners", self._owners_input, status=404)

    def test_patch_not_found_owner(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak", side_effect=KeycloakUserNotFound("tutu3")):

            testapp.patch_json(api_version + "/capsules/" + capsule_id + "/owners", self._owners_input, status=404)

    # Response 409: TODO => is it a real conflict ?
    def test_patch_conflict(self,testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            new_owner = {
                "newOwner": self._owners_output[0]["name"]
            }

            testapp.patch_json(api_version + "/capsules/" + capsule_id + "/owners", new_owner, status=409)

    # Response 200:
    def test_patch(self,testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak"):

            res = testapp.patch_json(api_version + "/capsules/" + capsule_id + "/owners", self._owners_input, status=200).json
            assert self._owners_input["newOwner"] in res["owners"]
    ################################################

    ################################################
    #### Testing DELETE /capsules/{cId}/owners/uId
    ################################################
    # Response 400:
    def test_delete_bad_request_wrong_capsule_id(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.delete(api_version + "/capsules/" + bad_id + "/owners/whatever", status=400)

    # Response 401:
    def test_delete_unauthorized(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        testapp.delete(api_version + "/capsules/" + capsule_id + "/owners/" + self._owners_output[0]["name"], status=401)

    # Response 403:
    def test_delete_forbidden(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=users["fake_user"]):

            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/owners/" + self._owners_output[0]["name"], status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_delete_not_found_capsule_id(self, testapp, users):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.delete(api_version + "/capsules/" + unexisting_id + "/owners/" + self._owners_output[1]["name"], status=404)

    def test_delete_not_found_owner(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak", side_effect=KeycloakUserNotFound("tutu3")):

            testapp.delete(api_version + "/capsules/" + capsule_id + "/owners/" + self._owners_input["newOwner"], status=404)

    # Response 409:
    def test_delete_conflict(self,testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.delete(api_version + "/capsules/" + capsule_id + "/owners/" + foobar.name, status=409)

    # Response 204:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete(self, testapp, users):
        capsule_id = get_capsule_id(testapp, users)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak"):

            # Delete owner
            testapp.delete(api_version + "/capsules/" + capsule_id + "/owners/" + self._owners_output[1]["name"], status=204)

            # Check owner is not present anymore
            res = testapp.get(api_version + "/capsules/" + capsule_id + "/owners", status=200).json
            assert self._owners_output[1]["name"] not in res
    ################################################