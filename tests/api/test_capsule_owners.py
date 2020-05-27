from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import dict_contains
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

    _foobar = User(name="toto1", role=RoleEnum.user)
    _fake_admin = User(name="fake_user", role=RoleEnum.admin)
    _fake_superadmin = User(name="fake_user", role=RoleEnum.superadmin)
    _fake_user = User(name="fake_user", role=RoleEnum.user)

    _bad_capsule_id = "XYZ"
    _unexisting_capsule_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"

    # Before anything we need a capsule id
    def get_capsule_id(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            # Get the capsule id
            res = testapp.get("/v1/capsules").json
            return res[0]["id"]

    ################################################
    #### Testing GET /capsules/{cId}/owners
    ################################################
    # Response 400:
    def test_get_bad_request(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            testapp.get("/v1/capsules/" + self._bad_capsule_id + "/owners", status=400)

    # Response 401:
    def test_get_with_no_token(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        testapp.get("/v1/capsules/" + capsule_id + "/owners", status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_user):

            res = testapp.get("/v1/capsules/" + capsule_id + "/owners", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_get_bad_capsule_id(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            res = testapp.get("/v1/capsules/" + self._unexisting_capsule_id + "/owners", status=404).json
            assert "The requested capsule '" + self._unexisting_capsule_id + "' has not been found." in res["detail"]

    # Response 200:
    def test_get(self, testapp, db):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            res = testapp.get("/v1/capsules/" + capsule_id + "/owners", status=200).json
            assert dict_contains(res, self._owners_output)
    ################################################

    ################################################
    #### Testing PATCH /capsules/{cId}/owners
    ################################################
    # Response 400:
    def test_patch_bad_request_wrong_capsule_id(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):
            testapp.patch_json("/v1/capsules/" + self._bad_capsule_id + "/owners", self._owners_input, status=400)

    def test_patch_bad_request_wrong_input(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            res = testapp.patch_json("/v1/capsules/" + capsule_id + "/owners", self._bad_owner_input, status=400).json
            print(res)
            assert "The key newOwner is required." in res["detail"]

    # Response 401:
    def test_patch_unauthorized(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        testapp.patch_json("/v1/capsules/" + capsule_id + "/owners", self._owners_input, status=401)

    # Response 403:
    def test_patch_forbidden(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_user):

            res = testapp.patch_json("/v1/capsules/" + capsule_id + "/owners", self._owners_input, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_patch_not_found_capsule_id(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            testapp.patch_json("/v1/capsules/" + self._unexisting_capsule_id + "/owners", self._owners_input, status=404)

    def test_patch_not_found_owner(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak", side_effect=KeycloakUserNotFound("tutu3")):

            testapp.patch_json("/v1/capsules/" + capsule_id + "/owners", self._owners_input, status=404)

    # Response 409: TODO => is it a real conflict ?
    def test_patch_conflict(self,testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            new_owner = {
                "newOwner": self._owners_output[0]["name"]
            }

            testapp.patch_json("/v1/capsules/" + capsule_id + "/owners", new_owner, status=409)

    # Response 200:
    def test_patch(self,testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak"):

            res = testapp.patch_json("/v1/capsules/" + capsule_id + "/owners", self._owners_input, status=200).json
            assert self._owners_input["newOwner"] in res["owners"]
    ################################################

    ################################################
    #### Testing DELETE /capsules/{cId}/owners/uId
    ################################################
    # Response 400:
    def test_delete_bad_request_wrong_capsule_id(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            testapp.delete("/v1/capsules/" + self._bad_capsule_id + "/owners/whatever", status=400)

    # Response 401:
    def test_delete_unauthorized(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        testapp.delete("/v1/capsules/" + capsule_id + "/owners/" + self._owners_output[0]["name"], status=401)

    # Response 403:
    def test_delete_forbidden(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_user):

            res = testapp.delete("/v1/capsules/" + capsule_id + "/owners/" + self._owners_output[0]["name"], status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_delete_not_found_capsule_id(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            testapp.delete("/v1/capsules/" + self._unexisting_capsule_id + "/owners/" + self._owners_output[1]["name"], status=404)

    def test_delete_not_found_owner(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak", side_effect=KeycloakUserNotFound("tutu3")):

            testapp.delete("/v1/capsules/" + capsule_id + "/owners/" + self._owners_input["newOwner"], status=404)

    # Response 409:
    def test_delete_conflict(self,testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            testapp.delete("/v1/capsules/" + capsule_id + "/owners/" + self._foobar.name, status=409)

    # Response 204:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete(self, testapp):
        capsule_id = TestCapsuleOwners.get_capsule_id(self, testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak"):

            # Delete owner
            testapp.delete("/v1/capsules/" + capsule_id + "/owners/" + self._owners_output[1]["name"], status=204)

            # Check owner is not present anymore
            res = testapp.get("/v1/capsules/" + capsule_id + "/owners", status=200).json
            assert self._owners_output[1]["name"] not in res
    ################################################