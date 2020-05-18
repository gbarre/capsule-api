from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import dict_contains
from unittest.mock import patch
import tests.foodata as foodata
from werkzeug.exceptions import Forbidden
from models import RoleEnum


class TestCapsules:
    _capsule_input = {
        "name": "test-capsule",
        "owners": [
            "foobar",
            "barfoo",
            "toto",
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
        testapp.get("/v1/capsules", status=401)

    # Response 403: TODO

    # Response 200:
    def test_get(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True):
            res = testapp.get("/v1/capsules", status=200).json

            assert dict_contains(res[0], self._capsule_output)
    #################################

    #################################
    #### Testing POST /capsules
    #################################
    # Response 400:
    def test_create_raises_on_invalid_owner(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=('fake_user', RoleEnum.admin)), \
            patch("api.capsules.check_owners_on_keycloak", side_effect=KeycloakUserNotFound("barfoo")):

            res = testapp.post_json("/v1/capsules", self._capsule_input, status=400).json
            assert "barfoo" in res["detail"]

    def test_create_illegal_name(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=('fake_user', RoleEnum.admin)), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json("/v1/capsules", self._capsule_input_illegal, status=400).json
            assert "illegal" in res["detail"]

    def test_create_duplicated_name(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=('fake_user', RoleEnum.admin)), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json("/v1/capsules", self._capsule_output, status=400).json
            assert "already exists" in res["detail"]

    def test_create_bad_json_missing_name(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=('fake_user', RoleEnum.admin)), \
            patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("name")
            res = testapp.post_json("/v1/capsules", temp_input, status=400).json
            assert "'name' is a required property" in res["detail"]

    def test_create_bad_json_missing_owners(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=('fake_user', RoleEnum.admin)), \
            patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("owners")
            res = testapp.post_json("/v1/capsules", temp_input, status=400).json
            assert "'owners' is a required property" in res["detail"]

    # Response 401:
    def test_create_with_no_token(self, testapp):
        testapp.post_json("/v1/capsules", self._capsule_input, status=401)

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden("User has not sufficient right")):

            res = testapp.post_json("/v1/capsules", self._capsule_input, status=403).json

    # Response 201:
    def test_create(self, testapp, db):

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=('fake_user', RoleEnum.admin)), \
            patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json("/v1/capsules", self._capsule_input, status=201).json

            assert dict_contains(res, self._capsule_input)
    #################################

    # TODO: GET & DELETE capsules/cId
    #################################
    #### Testing GET /capsules/cId
    #################################
    # Response 404:


    # Response 403:


    # Response 200:


    #################################

    #################################
    #### Testing DELETE /capsules/cId
    #################################
    # Response 204:


    # Response 400:


    # Response 401:


    # Response 403:


    #################################