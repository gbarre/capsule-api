from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import dict_contains
from unittest.mock import patch
import tests.foodata as foodata
from werkzeug.exceptions import Forbidden
from models import RoleEnum, User
import pytest


class TestRuntimes:
    _runtime_input = {
        "name": "Runtime Test",
        "runtime_type": "webapp",
        "desc": "test runtime",
        "fam": "test",
    }

    _runtime_output = foodata.runtime1

    _foobar = User(name="toto1", role=RoleEnum.user)
    _fake_admin = User(name="fake_user", role=RoleEnum.admin)
    _fake_superadmin = User(name="fake_user", role=RoleEnum.superadmin)

    @classmethod
    def get_runtime_id(cls, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=cls._foobar):

            # Get the runtime id
            res = testapp.get("/v1/runtimes", status=200).json
            return res[0]["id"]

    #################################
    #### Testing GET /runtimes
    #################################
    # Response 200:
    def test_get(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            res = testapp.get('/v1/runtimes', status=200).json
            assert dict_contains(res[0], self._runtime_output)

    # Response 401:
    def test_get_with_no_token(self, testapp):
        testapp.get('/v1/runtimes', status=401)
    #################################

    #################################
    #### Testing POST /runtimes
    #################################
    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            res = testapp.post_json('/v1/runtimes', self._runtime_input, status=201).json
            assert dict_contains(res, self._runtime_input)

    # Response 400:
    def test_create_bad_json_missing_name(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            temp_input = dict(self._runtime_input)
            temp_input.pop("name")
            res = testapp.post_json("/v1/runtimes", temp_input, status=400).json
            assert "'name' is a required property" in res["detail"]

    def test_create_bad_json_missing_runtime_type(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            temp_input = dict(self._runtime_input)
            temp_input.pop("runtime_type")
            res = testapp.post_json("/v1/runtimes", temp_input, status=400).json
            assert "'runtime_type' is a required property" in res["detail"]

    def test_create_bad_json_missing_description(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            temp_input = dict(self._runtime_input)
            temp_input.pop("desc")
            res = testapp.post_json("/v1/runtimes", temp_input, status=400).json
            assert "'desc' is a required property" in res["detail"]

    def test_create_bad_json_missing_runtime_familly(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            temp_input = dict(self._runtime_input)
            temp_input.pop("fam")
            res = testapp.post_json("/v1/runtimes", temp_input, status=400).json
            assert "'fam' is a required property" in res["detail"]

    # Response 401:
    def test_create_with_no_token(self, testapp):
        testapp.post_json('/v1/runtimes', self._runtime_input, status=401)

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            testapp.post_json("/v1/runtimes", self._runtime_input, status=403).json
    #################################

    #################################
    #### Testing GET /runtimes/rId
    #################################
    # Response 200:
    def test_get_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            # Get the runtime id
            res = testapp.get("/v1/runtimes", status=200).json
            runtime_id = res[0]["id"]

            # Get this runtime by id
            runtime = testapp.get("/v1/runtimes/" + runtime_id, status=200).json
            assert dict_contains(runtime, self._runtime_output)

    # Response 401:
    def test_get_runtime_unauthenticated(self, testapp, db):
        runtime_id = TestRuntimes.get_runtime_id(testapp)
        # Get this runtime by id
        testapp.get("/v1/runtimes/" + runtime_id, status=401)

    # Response 404:
    def test_get_bad_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._foobar):

            # Get the runtime id
            res = testapp.get("/v1/runtimes/ffffffff-ffff-ffff-ffff-ffffffffffff", status=404).json
            assert "The requested runtime 'ffffffff-ffff-ffff-ffff-ffffffffffff' has not been found." in res["detail"]
    #################################

    #################################
    #### Testing PUT /runtimes/rId
    #################################
    # Response 200:
    def test_update_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            # Get the runtime id
            res = testapp.get("/v1/runtimes", status=200).json
            runtime_id = res[0]["id"]
            # Update this runtime by id
            temp_runtime = dict(self._runtime_input)
            temp_runtime["name"] = "New runtime"
            runtime = testapp.put_json("/v1/runtimes/" + runtime_id, temp_runtime, status=200).json
            assert dict_contains(runtime, temp_runtime)

    # Response 201:
    def test_update_unexisting_runtime(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            res = testapp.put_json('/v1/runtimes/ffffffff-ffff-ffff-ffff-ffffffffffff', self._runtime_input, status=201).json
            assert dict_contains(res, self._runtime_input)

    # Response 400:
    def test_update_bad_runtime(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            res = testapp.put_json('/v1/runtimes/XYZ', self._runtime_input, status=400).json
            assert "The browser (or proxy) sent a request that this server could not understand." in res["detail"]

    # Response 401:
    def test_update_unauthenticated(self, testapp, db):
        runtime_id = TestRuntimes.get_runtime_id(testapp)
        # Delete this runtime
        testapp.put_json("/v1/runtimes/" + runtime_id, self._runtime_input, status=401)


    # Response 403:
    def test_update_insufficient_rights(self, testapp, db):
        runtime_id = TestRuntimes.get_runtime_id(testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this runtime
            res = testapp.put_json("/v1/runtimes/" + runtime_id, self._runtime_input, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]
    #################################

    #################################
    #### Testing DELETE /runtimes/rId
    #################################

    # Response 204
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=self._fake_superadmin):

            # Get the runtime id
            res = testapp.get("/v1/runtimes", status=200).json
            runtime_id = res[0]["id"]
            # Delete this runtime
            testapp.delete("/v1/runtimes/" + runtime_id, status=204)

            # No more runtime
            res = testapp.get("/v1/runtimes/" + runtime_id, status=404).json
            assert "The requested runtime '" + runtime_id + "' has not been found." in res["detail"]

    # Response 401
    def test_delete_unauthenticated(self, testapp, db):
        runtime_id = TestRuntimes.get_runtime_id(testapp)
        # Delete this runtime
        testapp.delete("/v1/runtimes/" + runtime_id, status=401)

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        runtime_id = TestRuntimes.get_runtime_id(testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this runtime
            res = testapp.delete("/v1/runtimes/" + runtime_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]
    #################################