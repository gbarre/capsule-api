from app import oidc
from tests.utils import *
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
from models import RoleEnum, apptokens_schema
# import json
import pytest

class TestAppToken:

    _apptoken_input = {"app": "My very super app"}

    _apptoken_bad_app_input = {"app": ""}

    _apptoken_bad_input = {"give_me_a_token": "My app"}

    @staticmethod
    def build_output(db):
        apptoken = db.apptoken1
        return apptokens_schema.dumps(db.apptoken1).data

    ################################################
    #### Testing POST /apptokens
    ################################################
    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(api_version + "/apptokens", self._apptoken_input, status=201).json
            assert dict_contains(res, self._apptoken_input)

    # Response 400:
    def test_create_bad_input(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(api_version + "/apptokens", self._apptoken_bad_input, status=400).json
            assert "'app' is a required property" in res["detail"]

    def test_create_bad_app_input(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(api_version + "/apptokens", self._apptoken_bad_app_input, status=400).json
            assert "'app' length must be 5 at least." in res["detail"]

    # Response 401:
    def test_create_unauthenticated(self, testapp, db):
        testapp.post_json(api_version + "/apptokens", self._apptoken_input, status=401)

    ################################################

    ################################################
    #### Testing GET /apptokens
    ################################################
    # Response 200:
    def test_get_all(self, testapp, db):
        apptokens_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.get(api_version + "/apptokens", status=200).json
            assert dict_contains(res, apptokens_output)

    def test_get(self, testapp, db):
        apptokens_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            res = testapp.get(api_version + "/apptokens", status=200).json
            assert dict_contains(res[0], apptokens_output[0])

    # Response 401:
    def test_get_unauthenticated(self, testapp, db):
        testapp.get(api_version + "/apptokens", status=401)

    # Response 404:
    def test_get_not_found(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.get(api_version + "/apptokens", status=404)

    ################################################

    ################################################
    #### Testing DELETE /apptokens/{tId}
    ################################################
    # Response 204:@pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_apptoken(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            # Get apptoken id
            apptoken_id = str(db.apptoken1.id)

            # Delete this apptoken
            testapp.delete(api_version + "/apptokens/" + apptoken_id, status=204)

            # Ensure this apptoken is not present anymore
            testapp.get(api_version + "/apptokens" + apptoken_id, status=404)

    # Response 400:
    def test_delete_bad_apptoken(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            res = testapp.delete(api_version + '/apptokens/' + bad_id, status=400).json
            assert "The browser (or proxy) sent a request that this server could not understand." in res["detail"]

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        apptoken_id = str(db.apptoken1.id)

        # Delete this apptoken
        testapp.delete(api_version + "/apptokens/" + apptoken_id, status=401)

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        apptoken_id = str(db.apptoken1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Delete this apptoken
            res = testapp.delete(api_version + "/apptokens/" + apptoken_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]
    #################################