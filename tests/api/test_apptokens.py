from tests.utils import api_version, bad_id, unexisting_id, dict_contains
from app import oidc
from unittest.mock import patch
from models import apptoken_schema
import json
import pytest


class TestAppToken:

    _apptoken_input = {"app": "My very super app"}

    _apptoken_bad_app_input = {"app": ""}

    _apptoken_bad_input = {"give_me_a_token": "My app"}

    @staticmethod
    def build_output(db):
        return [json.loads(apptoken_schema.dumps(db.apptoken1))]

    ################################################
    # Testing POST /apptokens
    ################################################
    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(
                api_version + "/apptokens",
                self._apptoken_input,
                status=201
            ).json
            assert dict_contains(res, self._apptoken_input)

    # Response 400:
    def test_create_bad_input(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(
                api_version + "/apptokens",
                self._apptoken_bad_input,
                status=400
            ).json
            assert "'app' is a required property" in res["error_description"]

    def test_create_bad_app_input(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(
                api_version + "/apptokens",
                self._apptoken_bad_app_input,
                status=400
            ).json
            msg = "'app' length must be 5 at least."
            assert msg in res["error_description"]

    # Response 401:
    def test_create_unauthenticated(self, testapp, db):
        testapp.post_json(
            api_version + "/apptokens",
            self._apptoken_input,
            status=401
        )

    ################################################

    ################################################
    # Testing GET /apptokens
    ################################################
    # Response 200:
    def test_get_all(self, testapp, db):
        apptokens_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.get(
                api_version + "/apptokens",
                status=200
            ).json
            assert dict_contains(apptokens_output, res)

    def test_get(self, testapp, db):
        apptokens_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            res = testapp.get(
                api_version + "/apptokens",
                status=200
            ).json
            assert dict_contains(apptokens_output[0], res[0])

    # Response 400:
    def test_get_bad_request(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                api_version + "/apptokens?filters[foo]=bar",
                status=400
            )

    # Response 401:
    def test_get_unauthenticated(self, testapp, db):
        testapp.get(
            api_version + "/apptokens",
            status=401
        )

    # Response 404:
    def test_get_not_found(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                api_version + "/apptokens",
                status=404
            )

    ################################################

    ################################################
    # Testing DELETE /apptokens/{tId}
    ################################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_apptoken(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            # Get apptoken id
            apptoken_id = str(db.apptoken1.id)

            # Delete this apptoken
            testapp.delete(
                api_version + "/apptokens/" + apptoken_id,
                status=204
            )

            # Ensure this apptoken is not present anymore
            testapp.get(
                api_version + "/apptokens" + apptoken_id,
                status=404
            )

    # Response 400:
    def test_delete_bad_apptoken(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.delete(
                api_version + '/apptokens/' + bad_id,
                status=400
            )

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        apptoken_id = str(db.apptoken1.id)

        # Delete this apptoken
        testapp.delete(
            api_version + "/apptokens/" + apptoken_id,
            status=401
        )

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        apptoken_id = str(db.apptoken1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Delete this apptoken
            testapp.delete(
                api_version + "/apptokens/" + apptoken_id,
                status=403
            )

    # Response 404:
    def test_delete_unexisting_apptoken(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.delete(
                api_version + '/apptokens/' + unexisting_id,
                status=404
            )
    #################################

    #################################
    # Use apptoken
    #################################
    def test_apptoken_usage(self, testapp, db):
        token = "KDCte1raIV-ItPQf-sf_tapY4q-kLmvlcJ9yUKPlqbo"  # from foodata
        headers = {'Authorization': f'Bearer: {token}'}
        testapp.get(
            api_version + '/apptokens',
            headers=headers,
            status=200
        )
