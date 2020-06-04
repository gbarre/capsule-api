from tests.utils import *
from models import webapp_schema
import json
import ast
from werkzeug.exceptions import Forbidden
import pytest

class TestCapsuleWebapp:

    _webapp_input = {
            "env": {
                "HTTP_PROXY": "http://example.com:3128/",
                "HTTPS_PROXY": "https://example.com:3128/",
            },
            "fqdns": [
                {
                    "name": "main.example.com",
                    "alias": False
                },
                {
                    "name": "sub.secondary.my-example.com",
                    "alias": True
                },
            ],
            "opts" : [
                {
                    "field_name": "worker",
                    "tag": "PHP",
                    "value": "42"
                },
            ],
            "tls_redirect_https": False,
            #"runtime_id": "..."
        }

    # Build webapp with correct runtime_id
    @classmethod
    def build_webapp(cls, db):
        runtime_id = str(db.runtime1.id)
        new_webapp = dict(cls._webapp_input)
        new_webapp["runtime_id"] = runtime_id
        return new_webapp

    @staticmethod
    def build_output(db):
        webapp = json.loads(webapp_schema.dumps(db.webapp1).data)
        webapp["env"] = ast.literal_eval(webapp["env"])
        return webapp

    ################################################
    #### Testing POST /capsules/{cId}/webapp
    ################################################
    # Response 400:
    def test_create_bad_capsule_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(api_version + '/capsules/' + bad_id + '/webapp', self._webapp_input, status=400)

    def test_create_missing_runtime_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            capsule_id = str(db.capsule1.id)
            testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', self._webapp_input, status=400)

    def test_create_missing_fqdns(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            capsule_id = str(db.capsule1.id)
            # Build webapp with correct runtime_id but no fqdns
            new_webapp = self.build_webapp(db)
            new_webapp.pop("fqdns")

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=400)

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_webapp = self.build_webapp(db)

        testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=401)

    # Response 403:
    def test_create_bad_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):
            capsule_id = str(db.capsule1.id)
            new_webapp = self.build_webapp(db)

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=403)

    # Response 409:
    def test_create_conflict(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):
            capsule_id = str(db.capsule1.id)
            new_webapp = self.build_webapp(db)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=409).json
            assert "This capsule already has a webapp." in res["detail"]

    # Response 201:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):
            capsule_id = str(db.capsule1.id)

            # Remove existing webapp
            testapp.delete(api_version + '/capsules/' + capsule_id + '/webapp', status=204)

            # Create webapp
            new_webapp = self.build_webapp(db)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=201).json
            assert dict_contains(res, new_webapp)
    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/webapp
    ################################################
    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_get_not_found(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Remove existing webapp
            testapp.delete(api_version + '/capsules/' + capsule_id + '/webapp', status=204)

            testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=404)

    # Response 200:
    def test_get(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        webapp_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=200).json
            assert dict_contains(res, webapp_output)
    ################################################

    ################################################
    #### Testing PUT /capsules/{cId}/webapp
    ################################################
    # Response 200:
    def test_update(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        runtime_id = str(db.runtime1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp["fqdns"] = [
                {
                    "alias": False,
                    "name": "domain.test.tld",
                }
            ]
            current_webapp["tls_redirect_https"] = False

            res = testapp.put_json(api_version + '/capsules/' + capsule_id + '/webapp', current_webapp, status=200).json
            assert dict_contains(res, current_webapp)

    # Response 201:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_update_unexisting_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Remove existing webapp
            testapp.delete(api_version + '/capsules/' + capsule_id + '/webapp', status=204)

            new_webapp = self.build_webapp(db)

            res = testapp.put_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=201).json
            assert dict_contains(res, self._webapp_input)

    # Response 401:
    def test_update_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_webapp = self.build_webapp(db)
        testapp.put_json(api_version + "/capsules/" + capsule_id + '/webapp', new_webapp, status=401)

    # Response 400:
    def test_update_bad_request(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(api_version + "/capsules/" + bad_id + '/webapp', self._webapp_input, status=400)

    # Response 403:
    def test_update_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            new_webapp = self.build_webapp(db)

            res = testapp.put_json(api_version + "/capsules/" + capsule_id + "/webapp", new_webapp, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    ################################################

    ################################################
    #### Testing DELETE /capsules/{cId}/webapp
    ################################################
    # Response 204:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Delete webapp
            testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=204)

            # Check webapp is not present anymore
            testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=404)

    # Response 401:
    def test_delete_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=401)

    # Response 403:
    def test_delete_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_delete_not_found_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(api_version + "/capsules/" + unexisting_id + "/webapp", status=404)

    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_no_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1), \
            patch("api.capsules.owners.check_owners_on_keycloak"):

            # Delete webapp
            testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=204)

            # Try to delete an unexisting webapp
            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=404).json
            assert "This capsule does not have webapp." in res["detail"]
    ################################################

