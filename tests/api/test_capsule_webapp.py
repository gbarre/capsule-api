from tests.utils import *
import tests.foodata as foodata
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

    _webapp_output = foodata.webapp

    # Build webapp with correct runtime_id
    @classmethod
    def build_webapp(cls, testapp):
        runtime_id = get_runtime_id(testapp)
        new_webapp = dict(cls._webapp_input)
        new_webapp["runtime_id"] = runtime_id
        return new_webapp

    ################################################
    #### Testing POST /capsules/{cId}/webapp
    ################################################
    # Response 400:
    def test_create_bad_capsule_id(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.post_json(api_version + '/capsules/' + bad_id + '/webapp', self._webapp_input, status=400)

    def test_create_missing_runtime_id(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', self._webapp_input, status=400)

    def test_create_missing_fqdns(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            # Build webapp with correct runtime_id but no fqdns
            new_webapp = self.build_webapp(testapp)
            new_webapp.pop("fqdns")

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=400)

    # Response 401:
    def test_create_with_no_token(self, testapp):
        capsule_id = get_capsule_id(testapp)
        new_webapp = self.build_webapp(testapp)

        testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=401)

    # Response 403:
    def test_create_bad_owner(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_user):
            capsule_id = get_capsule_id(testapp)
            new_webapp = self.build_webapp(testapp)

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=403)

    # Response 409:
    def test_create_conflict(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)
            new_webapp = self.build_webapp(testapp)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=409).json
            assert "This capsule already has a webapp." in res["detail"]

    # Response 201:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_create(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            # Remove existing webapp
            testapp.delete(api_version + '/capsules/' + capsule_id + '/webapp', status=204)

            # Create webapp
            new_webapp = self.build_webapp(testapp)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=201).json
            assert dict_contains(res, new_webapp)
    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/webapp
    ################################################
    # Response 401:
    def test_get_with_no_token(self, testapp):
        capsule_id = get_capsule_id(testapp)
        testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp):
        capsule_id = get_capsule_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_user):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_get_not_found(self, testapp):
        capsule_id = get_capsule_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Remove existing webapp
            testapp.delete(api_version + '/capsules/' + capsule_id + '/webapp', status=204)

            testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=404)

    # Response 200:
    def test_get(self, testapp):
        capsule_id = get_capsule_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=200).json
            assert dict_contains(res, self._webapp_output)
    ################################################

    ################################################
    #### Testing PUT /capsules/{cId}/webapp
    ################################################
    # Response 200:
    def test_update(self, testapp):
        capsule_id = get_capsule_id(testapp)
        runtime_id = get_runtime_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            current_webapp = self._webapp_output
            current_webapp["runtime_id"] = runtime_id
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
    def test_update_unexisting_webapp(self, testapp):
        capsule_id = get_capsule_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Remove existing webapp
            testapp.delete(api_version + '/capsules/' + capsule_id + '/webapp', status=204)

            new_webapp = self.build_webapp(testapp)

            res = testapp.put_json(api_version + '/capsules/' + capsule_id + '/webapp', new_webapp, status=201).json
            assert dict_contains(res, self._webapp_input)

    # Response 401:
    def test_update_unauthenticated(self, testapp):
        capsule_id = get_capsule_id(testapp)
        new_webapp = self.build_webapp(testapp)
        testapp.put_json(api_version + "/capsules/" + capsule_id + '/webapp', new_webapp, status=401)

    # Response 400:
    def test_update_bad_request(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.put_json(api_version + "/capsules/" + bad_id + '/webapp', self._webapp_input, status=400)

    # Response 403:
    def test_update_bad_owner(self, testapp):
        capsule_id = get_capsule_id(testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_user):

            new_webapp = self.build_webapp(testapp)

            res = testapp.put_json(api_version + "/capsules/" + capsule_id + "/webapp", new_webapp, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    ################################################

    ################################################
    #### Testing DELETE /capsules/{cId}/webapp
    ################################################
    # Response 204:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete(self, testapp):
        capsule_id = get_capsule_id(testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Delete webapp
            testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=204)

            # Check webapp is not present anymore
            testapp.get(api_version + "/capsules/" + capsule_id + "/webapp", status=404)

    # Response 401:
    def test_delete_unauthorized(self, testapp):
        capsule_id = get_capsule_id(testapp)
        testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=401)

    # Response 403:
    def test_delete_bad_owner(self, testapp):
        capsule_id = get_capsule_id(testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_user):

            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 404:
    def test_delete_not_found_capsule_id(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.delete(api_version + "/capsules/" + unexisting_id + "/webapp", status=404)

    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_no_webapp(self, testapp):
        capsule_id = get_capsule_id(testapp)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar), \
            patch("api.capsules.owners.check_owners_on_keycloak"):

            # Delete webapp
            testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=204)

            # Try to delete an unexisting webapp
            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/webapp", status=404).json
            assert "This capsule does not have webapp." in res["detail"]
    ################################################

