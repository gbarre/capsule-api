from tests.utils import *
import tests.foodata as foodata
from werkzeug.exceptions import Forbidden
import pytest

class TestCapsuleAddons:

    _addon_input = {
        "description": "Un redis sur la capsule",
        "env": {
            "REDIS_SERVER_HOST": "my-redis-host",
            "REDIS_SERVER_PORT": "6379",
        },
        "name": "redis-1",
        # "runtime_id": "d4541bee-eb0d-472a-9956-6bbfd63442c0",
    }

    _addon_output = foodata.addon

    # Build addon with correct runtime_id
    @classmethod
    def build_addon(cls, testapp):
        runtime_id = get_runtime_id(testapp)
        addon = dict(cls._addon_input)
        addon["runtime_id"] = runtime_id
        return addon

    ################################################
    #### Testing POST /capsules/{cId}/addon
    ################################################
    # Response 400:
    def test_create_bad_capsule_id(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            testapp.post_json(api_version + '/capsules/' + bad_id + '/addons', self._addon_input, status=400)

    def test_create_missing_runtime_id(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', self._addon_input, status=400)

    def test_create_missing_name(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(testapp)
            new_addon.pop("name")

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=400)

    # Response 401:
    def test_create_with_no_token(self, testapp):
        capsule_id = get_capsule_id(testapp)
        new_addon = self.build_addon(testapp)

        testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=401)

    # Response 403:
    def test_create_bad_owner(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_user):
            capsule_id = get_capsule_id(testapp)
            new_addon = self.build_addon(testapp)

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=403)

    # Response 201:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_create(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):
            capsule_id = get_capsule_id(testapp)

            # Create addon
            new_addon = self.build_addon(testapp)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=201).json
            assert dict_contains(res, new_addon)
    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/addon
    ################################################
    # Response 404:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_get_not_found(self, testapp):
        capsule_id = get_capsule_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Remove all existing addons (TODO)
            #testapp.delete(api_version + '/capsules/' + capsule_id + '/addons/{aId}', status=204)

            testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=404)

    # Response 401:
    def test_get_with_no_token(self, testapp):
        capsule_id = get_capsule_id(testapp)
        testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp):
        capsule_id = get_capsule_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_user):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]

    # Response 200:
    def test_get(self, testapp):
        capsule_id = get_capsule_id(testapp)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=200).json
            assert dict_contains(res, self._addon_output)

    ################################################

    ################################################
    #### Testing PUT /capsules/{cId}/addon/{aId}
    ################################################
    # Response 400:

    # Response 401:

    # Response 403:

    # Response 404:

    # Response 200:

    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/addon/{aId}
    ################################################
    # Response 404:

    # Response 401:

    # Response 403:

    # Response 200:

    ################################################

    ################################################
    #### Testing DELETE /capsules/{cId}/addon/{aId}
    ################################################
    # Response 404:

    # Response 401:

    # Response 403:

    # Response 204:

    ################################################