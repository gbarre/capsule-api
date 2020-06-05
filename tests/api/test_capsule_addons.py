from tests.utils import *
from models import addon_schema
import json
import ast
from werkzeug.exceptions import Forbidden
import pytest
from pprint import pprint

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

    # Build addon with correct runtime_id
    @classmethod
    def build_addon(cls, db):
        runtime_id = str(db.runtime2.id)
        addon = dict(cls._addon_input)
        addon["runtime_id"] = runtime_id
        return addon

    @staticmethod
    def build_output(db):
        addon = json.loads(addon_schema.dumps(db.addon1).data)
        addon["env"] = ast.literal_eval(addon["env"])
        return addon

    ################################################
    #### Testing POST /capsules/{cId}/addon
    ################################################
    # Response 400:
    def test_create_bad_capsule_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(api_version + '/capsules/' + bad_id + '/addons', self._addon_input, status=400)

    def test_create_missing_runtime_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):
            capsule_id = str(db.capsule1.id)

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', self._addon_input, status=400)

    def test_create_missing_name(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):
            capsule_id = str(db.capsule1.id)

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(db)
            new_addon.pop("name")

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=400)

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_addon = self.build_addon(db)

        testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=401)

    # Response 403:
    def test_create_bad_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):
            capsule_id = str(db.capsule1.id)
            new_addon = self.build_addon(db)

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=403)

    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):
            capsule_id = str(db.capsule1.id)

            # Create addon
            new_addon = self.build_addon(db)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=201).json
            assert dict_contains(res, new_addon)
    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/addon
    ################################################
    # Response 404:
    # TODO : implement code before uncomment
    # @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    # def test_get_not_found(self, testapp, db):
    #     capsule_id = str(db.capsule1.id)

    #     with patch.object(oidc, "validate_token", return_value=True), \
    #         patch("utils.check_user_role", return_value=db.user1):

    #         # Remove all existing addons
    #         testapp.delete(api_version + '/capsules/' + capsule_id + '/addons/' + str(db.addon1.id), status=204)

    #         testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=404)

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=403).json
            assert "You don't have the permission to access the requested resource." in res["error_description"]

    # Response 200:
    # TODO : implement code before uncomment
    # def test_get(self, testapp, db):
    #     capsule_id = str(db.capsule1.id)
    #     addon_output = db.addon1

    #     with patch.object(oidc, "validate_token", return_value=True), \
    #         patch("utils.check_user_role", return_value=db.user1):

    #         res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=200).json
    #         assert dict_contains(res, addon_output)

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