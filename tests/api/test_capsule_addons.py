from tests.utils import *
from models import addon_schema
import json
import ast
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
        return [addon]

    ################################################
    #### Testing POST /capsules/{cId}/addons
    ################################################
    # Response 400:
    def test_create_bad_capsule_id(self, testapp, db):
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(api_version + '/capsules/' + bad_id + '/addons', addon_input, status=400)

    def test_create_missing_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', self._addon_input, status=400).json
            assert "'runtime_id' is a required property" in res["error_description"]

    def test_create_missing_name(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(db)
            new_addon.pop("name")

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=400).json
            assert "'name' is a required property" in res["error_description"]

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_addon = self.build_addon(db)

        testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=401)

    # Response 403:
    def test_create_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_addon = self.build_addon(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=403)

    # Response 201:
    def test_create(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Create addon
            new_addon = self.build_addon(db)

            res = testapp.post_json(api_version + '/capsules/' + capsule_id + '/addons', new_addon, status=201).json
            assert dict_contains(res, new_addon)
    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/addons
    ################################################
    # Response 404:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_get_not_found(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Remove all existing addons
            testapp.delete(api_version + '/capsules/' + capsule_id + '/addons/' + str(db.addon1.id), status=204)

            testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=404)

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
    def test_get_all(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons", status=200).json
            assert dict_contains(res, addon_output)

    ################################################

    ################################################
    #### Testing PUT /capsules/{cId}/addons/{aId}
    ################################################
    # Response 400:
    def test_update_bad_capsule_id(self, testapp, db):
        addon_id = str(db.addon1)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(api_version + '/capsules/' + bad_id + '/addons/' + addon_id, addon_input, status=400)

    def test_update_bad_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(api_version + '/capsules/' + capsule_id + '/addons/' + bad_id, addon_input, status=400)

    def test_update_missing_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.put_json(api_version + '/capsules/' + capsule_id + '/addons/' + addon_id, self._addon_input, status=400).json
            assert "'runtime_id' is a required property" in res["error_description"]

    def test_update_missing_name(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(db)
            new_addon.pop("name")

            res = testapp.put_json(api_version + '/capsules/' + capsule_id + '/addons/' + addon_id, new_addon, status=400).json
            assert "'name' is a required property" in res["error_description"]

    # Response 401:
    def test_update_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1)
        new_addon = self.build_addon(db)
        testapp.put_json(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, new_addon, status=401)

    # Response 403:
    def test_update_insufficient_rights(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1)
        new_addon = self.build_addon(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            res = testapp.put_json(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, new_addon, status=403).json
            assert "You don't have the permission to access the requested resource." in res["error_description"]

    # Response 404:
    def test_update_unexisting_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.put_json(api_version + '/capsules/' + capsule_id + '/addons/' + unexisting_id, addon_input, status=404).json
            assert f"The requested addon '{unexisting_id}' has not been found." in res["error_description"]


    def test_update_unexisting_capsule_id(self, testapp, db):
        addon_id = str(db.addon1.id)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.put_json(api_version + '/capsules/' + unexisting_id + '/addons/' + addon_id, addon_input, status=404).json
            assert f"The requested capsule '{unexisting_id}' has not been found." in res["error_description"]

    # Response 200:
    def test_update(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            new_addon = self.build_addon(db)

            res = testapp.put_json(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, new_addon, status=200).json
            dict_contains(res, new_addon)
    ################################################

    ################################################
    #### Testing GET /capsules/{cId}/addons/{aId}
    ################################################
    # Response 404:
    def test_get_unexisting_capsule_id(self, testapp, db):
        addon_id = str(db.addon1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(api_version + "/capsules/" + unexisting_id + "/addons/" + addon_id, status=404).json
            assert "The requested capsule '" + unexisting_id + "' has not been found." in res["error_description"]

    def test_get_unexisting_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons/" + unexisting_id, status=404).json
            assert "The requested addon '" + unexisting_id + "' has not been found." in res["error_description"]

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        testapp.get(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["error_description"]

    # Response 200:
    def test_get(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        addon_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, status=200).json
            assert dict_contains(res, addon_output[0])

    ################################################

    ################################################
    #### Testing DELETE /capsules/{cId}/addons/{aId}
    ################################################
    # Response 404:
    def test_delete_unexisting_capsule_id(self, testapp, db):
        addon_id = str(db.addon1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.delete(api_version + "/capsules/" + unexisting_id + "/addons/" + addon_id, status=404).json
            assert "The requested capsule '" + unexisting_id + "' has not been found." in res["error_description"]

    def test_delete_unexisting_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/addons/" + unexisting_id, status=404).json
            assert "This addon is not present in this capsule." in res["error_description"]

    # Response 401:
    def test_delete_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        testapp.delete(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, status=401)

    # Response 403:
    def test_delete_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user3):

            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["error_description"]

    # Response 204:
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Delete addon
            testapp.delete(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, status=204)

            # Check addon is not present anymore
            testapp.get(api_version + "/capsules/" + capsule_id + "/addons/" + addon_id, status=404)
    ################################################