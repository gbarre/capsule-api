from tests.utils import api_version, dict_contains, unexisting_id, bad_id
from app import oidc
from models import addon_schema
from unittest.mock import patch
import json
from werkzeug.exceptions import Forbidden
import pytest
from nats import NATS


class TestCapsuleAddons:

    _addon_input = {
        "description": "Un redis sur la capsule",
        "env": {
            "REDIS_SERVER_HOST": "my-redis-host",
            "REDIS_SERVER_PORT": "6379",
        },
        "name": "redis-1",
        "opts": [
            {
                "tag": "SQL",
                "field_name": "my.cnf",
                "value": "c3VwZXJmaWxl",
            },
        ],
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
        return [addon]

    # Create a temp capsule
    @staticmethod
    def build_temp_capsule(db, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            _capsule_input = {
                "name": "test-capsule",
                "owners": [
                    "user1",
                ],
            }

            temp_capsule = testapp.post_json(
                api_version + "/capsules",
                _capsule_input,
                status=201
            ).json
        return temp_capsule

    ################################################
    # Testing POST /capsules/{cId}/addons
    ################################################
    # Response 201:
    def test_create(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_present") as publish_method:

            # Create addon
            new_addon = self.build_addon(db)

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                new_addon,
                status=201
            ).json
            publish_method.assert_called_once
            assert dict_contains(res, new_addon)

    def test_create_without_opts(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_present") as publish_method:

            # Create addon
            new_addon = self.build_addon(db)
            new_addon.pop('opts')

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                new_addon,
                status=201
            ).json
            publish_method.assert_called_once
            assert dict_contains(res, new_addon)

    # Response 400:
    def test_create_bad_capsule_id(self, testapp, db):
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(
                api_version + '/capsules/' + bad_id + '/addons',
                addon_input,
                status=400
            )

    def test_create_missing_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                self._addon_input,
                status=400
            ).json
            msg = "'runtime_id' is a required property"
            assert msg in res["error_description"]

    def test_create_unexisting_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            addon = dict(self._addon_input)
            addon["runtime_id"] = unexisting_id

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                addon,
                status=400
            ).json
            msg = f"The runtime_id '{unexisting_id}' does not exist."
            assert msg in res["error_description"]

    def test_create_bad_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            runtime_id = str(db.runtime1.id)  # webapp runtime id
            addon = dict(self._addon_input)
            addon["runtime_id"] = runtime_id

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                addon,
                status=400
            ).json
            msg = f"The runtime_id '{runtime_id}' has not type 'addon'."
            assert msg in res["error_description"]

    def test_create_missing_name(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(db)
            new_addon.pop("name")

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                new_addon,
                status=400
            ).json
            assert "'name' is a required property" in res["error_description"]

    def test_create_bad_name(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(db)
            new_addon['name'] = "My Addon - with bad characters,"\
                                " and also more than 64 chars, this is stupid!"

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                new_addon,
                status=400
            ).json
            assert "invalid" in res["error_description"]

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_addon = self.build_addon(db)

        testapp.post_json(
            api_version + '/capsules/' + capsule_id + '/addons',
            new_addon,
            status=401
        )

    # Response 403:
    def test_create_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_addon = self.build_addon(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                new_addon,
                status=403
            )
    ################################################

    ################################################
    # Testing GET /capsules/{cId}/addons
    ################################################
    # Response 200:
    def test_get_all(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + capsule_id + "/addons",
                status=200
            ).json
            assert dict_contains(res, addon_output)

    # Response 400:
    def test_get_bad_request(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                f"{api_version}/capsules/{capsule_id}/addons?filters[foo]=bar",
                status=400,
            )

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.get(
            api_version + "/capsules/" + capsule_id + "/addons",
            status=401
        )

    # Response 403:
    def test_get_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                api_version + "/capsules/" + capsule_id + "/addons",
                status=403
            )

    # Response 404:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_get_not_found(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_absent") as publish_method:

            # Remove all existing addons
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=204
            )
            publish_method.assert_called_once

            testapp.get(
                api_version + "/capsules/" + capsule_id + "/addons",
                status=404
            )
    ################################################

    ################################################
    # Testing PUT /capsules/{cId}/addons/{aId}
    ################################################
    # Response 200:
    def test_update(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_present") as publish_method:

            new_addon = self.build_addon(db)

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=200
            ).json
            publish_method.assert_called_once
            dict_contains(res, new_addon)

    def test_update_without_opts(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_present") as publish_method:

            new_addon = self.build_addon(db)
            new_addon.pop('opts')

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=200
            ).json
            publish_method.assert_called_once
            dict_contains(res, new_addon)

    # Response 400:
    def test_update_bad_capsule_id(self, testapp, db):
        addon_id = str(db.addon1)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(
                api_version + '/capsules/' + bad_id + '/addons/' + addon_id,
                addon_input,
                status=400
            )

    def test_update_bad_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{bad_id}",
                addon_input,
                status=400
            )

    def test_update_missing_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                self._addon_input,
                status=400
            ).json
            msg = "'runtime_id' is a required property"
            assert msg in res["error_description"]

    def test_update_invalid_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            new_addon = self.build_addon(db)
            new_addon['runtime_id'] = bad_id
            from pprint import pprint
            pprint(new_addon)

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res["error_description"]

    def test_update_unexisting_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            new_addon = self.build_addon(db)
            new_addon['runtime_id'] = unexisting_id

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=400
            ).json
            msg = f"The runtime_id '{unexisting_id}' does not exist."
            assert msg in res["error_description"]

    def test_update_with_webapp_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            new_addon = self.build_addon(db)
            new_addon['runtime_id'] = str(db.runtime1.id)

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=400
            ).json
            assert "Changing runtime familly" in res["error_description"]

    def test_update_missing_name(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(db)
            new_addon.pop("name")

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=400
            ).json
            assert "'name' is a required property" in res["error_description"]

    def test_update_bad_name(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Build addon with correct runtime_id but no name
            new_addon = self.build_addon(db)
            new_addon['name'] = "Bad addon Name"

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=400
            ).json
            assert "invalid: only lowercase" in res["error_description"]

    # Response 401:
    def test_update_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1)
        new_addon = self.build_addon(db)
        testapp.put_json(
            f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
            new_addon,
            status=401
        )

    # Response 403:
    def test_update_insufficient_rights(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1)
        new_addon = self.build_addon(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=403
            )

    def test_update_addon_forbidden(self, testapp, db):
        temp_capsule = self.build_temp_capsule(db, testapp)
        capsule_id = temp_capsule['id']
        addon_id = str(db.addon1.id)
        new_addon = self.build_addon(db)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                new_addon,
                status=403
            )

    # Response 404:
    def test_update_unexisting_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.put_json(
                f"{api_version}/capsules/{capsule_id}/addons/{unexisting_id}",
                addon_input,
                status=404
            ).json
            msg = f"The requested addon '{unexisting_id}' has not been found."
            assert msg in res["error_description"]

    def test_update_unexisting_capsule_id(self, testapp, db):
        addon_id = str(db.addon1.id)
        addon_input = self.build_addon(db)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.put_json(
                f"{api_version}/capsules/{unexisting_id}/addons/{addon_id}",
                addon_input,
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res["error_description"]
    ################################################

    ################################################
    # Testing GET /capsules/{cId}/addons/{aId}
    ################################################
    # Response 200:
    def test_get(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        addon_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=200
            ).json
            assert dict_contains(res, addon_output[0])

    # Response 400:
    def test_get_addon_bad_request(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/addons/{bad_id}",
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res["error_description"]

    # Response 401:
    def test_get_addon_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        testapp.get(
            f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
            status=401
        )

    # Response 403:
    def test_get_addon_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=403
            )

    def test_get_addon_forbidden(self, testapp, db):
        temp_capsule = self.build_temp_capsule(db, testapp)
        capsule_id = temp_capsule['id']
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=403
            )

    # Response 404:
    def test_get_unexisting_capsule_id(self, testapp, db):
        addon_id = str(db.addon1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{unexisting_id}/addons/{addon_id}",
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res["error_description"]

    def test_get_unexisting_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/addons/{unexisting_id}",
                status=404
            ).json
            msg = f"The requested addon '{unexisting_id}' has not been found."
            assert msg in res["error_description"]
    ################################################

    ################################################
    # Testing DELETE /capsules/{cId}/addons/{aId}
    ################################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_absent") as publish_method:

            # Delete addon
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=204
            )
            publish_method.assert_called_once

            # Check addon is not present anymore
            testapp.get(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=404
            )

    # Response 401:
    def test_delete_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)
        testapp.delete(
            f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
            status=401
        )

    # Response 403:
    def test_delete_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=403
            )

    def test_delete_addon_forbidden(self, testapp, db):
        temp_capsule = self.build_temp_capsule(db, testapp)
        capsule_id = temp_capsule['id']
        addon_id = str(db.addon1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/addons/{addon_id}",
                status=403
            )

    # Response 404:
    def test_delete_unexisting_capsule_id(self, testapp, db):
        addon_id = str(db.addon1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.delete(
                f"{api_version}/capsules/{unexisting_id}/addons/{addon_id}",
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res["error_description"]

    def test_delete_unexisting_addon_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.delete(
                f"{api_version}/capsules/{capsule_id}/addons/{unexisting_id}",
                status=404
            ).json
            msg = "This addon is not present in this capsule"
            assert msg in res["error_description"]
    ################################################
