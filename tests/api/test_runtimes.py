from tests.utils import api_version, bad_id, unexisting_id, dict_contains
from app import oidc
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
from models import runtime_schema
import pytest


class TestRuntimes:
    _runtime_input = {
        "name": "Runtime Test",
        "runtime_type": "addon",
        "desc": "test runtime",
        "fam": "test",
        "uri_template": {
            "pattern": "mysql://{test}:{password}@host:port/{test}",
            "variables": [
                {
                    "length": 16,
                    "name": "test",
                    "src": "capsule",
                    "unique": True
                },
                {
                    "length": 32,
                    "name": "password",
                    "src": "random",
                    "unique": False
                }
            ]
        },
        "available_opts": [
            {
                "access_level": "user",
                "tag": "SQL",
                "field_name": "minTest",
                "value_type": "integer",
                "field_description": "option description",
                "validation_rules": [
                    {
                        "type": "max",
                        "arg": "10",
                    },
                ],
            },
        ],
    }

    #################################
    # Testing GET /runtimes
    #################################
    # Response 200:
    def test_get(self, testapp, db):
        runtime_output = [
            runtime_schema.dump(db.runtime1).data,
            runtime_schema.dump(db.runtime2).data,
        ]
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + '/runtimes',
                status=200
            ).json
            assert dict_contains(res, runtime_output)

    # Response 400:
    def test_get_bad_request(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.fake_user):

            testapp.get(
                api_version + '/runtimes?filters[foo]=bar',
                status=400
            )

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        testapp.get(
            api_version + '/runtimes',
            status=401
        )

    # Response 404:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_get_not_found(self, testapp, db):
        # Delete all runtimes in db
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            for runtime in db.runtimes:
                testapp.delete(
                    api_version + "/runtimes/" + str(runtime.id),
                    status=204
                )

        # Ensure no runtime exists in db
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            res = testapp.get(
                api_version + '/runtimes',
                status=404
            ).json
            assert "No runtimes have been found." in res['error_description']
    #################################

    #################################
    # Testing POST /runtimes
    #################################
    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            res = testapp.post_json(
                api_version + '/runtimes',
                self._runtime_input,
                status=201
            ).json
            assert dict_contains(res, self._runtime_input)

    def test_create_without_options(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            new_runtime = dict(self._runtime_input)
            new_runtime.pop('available_opts')

            res = testapp.post_json(
                api_version + '/runtimes',
                new_runtime,
                status=201
            ).json
            assert dict_contains(res, new_runtime)

    def test_create_without_rules(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            new_runtime = dict(self._runtime_input)
            new_runtime['available_opts'][0].pop('validation_rules')

            res = testapp.post_json(
                api_version + '/runtimes',
                new_runtime,
                status=201
            ).json
            assert dict_contains(res, new_runtime)

    # Response 400:
    def test_create_bad_json_missing_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            temp_input = dict(self._runtime_input)
            temp_input.pop("name")
            res = testapp.post_json(
                api_version + "/runtimes",
                temp_input,
                status=400
            ).json
            assert "'name' is a required property" in res["error_description"]

    def test_create_bad_json_missing_runtime_type(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            temp_input = dict(self._runtime_input)
            temp_input.pop("runtime_type")
            res = testapp.post_json(
                api_version + "/runtimes",
                temp_input,
                status=400
            ).json
            msg = "'runtime_type' is a required property"
            assert msg in res["error_description"]

    def test_create_bad_json_missing_description(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            temp_input = dict(self._runtime_input)
            temp_input.pop("desc")
            res = testapp.post_json(
                api_version + "/runtimes",
                temp_input,
                status=400
            ).json
            assert "'desc' is a required property" in res["error_description"]

    def test_create_bad_json_missing_runtime_familly(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            temp_input = dict(self._runtime_input)
            temp_input.pop("fam")
            res = testapp.post_json(
                api_version + "/runtimes",
                temp_input,
                status=400
            ).json
            assert "'fam' is a required property" in res["error_description"]

    def test_create_uri_random_unique(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            temp_input = dict(self._runtime_input)
            temp_input.pop("runtime_type")
            res = testapp.post_json(
                api_version + "/runtimes",
                temp_input,
                status=400
            ).json
            msg = "'runtime_type' is a required property"
            assert msg in res["error_description"]

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        testapp.post_json(
            api_version + '/runtimes',
            self._runtime_input,
            status=401
        )

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            testapp.post_json(
                api_version + "/runtimes",
                self._runtime_input,
                status=403
            )
    #################################

    #################################
    # Testing GET /runtimes/rId
    #################################
    # Response 200:
    def test_get_runtime(self, testapp, db):
        runtime_output = runtime_schema.dump(db.runtime1).data
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.fake_user):

            # Get the runtime id
            runtime_id = str(db.runtime1.id)

            # Get this runtime by id
            runtime = testapp.get(
                api_version + "/runtimes/" + runtime_id, status=200).json
            assert dict_contains(runtime, runtime_output)

    # Response 400:
    def test_get_bad_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.fake_user):

            # Get the runtime id
            res = testapp.get(
                api_version + "/runtimes/" + bad_id,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res["error_description"]

    # Response 401:
    def test_get_runtime_unauthenticated(self, testapp, db):
        runtime_id = str(db.runtime1.id)
        # Get this runtime by id
        testapp.get(
            api_version + "/runtimes/" + runtime_id, status=401)

    # Response 404:
    def test_get_unexisting_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.fake_user):

            # Get the runtime id
            res = testapp.get(
                api_version + "/runtimes/" + unexisting_id,
                status=404
            ).json
            msg = f"The requested runtime '{unexisting_id}' "\
                  "has not been found."
            assert msg in res["error_description"]
    #################################

    #################################
    # Testing PUT /runtimes/rId
    #################################
    # Response 200:
    def test_update_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            # Get the runtime id
            runtime_id = str(db.runtime2.id)

            # Update this runtime by id
            temp_runtime = dict(self._runtime_input)
            temp_runtime["name"] = "New runtime"

            runtime = testapp.put_json(
                api_version + "/runtimes/" + runtime_id,
                temp_runtime,
                status=200
            ).json
            assert dict_contains(runtime, temp_runtime)

    # Response 201:
    def test_update_unexisting_runtime(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            res = testapp.put_json(
                api_version + '/runtimes/' + unexisting_id,
                self._runtime_input,
                status=201
            ).json
            assert dict_contains(res, self._runtime_input)

    # Response 400:
    def test_update_bad_runtime(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            testapp.put_json(
                api_version + '/runtimes/' + bad_id,
                self._runtime_input,
                status=400
            )

    # Response 401:
    def test_update_unauthenticated(self, testapp, db):
        runtime_id = str(db.runtime1.id)
        testapp.put_json(
            api_version + "/runtimes/" + runtime_id,
            self._runtime_input,
            status=401
        )

    # Response 403:
    def test_update_insufficient_rights(self, testapp, db):
        runtime_id = str(db.runtime1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            testapp.put_json(
                api_version + "/runtimes/" + runtime_id,
                self._runtime_input,
                status=403
            )
    #################################

    #################################
    # Testing DELETE /runtimes/rId
    #################################

    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            # Get the runtime id
            runtime_id = str(db.runtime1.id)
            # Delete this runtime
            testapp.delete(
                api_version + "/runtimes/" + runtime_id,
                status=204
            )

            # No more runtime
            res = testapp.get(
                api_version + "/runtimes/" + runtime_id,
                status=404
            ).json
            msg = f"The requested runtime '{runtime_id}' "\
                  "has not been found."
            assert msg in res["error_description"]

    # Response 400:
    def test_delete_bad_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            # Get the runtime id
            res = testapp.delete(
                api_version + "/runtimes/" + bad_id,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res["error_description"]

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        runtime_id = str(db.runtime1.id)
        # Delete this runtime
        testapp.delete(
            api_version + "/runtimes/" + runtime_id,
            status=401
        )

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        runtime_id = str(db.runtime1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this runtime
            testapp.delete(
                api_version + "/runtimes/" + runtime_id,
                status=403
            )

    # Response 404:
    def test_delete_unexisting_runtime(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.fake_user):

            # Get the runtime id
            res = testapp.delete(
                api_version + "/runtimes/" + unexisting_id,
                status=404
            ).json
            msg = f"The requested runtime '{unexisting_id}' "\
                  "has not been found."
            assert msg in res["error_description"]
    #################################
