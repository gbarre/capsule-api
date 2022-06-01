from tests.utils import api_version, dict_contains, unexisting_id, bad_id
from app import oidc
from exceptions import KeycloakUserNotFound
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
from models import capsule_output_schema, capsule_verbose_schema
import json
import pytest
from nats import NATS


class TestCapsules:
    _capsule_input = {
        "name": "test-capsule",
        "owners": [
            "foobar",
            "barfoo",
            "toto1",
        ],
        "authorized_keys": [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVbtGe1p6vAjwizq"
            "EiO8EY5K3jyB7NoBT+gDREp6TcimUMJzsWryJampX7IqDpkC7I2/Y7"
            "oiUudVR97Q6H//IckCJetaD/yONkqzRCxCoQz+J0JWlMZsS/MmIy6B"
            "HDrLYB6KBZ4zk6exxbxcanJnz2fHahom8GE57l9khYgm3WLGi+v3of"
            "b6ZsT6BrR8eXRpb6wJ6HcghGRwWg7+M6IMqZdprvzGomc7UO3fPmQX"
            "f3KF9ZlelNCBsczD4qrYshiScVqmWmo2jePTDESWaaP3jlqz7Ekvfx"
            "ukAuTm2spohtmVs+iwxOTvEwP3o7ucfp/o7QRYPqL/OPXAN8pjzf8z"
            "Z2 toto@input",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDCVu8lOZxm+7fjM"
            "QpdNuU2HinAhWmmEtYcX9wxCcBs14GmDrDSOhZB61bq9vdzkSlV0W"
            "st711mUlEZlXh/999NL7iAy6COKYxsEmRgbCU+9k8rBsSTDcXS6MW"
            "+aJI4vnqMgVSGwBDgxZs4X2mthYhCitgbk9D3WbstAinUkhEtzQ=="
            " phpseclib-generated-key",
        ],
        "size": 'small',
        "fqdns": [
            {
                "alias": False,
                "name": "test0.nip.io",
            }
        ]
    }

    _new_patch = {
        "no_update": True,
        "comment": "A new comment for this capsule",
        "size": "small",
    }

    @staticmethod
    def build_output(db):
        return json.loads(capsule_output_schema.dumps(db.capsule1))

    @staticmethod
    def build_verbose_output(db):
        return json.loads(capsule_verbose_schema.dumps(db.capsule1))

    #################################
    # Testing GET /capsules
    #################################
    # Response 200:
    def test_get(self, testapp, db):
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules",
                status=200
            ).json
            assert dict_contains(res[0], capsule_output)

    def test_get_verbose(self, testapp, db):
        capsule_output = self.build_verbose_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules?verbose=True",
                status=200
            ).json
            assert dict_contains(res[0], capsule_output)

    # Response 400:
    def test_get_bad_request(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                api_version + "/capsules?filters[foo]=bar",
                status=400
            )

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        testapp.get(
            api_version + "/capsules",
            status=401
        )

    # Response 404:
    def test_get_no_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                api_version + "/capsules",
                status=404
            )
    #################################

    #################################
    # Testing POST /capsules
    #################################
    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=201
            ).json

            res.pop('authorized_keys')
            clean_input = dict(self._capsule_input)
            clean_input.pop('authorized_keys')

            assert dict_contains(res, clean_input)

    # Response 400:
    def test_create_raises_on_invalid_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch(
                 "api.capsules.check_owners_on_keycloak",
                 side_effect=KeycloakUserNotFound("barfoo")):

            res = testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=400
            ).json
            assert "barfoo" in res["error_description"]

    def test_create_too_long_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            capsule_input_illegal = {
                "name": "1 Capsule with_illegal charactères",
                "owners": [
                    "foobar"
                ]
            }
            res = testapp.post_json(
                api_version + "/capsules",
                capsule_input_illegal,
                status=400
            ).json
            msg = 'is invalid: only lowercase alphanumeric characters '\
                  'or "-" are allowed, the first and the last characters '\
                  'must be alphanumeric, the name must have at '\
                  'least 2 characters and less than 64 characters.'
            assert msg in res["error_description"]

    def test_create_illegal_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            capsule_input_illegal = {
                "name": "1 Capsule with_illegal charactères",
                "owners": [
                    "foobar"
                ]
            }
            res = testapp.post_json(
                api_version + "/capsules",
                capsule_input_illegal,
                status=400
            ).json
            assert "illegal" in res["error_description"]

    def test_create_duplicated_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            # Create first caps
            testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=201
            ).json

            # Atempt to recreate
            temp_input = dict(self._capsule_input)
            temp_input['fqdns'] = [  # Avoid exeption on fqdns
                {
                    'alias': False,
                    'name': 'test1.nip.io',
                },
            ]
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=400
            ).json
            assert "already exists" in res["error_description"]

    def test_create_bad_json_missing_name(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("name")
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=400
            ).json
            assert "'name' is a required property" in res["error_description"]

    def test_create_bad_json_missing_owners(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input.pop("owners")
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=400
            ).json
            msg = "'owners' is a required property"
            assert msg in res["error_description"]

    def test_create_repeat_fqdn(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input['fqdns'] = [
                {
                    "alias": False,
                    "name": "test1.fr",
                },
                {
                    "alias": False,
                    "name": "test1.fr",
                },
            ]
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=400
            ).json
            msg = "Repetitions are not allowed for FQDNs"
            assert msg in res["error_description"]

    def test_create_already_exist_fqdn(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input['fqdns'] = [
                {
                    "alias": False,
                    "name": "main.fqdn.ac-versailles.fr",
                },
            ]
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=400
            ).json
            msg = "already exists."
            assert msg in res["error_description"]

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        testapp.post_json(
            api_version + "/capsules",
            self._capsule_input,
            status=401
        )

    # Response 402:
    def test_create_payment_required(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            temp_input = dict(self._capsule_input)
            temp_input['size'] = 'xlarge'
            res = testapp.post_json(
                api_version + "/capsules",
                temp_input,
                status=402
            ).json

            msg = 'Please set a lower size for this capsule or prepare '
            assert msg in res["error_description"]

    # Response 403:
    def test_create_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch(
                 "utils.check_user_role",
                 side_effect=Forbidden("User has not sufficient right")):

            testapp.post_json(
                api_version + "/capsules",
                self._capsule_input,
                status=403
            )
    #################################

    #################################
    # Testing GET /capsules/cId
    #################################
    # Response 200:
    def test_get_capsule(self, testapp, db):
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Get this capsule by id
            capsule = testapp.get(
                api_version + "/capsules/" + capsule_id,
                status=200
            ).json
            assert dict_contains(capsule, capsule_output)

    def test_get_capsule_verbose(self, testapp, db):
        capsule_output = self.build_verbose_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Get this capsule by id
            capsule = testapp.get(
                api_version + "/capsules/" + capsule_id + '?verbose=True',
                status=200,
            ).json
            assert dict_contains(capsule, capsule_output)

    # Response 400:
    def test_get_capsule_bad_request(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + bad_id,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    # Response 403:
    def test_get_capsule_raise_bad_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            capsule_id = str(db.capsule1.id)
            testapp.get(
                api_version + "/capsules/" + capsule_id,
                status=403
            )

    # Response 404:
    def test_get_bad_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + unexisting_id,
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' "\
                  "has not been found."
            assert msg in res["error_description"]
    #################################

    #################################
    # Testing DELETE /capsules/cId
    #################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_absent") as publish_method1, \
             patch.object(NATS, "publish_addon_absent") as publish_method2:

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Delete this capsule
            testapp.delete(
                api_version + "/capsules/" + capsule_id,
                status=204
            )
            publish_method1.assert_called_once()
            assert publish_method2.call_count > 0

            # No more capsule
            res = testapp.get(
                api_version + "/capsules/" + capsule_id,
                status=404
            ).json
            msg = f"The requested capsule '{capsule_id}' has not been found."
            assert msg in res["error_description"]

    # Response 400:
    def test_delete_bad_capsule(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            testapp.delete(
                api_version + '/capsules/' + bad_id,
                status=400
            )

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        # Delete this capsule
        testapp.delete(
            api_version + "/capsules/" + capsule_id,
            status=401
        )

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this capsule
            testapp.delete(
                api_version + "/capsules/" + capsule_id,
                status=403
            )

    # Response 404:
    def test_delete_not_found(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            # Delete this capsule
            testapp.delete(
                api_version + "/capsules/" + unexisting_id,
                status=404
            )
    #################################

    #################################
    # Testing PATCH /capsules/cId
    #################################
    # Response 200:
    def test_patch(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.patch_json(
                api_version + "/capsules/" + str(db.capsule1.id),
                self._new_patch,
                status=200
            ).json

            assert res["no_update"]
            assert self._new_patch['comment'] in res["comment"]

    def test_patch_disable_no_update(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch("api.capsules.check_owners_on_keycloak"):

            no_update = {'no_update': False}

            res = testapp.patch_json(
                api_version + "/capsules/" + str(db.capsule1.id),
                no_update,
                status=200
            ).json

            assert res["no_update"] == "1970-01-01T00:00:00"

    # Response 400:
    def test_patch_bad_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.patch_json(
                api_version + "/capsules/" + bad_id,
                self._new_patch,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res["error_description"]

    # Response 401:
    def test_patch_with_no_token(self, testapp, db):
        testapp.patch_json(
            api_version + "/capsules/" + str(db.capsule1.id),
            self._new_patch,
            status=401
        )

    # Response 402:
    def test_patch_payment_required(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            new_size = {'size': 'xlarge'}
            res = testapp.patch_json(
                api_version + "/capsules/" + str(db.capsule1.id),
                new_size,
                status=402
            ).json

            msg = 'Please set a lower size for this capsule or prepare '
            assert msg in res["error_description"]

    # Response 403:
    def test_patch_raises_on_invalid_role(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.patch_json(
                api_version + "/capsules/" + str(db.capsule1.id),
                self._new_patch,
                status=403
            )

    def test_patch_no_update_not_parts_manager(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch("api.capsules.check_owners_on_keycloak"):

            res = testapp.patch_json(
                api_version + "/capsules/" + str(db.capsule1.id),
                self._new_patch,
                status=403
            ).json

            msg = 'You cannot set the capsule size.'
            assert msg in res['error_description']

    # Response 404:
    def test_patch_not_found(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.patch_json(
                api_version + "/capsules/" + unexisting_id,
                self._new_patch,
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' "\
                  "has not been found."
            assert msg in res['error_description']
    #################################
