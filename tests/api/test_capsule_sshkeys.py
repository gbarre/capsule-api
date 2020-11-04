from app import oidc
from tests.utils import api_version, dict_contains, bad_id, unexisting_id
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
from models import capsule_output_schema
import pytest
import json
from nats import NATS


class TestCapsuleSshKeys:

    _sshkey_input = [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVbtGe1p6vAjwizqEiO"
        "8EY5K3jyB7NoBT+gDREp6TcimUMJzsWryJampX7IqDpkC7I2/Y7oiUudV"
        "R97Q6H//IckCJetaD/yONkqzRCxCoQz+J0JWlMZsS/MmIy6BHDrLYB6KB"
        "Z4zk6exxbxcanJnz2fHahom8GE57l9khYgm3WLGi+v3ofb6ZsT6BrR8eX"
        "Rpb6wJ6HcghGRwWg7+M6IMqZdprvzGomc7UO3fPmQXf3KF9ZlelNCBscz"
        "D4qrYshiScVqmWmo2jePTDESWaaP3jlqz7EkvfxukAuTm2spohtmVs+iw"
        "xOTvEwP3o7ucfp/o7QRYPqL/OPXAN8pjzf8zZ2 toto@input",
    ]

    @staticmethod
    def build_output(db):
        return json.loads(capsule_output_schema.dumps(db.capsule1).data)

    #############################################################
    # Testing POST /capsules/{cId}/sshkeys
    #############################################################
    # Response 201:
    def test_create(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            res = testapp.post_json(
                api_version + "/capsules/" + capsule_id + "/sshkeys",
                self._sshkey_input,
                status=201
            ).json
            publish_method.assert_called_once()
            assert dict_contains(res, capsule_output)

    # Response 400:
    def test_create_bad_json(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            _sshkey_bad_input = {
                "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB"
            }
            testapp.post_json(
                api_version + "/capsules/" + capsule_id + "/sshkeys",
                _sshkey_bad_input,
                status=400
            )

    def test_create_bad_sshkey(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            _sshkey_bad_input = [
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB",
            ]
            res = testapp.post_json(
                api_version + "/capsules/" + capsule_id + "/sshkeys",
                _sshkey_bad_input,
                status=400
            ).json
            assert 'not a valid ssh public key' in res["error_description"]

    def test_create_bad_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(
                api_version + "/capsules/" + bad_id + "/sshkeys",
                self._sshkey_input,
                status=400
            )

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.post_json(
            api_version + "/capsules/" + capsule_id + "/sshkeys",
            self._sshkey_input,
            status=401
        )

    # Response 403:
    def test_create_forbidden(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.post_json(
                api_version + "/capsules/" + capsule_id + "/sshkeys",
                self._sshkey_input,
                status=403
            )

    # Response 404:
    def test_create_unexisting_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(
                api_version + "/capsules/" + unexisting_id + "/sshkeys",
                self._sshkey_input,
                status=404
            )

    # Response 409:
    def test_create_conflict(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            # Add sshkey
            testapp.post_json(
                api_version + "/capsules/" + capsule_id + "/sshkeys",
                self._sshkey_input,
                status=201
            )
            publish_method.assert_called_once()

            # Try to add again
            res = testapp.post_json(
                api_version + "/capsules/" + capsule_id + "/sshkeys",
                self._sshkey_input,
                status=409
            ).json
            msg = "'public_key' already exist for this capsule"
            assert msg in res["error_description"]
    #############################################################

    #############################################################
    # Testing DELETE /capsules/{cId}/sshkeys/{kId}
    #############################################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_sshkey(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            # Get sshkey id
            sshkey = db.sshkey3
            sshkey_id = str(sshkey.id)

            # Delete this sshkey
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/sshkeys/{sshkey_id}",
                status=204
            )
            publish_method.assert_called_once()

            # Ensure this sshkey is not present anymore
            res = testapp.get(
                api_version + "/capsules/" + capsule_id,
                status=200
            ).json
            for authorized_key in res["authorized_keys"]:
                assert sshkey.public_key != authorized_key["public_key"]

            sshkey2_id = str(db.sshkey2.id)
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/sshkeys/{sshkey2_id}",
                status=204
            )

    # Response 400:
    def test_delete_bad_sshkey(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                api_version + "/capsules/" + capsule_id + "/sshkeys/" + bad_id,
                status=400
            )

    def test_delete_bad_sshkey_capsule(self, testapp, db):
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
        capsule_id = temp_capsule['id']

        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            key_id = str(db.sshkey1.id)
            testapp.delete(
                api_version + "/capsules/" + capsule_id + "/sshkeys/" + key_id,
                status=400
            )

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        sshkey_id = str(db.sshkey1.id)

        # Delete this sshkey
        testapp.delete(
            f"{api_version}/capsules/{capsule_id}/sshkeys/{sshkey_id}",
            status=401
        )

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        sshkey_id = str(db.sshkey1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this sshkey
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/sshkeys/{sshkey_id}",
                status=403
            )

    # Response 404:
    def test_delete_unexisting_sshkey(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/sshkeys/{unexisting_id}",
                status=404
            )
    #############################################################
