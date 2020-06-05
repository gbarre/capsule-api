from app import oidc
from tests.utils import *
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
from models import RoleEnum, capsule_output_schema, SSHKey
import pytest
import json


class TestCapsuleSshKeys:

    _sshkey_input = [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVbtGe1p6vAjwizqEiO"\
        "8EY5K3jyB7NoBT+gDREp6TcimUMJzsWryJampX7IqDpkC7I2/Y7oiUudV"\
        "R97Q6H//IckCJetaD/yONkqzRCxCoQz+J0JWlMZsS/MmIy6BHDrLYB6KB"\
        "Z4zk6exxbxcanJnz2fHahom8GE57l9khYgm3WLGi+v3ofb6ZsT6BrR8eX"\
        "Rpb6wJ6HcghGRwWg7+M6IMqZdprvzGomc7UO3fPmQXf3KF9ZlelNCBscz"\
        "D4qrYshiScVqmWmo2jePTDESWaaP3jlqz7EkvfxukAuTm2spohtmVs+iw"\
        "xOTvEwP3o7ucfp/o7QRYPqL/OPXAN8pjzf8zZ2",
    ]

    _sshkey_bad_input = {
        "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVbtGe1p6vAjwizqEiO"\
                    "8EY5K3jyB7NoBT+gDREp6TcimUMJzsWryJampX7IqDpkC7I2/Y7oiUudV"\
                    "R97Q6H//IckCJetaD/yONkqzRCxCoQz+J0JWlMZsS/MmIy6BHDrLYB6KB"\
                    "Z4zk6exxbxcanJnz2fHahom8GE57l9khYgm3WLGi+v3ofb6ZsT6BrR8eX"\
                    "Rpb6wJ6HcghGRwWg7+M6IMqZdprvzGomc7UO3fPmQXf3KF9ZlelNCBscz"\
                    "D4qrYshiScVqmWmo2jePTDESWaaP3jlqz7EkvfxukAuTm2spohtmVs+iw"\
                    "xOTvEwP3o7ucfp/o7QRYPqL/OPXAN8pjzf8zZ2"
    }

    @staticmethod
    def build_output(db):
        return json.loads(capsule_output_schema.dumps(db.capsule1).data)



    #############################################################
    #### Testing POST /capsules/{cId}/sshkeys
    #############################################################
    # Response 400:
    def test_create_bad_json(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(api_version + "/capsules/" + capsule_id + "/sshkeys", self._sshkey_bad_input, status=400)

    def test_create_bad_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            testapp.post_json(api_version + "/capsules/" + bad_id + "/sshkeys", self._sshkey_input, status=400)

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.post_json(api_version + "/capsules/" + capsule_id + "/sshkeys", self._sshkey_input, status=401)

    # Response 209:
    def test_create_confilct(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            # Add sshkey
            testapp.post_json(api_version + "/capsules/" + capsule_id + "/sshkeys", self._sshkey_input, status=201)

            # Try to add again
            res = testapp.post_json(api_version + "/capsules/" + capsule_id + "/sshkeys", self._sshkey_input, status=409).json
            assert "'public_key' already exist for this capsule" in res["error_description"]

    # Response 201:
    def test_create(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        capsule_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(api_version + "/capsules/" + capsule_id + "/sshkeys", self._sshkey_input, status=201).json
            assert dict_contains(res, capsule_output)
    #############################################################

    #############################################################
    #### Testing DELETE /capsules/{cId}/sshkeys/{kId}
    #############################################################
    # Response 204:
    # FIXME: how to remove the header "Content-Type" in the a DELETE request only?
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_sshkey(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=db.admin_user):

            # Get sshkey id
            sshkey = db.sshkey1
            sshkey_id = str(sshkey.id)

            # Delete this sshkey
            testapp.delete(api_version + "/capsules/" + capsule_id + "/sshkeys/" + sshkey_id, status=204)

            # Ensure this sshkey is not present anymore
            res = testapp.get(api_version + "/capsules/" + capsule_id, status=200).json
            for authorized_key in res["authorized_keys"]:
                assert sshkey.public_key != authorized_key["public_key"]

    # Response 400:
    def test_delete_bad_sshkey(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=db.fake_user):

            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/sshkeys/" + bad_id, status=400).json
            assert "The browser (or proxy) sent a request that this server could not understand." in res["error_description"]

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        sshkey_id = str(db.sshkey1.id)

        # Delete this sshkey
        testapp.delete(api_version + "/capsules/" + capsule_id + "/sshkeys/" + sshkey_id, status=401)

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        sshkey_id = str(db.sshkey1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this sshkey
            res = testapp.delete(api_version + "/capsules/" + capsule_id + "/sshkeys/" + sshkey_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["error_description"]
    #############################################################
